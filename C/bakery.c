#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <time.h>

#define NUM_CHEFS 4
#define SOFA_SEATS 4
#define MAX_INSIDE 25
#define MAX_INPUT_CUSTOMERS 1024


typedef enum { JOB_NONE = 0, JOB_BAKE = 1, JOB_ACCEPT = 2 } JobType;

// ------------------------ Time ------------------------
static long long base_ts = 0;
static struct timespec t0;

static inline long long now_tick(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    long long sec = (ts.tv_sec - t0.tv_sec);
    if (ts.tv_nsec < t0.tv_nsec) sec -= 1;
    return base_ts + sec;
}

// ------------------------ Printing ------------------------
static pthread_mutex_t print_mu = PTHREAD_MUTEX_INITIALIZER;
static void print_line_at(long long ts, const char *kind, long long id, const char *suffix) {
    pthread_mutex_lock(&print_mu);
    printf("%lld %s %lld %s\n", ts, kind, id, suffix);
    fflush(stdout);
    pthread_mutex_unlock(&print_mu);
}

//LLM code starts here // 
// ------------------------ Queue ------------------------
typedef struct {
    int a[MAX_INPUT_CUSTOMERS + 8];
    int head, tail;
} IntQueue;

static inline void q_init(IntQueue *q){ q->head = q->tail = 0; }
static inline bool q_empty(const IntQueue *q){ return q->head == q->tail; }
static inline void q_push(IntQueue *q, int v){ q->a[q->tail++] = v; if(q->tail >= (int)(sizeof(q->a)/sizeof(q->a[0]))) q->tail = 0; }
static inline int  q_pop(IntQueue *q){ int v = q->a[q->head++]; if(q->head >= (int)(sizeof(q->a)/sizeof(q->a[0]))) q->head = 0; return v; }

// ------------------------ Data Structures ------------------------
typedef struct Customer {
    long long id, arrival_ts;
    pthread_t thread;
    pthread_cond_t cv;

    bool entered, seat_assigned, seated;
    bool requested, baked, paid, payment_done, left;
    int assigned_chef;
} Customer;

typedef struct Chef {
    int id;
    pthread_t thread;
    pthread_cond_t cv;
    bool busy;
    JobType job;
    int cust_idx;
} Chef;

// ------------------------ Globals ------------------------
static Customer customers[MAX_INPUT_CUSTOMERS];
static Chef chefs[NUM_CHEFS];
static int N = 0;

static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t work_cv = PTHREAD_COND_INITIALIZER;

static IntQueue standing_q, sofa_q, pay_q;
static int inside_count = 0, seats_in_use = 0;
static bool cash_busy = false, shutdown_flag = false;

static int bake_order[NUM_CHEFS] = {2, 1, 3, 4};
static int bake_rr = 0;

// ------------------------ Helpers ------------------------
static void try_assign_seat_locked(void);
static void schedule_locked(void);

// ------------------------ Customer Thread ------------------------
static void *customer_thread(void *arg){
    int idx = (int)(intptr_t)arg;
    Customer *c = &customers[idx];

    long long rel = c->arrival_ts - base_ts;
    if (rel < 0) rel = 0;
    sleep((unsigned int)rel);

    pthread_mutex_lock(&mu);
    if (inside_count >= MAX_INSIDE) {
        pthread_mutex_unlock(&mu);
        return NULL;
    }

    inside_count++;
    c->entered = true;
    print_line_at(now_tick(), "Customer", c->id, "enters");

    pthread_mutex_unlock(&mu);
    sleep(1);
    pthread_mutex_lock(&mu);

    if (seats_in_use < SOFA_SEATS && q_empty(&standing_q)) {
        seats_in_use++;
        c->seat_assigned = true;
        print_line_at(now_tick(), "Customer", c->id, "sits");
        pthread_mutex_unlock(&mu);
        sleep(1);
        pthread_mutex_lock(&mu);
        c->seated = true;
        print_line_at(now_tick(), "Customer", c->id, "requests cake");
        pthread_mutex_unlock(&mu);
        sleep(1);
        pthread_mutex_lock(&mu);
        c->requested = true;
        q_push(&sofa_q, idx);
        schedule_locked();
    } else {
        q_push(&standing_q, idx);
        while (!c->seat_assigned)
            pthread_cond_wait(&c->cv, &mu);

        print_line_at(now_tick(), "Customer", c->id, "sits");
        pthread_mutex_unlock(&mu);
        sleep(1);
        pthread_mutex_lock(&mu);
        c->seated = true;
        print_line_at(now_tick(), "Customer", c->id, "requests cake");
        pthread_mutex_unlock(&mu);
        sleep(1);
        pthread_mutex_lock(&mu);
        c->requested = true;
        q_push(&sofa_q, idx);
        schedule_locked();
    }

    while (!c->baked) pthread_cond_wait(&c->cv, &mu);

    print_line_at(now_tick(), "Customer", c->id, "pays");
    pthread_mutex_unlock(&mu);
    sleep(1);
    pthread_mutex_lock(&mu);
    c->paid = true;
    q_push(&pay_q, idx);
    schedule_locked();

    while (!c->payment_done) pthread_cond_wait(&c->cv, &mu);

    print_line_at(now_tick(), "Customer", c->id, "leaves");
    c->left = true;
    inside_count--;
    seats_in_use--;

    try_assign_seat_locked();
    schedule_locked();
    pthread_mutex_unlock(&mu);
    return NULL;
}

// ------------------------ Seat Management ------------------------
static void try_assign_seat_locked(void){
    while (seats_in_use < SOFA_SEATS && !q_empty(&standing_q)) {
        int nxt = q_pop(&standing_q);
        Customer *nc = &customers[nxt];
        seats_in_use++;
        nc->seat_assigned = true;
        pthread_cond_signal(&nc->cv);
    }
}

// ------------------------ Scheduler ------------------------
static void schedule_locked(void){
    // Priority: payments first
    for (int i = 0; i < NUM_CHEFS && !q_empty(&pay_q); ++i) {
        int ci = pay_q.a[pay_q.head];
        Customer *c = &customers[ci];
        int target = (c->assigned_chef > 0 ? c->assigned_chef : 0);
        if (!cash_busy && target > 0) {
            Chef *ch = &chefs[target - 1];
            if (!ch->busy && ch->job == JOB_NONE) {
                q_pop(&pay_q);
                cash_busy = true;
                ch->job = JOB_ACCEPT;
                ch->cust_idx = ci;
                ch->busy = true;
                pthread_cond_signal(&ch->cv);
            }
        }
    }

    // Baking next (round-robin)
    for (;;) {
        if (q_empty(&sofa_q)) break;
        int chosen_slot = -1;
        for (int k = 0; k < NUM_CHEFS; ++k) {
            int idx = (bake_rr + k) % NUM_CHEFS;
            int chef_id = bake_order[idx];
            Chef *ch = &chefs[chef_id - 1];
            if (!ch->busy && ch->job == JOB_NONE) {
                chosen_slot = idx;
                break;
            }
        }
        if (chosen_slot < 0) break;

        bake_rr = (chosen_slot + 1) % NUM_CHEFS;
        int chef_id = bake_order[chosen_slot];
        Chef *ch = &chefs[chef_id - 1];
        int ci = q_pop(&sofa_q);
        Customer *c = &customers[ci];
        ch->job = JOB_BAKE;
        ch->cust_idx = ci;
        ch->busy = true;
        c->assigned_chef = chef_id;
        pthread_cond_signal(&ch->cv);
    }
}

// ------------------------ Chef Thread ------------------------
static void *chef_thread(void *arg){
    int chef_id = (int)(intptr_t)arg;
    Chef *self = &chefs[chef_id - 1];

    pthread_mutex_lock(&mu);
    for (;;) {
        if (self->job == JOB_NONE) {
            if (shutdown_flag && q_empty(&pay_q) && q_empty(&sofa_q)) {
                pthread_mutex_unlock(&mu);
                return NULL;
            }
            pthread_cond_wait(&self->cv, &mu);
            continue;
        }

        int ci = self->cust_idx;
        Customer *c = &customers[ci];
        JobType job = self->job;
        self->job = JOB_NONE;

        long long t = now_tick();
        if (job == JOB_ACCEPT) {
            pthread_mutex_unlock(&mu);
            char buf[64];
            snprintf(buf, sizeof(buf), "accepts payment for Customer %lld", c->id);
            print_line_at(t, "Chef", chef_id, buf);
            sleep(2);
            pthread_mutex_lock(&mu);
            c->payment_done = true;
            pthread_cond_signal(&c->cv);
            cash_busy = false;
            self->busy = false;
            try_assign_seat_locked();
            schedule_locked();
            continue;
        }

        if (job == JOB_BAKE) {
            pthread_mutex_unlock(&mu);
            char buf2[64];
            snprintf(buf2, sizeof(buf2), "bakes for Customer %lld", c->id);
            print_line_at(t, "Chef", chef_id, buf2);
            sleep(2);
            pthread_mutex_lock(&mu);
            c->baked = true;
            pthread_cond_signal(&c->cv);
            self->busy = false;
            schedule_locked();
        }
    }
}

// ------------------------ Main ------------------------
int main(void){
    char line[256];
    long long ts, id, min_ts = -1;

    while (fgets(line, sizeof(line), stdin)) {
        if (strncmp(line, "<EOF>", 5) == 0) break;
        char word[32];
        if (sscanf(line, "%lld %31s %lld", &ts, word, &id) == 3) {
            if (strcmp(word, "Customer") != 0) continue;
            if (N >= MAX_INPUT_CUSTOMERS) continue;
            customers[N].id = id;
            customers[N].arrival_ts = ts;
            pthread_cond_init(&customers[N].cv, NULL);
            if (min_ts < 0 || ts < min_ts) min_ts = ts;
            N++;
        }
    }
    if (N == 0) return 0;

    base_ts = min_ts;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    q_init(&standing_q);
    q_init(&sofa_q);
    q_init(&pay_q);

    //LLM code ends here //
    
    for (int i = 0; i < NUM_CHEFS; ++i) {
        chefs[i].id = i + 1;
        chefs[i].busy = false;
        chefs[i].job = JOB_NONE;
        pthread_cond_init(&chefs[i].cv, NULL);
        pthread_create(&chefs[i].thread, NULL, chef_thread, (void *)(intptr_t)(i + 1));
    }

    for (int i = 0; i < N; ++i)
        pthread_create(&customers[i].thread, NULL, customer_thread, (void *)(intptr_t)i);

    for (int i = 0; i < N; ++i)
        pthread_join(customers[i].thread, NULL);

    pthread_mutex_lock(&mu);
    shutdown_flag = true;
    for (int i = 0; i < NUM_CHEFS; ++i)
        pthread_cond_signal(&chefs[i].cv);
    pthread_mutex_unlock(&mu);

    for (int i = 0; i < NUM_CHEFS; ++i)
        pthread_join(chefs[i].thread, NULL);

    return 0;
}
