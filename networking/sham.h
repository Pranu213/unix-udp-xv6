#ifndef SHAM_H
#define SHAM_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>   // needed for va_list in log_event

// -------------------- Constants --------------------
#define SHAM_PAYLOAD_SIZE 1024       // Each data chunk = 1024 bytes
#define SHAM_WINDOW_PKTS 10          // Sliding window size (packets)
#define SHAM_RTO_MS 500              // Retransmission timeout in ms

// -------------------- Flags --------------------
#define SHAM_SYN 0x1
#define SHAM_ACK 0x2
#define SHAM_FIN 0x4

// -------------------- SHAM Packet Header --------------------
struct sham_header {
    uint32_t seq_num;      // Sequence Number (byte-stream number of first byte in data)
    uint32_t ack_num;      // Acknowledgment Number (next expected byte)
    uint16_t flags;        // Control flags (SYN, ACK, FIN)
    uint16_t window_size;  // Flow control window size (bytes)
} __attribute__((packed));

// -------------------- SHAM Packet --------------------
struct sham_packet {
    struct sham_header header;
    char data[SHAM_PAYLOAD_SIZE]; // Application data
};

// -------------------- Logging --------------------
static inline FILE *get_log_file(const char *role) {
    static FILE *logf = NULL;
    static int initialized = 0;

    if (!initialized) {
        initialized = 1;
        char *env = getenv("RUDP_LOG");
        if (env && strcmp(env, "1") == 0) {
            if (strcmp(role, "server") == 0)
                logf = fopen("server_log.txt", "w");
            else
                logf = fopen("client_log.txt", "w");
            if (!logf) {
                perror("fopen log");
                exit(EXIT_FAILURE);
            }
        }
    }
    return logf;
}

//llm code begins

static inline void log_event(const char *role, const char *fmt, ...) {
    FILE *logf = get_log_file(role);
    if (!logf) return; // logging disabled

    char time_buffer[30];
    struct timeval tv;
    time_t curtime;

    gettimeofday(&tv, NULL);
    curtime = tv.tv_sec;
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", localtime(&curtime));

    fprintf(logf, "[%s.%06ld] [%s] ", time_buffer, tv.tv_usec, role);

    va_list args;
    va_start(args, fmt);
    vfprintf(logf, fmt, args);
    va_end(args);

    fprintf(logf, "\n");
    fflush(logf);
}

//llm code ends

// -------------------- Packet Loss Simulation --------------------
static inline int should_drop_packet(double loss_rate) {
    if (loss_rate <= 0.0) return 0;
    double r = (double)rand() / RAND_MAX;
    return (r < loss_rate);
}

#endif // SHAM_H
