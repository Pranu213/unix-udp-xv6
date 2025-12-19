#include "packet_store.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// LLM code starts here //

void init_packet_store(PacketStore *store) {
    store->count = 0;
    store->session_active = 0;
    store->session_start = 0;
    for (int i = 0; i < MAX_PACKETS; i++) {
        store->packets[i].data = NULL;
        store->packets[i].length = 0;
    }
}

void add_packet(PacketStore *store, const struct pcap_pkthdr *header, const u_char *data) {
    // If this is the first packet of a new session, clear old data
    static time_t last_session_start = 0;
    if (store->session_start != last_session_start) {
        // New session started, clear old packets
        for (int i = 0; i < store->count; i++) {
            if (store->packets[i].data) {
                free(store->packets[i].data);
                store->packets[i].data = NULL;
            }
        }
        store->count = 0;
        last_session_start = store->session_start;
    }
    
    if (store->count >= MAX_PACKETS) {
        fprintf(stderr, "[packet_store] Store is full! Ignoring packet.\n");
        return;
    }

    StoredPacket *pkt = &store->packets[store->count];

    pkt->ts = header->ts;
    pkt->length = header->len;

    // Allocate memory and copy raw data
    pkt->data = (unsigned char *) malloc(header->len);
    if (pkt->data == NULL) {
        fprintf(stderr, "[packet_store] Memory allocation failed!\n");
        return;
    }
    memcpy(pkt->data, data, header->len);

    store->count++;
}

void print_packet_store(const PacketStore *store) {
    printf("=== Packet Store Summary ===\n");
    printf("Total packets stored: %d\n", store->count);
    for (int i = 0; i < store->count; i++) {
        const StoredPacket *pkt = &store->packets[i];
        printf("[%d] Time: %ld.%06ld  Length: %u bytes\n",
               i,
               (long) pkt->ts.tv_sec,
               (long) pkt->ts.tv_usec,
               pkt->length);
    }
}

void free_packet_store(PacketStore *store) {
    for (int i = 0; i < store->count; i++) {
        free(store->packets[i].data);
        store->packets[i].data = NULL;
    }
    store->count = 0;
    store->session_active = 0;
}

void start_new_session(PacketStore *store) {
    // Don't clear previous session data immediately
    // Only clear when first packet is actually captured
    store->session_active = 1;
    store->session_start = time(NULL);
    printf("[C-Shark] New packet capture session started.\n");
}

int has_session_data(const PacketStore *store) {
    return (store->session_active && store->count > 0);
}

const StoredPacket* get_packet_by_id(const PacketStore *store, int packet_id) {
    // packet_id is 1-based for user display, but array is 0-based
    if (packet_id < 1 || packet_id > store->count) {
        return NULL;
    }
    return &store->packets[packet_id - 1];
}
// LLM code ends here //
