#ifndef PACKET_STORE_H
#define PACKET_STORE_H

#include <pcap.h>
#include <time.h>

// Maximum number of packets to store (Phase 4 requirement)
#define MAX_PACKETS 10000

// Structure to hold packet metadata + data
typedef struct {
    struct timeval ts;     // timestamp of capture
    unsigned int length;   // length of packet
    unsigned char *data;   // raw packet data (malloc'd)
} StoredPacket;

// Store structure (array-based for now)
typedef struct {
    StoredPacket packets[MAX_PACKETS];
    int count;             // current number of stored packets
    int session_active;    // 1 if we have an active session, 0 otherwise
    time_t session_start;  // timestamp when session started
} PacketStore;

/**
 * Initialize the packet store
 */
void init_packet_store(PacketStore *store);

/**
 * Add a packet to the store
 * (makes a deep copy of packet data)
 */
void add_packet(PacketStore *store, const struct pcap_pkthdr *header, const u_char *data);

/**
 * Print summary of stored packets
 */
void print_packet_store(const PacketStore *store);

/**
 * Free all allocated memory in the store
 */
void free_packet_store(PacketStore *store);

/**
 * Start a new session (clear previous packets)
 */
void start_new_session(PacketStore *store);

/**
 * Check if there's an active session with packets
 */
int has_session_data(const PacketStore *store);

/**
 * Get detailed packet info for inspection (Phase 5)
 */
const StoredPacket* get_packet_by_id(const PacketStore *store, int packet_id);

#endif // PACKET_STORE_H
