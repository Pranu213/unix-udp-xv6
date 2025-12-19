#ifndef FILTERS_H
#define FILTERS_H

#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>
#include <stdbool.h>

typedef enum {
    FILTER_ALL = 0,
    FILTER_HTTP,
    FILTER_HTTPS,
    FILTER_DNS,
    FILTER_ARP,
    FILTER_TCP,
    FILTER_UDP
} FilterType;

/**
 * Filter configuration structure
 * (empty fields mean "any")
 */
typedef struct {
    FilterType filter_type;  // High-level protocol filter
    int protocol;            // 0 = any, 6 = TCP, 17 = UDP, 1 = ICMP
    char src_ip[16];         // source IPv4 string ("" = any)
    char dst_ip[16];         // destination IPv4 string ("" = any)
    int src_port;            // source port (0 = any)
    int dst_port;            // destination port (0 = any)
} PacketFilter;

/**
 * Initialize filter to match all packets
 */
void init_filter(PacketFilter *filter);

/**
 * Set filter rules
 */
void set_filter(PacketFilter *filter, int protocol,
                const char *src_ip, const char *dst_ip,
                int src_port, int dst_port);

/**
 * Check if a packet matches filter rules
 */
bool packet_matches_filter(const PacketFilter *filter,
                           const struct pcap_pkthdr *header,
                           const u_char *packet);

/**
 * Set filter by protocol type (HTTP, HTTPS, DNS, etc.)
 */
void set_filter_by_type(PacketFilter *filter, FilterType type);

/**
 * Get filter type name for display
 */
const char* get_filter_type_name(FilterType type);

#endif /* FILTERS_H */
