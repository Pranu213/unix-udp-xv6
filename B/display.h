#ifndef DISPLAY_H
#define DISPLAY_H

#include <pcap.h>
#include "packet_store.h"

/* Print packet summary line (timestamp, lengths, protocol info) */
void print_packet_summary(const struct pcap_pkthdr *header,
                          const char *src_ip, const char *dst_ip,
                          const char *protocol);

/* Print detailed view: header + payload dump */
void print_packet_details(const struct pcap_pkthdr *header,
                          const u_char *packet,
                          const char *summary);

/* Print a divider line for readability */
void print_divider(void);

/* Print basic packet info (ID, timestamp, length, first 16 hex bytes) */
void print_basic_packet(int packet_id, const struct pcap_pkthdr *header, const u_char *packet);

/* Phase 5: Detailed packet inspection functions */
void print_packet_list_summary(const PacketStore *store);
void print_detailed_packet_analysis(const StoredPacket *packet, int packet_id);
void print_full_hex_dump(const u_char *data, int length);

#endif
