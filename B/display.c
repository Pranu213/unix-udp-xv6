#include "display.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

// LLM code starts here //

/* Draw a visual divider between packets */
void print_divider(void) {
    printf("\n------------------------------------------------------------\n");
}

/* Print short summary info for one packet */
void print_packet_summary(const struct pcap_pkthdr *header,
                          const char *src_ip, const char *dst_ip,
                          const char *protocol) {
    char ts_buf[64];
    ts_to_str(&header->ts, ts_buf, sizeof(ts_buf));
    printf("[%s] ", ts_buf);
    printf("%s -> %s  |  Proto: %s  |  Len: %d bytes\n",
           src_ip ? src_ip : "unknown",
           dst_ip ? dst_ip : "unknown",
           protocol ? protocol : "N/A",
           header->len);
}

/* Print detailed payload (hex + ascii) */
void print_packet_details(const struct pcap_pkthdr *header,
                          const u_char *packet,
                          const char *summary) {
    if (summary)
        printf("%s\n", summary);

    printf("Captured Length: %d bytes | Actual Length: %d bytes\n",
           header->caplen, header->len);

    int len_rem = header->caplen;
    int line_width = 16;
    int offset = 0;
    const u_char *ch = packet;

    /* print payload in lines of 16 bytes */
    while (len_rem > 0) {
        int line_len = len_rem < line_width ? len_rem : line_width;
        print_hex_ascii_line(ch, line_len, offset);
        len_rem -= line_len;
        ch += line_len;
        offset += line_width;
    }
}

/* Print basic packet info - used by simple packet sniffer */
void print_basic_packet(int packet_id, const struct pcap_pkthdr *header, const u_char *packet) {
    char ts_buf[64];
    ts_to_str(&header->ts, ts_buf, sizeof(ts_buf));
    
    printf("Packet #%d | Timestamp: %s | Length: %d bytes\n", 
           packet_id, ts_buf, header->caplen);
    
    /* Print first 16 bytes in hex format */
    printf("First 16 bytes (hex): ");
    int bytes_to_show = header->caplen < 16 ? header->caplen : 16;
    for (int i = 0; i < bytes_to_show; i++) {
        printf("%02X ", packet[i]);
    }
    printf("\n");
}

/* Phase 5: Print summary list of stored packets */
void print_packet_list_summary(const PacketStore *store) {
    if (!has_session_data(store)) {
        printf("\n[C-Shark] No packet data available. Run a capture session first.\n");
        return;
    }
    
    printf("\n=== Last Session Packet Summary ===\n");
    printf("Total packets captured: %d\n\n", store->count);
    printf("%-4s %-20s %-6s %-15s %-15s %-10s\n", 
           "ID", "Timestamp", "Length", "Src IP", "Dst IP", "Protocol");
    printf("-------------------------------------------------------------------------------------\n");
    
    for (int i = 0; i < store->count; i++) {
        const StoredPacket *pkt = &store->packets[i];
        char ts_buf[32];
        ts_to_str(&pkt->ts, ts_buf, sizeof(ts_buf));
        
        // Extract basic info from packet
        const u_char *data = pkt->data;
        char src_ip[16] = "N/A", dst_ip[16] = "N/A", protocol[10] = "N/A";
        
        // Determine if this is cooked-mode or Ethernet
        const u_char *payload;
        size_t payload_offset;
        uint16_t ether_type;
        
        if (pkt->length >= 16 && ntohs(*(uint16_t*)data) <= 4) {
            // Likely cooked-mode
            payload_offset = 16;
            ether_type = ntohs(*(uint16_t*)(data + 14));
            payload = data + 16;
        } else if (pkt->length >= sizeof(struct ether_header)) {
            // Standard Ethernet
            payload_offset = sizeof(struct ether_header);
            const struct ether_header *eth = (const struct ether_header *)data;
            ether_type = ntohs(eth->ether_type);
            payload = data + sizeof(struct ether_header);
        } else {
            // Too short, skip
            goto print_packet;
        }
        
        if (ether_type == ETHERTYPE_IP && pkt->length >= payload_offset + sizeof(struct ip)) {
            const struct ip *ip = (const struct ip *)payload;
            strncpy(src_ip, inet_ntoa(ip->ip_src), sizeof(src_ip) - 1);
            strncpy(dst_ip, inet_ntoa(ip->ip_dst), sizeof(dst_ip) - 1);
            
            if (ip->ip_p == IPPROTO_TCP) strcpy(protocol, "TCP");
            else if (ip->ip_p == IPPROTO_UDP) strcpy(protocol, "UDP");
            else if (ip->ip_p == IPPROTO_ICMP) strcpy(protocol, "ICMP");
            else snprintf(protocol, sizeof(protocol), "IP(%d)", ip->ip_p);
        } else if (ether_type == ETHERTYPE_ARP) {
            strcpy(protocol, "ARP");
            strcpy(src_ip, "ARP");
            strcpy(dst_ip, "ARP");
        } else if (ether_type == ETHERTYPE_IPV6) {
            strcpy(protocol, "IPv6");
            strcpy(src_ip, "IPv6");
            strcpy(dst_ip, "IPv6");
        }
        
        print_packet:
        
        printf("%-4d %-20s %-6u %-15s %-15s %-10s\n", 
               i + 1, ts_buf, pkt->length, src_ip, dst_ip, protocol);
    }
    printf("\n");
}

/* Phase 5: Print comprehensive packet analysis */
void print_detailed_packet_analysis(const StoredPacket *packet, int packet_id) {
    printf("\n" "=" "===============================================\n");
    printf("   DETAILED PACKET ANALYSIS - Packet #%d\n", packet_id);
    printf("" "=" "===============================================\n");
    
    char ts_buf[64];
    ts_to_str(&packet->ts, ts_buf, sizeof(ts_buf));
    printf("Timestamp: %s\n", ts_buf);
    printf("Total Length: %u bytes\n\n", packet->length);
    
    const u_char *data = packet->data;
    
    // Use existing detailed analysis logic for comprehensive breakdown
    printf("=== LAYER-BY-LAYER ANALYSIS ===\n");
    
    // Determine if this is cooked-mode or Ethernet
    const u_char *l3_data;
    size_t l3_len;
    uint16_t ether_type;
    
    // Check if this looks like cooked-mode (16-byte header)
    if (packet->length >= 16 && ntohs(*(uint16_t*)data) <= 4) {
        // Linux cooked-mode
        uint16_t pkt_type = ntohs(*(uint16_t*)data);
        uint16_t arphrd = ntohs(*(uint16_t*)(data + 2));
        uint16_t addr_len = ntohs(*(uint16_t*)(data + 4));
        const u_char *addr = data + 6;
        ether_type = ntohs(*(uint16_t*)(data + 14));
        
        printf("\n[Layer 2 - Data Link (Linux Cooked)]\n");
        printf("  Packet Type: %u\n", pkt_type);
        printf("  ARPHRD Type: %u\n", arphrd);
        printf("  Address Length: %u\n", addr_len);
        if (addr_len > 0 && addr_len <= 8) {
            printf("  Address: ");
            for (int i = 0; i < addr_len && i < 6; i++) {
                printf("%02X", addr[i]);
                if (i < addr_len - 1) printf(":");
            }
            printf("\n");
        }
        printf("  EtherType: 0x%04X ", ether_type);
        
        l3_data = data + 16;
        l3_len = packet->length - 16;
    } else if (packet->length >= sizeof(struct ether_header)) {
        // Standard Ethernet
        const struct ether_header *eth = (const struct ether_header *)data;
        printf("\n[Layer 2 - Data Link (Ethernet)]\n");
        printf("  Destination MAC: "); print_mac(eth->ether_dhost); printf("\n");
        printf("  Source MAC: "); print_mac(eth->ether_shost); printf("\n");
        printf("  EtherType: 0x%04X ", ntohs(eth->ether_type));
        
        ether_type = ntohs(eth->ether_type);
        l3_data = data + sizeof(struct ether_header);
        l3_len = packet->length - sizeof(struct ether_header);
    } else {
        printf("\n[Error: Packet too short for analysis]\n");
        goto hex_dump;
    }
    
    if (ether_type == ETHERTYPE_IP) printf("(IPv4)\n");
    else if (ether_type == ETHERTYPE_IPV6) printf("(IPv6)\n");
    else if (ether_type == ETHERTYPE_ARP) printf("(ARP)\n");
    else printf("(Unknown)\n");
    
    // Continue with Layer 3 analysis based on EtherType
    if (ether_type == ETHERTYPE_IP && l3_len >= sizeof(struct ip)) {
            const struct ip *ip = (const struct ip *)l3_data;
            printf("\n[Layer 3 - Network (IPv4)]\n");
            printf("  Version: %d\n", ip->ip_v);
            printf("  Header Length: %d bytes\n", ip->ip_hl * 4);
            printf("  Type of Service: 0x%02X\n", ip->ip_tos);
            printf("  Total Length: %d bytes\n", ntohs(ip->ip_len));
            printf("  Identification: 0x%04X\n", ntohs(ip->ip_id));
            printf("  Flags: 0x%04X\n", ntohs(ip->ip_off));
            printf("  TTL: %d\n", ip->ip_ttl);
            printf("  Protocol: %d (%s)\n", ip->ip_p, 
                   (ip->ip_p == IPPROTO_TCP) ? "TCP" : 
                   (ip->ip_p == IPPROTO_UDP) ? "UDP" : 
                   (ip->ip_p == IPPROTO_ICMP) ? "ICMP" : "Other");
            printf("  Header Checksum: 0x%04X\n", ntohs(ip->ip_sum));
            printf("  Source IP: %s\n", inet_ntoa(ip->ip_src));
            printf("  Destination IP: %s\n", inet_ntoa(ip->ip_dst));
            
            // Layer 4 analysis
            int ip_hdr_len = ip->ip_hl * 4;
            const u_char *l4_data = l3_data + ip_hdr_len;
            size_t l4_len = (l3_len > ip_hdr_len) ? (l3_len - ip_hdr_len) : 0;
            
            if (ip->ip_p == IPPROTO_TCP && l4_len >= sizeof(struct tcphdr)) {
                const struct tcphdr *tcp = (const struct tcphdr *)l4_data;
                printf("\n[Layer 4 - Transport (TCP)]\n");
                printf("  Source Port: %u\n", ntohs(tcp->th_sport));
                printf("  Destination Port: %u\n", ntohs(tcp->th_dport));
                printf("  Sequence Number: %u\n", ntohl(tcp->th_seq));
                printf("  Acknowledgment Number: %u\n", ntohl(tcp->th_ack));
                printf("  Header Length: %d bytes\n", tcp->th_off * 4);
                printf("  Flags: 0x%02X [", tcp->th_flags);
                if (tcp->th_flags & TH_URG) printf(" URG");
                if (tcp->th_flags & TH_ACK) printf(" ACK");
                if (tcp->th_flags & TH_PUSH) printf(" PSH");
                if (tcp->th_flags & TH_RST) printf(" RST");
                if (tcp->th_flags & TH_SYN) printf(" SYN");
                if (tcp->th_flags & TH_FIN) printf(" FIN");
                printf(" ]\n");
                printf("  Window Size: %u\n", ntohs(tcp->th_win));
                printf("  Checksum: 0x%04X\n", ntohs(tcp->th_sum));
                printf("  Urgent Pointer: %u\n", ntohs(tcp->th_urp));
            } else if (ip->ip_p == IPPROTO_UDP && l4_len >= sizeof(struct udphdr)) {
                const struct udphdr *udp = (const struct udphdr *)l4_data;
                printf("\n[Layer 4 - Transport (UDP)]\n");
                printf("  Source Port: %u\n", ntohs(udp->uh_sport));
                printf("  Destination Port: %u\n", ntohs(udp->uh_dport));
                printf("  Length: %u bytes\n", ntohs(udp->uh_ulen));
                printf("  Checksum: 0x%04X\n", ntohs(udp->uh_sum));
            }
        } else if (ether_type == ETHERTYPE_ARP && l3_len >= sizeof(struct arphdr)) {
            const struct arphdr *arp = (const struct arphdr *)l3_data;
            printf("\n[Layer 3 - Network (ARP)]\n");
            printf("  Hardware Type: %u\n", ntohs(arp->ar_hrd));
            printf("  Protocol Type: 0x%04X\n", ntohs(arp->ar_pro));
            printf("  Hardware Length: %u\n", arp->ar_hln);
            printf("  Protocol Length: %u\n", arp->ar_pln);
            printf("  Operation: %u (%s)\n", ntohs(arp->ar_op),
                   (ntohs(arp->ar_op) == ARPOP_REQUEST) ? "Request" :
                   (ntohs(arp->ar_op) == ARPOP_REPLY) ? "Reply" : "Other");
    }
    
    hex_dump:
    printf("\n=== COMPLETE HEX DUMP ===\n");
    print_full_hex_dump(data, packet->length);
}

/* Phase 5: Print complete hex dump */
void print_full_hex_dump(const u_char *data, int length) {
    int offset = 0;
    while (offset < length) {
        int chunk = (length - offset) >= 16 ? 16 : (length - offset);
        print_hex_ascii_line(data + offset, chunk, offset);
        offset += 16;
    }
    printf("\n");
}

// LLM code ends here //
