#include "filters.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

// LLM code starts here //

void init_filter(PacketFilter *filter) {
    filter->filter_type = FILTER_ALL;
    filter->protocol = 0;        // match any
    filter->src_ip[0] = '\0';    // empty = any
    filter->dst_ip[0] = '\0';
    filter->src_port = 0;
    filter->dst_port = 0;
}

void set_filter(PacketFilter *filter, int protocol,
                const char *src_ip, const char *dst_ip,
                int src_port, int dst_port) {
    filter->protocol = protocol;

    if (src_ip != NULL) {
        strncpy(filter->src_ip, src_ip, sizeof(filter->src_ip) - 1);
        filter->src_ip[sizeof(filter->src_ip) - 1] = '\0';
    }
    if (dst_ip != NULL) {
        strncpy(filter->dst_ip, dst_ip, sizeof(filter->dst_ip) - 1);
        filter->dst_ip[sizeof(filter->dst_ip) - 1] = '\0';
    }

    filter->src_port = src_port;
    filter->dst_port = dst_port;
}

bool packet_matches_filter(const PacketFilter *filter,
                           const struct pcap_pkthdr *header,
                           const u_char *packet) {
    // Parse Ethernet header
    const struct ether_header *eth = (struct ether_header *) packet;
    uint16_t ether_type = ntohs(eth->ether_type);
    
    // Handle ARP filter specifically
    if (filter->filter_type == FILTER_ARP) {
        return (ether_type == ETHERTYPE_ARP);
    }
    
    // For all other filters, we need IP packets
    if (ether_type != ETHERTYPE_IP) {
        return false;
    }

    // Parse IP header
    const struct ip *ip_hdr = (struct ip *)(packet + sizeof(struct ether_header));

    // Check protocol (if set)
    if (filter->protocol != 0 && ip_hdr->ip_p != filter->protocol) {
        return false;
    }

    char src_ip[16], dst_ip[16];
    strncpy(src_ip, inet_ntoa(ip_hdr->ip_src), sizeof(src_ip) - 1);
    src_ip[sizeof(src_ip) - 1] = '\0';
    strncpy(dst_ip, inet_ntoa(ip_hdr->ip_dst), sizeof(dst_ip) - 1);
    dst_ip[sizeof(dst_ip) - 1] = '\0';

    // Check source IP
    if (strlen(filter->src_ip) > 0 && strcmp(filter->src_ip, src_ip) != 0) {
        return false;
    }

    // Check destination IP
    if (strlen(filter->dst_ip) > 0 && strcmp(filter->dst_ip, dst_ip) != 0) {
        return false;
    }

    // Check ports if TCP/UDP
    if (ip_hdr->ip_p == IPPROTO_TCP) {
        const struct tcphdr *tcp_hdr = (struct tcphdr *)((u_char *)ip_hdr + ip_hdr->ip_hl * 4);
        uint16_t src_port = ntohs(tcp_hdr->th_sport);
        uint16_t dst_port = ntohs(tcp_hdr->th_dport);

        // For specific protocol filters, check if either port matches
        if (filter->filter_type == FILTER_HTTP) {
            return (src_port == 80 || dst_port == 80);
        }
        if (filter->filter_type == FILTER_HTTPS) {
            return (src_port == 443 || dst_port == 443);
        }
        
        // For general port filters
        if (filter->src_port != 0 && src_port != filter->src_port)
            return false;
        if (filter->dst_port != 0 && dst_port != filter->dst_port)
            return false;

    } else if (ip_hdr->ip_p == IPPROTO_UDP) {
        const struct udphdr *udp_hdr = (struct udphdr *)((u_char *)ip_hdr + ip_hdr->ip_hl * 4);
        uint16_t src_port = ntohs(udp_hdr->uh_sport);
        uint16_t dst_port = ntohs(udp_hdr->uh_dport);

        // For DNS filter, check if either port matches
        if (filter->filter_type == FILTER_DNS) {
            return (src_port == 53 || dst_port == 53);
        }
        
        // For general port filters
        if (filter->src_port != 0 && src_port != filter->src_port)
            return false;
        if (filter->dst_port != 0 && dst_port != filter->dst_port)
            return false;
    }

    // Passed all checks
    return true;
}

void set_filter_by_type(PacketFilter *filter, FilterType type) {
    init_filter(filter);
    filter->filter_type = type;
    
    switch (type) {
        case FILTER_HTTP:
            filter->protocol = IPPROTO_TCP;
            filter->src_port = 80;
            filter->dst_port = 80;
            break;
        case FILTER_HTTPS:
            filter->protocol = IPPROTO_TCP;
            filter->src_port = 443;
            filter->dst_port = 443;
            break;
        case FILTER_DNS:
            filter->protocol = IPPROTO_UDP;
            filter->src_port = 53;
            filter->dst_port = 53;
            break;
        case FILTER_ARP:
            // ARP doesn't use IP protocol field, handled separately
            filter->protocol = 0;
            break;
        case FILTER_TCP:
            filter->protocol = IPPROTO_TCP;
            break;
        case FILTER_UDP:
            filter->protocol = IPPROTO_UDP;
            break;
        case FILTER_ALL:
        default:
            // Already initialized to match all
            break;
    }
}

const char* get_filter_type_name(FilterType type) {
    switch (type) {
        case FILTER_HTTP: return "HTTP";
        case FILTER_HTTPS: return "HTTPS";
        case FILTER_DNS: return "DNS";
        case FILTER_ARP: return "ARP";
        case FILTER_TCP: return "TCP";
        case FILTER_UDP: return "UDP";
        case FILTER_ALL: return "All Packets";
        default: return "Unknown";
    }
}
// LLM code ends here //
