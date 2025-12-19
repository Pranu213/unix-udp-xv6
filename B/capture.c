#define _GNU_SOURCE
#include "capture.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <sys/select.h>
#include <fcntl.h>

// LLM code starts here //

static pcap_t *global_handle = NULL;
static volatile sig_atomic_t global_stop = 0;
static volatile sig_atomic_t g_eof_detected = 0;
static unsigned long pkt_id = 0;

/* SIGINT handler to gracefully stop capture */
static void sigint_handler(int signo) {
    (void)signo;
    global_stop = 1;
    if (global_handle) pcap_breakloop(global_handle);
}

/* Utility: Identify common app protocols by port */
static const char *identify_app_by_port(uint16_t sport, uint16_t dport) {
    uint16_t p = ntohs(sport);
    uint16_t q = ntohs(dport);
    if (p == 80 || q == 80) return "HTTP";
    if (p == 443 || q == 443) return "HTTPS/TLS";
    if (p == 53 || q == 53) return "DNS";
    return "Unknown";
}

/* Print IPv4 flags nicely */
static void print_ipv4_flags(uint16_t frag_off) {
    uint16_t fo = ntohs(frag_off);
    int flags = (fo & 0xE000) >> 13;
    printf("Flags:");
    if (flags == 0) printf(" [none]");
    if (flags & 0x2) printf(" [Don't Fragment]");
    if (flags & 0x1) printf(" [More Fragments]");
}

/* Print first 64 bytes of payload in hex + ASCII */
static void print_payload_hex_ascii(const u_char *payload, int len) {
    int to_print = len < 64 ? len : 64;
    int offset = 0;
    while (to_print > 0) {
        int chunk = to_print >= 16 ? 16 : to_print;
        print_hex_ascii_line(payload + offset, chunk, offset);
        offset += chunk;
        to_print -= chunk;
    }
}

/* Check if this is Linux cooked-mode capture (used by 'any' interface) */
static int is_cooked_mode(const u_char *packet, uint32_t len) {
    if (len < 16) return 0;
    
    uint16_t pkt_type = ntohs(*(uint16_t*)packet);
    uint16_t arphrd = ntohs(*(uint16_t*)(packet + 2));
    
    uint8_t first_byte = packet[0];
    if ((first_byte & 0xF0) == 0x40 || (first_byte & 0xF0) == 0x60) {
        return 0;
    }
    
    return (pkt_type <= 4 && (arphrd == 1 || arphrd == 772 || arphrd == 0));
}

/* Check if this is a raw IP packet (no L2 header) */
static int is_raw_ip(const u_char *packet, uint32_t len) {
    if (len < 20) return 0;
    
    uint8_t version = (packet[0] & 0xF0) >> 4;
    return (version == 4 || version == 6);
}

/* L2-L7 packet handler */
static void handle_ethernet(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
    (void)user;
    pkt_id++;
    char tsbuf[64];
    ts_to_str(&h->ts, tsbuf, sizeof(tsbuf));
    printf("-----------------------------------------\n");
    printf("Packet #%lu | Timestamp: %s | Length: %u bytes\n", pkt_id, tsbuf, h->caplen);

    const u_char *payload;
    size_t payload_cap;
    uint16_t ether_type;
    
    if (is_raw_ip(packet, h->caplen)) {
        uint8_t version = (packet[0] & 0xF0) >> 4;
        if (version == 4) {
            printf("L2 (Raw): No Layer 2 header (loopback interface)\n");
            ether_type = ETHERTYPE_IP;
        } else if (version == 6) {
            printf("L2 (Raw): No Layer 2 header (loopback interface)\n");
            ether_type = ETHERTYPE_IPV6;
        } else {
            printf("L2 (Raw): Unknown IP version %d\n", version);
            return;
        }
        payload = packet;
        payload_cap = h->caplen;
    } else if (is_cooked_mode(packet, h->caplen)) {
        if (h->caplen < 16) {
            printf("Truncated cooked-mode header\n");
            return;
        }
        
        uint16_t pkt_type = ntohs(*(uint16_t*)packet);
        uint16_t arphrd = ntohs(*(uint16_t*)(packet + 2));
        uint16_t addr_len = ntohs(*(uint16_t*)(packet + 4));
        const u_char *addr = packet + 6;
        ether_type = ntohs(*(uint16_t*)(packet + 14));
        
        printf("L2 (Linux Cooked): Pkt Type: %u | ARPHRD: %u | Addr Len: %u\n", pkt_type, arphrd, addr_len);
        if (addr_len > 0 && addr_len <= 8) {
            printf("Address: ");
            for (int i = 0; i < addr_len && i < 6; i++) {
                printf("%02X", addr[i]);
                if (i < addr_len - 1) printf(":");
            }
            printf("\n");
        }
        
        payload = packet + 16;
        payload_cap = (h->caplen > 16) ? (h->caplen - 16) : 0;
    } else {
        if (h->caplen < sizeof(struct ether_header)) {
            printf("Truncated Ethernet header\n");
            return;
        }
        
        const struct ether_header *eth = (const struct ether_header *)packet;
        printf("L2 (Ethernet): Dst MAC: "); print_mac(eth->ether_dhost);
        printf(" | Src MAC: "); print_mac(eth->ether_shost); printf(" |\n");
        
        ether_type = ntohs(eth->ether_type);
        payload = packet + sizeof(struct ether_header);
        payload_cap = (h->caplen > sizeof(struct ether_header)) ? (h->caplen - sizeof(struct ether_header)) : 0;
    }

    if (ether_type == ETHERTYPE_IP) {
        printf("EtherType: IPv4 (0x%04x)\n", ether_type);
        if (payload_cap < sizeof(struct ip)) { printf("Truncated IPv4 header\n"); return; }
        const struct ip *ip4 = (const struct ip *)payload;
        char srcbuf[INET_ADDRSTRLEN], dstbuf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(ip4->ip_src), srcbuf, sizeof(srcbuf));
        inet_ntop(AF_INET, &(ip4->ip_dst), dstbuf, sizeof(dstbuf));
        int ip_hdr_len = ip4->ip_hl * 4;
        uint16_t total_len = ntohs(ip4->ip_len);
        const char *proto_name = (ip4->ip_p == IPPROTO_TCP) ? "TCP" : (ip4->ip_p == IPPROTO_UDP) ? "UDP" : "Unknown";

        printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s (%d) |\n",
               srcbuf, dstbuf, proto_name, ip4->ip_p);
        printf("TTL: %d\n", ip4->ip_ttl);
        printf("ID: 0x%04x | Total Length: %u | Header Length: %d bytes\n",
               ntohs(ip4->ip_id), total_len, ip_hdr_len);
        printf("  "); print_ipv4_flags(ip4->ip_off); printf("\n");

        if ((size_t)ip_hdr_len > payload_cap) { printf("Truncated IPv4 options/header\n"); return; }
        const u_char *l4 = payload + ip_hdr_len;
        size_t l4_len = (total_len > (uint16_t)ip_hdr_len) ? (size_t)(total_len - ip_hdr_len) : 0;
        if (l4_len > (payload_cap - ip_hdr_len)) l4_len = payload_cap - ip_hdr_len;

        if (ip4->ip_p == IPPROTO_TCP) {
            if (l4_len >= sizeof(struct tcphdr)) {
                const struct tcphdr *tcp = (const struct tcphdr *)l4;
                uint16_t sport = tcp->th_sport, dport = tcp->th_dport;
                uint32_t seq = ntohl(tcp->th_seq), ack = ntohl(tcp->th_ack);
                int tcp_hdr_len = tcp->th_off * 4;

                printf("L4 (TCP): Src Port: %u | Dst Port: %u | Seq: %u | Ack: %u |\n",
                       ntohs(sport), ntohs(dport), seq, ack);
                printf("Flags: ["); int first = 1;
                if (tcp->th_flags & TH_SYN) { if (!first) printf(","); printf("SYN"); first=0; }
                if (tcp->th_flags & TH_ACK) { if (!first) printf(","); printf("ACK"); first=0; }
                if (tcp->th_flags & TH_FIN) { if (!first) printf(","); printf("FIN"); first=0; }
                if (tcp->th_flags & TH_RST) { if (!first) printf(","); printf("RST"); first=0; }
                if (tcp->th_flags & TH_PUSH) { if (!first) printf(","); printf("PSH"); first=0; }
                if (tcp->th_flags & TH_URG) { if (!first) printf(","); printf("URG"); first=0; }
                printf("]\n");
                printf("Window: %u | Checksum: 0x%04X | Header Length: %d bytes\n",
                       ntohs(tcp->th_win), ntohs(tcp->th_sum), tcp_hdr_len);

                const u_char *app_payload = l4 + tcp_hdr_len;
                size_t app_payload_len = (l4_len > (size_t)tcp_hdr_len) ? (size_t)(l4_len - tcp_hdr_len) : 0;
                const char *app = identify_app_by_port(sport, dport);
                printf("L7 (Payload): Identified as %s on port %u/%u - %zu bytes\n",
                       app, ntohs(sport), ntohs(dport), app_payload_len);
                if (app_payload_len > 0) print_payload_hex_ascii(app_payload, (int)app_payload_len);
            } else printf("Truncated TCP segment\n");
        } else if (ip4->ip_p == IPPROTO_UDP) {
            if (l4_len >= sizeof(struct udphdr)) {
                const struct udphdr *udp = (const struct udphdr *)l4;
                uint16_t sport = udp->uh_sport, dport = udp->uh_dport;
                uint16_t ulen = ntohs(udp->uh_ulen);
                printf("L4 (UDP): Src Port: %u | Dst Port: %u | Length: %u | Checksum: 0x%04X\n",
                       ntohs(sport), ntohs(dport), ulen, ntohs(udp->uh_sum));
                const u_char *app_payload = l4 + sizeof(struct udphdr);
                size_t app_payload_len = (l4_len > sizeof(struct udphdr)) ? (size_t)(l4_len - sizeof(struct udphdr)) : 0;
                const char *app = identify_app_by_port(sport, dport);
                printf("L7 (Payload): Identified as %s on port %u/%u - %zu bytes\n",
                       app, ntohs(sport), ntohs(dport), app_payload_len);
                if (app_payload_len > 0) print_payload_hex_ascii(app_payload, (int)app_payload_len);
            } else printf("Truncated UDP datagram\n");
        } else printf("L4: Protocol not parsed\n");

    } else if (ether_type == ETHERTYPE_IPV6) {
        printf("EtherType: IPv6 (0x%04x)\n", ether_type);
        if (payload_cap < sizeof(struct ip6_hdr)) { printf("Truncated IPv6 header\n"); return; }
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)payload;
        char srcbuf[INET6_ADDRSTRLEN], dstbuf[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6->ip6_src), srcbuf, sizeof(srcbuf));
        inet_ntop(AF_INET6, &(ip6->ip6_dst), dstbuf, sizeof(dstbuf));
        uint8_t next = ip6->ip6_nxt;
        uint16_t payload_len = ntohs(ip6->ip6_plen);
        uint8_t hop = ip6->ip6_hlim;
        uint32_t vtcfl = ntohl(*(const uint32_t *)payload);
        uint8_t traffic_class = (vtcfl & 0x0FF00000) >> 20;
        uint32_t flow_label = vtcfl & 0x000FFFFF;

        const char *proto_name = (next==IPPROTO_TCP)?"TCP":(next==IPPROTO_UDP)?"UDP":"Unknown";
        printf("L3 (IPv6): Src IP: %s | Dst IP: %s | Next Header: %s (%d) | Hop Limit: %d\n",
               srcbuf,dstbuf,proto_name,next,hop);
        printf("Traffic Class: %u | Flow Label: 0x%05x | Payload Length: %u\n",
               traffic_class, flow_label, payload_len);

        const u_char *l4 = payload + sizeof(struct ip6_hdr);
        size_t l4_len = payload_len;
        if (l4_len > (payload_cap - sizeof(struct ip6_hdr))) l4_len = payload_cap - sizeof(struct ip6_hdr);

        if (next == IPPROTO_TCP) {
            if (l4_len >= sizeof(struct tcphdr)) {
                const struct tcphdr *tcp = (const struct tcphdr *)l4;
                uint16_t sport = tcp->th_sport, dport = tcp->th_dport;
                uint32_t seq = ntohl(tcp->th_seq), ack = ntohl(tcp->th_ack);
                int tcp_hdr_len = tcp->th_off * 4;

                printf("L4 (TCP): Src Port: %u | Dst Port: %u | Seq: %u | Ack: %u |\n",
                       ntohs(sport), ntohs(dport), seq, ack);
                printf("Flags: ["); int first=1;
                if (tcp->th_flags & TH_SYN){if(!first)printf(",");printf("SYN");first=0;}
                if (tcp->th_flags & TH_ACK){if(!first)printf(",");printf("ACK");first=0;}
                if (tcp->th_flags & TH_FIN){if(!first)printf(",");printf("FIN");first=0;}
                if (tcp->th_flags & TH_RST){if(!first)printf(",");printf("RST");first=0;}
                if (tcp->th_flags & TH_PUSH){if(!first)printf(",");printf("PSH");first=0;}
                if (tcp->th_flags & TH_URG){if(!first)printf(",");printf("URG");first=0;}
                printf("]\n");
                printf("Window: %u | Checksum: 0x%04X | Header Length: %d bytes\n",
                       ntohs(tcp->th_win), ntohs(tcp->th_sum), tcp_hdr_len);

                const u_char *app_payload = l4 + tcp_hdr_len;
                size_t app_payload_len = (l4_len > (size_t)tcp_hdr_len) ? (size_t)(l4_len - tcp_hdr_len) : 0;
                const char *app = identify_app_by_port(sport,dport);
                printf("L7 (Payload): Identified as %s on port %u/%u - %zu bytes\n",
                       app, ntohs(sport), ntohs(dport), app_payload_len);
                if(app_payload_len>0) print_payload_hex_ascii(app_payload,(int)app_payload_len);
            } else printf("Truncated TCP in IPv6\n");
        } else if (next==IPPROTO_UDP) {
            if(l4_len>=sizeof(struct udphdr)) {
                const struct udphdr *udp=(const struct udphdr *)l4;
                uint16_t sport=udp->uh_sport, dport=udp->uh_dport;
                uint16_t ulen=ntohs(udp->uh_ulen);
                printf("L4 (UDP): Src Port: %u | Dst Port: %u | Length: %u | Checksum: 0x%04X\n",
                       ntohs(sport),ntohs(dport),ulen,ntohs(udp->uh_sum));
                const u_char *app_payload=l4+sizeof(struct udphdr);
                size_t app_payload_len=(l4_len>sizeof(struct udphdr))?(l4_len-sizeof(struct udphdr)):0;
                const char *app=identify_app_by_port(sport,dport);
                printf("L7 (Payload): Identified as %s on port %u/%u - %zu bytes\n",
                       app,ntohs(sport),ntohs(dport),app_payload_len);
                if(app_payload_len>0) print_payload_hex_ascii(app_payload,(int)app_payload_len);
            } else printf("Truncated UDP in IPv6\n");
        } else printf("L4: not parsed for Next Header %d\n", next);

    } else if (ether_type == ETHERTYPE_ARP) {
        printf("EtherType: ARP (0x%04x)\n", ether_type);
        if (payload_cap < sizeof(struct arphdr)) { printf("Truncated ARP header\n"); return; }
        const struct arphdr *arp = (const struct arphdr *)payload;
        uint16_t ar_hrd = ntohs(arp->ar_hrd);
        uint16_t ar_pro = ntohs(arp->ar_pro);
        uint8_t ar_hln = arp->ar_hln;
        uint8_t ar_pln = arp->ar_pln;
        uint16_t ar_op = ntohs(arp->ar_op);

        const u_char *ptr = payload + sizeof(struct arphdr);
        char s_ip[INET_ADDRSTRLEN]="N/A", t_ip[INET_ADDRSTRLEN]="N/A";
        const u_char *sha=NULL, *spa=NULL, *tha=NULL, *tpa=NULL;

        if(payload_cap>=(size_t)(sizeof(struct arphdr)+2*ar_hln+2*ar_pln)){
            sha=ptr; ptr+=ar_hln;
            spa=ptr; ptr+=ar_pln;
            tha=ptr; ptr+=ar_hln;
            tpa=ptr; ptr+=ar_pln;
            if(ar_pln==4){
                inet_ntop(AF_INET,spa,s_ip,sizeof(s_ip));
                inet_ntop(AF_INET,tpa,t_ip,sizeof(t_ip));
            }
            printf("\nL3 (ARP): Operation: %s (%d) | Sender IP: %s | Target IP: %s\n",
                   (ar_op==ARPOP_REQUEST)?"Request":(ar_op==ARPOP_REPLY)?"Reply":"Other",ar_op,s_ip,t_ip);
            printf("Sender MAC: "); if(sha) print_mac(sha); else printf("N/A");
            printf(" | Target MAC: "); if(tha) print_mac(tha); else printf("N/A"); printf("\n");
            printf("HW Type: %u | Proto Type: 0x%04x | HW Len: %u | Proto Len: %u\n",
                   ar_hrd,ar_pro,ar_hln,ar_pln);
        } else printf("Truncated ARP payload\n");

    } else printf("EtherType: Unknown (0x%04x)\n", ether_type);
}

/* Packet handler that stores packets */
static void handle_ethernet_store(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
    PacketStore *store = (PacketStore *)user;
    handle_ethernet(NULL, h, packet);
    add_packet(store, h, packet);
}

/* Packet handler that stores packets with filtering */
static void handle_ethernet_filter_store(u_char *user, const struct pcap_pkthdr *h, const u_char *packet) {
    typedef struct { PacketStore *store; const PacketFilter *filter; } UserData;
    UserData *data = (UserData *)user;
    
    const u_char *payload;
    size_t payload_cap;
    uint16_t ether_type;
    
    if (is_raw_ip(packet, h->caplen)) {
        uint8_t version = (packet[0] & 0xF0) >> 4;
        if (version == 4) {
            ether_type = ETHERTYPE_IP;
        } else if (version == 6) {
            ether_type = ETHERTYPE_IPV6;
        } else {
            return;
        }
        payload = packet;
        payload_cap = h->caplen;
    } else if (is_cooked_mode(packet, h->caplen)) {
        if (h->caplen < 16) return;
        ether_type = ntohs(*(uint16_t*)(packet + 14));
        payload = packet + 16;
        payload_cap = (h->caplen > 16) ? (h->caplen - 16) : 0;
    } else {
        if (h->caplen < sizeof(struct ether_header)) return;
        const struct ether_header *eth = (const struct ether_header *)packet;
        ether_type = ntohs(eth->ether_type);
        payload = packet + sizeof(struct ether_header);
        payload_cap = (h->caplen > sizeof(struct ether_header)) ? (h->caplen - sizeof(struct ether_header)) : 0;
    }
    
    if (data->filter->filter_type == FILTER_ARP) {
        if (ether_type != ETHERTYPE_ARP) return;
    } else if (ether_type == ETHERTYPE_IP && payload_cap >= sizeof(struct ip)) {
        const struct ip *ip4 = (const struct ip *)payload;
        
        if (data->filter->protocol != 0 && ip4->ip_p != data->filter->protocol) return;
        
        if (strlen(data->filter->src_ip) > 0 || strlen(data->filter->dst_ip) > 0) {
            char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(ip4->ip_src), src_ip_str, sizeof(src_ip_str));
            inet_ntop(AF_INET, &(ip4->ip_dst), dst_ip_str, sizeof(dst_ip_str));
            
            if (strlen(data->filter->src_ip) > 0 && strcmp(src_ip_str, data->filter->src_ip) != 0) return;
            if (strlen(data->filter->dst_ip) > 0 && strcmp(dst_ip_str, data->filter->dst_ip) != 0) return;
        }
        
        if (ip4->ip_p == IPPROTO_TCP || ip4->ip_p == IPPROTO_UDP) {
            int ip_hdr_len = ip4->ip_hl * 4;
            const u_char *l4 = payload + ip_hdr_len;
            size_t l4_available = (payload_cap > ip_hdr_len) ? (payload_cap - ip_hdr_len) : 0;
            
            if (l4_available >= 4) {
                uint16_t sport = ntohs(*(const uint16_t *)(l4 + 0));
                uint16_t dport = ntohs(*(const uint16_t *)(l4 + 2));
                
                switch (data->filter->filter_type) {
                    case FILTER_HTTP:
                        if (sport != 80 && dport != 80) return;
                        break;
                    case FILTER_HTTPS:
                        if (sport != 443 && dport != 443) return;
                        break;
                    case FILTER_DNS:
                        if (sport != 53 && dport != 53) return;
                        break;
                    case FILTER_TCP:
                        if (ip4->ip_p != IPPROTO_TCP) return;
                        break;
                    case FILTER_UDP:
                        if (ip4->ip_p != IPPROTO_UDP) return;
                        break;
                    default:
                        if (data->filter->src_port != 0 && sport != data->filter->src_port) return;
                        if (data->filter->dst_port != 0 && dport != data->filter->dst_port) return;
                        break;
                }
            }
        }
    } else if (ether_type == ETHERTYPE_IPV6 && payload_cap >= sizeof(struct ip6_hdr)) {
        const struct ip6_hdr *ip6 = (const struct ip6_hdr *)payload;
        uint8_t next_header = ip6->ip6_nxt;
        
        if (data->filter->protocol != 0 && next_header != data->filter->protocol) return;
        
        if (next_header == IPPROTO_TCP || next_header == IPPROTO_UDP) {
            const u_char *l4 = payload + sizeof(struct ip6_hdr);
            size_t l4_available = (payload_cap > sizeof(struct ip6_hdr)) ? (payload_cap - sizeof(struct ip6_hdr)) : 0;
            
            if (l4_available >= 4) {
                uint16_t sport = ntohs(*(const uint16_t *)(l4 + 0));
                uint16_t dport = ntohs(*(const uint16_t *)(l4 + 2));
                
                switch (data->filter->filter_type) {
                    case FILTER_HTTP:
                        if (sport != 80 && dport != 80) return;
                        break;
                    case FILTER_HTTPS:
                        if (sport != 443 && dport != 443) return;
                        break;
                    case FILTER_DNS:
                        if (sport != 53 && dport != 53) return;
                        break;
                    case FILTER_TCP:
                        if (next_header != IPPROTO_TCP) return;
                        break;
                    case FILTER_UDP:
                        if (next_header != IPPROTO_UDP) return;
                        break;
                    default:
                        if (data->filter->src_port != 0 && sport != data->filter->src_port) return;
                        if (data->filter->dst_port != 0 && dport != data->filter->dst_port) return;
                        break;
                }
            }
        }
    } else if (data->filter->filter_type != FILTER_ALL) {
        return;
    }
    
    handle_ethernet(NULL, h, packet);
    add_packet(data->store, h, packet);
}

/* Start capture with packet storage */
int start_capture_store(const char *devname, PacketStore *store) {
    char errbuf[PCAP_ERRBUF_SIZE];
    global_handle = pcap_open_live(devname, 65535, 1, 1000, errbuf);
    if (!global_handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return -1;
    }
    
    if (pcap_setnonblock(global_handle, 1, errbuf) == -1) {
        fprintf(stderr, "Warning: Could not set non-blocking mode: %s\n", errbuf);
    }
    
    start_new_session(store);
    
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    
    printf("[C-Shark] Starting capture with storage on %s — press Ctrl+C to stop, Ctrl+D to exit.\n", devname);
    
    g_eof_detected = 0;
    global_stop = 0;
    
  while (!global_stop && !g_eof_detected) {
        fd_set readfds;
        struct timeval tv;
        
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        
        int select_ret = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv);
        
        if (select_ret > 0 && FD_ISSET(STDIN_FILENO, &readfds)) {
            int c = getchar();
            if (c == EOF) {
                printf("\n\nDetected EOF (Ctrl+D). Exiting C-Shark.\n");
                g_eof_detected = 1;
                break;
            }
        }
        
        int ret = pcap_dispatch(global_handle, 10, handle_ethernet_store, (u_char *)store);
        if (ret == -1) {
            fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(global_handle));
            break;
        }
    }
    
    pcap_close(global_handle);
    global_handle = NULL;
    global_stop = 0;
    
    if (g_eof_detected) {
        return -2;
    }
    
    printf("[C-Shark] Capture stopped. Stored %d packets. Returning to main menu.\n", store->count);
    return 0;
}

/* Start capture with packet storage and filtering */
int start_capture_store_with_filter(const char *devname, PacketStore *store, const PacketFilter *filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    global_handle = pcap_open_live(devname, 65535, 1, 1000, errbuf);
    if (!global_handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return -1;
    }
    
    if (pcap_setnonblock(global_handle, 1, errbuf) == -1) {
        fprintf(stderr, "Warning: Could not set non-blocking mode: %s\n", errbuf);
    }
    
    start_new_session(store);
    
    struct sigaction sa;
    sa.sa_handler = sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    
    typedef struct { PacketStore *store; const PacketFilter *filter; } UserData;
    UserData user_data = { store, filter };
    
    printf("[C-Shark] Starting filtered capture with storage on %s — press Ctrl+C to stop, Ctrl+D to exit.\n", devname);
    
    g_eof_detected = 0;
    global_stop = 0;
    
    while (!global_stop && !g_eof_detected) {
        fd_set readfds;
        struct timeval tv;
        
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        
        int select_ret = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv);
        
        if (select_ret > 0 && FD_ISSET(STDIN_FILENO, &readfds)) {
            int c = getchar();
            if (c == EOF) {
                printf("\n\nDetected EOF (Ctrl+D). Exiting C-Shark.\n");
                g_eof_detected = 1;
                break;
            }
        }
        
        int ret = pcap_dispatch(global_handle, 10, handle_ethernet_filter_store, (u_char *)&user_data);
        if (ret == -1) {
            fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(global_handle));
            break;
        }
    }
    
    pcap_close(global_handle);
    global_handle = NULL;
    global_stop = 0;
    
    if (g_eof_detected) {
        return -2;
    }
    
    printf("[C-Shark] Filtered capture stopped. Stored %d packets. Returning to main menu.\n", store->count);
    return 0;
}
// LLM code ends here //
