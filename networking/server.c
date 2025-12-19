#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <errno.h>
#include <openssl/md5.h>

#include "sham.h"

#define SERVER_RECV_BUF_BYTES (SHAM_PAYLOAD_SIZE * 1000)

uint64_t now_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

static void header_hton(struct sham_header *h) {
    h->seq_num = htonl(h->seq_num);
    h->ack_num = htonl(h->ack_num);
    h->flags = htons(h->flags);
    h->window_size = htons(h->window_size);
}

static void header_ntoh(struct sham_header *h) {
    h->seq_num = ntohl(h->seq_num);
    h->ack_num = ntohl(h->ack_num);
    h->flags = ntohs(h->flags);
    h->window_size = ntohs(h->window_size);
}

//llm code begins
static ssize_t send_sham_packet(int sock, struct sockaddr_in *peer, socklen_t peerlen,
                                struct sham_header *hdr, const void *payload, size_t payload_len,
                                const char *role)
{
    uint8_t buf[sizeof(struct sham_header) + SHAM_PAYLOAD_SIZE];
    struct sham_header hnet = *hdr;
    header_hton(&hnet);
    memcpy(buf, &hnet, sizeof(hnet));
    if (payload && payload_len > 0) memcpy(buf + sizeof(hnet), payload, payload_len);
    ssize_t s = sendto(sock, buf, sizeof(hnet) + payload_len, 0, (struct sockaddr*)peer, peerlen);

    if (get_log_file(role)) {
        if ((hdr->flags & SHAM_SYN) && (hdr->flags & SHAM_ACK)) {
            log_event(role, "SND SYN-ACK SEQ=%u ACK=%u", hdr->seq_num, hdr->ack_num);
        } else if (hdr->flags & SHAM_SYN) {
            log_event(role, "SND SYN SEQ=%u", hdr->seq_num);
        } else if (hdr->flags & SHAM_FIN) {
            log_event(role, "SND FIN SEQ=%u", hdr->seq_num);
        } else if (hdr->flags & SHAM_ACK && payload_len == 0) {
            log_event(role, "SND ACK=%u WIN=%u", hdr->ack_num, hdr->window_size);
        } else if (payload_len > 0) {
            log_event(role, "SND DATA SEQ=%u LEN=%zu", hdr->seq_num, payload_len);
        }
    }
    return s;
}

static ssize_t recv_sham_packet(int sock, struct sham_header *hdr, uint8_t *payload,
                                struct sockaddr_in *from, socklen_t *fromlen)
{
    uint8_t buf[sizeof(struct sham_header) + SHAM_PAYLOAD_SIZE];
    ssize_t r = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)from, fromlen);
    if (r < (ssize_t)sizeof(struct sham_header)) return -1;
    memcpy(hdr, buf, sizeof(*hdr));
    header_ntoh(hdr);
    ssize_t payload_len = r - (ssize_t)sizeof(*hdr);
    if (payload_len > 0 && payload) memcpy(payload, buf + sizeof(*hdr), payload_len);
    return payload_len;
}

//llm code ends

static void usage_and_exit(const char *prog) {
    fprintf(stderr, "Usage: %s <port> [--chat] [loss_rate]\n", prog);
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 2) usage_and_exit(argv[0]);

    int port = atoi(argv[1]);
    int chat_mode = 0;
    double loss_rate = 0.0;

    // Parse arguments
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--chat") == 0) {
            chat_mode = 1;
        } else {
            loss_rate = atof(argv[i]);
        }
    }

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in local = {0};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = INADDR_ANY;
    local.sin_port = htons(port);
    if (bind(sock, (struct sockaddr*)&local, sizeof(local)) < 0) { 
        perror("bind"); 
        close(sock); 
        return 1; 
    }

    printf("Server listening on port %d%s\n", port, chat_mode ? " [chat mode]" : "");

    uint32_t server_isn = (uint32_t)(rand() % 1000000) + 1;
    uint32_t client_isn = 0;
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);

    printf("Waiting for client connection...\n");

    //llm code begins
    // Three-way handshake
    while (1) {
        struct sham_header rh;
        uint8_t payload[SHAM_PAYLOAD_SIZE];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);

        // Step 1: Wait for SYN
        ssize_t plen = recv_sham_packet(sock, &rh, payload, &from, &fromlen);
        if (plen < 0) continue;

        if ((rh.flags & SHAM_SYN) && !(rh.flags & SHAM_ACK)) {
            client_isn = rh.seq_num;
            client_addr = from;
            client_len = fromlen;
            
            printf("Received SYN from client (seq=%u)\n", client_isn);

            // Step 2: Send SYN-ACK
            struct sham_header synack_hdr = { 
                server_isn, 
                client_isn + 1, 
                SHAM_SYN | SHAM_ACK, 
                (uint16_t)SERVER_RECV_BUF_BYTES 
            };
            
            if (send_sham_packet(sock, &from, fromlen, &synack_hdr, NULL, 0, "server") < 0) {
                perror("send SYN-ACK");
                continue;
            }
            
            printf("Sent SYN-ACK to client\n");

            // Step 3: Wait for final ACK
            struct sham_header ack_hdr;
            uint8_t tmp[SHAM_PAYLOAD_SIZE];
            struct sockaddr_in ack_from;
            socklen_t ack_fromlen = sizeof(ack_from);

            ssize_t ack_len = recv_sham_packet(sock, &ack_hdr, tmp, &ack_from, &ack_fromlen);
            if (ack_len >= 0 && 
                (ack_hdr.flags & SHAM_ACK) && 
                !(ack_hdr.flags & SHAM_SYN) &&
                ack_hdr.seq_num == client_isn + 1 &&
                ack_hdr.ack_num == server_isn + 1) {
                
                printf("Received final ACK - handshake complete!\n");
                break;
            } else {
                printf("Invalid ACK received, waiting for new connection...\n");
            }
        }
    }

    // Chat mode
    if (chat_mode) {
        printf("=== CHAT MODE ===\n");
        printf("Type your messages (type 'quit' to exit):\n");
        printf("> ");
        fflush(stdout);
        
        fd_set readfds;
        int maxfd = (sock > STDIN_FILENO ? sock : STDIN_FILENO) + 1;
        int running = 1;
        uint32_t my_seq = server_isn + 1;
        
        while (running) {
            FD_ZERO(&readfds);
            FD_SET(STDIN_FILENO, &readfds);
            FD_SET(sock, &readfds);

            int activity = select(maxfd, &readfds, NULL, NULL, NULL);
            if (activity < 0) {
                perror("select");
                break;
            }

            // Handle user input
            if (FD_ISSET(STDIN_FILENO, &readfds)) {
                char buffer[1000];
                
                if (fgets(buffer, sizeof(buffer), stdin)) {
                    // Remove newline
                    size_t len = strlen(buffer);
                    if (len > 0 && buffer[len-1] == '\n') {
                        buffer[len-1] = '\0';
                        len--;
                    }
                    
                    if (strcmp(buffer, "quit") == 0) {
                        running = 0;
                        continue;
                    }
                    
                    if (len > 0) {
                        struct sham_header data_hdr = { my_seq, 0, 0, (uint16_t)SERVER_RECV_BUF_BYTES };
                        ssize_t sent = send_sham_packet(sock, &client_addr, client_len, &data_hdr, buffer, len, "server");
                        if (sent > 0) {
                            my_seq += len;
                            printf("Sent: %s\n", buffer);
                        } else {
                            printf("Failed to send message\n");
                        }
                    }
                    printf("> ");
                    fflush(stdout);
                } else {
                    // EOF on stdin - exit chat mode
                    running = 0;
                    printf("\nEOF on stdin, exiting chat mode\n");
                }
            }
//llm code ends

            // Handle incoming data
            if (FD_ISSET(sock, &readfds)) {
                struct sham_header recv_hdr;
                uint8_t payload[SHAM_PAYLOAD_SIZE];
                struct sockaddr_in from;
                socklen_t fromlen = sizeof(from);

                ssize_t plen = recv_sham_packet(sock, &recv_hdr, payload, &from, &fromlen);
                if (plen > 0) {
                    payload[plen] = '\0';  // Null terminate
                    printf("\nClient says: %s\n", (char*)payload);
                    printf("> ");
                    fflush(stdout);
                }
            }
        }
    }

    close(sock);
    return 0;
}