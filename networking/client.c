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

#define CLIENT_RECV_BUF_BYTES (SHAM_PAYLOAD_SIZE * 1000)

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

//LLM CODE BEGINS
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

//LLM CODE ENDS

static void usage_and_exit(const char *prog) {
    fprintf(stderr, "Usage: %s <server_ip> <port> [--chat] [loss_rate]\n", prog);
    exit(1);
}

int main(int argc, char **argv) {
    if (argc < 3) usage_and_exit(argv[0]);

    const char *server_ip = argv[1];
    int port = atoi(argv[2]);
    int chat_mode = 0;
    double loss_rate = 0.0;

    // Parse arguments
    for (int i = 3; i < argc; i++) {
        if (strcmp(argv[i], "--chat") == 0) {
            chat_mode = 1;
        } else {
            loss_rate = atof(argv[i]);
        }
    }

    srand((unsigned)time(NULL) ^ (unsigned)getpid());

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { perror("socket"); return 1; }

    struct sockaddr_in server;
    socklen_t serverlen = sizeof(server);
    memset(&server, 0, sizeof(server));
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    if (inet_pton(AF_INET, server_ip, &server.sin_addr) <= 0) {
        perror("inet_pton"); close(sock); return 1;
    }

    printf("Client connecting to %s:%d%s\n", server_ip, port, chat_mode ? " [chat]" : "");

    uint32_t client_isn = (uint32_t)(rand() % 1000000) + 1;
    uint32_t server_isn = 0;

    // Three-way handshake
    printf("Starting handshake...\n");
    
    // Step 1: Send SYN
    struct sham_header syn_hdr = { client_isn, 0, SHAM_SYN, (uint16_t)CLIENT_RECV_BUF_BYTES };
    if (send_sham_packet(sock, &server, serverlen, &syn_hdr, NULL, 0, "client") < 0) {
        perror("send SYN");
        close(sock);
        return 1;
    }

    // Step 2: Wait for SYN-ACK
    struct sham_header rh;
    uint8_t tmp[SHAM_PAYLOAD_SIZE];
    ssize_t p = recv_sham_packet(sock, &rh, tmp, &server, &serverlen);
    if (p < 0 || (rh.flags & (SHAM_SYN|SHAM_ACK)) != (SHAM_SYN|SHAM_ACK) || rh.ack_num != client_isn + 1) {
        fprintf(stderr, "Handshake failed - invalid SYN-ACK\n");
        close(sock);
        return 1;
    }
    
    server_isn = rh.seq_num;
    printf("Received SYN-ACK from server\n");

    // Step 3: Send final ACK
    struct sham_header ack_hdr = { client_isn + 1, server_isn + 1, SHAM_ACK, (uint16_t)CLIENT_RECV_BUF_BYTES };
    if (send_sham_packet(sock, &server, serverlen, &ack_hdr, NULL, 0, "client") < 0) {
        perror("send ACK");
        close(sock);
        return 1;
    }

    printf("Handshake completed successfully!\n");

    // Chat mode
    if (chat_mode) {
        printf("=== CHAT MODE ===\n");
        printf("Type your messages (type 'quit' to exit):\n");
        printf("> ");
        fflush(stdout);
        
        fd_set readfds;
        int maxfd = (sock > STDIN_FILENO ? sock : STDIN_FILENO) + 1;
        int running = 1;
        uint32_t my_seq = client_isn + 1;
        
        while (running) {
            FD_ZERO(&readfds);
            FD_SET(STDIN_FILENO, &readfds);
            FD_SET(sock, &readfds);

            int activity = select(maxfd, &readfds, NULL, NULL, NULL);
            if (activity < 0) {
                perror("select");
                break;
            }

            //LLLM CODE BEGIN
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
                        struct sham_header data_hdr = { my_seq, 0, 0, (uint16_t)CLIENT_RECV_BUF_BYTES };
                        ssize_t sent = send_sham_packet(sock, &server, serverlen, &data_hdr, buffer, len, "client");
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

            // Handle incoming data
            if (FD_ISSET(sock, &readfds)) {
                struct sham_header recv_hdr;
                uint8_t payload[SHAM_PAYLOAD_SIZE];
                struct sockaddr_in from;
                socklen_t fromlen = sizeof(from);

                ssize_t plen = recv_sham_packet(sock, &recv_hdr, payload, &from, &fromlen);
                if (plen > 0) {
                    payload[plen] = '\0';  // Null terminate
                    printf("\nServer says: %s\n", (char*)payload);
                    printf("> ");
                    fflush(stdout);
                }
            }
            //LLM CODE ENDS
        }
    }

    close(sock);
    return 0;
}