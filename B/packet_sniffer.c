// src/packet_sniffer.c
#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE
#include <sys/types.h>
#include <sys/select.h>
#include <fcntl.h>
#include <stdint.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include "packet_sniffer.h"
#include "display.h"

// LLM code starts here //

static pcap_t *g_handle = NULL;
static volatile sig_atomic_t g_in_capture = 0;
static volatile sig_atomic_t g_packet_id = 0;
static volatile sig_atomic_t g_eof_detected = 0;

// Signal handler — used to break the pcap_loop
static void internal_sigint_handler(int signo) {
    (void)signo;
    if (g_in_capture && g_handle != NULL) {
        // Ask libpcap to break out of pcap_loop
        pcap_breakloop(g_handle);
    } else {
        // If not in capture, just print helpful message and return to prompt
        puts("\n(Ctrl+C pressed) Not capturing — use Ctrl+D to exit or continue.");
    }
}

void register_signal_handlers(void) {
    struct sigaction sa;
    sa.sa_handler = internal_sigint_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
}

// callback for every captured packet
static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    g_packet_id++;
    print_basic_packet(g_packet_id, h, bytes);
}

void start_sniffer(const char *device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    g_packet_id = 0;
    g_eof_detected = 0;
    
    // Open device for live capture
    g_handle = pcap_open_live(device, BUFSIZ, 1, 1000, errbuf);
    if (!g_handle) {
        fprintf(stderr, "Error opening device %s: %s\n", device, errbuf);
        return;
    }
    
    // Set non-blocking mode for pcap
    if (pcap_setnonblock(g_handle, 1, errbuf) == -1) {
        fprintf(stderr, "Warning: Could not set non-blocking mode: %s\n", errbuf);
    }
    
    printf("\n[C-Shark] Sniffing on device %s ... (Press Ctrl+C to stop, Ctrl+D to exit)\n", device);
    
    g_in_capture = 1;
    
    // Loop with timeout to check for EOF
    while (g_in_capture && !g_eof_detected) {
        // Use select() to check if stdin has data (EOF)
        fd_set readfds;
        struct timeval tv;
        
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        
        // 100ms timeout
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        
        int select_ret = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv);
        
        if (select_ret > 0 && FD_ISSET(STDIN_FILENO, &readfds)) {
            // stdin is readable - check if it's EOF
            int c = getchar();
            if (c == EOF) {
                puts("\n\nDetected EOF (Ctrl+D). Exiting C-Shark.");
                g_eof_detected = 1;
                break;
            }
            // If it's not EOF (e.g., user typed something), ignore it
        }
        
        // Capture a few packets with timeout
        int ret = pcap_dispatch(g_handle, 10, packet_handler, NULL);
        if (ret == -1) {
            fprintf(stderr, "pcap_dispatch error: %s\n", pcap_geterr(g_handle));
            break;
        }
    }
    
    if (g_eof_detected) {
        // Propagate EOF exit back to main menu
        // You might want to set a global flag here
        g_in_capture = 0;
    } else if (g_in_capture) {
        // Normal Ctrl+C exit
        puts("\nCapture stopped by user (Ctrl+C). Returning to main menu.");
        g_in_capture = 0;
    }
    
    pcap_close(g_handle);
    g_handle = NULL;
    return;
}

// list interfaces and prompt user to choose one
int list_and_choose_interface(char *chosen_dev, size_t len) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error finding devices: %s\n", errbuf);
        return -1;
    }
    
    if (!alldevs) {
        fprintf(stderr, "No devices found.\n");
        return -1;
    }
    
    printf("[C-Shark] Searching for available interfaces... Found!\n\n");
    
    pcap_if_t *d;
    int i = 0;
    for (d = alldevs; d; d = d->next) {
        i++;
        printf("%2d. %s", i, d->name);
        if (d->description) {
            printf(" - %s", d->description);
        }
        printf("\n");
    }
    
    // Prompt
    char buf[64];
    while (1) {
        printf("\nSelect an interface to sniff (1-%d): ", i);
        if (!fgets(buf, sizeof(buf), stdin)) {
            // Ctrl+D => cleanup and exit
            puts("\nDetected EOF (Ctrl+D). Exiting.");
            pcap_freealldevs(alldevs);
            return -1;
        }
        
        int choice = atoi(buf);
        if (choice >= 1 && choice <= i) {
            // find the selected device
            int idx = 1;
            for (d = alldevs; d; d = d->next, idx++) {
                if (idx == choice) {
                    strncpy(chosen_dev, d->name, len-1);
                    chosen_dev[len-1] = '\0';
                    pcap_freealldevs(alldevs);
                    return 0;
                }
            }
        }
        printf("Invalid choice. Try again or press Ctrl+D to exit.\n");
    }
    
    // unreachable
    pcap_freealldevs(alldevs);
    return -1;
}
// LLM code ends here //
