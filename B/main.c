#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>

#include "packet_sniffer.h"
#include "interface.h"
#include "capture.h"
#include "utils.h"
#include "packet_store.h"
#include "filters.h"
#include "display.h"

// LLM code starts here //

/* Helper: read integer with default if blank or EOF */
static int read_int_default(const char *prompt, int def) {
    char buf[64];
    printf("%s", prompt);
    if (safe_getline(buf, sizeof(buf)) == -1) return def;
    if (buf[0] == '\0') return def;
    return atoi(buf);
}

/* Helper: read a trimmed string from user */
static void read_string_prompt(const char *prompt, char *out, size_t outsz) {
    char buf[256];
    printf("%s", prompt);
    if (safe_getline(buf, sizeof(buf)) == -1) {
        out[0] = '\0';
        return;
    }
    size_t i = 0, j = strlen(buf);
    while (i < j && isspace((unsigned char)buf[i])) i++;
    while (j > i && isspace((unsigned char)buf[j-1])) j--;
    size_t len = (j > i) ? (j - i) : 0;
    if (len >= outsz) len = outsz - 1;
    if (len > 0) memcpy(out, buf + i, len);
    out[len] = '\0';
}

/* Signal handler for Ctrl+D in main menu */
static volatile sig_atomic_t g_exit_requested = 0;
static void handle_sigint_main(int signo) {
    (void)signo;
    /* do nothing; Ctrl+C handled inside capture */
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0); /* unbuffered stdout for live display */
    printf("[C-Shark] The Command-Line Packet Predator\n");
    printf("==============================================\n");

    /* Register signal handler to ignore Ctrl+C in main menu */
    struct sigaction sa;
    sa.sa_handler = handle_sigint_main;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    /* Register Ctrl+C for capture */
    register_signal_handlers();

    dev_list_t list = {0};
    char errbuf[PCAP_ERRBUF_SIZE];

    if (list_devices(&list, errbuf, NULL) == -1) {
        fprintf(stderr, "Error discovering devices: %s\n", errbuf);
        return 1;
    }

    if (list.count == 0) {
        printf("No devices found. Exiting.\n");
        free_devices(&list);
        return 0;
    }

    print_device_list(&list);

    char line[256];
    int idx = -1;
    while (1) {
        printf("\nSelect an interface to sniff (1-%d): ", list.count);
        if (safe_getline(line, sizeof(line)) == -1) {
            printf("\nDetected EOF (Ctrl+D). Exiting.\n");
            free_devices(&list);
            return 0;
        }
        idx = atoi(line);
        if (idx >= 1 && idx <= list.count) break;
        printf("Invalid selection. Try again.\n");
    }

    const char *devname = get_device_name_by_index(&list, idx);
    if (!devname) {
        fprintf(stderr, "Unable to resolve device name.\n");
        free_devices(&list);
        return 1;
    }

    printf("[C-Shark] Interface '%s' selected. What's next?\n\n", devname);

    /* Prepare packet store */
    PacketStore store;
    init_packet_store(&store);

    int exit_now = 0;
    while (!exit_now) {
        printf("\nMain Menu:\n\n");
        printf("1. Start Sniffing (All Packets)\n");
        printf("2. Start Sniffing (With Filters)\n");
        printf("3. Inspect Last Session\n");
        printf("4. Exit C-Shark\n\n");
        printf("Select an option (1-4): ");

        if (safe_getline(line, sizeof(line)) == -1) {
            printf("\nDetected EOF (Ctrl+D). Exiting.\n");
            break;
        }
        int opt = atoi(line);

        switch (opt) {
            case 1:
                printf("[C-Shark] Starting capture (all packets) on %s\n", devname);
                if (start_capture_store(devname, &store) != 0) {
                    fprintf(stderr, "Capture failed or returned error.\n");
                } else {
                    printf("\nCapture session ended. Returned to main menu.\n");
                }
                break;

            case 2: {
                printf("\n[C-Shark] Filter Configuration\n");
                printf("Choose a filter type:\n\n");
                printf("1. HTTP (port 80)\n");
                printf("2. HTTPS (port 443)\n");
                printf("3. DNS (port 53)\n");
                printf("4. ARP\n");
                printf("5. TCP (all TCP traffic)\n");
                printf("6. UDP (all UDP traffic)\n");
                printf("7. Custom filter (advanced)\n\n");
                printf("Select filter type (1-7): ");

                PacketFilter filter;
                init_filter(&filter);

                if (safe_getline(line, sizeof(line)) == -1) {
                    printf("\nDetected EOF (Ctrl+D). Returning to main menu.\n");
                    break;
                }

                int filter_choice = atoi(line);
                switch (filter_choice) {
                    case 1: set_filter_by_type(&filter, FILTER_HTTP); break;
                    case 2: set_filter_by_type(&filter, FILTER_HTTPS); break;
                    case 3: set_filter_by_type(&filter, FILTER_DNS); break;
                    case 4: set_filter_by_type(&filter, FILTER_ARP); break;
                    case 5: set_filter_by_type(&filter, FILTER_TCP); break;
                    case 6: set_filter_by_type(&filter, FILTER_UDP); break;
                    case 7:
                        printf("\n[Custom Filter Configuration]\n");
                        printf("Protocol (0=any, 6=TCP, 17=UDP, 1=ICMP) [0]: ");
                        if (safe_getline(line, sizeof(line)) == -1) line[0]='\0';
                        filter.protocol = (line[0] == '\0') ? 0 : atoi(line);

                        printf("Source IP (IPv4) [any]: ");
                        read_string_prompt("", filter.src_ip, sizeof(filter.src_ip));

                        printf("Destination IP (IPv4) [any]: ");
                        read_string_prompt("", filter.dst_ip, sizeof(filter.dst_ip));

                        filter.src_port = read_int_default("Source port [0]: ", 0);
                        filter.dst_port = read_int_default("Destination port [0]: ", 0);
                        break;
                    default:
                        printf("Invalid selection. Returning to main menu.\n");
                        continue;
                }

                printf("\n[C-Shark] Starting filtered capture (%s) on %s\n",
                       get_filter_type_name(filter.filter_type), devname);
                if (start_capture_store_with_filter(devname, &store, &filter) != 0) {
                    fprintf(stderr, "Filtered capture failed or returned error.\n");
                } else {
                    printf("\nFiltered capture session ended. Returned to main menu.\n");
                }
                break;
            }

            case 3: {
                if (!has_session_data(&store)) {
                    printf("\n[C-Shark] No packet data available. Please run a capture session first.\n");
                    break;
                }
                print_packet_list_summary(&store);

                printf("Enter Packet ID for detailed analysis (1-%d), or 0 to return: ", store.count);
                if (safe_getline(line, sizeof(line)) == -1) {
                    printf("\nDetected EOF (Ctrl+D). Returning to main menu.\n");
                    break;
                }

                int packet_id = atoi(line);
                if (packet_id == 0) break;

                const StoredPacket *selected_packet = get_packet_by_id(&store, packet_id);
                if (!selected_packet) {
                    printf("Invalid Packet ID. Choose 1-%d.\n", store.count);
                    break;
                }

                print_detailed_packet_analysis(selected_packet, packet_id);
                printf("\nPress Enter to continue...");
                safe_getline(line, sizeof(line));
                break;
            }

            case 4:
                exit_now = 1;
                break;

            default:
                printf("Invalid option.\n");
        }
    }

    free_packet_store(&store);
    free_devices(&list);
    return 0;
}

// LLM code ends here //
