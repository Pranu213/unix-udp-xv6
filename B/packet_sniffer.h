// include/packet_sniffer.h
#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

// Prompt list interfaces and let user choose one.
// chosen_dev must be a buffer where chosen device name is copied.
// Returns 0 on success, non-zero on failure/exit.
int list_and_choose_interface(char *chosen_dev, size_t len);

// Start sniffing on the given device. This function returns when sniffing
// stops (pcap_loop ended) — e.g. due to user pressing Ctrl+C.
void start_sniffer(const char *device);

// Install signal handlers (SIGINT) used to break capture loop, etc.
void register_signal_handlers(void);

#endif // PACKET_SNIFFER_H
