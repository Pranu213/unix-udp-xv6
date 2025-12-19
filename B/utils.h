#ifndef UTILS_H
#define UTILS_H

#include <pcap.h>

void print_hex_ascii_line(const u_char *payload, int len, int offset);
void print_mac(const u_char *mac); /* prints like AA:BB:CC:DD:EE:FF */
void ts_to_str(const struct timeval *ts, char *buf, size_t bufsz);
int safe_getline(char *buf, size_t sz); /* returns -1 on EOF, 0 on success */

#endif
