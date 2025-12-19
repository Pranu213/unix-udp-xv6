#include "utils.h"
#include <stdio.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

// LLM code starts here //

/* print MAC in standard format */
void print_mac(const u_char *mac) {
    if (!mac) {
        printf("00:00:00:00:00:00");
        return;
    }
    printf("%02X:%02X:%02X:%02X:%02X:%02X",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* timestamp to human-readable string with microseconds */
void ts_to_str(const struct timeval *ts, char *buf, size_t bufsz) {
    time_t sec = ts->tv_sec;
    struct tm lt;
    localtime_r(&sec, &lt);
    char timestr[64];
    strftime(timestr, sizeof(timestr), "%F %T", &lt);
    snprintf(buf, bufsz, "%s.%06ld", timestr, (long)ts->tv_usec);
}

/* print a single line of hex + ascii for payload (len <= 16) with offset */
void print_hex_ascii_line(const u_char *payload, int len, int offset) {
    /* print offset at start */
    printf("%04X  ", offset & 0xFFFF);

    int i;
    /* hex bytes */
    for (i = 0; i < len; i++) {
        printf("%02X ", payload[i]);
        if ((i + 1) % 8 == 0) printf(" ");
    }
    /* padding for alignment if len < 16 */
    for (; i < 16; i++) {
        printf("   ");
        if ((i + 1) % 8 == 0) printf(" ");
    }

    /* ASCII characters */
    printf(" ");
    for (i = 0; i < len; i++) {
        unsigned char c = payload[i];
        printf("%c", isprint(c) ? c : '.');
    }
    printf("\n");
}

/* safe fgets wrapper: returns -1 on EOF (Ctrl+D), 0 on success */
int safe_getline(char *buf, size_t sz) {
    if (!fgets(buf, sz, stdin)) {
        if (feof(stdin)) return -1;
        return -1;
    }
    /* strip newline */
    size_t len = strlen(buf);
    if (len && buf[len - 1] == '\n') buf[len - 1] = '\0';
    return 0;
}

// LLM code ends here //