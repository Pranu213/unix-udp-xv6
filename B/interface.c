#include "interface.h"
#include <stdio.h>
#include <stdlib.h>

// LLM code starts here //

void interface_menu(void) {
    char device[128];

    while (1) {
        printf("\n==== [C-Shark Interface Menu] ====\n");
        if (list_and_choose_interface(device, sizeof(device)) != 0) {
            printf("Exiting C-Shark.\n");
            break;  // user pressed Ctrl+D or no interfaces
        }

        start_sniffer(device);  // Run the sniffer
        printf("\nReturned from sniffer.\n");
    }
}

int list_devices(dev_list_t *list, char *errbuf, int *num) {
    pcap_if_t *alldevs;
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        return -1;
    }
    list->devs = alldevs;
    int cnt = 0;
    for (pcap_if_t *d = alldevs; d; d = d->next) cnt++;
    list->count = cnt;
    if (num) *num = cnt;
    return 0;
}

void free_devices(dev_list_t *list) {
    if (list && list->devs) {
        pcap_freealldevs(list->devs);
        list->devs = NULL;
        list->count = 0;
    }
}

void print_device_list(dev_list_t *list) {
    printf("[C-Shark] Searching for available interfaces... Found!\n\n");
    int idx = 1;
    for (pcap_if_t *d = list->devs; d; d = d->next) {
        printf("%d. %s", idx++, d->name);
        if (d->description) printf(" (%s)", d->description);
        printf("\n");
    }
    if (list->count == 0) {
        printf("No interfaces found.\n");
    }
}

const char *get_device_name_by_index(dev_list_t *list, int idx) {
    int i = 1;
    for (pcap_if_t *d = list->devs; d; d = d->next) {
        if (i == idx) return d->name;
        i++;
    }
    return NULL;
}

// LLM code ends here //
