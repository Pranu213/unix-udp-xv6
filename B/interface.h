#ifndef INTERFACE_H
#define INTERFACE_H

#include <pcap.h>

typedef struct {
    pcap_if_t *devs;
    int count;
} dev_list_t;

int list_devices(dev_list_t *list, char *errbuf, int *num);
void print_device_list(dev_list_t *list);
void free_devices(dev_list_t *list);
const char *get_device_name_by_index(dev_list_t *list, int idx);

#endif
