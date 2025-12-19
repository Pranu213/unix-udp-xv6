#ifndef CAPTURE_H
#define CAPTURE_H

#include "packet_store.h"
#include "filters.h"

/* Phase-1: simple live capture */
int start_capture(const char *devname);
void stop_capture_graceful(void);
int start_capture_store(const char *devname, PacketStore *store);
int start_capture_store_with_filter(const char *devname, PacketStore *store, const PacketFilter *filter);

/* Phase-2: capture with packet storage */
int start_capture_store(const char *devname, PacketStore *store);

/* Phase-2: capture with packet storage + filter */
int start_capture_store_with_filter(const char *devname, PacketStore *store, const PacketFilter *filter);

#endif /* CAPTURE_H */
