CC = gcc
CFLAGS = -Wall -O2 -g
LIBS = -lpcap

OBJS = main.o capture.o utils.o packet_store.o filters.o packet_sniffer.o interface.o display.o

cshark: $(OBJS)
	$(CC) $(CFLAGS) -o cshark $(OBJS) $(LIBS)

main.o: main.c capture.h utils.h packet_store.h filters.h
	$(CC) $(CFLAGS) -c main.c

capture.o: capture.c capture.h utils.h packet_store.h filters.h
	$(CC) $(CFLAGS) -c capture.c

utils.o: utils.c utils.h
	$(CC) $(CFLAGS) -c utils.c

packet_store.o: packet_store.c packet_store.h
	$(CC) $(CFLAGS) -c packet_store.c

filters.o: filters.c filters.h
	$(CC) $(CFLAGS) -c filters.c

packet_sniffer.o: packet_sniffer.c packet_sniffer.h
	$(CC) $(CFLAGS) -c packet_sniffer.c

interface.o: interface.c interface.h
	$(CC) $(CFLAGS) -c interface.c

display.o: display.c display.h utils.h
	$(CC) $(CFLAGS) -c display.c

clean:
	rm -f *.o cshark
