#ifndef HOP_H
#define HOP_H


void hop_init();       
// hop command
void cmd_hop(int argc, char **argv);
// Get previous directory
char* get_prev_dir();

#endif
