#ifndef LOG_H
#define LOG_H

#define MAX_LOG 15
#define MAX_CMD_LEN 256
#define LOG_FILE "history.log"

void log_init();
void log_add(const char *cmd);
void log_print();
void log_purge();
void log_execute(int index);

#endif
