#ifndef ACTIVITIES_H
#define ACTIVITIES_H

#include <sys/types.h>

#define MAX_JOBS 64

typedef enum { JOB_RUNNING, JOB_STOPPED } JobState;

typedef struct {
    pid_t pid;
    char cmd[256];
    JobState state;
} JobEntry;

extern JobEntry jobs[MAX_JOBS];
extern int job_count;
extern pid_t fg_pid;  // foreground process PID

// Job management
void add_job(pid_t pid, const char *cmd, int bg);
void remove_finished_jobs();
void cmd_activities();

// Signal handlers
void sigint_handler(int signo);
void sigtstp_handler(int signo);
void set_fg_cmd(const char *cmd);

// Ping command
void cmd_ping(int n, char **tokens);

// Job control commands
void cmd_fg(int n, char **tokens);
void cmd_bg(int n, char **tokens);

#endif
