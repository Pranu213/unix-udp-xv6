#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include "log.h"
#include "commands.h"  // for tokenize(), cmd_hop, cmd_reveal

static char history[MAX_LOG][MAX_CMD_LEN];
static int start = 0, count = 0;

static void load_history() {
    FILE *fp = fopen(LOG_FILE, "r");
    if (!fp) return;
    int temp_count = 0;
    while (temp_count < MAX_LOG && fgets(history[temp_count], MAX_CMD_LEN, fp)) {
        history[temp_count][strcspn(history[temp_count], "\n")] = '\0';
        temp_count++;
    }
    count = temp_count;
    fclose(fp);
}

static void save_history() {
    FILE *fp = fopen(LOG_FILE, "w");
    if (!fp) return;
    for (int i = 0; i < count; i++) {
        int idx = (start + i) % MAX_LOG;
        fprintf(fp, "%s\n", history[idx]);
    }
    fclose(fp);
}

void log_init() {
    load_history();
}

static int contains_log_command(const char *cmd) {
    // Simple check if command starts with "log"
    if (strncmp(cmd, "log", 3) == 0) {
        // Check if it's followed by space, end of string, or other operators
        char next = cmd[3];
        return (next == '\0' || next == ' ' || next == '\t' || next == ';' || next == '&' || next == '|');
    }
    return 0;
}

//LLM BEGINS
void log_add(const char *cmd) {
    // Don't store if it contains log command
    if (contains_log_command(cmd)) {
        return;
    }
    
    // Remove trailing newline if present
    char clean_cmd[MAX_CMD_LEN];
    strncpy(clean_cmd, cmd, MAX_CMD_LEN - 1);
    clean_cmd[MAX_CMD_LEN - 1] = '\0';
    int len = strlen(clean_cmd);
    if (len > 0 && clean_cmd[len - 1] == '\n') {
        clean_cmd[len - 1] = '\0';
    }
    
    // Don't store if identical to previous command
    if (count > 0) {
        int prev_idx = (start + count - 1) % MAX_LOG;
        if (strcmp(history[prev_idx], clean_cmd) == 0) {
            return;
        }
    }
    
    if (count < MAX_LOG) {
        strncpy(history[(start + count) % MAX_LOG], clean_cmd, MAX_CMD_LEN - 1);
        history[(start + count) % MAX_LOG][MAX_CMD_LEN - 1] = '\0';
        count++;
    } else {
        strncpy(history[start], clean_cmd, MAX_CMD_LEN - 1);
        history[start][MAX_CMD_LEN - 1] = '\0';
        start = (start + 1) % MAX_LOG;
    }
    save_history();
}

//LLM CODE ENDS

void log_print() {
    // Print in order from oldest to newest
    for (int i = 0; i < count; i++) {
        int idx = (start + i) % MAX_LOG;
        printf("%s\n", history[idx]);
    }
}

void log_purge() {
    start = 0;
    count = 0;
    FILE *fp = fopen(LOG_FILE, "w"); // overwrite empty file
    if (fp) fclose(fp);
}

void log_execute(int index) {
    // Index is 1-based, newest to oldest
    if (index <= 0 || index > count) {
        printf("Invalid index\n");
        return;
    }

    // Convert to 0-based index (newest to oldest)
    int pos = (start + count - index) % MAX_LOG;
    char *cmd = history[pos];
    
    // Don't print "Executing" message, just execute
    char *tokens[MAX_TOKENS];
    int n = tokenize(cmd, tokens);
    if (n == 0) return;

    if (strcmp(tokens[0], "hop") == 0) {
        cmd_hop(n, tokens);
    } else if (strcmp(tokens[0], "reveal") == 0) {
        cmd_reveal(n, tokens);
    } else {
        pid_t pid = fork();
        if (pid == 0) {
            execvp(tokens[0], tokens);
            perror("execvp failed");
            exit(1);
        } else {
            wait(NULL);
        }
    }
}
