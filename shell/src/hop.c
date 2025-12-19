#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include <pwd.h>
#include "hop.h"

static char prev_dir[PATH_MAX] = ""; // previous directory
extern char home[PATH_MAX]; // shell's home directory from main.c

void hop_init() {
    prev_dir[0] = '\0'; // reset previous directory
}

void cmd_hop(int argc, char **argv) {
    char curr_dir[PATH_MAX];
    if (!getcwd(curr_dir, sizeof(curr_dir))) {
        perror("getcwd");
        return;
    }

    // If no arguments -> treat like "~"
    if (argc == 1) {
        if (chdir(home) == -1) {
            printf("No such directory!\n");
            return;
        }
        strcpy(prev_dir, curr_dir);
        return;
    }

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        char temp_prev[PATH_MAX];
        strcpy(temp_prev, curr_dir); // save current for potential prev_dir update

        if (strcmp(arg, ".") == 0) {
            continue; // do nothing
        } 
        else if (strcmp(arg, "~") == 0) {
            if (chdir(home) == -1) {
                printf("No such directory!\n");
                continue;
            }
            strcpy(prev_dir, temp_prev);
        } 
        else if (strcmp(arg, "..") == 0) {
            if (chdir("..") == -1) {
                printf("No such directory!\n");
                continue;
            }
            strcpy(prev_dir, temp_prev);
        } 
        else if (strcmp(arg, "-") == 0) {
            if (strlen(prev_dir) == 0) {
                // no previous dir yet, do nothing
                continue;
            }
            char old_prev[PATH_MAX];
            strcpy(old_prev, prev_dir);
            if (chdir(prev_dir) == -1) {
                printf("No such directory!\n");
                continue;
            }
            strcpy(prev_dir, temp_prev); // current becomes previous
        } 
        else { 
            if (chdir(arg) == -1) {
                printf("No such directory!\n");
                continue;
            }
            strcpy(prev_dir, temp_prev);
        }

        // Update curr_dir for next iteration
        if (!getcwd(curr_dir, sizeof(curr_dir))) {
            perror("getcwd");
            return;
        }
    }
}

char* get_prev_dir() {
    return prev_dir;
}
