#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "reveal.h"
#include <dirent.h>
#include <sys/stat.h>
#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include "hop.h"

extern char home[PATH_MAX]; // shell's home directory from main.c

void reveal_init() {
    // No longer needed - hop manages prev_dir
}

static int compare_strings(const void *a, const void *b) {
    return strcmp(*(const char**)a, *(const char**)b);
}

static char* resolve_path(const char* arg, char* resolved) {
    if (strcmp(arg, "~") == 0) {
        strcpy(resolved, home);
    } else if (strcmp(arg, ".") == 0) {
        if (!getcwd(resolved, PATH_MAX)) {
            return NULL;
        }
    } else if (strcmp(arg, "..") == 0) {
        if (!getcwd(resolved, PATH_MAX)) {
            return NULL;
        }
        strcat(resolved, "/..");
    } else if (strcmp(arg, "-") == 0) {
        char *prev_dir = get_prev_dir();
        if (strlen(prev_dir) == 0) {
            return NULL; // no previous directory
        }
        strcpy(resolved, prev_dir);
    } else {
        strcpy(resolved, arg); // relative or absolute path
    }
    return resolved;
}

//LLM CODE BEGINS
void cmd_reveal(int argc, char *argv[]) {
    int show_all = 0, long_list = 0;
    char* path_arg = NULL;
    int flag_count = 0, path_count = 0;

    // Parse flags and path
    for (int i = 1; i < argc; i++) {
        if (argv[i][0] == '-' && strlen(argv[i]) > 1) {
            flag_count++;
            // Parse individual flags in the argument
            for (int j = 1; argv[i][j]; j++) {
                if (argv[i][j] == 'a') show_all = 1;
                else if (argv[i][j] == 'l') long_list = 1;
            }
        } else {
            path_count++;
            if (path_count == 1) {
                path_arg = argv[i];
            }
        }
    }

    // Check for too many arguments
    if (path_count > 1) {
        printf("reveal: Invalid Syntax!\n");
        return;
    }

    char target_path[PATH_MAX];
    if (!path_arg) {
        // No path specified, use current directory
        if (!getcwd(target_path, sizeof(target_path))) {
            printf("No such directory!\n");
            return;
        }
    } else {
        // Resolve the path
        if (!resolve_path(path_arg, target_path)) {
            printf("No such directory!\n");
            return;
        }
    }

    //LLM CODE ENDS
    
    // Previous directory is managed by hop command

    DIR *dir = opendir(target_path);
    if (!dir) {
        printf("No such directory!\n");
        return;
    }

    // Collect all entries
    char **entries = NULL;
    int count = 0;
    struct dirent *entry;
    
    while ((entry = readdir(dir)) != NULL) {
        if (!show_all && entry->d_name[0] == '.') continue;
        
        entries = realloc(entries, (count + 1) * sizeof(char*));
        entries[count] = malloc(strlen(entry->d_name) + 1);
        strcpy(entries[count], entry->d_name);
        count++;
    }
    closedir(dir);

    // Sort lexicographically
    qsort(entries, count, sizeof(char*), compare_strings);

    // Print results
    if (long_list) {
        for (int i = 0; i < count; i++) {
            printf("%s\n", entries[i]);
        }
    } else {
        for (int i = 0; i < count; i++) {
            printf("%s", entries[i]);
            if (i < count - 1) printf(" ");
        }
        printf("\n");
    }

    // Free memory
    for (int i = 0; i < count; i++) {
        free(entries[i]);
    }
    free(entries);
}
