#include <stdio.h>
#include <string.h>
#include<stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include "commands.h"

void cmd_search(int n, char **tokens) {
    if (n < 2) {
        printf("Usage: search <word>\n");
        return;
    }
    printf("Searching for: %s\n", tokens[1]);
    // TODO: implement search logic
}

void cmd_delete(int n, char **tokens) {
    if (n < 2) {
        printf("Usage: delete <filename>\n");
        return;
    }
    printf("Deleting: %s\n", tokens[1]);
    // TODO: implement delete logic
}

//LLM CODE BEGINS
int parse_line(char *input, Command cmds[], int *num_cmds) {
    // Make a copy of input since strtok modifies it
    char *input_copy = strdup(input);
    if (!input_copy) {
        perror("strdup");
        return -1;
    }
    
    int count = 0;
    char *token = strtok(input_copy, " \t\n");
    int arg_index = 0;

    // Initialize first command
    cmds[count].argv[0] = NULL;
    cmds[count].infile = NULL;
    cmds[count].outfile = NULL;
    cmds[count].append = 0;
    cmds[count].num_infiles = 0;
    cmds[count].num_outfiles = 0;

    while (token != NULL) {
        if (strcmp(token, "|") == 0) {
            // End current command args
            cmds[count].argv[arg_index] = NULL;
            count++;
            arg_index = 0;

            // Initialize next command
            if (count >= MAX_CMDS) {
                fprintf(stderr, "Too many commands in pipeline\n");
                free(input_copy);
                return -1;
            }
            cmds[count].argv[0] = NULL;
            cmds[count].infile = NULL;
            cmds[count].outfile = NULL;
            cmds[count].append = 0;
            cmds[count].num_infiles = 0;
            cmds[count].num_outfiles = 0;
        }
        else if (strcmp(token, "<") == 0) {
            token = strtok(NULL, " \t\n");
            if (!token) {
                fprintf(stderr, "Syntax error: no input file\n");
                free(input_copy);
                return -1;
            }


// Parse input line into array of Command structsation
            if (cmds[count].num_infiles < MAX_TOKENS) {
                cmds[count].all_infiles[cmds[count].num_infiles] = strdup(token);
                cmds[count].num_infiles++;
            }
            
            // Only last input redirection takes effect for actual input
            if (cmds[count].infile) free(cmds[count].infile);
            cmds[count].infile = strdup(token);
        }
        else if (strcmp(token, ">") == 0) {
            token = strtok(NULL, " \t\n");
            if (!token) {
                fprintf(stderr, "Syntax error: no output file\n");
                free(input_copy);
                return -1;
            }
            // Store all output files for validation
            if (cmds[count].num_outfiles < MAX_TOKENS) {
                cmds[count].all_outfiles[cmds[count].num_outfiles] = strdup(token);
                cmds[count].all_append[cmds[count].num_outfiles] = 0;
                cmds[count].num_outfiles++;
            }
            
            // Only last output redirection takes effect for actual output
            if (cmds[count].outfile) free(cmds[count].outfile);
            cmds[count].outfile = strdup(token);
            cmds[count].append = 0;  // Override any previous >> setting
        }
        else if (strcmp(token, ">>") == 0) {
            token = strtok(NULL, " \t\n");
            if (!token) {
                fprintf(stderr, "Syntax error: no output file\n");
                free(input_copy);
                return -1;
            }
            // Store all output files for validation
            if (cmds[count].num_outfiles < MAX_TOKENS) {
                cmds[count].all_outfiles[cmds[count].num_outfiles] = strdup(token);
                cmds[count].all_append[cmds[count].num_outfiles] = 1;
                cmds[count].num_outfiles++;
            }
            
            // Only last output redirection takes effect for actual output
            if (cmds[count].outfile) free(cmds[count].outfile);
            cmds[count].outfile = strdup(token);
            cmds[count].append = 1;
        }
        else {
            if (arg_index >= MAX_TOKENS - 1) {
                fprintf(stderr, "Too many arguments\n");
                free(input_copy);
                return -1;
            }
            cmds[count].argv[arg_index++] = strdup(token);
        }
        token = strtok(NULL, " \t\n");
    }

    // LLLM CODE ENDS
    

    cmds[count].argv[arg_index] = NULL;
    *num_cmds = count + 1;
    
    free(input_copy);
    return 0;
}
