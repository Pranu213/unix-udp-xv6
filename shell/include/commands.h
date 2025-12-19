#ifndef COMMANDS_H
#define COMMANDS_H

#define MAX_TOKENS 128
#define MAX_CMDS 64

// Command prototypes
void cmd_search(int n, char **tokens);
void cmd_delete(int n, char **tokens);
void cmd_hop(int n, char **tokens);
void cmd_reveal(int n, char **tokens);

// Tokenizer
int tokenize(char *input, char *tokens[]);

// Parsed command structure
typedef struct {
    char *argv[MAX_TOKENS];  // arguments
    char *infile;            // for input redirection (final one)
    char *outfile;           // for output redirection (final one)
    int append;              // 1 if >>, 0 if >
    char *all_infiles[MAX_TOKENS];   // all input files for validation
    int num_infiles;                 // number of input redirections
    char *all_outfiles[MAX_TOKENS];  // all output files for validation
    int all_append[MAX_TOKENS];      // append flags for all files
    int num_outfiles;                // number of output redirections
} Command;

// Parse input into commands, handle <, >, >>, |
int parse_line(char *input, Command cmds[], int *num_cmds);
#endif
