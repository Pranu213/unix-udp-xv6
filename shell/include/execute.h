#ifndef EXECUTE_H
#define EXECUTE_H
#include "commands.h"
// Executes a command (array of tokens).
// Returns 0 if executed successfully, -1 if error.
int cmd_execute(char *tokens[]);
void execute_commands(Command cmds[], int num_cmds);
#endif
