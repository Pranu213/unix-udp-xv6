#include "reveal.h"
#include "hop.h"
#include "log.h"
#include "commands.h"
#include "execute.h"
#include "activities.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <limits.h>
#include <string.h>
#include <pwd.h>
#include <ctype.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <signal.h>
#include <termios.h>

#define MAX_LEN 1024
#define MAX_TOKENS 128

extern int fg_pid;
extern int job_count;
char home[PATH_MAX];  

/* ---------------- PROMPT ---------------- */
void format_path(char *cwd, char *display) {
    size_t home_len = strlen(home);
    
    // Check if current directory is exactly the home directory
    if (strcmp(cwd, home) == 0) {
        strcpy(display, "~");
    }
    // Check if current directory is under home directory
    else if (strncmp(cwd, home, home_len) == 0 && cwd[home_len] == '/') {
        sprintf(display, "~%s", cwd + home_len);
    } else {
        strcpy(display, cwd);
    }
}

//LLM code begins//
/* ---------------- TOKENIZER ---------------- */
int tokenize(char *input, char *tokens[]) {
    static char buf[MAX_LEN];
    strncpy(buf, input, MAX_LEN - 1);
    buf[MAX_LEN - 1] = '\0';

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') buf[len - 1] = '\0';

    int count = 0;
    char *p = buf;

    while (*p) {
        while (isspace((unsigned char)*p)) p++;
        if (*p == '\0') break;

        if (*p == '>' && *(p + 1) == '>') {
            tokens[count++] = ">>";
            p += 2;
            continue;
        }
        if (*p == '&' && *(p + 1) == '&') {
            tokens[count++] = "&&";
            p += 2;
            continue;
        }
        if (*p == '|' || *p == ';' || *p == '&' || *p == '<' || *p == '>') {
            char *op = malloc(2);
            op[0] = *p; op[1] = '\0';
            tokens[count++] = op;
            p++;
            continue;
        }

        if (*p == '"' || *p == '\'') {
            char quote = *p++;
            char *start = p;
            while (*p && *p != quote) p++;
            if (*p) *p++ = '\0';
            tokens[count++] = start;
            continue;
        }

        char *start = p;
        while (*p && !isspace((unsigned char)*p) &&
               *p != '|' && *p != ';' && *p != '&' &&
               *p != '<' && *p != '>') {
            p++;
        }
        
        int len = p - start;
        char *word = malloc(len + 1);
        strncpy(word, start, len);
        word[len] = '\0';
        tokens[count++] = word;
    }

    tokens[count] = NULL;
    return count;
}



/* ---------------- GRAMMAR CHECK ---------------- */
int pos = 0;
char **tok;

int is_name(const char *s) {
    if (!s) return 0;
    return strcmp(s,"|")!=0 && strcmp(s,"&")!=0 && strcmp(s,"&&")!=0 && strcmp(s,";")!=0 &&
           strcmp(s,"<")!=0 && strcmp(s,">")!=0 && strcmp(s,">>")!=0;
}

int parse_atomic() {
    if (!tok[pos] || !is_name(tok[pos])) return 0;
    pos++;
    while (tok[pos]) {
        if (is_name(tok[pos])) { pos++; continue; }
        if (strcmp(tok[pos], "<")==0 || strcmp(tok[pos], ">")==0 || strcmp(tok[pos], ">>")==0) {
            pos++;
            if (!tok[pos] || !is_name(tok[pos])) return 0;
            pos++;
            continue;
        }
        break;
    }
    return 1;
}

int parse_cmd_group() {
    if (!parse_atomic()) return 0;
    while (tok[pos] && strcmp(tok[pos], "|")==0) {
        pos++;
        if (!parse_atomic()) return 0;
    }
    return 1;
}

int parse_shell_cmd() {
    if (!parse_cmd_group()) return 0;
    while (tok[pos] && (strcmp(tok[pos], "&&")==0 || strcmp(tok[pos], ";")==0)) {
        pos++;
        if (!parse_cmd_group()) return 0;
    }
    if (tok[pos] && strcmp(tok[pos], "&")==0) pos++;
    return tok[pos]==NULL;
}


/* ---------------- FUNCTION DECLARATIONS ---------------- */
void run_command(char *tokens[], int bg);
void execute_sequential(char *tokens[], int total_tokens);

/* ---------------- SEQUENTIAL EXECUTION ---------------- */
void execute_sequential(char *tokens[], int total_tokens) {
    int start = 0;
    
    for (int i = 0; i <= total_tokens; i++) {
        // Check if we've reached a semicolon or end of tokens
        if (i == total_tokens || (tokens[i] && strcmp(tokens[i], ";") == 0)) {
            if (start < i) {
                // Extract command from start to i-1
                char *cmd_tokens[MAX_TOKENS];
                int cmd_len = 0;
                
                // Check for background operator at the end of this command
                int bg = 0;
                int end = i;
                if (i > start && tokens[i-1] && strcmp(tokens[i-1], "&") == 0) {
                    bg = 1;
                    end = i - 1;
                }
                
                // Copy tokens for this command
                for (int j = start; j < end; j++) {
                    cmd_tokens[cmd_len++] = tokens[j];
                }
                cmd_tokens[cmd_len] = NULL;
                
                if (cmd_len > 0) {
                    // Check if command contains pipes or redirections
                    int has_complex_ops = 0;
                    for (int k = 0; k < cmd_len; k++) {
                        if (strcmp(cmd_tokens[k], "|") == 0 || strcmp(cmd_tokens[k], "<") == 0 || 
                            strcmp(cmd_tokens[k], ">") == 0 || strcmp(cmd_tokens[k], ">>") == 0) {
                            has_complex_ops = 1;
                            break;
                        }
                    }
                    
                    // Handle built-ins for non-complex commands
                    if (!has_complex_ops) {
                        if (strcmp(cmd_tokens[0], "hop") == 0) { 
                            cmd_hop(cmd_len, cmd_tokens); 
                        } else if (strcmp(cmd_tokens[0], "reveal") == 0) { 
                            cmd_reveal(cmd_len, cmd_tokens);
                        } else if (strcmp(cmd_tokens[0], "activities") == 0) {
                            cmd_activities();
                        } else if (strcmp(cmd_tokens[0], "ping") == 0) {
                            cmd_ping(cmd_len, cmd_tokens);
                        } else if (strcmp(cmd_tokens[0], "fg") == 0) {
                            cmd_fg(cmd_len, cmd_tokens);
                        } else if (strcmp(cmd_tokens[0], "bg") == 0) {
                            cmd_bg(cmd_len, cmd_tokens);
                        } else {
                            // Regular command execution
                            run_command(cmd_tokens, bg);
                        }
                    } else {
                        // Build command string for complex commands
                        char cmd_str[MAX_LEN] = "";
                        for (int k = 0; k < cmd_len; k++) {
                            if (strlen(cmd_str) > 0) strcat(cmd_str, " ");
                            strcat(cmd_str, cmd_tokens[k]);
                        }
                        
                        // Use complex command execution for pipes/redirections
                        Command cmds[MAX_CMDS];
                        int num_cmds;
                        
                        if (parse_line(cmd_str, cmds, &num_cmds) == 0) {
                            if (bg) {
                                // For background complex commands, fork the entire pipeline
                                pid_t pid = fork();
                                if (pid == 0) {
                                    // Child: execute the pipeline
                                    setpgid(0, 0);
                                    // Redirect stdin for background
                                    int null_fd = open("/dev/null", O_RDONLY);
                                    if (null_fd != -1) {
                                        dup2(null_fd, STDIN_FILENO);
                                        close(null_fd);
                                    }
                                    execute_commands(cmds, num_cmds);
                                    exit(0);
                                } else if (pid > 0) {
                                    add_job(pid, cmd_tokens[0], 1);
                                    printf("[%d] %d\n", job_count, pid);
                                }
                            } else {
                                execute_commands(cmds, num_cmds);
                            }
                        }
                    }
                }
            }
            start = i + 1; // Move to next command after semicolon
        }
    }
}

/* ---------------- EXECUTOR ---------------- */
void run_command(char *tokens[], int bg) {
    pid_t pid = fork();
    if (pid == 0) {
        // Child: create a new process group
        setpgid(0, 0);

        // For background processes, don't give terminal access
        if (!bg) {
            signal(SIGINT, SIG_DFL);   // restore default signal handlers
            signal(SIGTSTP, SIG_DFL);
            
        } else {
            
            int null_fd = open("/dev/null", O_RDONLY);
            if (null_fd != -1) {
                dup2(null_fd, STDIN_FILENO);
                close(null_fd);
            }
        }

        // Build argv for exec
        char *argv[128];
        int argc = 0;
        for (int i = 0; tokens[i]; i++) {
            if (strcmp(tokens[i], "<") == 0 || strcmp(tokens[i], ">") == 0 || strcmp(tokens[i], ">>") == 0) {
                i++; // skip filename (TODO: implement redirection)
            } else {
                argv[argc++] = tokens[i];
            }
        }
        argv[argc] = NULL;

        execvp(argv[0], argv);

        // If execvp fails
        fprintf(stderr, "Command not found!\n");
        _exit(127);
    } else if (pid > 0) {
        setpgid(pid, pid); // ensure child is in its own group
        if (!bg) {
            fg_pid = pid;
            set_fg_cmd(tokens[0]);  // Store foreground command name
            
            int status;
            do {
                waitpid(pid, &status, WUNTRACED);  // wait for child or stop
            } while (!WIFEXITED(status) && !WIFSIGNALED(status) && !WIFSTOPPED(status));

        
            fg_pid = 0;

            // If execvp failed
            if (WIFEXITED(status) && WEXITSTATUS(status) == 127) {
                // already printed "Command not found!" in child
            }
        } else {
            // Background process: add to job list and print info
            add_job(pid, tokens[0], 1);
            printf("[%d] %d\n", job_count, pid);
        }
    } else {
        perror("fork failed");
    }
}

// LLM CODE ENDS

/* ---------------- MAIN ---------------- */
int main(void) {
    if (getcwd(home, sizeof(home)) == NULL) { perror("getcwd"); return 1; }

    hop_init();
    log_init();

    // Shell process group and signal setup
    pid_t shell_pid = getpid();
    setpgid(shell_pid, shell_pid);


    signal(SIGINT, sigint_handler);   
    signal(SIGTSTP, sigtstp_handler); 

    while (1) {
        remove_finished_jobs();

        struct passwd *pw = getpwuid(getuid());
        const char *username = pw ? pw->pw_name : "unknown";

        char hostname[HOST_NAME_MAX];
        gethostname(hostname, sizeof(hostname));

        char cwd[PATH_MAX], display[PATH_MAX];
        getcwd(cwd, sizeof(cwd));
        format_path(cwd, display);

        printf("<%s@%s:%s> ", username, hostname, display);
        fflush(stdout);

        char input[MAX_LEN];
        if (!fgets(input, sizeof(input), stdin)) {
            printf("logout\n");
            for (int i = 0; i < job_count; i++)
                kill(-jobs[i].pid, SIGKILL);
            exit(0);
        }

        char *tokens[MAX_TOKENS];
        int n = tokenize(input, tokens);
        if (n == 0) continue;

        pos = 0;
        tok = tokens;
        if (!parse_shell_cmd()) {
            printf("Invalid Syntax!\n");
            continue;
        }

        // Handle exit command first
        if (strcmp(tokens[0], "exit") == 0) break;

        // Handle log commands (don't add to history)
        if (strcmp(tokens[0], "log") == 0) { 
            if (n == 1) {
                log_print(); 
            } else if (n == 2 && strcmp(tokens[1], "purge") == 0) {
                log_purge();
            } else if (n == 3 && strcmp(tokens[1], "execute") == 0) {
                int index = atoi(tokens[2]);
                log_execute(index);
            }
            continue; 
        }
        
        log_add(input);
        
        // Check if we have sequential execution (semicolons)
        int has_sequential = 0;
        for (int i = 0; i < n; i++) {
            if (strcmp(tokens[i], ";") == 0) {
                has_sequential = 1;
                break;
            }
        }
        
        if (has_sequential) {
            // Use sequential execution handler
            execute_sequential(tokens, n);
        } else {
            int bg = 0;
            int cmd_end = n;
            if (n > 0 && strcmp(tokens[n-1], "&") == 0) {
                bg = 1;
                cmd_end = n - 1;
            }
            
            if (cmd_end == 0) continue; // Empty command

            int has_complex_ops = 0;
            for (int i = 0; i < cmd_end; i++) {
                if (strcmp(tokens[i], "|") == 0 || strcmp(tokens[i], "<") == 0 || 
                    strcmp(tokens[i], ">") == 0 || strcmp(tokens[i], ">>") == 0) {
                    has_complex_ops = 1;
                    break;
                }
            }
            
            if (!has_complex_ops) {
                // Handle built-in commands
                if (strcmp(tokens[0], "hop") == 0) { 
                    cmd_hop(cmd_end, tokens); 
                } else if (strcmp(tokens[0], "reveal") == 0) { 
                    cmd_reveal(cmd_end, tokens);
                } else if (strcmp(tokens[0], "activities") == 0) {
                    cmd_activities();
                } else if (strcmp(tokens[0], "ping") == 0) {
                    cmd_ping(cmd_end, tokens);
                } else if (strcmp(tokens[0], "fg") == 0) {
                    cmd_fg(cmd_end, tokens);
                } else if (strcmp(tokens[0], "bg") == 0) {
                    cmd_bg(cmd_end, tokens);
                } else {
                    // Regular command execution
                    char *cmd_tokens[MAX_TOKENS];
                    for (int i = 0; i < cmd_end; i++) {
                        cmd_tokens[i] = tokens[i];
                    }
                    cmd_tokens[cmd_end] = NULL;
                    run_command(cmd_tokens, bg);
                }
            } else {
                char cmd_str[MAX_LEN] = "";
                for (int i = 0; i < cmd_end; i++) {
                    if (strlen(cmd_str) > 0) strcat(cmd_str, " ");
                    strcat(cmd_str, tokens[i]);
                }
                
                Command cmds[MAX_CMDS];
                int num_cmds;
                
                if (parse_line(cmd_str, cmds, &num_cmds) == 0) {
                    if (bg) {
                        pid_t pid = fork();
                        if (pid == 0) {
                            setpgid(0, 0);
                            int null_fd = open("/dev/null", O_RDONLY);
                            if (null_fd != -1) {
                                dup2(null_fd, STDIN_FILENO);
                                close(null_fd);
                            }
                            execute_commands(cmds, num_cmds);
                            exit(0);
                        } else if (pid > 0) {
                            add_job(pid, tokens[0], 1);
                            printf("[%d] %d\n", job_count, pid);
                        }
                    } else {
                        execute_commands(cmds, num_cmds);
                    }
                }
            }
        }
    }

    return 0;
}
