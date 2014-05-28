/**
 * Operating Sytems 2013 - Assignment 2
 *
 */

#include <assert.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <unistd.h>

#include "utils.h"

#define READ		0
#define WRITE		1

#define OVERWRITE 11
#define APPEND 22

static void do_redirect(int filedes, const char *filename, int mode)
{
	int rc;
	int fd;

    if (filedes == STDIN_FILENO) {
        fd = open(filename, O_RDONLY);
    }
    
    else if (filedes == STDOUT_FILENO || filedes == STDERR_FILENO) {

        if (mode == OVERWRITE) {
            fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        }
        else {
            fd = open(filename, O_WRONLY | O_CREAT | O_APPEND, 0644);
        }
        DIE(fd < 0, "open");

    }

    rc = dup2(fd, filedes);
    DIE(rc < 0, "dup2");
    close(fd);
}

/**
 * Concatenate parts of the word to obtain the command
 */
static char *get_word(word_t *s)
{
	int string_length = 0;
	int substring_length = 0;

	char *string = NULL;
	char *substring = NULL;

	while (s != NULL) {
		substring = strdup(s->string);

		if (substring == NULL) {
			return NULL;
		}

		if (s->expand == true) {
			char *aux = substring;
			substring = getenv(substring);

			/* prevents strlen from failing */
			if (substring == NULL) {
				substring = calloc(1, sizeof(char));
				if (substring == NULL) {
					free(aux);
					return NULL;
				}
			}

			free(aux);
		}

		substring_length = strlen(substring);

		string = realloc(string, string_length + substring_length + 1);
		if (string == NULL) {
			if (substring != NULL)
				free(substring);
			return NULL;
		}

		memset(string + string_length, 0, substring_length + 1);

		strcat(string, substring);
		string_length += substring_length;

		if (s->expand == false) {
			free(substring);
		}

		s = s->next_part;
	}

	return string;
}

/**
 * Internal change-directory command.
 */
static bool shell_cd(word_t *dir, word_t *err, word_t *out, int flags)
{
    char* path = get_word(dir);

    if (err != NULL && out != NULL) {
        char *filename_err, *filename_out;
        int mode;
        filename_err = get_word(err);
        filename_out = get_word(out);
        if (flags & IO_OUT_APPEND) {
            mode = APPEND;
        }
        else {
            mode = OVERWRITE;
        }
        if (strcmp(filename_err, filename_out) == 0) {
            do_redirect(STDERR_FILENO, filename_err, mode);
            do_redirect(STDOUT_FILENO, filename_out, APPEND);
        }
        else {
            do_redirect(STDERR_FILENO, filename_err, mode);
            do_redirect(STDOUT_FILENO, filename_out, mode);
        }
        free(filename_err);
        free(filename_out);
    }
    else if (err != NULL && out == NULL) {
        char* filename;
        int mode;
        filename = get_word(err);
        if (flags & IO_OUT_APPEND) {
            mode = APPEND;
        }
        else {
            mode = OVERWRITE;
        }
        do_redirect(STDERR_FILENO, filename, mode);
        free(filename);
    }
    else if (out != NULL && err == NULL) {
        char* filename;
        int mode;
        filename = get_word(out);
        if (flags & IO_OUT_APPEND) {
            mode = APPEND;
        }
        else {
            mode = OVERWRITE;
        }
        do_redirect(STDOUT_FILENO, filename, mode);
        free(filename);
    }
    
    int ret = chdir(path);
    free(path);
	return ret;
}

/**
 * Internal exit/quit command.
 */
static int shell_exit()
{
    return SHELL_EXIT;
}

/**
 * Concatenate command arguments in a NULL terminated list in order to pass
 * them directly to execv.
 */
static char **get_argv(simple_command_t *command, int *size)
{
	char **argv;
	word_t *param;

	int argc = 0;
	argv = calloc(argc + 1, sizeof(char *));
	assert(argv != NULL);

	argv[argc] = get_word(command->verb);
	assert(argv[argc] != NULL);

	argc++;

	param = command->params;
	while (param != NULL) {
		argv = realloc(argv, (argc + 1) * sizeof(char *));
		assert(argv != NULL);

		argv[argc] = get_word(param);
		assert(argv[argc] != NULL);

		param = param->next_word;
		argc++;
	}

	argv = realloc(argv, (argc + 1) * sizeof(char *));
	assert(argv != NULL);

	argv[argc] = NULL;
	*size = argc;

	return argv;
}

static int set_var(const char *name, const char *value)
{
	return setenv(name, value, 1);
}

/**
 * Parse a simple command (internal, environment variable assignment,
 * external command).
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{

	pid_t child_pid;
	pid_t wait_ret;
	int status;
	int ret;

	char* verb;
	verb = get_word(s->verb);
	if (strncmp(verb, "quit", 4) == 0 || strncmp(verb, "exit", 4) == 0) {
	    free(verb);
	    ret = shell_exit();
	    return ret;
	}

	if (strncmp(verb, "cd", 2) == 0) {
	    ret = shell_cd(s->params, s->out, s->err, s->io_flags);
	    free(verb);
	    return ret;
	}

	if (s->verb->next_part != NULL) {
	    const char* var = s->verb->string;
	    const char* value;
	    if (strcmp(s->verb->next_part->string, "=") == 0) {
	        if (s->verb->next_part->next_part == NULL) {
                fprintf(stderr, "Invalid command.");
                return -1;
	        }
	        else {
    	        value = s->verb->next_part->next_part->string;
	        }
	    }
	    return set_var(var, value);
	}

    child_pid = fork();
    switch(child_pid) {
    
        case -1:
        {
            // error forking
            DIE(1, "fork");
            break;
        }
        case 0:
        {
            // child

            int mode;
            if (s->in != NULL) {
                char* filename;
                filename = get_word(s->in);
                int anything = 42;
                do_redirect(STDIN_FILENO, filename, anything);
                free(filename);
            }
            if (s->out != NULL && s->err != NULL) {
                char* filename_out, *filename_err;
                int mode_out, mode_err;
                filename_out = get_word(s->out);
                filename_err = get_word(s->err);
                if (s->io_flags & IO_OUT_APPEND) {
                    mode_out = APPEND;
                }
                else {
                    mode_out = OVERWRITE;
                }
                if (s->io_flags & IO_ERR_APPEND) {
                    mode_err = APPEND;
                }
                else {
                    mode_err = OVERWRITE;
                }
                if (strcmp(filename_err, filename_out) == 0) {
                    do_redirect(STDERR_FILENO, filename_err, mode_err);
                    do_redirect(STDOUT_FILENO, filename_out, APPEND);

                }
                else {
                    do_redirect(STDOUT_FILENO, filename_out, mode_out);
                    do_redirect(STDERR_FILENO, filename_err, mode_err);
                }
                free(filename_out);
                free(filename_err);
            }
            else {
                if (s->out != NULL) {
                    char* filename;
                    filename = get_word(s->out);
                    if (s->io_flags & IO_OUT_APPEND) {
                        mode = APPEND;
                    }
                    else {
                        mode = OVERWRITE;
                    }
                    do_redirect(STDOUT_FILENO, filename, mode);
                    free(filename);
                }
                else if (s->err != NULL) {
                    char* filename;
                    filename = get_word(s->err);
                    if (s->io_flags & IO_ERR_APPEND) {
                        mode = APPEND;
                    }
                    else {
                        mode = OVERWRITE;
                    }
                    do_redirect(STDERR_FILENO, filename, mode);
                    free(filename);
                }
            }
            
            char* cmd = get_word(s->verb);
            int argv_size;
            char** argv = get_argv(s, &argv_size);
            if (execvp(cmd, argv) == -1) {
                fprintf(stderr, "Execution failed for '%s'\n", cmd);
            }
            free(cmd);
            int i;
            for (i = 0; i < argv_size; i++) {
                free(argv[i]);
            }
            free(argv);

            exit(EXIT_FAILURE);
            break;

        }
        default:
        {
            // parent
            wait_ret = waitpid(child_pid, &status, 0);
          	DIE(wait_ret < 0, "waitpid");

            if (WIFEXITED(status))
                return WEXITSTATUS(status);
                
            break;
        }
        
    }
    
    return 0;

}

/**
 * Process two commands in parallel, by creating two children.
 */
static bool do_in_parallel(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{

    pid_t child_pid;
    pid_t wait_ret;
    int status;

    child_pid = fork();
    switch(child_pid) {
        case -1:
        {
            // error forking
            DIE(1, "fork");
            break;
        }
        case 0:
        {
            // child
            exit(parse_command(cmd1, level + 1, father));
        }
        default:
        {
            // parent

            return parse_command(cmd2, level + 1, father);
            
            wait_ret = waitpid(child_pid, &status, 0);
          	DIE(wait_ret < 0, "waitpid");

            if (WIFEXITED(status))
                return WEXITSTATUS(status);
        }
    }
    
    return 0;

}

/**
 * Run commands by creating an anonymous pipe (cmd1 | cmd2)
 */
static bool do_on_pipe(command_t *cmd1, command_t *cmd2, int level, command_t *father)
{
	/* redirect the output of cmd1 to the input of cmd2 */

	pid_t pid_child, wait_ret;
    int status;
    int fd[2];
    int pret;

    pret = pipe(fd);
    DIE(pret < 0, "pipe");

    pid_child = fork();

    switch(pid_child) {
        case -1:
        {
            // error
            DIE(1, "fork");    
        }
        case 0:
        {
            // child
            close(fd[0]);
        	int ret;
            ret = dup2(fd[1], STDOUT_FILENO);
            DIE(ret < 0, "dup2");
            close(fd[1]);
            exit(parse_command(cmd1, level + 1, father));
        }
        default:
        {
            // parent
            close(fd[1]);
            int ret = dup2(fd[0], STDIN_FILENO);
            DIE(ret < 0, "dup2");
            close(fd[0]);
            
            pret = parse_command(cmd2, level + 1, father);
            
            wait_ret = waitpid(pid_child, &status, 0);
          	DIE(wait_ret < 0, "waitpid");

            if (WIFEXITED(status))
                return WEXITSTATUS(status);

        }
    }

    return pret;

}

/**
 * Parse and execute a command.
 */
int parse_command(command_t *c, int level, command_t *father)
{

	if (c->op == OP_NONE) {
	    return parse_simple(c->scmd, level, father);
	}

    int ret;

	switch (c->op) {
	case OP_SEQUENTIAL:
	{
        parse_command(c->cmd1, level + 1, c);
        return parse_command(c->cmd2, level + 1, c);
        break;
    }

	case OP_PARALLEL:
	{
		/* execute the commands simultaneously */
		return do_in_parallel(c->cmd1, c->cmd2, level + 1, c);
		break;
    }

	case OP_CONDITIONAL_NZERO:
	{
		/* execute the second command only if the first one
                 * returns non zero */
        ret = parse_command(c->cmd1, level + 1, c);
        if (ret != 0) {
            return parse_command(c->cmd2, level + 1, c);
        }
		break;
    }

	case OP_CONDITIONAL_ZERO:
		/* execute the second command only if the first one
                 * returns zero */
    {
        ret = parse_command(c->cmd1, level + 1, c);
        if (ret == 0) {
            return parse_command(c->cmd2, level + 1, c);
        }
		break;
    }

	case OP_PIPE:
		/* redirect the output of the first command to the
		 * input of the second */
		return do_on_pipe(c->cmd1, c->cmd2, level + 1, c);
		break;

	default:
		assert(false);
	}

	return 0;
}

/**
 * Readline from mini-shell.
 */
char *read_line()
{
	char *instr;
	char *chunk;
	char *ret;

	int instr_length;
	int chunk_length;

	int endline = 0;

	instr = NULL;
	instr_length = 0;

	chunk = calloc(CHUNK_SIZE, sizeof(char));
	if (chunk == NULL) {
		fprintf(stderr, ERR_ALLOCATION);
		return instr;
	}

	while (!endline) {
		ret = fgets(chunk, CHUNK_SIZE, stdin);
		if (ret == NULL) {
			break;
		}

		chunk_length = strlen(chunk);
		if (chunk[chunk_length - 1] == '\n') {
			chunk[chunk_length - 1] = 0;
			endline = 1;
		}

		ret = instr;
		instr = realloc(instr, instr_length + CHUNK_SIZE + 1);
		if (instr == NULL) {
			free(ret);
			return instr;
		}
		memset(instr + instr_length, 0, CHUNK_SIZE);
		strcat(instr, chunk);
		instr_length += chunk_length;
	}

	free(chunk);

	return instr;
}

