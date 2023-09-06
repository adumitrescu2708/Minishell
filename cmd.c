// SPDX-License-Identifier: BSD-3-Clause
/***
 * @name Dumitrescu Alexandra
 * @date May 2023
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include "cmd.h"
#include "utils.h"

#define		READ		0
#define		WRITE		1
#define		ERROR		-1
#define		MAX_DIR_LEN 100
#define		HOME		"HOME"
#define		OLDPWD		"OLDPWD"

/**
 * --------------- shell_cd
 *
 * BONUS #1 - if no directory is specified, we check if the HOME
 *			variable is set, and if so we change directory to it
 * BONUS #2 - if the given directory is '-', we change directory
 *			to OLDPWD variable, that is reset each time a cd is
 *			called, since chdir doesn't change the OLDPWD variale.
 *
 * Changes directory to specified directory in @param1 and
 * returns ERROR if syscall fails.
 */
static bool shell_cd(word_t *dir)
{
	if (dir == NULL) {
		char *home_dir_name = getenv(HOME);

		if (home_dir_name != NULL) {
			int result = chdir(home_dir_name);
			return result;
		} else {
			return ERROR;
		}
	}
	char *dir_name = get_word(dir);

	if (strcmp(dir_name, "-") == 0) {
		free(dir_name);
		char *old_pwd_dir_name = getenv(OLDPWD);

		if (old_pwd_dir_name != NULL) {
			int result = chdir(old_pwd_dir_name);
			return result;
		} else {
			return ERROR;
		}
	}
	char current_dir[MAX_DIR_LEN];
	char *result_pwd = getcwd(current_dir, MAX_DIR_LEN);

	if (result_pwd != NULL)
		setenv(OLDPWD, result_pwd, 1);

	int result = chdir(dir_name);

	free(dir_name);
	return result;
}

/**
 * --------------- shell_exit
 *
 * Returns exit code.
 */
static int shell_exit(void)
{
	close(STDERR_FILENO);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	#define VALGRIND_FILEDS 3
	close(VALGRIND_FILEDS);
	return SHELL_EXIT;
}

/**
 * --------------- input & output & error redirect methods
 * Later described at comments for parse_simple()
 */
void input_redirect(char *input)
{
	if (input == NULL)
		return;

	if (input != NULL) {
		int input_fd = open(input, O_RDONLY, 666);

		int err_dup2 = dup2(input_fd, STDIN_FILENO);
		int err_close = close(input_fd);

		if (err_dup2 == ERROR || err_close == ERROR)
			exit(-1);
	}
}

void output_error_redirect(char *output, char *err, int io_flags)
{
	if (output != NULL) {
		int output_fd;
		int err_dup2, err_close;

		if (io_flags == IO_REGULAR)
			output_fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 666);
		else if (io_flags == IO_OUT_APPEND)
			output_fd = open(output, O_CREAT | O_WRONLY | O_APPEND, 666);
		err_dup2 = dup2(output_fd, STDOUT_FILENO);

		// Check if there is an error redirection with the same file
		if (err != NULL && strcmp(err, output) == 0)
			err_dup2 = dup2(output_fd, STDERR_FILENO);

		err_close = close(output_fd);
		if (err_dup2 == ERROR || err_close == ERROR)
			exit(-1);
	}
	if (err != NULL) {
		// Check if there isn't already a file descriptor for the same file
		if (!(output != NULL && strcmp(err, output) == 0)) {
			int err_fd, err_dup2, err_close;

			if (io_flags == IO_REGULAR)
				err_fd = open(err, O_WRONLY | O_CREAT | O_TRUNC, 666);
			else if (io_flags == IO_ERR_APPEND)
				err_fd = open(err, O_WRONLY | O_APPEND, 666);

			err_dup2 = dup2(err_fd, STDERR_FILENO);
			err_close = close(err_fd);
			if (err_dup2 == ERROR || err_close == ERROR)
				exit(-1);
		}
	}
}

/**
 * --------------- parse_simple
 *
 * We have the following cases:
 *	a) If the given command is a built-in one (cd/exit/quit) we execute it
 *	b) If the given command is an environment variable assignment, then we
 *	split the parsed command into variable_name and value and call setenv
 *	syscall.
 *	c) If the command is another one, we extract the possible input, output
 *	err redirect files names and the possible arguments. We then fork a new
 *	child process that calls using execvp the given command.
 *		c.1) If there is specified an input redirect file, we open/create it,
 *		then we copy the STDIN_FILENO to the resulted file descriptor.
 *		c.2) If there is specified an output redirect file, depending on the
 *		io flags we open the file either in APPEND mode, or in CREATE mode
 *		If an error output file is also specified and it's the same file,
 *		then we use the same file descriptor for redirecting both the
 *		output and the error log.
 *		c.3) If there is specified an error redirect file we treat the case if
 *		there isn't already an output redirection with the same file.
 *		Similarly to the output redirection, we check the io flags.
 *	The parent process will wait for the status code, free the alloced memory
 *	and return the WEXISTATUS of the received status
 */
static int parse_simple(simple_command_t *s, int level, command_t *father)
{
	if (s == NULL)
		return ERROR;

	int argv_size;
	char *command = get_word(s->verb);

	// (a)
	if (strstr("cd", command) != NULL) {
		char *output = get_word(s->out);

		if (output != NULL) {
			int output_fd = open(output, O_WRONLY | O_CREAT | O_TRUNC, 666);

			close(output_fd);
		}
		int result = shell_cd(s->params);

		free(command);
		free(output);
		return WEXITSTATUS(result);
	}

	// (a)
	if (strstr("exit", command) != NULL) {
		free(command);
		return shell_exit();
	}
	if (strstr("quit", command) != NULL) {
		free(command);
		return shell_exit();
	}

	// (b)
	if (strchr(command, '=') != NULL) {
		char *value = strchr(command, '=') + 1;

		for (int i = 0; i < strlen(command); i++) {
			if (command[i] == '=') {
				command[i] = '\0';
				break;
			}
		}
		int res = setenv(command, value, 1);

		free(command);
		return WEXITSTATUS(res);
	}

	// (c)
	// Extract input/output/err redirect file names and arguments
	char **argv = get_argv(s, &argv_size);
	char *input = NULL, *output = NULL, *err = NULL;

	if (s->in != NULL)
		input = get_word(s->in);

	if (s->out != NULL)
		output = get_word(s->out);

	if (s->err != NULL)
		err = get_word(s->err);


	int status;
	pid_t pid = fork();

	if (pid == 0) {
		// (c.1)
		input_redirect(input);
		// (c.2)
		// (c.3)
		output_error_redirect(output, err, s->io_flags);

		int error = execvp(command, argv);

		if (error == -1) {
			fprintf(stderr, "Execution failed for '%s'\n", command);
			exit(WEXITSTATUS(error));
		}

		free(command);
		for (int i = 0; i < argv_size; i++)
			free(argv[i]);

		free(argv);
		if (input != NULL)
			free(input);

		if (output != NULL)
			free(output);

		if (err != NULL)
			free(err);

		exit(error);
	} else {
		wait(&status);
		free(command);
		for (int i = 0; i < argv_size; i++)
			free(argv[i]);

		free(argv);
		if (input != NULL)
			free(input);

		if (output != NULL)
			free(output);

		if (err != NULL)
			free(err);

		return WEXITSTATUS(status);
	}
}

/**
 * --------------- run_in_parallel
 *	a) We fork 2 new child processes that will execute in parallel
 * the 2 given commands.
 *	b) Suppose in one kid, the command fails, meaning it received value 1. We
 * exit with the returned value in order to announce the parent process that
 * an error occured.
 *	c) The parent process waits for 2 status codes. If both are 0, meaning
 * SUCCESS then we return 0 - false. If not, we return 1.
 */
static bool run_in_parallel(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int status1, status2;
	// (a)
	pid_t pid1 = fork();

	if (pid1 == -1)
		return ERROR;

	if (pid1 == 0) {
		// (b)
		int res = parse_command(cmd1, level + 1, father);

		exit(res);
	} else {
		pid_t pid2 = fork();
		int res;

		switch (pid2) {
		case -1:
			return ERROR;
		case 0:
			res = parse_command(cmd2, level + 1, father);

			exit(res);
		default:
			// (c)
			wait(&status1);
			status1 = (status1);
			wait(&status2);
			status2 = (status2);
			if (status1 == 0 && status2 == 0)
				return 0;
			if (status1 != 0)
				return 1;
			else
				return 1;
		}
	}
	return 1;
}

/**
 * --------------- run_on_pipe
 * a) We fork 2 new child processes that will communicate via a pipe and
 * execute the 2 given commands.
 * b) The first child, will use the 2nd file descriptor to redirect its output
 * It, then, executes the first command.
 * c) The second child will use the first file descriptor to get its input and
 * print the output. It then executes the second command.
 * d) The parent will wait in order for the first child's status and then for
 * the next one's. The resulted status code will be the one determined from
 * the second one.
 */
static bool run_on_pipe(command_t *cmd1, command_t *cmd2, int level,
		command_t *father)
{
	int fileds[2];
	int status1, status2;
	int err = pipe(fileds);

	if (err == ERROR)
		return ERROR;
	// (a)
	pid_t pid1, pid2;

	for (int i = 0; i < 2; i++) {
		if (i == 0) {
			// (b)
			pid1 = fork();

			switch (pid1) {
			case -1:
				return ERROR;
			case 0:
				close(fileds[0]);
				int res_dup2 = dup2(fileds[1], STDOUT_FILENO);

				if (res_dup2 == -1)
					return ERROR;

				int ret = parse_command(cmd1, level + 1, father);

				close(fileds[1]);
				exit(ret);
			default:
				continue;
			}
		} else if (i == 1) {
			// (c)
			pid2 = fork();

			switch (pid2) {
			case -1:
				return ERROR;
			case 0:
				close(fileds[1]);
				int res_dup2 = dup2(fileds[0], STDIN_FILENO);

				if (res_dup2 == -1)
					return ERROR;

				int ret = parse_command(cmd2, level + 1, father);

				close(fileds[0]);
				exit(ret);
			default:
				continue;
			}
		}
	}
	// (d)
	close(fileds[0]);
	close(fileds[1]);
	waitpid(pid1, &status1, 0);
	waitpid(pid2, &status2, 0);

	if (status2 == 0)
		return status2;
	return 1;
}

/**
 * --------------- parse_command
 */
int parse_command(command_t *c, int level, command_t *father)
{
	int result, result_2;

	// check NULL command
	if (c == NULL)
		return ERROR;

	// if the given command is a leaf, we simply execute the command
	if (c->op == OP_NONE)
		return parse_simple(c->scmd, level + 1, father);

	switch (c->op) {
	// In SEQUENTIAL case, the main oprocess first parses the first command,
	// then the second one and return 0 if both returned SUCCESS and 1 otherwise.
	case OP_SEQUENTIAL:
		result = parse_command(c->cmd1, level + 1, father);
		result_2 = parse_command(c->cmd2, level + 1, father);
		if (result == 0 && result_2 == 0)
			return 0;

		if (result != 0)
			return result;

		return result_2;
	case OP_PARALLEL:
		// in PARALLEL case we execute the previous described method.
		return run_in_parallel(c->cmd1, c->cmd2, level + 1, c);

	case OP_CONDITIONAL_NZERO:
		// In CONDITIONAL NZERO case the main process will first execute the
		// first command and cxontinue executing the second command only if
		// the first one failed.
		result = parse_command(c->cmd1, level + 1, father);

		if (result != 0)
			return parse_command(c->cmd2, level + 1, father);
		else
			return result;
	case OP_CONDITIONAL_ZERO:
		// In CONDITIONAL ZERO case the main process will first execute the
		// first command and cxontinue executing the second command only if
		// the first one succeded.
		result = parse_command(c->cmd1, level + 1, father);
		if (result == 0)
			return parse_command(c->cmd2, level + 1, father);
		else
			return result;

	case OP_PIPE:
		// in PIPE case we execute the previous described method.
		return run_on_pipe(c->cmd1, c->cmd2, level + 1, father);

	default:
		return SHELL_EXIT;
	}

	return 0;
}
