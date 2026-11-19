// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
// Test-only tracked parent: unlike bash, a failed fork is recoverable here.
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	const int immediate = argc == 2 && !strcmp(argv[1], "immediate");
	if (argc > 2 || (argc == 2 && !immediate))
		return 99;
	char *line = NULL;
	size_t capacity = 0;
	pid_t children[32] = {};
	int live = 0;
	for (int i = 0; i < (immediate ? 32 : 34); i++) {
		if (getline(&line, &capacity, stdin) < 0 ||
		    strcmp(line, "GO\n"))
			return 98;
		pid_t child = fork();
		if (child < 0) {
			printf("STEP:%d:1:%d\n", i, errno);
			fflush(stdout);
		} else if (child == 0) {
			if (immediate) {
				execl("/bin/true", "true", (char *)NULL);
				_exit(99);
			}
			for (;;)
				pause();
		} else {
			if (immediate) {
				int status = 0;
				if (waitpid(child, &status, 0) != child)
					return 94;
				printf("STEP:%d:%d:0\n", i,
				       WIFEXITED(status) &&
						       WEXITSTATUS(status) ==
							       0 ?
					       0 :
					       3);
				fflush(stdout);
				continue;
			}
			if (live >= 32)
				return 97;
			children[live++] = child;
			printf("STEP:%d:0:0\n", i);
			fflush(stdout);
		}
		if (immediate || (i != 32 && i != 33))
			continue;
		if (getline(&line, &capacity, stdin) < 0 ||
		    strcmp(line, "REAP\n"))
			return 98;
		for (int j = 0; j < live; j++) {
			if (kill(children[j], SIGTERM))
				return 96;
			int status = 0;
			if (waitpid(children[j], &status, 0) != children[j] ||
			    !WIFSIGNALED(status) || WTERMSIG(status) != SIGTERM)
				return 95;
		}
		printf("REAPED:%d\n", live);
		fflush(stdout);
		live = 0;
	}
	if (getline(&line, &capacity, stdin) < 0 || strcmp(line, "DONE\n"))
		return 98;
	free(line);
	return 0;
}
