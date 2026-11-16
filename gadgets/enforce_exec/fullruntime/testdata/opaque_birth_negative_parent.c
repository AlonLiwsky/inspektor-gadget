// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
// Disposable audit-only fault probe: hold a real child before and after exec.
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static int child_loop(int after)
{
	printf("%s:%ld\n", after ? "EXEC-OK" : "BEFORE", (long)getpid());
	fflush(stdout);
	char line[32];
	while (fgets(line, sizeof(line), stdin)) {
		if (!strcmp(line, "DONE\n"))
			return 0;
		if (strcmp(line, "EXEC\n"))
			return 91;
		execl("/proc/self/exe", "opaque-birth-negative", "child",
		      (char *)0);
		printf("EXEC-ERR:%ld:%d\n", (long)getpid(), errno);
		fflush(stdout);
	}
	return 92;
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "child"))
		return child_loop(1);
	if (argc != 1)
		return 93;
	puts("READY");
	fflush(stdout);
	char line[32];
	while (fgets(line, sizeof(line), stdin)) {
		if (!strcmp(line, "DONE\n"))
			return 0;
		if (strcmp(line, "FORK\n"))
			return 94;
		pid_t child = fork();
		if (child < 0)
			return 95;
		if (!child)
			return child_loop(0);
		int status = 0;
		if (waitpid(child, &status, 0) != child)
			return 96;
		printf("REAPED:%ld:%d\n", (long)child,
		       WIFEXITED(status) ? WEXITSTATUS(status) : -1);
		fflush(stdout);
	}
	return 97;
}
