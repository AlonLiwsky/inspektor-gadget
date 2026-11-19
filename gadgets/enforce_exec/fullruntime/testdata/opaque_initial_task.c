// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
// Disposable current-task constructor probe; not a trusted runtime init.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc != 2 || argv[1][0] != '/')
		return 90;
	puts("READY");
	fflush(stdout);
	char go;
	if (read(STDIN_FILENO, &go, 1) != 1 || go != 'G')
		return 91;
	char path[512], pid[32];
	int n = snprintf(path, sizeof(path), "%s/cgroup.procs", argv[1]);
	if (n <= 0 || n >= (int)sizeof(path))
		return 92;
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return 93;
	n = snprintf(pid, sizeof(pid), "%ld", (long)getpid());
	if (n <= 0 || n >= (int)sizeof(pid) || write(fd, pid, n) != n) {
		close(fd);
		return 94;
	}
	close(fd);
	if (prctl(PR_SET_NAME, "ig15-initial") != 0) {
		printf("ROOTFAIL:%d\n", errno);
		return 95;
	}
	pid_t child = fork();
	if (child < 0) {
		printf("FORKFAIL:%d\n", errno);
		return 96;
	}
	if (child == 0)
		_exit(0);
	int status = 0;
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		return 97;
	if (prctl(PR_SET_NAME, "ig15-replay") != -1 || errno != EPERM)
		return 98;
	puts("ROOT_FORK_OK");
	return 0;
}
