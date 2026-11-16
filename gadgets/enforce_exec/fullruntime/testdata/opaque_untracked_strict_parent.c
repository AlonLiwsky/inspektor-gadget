// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
// Disposable probe: enter a strict route after birth, without a TASK owner.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc != 2 || argv[1][0] != '/')
		return 90;
	char path[512];
	int n = snprintf(path, sizeof(path), "%s/cgroup.procs", argv[1]);
	if (n <= 0 || n >= (int)sizeof(path))
		return 91;
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return 92;
	char pid[32];
	n = snprintf(pid, sizeof(pid), "%ld", (long)getpid());
	if (n <= 0 || n >= (int)sizeof(pid) || write(fd, pid, n) != n) {
		close(fd);
		return 93;
	}
	close(fd);
	pid_t child = fork();
	if (child == -1 && errno == EPERM) {
		puts("EPERM_SURVIVED");
		return 0;
	}
	if (child == 0)
		_exit(0);
	if (child > 0)
		(void)waitpid(child, NULL, 0);
	fprintf(stderr, "unexpected fork result=%ld errno=%d\n", (long)child,
		errno);
	return 94;
}
