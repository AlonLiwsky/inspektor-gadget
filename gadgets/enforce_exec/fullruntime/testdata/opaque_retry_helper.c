/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Isolated test helper: enter the cgroup without creating a charged child,
 * survive one exact EPERM from fork(), then retry from this same PID after
 * the controller releases quota. FD 3 is the retry signal, FD 4 the status. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int enter_cgroup(const char *path)
{
	char file[4096], pid[32];
	int n = snprintf(file, sizeof(file), "%s/cgroup.procs", path);
	if (n <= 0 || n >= (int)sizeof(file))
		return -1;
	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = snprintf(pid, sizeof(pid), "%ld", (long)getpid());
	int ok = n > 0 && n < (int)sizeof(pid) && write(fd, pid, n) == n;
	close(fd);
	return ok ? 0 : -1;
}

int main(int argc, char **argv)
{
	if (argc != 2 || enter_cgroup(argv[1]))
		return 2;
	pid_t child = fork();
	if (child == 0)
		_exit(0);
	if (child >= 0) {
		(void)waitpid(child, 0, 0);
		(void)write(4, "UNEXPECTED\n", 11);
		return 3;
	}
	if (errno != EPERM) {
		(void)write(4, "OTHER\n", 6);
		return 4;
	}
	if (write(4, "EPERM\n", 6) != 6)
		return 5;
	char signal;
	if (read(3, &signal, 1) != 1 || signal != 'R')
		return 6;
	child = fork();
	if (child == 0)
		_exit(0);
	if (child < 0) {
		(void)write(4, "RETRY_FAIL\n", 11);
		return 7;
	}
	int status = 0;
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) ||
	    WEXITSTATUS(status) != 0)
		return 8;
	if (write(4, "OK\n", 3) != 3)
		return 9;
	return 0;
}
