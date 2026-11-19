// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
/* Test-only launcher for TestSharedImageClassifyAttached. It joins the
 * dedicated cgroup BEFORE the measured exec so its own launch is unobserved.
 * usage: helper CGROUP_PROCS exec|fd-unlink|memfd PATH */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
	if (argc != 4)
		return 99;
	int cg = open(argv[1], O_WRONLY | O_CLOEXEC);
	if (cg < 0 || write(cg, "0", 1) != 1 || close(cg))
		return 98;
	char *args[] = { argv[3], 0 }, *env[] = { 0 };
	if (!strcmp(argv[2], "exec")) {
		execve(argv[3], args, env);
		return errno;
	}
	int fd = -1;
	if (!strcmp(argv[2], "fd-unlink")) {
		fd = open(argv[3], O_RDONLY | O_CLOEXEC);
		if (fd < 0 || unlink(argv[3]))
			return 97;
	} else if (!strcmp(argv[2], "memfd")) {
		int src = open(argv[3], O_RDONLY | O_CLOEXEC);
		fd = memfd_create("ig15-g020-image", MFD_CLOEXEC);
		if (src < 0 || fd < 0)
			return 96;
		char buf[65536];
		for (;;) {
			ssize_t n = read(src, buf, sizeof(buf));
			if (n < 0)
				return 95;
			if (!n)
				break;
			if (write(fd, buf, n) != n)
				return 95;
		}
		close(src);
	} else {
		return 94;
	}
	syscall(SYS_execveat, fd, "", args, env, AT_EMPTY_PATH);
	return errno;
}
