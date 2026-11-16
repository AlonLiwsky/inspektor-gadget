// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

/* G020 carryover D (TestSharedNodeExecveCheckAttached): one
 * execveat(AT_FDCWD, path, AT_EXECVE_CHECK). Exit 0 when it returned 0,
 * else its errno (EINVAL on 6.12, which rejects the flag); exit 2 without a
 * path (the test's calibration: the same process, no execveat). Build:
 * gcc -static -O2 -o shared-execve-check shared_execve_check.c */
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AT_EXECVE_CHECK
#define AT_EXECVE_CHECK 0x10000
#endif

int main(int argc, char **argv)
{
	extern char **environ;
	if (argc != 2)
		return 2;
	char *args[] = { argv[1], 0 };
	long rc = syscall(SYS_execveat, AT_FDCWD, argv[1], args, environ,
			  AT_EXECVE_CHECK);
	return rc ? (errno ? errno : 1) : 0;
}
