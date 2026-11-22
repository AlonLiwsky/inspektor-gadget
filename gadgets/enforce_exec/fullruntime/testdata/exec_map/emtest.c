// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

/* Test helper of TestSharedNodeExecMapAttached. Exit 0: the mapping worked;
 * 13: refused with EACCES; 1: another failure. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static int fail(const char *what)
{
	int e = errno;
	printf("%s: %s\n", what, strerror(e));
	return e == EACCES ? 13 : 1;
}
/* mov eax, 42; ret */
static const unsigned char code[] = { 0xb8, 0x2a, 0x00, 0x00, 0x00, 0xc3 };

int main(int argc, char **argv)
{
	const char *op = argc > 1 ? argv[1] : "";
	const char *path = argc > 2 ? argv[2] : 0;
	if (!strcmp(op, "dlopen") && path) {
		if (!dlopen(path, RTLD_NOW)) {
			printf("dlopen: %s\n", dlerror());
			return 13;
		}
		return 0;
	}
	if ((!strcmp(op, "mmapx") || !strcmp(op, "mprotx") ||
	     !strcmp(op, "modx")) &&
	    path) {
		int fd = open(path, O_RDONLY);
		if (fd < 0)
			return fail("open");
		if (!strcmp(op, "mmapx")) {
			if (mmap(0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE,
				 fd, 0) == MAP_FAILED)
				return fail("mmap exec");
			return 0;
		}
		int prot = PROT_READ | (!strcmp(op, "modx") ? PROT_WRITE : 0);
		char *p = mmap(0, 4096, prot, MAP_PRIVATE, fd, 0);
		if (p == MAP_FAILED)
			return fail("mmap");
		if (!strcmp(op, "modx"))
			*(volatile char *)p = p[0]; /* a private written page */
		if (mprotect(p, 4096, PROT_READ | PROT_EXEC))
			return fail("mprotect exec");
		return 0;
	}
	if (!strcmp(op, "bench") && path && argc > 3) {
		long n = atol(argv[3]), ok = 0;
		int fd = open(path, O_RDONLY);
		if (fd < 0)
			return fail("open");
		struct timespec a, b;
		clock_gettime(CLOCK_MONOTONIC, &a);
		for (long i = 0; i < n; i++) {
			void *p = mmap(0, 4096, PROT_READ | PROT_EXEC,
				       MAP_PRIVATE, fd, 0);
			if (p != MAP_FAILED) {
				ok++;
				munmap(p, 4096);
			}
		}
		clock_gettime(CLOCK_MONOTONIC, &b);
		double ns =
			(b.tv_sec - a.tv_sec) * 1e9 + (b.tv_nsec - a.tv_nsec);
		printf("maps=%ld ok=%ld ns_per_map=%.0f\n", n, ok, ns / n);
		return 0;
	}
	if (!strcmp(op, "memfdx")) {
		int fd = memfd_create("emtest", 0);
		if (fd < 0 || write(fd, code, sizeof(code)) != sizeof(code))
			return fail("memfd");
		if (mmap(0, 4096, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0) ==
		    MAP_FAILED)
			return fail("mmap exec memfd");
		return 0;
	}
	if (!strcmp(op, "anonx") || !strcmp(op, "anonwx")) {
		int rwx = !strcmp(op, "anonwx");
		unsigned char *p = mmap(
			0, 4096, PROT_READ | PROT_WRITE | (rwx ? PROT_EXEC : 0),
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED)
			return fail("mmap anon");
		memcpy(p, code, sizeof(code));
		if (!rwx && mprotect(p, 4096, PROT_READ | PROT_EXEC))
			return fail("mprotect exec anon");
		int r = ((int (*)(void))p)();
		printf("anon code returned %d\n", r);
		return r == 42 ? 0 : 1;
	}
	return 2;
}
