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
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/shm.h>
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

/* Run the code at p (it must return 42). */
static int run_code(const void *p, const char *what)
{
	int r = ((int (*)(void))p)();
	printf("%s code returned %d\n", what, r);
	return r == 42 ? 0 : 1;
}

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
	/* A JIT's double mapping: one RW view and one RX view of one memfd. */
	if (!strcmp(op, "dualmap")) {
		int fd = memfd_create("emdual", 0);
		if (fd < 0 || ftruncate(fd, 4096))
			return fail("memfd");
		unsigned char *rw = mmap(0, 4096, PROT_READ | PROT_WRITE,
					 MAP_SHARED, fd, 0);
		if (rw == MAP_FAILED)
			return fail("mmap rw view");
		memcpy(rw, code, sizeof(code));
		void *rx =
			mmap(0, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
		if (rx == MAP_FAILED)
			return fail("mmap rx view");
		return run_code(rx, "dual");
	}
	/* Shared anonymous memory (shmem_zero_setup), made executable. */
	if (!strcmp(op, "shmanonx")) {
		unsigned char *p = mmap(0, 4096, PROT_READ | PROT_WRITE,
					MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED)
			return fail("mmap shared anon");
		memcpy(p, code, sizeof(code));
		if (mprotect(p, 4096, PROT_READ | PROT_EXEC))
			return fail("mprotect exec shared anon");
		return run_code(p, "shmanon");
	}
	/* SysV shm: shmat(SHM_EXEC), or shmat RW then mprotect +EXEC. */
	if (!strcmp(op, "shmatx") || !strcmp(op, "shmprotx")) {
		int id = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
		if (id < 0)
			return fail("shmget");
		unsigned char *w = shmat(id, 0, 0);
		if (w == (void *)-1) {
			shmctl(id, IPC_RMID, 0);
			return fail("shmat rw");
		}
		memcpy(w, code, sizeof(code));
		void *x;
		if (!strcmp(op, "shmatx")) {
			x = shmat(id, 0, SHM_EXEC | SHM_RDONLY);
		} else {
			x = w;
			if (mprotect(w, 4096, PROT_READ | PROT_EXEC))
				x = (void *)-1;
		}
		shmctl(id, IPC_RMID, 0);
		if (x == (void *)-1)
			return fail(!strcmp(op, "shmatx") ?
					    "shmat exec" :
					    "mprotect exec shm");
		return run_code(x, "shm");
	}
	/* /dev/zero mapped PROT_EXEC, private or shared. */
	if (!strcmp(op, "zerox") || !strcmp(op, "zerosx")) {
		int fd = open("/dev/zero", O_RDWR);
		if (fd < 0)
			return fail("open /dev/zero");
		int flags = !strcmp(op, "zerox") ? MAP_PRIVATE : MAP_SHARED;
		unsigned char *p = mmap(0, 4096,
					PROT_READ | PROT_WRITE | PROT_EXEC,
					flags, fd, 0);
		if (p == MAP_FAILED)
			return fail("mmap exec /dev/zero");
		memcpy(p, code, sizeof(code));
		return run_code(p, "zero");
	}
	/* POSIX shm (a file on the /dev/shm tmpfs) mapped PROT_EXEC. */
	if (!strcmp(op, "posixshmx")) {
		char name[64];
		snprintf(name, sizeof(name), "/dev/shm/emtest-%d", getpid());
		int fd = open(name, O_RDWR | O_CREAT | O_EXCL, 0600);
		if (fd < 0)
			return fail("open /dev/shm");
		unlink(name);
		if (write(fd, code, sizeof(code)) != sizeof(code) ||
		    ftruncate(fd, 4096))
			return fail("write /dev/shm");
		void *p =
			mmap(0, 4096, PROT_READ | PROT_EXEC, MAP_SHARED, fd, 0);
		if (p == MAP_FAILED)
			return fail("mmap exec /dev/shm");
		return run_code(p, "posixshm");
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
		return run_code(p, "anon");
	}
	return 2;
}
