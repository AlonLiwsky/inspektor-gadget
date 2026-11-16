/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* G020 image facts test helper (static): copy argv[1] into a memfd and
 * fexecve it. Exits 126 when the exec is refused with EPERM, 127 on any
 * other failure. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <unistd.h>

extern char **environ;

int main(int argc, char **argv)
{
	if (argc != 2)
		return 2;
	int in = open(argv[1], O_RDONLY | O_CLOEXEC);
	struct stat st;
	if (in < 0 || fstat(in, &st))
		return 127;
	int fd = memfd_create("ig20-image", MFD_CLOEXEC);
	if (fd < 0)
		return 127;
	off_t off = 0;
	while (off < st.st_size)
		if (sendfile(fd, in, &off, st.st_size - off) <= 0)
			return 127;
	char *args[] = { argv[1], 0 };
	fexecve(fd, args, environ);
	fprintf(stderr, "fexecve: %d\n", errno);
	return errno == EPERM ? 126 : 127;
}
