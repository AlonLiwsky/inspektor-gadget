// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
// Diagnostic: keep SYS_ADMIN permitted/bounding but clear effective before exec.
#define _GNU_SOURCE
#include <linux/capability.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sched.h>
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
	if (argc < 3)
		return 2;
	if (!strcmp(argv[1], "echo")) {
		puts(argv[2]);
		return 0;
	}
	struct __user_cap_header_struct h = {
		.version = _LINUX_CAPABILITY_VERSION_3
	};
	struct __user_cap_data_struct d[2] = {};
	if (syscall(SYS_capget, &h, d)) {
		perror("capget");
		return 2;
	}
	if (!strcmp(argv[1], "receive")) {
		int rootfd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (rootfd < 0) {
			perror("open root");
			return 2;
		}
		int sock = socket(AF_UNIX, SOCK_STREAM, 0);
		struct sockaddr_un addr = { .sun_family = AF_UNIX };
		strcpy(addr.sun_path, "/handoff/ns.sock");
		if (sock < 0 ||
		    connect(sock, (struct sockaddr *)&addr, sizeof(addr))) {
			perror("connect");
			return 2;
		}
		char byte, control[CMSG_SPACE(sizeof(int))];
		struct iovec iov = { .iov_base = &byte, .iov_len = 1 };
		struct msghdr msg = { .msg_iov = &iov,
				      .msg_iovlen = 1,
				      .msg_control = control,
				      .msg_controllen = sizeof(control) };
		if (recvmsg(sock, &msg, MSG_CMSG_CLOEXEC) != 1) {
			perror("recvmsg");
			return 2;
		}
		struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
		if (!c || c->cmsg_level != SOL_SOCKET ||
		    c->cmsg_type != SCM_RIGHTS ||
		    c->cmsg_len != CMSG_LEN(sizeof(int)))
			return 2;
		int fd;
		memcpy(&fd, CMSG_DATA(c), sizeof(fd));
		close(sock);
		puts("RECEIVED_HOST_NAMESPACE_FD");
		fflush(stdout);
		if (setns(fd, CLONE_NEWNS)) {
			fprintf(stderr, "SETNS_FAILED errno=%d %s\n", errno,
				strerror(errno));
			close(fd);
			return 1;
		}
		close(fd);
		if (fchdir(rootfd) || chroot(".")) {
			perror("restore container root");
			return 2;
		}
		close(rootfd);
		puts("SETNS_SUCCEEDED");
		fflush(stdout);
		execv(argv[2], argv + 2);
		perror("execv");
		return 2;
	}
	if (!strcmp(argv[1], "clear-effective")) {
		d[0].effective = d[1].effective = 0;
		if (syscall(SYS_capset, &h, d)) {
			perror("capset");
			return 2;
		}
		puts("CLEARED_EFFECTIVE; permitted and bounding unchanged");
		fflush(stdout);
		execv(argv[2], argv + 2);
		perror("execv");
		return 2;
	}
	return 2;
}
