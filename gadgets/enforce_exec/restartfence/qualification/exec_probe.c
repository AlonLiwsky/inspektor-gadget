// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Independent workload probe. Start before fencing, place its PID in a child
// cgroup of the pod binding, then submit "batch count" lines on stdin. Each
// batch attempts denied then allowed paths count times. No shell translates
// errno: a CLOEXEC pipe carries the exact execve failure back to the parent.
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		perror("clock_gettime");
		exit(2);
	}
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int attempt(const char *path, const char *target, unsigned long batch,
		   unsigned long sample)
{
	int pipefd[2];
	if (pipe2(pipefd, O_CLOEXEC)) {
		perror("pipe2");
		return 2;
	}
	uint64_t start = now_ns();
	pid_t child = fork();
	if (child < 0) {
		perror("fork");
		close(pipefd[0]);
		close(pipefd[1]);
		return 2;
	}
	if (!child) {
		close(pipefd[0]);
		char *const argv[] = { (char *)path, "marker", NULL };
		char *const envp[] = { NULL };
		execve(path, argv, envp);
		int error = errno;
		ssize_t n;
		do {
			n = write(pipefd[1], &error, sizeof(error));
		} while (n < 0 && errno == EINTR);
		_exit(n == sizeof(error) ? 100 : 101);
	}
	close(pipefd[1]);
	int error = 0;
	size_t used = 0;
	int bad = 0;
	for (;;) {
		ssize_t n = read(pipefd[0], (char *)&error + used,
				 sizeof(error) - used);
		if (n < 0 && errno == EINTR)
			continue;
		if (n < 0) {
			perror("read errno");
			bad = 1;
			break;
		}
		if (!n)
			break;
		used += (size_t)n;
		if (used == sizeof(error))
			break;
	}
	close(pipefd[0]);
	int status;
	pid_t waited;
	do {
		waited = waitpid(child, &status, 0);
	} while (waited < 0 && errno == EINTR);
	if (waited < 0) {
		perror("waitpid");
		return 2;
	}
	if (bad || (used != 0 && used != sizeof(error)) ||
	    (used == sizeof(error) && error <= 0)) {
		fprintf(stderr, "invalid errno channel\n");
		return 2;
	}
	int exited = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
	int signal = WIFSIGNALED(status) ? WTERMSIG(status) : 0;
	printf("{\"batch\":%lu,\"sample\":%lu,\"target\":\"%s\","
	       "\"errno\":%d,\"exit\":%d,\"signal\":%d,"
	       "\"start_ns\":%" PRIu64 ",\"end_ns\":%" PRIu64 "}\n",
	       batch, sample, target, error, exited, signal, start, now_ns());
	if (fflush(stdout) || ferror(stdout))
		return 2;
	// Failure of the observation machinery is never an enforcement verdict.
	if (signal || (used == sizeof(error) ? exited != 100 : exited != 0)) {
		fprintf(stderr, "unexpected probe child status\n");
		return 2;
	}
	return 0;
}

int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "marker"))
		return 0;
	if (argc != 4 || strcmp(argv[1], "serve")) {
		fprintf(stderr,
			"usage: exec-probe serve DENIED_PATH ALLOWED_PATH\n");
		return 2;
	}
	printf("{\"ready_pid\":%ld}\n", (long)getpid());
	if (fflush(stdout))
		return 2;
	char line[128];
	while (fgets(line, sizeof(line), stdin)) {
		unsigned long batch, count;
		char extra;
		if (sscanf(line, "%lu %lu %c", &batch, &count, &extra) != 2 ||
		    count == 0 || count > 1000000UL) {
			fprintf(stderr,
				"expected batch count (count 1..1000000)\n");
			return 2;
		}
		for (unsigned long i = 0; i < count; i++) {
			if (attempt(argv[2], "denied", batch, i) ||
			    attempt(argv[3], "allowed", batch, i))
				return 2;
		}
	}
	if (ferror(stdin)) {
		perror("read commands");
		return 2;
	}
	return 0;
}
