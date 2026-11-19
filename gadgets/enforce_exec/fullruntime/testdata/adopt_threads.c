// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// adopt_threads: a container-like init with N idle threads for the G019 M4
// adoption tests (TestSharedNodeM4AdoptionThreadExitedAndStuck,
// TestSharedNodeM4AdoptionCloneRefused). Build it static:
// gcc -static -O2 -pthread -o adopt-threads adopt_threads.c
//
// It creates every thread at start, prints "ready <N>" and then creates a
// task only when asked: the byte 'f' read from stdin makes the main thread
// attempt exactly one fork and print "fork <errno>" (0: forked; the child
// _exits at once and is reaped), and the process stays alive whatever the
// outcome (a refused fork never ends it, unlike a shell). Every other byte
// makes exactly one idle thread call pthread_exit (no clone, no fork), so a
// thread can exit between its adoption and the adoption's finish
// deterministically. EOF on stdin leaves the remaining threads idle until
// the process is killed.
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t wake = PTHREAD_COND_INITIALIZER;
static int exits; /* threads asked to exit, not yet gone */

static void *idle(void *arg)
{
	(void)arg;
	pthread_mutex_lock(&lock);
	while (exits == 0)
		pthread_cond_wait(&wake, &lock);
	exits--;
	pthread_mutex_unlock(&lock);
	pthread_exit(NULL);
}

int main(int argc, char **argv)
{
	int n = argc > 1 ? atoi(argv[1]) : 4;
	if (n < 1 || n > 64) {
		fprintf(stderr, "thread count 1..64\n");
		return 2;
	}
	for (int i = 0; i < n; i++) {
		pthread_t t;
		if (pthread_create(&t, NULL, idle, NULL) != 0) {
			perror("pthread_create");
			return 1;
		}
		pthread_detach(t);
	}
	printf("ready %d\n", n);
	fflush(stdout);
	char c;
	while (read(STDIN_FILENO, &c, 1) == 1) {
		if (c == 'f') {
			pid_t pid = fork();
			int err = pid < 0 ? errno : 0;
			if (pid == 0)
				_exit(0);
			if (pid > 0) {
				while (waitpid(pid, NULL, 0) < 0 &&
				       errno == EINTR)
					;
			}
			printf("fork %d\n", err);
			fflush(stdout);
			continue;
		}
		pthread_mutex_lock(&lock);
		exits++;
		pthread_cond_signal(&wake);
		pthread_mutex_unlock(&lock);
	}
	for (;;)
		pause();
}
