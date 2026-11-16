// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
/* Disposable held target for pidfd->task_kill zero-signal observation. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>

static int precreated_swap_pipe[2] = { -1, -1 };
static pid_t held_children[64];
static int held_count;
static int qualified_control[8], qualified_result[8], qualified_count;

static int release_held_children(void)
{
	int count = held_count;
	for (int i = 0; i < count; i++)
		if (kill(held_children[i], SIGTERM))
			return -1;
	for (int i = 0; i < count; i++) {
		int status;
		if (waitpid(held_children[i], &status, 0) != held_children[i] ||
		    !WIFSIGNALED(status) || WTERMSIG(status) != SIGTERM)
			return -1;
	}
	held_count = 0;
	for (int i = 0; i < qualified_count; i++) {
		close(qualified_control[i]);
		close(qualified_result[i]);
	}
	qualified_count = 0;
	return count;
}

static void *exec_from_nonleader(void *unused)
{
	(void)unused;
	char *const args[] = { "/proc/self/exe", "resume", NULL };
	execv(args[0], args);
	perror("nonleader exec");
	return NULL;
}

static void *exec_from_precreated_nonleader(void *unused)
{
	(void)unused;
	char command;
	if (read(precreated_swap_pipe[0], &command, 1) != 1 || command != 'T')
		_exit(101);
	exec_from_nonleader(NULL);
	_exit(102);
}

int main(int argc, char **argv)
{
	if (argc == 2 && argv[1][0] == 'r') {
		puts("SWAPPED");
		fflush(stdout);
		char command;
		return read(STDIN_FILENO, &command, 1) == 1 && command == 'X' ?
			       0 :
			       96;
	}
	if (argc != 2 || argv[1][0] != '/')
		return 90;
	if (getenv("IG_TEST_ISOLATE_MOUNT_NS") && unshare(CLONE_NEWNS)) {
		perror("unshare mount namespace");
		return 100;
	}
	int precreated_swap = getenv("IG_TEST_PRECREATE_SWAP_THREAD") != NULL;
	if (precreated_swap) {
		pthread_t thread;
		if (pipe(precreated_swap_pipe) ||
		    pthread_create(&thread, NULL,
				   exec_from_precreated_nonleader, NULL))
			return 101;
	}
	puts("READY");
	fflush(stdout);
	char command;
	if (read(STDIN_FILENO, &command, 1) != 1 || command != 'M')
		return 91;
	char path[512], pid[32];
	int n = snprintf(path, sizeof(path), "%s/cgroup.procs", argv[1]);
	if (n <= 0 || n >= (int)sizeof(path))
		return 92;
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return 93;
	n = snprintf(pid, sizeof(pid), "%ld", (long)getpid());
	if (n <= 0 || n >= (int)sizeof(pid) || write(fd, pid, n) != n) {
		close(fd);
		return 94;
	}
	close(fd);
	puts("IN_CGROUP");
	fflush(stdout);
	for (;;) {
		if (read(STDIN_FILENO, &command, 1) != 1)
			return 95;
		if (command == 'F') {
			pid_t child = fork();
			if (child < 0)
				return 99;
			if (child == 0)
				_exit(0);
			int status = 0;
			if (waitpid(child, &status, 0) != child ||
			    !WIFEXITED(status) || WEXITSTATUS(status) != 0)
				return 99;
			printf("FORKED:%d\n", child);
			fflush(stdout);
			continue;
		}
		if (command == 'H') {
			if (held_count == 64)
				return 103;
			pid_t parent = getpid();
			pid_t child = fork();
			if (child < 0) {
				printf("DENIED:%d\n", errno);
				fflush(stdout);
				continue;
			}
			if (child == 0) {
				if (prctl(PR_SET_PDEATHSIG, SIGKILL) ||
				    getppid() != parent)
					_exit(104);
				for (;;)
					pause();
			}
			held_children[held_count++] = child;
			printf("HELD:%d\n", child);
			fflush(stdout);
			continue;
		}
		if (command == 'Q') {
			if (held_count == 64 || qualified_count == 8)
				return 107;
			int control[2], result[2];
			if (pipe(control) || pipe(result))
				return 108;
			pid_t parent = getpid();
			pid_t child = fork();
			if (child < 0)
				return 109;
			if (child == 0) {
				close(control[1]);
				close(result[0]);
				if (prctl(PR_SET_PDEATHSIG, SIGKILL) ||
				    getppid() != parent ||
				    write(result[1], "R", 1) != 1)
					_exit(110);
				char action;
				if (read(control[0], &action, 1) != 1 ||
				    action != 'B')
					_exit(111);
				/* All held parents must reach this barrier before any of
				 * them attempts its first fork. */
				if (write(result[1], "A", 1) != 1 ||
				    read(control[0], &action, 1) != 1 ||
				    action != 'G')
					_exit(118);
				pid_t grandchild = fork();
				char outcome = '0';
				if (grandchild < 0) {
					if (errno != EPERM)
						outcome = 'E';
				} else if (grandchild == 0) {
					_exit(0);
				} else {
					int status;
					if (waitpid(grandchild, &status, 0) !=
						    grandchild ||
					    !WIFEXITED(status) ||
					    WEXITSTATUS(status) != 0)
						outcome = 'E';
					else
						outcome = '1';
				}
				if (write(result[1], &outcome, 1) != 1)
					_exit(112);
				for (;;)
					pause();
			}
			close(control[0]);
			close(result[1]);
			char ready;
			if (read(result[0], &ready, 1) != 1 || ready != 'R')
				return 113;
			held_children[held_count++] = child;
			qualified_control[qualified_count] = control[1];
			qualified_result[qualified_count++] = result[0];
			printf("QUALIFIED_PARENT:%d\n", child);
			fflush(stdout);
			continue;
		}
		if (command == 'B') {
			if (!qualified_count)
				return 114;
			for (int i = 0; i < qualified_count; i++)
				if (write(qualified_control[i], "B", 1) != 1)
					return 115;
			for (int i = 0; i < qualified_count; i++) {
				char arrived;
				if (read(qualified_result[i], &arrived, 1) !=
					    1 ||
				    arrived != 'A')
					return 119;
			}
			for (int i = 0; i < qualified_count; i++)
				if (write(qualified_control[i], "G", 1) != 1)
					return 120;
			int succeeded = 0, denied = 0;
			for (int i = 0; i < qualified_count; i++) {
				char outcome;
				if (read(qualified_result[i], &outcome, 1) != 1)
					return 116;
				if (outcome == '1')
					succeeded++;
				else if (outcome == '0')
					denied++;
				else
					return 117;
			}
			printf("BURST:%d:%d\n", succeeded, denied);
			fflush(stdout);
			continue;
		}
		if (command == 'R') {
			int count = release_held_children();
			if (count < 0)
				return 105;
			printf("REAPED:%d\n", count);
			fflush(stdout);
			continue;
		}
		if (command == 'T') {
			if (precreated_swap) {
				if (write(precreated_swap_pipe[1], "T", 1) != 1)
					return 102;
				for (;;)
					pause(); /* nonleader exec replaces this leader */
			}
			pthread_t thread;
			if (pthread_create(&thread, NULL, exec_from_nonleader,
					   NULL))
				return 97;
			pthread_join(thread, NULL);
			return 98;
		}
		if (command == 'X')
			return held_count && release_held_children() < 0 ? 106 :
									   0;
		return 95;
	}
}
