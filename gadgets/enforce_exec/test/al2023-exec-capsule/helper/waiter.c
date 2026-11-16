// SPDX-License-Identifier: Apache-2.0
/* Test-only trigger for the exec-capsule fixture. A NONLEADER thread execs the
 * script given as argv[1] (and blocks in the runner's fanotify permission
 * check on the interpreter while holding cred_guard_mutex). A second nonleader
 * thread then calls execve and waits on the same mutex: it is the same-TGID
 * losing waiter that de_thread() kills. The leader only waits.
 *
 * "waiter exec PATH" instead execs PATH directly. The Go runner starts its
 * children with vfork and stays blocked until their exec completes; a child
 * whose exec waits on the runner's own fanotify response would deadlock the
 * Go runtime, so the runner execs this launcher first. */
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static char *script;

static void *winner(void *unused)
{
	(void)unused;
	char *argv[] = { script, NULL };
	char *envp[] = { NULL };
	execve(script, argv, envp);
	_exit(101);
}

static void *loser(void *unused)
{
	(void)unused;
	struct timespec delay = { 0, 300 * 1000 * 1000 };
	nanosleep(&delay, NULL);
	char *argv[] = { "/bin/true", NULL };
	char *envp[] = { NULL };
	execve("/bin/true", argv, envp);
	_exit(102);
}

int main(int argc, char **argv)
{
	if (argc == 3 && argv[1][0] == 'e' && argv[1][1] == 'x' &&
	    argv[1][2] == 'e' && argv[1][3] == 'c' && !argv[1][4]) {
		char *child[] = { argv[2], NULL };
		char *envp[] = { NULL };
		execve(argv[2], child, envp);
		return 104;
	}
	if (argc != 2)
		return 2;
	script = argv[1];
	pthread_t a, b;
	if (pthread_create(&a, NULL, winner, NULL) ||
	    pthread_create(&b, NULL, loser, NULL))
		return 3;
	for (;;)
		pause();
}
