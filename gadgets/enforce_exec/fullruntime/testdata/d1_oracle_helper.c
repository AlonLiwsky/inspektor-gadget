// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

/* D1 (LSM-only prototype) oracle helper. Static; the oracle installs it
 * under several paths (helper, promote-ok, marker, interp, denied-interp)
 * so that policy rules select it by target path. The command is argv[1].
 *
 * Every line it prints is KEY=VALUE; an exec failure is reported by its
 * errno, never by a shell's exit status. A child that cannot exec exits
 * with 100 + errno. */
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/io_uring.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MARKER "/d1/marker"

static char *const envp_none[] = { 0 };

static void out(const char *fmt, long value)
{
	char line[128];
	int n = snprintf(line, sizeof(line), fmt, value);
	if (n > 0 && write(1, line, n) != n)
		_exit(98);
}

static int status_of(pid_t pid)
{
	int status = 0;
	while (waitpid(pid, &status, 0) < 0)
		if (errno != EINTR)
			return 250;
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return 200 + (WIFSIGNALED(status) ? WTERMSIG(status) : 0);
}

/* Fork, exec path with one argument; 0 when it ran and exited 0. */
static int run_child(const char *path, const char *arg)
{
	pid_t pid = fork();
	if (pid < 0)
		return 240;
	if (!pid) {
		char *const argv[] = { (char *)path, (char *)arg, 0 };
		execve(path, argv, envp_none);
		_exit(100 + (errno & 0x3f));
	}
	return status_of(pid);
}

struct exec_args {
	const char *path, *arg;
	pthread_barrier_t *barrier;
};

static void *exec_thread(void *p)
{
	struct exec_args *a = p;
	if (a->barrier)
		pthread_barrier_wait(a->barrier);
	char *const argv[] = { (char *)a->path, (char *)a->arg, 0 };
	execve(a->path, argv, envp_none);
	out("ERRNO=%ld\n", errno);
	return 0;
}

static void *idle_thread(void *p)
{
	(void)p;
	for (;;)
		pause();
	return 0;
}


/* S1 review N1: count this process's tasks whose comm starts with prefix. */
static long count_tasks(const char *prefix)
{
	DIR *d = opendir("/proc/self/task");
	if (!d)
		return -1;
	long n = 0;
	struct dirent *e;
	while ((e = readdir(d))) {
		if (e->d_name[0] == '.')
			continue;
		char path[300], comm[32] = { 0 };
		snprintf(path, sizeof(path), "/proc/self/task/%s/comm", e->d_name);
		int fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		if (read(fd, comm, sizeof(comm) - 1) > 0 &&
		    !strncmp(comm, prefix, strlen(prefix)))
			n++;
		close(fd);
	}
	closedir(d);
	return n;
}

/* Count children of this process in state Z. */
static long count_zombies(void)
{
	char path[64];
	snprintf(path, sizeof(path), "/proc/self/task/%d/children", getpid());
	FILE *f = fopen(path, "r");
	if (!f)
		return -1;
	long n = 0;
	int pid;
	while (fscanf(f, "%d", &pid) == 1) {
		char stat[64], buf[256] = { 0 };
		snprintf(stat, sizeof(stat), "/proc/%d/stat", pid);
		int fd = open(stat, O_RDONLY);
		if (fd < 0)
			continue;
		if (read(fd, buf, sizeof(buf) - 1) > 0) {
			char *p = strrchr(buf, ')');
			if (p && p[1] == ' ' && p[2] == 'Z')
				n++;
		}
		close(fd);
	}
	fclose(f);
	return n;
}

static void wait_stdin(void)
{
	char c;
	(void)!read(0, &c, 1);
}

int main(int argc, char **argv)
{
	const char *cmd = argc > 1 ? argv[1] : "noop";
	if (!strcmp(cmd, "noop"))
		return 0;
	/* S1 witness test: N fork attempts from a task alone in a cgroup with
	 * pids.max=1 (the caller puts it there). Each fails in
	 * cgroup_can_fork, AFTER security_task_alloc: the LSM half runs, the
	 * tracepoint half never does. FORK_EAGAIN counts those failures. */
	if (!strcmp(cmd, "bank-forks") && argc > 2) {
		long n = atol(argv[2]), eagain = 0, other = 0;
		for (long i = 0; i < n; i++) {
			pid_t pid = fork();
			if (!pid)
				_exit(0);
			if (pid > 0) {
				waitpid(pid, 0, 0);
				other++;
			} else if (errno == EAGAIN) {
				eagain++;
			}
		}
		out("FORK_EAGAIN=%ld\n", eagain);
		out("FORK_OK=%ld\n", other);
		return 0;
	}
	/* S1 review N1: N io_uring io-wq workers held at once. N opens of a
	 * FIFO with no writer (argv[3], created here): an open always runs in
	 * an io-wq worker and blocks there, so each parks one unbound worker
	 * (create_io_thread: copy_process, no sched_process_fork). A pipe read
	 * would not do: io-wq re-arms poll for it instead of blocking.
	 * Prints WORKERS=, then holds them until a byte on stdin. */
	if (!strcmp(cmd, "iowq") && argc > 3) {
		unsigned n = (unsigned)atol(argv[2]);
		struct rlimit inf = { RLIM_INFINITY, RLIM_INFINITY };
		(void)setrlimit(RLIMIT_NPROC, &inf);
		struct io_uring_params p = { 0 };
		int ring = (int)syscall(SYS_io_uring_setup, n, &p);
		if (ring < 0) {
			out("SETUP_ERRNO=%ld\n", errno);
			return 1;
		}
		/* An open is BOUND work (no file yet): raise both limits. */
		unsigned limits[2] = { n + 64, n + 64 };
		if (syscall(SYS_io_uring_register, ring,
			    IORING_REGISTER_IOWQ_MAX_WORKERS, limits, 2) < 0)
			out("MAXW_ERRNO=%ld\n", errno);
		size_t sqsz = p.sq_off.array + p.sq_entries * sizeof(unsigned);
		char *sq = mmap(0, sqsz, PROT_READ | PROT_WRITE, MAP_SHARED,
				ring, IORING_OFF_SQ_RING);
		struct io_uring_sqe *sqes = mmap(
			0, p.sq_entries * sizeof(struct io_uring_sqe),
			PROT_READ | PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQES);
		if (sq == MAP_FAILED || sqes == MAP_FAILED) {
			out("MMAP_ERRNO=%ld\n", errno);
			return 1;
		}
		unlink(argv[3]);
		if (mkfifo(argv[3], 0600)) {
			out("MKFIFO_ERRNO=%ld\n", errno);
			return 1;
		}
		unsigned *array = (unsigned *)(sq + p.sq_off.array);
		unsigned *tail = (unsigned *)(sq + p.sq_off.tail);
		unsigned t = *tail, mask = *(unsigned *)(sq + p.sq_off.ring_mask);
		for (unsigned i = 0; i < n && i < p.sq_entries; i++) {
			struct io_uring_sqe *e = &sqes[i];
			memset(e, 0, sizeof(*e));
			e->opcode = IORING_OP_OPENAT;
			e->fd = AT_FDCWD;
			e->addr = (unsigned long)argv[3];
			e->open_flags = O_RDONLY;
			/* Straight to io-wq: the inline attempt would add
			 * O_NONBLOCK, and a FIFO opens at once with it. */
			e->flags = IOSQE_ASYNC;
			array[(t + i) & mask] = i;
		}
		__atomic_store_n(tail, t + n, __ATOMIC_RELEASE);
		long sub = syscall(SYS_io_uring_enter, ring, n, 0, 0, 0, 0);
		if (sub < 0)
			out("ENTER_ERRNO=%ld\n", errno);
		long w = 0;
		for (int i = 0; i < 600; i++) { /* up to 60 s */
			w = count_tasks("iou-wrk-");
			if (w >= (long)n)
				break;
			usleep(100000);
		}
		out("SUBMITTED=%ld\n", sub);
		/* Requests that already completed (a worker never parked on
		 * them): COMPLETED and the first result, for the record. */
		{
			size_t cqsz = p.cq_off.cqes + p.cq_entries * sizeof(struct io_uring_cqe);
			char *cq = (p.features & IORING_FEAT_SINGLE_MMAP) ? sq :
				mmap(0, cqsz, PROT_READ | PROT_WRITE, MAP_SHARED, ring, IORING_OFF_CQ_RING);
			if (p.features & IORING_FEAT_SINGLE_MMAP && cqsz > sqsz)
				cq = mmap(0, cqsz, PROT_READ | PROT_WRITE, MAP_SHARED, ring, IORING_OFF_SQ_RING);
			if (cq != MAP_FAILED) {
				unsigned head = *(unsigned *)(cq + p.cq_off.head);
				unsigned ctail = __atomic_load_n((unsigned *)(cq + p.cq_off.tail), __ATOMIC_ACQUIRE);
				out("COMPLETED=%ld\n", (long)(ctail - head));
				if (ctail != head)
					out("FIRST_RES=%ld\n", ((struct io_uring_cqe *)(cq + p.cq_off.cqes))[head & *(unsigned *)(cq + p.cq_off.ring_mask)].res);
			}
		}
		out("WORKERS=%ld\n", w);
		fflush(stdout);
		wait_stdin();
		unlink(argv[3]);
		return 0;
	}
	/* S1 review N1: N unreaped children, each killed after the point of no
	 * return of an exec (argv[3] under RLIMIT_AS argv[4]). Prints ZOMBIES=,
	 * then holds them until a byte on stdin (exiting reparents them). */
	if (!strcmp(cmd, "zombies") && argc > 4) {
		long n = atol(argv[2]);
		rlim_t as = (rlim_t)atoll(argv[4]);
		struct rlimit inf = { RLIM_INFINITY, RLIM_INFINITY };
		(void)setrlimit(RLIMIT_NPROC, &inf);
		for (long i = 0; i < n; i++) {
			pid_t pid = fork();
			if (!pid) {
				struct rlimit r = { as, as };
				if (setrlimit(RLIMIT_AS, &r))
					_exit(98);
				char *const av[] = { argv[3], "noop", 0 };
				execve(argv[3], av, envp_none);
				_exit(100 + errno);
			}
			if (pid < 0) {
				out("FORK_ERRNO=%ld\n", errno);
				break;
			}
		}
		long z = 0;
		for (int i = 0; i < 600; i++) {
			z = count_zombies();
			if (z >= n)
				break;
			usleep(100000);
		}
		out("ZOMBIES=%ld\n", z);
		fflush(stdout);
		wait_stdin();
		return 0;
	}
	/* S1 witness test: N children each exec argv[3] under RLIMIT_AS
	 * argv[4] bytes. The image's mappings exceed it, so the exec fails
	 * after the point of no return (bprm_committed_creds ran,
	 * sched_process_exec never fires) and the kernel kills the child.
	 * LATE counts children killed by a signal. */
	if (!strcmp(cmd, "late-exec") && argc > 4) {
		long n = atol(argv[2]), late = 0, early = 0;
		rlim_t as = (rlim_t)atoll(argv[4]);
		for (long i = 0; i < n; i++) {
			pid_t pid = fork();
			if (!pid) {
				struct rlimit r = { as, as };
				if (setrlimit(RLIMIT_AS, &r))
					_exit(98);
				char *const av[] = { argv[3], "noop", 0 };
				execve(argv[3], av, envp_none);
				_exit(100 + errno);
			}
			int status = 0;
			if (pid < 0 || waitpid(pid, &status, 0) < 0)
				continue;
			if (WIFSIGNALED(status))
				late++;
			else
				early++;
		}
		out("LATE=%ld\n", late);
		out("EARLY=%ld\n", early);
		return 0;
	}
	/* Syscall cost: N getppid calls, nanoseconds per call (best of 5). */
	if (!strcmp(cmd, "bench") && argc > 2) {
		long n = atol(argv[2]), best = -1;
		for (int round = 0; round < 5; round++) {
			struct timespec a, b;
			clock_gettime(CLOCK_MONOTONIC, &a);
			for (long i = 0; i < n; i++)
				syscall(SYS_getppid);
			clock_gettime(CLOCK_MONOTONIC, &b);
			long ns = (b.tv_sec - a.tv_sec) * 1000000000L +
				  (b.tv_nsec - a.tv_nsec);
			if (best < 0 || ns < best)
				best = ns;
		}
		out("NS_PER_1000_SYSCALLS=%ld\n", best * 1000 / n);
		return 0;
	}
	/* The role-b probe: exec the marker in a child. MARKER=0 it ran,
	 * MARKER=101 the exec was refused with EPERM. */
	if (!strcmp(cmd, "marker-check")) {
		out("MARKER=%ld\n", run_child(MARKER, "noop"));
		return 0;
	}
	/* A failing exec in THIS task, then the marker probe from the same
	 * task and from a fresh child. */
	if (!strcmp(cmd, "execfail") && argc > 2) {
		char *const av[] = { argv[2], "noop", 0 };
		execve(argv[2], av, envp_none);
		out("ERRNO=%ld\n", errno);
		out("MARKER=%ld\n", run_child(MARKER, "noop"));
		/* The same task execs again: its own state must be clean. */
		char *const again[] = { argv[0], "noop-after", 0 };
		execve("/d1/helper", again, envp_none);
		out("REEXEC_ERRNO=%ld\n", errno);
		return 1;
	}
	/* A failing exec, then at once (no fork in between) another exec of
	 * the same task, which reports and then probes the marker. */
	if (!strcmp(cmd, "execfail2") && argc > 2) {
		char *const av[] = { argv[2], "noop", 0 };
		execve(argv[2], av, envp_none);
		out("ERRNO=%ld\n", errno);
		char *const again[] = { argv[0], "noop-after2", 0 };
		execve("/d1/helper", again, envp_none);
		out("REEXEC_ERRNO=%ld\n", errno);
		return 1;
	}
	if (!strcmp(cmd, "noop-after2")) {
		out("REEXEC=%ld\n", 0);
		out("MARKER=%ld\n", run_child(MARKER, "noop"));
		return 0;
	}
	if (!strcmp(cmd, "noop-after")) {
		out("REEXEC=%ld\n", 0);
		return 0;
	}
	if (!strcmp(cmd, "exec") && argc > 3) {
		execve(argv[2], argv + 2, envp_none);
		out("ERRNO=%ld\n", errno);
		return 1;
	}
	/* exec as another uid from a child: ST=0 ran, ST=101 EPERM. */
	if (!strcmp(cmd, "asuid") && argc > 4) {
		pid_t pid = fork();
		if (!pid) {
			uid_t id = (uid_t)atoi(argv[2]);
			if (setgroups(0, 0) || setresgid(id, id, id) ||
			    setresuid(id, id, id))
				_exit(97);
			execve(argv[3], argv + 3, envp_none);
			_exit(100 + (errno & 0x3f));
		}
		out("ST=%ld\n", pid < 0 ? 240 : status_of(pid));
		return 0;
	}
	/* fork DEPTH levels (the last one a thread's fork), then asuid. */
	if (!strcmp(cmd, "tree") && argc > 5) {
		int depth = atoi(argv[2]);
		if (depth > 0) {
			pid_t pid = fork();
			if (!pid) {
				char d[16];
				snprintf(d, sizeof(d), "%d", depth - 1);
				char *const av[] = { argv[0], "tree",  d,
						     argv[3], argv[4], argv[5],
						     0 };
				execve("/d1/helper", av, envp_none);
				_exit(100 + (errno & 0x3f));
			}
			int st = pid < 0 ? 240 : status_of(pid);
			if (st)
				out("TREE_FAIL=%ld\n", st);
			return st;
		}
		char *const av[] = { argv[0], "asuid", argv[3],
				     argv[4], argv[5], 0 };
		execve("/d1/helper", av, envp_none);
		_exit(100 + (errno & 0x3f));
	}
	/* A non-leader thread execs: de_thread, the TID becomes the TGID. */
	if (!strcmp(cmd, "thread-exec") && argc > 3) {
		pthread_t t;
		struct exec_args a = { argv[2], argv[3], 0 };
		pthread_t idle;
		pthread_create(&idle, 0, idle_thread, 0);
		if (pthread_create(&t, 0, exec_thread, &a))
			return 3;
		pthread_join(t, 0);
		return 4; /* reached only if the exec failed */
	}
	/* N threads exec at once: one wins, de_thread kills the others. */
	if (!strcmp(cmd, "race-exec") && argc > 4) {
		int n = atoi(argv[2]);
		if (n < 2 || n > 32)
			return 2;
		pthread_barrier_t barrier;
		pthread_barrier_init(&barrier, 0, n);
		struct exec_args a = { argv[3], argv[4], &barrier };
		pthread_t t[32];
		for (int i = 0; i < n; i++)
			if (pthread_create(&t[i], 0, exec_thread, &a))
				return 3;
		for (;;)
			pause();
	}
	/* ITER children, each with threads; one thread execs while the parent
	 * SIGKILLs the group after a short random delay. */
	if (!strcmp(cmd, "kill-race") && argc > 3) {
		int iter = atoi(argv[2]), killed = 0, ran = 0;
		srand(getpid());
		for (int i = 0; i < iter; i++) {
			pid_t pid = fork();
			if (!pid) {
				pthread_t t;
				struct exec_args a = { argv[3], "noop", 0 };
				pthread_create(&t, 0, idle_thread, 0);
				pthread_create(&t, 0, idle_thread, 0);
				pthread_create(&t, 0, exec_thread, &a);
				for (;;)
					pause();
			}
			if (pid < 0)
				return 5;
			usleep(rand() % 600);
			kill(pid, SIGKILL);
			int st = status_of(pid);
			if (st == 200 + SIGKILL)
				killed++;
			else if (!st)
				ran++;
		}
		out("KILLED=%ld\n", killed);
		out("RAN=%ld\n", ran);
		out("ITER=%ld\n", iter);
		return 0;
	}
	/* ITER children: one thread execs while the leader exits the group. */
	if (!strcmp(cmd, "exit-race") && argc > 3) {
		int iter = atoi(argv[2]), exited = 0, ran = 0;
		srand(getpid() * 7);
		for (int i = 0; i < iter; i++) {
			pid_t pid = fork();
			if (!pid) {
				pthread_t t;
				struct exec_args a = { argv[3], "noop", 0 };
				int spin = rand() % 400000;
				pthread_create(&t, 0, exec_thread, &a);
				for (volatile int k = 0; k < spin; k++)
					;
				syscall(SYS_exit_group, 7);
			}
			if (pid < 0)
				return 5;
			int st = status_of(pid);
			if (st == 7)
				exited++;
			else if (!st)
				ran++;
		}
		out("EXITED=%ld\n", exited);
		out("RAN=%ld\n", ran);
		out("ITER=%ld\n", iter);
		return 0;
	}
	return 2;
}
