// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sched.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "prefix.h"
#include "failure-diagnostic.h"
int px_check_abi(const char *path);
static struct bpf_object *obj;
static struct bpf_link *links[10];
static unsigned nlinks;
static pid_t workers[2];
static int input[2][2], output[2][2], command_fd = -1, state_fd = -1,
				      tasks_fd = -1, cmd_prog = -1;
static struct px_config config;
static const __u32 zero;
static unsigned creator_cpu, admin_cpu;
static int missed, preexec;
static void require(int ok, const char *msg)
{
	printf("%s %s\n", ok ? "PASS" : "FAIL", msg);
	if (!ok)
		exit(1);
}
static struct px_state state(void)
{
	struct px_state s = {};
	require(!bpf_map_lookup_elem_flags(state_fd, &zero, &s, BPF_F_LOCK),
		"state snapshot");
	return s;
}
static int command(__u64 op, __u64 arg)
{
	struct px_command q = { config.nonce, op, arg };
	require(!bpf_map_update_elem(command_fd, &zero, &q, BPF_ANY),
		"authenticated command");
	LIBBPF_OPTS(bpf_test_run_opts, o);
	require(!bpf_prog_test_run_opts(cmd_prog, &o), "command invocation");
	return (int)o.retval;
}
static void cleanup(void)
{
	for (unsigned i = 0; i < nlinks; i++)
		bpf_link__destroy(links[i]);
	/* Object closure releases all owned kptr references; never touch foreign refs. */
	bpf_object__close(obj);
	for (unsigned i = 0; i < 2; i++)
		if (workers[i] > 0) {
			kill(-workers[i], SIGKILL);
			waitpid(workers[i], NULL, 0);
		}
}
static void move(const char *directory, pid_t pid)
{
	char path[4096], text[32];
	require(snprintf(path, sizeof(path), "%s/cgroup.procs", directory) <
			(int)sizeof(path),
		"cgroup path");
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	require(fd >= 0, "open migration FD");
	int n = snprintf(text, sizeof(text), "%d", pid);
	require(write(fd, text, n) == n, "move exact owned task");
	close(fd);
}
static int pin(const char *directory)
{
	char path[4096];
	require(snprintf(path, sizeof(path), "%s/cgroup.procs", directory) <
			(int)sizeof(path),
		"pin path");
	int fd = open(path, O_PATH | O_CLOEXEC);
	require(fd >= 0, "pin exact procs node");
	return fd;
}
static void attach(const char *name)
{
	require(nlinks < 10, "bounded links");
	struct bpf_link *l = bpf_program__attach(
		bpf_object__find_program_by_name(obj, name));
	require(!libbpf_get_error(l), name);
	links[nlinks++] = l;
}
static void barrier(const char *control, __u64 receipt)
{
	struct px_command q = { config.nonce, PX_BARRIER, receipt };
	require(!bpf_map_update_elem(command_fd, &zero, &q, BPF_ANY),
		"fresh barrier request");
	char path[4096];
	require(snprintf(path, sizeof(path), "%s/cgroup.procs", control) <
			(int)sizeof(path),
		"barrier path");
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	require(fd >= 0, "barrier write FD");
	errno = 0;
	ssize_t n = write(fd, "-1", 2);
	int error = errno;
	close(fd);
	require(n == -1 && error == EINVAL && state().barrier == receipt,
		"exact EINVAL plus fresh successful live-return receipt");
}
static __u64 clock_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (__u64)t.tv_sec * 1000000000 + t.tv_nsec;
}
static void blocked_syscall(pid_t pid, long syscall_nr, int argument)
{
	char path[80];
	snprintf(path, sizeof(path), "/proc/%d/syscall", pid);
	__u64 deadline = clock_ns() + 2000000000ULL;
	while (clock_ns() < deadline) {
		FILE *f = fopen(path, "r");
		require(f != NULL, "owned worker syscall witness");
		long nr = -1;
		unsigned long arg = ~0UL;
		int n = fscanf(f, "%ld %lx", &nr, &arg);
		fclose(f);
		if (n == 2 && nr == syscall_nr && arg == (unsigned)argument) {
			printf("WITNESS pid=%d syscall=%ld arg0=%d (actual blocked syscall, not elapsed-time evidence)\n",
			       pid, syscall_nr, argument);
			return;
		}
		usleep(1000);
	}
	require(0, "actual blocked syscall entry witness deadline");
}
static void blocked_read(pid_t pid, int fd)
{
	blocked_syscall(pid, SYS_read, fd);
}
static struct px_row row(pid_t pid, __u64 *key_out)
{
	__u64 key, next;
	int rc = bpf_map_get_next_key(tasks_fd, NULL, &next);
	while (!rc) {
		key = next;
		struct px_row r = {};
		require(!bpf_map_lookup_elem_flags(tasks_fd, &key, &r,
						   BPF_F_LOCK),
			"protected row read");
		if (r.pid == (unsigned)pid) {
			if (key_out)
				*key_out = key;
			return r;
		}
		rc = bpf_map_get_next_key(tasks_fd, &key, &next);
	}
	require(0, "expected protected physical task row");
	return (struct px_row){};
}
/* Every asserted refusal carries a new, exact kernel receipt and preserves
 * the entire stable task ledger, not merely a returned EAGAIN. */
static __u64 refuse(__u64 target_id)
{
	require(!command(PX_INVENTORY, target_id),
		"fresh stable inventory for refusal");
	struct px_row before[PX_LIMIT], after;
	__u64 keys[PX_LIMIT], next, key;
	unsigned n = 0;
	int rc = bpf_map_get_next_key(tasks_fd, NULL, &next);
	while (!rc) {
		require(n < PX_LIMIT, "bounded refusal snapshot");
		key = next;
		keys[n] = key;
		require(!bpf_map_lookup_elem_flags(tasks_fd, &key, &before[n],
						   BPF_F_LOCK),
			"before-refusal task snapshot");
		n++;
		rc = bpf_map_get_next_key(tasks_fd, &key, &next);
	}
	struct px_state a = state();
	require(a.refusals != ~0ULL && !a.strict_ready && !a.writers &&
			a.initial_done && a.inventory_serial == a.serial,
		"fresh refusal preconditions and no overflow");
	require(command(PX_REFUSE, a.inventory_generation) == -EAGAIN,
		"actual qualification refusal");
	struct px_state b = state();
	printf("REFUSAL before=%llu after=%llu serial=%llu inventory=%llu barrier=%llu\n",
	       (unsigned long long)a.refusals, (unsigned long long)b.refusals,
	       (unsigned long long)b.serial,
	       (unsigned long long)b.inventory_generation,
	       (unsigned long long)b.barrier);
	require(b.refusals == a.refusals + 1 && !b.strict_ready &&
			b.strict_ready == a.strict_ready &&
			b.serial == a.serial && !b.writers &&
			b.retained == a.retained && b.inflight == a.inflight &&
			b.allocs == a.allocs && b.births == a.births &&
			b.frees == a.frees && b.failed == a.failed &&
			b.unowned == a.unowned && b.errors == a.errors &&
			px_refusal_valid(
				b.refusals, b.refusals, b.inventory_generation,
				b.refusal_inventory, b.serial, b.refusal_serial,
				b.barrier, b.refusal_barrier, b.writers),
		"exactly one new current refusal; ownership unchanged");
	for (unsigned i = 0; i < n; i++) {
		require(!bpf_map_lookup_elem_flags(tasks_fd, &keys[i], &after,
						   BPF_F_LOCK) &&
				!memcmp(&before[i], &after, sizeof(after)),
			"refusal preserves physical cookie, ownership, prefix and history bytes");
	}
	return b.refusals;
}
static void child(unsigned i)
{
	cpu_set_t cpus;
	CPU_ZERO(&cpus);
	CPU_SET(creator_cpu, &cpus);
	if (sched_setaffinity(0, sizeof(cpus), &cpus))
		_exit(10);
	if (setpgid(0, 0))
		_exit(9);
	close(input[i][1]);
	close(output[i][0]);
	char op;
	if (preexec && i == 0) {
		if (ptrace(PTRACE_TRACEME, 0, NULL, NULL))
			_exit(11);
		raise(SIGSTOP);
		char fdtext[32];
		snprintf(fdtext, sizeof(fdtext), "%d", input[i][0]);
		if (fcntl(input[i][0], F_SETFD, 0))
			_exit(12);
		execl("/proc/self/exe", "prefix-exec-worker", "--exec-worker",
		      fdtext, NULL);
		_exit(13);
	}
	if (read(input[i][0], &op, 1) != 1)
		_exit(2);
	if (op == 'f') {
		pid_t p = fork();
		if (p < 0)
			_exit(3);
		if (!p) {
			pid_t me = getpid();
			if (write(output[i][1], &me, sizeof(me)) != sizeof(me))
				_exit(4);
			if (read(input[i][0], &op, 1) != 1)
				_exit(5);
			_exit(0);
		}
		if (waitpid(p, NULL, 0) != p)
			_exit(6);
	} else {
		pid_t me = getpid();
		if (write(output[i][1], &me, sizeof(me)) != sizeof(me))
			_exit(7);
		if (read(input[i][0], &op, 1) != 1)
			_exit(8);
	}
	_exit(0);
}
int main(int argc, char **argv)
{
	if (argc == 3 && !strcmp(argv[1], "--exec-worker")) {
		char c;
		int fd = atoi(argv[2]);
		return read(fd, &c, 1) == 1 ? 0 : 1;
	}
	setvbuf(stdout, NULL, _IONBF, 0);
	require(argc == 6,
		"usage: runner OBJECT TARGET_CGROUP CONTROL_CGROUP EVIDENCE_DIRECTORY core|missed-entry|preexec");
	missed = !strcmp(argv[5], "missed-entry");
	preexec = !strcmp(argv[5], "preexec");
	require(missed || preexec || !strcmp(argv[5], "core"), "known case");
	cpu_set_t available;
	require(!sched_getaffinity(0, sizeof(available), &available),
		"CPU affinity witness");
	int first = -1, second = -1;
	for (int i = 0; i < CPU_SETSIZE; i++)
		if (CPU_ISSET(i, &available)) {
			if (first < 0)
				first = i;
			else {
				second = i;
				break;
			}
		}
	require(first >= 0 && (!missed || second >= 0),
		"distinct CPUs available for bounded missed-entry case");
	creator_cpu = first;
	admin_cpu = second < 0 ? first : second;
	const char *consent = getenv("IG_ABI3_GATE_A_DISPOSABLE");
	require(geteuid() == 0 && consent && !strcmp(consent, "1"),
		"explicit disposable-host consent");
	require(!px_check_abi("/sys/kernel/btf/vmlinux"),
		"copy_thread and ret_from_fork BTF supported before load");
	atexit(cleanup);
	move(argv[3], getpid());
	for (unsigned i = 0; i < 2; i++) {
		require(!pipe2(input[i], O_CLOEXEC) &&
				!pipe2(output[i], O_CLOEXEC),
			"owned worker pipes");
		workers[i] = fork();
		require(workers[i] >= 0, "pre-attachment worker");
		if (!workers[i])
			child(i);
		close(input[i][0]);
		close(output[i][1]);
		move(argv[2],
		     workers[i]); /* fd number is inherited and unchanged in child */
	}
	/* Parent closed its copies, but the inherited read-end numbers remain exact. */
	if (preexec) {
		int status;
		require(waitpid(workers[0], &status, 0) == workers[0] &&
				WIFSTOPPED(status) &&
				WSTOPSIG(status) == SIGSTOP,
			"owned pre-exec ptrace stop");
		require(!ptrace(PTRACE_SETOPTIONS, workers[0], NULL,
				(void *)(long)(PTRACE_O_TRACEEXEC |
					       PTRACE_O_EXITKILL)),
			"owned trace-exec only");
		require(!ptrace(PTRACE_CONT, workers[0], NULL, NULL),
			"run to actual exec event");
		require(waitpid(workers[0], &status, 0) == workers[0] &&
				WIFSTOPPED(status) &&
				((unsigned)status >> 16) == PTRACE_EVENT_EXEC,
			"actual PTRACE_EVENT_EXEC stop before observer attachment");
	}
	for (unsigned i = preexec ? 1 : 0; i < 2; i++)
		blocked_read(workers[i], input[i][0]);
	cpu_set_t adminset;
	CPU_ZERO(&adminset);
	CPU_SET(admin_cpu, &adminset);
	require(!sched_setaffinity(0, sizeof(adminset), &adminset),
		"pin admin distinct CPU");
	config = (struct px_config){ .admin = ((__u64)getpid() << 32) |
					      (__u32)syscall(SYS_gettid),
				     .target_fd = pin(argv[2]),
				     .control_fd = pin(argv[3]),
				     .creator_cpu = creator_cpu,
				     .admin_cpu = admin_cpu };
	require(getrandom(&config.nonce, sizeof(config.nonce), 0) ==
				sizeof(config.nonce) &&
			config.nonce,
		"fresh nonzero nonce");
	obj = bpf_object__open_file(argv[1], NULL);
	if (libbpf_get_error(obj)) {
		obj = NULL;
		require(0, "open object");
	}
	struct bpf_program *p;
	char *logs[16] = {};
	const char *names[16] = {};
	unsigned n = 0;
	bpf_object__for_each_program(p, obj)
	{
		require(n < 16, "bounded program count");
		logs[n] = calloc(1, 8U << 20);
		require(logs[n] != NULL, "verifier buffer");
		names[n] = bpf_program__name(p);
		require(!bpf_program__set_log_buf(p, logs[n], 8U << 20) &&
				!bpf_program__set_log_level(p, 1),
			"verifier logging");
		n++;
	}
	int loaded = bpf_object__load(obj);
	char logpath[4096];
	require(snprintf(logpath, sizeof(logpath), "%s/verifier.log", argv[4]) <
			(int)sizeof(logpath),
		"log path");
	FILE *log = fopen(logpath, "w");
	require(log != NULL, "verifier evidence");
	for (unsigned i = 0; i < n; i++) {
		fprintf(log, "=== %s ===\n%s\n", names[i], logs[i]);
		free(logs[i]);
	}
	fclose(log);
	require(!loaded, "actual load (not proved by compilation)");
	bpf_object__for_each_program(p, obj)
	{
		struct bpf_prog_info info = {};
		__u32 len = sizeof(info);
		require(!bpf_obj_get_info_by_fd(bpf_program__fd(p), &info,
						&len),
			"owned program id");
		printf("PROGRAM_ID %u %s\n", info.id, bpf_program__name(p));
	}
	command_fd = bpf_object__find_map_fd_by_name(obj, "command");
	state_fd = bpf_object__find_map_fd_by_name(obj, "state");
	tasks_fd = bpf_object__find_map_fd_by_name(obj, "tasks");
	cmd_prog = bpf_program__fd(
		bpf_object__find_program_by_name(obj, "px_command"));
	int cfd = bpf_object__find_map_fd_by_name(obj, "config");
	require(!bpf_map_update_elem(cfd, &zero, &config, BPF_ANY) &&
			!bpf_map_freeze(cfd),
		"frozen config");
	require(!command(PX_PIN, 0),
		"one-shot exact admin/target/control pins");
	require(command(PX_PIN, 0) == -EEXIST, "pin cannot reset state");
	for (unsigned i = 0; i < 2; i++)
		require(!command(PX_HOLD, workers[i]),
			"protected existing worker reference");
	const char *hooks[] = { "px_free",    "px_birth", "px_failed",
				"px_retfork", "px_enter", "px_exit",
				"px_barrier", "px_alloc" };
	for (unsigned i = 0; i < sizeof(hooks) / sizeof(hooks[0]); i++) {
		if (missed && !strcmp(hooks[i], "px_alloc"))
			continue;
		attach(hooks[i]);
	}
	if (missed) {
		attach("px_copy_thread");
		require(!command(PX_DIAG_ARM, workers[0]),
			"one-shot held creator diagnostic nonce");
		require(write(input[0][1], "f", 1) == 1,
			"start fork with genuinely missing task_alloc observer");
		__u64 deadline = clock_ns() + 2000000000ULL;
		struct px_state diagnostic = {};
		do {
			require(!bpf_map_lookup_elem_flags(state_fd, &zero,
							   &diagnostic,
							   BPF_F_LOCK),
				"diagnostic entry poll");
			if (diagnostic.diagnostic_enter)
				break;
		} while (clock_ns() < deadline);
		require(diagnostic.diagnostic_enter &&
				!diagnostic.diagnostic_timeout &&
				!diagnostic.diagnostic_exit,
			"successful copy_thread stopped after missed alloc before can_fork");
		attach("px_alloc");
	}
	require(!state().enabled && !state().allocs && !state().births,
		"all links attached unarmed");
	require(!command(PX_ENABLE, 0),
		"enable only after required links exist");
	barrier(argv[3], 1);
	struct stat st;
	require(!stat(argv[2], &st), "target cgroup ID");
	require(!command(PX_INVENTORY, st.st_ino),
		"single initial all-thread inventory");
	__u64 keys[2];
	struct px_row before[2];
	for (unsigned i = 0; i < 2; i++) {
		before[i] = row(workers[i], &keys[i]);
		require(before[i].origin == PX_INITIAL &&
				!before[i].boundary_seen &&
				!before[i].prefix_qualified &&
				!before[i].history_complete,
			"initial task UNQUALIFIED and UNKNOWN");
	}
	struct px_state s = state();
	int initial_counts_ok = s.inventory == 2 && s.prefix_missing == 2 &&
				s.history_unknown == 2 && !s.inflight &&
				!s.allocs && !s.births && !s.errors;
	if (!initial_counts_ok)
		px_dump_initial_failure(stderr, &s);
	require(initial_counts_ok,
		"zero owned counts do not qualify prefix or history");
	__u64 refusal = refuse(st.st_ino);
	if (missed) {
		require(!command(PX_DIAG_RELEASE, refusal),
			"release only after missing-link attach/enable/fresh barrier/complete inventory/actual refusal");
		pid_t born;
		require(read(output[0][0], &born, sizeof(born)) ==
					sizeof(born) &&
				born > 0,
			"previously unowned fork allowed to complete");
		blocked_read(born, input[0][0]);
		blocked_syscall(workers[0], SYS_wait4, born);
		struct px_row birth = row(born, NULL);
		struct px_state d = state();
		require(d.diagnostic_enter && d.diagnostic_release &&
				d.diagnostic_exit && !d.diagnostic_timeout &&
				d.diagnostic_cpu == creator_cpu &&
				d.admin_cpu == admin_cpu &&
				d.admin_cpu != d.diagnostic_cpu,
			"bounded one-shot distinct-CPU overlap witness");
		require(!d.allocs && !d.births && !d.inflight &&
				d.unowned == 1 && !d.errors,
			"unowned birth never decrements invented ownership");
		require(birth.origin == PX_LATE && birth.birth_uncertain &&
				birth.boundary_seen &&
				!birth.prefix_qualified &&
				!birth.history_complete,
			"actual unowned child remains UNKNOWN and ineligible after own sys_exit");
		require(!command(PX_INVENTORY, st.st_ino),
			"fresh post-birth all-thread inventory");
		struct px_row again = row(born, NULL);
		require(!memcmp(&birth, &again, sizeof(birth)),
			"reinventory cannot repair unowned birth or fabricate history");
		refuse(st.st_ino);
		require(write(input[0][1], "x", 1) == 1,
			"release unowned child");
		require(write(input[1][1], "q", 1) == 1,
			"release withheld worker");
		pid_t ack;
		require(read(output[1][0], &ack, sizeof(ack)) == sizeof(ack) &&
				ack == workers[1],
			"withheld worker acknowledgment");
		require(write(input[1][1], "x", 1) == 1,
			"finish withheld worker");
		goto finish;
	}
	if (preexec) {
		require(!ptrace(PTRACE_DETACH, workers[0], NULL, NULL),
			"resume owned successful prehook exec");
		blocked_read(workers[0], input[0][0]);
		struct px_row afterexec = row(workers[0], NULL);
		require(afterexec.cookie == before[0].cookie &&
				afterexec.boundary_seen &&
				afterexec.prefix_qualified &&
				!afterexec.history_complete &&
				!memcmp(afterexec.history, before[0].history,
					sizeof(afterexec.history)),
			"resumed exec boundary cannot reconstruct missing prehook history");
		refuse(st.st_ino);
		require(write(input[0][1], "x", 1) == 1, "finish exec worker");
		require(write(input[1][1], "q", 1) == 1,
			"release withheld worker");
		pid_t ack;
		require(read(output[1][0], &ack, sizeof(ack)) == sizeof(ack) &&
				ack == workers[1],
			"withheld acknowledgment");
		require(write(input[1][1], "x", 1) == 1,
			"finish withheld worker");
		goto finish;
	}
	require(write(input[0][1], "q", 1) == 1, "release one prehook read");
	pid_t ack;
	require(read(output[0][0], &ack, sizeof(ack)) == sizeof(ack) &&
			ack == workers[0],
		"released worker progressed");
	blocked_read(workers[0], input[0][0]);
	__u64 key;
	struct px_row after = row(workers[0], &key),
		      withheld = row(workers[1], NULL);
	require(key == keys[0] && after.cookie == before[0].cookie &&
			after.boundary_seen && after.prefix_qualified &&
			!after.history_complete &&
			!memcmp(after.history, before[0].history,
				sizeof(after.history)),
		"actual same-cookie sys_exit qualifies only prefix and preserves UNKNOWN history bytes");
	require(withheld.cookie == before[1].cookie &&
			!withheld.boundary_seen && !withheld.prefix_qualified &&
			!memcmp(&withheld, &before[1], sizeof(withheld)),
		"withheld task unchanged and unqualified");
	require(write(input[1][1], "f", 1) == 1, "real subsequent owned fork");
	pid_t born;
	require(read(output[1][0], &born, sizeof(born)) == sizeof(born) &&
			born > 0,
		"child reached userspace only after fork return witness");
	blocked_read(born, input[1][0]);
	blocked_syscall(workers[1], SYS_wait4, born);
	struct px_row birth = row(born, NULL);
	s = state();
	require(birth.cookie != before[1].cookie &&
			birth.cookie != after.cookie &&
			birth.origin == PX_OWNED_BIRTH && birth.alloc_seen &&
			birth.new_seen && birth.retfork_seen &&
			birth.boundary_seen && birth.prefix_qualified &&
			!birth.birth_uncertain && !birth.history_complete &&
			birth.first_exit_entries == 0 &&
			birth.retfork_entries == 0,
		"reserve then exact owned birth then child ret_from_fork fn NULL then own first sys_exit (no later syscall substitution)");
	require(s.allocs == 1 && s.births == 1 && !s.inflight && !s.errors,
		"exact owned acquisition/completion accounting");
	refuse(st.st_ino);
	require(!state().strict_ready,
		"UNKNOWN history still blocks strict even after prefix qualification");
	require(write(input[1][1], "x", 1) == 1 &&
			write(input[0][1], "x", 1) == 1,
		"release owned descendants");
finish:
	for (unsigned i = 0; i < 2; i++) {
		int status;
		require(waitpid(workers[i], &status, 0) == workers[i] &&
				WIFEXITED(status) && !WEXITSTATUS(status),
			"owned worker clean exit");
		workers[i] = 0;
	}
	require(!command(PX_RELEASE_REFS, 0),
		"release exact held refs after row readers done");
	__u64 deadline = clock_ns() + 5000000000ULL;
	do {
		s = state();
		if (!s.retained)
			break;
		usleep(10000);
	} while (clock_ns() < deadline);
	require(!s.retained && !s.inflight && s.frees == (preexec ? 2U : 3U) &&
			!s.errors,
		"task_free-only deletion/refund completed");
	puts("UNKNOWN/NOTRUN kernel_exec failure: no approved trigger; strict remains NotReady");
	printf("PREFIX CASE %s: no G018 closure, no complete history or production authority\n",
	       argv[5]);
	return 0;
}
