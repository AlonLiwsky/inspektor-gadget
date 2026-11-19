// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <linux/magic.h>
#include <limits.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/random.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include <time.h>
#include "ingress.h"
static struct bpf_object *object;
static struct bpf_link *guard, *arm_link;
static struct bpf_link *ingress_links[6];
static int state_fd = -1, command_fd, command_prog, tokens_fd;
static int target_pin = -1, control_pin = -1, bad_pin = -1;
static struct in_config config;
static const __u32 zero;
static void die(const char *msg)
{
	perror(msg);
	exit(1);
}
static struct in_state state(void)
{
	struct in_state s = {};
	if (state_fd >= 0 &&
	    bpf_map_lookup_elem_flags(state_fd, &zero, &s, BPF_F_LOCK))
		die("state");
	return s;
}
static void require(int ok, const char *msg)
{
	struct in_state s = state();
	printf("%s %s pinned=%u mode=%llu attempt=%llu pending=%llu hits=%llu deny=%llu audit=%llu errors=%llu arms=%llu wrong_control=%llu kn=%llx sb=%llx target_kn=%llx target_sb=%llx tid=%llu mask=%llu\n",
	       ok ? "PASS" : "FAIL", msg, s.pinned, (unsigned long long)s.mode,
	       (unsigned long long)s.active_attempt,
	       (unsigned long long)s.pending_attempt,
	       (unsigned long long)s.permission_hits,
	       (unsigned long long)s.denials, (unsigned long long)s.audit_hits,
	       (unsigned long long)s.inspection_errors,
	       (unsigned long long)s.arms, (unsigned long long)s.wrong_control,
	       (unsigned long long)s.last_kn, (unsigned long long)s.last_sb,
	       (unsigned long long)s.target_kn, (unsigned long long)s.target_sb,
	       (unsigned long long)s.last_tid, (unsigned long long)s.last_mask);
	printf("REACH calls=%llu prior=%llu zero=%llu cgroup=%llu write=%llu node_match=%llu observed_magic=%llx sb=%llx kn=%llx mask=%llu tid=%llu\n",
	       (unsigned long long)s.hook_calls,
	       (unsigned long long)s.prior_returns,
	       (unsigned long long)s.zero_inputs,
	       (unsigned long long)s.cgroup_inodes,
	       (unsigned long long)s.write_requests,
	       (unsigned long long)s.node_matches,
	       (unsigned long long)s.observed_magic,
	       (unsigned long long)s.observed_sb,
	       (unsigned long long)s.observed_kn,
	       (unsigned long long)s.observed_mask,
	       (unsigned long long)s.observed_tid);
	printf("INGRESS serial=%llu receipt=%llu next_token=%llu inflight=%llu uncertain=%llu admitted=%llu completed=%llu cancelled=%llu unowned=%llu failures=%llu arm_refused=%llu arm_reason=%llu fact_cookie=%llu fact_child=%llx fact_kind=%llu\n",
	       (unsigned long long)s.serial,
	       (unsigned long long)s.pending_serial,
	       (unsigned long long)s.next_token,
	       (unsigned long long)s.ingress_inflight,
	       (unsigned long long)s.uncertain,
	       (unsigned long long)s.ingress_admitted,
	       (unsigned long long)s.ingress_completed,
	       (unsigned long long)s.ingress_cancelled,
	       (unsigned long long)s.unowned_completions,
	       (unsigned long long)s.token_failures,
	       (unsigned long long)s.arm_refusals,
	       (unsigned long long)s.last_arm_reason,
	       (unsigned long long)s.last_fact_cookie,
	       (unsigned long long)s.last_fact_child,
	       (unsigned long long)s.last_fact_kind);
	printf("CANCEL_TEST task=%llx nonce=%llx armed=%llu requests=%llu errors=%llu\n",
	       (unsigned long long)s.test_task,
	       (unsigned long long)s.test_nonce,
	       (unsigned long long)s.test_armed,
	       (unsigned long long)s.signal_requests,
	       (unsigned long long)s.signal_errors);
	if (!ok)
		exit(1);
}
static void cleanup(void)
{
	for (unsigned i = 0; i < 6; i++)
		bpf_link__destroy(ingress_links[i]);
	bpf_link__destroy(guard);
	bpf_link__destroy(arm_link);
	bpf_object__close(object);
	if (target_pin >= 0)
		close(target_pin);
	if (control_pin >= 0)
		close(control_pin);
	if (bad_pin >= 0)
		close(bad_pin);
}
static int invoke(__u32 op, __u64 attempt, __u32 mode, int wrong_nonce)
{
	struct in_command q = { .nonce = config.nonce ^ (wrong_nonce ? 1 : 0),
				.attempt = attempt,
				.operation = op,
				.mode = mode };
	if (bpf_map_update_elem(command_fd, &zero, &q, BPF_ANY))
		die("command update");
	LIBBPF_OPTS(bpf_test_run_opts, opt);
	if (bpf_prog_test_run_opts(command_prog, &opt))
		die("test run");
	return (int)opt.retval;
}
static int negative_pid_write(int fd)
{
	errno = 0;
	ssize_t result = write(fd, "-1\n", 3);
	return result < 0 ? -errno : 0;
}
static void set_mode(int control_write, __u64 attempt, __u32 mode)
{
	require(invoke(IN_STAGE, attempt, mode, 0) == 0,
		"stage authenticated class change");
	require(negative_pid_write(control_write) == -EINVAL,
		"administrative negative-PID write fails without moving task");
	struct in_state s = state();
	require(s.active_attempt == attempt && s.mode == mode &&
			!s.pending_attempt,
		"matching mutex-held ARM receipt commits class");
}
static void read_cgroup(char *buf, size_t size)
{
	int fd = open("/proc/self/cgroup", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		die("self cgroup");
	ssize_t n = read(fd, buf, size - 1);
	if (n < 0)
		die("read cgroup");
	buf[n] = 0;
	close(fd);
}
static int clone_into(int fd, const char *expected)
{
	int p[2];
	if (pipe2(p, O_CLOEXEC))
		die("pipe");
	struct clone_args args = { .flags = CLONE_INTO_CGROUP,
				   .exit_signal = SIGCHLD,
				   .cgroup = fd };
	pid_t pid = fd < 0 ? fork() : syscall(SYS_clone3, &args, sizeof(args));
	int error = errno;
	if (!pid) {
		close(p[0]);
		char buf[4096];
		read_cgroup(buf, sizeof(buf));
		size_t n = strlen(buf);
		if (write(p[1], buf, n) != (ssize_t)n)
			_exit(98);
		_exit(0);
	}
	close(p[1]);
	if (pid < 0) {
		close(p[0]);
		printf("CLONE_RESULT target_fd=%d result=%d\n", fd, -error);
		return -error;
	}
	char buf[4096];
	ssize_t n = read(p[0], buf, sizeof(buf) - 1);
	close(p[0]);
	int status;
	if (waitpid(pid, &status, 0) != pid)
		die("wait clone");
	if (n < 0 || !WIFEXITED(status) || WEXITSTATUS(status))
		return -EIO;
	buf[n] = 0;
	if (strcmp(buf, expected)) {
		fprintf(stderr, "placement expected=%s actual=%s", expected,
			buf);
		return -EXDEV;
	}
	printf("CLONE_RESULT target_fd=%d result=0 placement=%s", fd, buf);
	return 0;
}
static struct bpf_link *attach(const char *name)
{
	struct bpf_program *p = bpf_object__find_program_by_name(object, name);
	if (!p)
		die(name);
	struct bpf_link *l = bpf_program__attach(p);
	if (libbpf_get_error(l))
		die(name);
	return l;
}
static void load(const char *path, const char *out)
{
	object = bpf_object__open_file(path, NULL);
	if (libbpf_get_error(object)) {
		object = NULL;
		die("open");
	}
	atexit(cleanup);
	char *logs[9] = {};
	const char *names[9] = {};
	unsigned n = 0;
	struct bpf_program *p;
	bpf_object__for_each_program(p, object)
	{
		if (n == 9)
			die("program count");
		logs[n] = calloc(1, 8U << 20);
		if (!logs[n])
			die("log");
		names[n] = bpf_program__name(p);
		if (bpf_program__set_log_buf(p, logs[n], 8U << 20) ||
		    bpf_program__set_log_level(p, 1))
			die("log config");
		n++;
	}
	int result = bpf_object__load(object);
	char logpath[4096];
	if (snprintf(logpath, sizeof(logpath), "%s/verifier.log", out) >=
	    (int)sizeof(logpath))
		die("log path");
	FILE *f = fopen(logpath, "w");
	if (!f)
		die("log open");
	for (unsigned i = 0; i < n; i++) {
		fprintf(f, "=== %s ===\n", names[i]);
		fputs(logs[i], f);
		free(logs[i]);
	}
	fclose(f);
	if (result)
		die("load");
	bpf_object__for_each_program(p, object)
	{
		struct bpf_prog_info info = {};
		__u32 len = sizeof(info);
		if (bpf_obj_get_info_by_fd(bpf_program__fd(p), &info, &len))
			die("prog info");
		printf("PROGRAM_ID %u %s\n", info.id, bpf_program__name(p));
	}
	state_fd = bpf_object__find_map_fd_by_name(object, "state");
	tokens_fd = bpf_object__find_map_fd_by_name(object, "tokens");
	command_fd = bpf_object__find_map_fd_by_name(object, "command");
	command_prog = bpf_program__fd(
		bpf_object__find_program_by_name(object, "in_command"));
	int cfg = bpf_object__find_map_fd_by_name(object, "config");
	if (bpf_map_update_elem(cfg, &zero, &config, BPF_ANY) ||
	    bpf_map_freeze(cfg))
		die("freeze config");
}
static void test_owned_cancellation(int target_fd)
{
	int gate[2];
	if (pipe2(gate, O_CLOEXEC))
		die("cancel gate");
	pid_t worker = fork();
	if (worker < 0)
		die("cancel worker");
	if (!worker) {
		close(gate[1]);
		char go;
		if (read(gate[0], &go, 1) != 1)
			_exit(80);
		close(gate[0]);
		struct clone_args args = { .flags = CLONE_INTO_CGROUP,
					   .exit_signal = SIGCHLD,
					   .cgroup = target_fd };
		pid_t child = syscall(SYS_clone3, &args, sizeof(args));
		if (!child)
			_exit(81);
		if (child > 0) {
			int status;
			(void)waitpid(child, &status, 0);
		}
		_exit(82); // A real post-can_fork cancellation must kill this exact worker.
	}
	close(gate[0]);
	__u64 nonce = 0;
	if (getrandom(&nonce, sizeof(nonce), 0) != (ssize_t)sizeof(nonce) ||
	    !nonce)
		die("cancel nonce");
	struct in_state before = state();
	require(invoke(IN_CANCEL_ARM, nonce, (__u32)getpid(), 0) == -EINVAL,
		"cancellation injection rejects the admin instead of a direct child");
	require(invoke(IN_CANCEL_ARM, nonce, (__u32)worker, 0) == 0 &&
			state().test_task && state().test_nonce == nonce,
		"cancellation injection pins exact disposable child and nonce");
	if (write(gate[1], "x", 1) != 1)
		die("cancel go");
	close(gate[1]);
	int status;
	if (waitpid(worker, &status, 0) != worker)
		die("cancel wait");
	require(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
		"exact cancellation worker exits by SIGKILL");
	struct in_state after = state();
	require(after.signal_requests == before.signal_requests + 1 &&
			after.signal_errors == before.signal_errors &&
			after.ingress_admitted == before.ingress_admitted + 1 &&
			after.ingress_cancelled ==
				before.ingress_cancelled + 1 &&
			after.ingress_completed == before.ingress_completed &&
			after.ingress_inflight == before.ingress_inflight &&
			!after.uncertain && after.last_fact_kind == 2,
		"real owned cancel publishes cancellation then releases exactly one ingress token");
	require(invoke(IN_CANCEL_RELEASE, nonce, 0, 0) == 0 &&
			!state().test_task && !state().test_nonce,
		"release cancellation target reference and nonce");
	__u64 key = 0;
	errno = 0;
	require(bpf_map_get_next_key(tokens_fd, NULL, &key) < 0 &&
			errno == ENOENT,
		"cancelled ingress token storage reclaimed");
}
static __u64 monotonic_ns(void)
{
	struct timespec t;
	if (clock_gettime(CLOCK_MONOTONIC, &t))
		die("clock");
	return (__u64)t.tv_sec * 1000000000 + t.tv_nsec;
}
static void pin_cpu(unsigned cpu)
{
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set))
		die("pin CPU");
}
static void test_overlap(int target_fd, int control_write, const char *target)
{
	int gate[2];
	if (pipe2(gate, O_CLOEXEC))
		die("overlap gate");
	pid_t worker = fork();
	if (worker < 0)
		die("overlap worker");
	if (!worker) {
		close(gate[1]);
		pin_cpu(config.creator_cpu);
		char go;
		if (read(gate[0], &go, 1) != 1)
			_exit(90);
		close(gate[0]);
		_exit(clone_into(target_fd, target) ? 91 : 0);
	}
	close(gate[0]);
	__u64 nonce = 0;
	if (getrandom(&nonce, sizeof(nonce), 0) != (ssize_t)sizeof(nonce) ||
	    !nonce)
		die("overlap nonce");
	require(invoke(IN_OVERLAP_ARM, nonce, worker, 0) == 0,
		"pin exact owned overlap creator and nonce");
	require(invoke(IN_STAGE, 6, IN_STRICT, 0) == 0,
		"stage strict before real overlap admission");
	struct in_state before = state();
	if (write(gate[1], "x", 1) != 1)
		die("overlap go");
	close(gate[1]);
	__u64 deadline = monotonic_ns() + 1000000000ULL;
	struct in_state ready = {};
	for (unsigned i = 0; i < 1000000; i++) {
		ready = state();
		if (ready.overlap_ready || ready.overlap_failed ||
		    monotonic_ns() >= deadline)
			break;
	}
	if (!ready.overlap_ready || ready.overlap_failed)
		require(0,
			"real successful can_fork bounded rendezvous failed");
	require(negative_pid_write(control_write) == -EINVAL,
		"overlap administrative negative-PID write fails");
	int status;
	if (waitpid(worker, &status, 0) != worker)
		die("overlap wait");
	struct in_state after = state();
	printf("OVERLAP nonce=%llx creator_cpu=%llu admin_cpu=%llu entry=%llu release=%llu exit=%llu failed=%llu child=%llx cookie=%llu inflight_at_arm=%llu serial=%llu receipt=%llu reason=%llu\n",
	       (unsigned long long)after.overlap_nonce,
	       (unsigned long long)after.overlap_creator_cpu,
	       (unsigned long long)after.overlap_admin_cpu,
	       (unsigned long long)after.overlap_entry,
	       (unsigned long long)after.overlap_release,
	       (unsigned long long)after.overlap_exit,
	       (unsigned long long)after.overlap_failed,
	       (unsigned long long)after.overlap_child,
	       (unsigned long long)after.overlap_cookie,
	       (unsigned long long)after.overlap_inflight,
	       (unsigned long long)after.overlap_serial,
	       (unsigned long long)after.overlap_receipt,
	       (unsigned long long)after.overlap_reason);
	require(after.overlap_inflight == 1 &&
			(after.overlap_reason & IN_ARM_BUSY) &&
			after.overlap_serial != after.overlap_receipt &&
			after.overlap_cookie == after.last_fact_cookie &&
			after.overlap_child == after.last_fact_child &&
			after.audit_hits == before.audit_hits + 1 &&
			after.overlap_creator_cpu == config.creator_cpu &&
			after.overlap_admin_cpu == config.admin_cpu,
		"nonce-bound real token, audit hit, distinct CPU and BUSY witnesses");
	require(WIFEXITED(status) && !WEXITSTATUS(status),
		"audit-era overlap clone succeeds with actual target placement");
	require(after.overlap_entry && after.overlap_release &&
			after.overlap_exit && !after.overlap_failed,
		"exact ARM entry precedes mutex release and ARM exit precedes factual completion");
	require(after.arms == before.arms && after.active_attempt == 5 &&
			after.mode == IN_AUDIT && after.pending_attempt == 6 &&
			after.arm_refusals == before.arm_refusals + 1 &&
			(after.last_arm_reason & IN_ARM_BUSY) &&
			(after.last_arm_reason & IN_ARM_STALE),
		"real inflight overlap refuses ARM BUSY and STALE without committing strict");
	require(after.ingress_admitted == before.ingress_admitted + 1 &&
			after.ingress_completed ==
				before.ingress_completed + 1 &&
			!after.ingress_inflight && !after.uncertain &&
			after.last_fact_kind == 1,
		"post-fork fact publication releases exact real token");
	require(invoke(IN_CANCEL_RELEASE, nonce, 0, 0) == 0,
		"release overlap creator reference");
	require(invoke(IN_OVERLAP_ARM, nonce, worker, 0) == -EBUSY,
		"one-shot overlap cannot replay or rearm");
	// Restore the authenticated pending ARM command after the negative replay control.
	struct in_command pending = { .nonce = config.nonce,
				      .attempt = 6,
				      .operation = IN_STAGE,
				      .mode = IN_STRICT };
	if (bpf_map_update_elem(command_fd, &zero, &pending, BPF_ANY))
		die("restore pending command");
	struct in_state stale_before = state();
	int stale_write = negative_pid_write(control_write);
	struct in_state stale_after = state();
	require(stale_write == -EINVAL &&
			stale_after.arm_refusals ==
				stale_before.arm_refusals + 1 &&
			(stale_after.last_arm_reason & IN_ARM_STALE) &&
			!(stale_after.last_arm_reason & IN_ARM_BUSY) &&
			!stale_before.ingress_inflight &&
			!stale_after.ingress_inflight &&
			stale_after.arms == stale_before.arms &&
			stale_before.active_attempt == 5 &&
			stale_after.active_attempt ==
				stale_before.active_attempt &&
			stale_before.mode == IN_AUDIT &&
			stale_after.mode == stale_before.mode &&
			stale_before.pending_attempt == 6 &&
			stale_after.pending_attempt == 6,
		"fresh ARM refusal proves old overlap receipt stays stale after real completion");
	require(invoke(IN_ABORT, 6, 0, 0) == 0,
		"abort only stale overlap candidate");
	set_mode(control_write, 7, IN_STRICT);
	require(clone_into(target_fd, target) == -EPERM,
		"fresh overlap receipt establishes prospective strict denial");
	set_mode(control_write, 8, IN_AUDIT);
}
static int path_open(const char *base, const char *name, int flags)
{
	char path[4096];
	if (snprintf(path, sizeof(path), "%s/%s", base, name) >=
	    (int)sizeof(path))
		die("path");
	int fd = open(path, flags | O_CLOEXEC);
	if (fd < 0)
		die(path);
	return fd;
}
struct mount_proof {
	struct stat before_mount_ns, after_mount_ns, before_cgroup_ns,
		after_cgroup_ns;
	struct statx original, target;
	struct statvfs flags;
	struct statfs filesystem;
};
enum mount_proof_error {
	MOUNT_OK,
	MOUNT_ID_MISSING,
	MOUNT_ID_SAME,
	MOUNT_NS_SAME,
	CGROUP_NS_SAME,
	MOUNT_WRITABLE,
	MOUNT_NOT_CGROUP2
};
static enum mount_proof_error check_mount_proof(const struct mount_proof *p)
{
	if (!(p->original.stx_mask & STATX_MNT_ID) ||
	    !(p->target.stx_mask & STATX_MNT_ID))
		return MOUNT_ID_MISSING;
	if (p->original.stx_mnt_id == p->target.stx_mnt_id)
		return MOUNT_ID_SAME;
	if (p->before_mount_ns.st_dev == p->after_mount_ns.st_dev &&
	    p->before_mount_ns.st_ino == p->after_mount_ns.st_ino)
		return MOUNT_NS_SAME;
	if (p->before_cgroup_ns.st_dev == p->after_cgroup_ns.st_dev &&
	    p->before_cgroup_ns.st_ino == p->after_cgroup_ns.st_ino)
		return CGROUP_NS_SAME;
	if (!(p->flags.f_flag & ST_RDONLY))
		return MOUNT_WRITABLE;
	if (p->filesystem.f_type != CGROUP2_SUPER_MAGIC)
		return MOUNT_NOT_CGROUP2;
	return MOUNT_OK;
}
static int mount_identity_tests(void)
{
	struct mount_proof valid = {
		.before_mount_ns = { .st_dev = 1, .st_ino = 10 },
		.after_mount_ns = { .st_dev = 1, .st_ino = 11 },
		.before_cgroup_ns = { .st_dev = 1, .st_ino = 20 },
		.after_cgroup_ns = { .st_dev = 1, .st_ino = 21 },
		.original = { .stx_mask = STATX_MNT_ID, .stx_mnt_id = 100 },
		.target = { .stx_mask = STATX_MNT_ID, .stx_mnt_id = 101 },
		.flags = { .f_flag = ST_RDONLY },
		.filesystem = { .f_type = CGROUP2_SUPER_MAGIC }
	};
	if (check_mount_proof(&valid) != MOUNT_OK)
		return 1;
	struct mount_proof bad = valid;
	bad.original.stx_mask = 0;
	if (check_mount_proof(&bad) != MOUNT_ID_MISSING)
		return 1;
	bad = valid;
	bad.target.stx_mask = 0;
	if (check_mount_proof(&bad) != MOUNT_ID_MISSING)
		return 1;
	bad = valid;
	bad.target.stx_mnt_id = bad.original.stx_mnt_id;
	if (check_mount_proof(&bad) != MOUNT_ID_SAME)
		return 1;
	bad = valid;
	bad.after_mount_ns = bad.before_mount_ns;
	if (check_mount_proof(&bad) != MOUNT_NS_SAME)
		return 1;
	bad = valid;
	bad.after_cgroup_ns = bad.before_cgroup_ns;
	if (check_mount_proof(&bad) != CGROUP_NS_SAME)
		return 1;
	bad = valid;
	bad.flags.f_flag = 0;
	if (check_mount_proof(&bad) != MOUNT_WRITABLE)
		return 1;
	bad = valid;
	bad.filesystem.f_type = TMPFS_MAGIC;
	if (check_mount_proof(&bad) != MOUNT_NOT_CGROUP2)
		return 1;
	int fd = open(".", O_PATH | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0)
		die("identity self-test open");
	bad = valid;
	if (statx(fd, "", AT_EMPTY_PATH, STATX_MNT_ID, &bad.original) ||
	    statx(fd, "", AT_EMPTY_PATH, STATX_MNT_ID, &bad.target))
		die("identity self-test statx");
	close(fd);
	if (check_mount_proof(&bad) != MOUNT_ID_SAME)
		return 1;
	puts("PASS: mount identity positive case, seven negative controls, and actual same-FD statx rejection");
	return 0;
}
static void cross_mount(const char *out, int original_fd, int expected)
{
	struct in_state before = state();
	pid_t p = fork();
	if (p < 0)
		die("namespace fork");
	if (!p) {
		struct mount_proof proof = {};
		if (stat("/proc/self/ns/mnt", &proof.before_mount_ns) ||
		    stat("/proc/self/ns/cgroup", &proof.before_cgroup_ns) ||
		    statx(original_fd, "", AT_EMPTY_PATH, STATX_MNT_ID,
			  &proof.original))
			_exit(37);
		if (unshare(CLONE_NEWNS | CLONE_NEWCGROUP) ||
		    mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL))
			_exit(30);
		if (stat("/proc/self/ns/mnt", &proof.after_mount_ns) ||
		    stat("/proc/self/ns/cgroup", &proof.after_cgroup_ns))
			_exit(38);
		char point[4096];
		if (snprintf(point, sizeof(point), "%s/namespace-mount", out) >=
		    (int)sizeof(point))
			_exit(31);
		if (mkdir(point, 0700) && errno != EEXIST)
			_exit(32);
		if (mount("none", point, "cgroup2", MS_RDONLY, NULL))
			_exit(33);
		int fd = path_open(point, "target", O_PATH | O_DIRECTORY);
		if (statx(fd, "", AT_EMPTY_PATH, STATX_MNT_ID, &proof.target) ||
		    fstatvfs(fd, &proof.flags) ||
		    fstatfs(fd, &proof.filesystem))
			_exit(34);
		enum mount_proof_error identity = check_mount_proof(&proof);
		printf("MOUNT_IDENTITY result=%d original_mount=%llu target_mount=%llu mntns_before=%llu:%llu mntns_after=%llu:%llu cgroupns_before=%llu:%llu cgroupns_after=%llu:%llu readonly=%d magic=%lx\n",
		       identity, (unsigned long long)proof.original.stx_mnt_id,
		       (unsigned long long)proof.target.stx_mnt_id,
		       (unsigned long long)proof.before_mount_ns.st_dev,
		       (unsigned long long)proof.before_mount_ns.st_ino,
		       (unsigned long long)proof.after_mount_ns.st_dev,
		       (unsigned long long)proof.after_mount_ns.st_ino,
		       (unsigned long long)proof.before_cgroup_ns.st_dev,
		       (unsigned long long)proof.before_cgroup_ns.st_ino,
		       (unsigned long long)proof.after_cgroup_ns.st_dev,
		       (unsigned long long)proof.after_cgroup_ns.st_ino,
		       !!(proof.flags.f_flag & ST_RDONLY),
		       (unsigned long)proof.filesystem.f_type);
		if (identity != MOUNT_OK)
			_exit(39);
		int result = clone_into(fd, "0::/target\n");
		close(fd);
		int unrelated = path_open(point, "other", O_PATH | O_DIRECTORY);
		int other_result = clone_into(unrelated, "0::/other\n");
		close(unrelated);
		if (other_result)
			_exit(40);
		if (umount(point) || rmdir(point))
			_exit(35);
		_exit(result == expected ? 0 : 36);
	}
	int status;
	if (waitpid(p, &status, 0) != p)
		die("namespace wait");
	printf("MOUNT_CHILD_STATUS %d\n", status);
	require(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		"distinct mount/namespaces, read-only cgroup2 FD and expected clone result");
	struct in_state s = state();
	require(s.last_kn == s.target_kn && (__u32)s.last_tid == (__u32)p &&
			(s.last_mask & 2) &&
			s.permission_hits == before.permission_hits + 1,
		"new mount clone freshly matches exact pinned target in its creator");
	require(expected == 0 ? (s.audit_hits == before.audit_hits + 1 &&
				 s.denials == before.denials) :
				(s.denials == before.denials + 1 &&
				 s.audit_hits == before.audit_hits),
		"new mount clone has the expected fresh audit/strict outcome");
	// Same-root cgroup2 mounts share the pinned kernel's superblock. Its pointer
	// remains diagnostic only: neither equality nor inequality is an acceptance.
	printf("SUPERBLOCK_DIAGNOSTIC original=%llx observed=%llx\n",
	       (unsigned long long)s.target_sb, (unsigned long long)s.last_sb);
}
int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "--self-test-identities"))
		return mount_identity_tests();
	if (argc != 4 || geteuid() || !getenv("IG_ABI3_GATE_A_DISPOSABLE") ||
	    strcmp(getenv("IG_ABI3_GATE_A_DISPOSABLE"), "1")) {
		fprintf(stderr,
			"requires disposable root; OBJECT NEW_LOG_DIRECTORY OWNED_CGROUP_ROOT\n");
		return 2;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	const char *base = argv[3];
	char current[4096], target[4096], other[4096];
	read_cgroup(current, sizeof(current));
	char *nl = strchr(current, '\n');
	if (!nl)
		die("cgroup line");
	*nl = 0;
	if (snprintf(target, sizeof(target), "%s/target\n", current) >=
		    (int)sizeof(target) ||
	    snprintf(other, sizeof(other), "%s/other\n", current) >=
		    (int)sizeof(other))
		die("group names");
	*nl = '\n';
	int target_dir = path_open(base, "target", O_PATH | O_DIRECTORY),
	    other_dir = path_open(base, "other", O_PATH | O_DIRECTORY);
	target_pin = path_open(base, "target/cgroup.procs", O_PATH);
	control_pin = path_open(base, "cgroup.procs", O_PATH);
	bad_pin = open("/dev/null", O_PATH | O_CLOEXEC);
	if (bad_pin < 0)
		die("bad pin");
	int control_write = path_open(base, "cgroup.procs", O_WRONLY),
	    other_write = path_open(base, "other/cgroup.procs", O_WRONLY);
	require(clone_into(target_dir, target) == 0,
		"outside CLONE_INTO_CGROUP positive baseline before hooks");
	if (getrandom(&config.nonce, sizeof(config.nonce), 0) !=
		    (ssize_t)sizeof(config.nonce) ||
	    !config.nonce)
		die("nonce");
	config.tid = syscall(SYS_gettid);
	config.target_fd = target_pin;
	config.control_fd = control_pin;
	config.bad_fd = bad_pin;
	cpu_set_t allowed;
	if (sched_getaffinity(0, sizeof(allowed), &allowed))
		die("CPU affinity");
	unsigned found = 0;
	for (unsigned cpu = 0; cpu < CPU_SETSIZE; cpu++)
		if (CPU_ISSET(cpu, &allowed)) {
			if (!found)
				config.admin_cpu = cpu;
			else {
				config.creator_cpu = cpu;
				found++;
				break;
			}
			found++;
		}
	require(found == 2,
		"two distinct allowed CPUs required for bounded overlap");
	pin_cpu(config.admin_cpu);
	load(argv[1], argv[2]);
	for (int prior = -4095; prior <= 0; prior++) {
		int result = invoke(IN_RETURN_TEST, 0, (__u32)prior, 0);
		if (result != prior) {
			fprintf(stderr, "BPF valid return prior=%d actual=%d\n",
				prior, result);
			require(0, "actual BPF valid errno preservation");
		}
	}
	const int invalid[] = { INT_MIN, -65536, -4096, 1,
				4095,	 4096,	 65536, INT_MAX };
	for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		int result = invoke(IN_RETURN_TEST, 0, (__u32)invalid[i], 0);
		if (result != -EPERM) {
			fprintf(stderr,
				"BPF invalid return prior=%d actual=%d\n",
				invalid[i], result);
			require(0, "actual BPF invalid nonzero stays denial");
		}
	}
	require(1,
		"actual BPF return helper preserves all valid errnos and rejects invalid nonzero");
	require(invoke(IN_PIN, 0, 0, 1) == -EPERM && !state().pinned,
		"wrong nonce cannot authenticate pins");
	require(invoke(IN_BAD_PIN, 0, 0, 0) == -EINVAL && !state().pinned,
		"non-cgroup O_PATH inode cannot authenticate target");
	require(invoke(IN_PIN, 0, 0, 0) == 0 && state().pinned,
		"authenticate retained exact cgroup.procs O_PATH pins");
	require(invoke(IN_PIN, 0, 0, 0) == -EEXIST,
		"pin identity cannot be overwritten");
	guard = attach("in_permission");
	arm_link = attach("in_arm");
	ingress_links[0] = attach("in_can_fork");
	ingress_links[1] = attach("in_post_enter");
	ingress_links[2] = attach("in_cancel_enter");
	ingress_links[3] = attach("in_post_exit");
	ingress_links[4] = attach("in_cancel_exit");
	ingress_links[5] = attach("in_arm_enter");
	require(clone_into(target_dir, target) == 0 && state().audit_hits > 0,
		"audit allows real outside clone-into and records exact target");
	require(state().next_token == 1 && state().ingress_admitted == 1 &&
			state().ingress_completed == 1 &&
			!state().ingress_inflight && !state().uncertain,
		"successful target fork owns and completes exactly one ingress token");
	__u64 token_key = 0;
	errno = 0;
	require(bpf_map_get_next_key(tokens_fd, NULL, &token_key) < 0 &&
			errno == ENOENT,
		"completed ingress token storage reclaimed");
	require(invoke(IN_STAGE, 1, IN_STRICT, 1) == -EPERM &&
			!state().pending_attempt,
		"wrong nonce cannot stage strict");
	require(invoke(IN_STAGE, 1, IN_STRICT, 0) == 0,
		"stage strict pending identity");
	require(negative_pid_write(other_write) < 0 &&
			state().active_attempt == 0 &&
			state().pending_attempt == 1 &&
			state().wrong_control == 1,
		"wrong control inode cannot ARM despite negative write error");
	require(negative_pid_write(control_write) == -EINVAL &&
			state().active_attempt == 1 &&
			state().mode == IN_STRICT,
		"exact administrative control inode commits strict under mutex");
	struct in_state before = state();
	require(clone_into(target_dir, target) == -EPERM &&
			state().denials == before.denials + 1,
		"strict refuses outside clone before child succeeds");
	errno = 0;
	int denied_open =
		openat(target_dir, "cgroup.procs", O_WRONLY | O_CLOEXEC);
	int open_error = errno;
	if (denied_open >= 0)
		close(denied_open);
	require(denied_open < 0 && open_error == EPERM,
		"administrative caller has no target-write exemption");
	require(clone_into(other_dir, other) == 0,
		"unrelated target remains allowed");
	require(clone_into(-1, current) == 0,
		"ordinary outside fork remains allowed");
	require(state().ingress_admitted == 1 &&
			state().ingress_completed == 1 &&
			!state().ingress_inflight &&
			!state().unowned_completions,
		"strict refusal and unrelated/ordinary forks do not acquire or refund target tokens");
	cross_mount(argv[2], target_dir, -EPERM);
	set_mode(control_write, 2, IN_AUDIT);
	before = state();
	require(clone_into(target_dir, target) == 0 &&
			state().audit_hits == before.audit_hits + 1,
		"audit restored without target exemption");
	cross_mount(argv[2], target_dir, 0);
	require(state().inspection_errors == 0 && !state().pending_attempt,
		"no target inspection fault or pending ARM");
	before = state();
	require(!before.ingress_inflight && !before.uncertain &&
			before.ingress_admitted == before.ingress_completed,
		"all observed target births completed ownership naturally");
	require(invoke(IN_STAGE, 3, IN_STRICT, 0) == 0,
		"stage candidate before audit birth");
	require(clone_into(target_dir, target) == 0,
		"audit stays nonblocking while candidate is staged");
	require(negative_pid_write(control_write) == -EINVAL &&
			state().mode == IN_AUDIT &&
			state().active_attempt == 2 &&
			state().pending_attempt == 3 &&
			state().arm_refusals == before.arm_refusals + 1 &&
			(state().last_arm_reason & IN_ARM_STALE) &&
			!state().ingress_inflight,
		"completed audit birth invalidates receipt even after natural quiescence");
	require(invoke(IN_ABORT, 3, 0, 0) == 0 && !state().pending_attempt,
		"abort refuses no active history and clears only pending candidate");
	set_mode(control_write, 4, IN_STRICT);
	require(clone_into(target_dir, target) == -EPERM,
		"fresh receipt restores prospective strict denial");
	set_mode(control_write, 5, IN_AUDIT);
	test_owned_cancellation(target_dir);
	test_overlap(target_dir, control_write, target);
	before = state();
	bpf_link__destroy(ingress_links[0]);
	ingress_links[0] = NULL;
	require(clone_into(target_dir, target) == 0,
		"unobserved-prefix audit birth remains allowed");
	require(state().uncertain &&
			state().unowned_completions ==
				before.unowned_completions + 1 &&
			state().ingress_admitted == before.ingress_admitted &&
			state().ingress_completed == before.ingress_completed &&
			state().ingress_inflight == before.ingress_inflight,
		"unowned completion records uncertainty without refunding another token");
	require(invoke(IN_STAGE, 9, IN_STRICT, 0) == -EAGAIN &&
			state().mode == IN_AUDIT &&
			state().active_attempt == 8 && !state().pending_attempt,
		"prefix uncertainty refuses strict promotion without blocking audit");
	errno = 0;
	require(bpf_map_get_next_key(tokens_fd, NULL, &token_key) < 0 &&
			errno == ENOENT,
		"all owned ingress tokens reclaimed at teardown");
	puts("NOT_RUN: overflow/failure injection and full production-history qualification remain required");
	close(target_dir);
	close(other_dir);
	close(control_write);
	close(other_write);
	return 0;
}
