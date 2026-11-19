// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "fixture.h"
static struct bpf_object *obj;
static struct bpf_link *links[5];
static int config_fd, command_fd, command_prog;
static int state_fd = -1;
static struct ga_config config;
static const __u32 zero;
static void die(const char *what)
{
	perror(what);
	exit(1);
}
static struct ga_stats stats(void);
static void snapshot(const char *label, const struct ga_stats *s)
{
	printf("COUNTERS %s serial=%llu cookie=%llu inflight=%llu retained=%llu births=%llu frees=%llu refused=%llu failures=%llu faults=%llu taint=%llu scratch=%llu last_key=%llx last_cookie=%llu last_free=%llu active_attempt=%llu active_bank=%llu active_program=%llu receipt_serial=%llu receipt_attempt=%llu ready=%llu inventory=%llu armed=%llu\n",
	       label, (unsigned long long)s->serial,
	       (unsigned long long)s->next_cookie,
	       (unsigned long long)s->inflight, (unsigned long long)s->retained,
	       (unsigned long long)s->births, (unsigned long long)s->frees,
	       (unsigned long long)s->refused, (unsigned long long)s->failures,
	       (unsigned long long)s->faults, (unsigned long long)s->taint,
	       (unsigned long long)s->scratch_collisions,
	       (unsigned long long)s->last_key,
	       (unsigned long long)s->last_cookie,
	       (unsigned long long)s->last_free_cookie,
	       (unsigned long long)s->active_attempt,
	       (unsigned long long)s->active_bank,
	       (unsigned long long)s->active_program,
	       (unsigned long long)s->receipt_serial,
	       (unsigned long long)s->receipt_attempt,
	       (unsigned long long)s->ready, (unsigned long long)s->inventory,
	       (unsigned long long)s->armed);
}
static void require(int condition, const char *what)
{
	static struct ga_stats previous;
	printf("ASSERT: %s\n", what);
	if (state_fd >= 0) {
		struct ga_stats current = stats();
		snapshot("previous_assert", &previous);
		snapshot("current_assert", &current);
		previous = current;
	}
	if (!condition) {
		fprintf(stderr, "FAIL: %s\n", what);
		exit(1);
	}
	printf("PASS: %s\n", what);
	fflush(stdout);
}
static void write_config(void)
{
	if (bpf_map_update_elem(config_fd, &zero, &config, BPF_ANY))
		die("config");
}
static struct ga_stats stats(void)
{
	struct ga_stats s = {};
	if (bpf_map_lookup_elem_flags(state_fd, &zero, &s, BPF_F_LOCK))
		die("stats");
	return s;
}
static int command(__u32 op, __u64 attempt)
{
	struct ga_command cmd = { .operation = op, .attempt = attempt };
	if (bpf_map_update_elem(command_fd, &zero, &cmd, BPF_ANY))
		die("command map");
	LIBBPF_OPTS(bpf_test_run_opts, o);
	if (bpf_prog_test_run_opts(command_prog, &o))
		die("command test_run");
	return (int)o.retval;
}
static void wait_rows(__u64 rows)
{
	for (int i = 0; i < 500; i++) {
		struct ga_stats s = stats();
		if (s.retained == rows && s.inflight == 0)
			return;
		usleep(10000);
	}
	struct ga_stats s = stats();
	fprintf(stderr, "retained=%llu inflight=%llu faults=%llu wanted=%llu\n",
		(unsigned long long)s.retained, (unsigned long long)s.inflight,
		(unsigned long long)s.faults, (unsigned long long)rows);
	require(0, "bounded task_free cleanup");
}
static void child_success(void)
{
	pid_t p = fork();
	if (p < 0)
		die("fork");
	if (!p)
		_exit(0);
	int status;
	if (waitpid(p, &status, 0) != p)
		die("waitpid");
	require(WIFEXITED(status) && WEXITSTATUS(status) == 0,
		"child succeeds");
}
static struct bpf_link *attach(const char *name)
{
	struct bpf_program *p = bpf_object__find_program_by_name(obj, name);
	if (!p)
		die(name);
	struct bpf_link *l = bpf_program__attach(p);
	if (libbpf_get_error(l))
		die(name);
	return l;
}
static void cleanup(void)
{
	for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++)
		bpf_link__destroy(links[i]);
	bpf_object__close(obj);
}
static void pids_limit(const char *dir, const char *value)
{
	char path[4096];
	if (snprintf(path, sizeof(path), "%s/pids.max", dir) >=
	    (int)sizeof(path))
		die("path");
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		die("pids.max");
	size_t n = strlen(value);
	if (write(fd, value, n) != (ssize_t)n)
		die("write pids.max");
	close(fd);
}
/* Each boundary case needs a NEW object/session: never reset a live counter. */
static void boundary_case(const char *name)
{
	__u64 profile = 0;
	if (!strcmp(name, "cookie-max"))
		profile = 1;
	else if (!strcmp(name, "cookie-last"))
		profile = 2;
	else if (!strcmp(name, "serial-max"))
		profile = 3;
	else if (!strcmp(name, "serial-last"))
		profile = 4;
	else
		require(!strcmp(name, "capacity-audit"),
			"known boundary profile");
	printf("EVIDENCE: fresh authenticated seed profile=%llu; synthetic boundary initialization, actual fork hooks, no concurrency claim\n",
	       (unsigned long long)profile);
	config.admin_pid = 0;
	write_config();
	require(command(GA_SEED, profile) == -EPERM &&
			stats().next_cookie == 0 && stats().serial == 0,
		"unauthenticated boundary seed rejected without mutation");
	config.admin_pid = getpid();
	write_config();
	require(command(GA_SEED, 5) == -EINVAL && stats().seeded == 0,
		"invalid boundary profile rejected before one-shot claim");
	require(command(GA_SEED, profile) == 0, "fresh boundary seed");
	struct ga_stats seed = stats();
	require(command(GA_SEED, 0) == -EEXIST &&
			stats().serial == seed.serial &&
			stats().next_cookie == seed.next_cookie,
		"seed cannot reset a live fixture");
	pid_t children[GA_LIMIT - 1];
	unsigned count = 0;
	if (!profile) {
		for (; count < GA_LIMIT - 1; count++) {
			children[count] = fork();
			if (children[count] < 0)
				die("boundary capacity fork");
			if (!children[count]) {
				for (;;)
					pause();
			}
		}
		require(stats().retained == GA_LIMIT,
			"actual retained capacity exhausted");
	} else if (profile == 2 || profile == 4) {
		require(command(GA_STAGE, 2) == 0,
			"stage before final counter admission");
		struct ga_stats before = stats();
		child_success();
		wait_rows(1);
		struct ga_stats after = stats();
		require(after.next_cookie == before.next_cookie + 1 &&
				after.births == before.births + 1 &&
				after.frees == before.frees + 1 &&
				after.inflight == 0,
			"last reservation completes and owned row is freed exactly once");
		require((profile == 2 && after.next_cookie == ~0ULL &&
			 after.faults == 0) ||
				(profile == 4 && after.serial == ~0ULL &&
				 after.faults > before.faults),
			"counter saturates without wrap and serial exhaustion is sticky");
		require(command(GA_ARM, 2) == -EAGAIN,
			"last admission invalidates staged receipt");
	}
	if (profile == 3)
		require(command(GA_STAGE, 2) == -EAGAIN,
			"serial MAX cannot certify even before a new mutation");
	struct ga_stats before = stats();
	/* Read the seeded parent's row byte-for-byte around the refused operations. */
	int fd = bpf_object__find_map_fd_by_name(obj, "tasks");
	struct bpf_map_info mi = {};
	__u32 len = sizeof(mi);
	if (bpf_obj_get_info_by_fd(fd, &mi, &len))
		die("boundary map info");
	__u64 key = 0, next = 0;
	int found = 0, seed_found = 0;
	while (!bpf_map_get_next_key(fd, found ? &key : NULL, &next)) {
		key = next;
		found = 1;
		/* The only cookie 1 belongs to the seed, including high-cookie profiles. */
		unsigned char *row = calloc(1, mi.value_size);
		if (!row)
			die("row allocation");
		if (bpf_map_lookup_elem_flags(fd, &key, row, BPF_F_LOCK))
			die("row read");
		__u64 cookie;
		memcpy(&cookie, row + 8, sizeof(cookie));
		free(row);
		if (cookie == 1) {
			seed_found = 1;
			break;
		}
	}
	require(seed_found, "seed row found");
	void *row_before = calloc(1, mi.value_size),
	     *row_after = calloc(1, mi.value_size);
	if (!row_before || !row_after)
		die("row snapshots");
	if (bpf_map_lookup_elem_flags(fd, &key, row_before, BPF_F_LOCK))
		die("row before");
	errno = 0;
	pid_t child = fork();
	int error = errno;
	if (!child)
		_exit(99);
	require(child == -1 && error == EAGAIN,
		"strict exhausted reservation refuses affected fork");
	struct ga_stats strict = stats();
	require(strict.refused == before.refused + 1 &&
			strict.taint == before.taint,
		"strict pre-reservation pressure does not add coverage loss");
	config.strict = GA_AUDIT;
	write_config();
	child_success();
	struct ga_stats after = stats();
	require(after.refused == strict.refused + 1 &&
			after.taint == strict.taint + 1,
		"audit exhausted reservation preserves success and records coverage uncertainty");
	require(after.serial == before.serial &&
			after.next_cookie == before.next_cookie &&
			after.retained == before.retained &&
			after.inflight == 0 && after.births == before.births,
		"refusal neither wraps nor consumes storage or completion ownership");
	require(after.active_bank == before.active_bank &&
			after.active_attempt == before.active_attempt &&
			after.active_program == before.active_program &&
			!memcmp(after.catalogue, before.catalogue,
				sizeof(after.catalogue)),
		"refusal preserves accepted descriptor and catalogue");
	if (bpf_map_lookup_elem_flags(fd, &key, row_after, BPF_F_LOCK))
		die("row after");
	require(!memcmp(row_before, row_after, mi.value_size),
		"refusal preserves accepted parent history and scratch bytes");
	free(row_before);
	free(row_after);
	require(command(GA_STAGE, 3) == -EAGAIN &&
			command(GA_ARM, 3) == -EAGAIN,
		"lost audit coverage cannot certify or publish");
	for (unsigned i = 0; i < count; i++)
		if (kill(children[i], SIGTERM))
			die("boundary kill");
	for (unsigned i = 0; i < count; i++) {
		int status;
		if (waitpid(children[i], &status, 0) != children[i])
			die("boundary wait");
	}
	wait_rows(1);
	require(stats().taint == after.taint,
		"cleanup cannot clear audit uncertainty");
}
int main(int argc, char **argv)
{
	if (argc != 4 || geteuid() != 0 ||
	    !getenv("IG_ABI3_GATE_A_DISPOSABLE") ||
	    strcmp(getenv("IG_ABI3_GATE_A_DISPOSABLE"), "1")) {
		fprintf(stderr,
			"Requires isolated disposable host, root, IG_ABI3_GATE_A_DISPOSABLE=1; usage: %s OBJECT LOGDIR DEDICATED_CGROUP\n",
			argv[0]);
		return 2;
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	size_t log_size = 8U << 20;
	LIBBPF_OPTS(bpf_object_open_opts, opts);
	obj = bpf_object__open_file(argv[1], &opts);
	if (libbpf_get_error(obj)) {
		obj = NULL;
		die("open object");
	}
	atexit(cleanup);
	struct bpf_program *program;
	char *logs[16] = {};
	const char *names[16] = {};
	size_t logs_n = 0;
	bpf_object__for_each_program(program, obj)
	{
		if (logs_n == 16)
			die("too many programs");
		logs[logs_n] = calloc(1, log_size);
		if (!logs[logs_n])
			die("log allocation");
		names[logs_n] = bpf_program__name(program);
		if (bpf_program__set_log_buf(program, logs[logs_n], log_size) ||
		    bpf_program__set_log_level(program, 1))
			die("set verifier log");
		logs_n++;
	}
	int err = bpf_object__load(obj);
	char path[4096];
	if (snprintf(path, sizeof(path), "%s/verifier.log", argv[2]) >=
	    (int)sizeof(path))
		die("log path");
	FILE *f = fopen(path, "w");
	if (!f)
		die("verifier log");
	for (size_t i = 0; i < logs_n; i++) {
		fprintf(f, "=== %s ===\n", names[i]);
		fputs(logs[i], f);
		free(logs[i]);
	}
	fclose(f);
	if (err) {
		fprintf(stderr, "load error=%d; verifier evidence: %s\n", err,
			path);
		return 1;
	}
	bpf_object__for_each_program(program, obj)
	{
		struct bpf_prog_info pi = {};
		__u32 size = sizeof(pi);
		if (bpf_obj_get_info_by_fd(bpf_program__fd(program), &pi,
					   &size))
			die("program info");
		printf("PROGRAM_ID %u %s\n", pi.id, bpf_program__name(program));
	}
	config_fd = bpf_object__find_map_fd_by_name(obj, "config");
	state_fd = bpf_object__find_map_fd_by_name(obj, "state");
	command_fd = bpf_object__find_map_fd_by_name(obj, "commands");
	command_prog = bpf_program__fd(
		bpf_object__find_program_by_name(obj, "ga_command"));
	int program_map = bpf_object__find_map_fd_by_name(obj, "programs");
	for (__u32 i = 0; i < 2; i++) {
		__u64 value = 100 + i;
		if (bpf_map_update_elem(program_map, &i, &value, BPF_ANY))
			die("program bank");
	}
	if (bpf_map_freeze(program_map))
		die("freeze program bank");
	__u64 changed = 999;
	errno = 0;
	require(bpf_map_update_elem(program_map, &zero, &changed, BPF_ANY) <
				0 &&
			errno == EPERM,
		"program payloads frozen before activation");
	int task_fd = bpf_object__find_map_fd_by_name(obj, "tasks");
	struct bpf_map_info info = {};
	__u32 len = sizeof(info);
	if (bpf_obj_get_info_by_fd(task_fd, &info, &len))
		die("map info");
	require(info.type == BPF_MAP_TYPE_HASH &&
			!(info.map_flags & BPF_F_NO_PREALLOC) &&
			info.max_entries == GA_LIMIT,
		"preallocated bounded HASH");
	config = (struct ga_config){ .admin_pid = getpid(),
				     .strict = GA_STRICT };
	write_config();
	// Pinned trampoline prepends links: attach denial first so allocation runs first.
	links[1] = attach("ga_later");
	links[0] = attach("ga_alloc");
	links[2] = attach("ga_new");
	links[3] = attach("ga_failed");
	links[4] = attach("ga_free");
	const char *boundary = getenv("IG_ABI3_GATE_A_BOUNDARY");
	if (boundary) {
		boundary_case(boundary);
		return 0;
	}
	require(command(GA_SEED, 0) == 0, "seed exact admin task");
	require(command(GA_SEED, 0) == -EEXIST && stats().next_cookie == 1,
		"one-shot seed refuses replacement of accepted row");
	require(command(GA_INVENTORY, 0) == 0 && stats().inventory == 1,
		"CSS inventory holds task lifetime");
	struct ga_stats iterator_before = stats();
	require(command(GA_ITERATOR_ERROR, 0) == -EINVAL,
		"invalid iterator flags exercise creation-error cleanup");
	require(command(GA_INVENTORY, 0) == 0 && stats().inventory == 1 &&
			stats().retained == iterator_before.retained &&
			stats().serial == iterator_before.serial &&
			stats().faults == 0,
		"inventory remains usable after iterator creation failure");
	child_success();
	wait_rows(1);
	require(stats().births == 1 && stats().frees == 1,
		"successful fork and final-ref cleanup");
	config.reject_later = 1;
	write_config();
	struct ga_stats before = stats();
	snapshot("later_lsm_before_fork", &before);
	errno = 0;
	pid_t p = fork();
	int error = errno;
	if (!p)
		_exit(99);
	require(p == -1 && error == EACCES, "later LSM refuses fork");
	wait_rows(1);
	struct ga_stats after = stats();
	snapshot("later_lsm_after_cleanup", &after);
	require(after.next_cookie == before.next_cookie + 1 &&
			after.frees == before.frees + 1 &&
			after.failures == before.failures + 1,
		"later LSM rollback exactly once");
	config.reject_later = 0;
	write_config();
	before = stats();
	snapshot("post_lsm_before_fork", &before);
	pids_limit(argv[3], "1");
	errno = 0;
	p = fork();
	error = errno;
	if (!p)
		_exit(99);
	pids_limit(argv[3], "max");
	require(p == -1 && error == EAGAIN,
		"pids controller refuses after task_alloc");
	wait_rows(1);
	after = stats();
	snapshot("post_lsm_after_cleanup", &after);
	require(after.next_cookie == before.next_cookie + 1 &&
			after.frees == before.frees + 1 &&
			after.failures == before.failures + 1,
		"post-LSM failed fork rollback exactly once");
	pid_t capacity_children[GA_LIMIT - 1];
	for (unsigned i = 0; i < GA_LIMIT - 1; i++) {
		capacity_children[i] = fork();
		if (capacity_children[i] < 0)
			die("capacity fork");
		if (!capacity_children[i]) {
			for (;;)
				pause();
		}
	}
	require(stats().retained == GA_LIMIT,
		"all preallocated retained slots occupied");
	before = stats();
	errno = 0;
	p = fork();
	error = errno;
	if (!p)
		_exit(99);
	require(p == -1 && error == EAGAIN &&
			stats().refused == before.refused + 1 &&
			stats().faults == 0,
		"capacity refusal is local and precedes child success");
	for (unsigned i = 0; i < GA_LIMIT - 1; i++) {
		if (kill(capacity_children[i], SIGTERM))
			die("kill capacity child");
	}
	for (unsigned i = 0; i < GA_LIMIT - 1; i++) {
		int st;
		if (waitpid(capacity_children[i], &st, 0) !=
		    capacity_children[i])
			die("wait capacity child");
	}
	wait_rows(1);
	child_success();
	wait_rows(1);
	require(stats().faults == 0,
		"reaped capacity is reusable without reset");
	config.hold_child = 1;
	write_config();
	before = stats();
	child_success();
	config.hold_child = 0;
	write_config();
	usleep(100000);
	after = stats();
	require(after.retained == 2 && after.frees == before.frees,
		"acquired task reference retains row after reap");
	require(command(GA_RELEASE_TASK, 0) == 0,
		"release acquired task reference");
	wait_rows(1);
	require(command(GA_STAGE, 2) == 0, "stage coherent inactive banks");
	before = stats();
	child_success();
	wait_rows(1);
	require(command(GA_ARM, 2) == -EAGAIN &&
			stats().active_attempt == before.active_attempt,
		"admission invalidates ARM receipt without publication");
	require(command(GA_STAGE, 3) == 0 && command(GA_ARM, 3) == 0,
		"zero-inflight serial receipt ARM");
	after = stats();
	require(after.active_attempt == 3 && after.active_bank < 2 &&
			after.active_program == 100 + after.active_bank &&
			after.catalogue[after.active_bank].generation == 3,
		"lost ACK recoverable from committed descriptor");
	require(command(GA_ARM, 3) == -EAGAIN && stats().active_attempt == 3,
		"duplicate ARM cannot toggle banks");
	require(command(GA_INVENTORY, 0) == 0, "post-ARM CSS iterator");
	__u64 keys[512] = {}, cookies[512] = {};
	unsigned reuse = 0;
	for (unsigned i = 0; i < 512; i++) {
		pid_t pid = fork();
		if (pid < 0)
			die("reuse fork");
		if (!pid)
			_exit(0);
		int st;
		if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st) ||
		    WEXITSTATUS(st))
			die("reuse waitpid");
		after = stats();
		keys[i] = after.last_key;
		cookies[i] = after.last_cookie;
		for (unsigned j = 0; j < i; j++)
			if (keys[j] == keys[i]) {
				require(cookies[j] < cookies[i],
					"reused address has newer cookie");
				reuse++;
				break;
			}
		wait_rows(1);
	}
	printf("EVIDENCE: 512 fork/reap cycles, observed reused task addresses=%u\n",
	       reuse);
	require(reuse > 0, "actual task address reuse observed (not assumed)");
	require(command(GA_HOLD_SCRATCH, 77) == 0,
		"outer invocation owns scratch");
	require(command(GA_HOLD_SCRATCH, 88) == -EBUSY &&
			command(GA_FREE_SCRATCH, 88) == -EPERM,
		"nested invocation cannot overwrite or release owner scratch");
	before = stats();
	errno = 0;
	p = fork();
	error = errno;
	if (!p)
		_exit(99);
	require(p == -1 && error == EAGAIN,
		"strict scratch collision refuses affected fork");
	config.strict = GA_AUDIT;
	write_config();
	child_success();
	wait_rows(1);
	require(stats().scratch_collisions == before.scratch_collisions + 2,
		"audit scratch collision observed without blocking fork");
	require(command(GA_FREE_SCRATCH, 77) == 0,
		"outer scratch survives both collisions");
	config.reject_later = 1;
	write_config();
	bpf_link__destroy(links[0]);
	links[0] = NULL;
	bpf_link__destroy(links[1]);
	links[1] = NULL;
	// Denial attached last executes first and short-circuits the allocator.
	links[0] = attach("ga_alloc");
	links[1] = attach("ga_later");
	before = stats();
	snapshot("prior_lsm_before_fork", &before);
	errno = 0;
	p = fork();
	error = errno;
	if (!p)
		_exit(99);
	require(p == -1 && error == EACCES &&
			stats().next_cookie == before.next_cookie,
		"prior LSM denial remains effective with audit attached and no reservation");
	after = stats();
	require(after.faults == 0 && after.inflight == 0 && after.retained == 1,
		"no structural fault, transaction leak or child row leak");
	printf("EVIDENCE: serial=%llu cookies=%llu births=%llu frees=%llu failures=%llu audit_taint=%llu\n",
	       (unsigned long long)after.serial,
	       (unsigned long long)after.next_cookie,
	       (unsigned long long)after.births,
	       (unsigned long long)after.frees,
	       (unsigned long long)after.failures,
	       (unsigned long long)after.taint);
	return 0;
}
