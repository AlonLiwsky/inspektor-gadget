// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "publication.h"
static struct bpf_object *object;
static struct bpf_link *arm_link;
static int state_fd = -1, commands_fd = -1, command_prog = -1, control_pin = -1,
	   control_write = -1;
static struct pc_config config;
static const __u32 zero;
static struct pc_command candidate;
static atomic_uint eval_errors;
struct worker {
	pthread_t thread;
	pthread_mutex_t mutex;
	pthread_cond_t cond;
	unsigned slot;
	bool ready, request, done, stop, loop;
	struct pc_command command;
	int result;
};
static struct worker workers[2];
static void die(const char *msg)
{
	perror(msg);
	exit(1);
}
static struct pc_stats stats(void)
{
	struct pc_stats s = {};
	if (state_fd >= 0 &&
	    bpf_map_lookup_elem_flags(state_fd, &zero, &s, BPF_F_LOCK))
		die("state lookup");
	return s;
}
static void require(bool ok, const char *message)
{
	struct pc_stats s = stats();
	printf("%s %s active=%llu bank=%llu class=%llu candidate=%llu phase=%llu serial=%llu receipt=%llu/%llu readers=%llu writers=%llu staged=%llx reserved=%llu accepted=%llu arms=%llu refused=%llu incoherent=%llu evals=%llu strict=%llu audit=%llu\n",
	       ok ? "PASS" : "FAIL", message,
	       (unsigned long long)s.active_attempt,
	       (unsigned long long)s.active_bank,
	       (unsigned long long)s.active_mode, (unsigned long long)s.attempt,
	       (unsigned long long)s.phase, (unsigned long long)s.serial,
	       (unsigned long long)s.receipt_attempt,
	       (unsigned long long)s.receipt_serial,
	       (unsigned long long)s.readers, (unsigned long long)s.writers,
	       (unsigned long long)s.staged_mask,
	       (unsigned long long)s.reserved, (unsigned long long)s.accepted,
	       (unsigned long long)s.arms, (unsigned long long)s.arm_refused,
	       (unsigned long long)s.incoherent, (unsigned long long)s.evals,
	       (unsigned long long)s.denials,
	       (unsigned long long)s.audit_denials);
	if (!ok)
		exit(1);
}
static int invoke_nonce(struct pc_command q, bool wrong_nonce)
{
	__u32 tid = (__u32)syscall(SYS_gettid);
	q.nonce = config.nonce ^ (wrong_nonce ? 1 : 0);
	if (bpf_map_update_elem(commands_fd, &tid, &q, BPF_ANY))
		die("command update");
	LIBBPF_OPTS(bpf_test_run_opts, opt);
	if (bpf_prog_test_run_opts(command_prog, &opt))
		die("BPF command run");
	return (int)opt.retval;
}
static int invoke(struct pc_command q)
{
	return invoke_nonce(q, false);
}
static void cleanup(void)
{
	/* Fatal assertions exit the process, terminating its threads and their owned
  * test-only tokens; links/maps are not pinned and disappear with process FDs. */
	bpf_link__destroy(arm_link);
	bpf_object__close(object);
	if (control_pin >= 0)
		close(control_pin);
	if (control_write >= 0)
		close(control_write);
}
static void *worker_main(void *arg)
{
	struct worker *w = arg;
	struct pc_command q = { .op = PC_REGISTER, .slot = w->slot };
	int result = invoke(q);
	pthread_mutex_lock(&w->mutex);
	w->result = result;
	w->ready = true;
	pthread_cond_signal(&w->cond);
	for (;;) {
		while (!w->request && !w->loop && !w->stop)
			pthread_cond_wait(&w->cond, &w->mutex);
		if (w->stop)
			break;
		if (w->request) {
			q = w->command;
			w->request = false;
			pthread_mutex_unlock(&w->mutex);
			result = invoke(q);
			pthread_mutex_lock(&w->mutex);
			w->result = result;
			w->done = true;
			pthread_cond_signal(&w->cond);
		} else {
			q = (struct pc_command){ .op = PC_EVAL, .arg0 = 0 };
			pthread_mutex_unlock(&w->mutex);
			result = invoke(q);
			pthread_mutex_lock(&w->mutex);
			if (result)
				atomic_fetch_add(&eval_errors, 1);
		}
	}
	pthread_mutex_unlock(&w->mutex);
	return NULL;
}
static void start_workers(void)
{
	for (unsigned i = 0; i < 2; i++) {
		struct worker *w = &workers[i];
		w->slot = i + 1;
		if (pthread_mutex_init(&w->mutex, NULL) ||
		    pthread_cond_init(&w->cond, NULL) ||
		    pthread_create(&w->thread, NULL, worker_main, w))
			die("worker create");
		pthread_mutex_lock(&w->mutex);
		while (!w->ready)
			pthread_cond_wait(&w->cond, &w->mutex);
		int result = w->result;
		pthread_mutex_unlock(&w->mutex);
		require(!result,
			"native worker registers its own retained task row");
	}
}
static int call_worker(unsigned i, struct pc_command q)
{
	struct worker *w = &workers[i];
	pthread_mutex_lock(&w->mutex);
	w->command = q;
	w->done = false;
	w->request = true;
	pthread_cond_signal(&w->cond);
	while (!w->done)
		pthread_cond_wait(&w->cond, &w->mutex);
	int result = w->result;
	pthread_mutex_unlock(&w->mutex);
	return result;
}
static void looping(bool enabled, unsigned mask)
{
	for (unsigned i = 0; i < 2; i++) {
		if (!(mask & (1U << i)))
			continue;
		pthread_mutex_lock(&workers[i].mutex);
		workers[i].loop = enabled;
		pthread_cond_signal(&workers[i].cond);
		pthread_mutex_unlock(&workers[i].mutex);
	}
	if (!enabled) {
		/* A synchronous query-shaped EVAL per worker joins any previously running
   * evaluation. No elapsed-time assumption establishes quiescence. */
		for (unsigned i = 0; i < 2; i++)
			if (mask & (1U << i))
				require(call_worker(i,
						    (struct pc_command){
							    .op = PC_EVAL }) ==
						0,
					"worker evaluation loop joins with coherent allowed input");
	}
}
static void stop_workers(void)
{
	for (unsigned i = 0; i < 2; i++) {
		pthread_mutex_lock(&workers[i].mutex);
		workers[i].stop = true;
		pthread_cond_signal(&workers[i].cond);
		pthread_mutex_unlock(&workers[i].mutex);
	}
	for (unsigned i = 0; i < 2; i++) {
		if (pthread_join(workers[i].thread, NULL))
			die("worker join");
		pthread_cond_destroy(&workers[i].cond);
		pthread_mutex_destroy(&workers[i].mutex);
	}
}
static int operation(__u32 op)
{
	struct pc_command q = candidate;
	q.op = op;
	return invoke(q);
}
static void new_candidate(__u64 attempt, __u32 bank, __u32 mode, __u64 a,
			  __u64 b)
{
	candidate = (struct pc_command){ .attempt = attempt,
					 .bank = bank,
					 .mode = mode,
					 .uid0 = a,
					 .uid1 = b,
					 .arg0 = 101,
					 .arg1 = 202,
					 .deny_bits = 3 };
	for (unsigned i = 0; i < 6; i++)
		candidate.extra_uids[i] = a + 2 + i;
	require(operation(PC_BEGIN) == 0,
		"BEGIN exclusively leases inactive fixed banks and catalogue reservations");
}
static void write_candidate(bool malformed)
{
	struct pc_command q = candidate;
	q.op = PC_WRITE_BEGIN;
	require(call_worker(0, q) == 0,
		"writer owns inactive-bank write token");
	require(operation(PC_SEAL) == -EBUSY,
		"SEAL refuses an outstanding writer");
	require(operation(PC_ABORT) == -EBUSY,
		"abort cannot recycle an owned writer bank");
	q.op = PC_WRITE_END;
	q.bad_stamp = malformed;
	require(call_worker(0, q) == 0,
		"writer publishes actual UID/role/argument/action content and releases ownership");
}
static void seal_candidate(void)
{
	require(operation(PC_SEAL) == 0,
		"complete stamp/content/class validation seals program");
	struct pc_command q = candidate;
	q.op = PC_WRITE_BEGIN;
	require(call_worker(0, q) == -EPERM,
		"sealed program rejects later loader writes");
}
static void stage_all(void)
{
	require(operation(PC_SNAPSHOT) == 0,
		"snapshot captures quiescent descriptor and serial");
	require(operation(PC_STAGE) == 0,
		"admin task stages factual role history");
	struct pc_command q = candidate;
	q.op = PC_STAGE;
	for (unsigned i = 0; i < 2; i++)
		require(call_worker(i, q) == 0,
			"worker stages its real task-cookie role bank");
}
/* Pure receipt predicate: the host-only regression never opens control/BPF FDs. */
static bool fresh_arm_receipt(const struct pc_stats *before,
			      const struct pc_stats *after, bool success)
{
	return success ?
		       (after->arm_result == 0 && before->arms != ~0ULL &&
			after->arms == before->arms + 1 &&
			after->arm_refused == before->arm_refused) :
		       (after->arm_result < 0 && before->arm_refused != ~0ULL &&
			after->arm_refused == before->arm_refused + 1 &&
			after->arms == before->arms);
}
static int arm_receipt_tests(void)
{
	struct pc_stats before = { .arm_refused = 7,
				   .arms = 3,
				   .arm_result = -EAGAIN },
			after = before;
	if (fresh_arm_receipt(&before, &after, false)) {
		fputs("FAIL: stale EAGAIN without fresh hook accepted\n",
		      stderr);
		return 1;
	}
	after.arm_refused++;
	if (!fresh_arm_receipt(&before, &after, false))
		return 1;
	after.arm_refused++;
	if (fresh_arm_receipt(&before, &after, false))
		return 1;
	after = before;
	after.arm_result = 0;
	if (fresh_arm_receipt(&before, &after, true))
		return 1;
	after.arms++;
	if (!fresh_arm_receipt(&before, &after, true))
		return 1;
	after.arms++;
	if (fresh_arm_receipt(&before, &after, true))
		return 1;
	before.arm_refused = ~0ULL;
	after = before;
	after.arm_refused = 0;
	if (fresh_arm_receipt(&before, &after, false))
		return 1;
	before.arms = ~0ULL;
	after = before;
	after.arms = 0;
	after.arm_result = 0;
	if (fresh_arm_receipt(&before, &after, true))
		return 1;
	puts("PASS: stale/skipped-hook, duplicate-count and wrapped ARM receipts rejected; exact fresh refusal/success accepted");
	return 0;
}
static void arm(bool success, bool ignore_ack)
{
	struct pc_stats before = stats();
	struct pc_command q = candidate;
	q.op = PC_ARM;
	q.nonce = config.nonce;
	__u32 tid = config.admin_tid;
	if (bpf_map_update_elem(commands_fd, &tid, &q, BPF_ANY))
		die("ARM pending");
	errno = 0;
	ssize_t result = write(control_write, "-1\n", 3);
	int error = errno;
	if (ignore_ack) {
		if (!(result < 0 && error == EINVAL))
			die("negative PID probe");
		puts("PASS: expected write error; deliberately did not inspect commit receipt");
		return;
	}
	require(result < 0 && error == EINVAL,
		"negative PID probe fails without moving task");
	struct pc_stats s = stats();
	require(fresh_arm_receipt(&before, &s, success),
		"this ARM probe produced exactly one fresh success/refusal receipt");
	if (!success)
		require(s.active_attempt == before.active_attempt &&
				s.active_bank == before.active_bank &&
				s.active_mode == before.active_mode &&
				s.accepted == before.accepted &&
				s.arms == before.arms &&
				s.phase == before.phase &&
				s.serial == before.serial &&
				s.receipt_attempt == before.receipt_attempt &&
				s.receipt_serial == before.receipt_serial &&
				s.readers == before.readers &&
				s.writers == before.writers &&
				s.registrations == before.registrations &&
				s.staged_mask == before.staged_mask &&
				s.attempt == before.attempt &&
				s.bank == before.bank &&
				s.mode == before.mode &&
				s.expected_active == before.expected_active &&
				s.reserved == before.reserved,
			"refused ARM preserves complete descriptor, accepted count and publication receipt");
	require(success ? (s.arm_result == 0 &&
			   s.active_attempt == candidate.attempt &&
			   s.active_bank == candidate.bank &&
			   s.active_mode == candidate.mode &&
			   s.phase == PC_COMMITTED) :
			  (s.arm_result < 0 &&
			   s.active_attempt != candidate.attempt),
		success ?
			"mutex-held ARM commits coherent content/catalogue/history/class" :
			"ARM refuses concurrent ownership or stale receipt without replacing active state");
}
static void query(__u64 a, __u64 b)
{
	struct pc_command q = { .op = PC_QUERY, .uid0 = a, .uid1 = b };
	require(invoke(q) == 0,
		"counted control query reads catalogue and committed descriptor");
}
static void load(const char *path, const char *out)
{
	object = bpf_object__open_file(path, NULL);
	if (libbpf_get_error(object)) {
		object = NULL;
		die("open object");
	}
	struct bpf_program *p;
	char *logs[4] = {};
	const char *names[4] = {};
	unsigned count = 0;
	bpf_object__for_each_program(p, object)
	{
		if (count == 4)
			die("too many programs");
		logs[count] = calloc(1, 16U << 20);
		if (!logs[count])
			die("verifier log allocation");
		names[count] = bpf_program__name(p);
		if (bpf_program__set_log_buf(p, logs[count], 16U << 20) ||
		    bpf_program__set_log_level(p, 1))
			die("verifier config");
		count++;
	}
	int result = bpf_object__load(object);
	char name[4096];
	if (snprintf(name, sizeof(name), "%s/verifier.log", out) >=
	    (int)sizeof(name))
		die("log path");
	FILE *f = fopen(name, "w");
	if (!f)
		die("log file");
	for (unsigned i = 0; i < count; i++) {
		fprintf(f, "=== %s ===\n", names[i]);
		fputs(logs[i], f);
		free(logs[i]);
	}
	fclose(f);
	if (result)
		die("BPF load");
	bpf_object__for_each_program(p, object)
	{
		struct bpf_prog_info info = {};
		__u32 len = sizeof(info);
		if (bpf_obj_get_info_by_fd(bpf_program__fd(p), &info, &len))
			die("program info");
		printf("PROGRAM_ID %u %s\n", info.id, bpf_program__name(p));
	}
	state_fd = bpf_object__find_map_fd_by_name(object, "state");
	commands_fd = bpf_object__find_map_fd_by_name(object, "commands");
	p = bpf_object__find_program_by_name(object, "pc_command");
	if (!p)
		die("command program");
	command_prog = bpf_program__fd(p);
	int fd = bpf_object__find_map_fd_by_name(object, "config");
	if (bpf_map_update_elem(fd, &zero, &config, BPF_ANY) ||
	    bpf_map_freeze(fd))
		die("freeze configuration");
	p = bpf_object__find_program_by_name(object, "pc_arm");
	if (!p)
		die("ARM program");
	arm_link = bpf_program__attach(p);
	if (libbpf_get_error(arm_link)) {
		arm_link = NULL;
		die("ARM attach");
	}
	/* Kernel loader owns all writes to these authority maps. */
	const char *readonly[] = { "programs", "catalogue", "tasks", "state" };
	for (unsigned i = 0; i < 4; i++) {
		struct bpf_map *m =
			bpf_object__find_map_by_name(object, readonly[i]);
		require(m && (bpf_map__map_flags(m) & BPF_F_RDONLY),
			"authority map is UAPI-readonly");
	}
	struct pc_program zero_program = {};
	errno = 0;
	require(bpf_map_update_elem(bpf_object__find_map_fd_by_name(object,
								    "programs"),
				    &zero, &zero_program, BPF_ANY) < 0 &&
			errno == EPERM,
		"userspace cannot overwrite active/inactive program storage");
}
static bool disposable_allowed(uid_t uid, const char *consent)
{
	return uid == 0 && consent && !strcmp(consent, "1");
}
static int consent_tests(void)
{
	const char *denied[] = { NULL, "", "0", "true", "01", "1 " };
	for (unsigned i = 0; i < sizeof(denied) / sizeof(denied[0]); i++)
		if (disposable_allowed(0, denied[i]))
			return 1;
	if (!disposable_allowed(0, "1") || disposable_allowed(1000, "1"))
		return 1;
	puts("PASS: explicit disposable consent requires uid zero and exactly value 1");
	return 0;
}
int main(int argc, char **argv)
{
	if (argc == 2 && !strcmp(argv[1], "--self-test-consent"))
		return consent_tests();
	if (argc == 2 && !strcmp(argv[1], "--self-test-arm-receipt"))
		return arm_receipt_tests();
	if (argc != 4) {
		fprintf(stderr,
			"usage: %s OBJECT EVIDENCE_DIR NEW_CONTROL_CGROUP\n",
			argv[0]);
		return 2;
	}
	setvbuf(stdout, NULL, _IONBF, 0);
	const char *consent = getenv("IG_ABI3_GATE_A_DISPOSABLE");
	if (!disposable_allowed(geteuid(), consent)) {
		fprintf(stderr,
			"Refusing: disposable root host and IG_ABI3_GATE_A_DISPOSABLE=1 required\n");
		return 2;
	}
	char path[4096];
	if (snprintf(path, sizeof(path), "%s/cgroup.procs", argv[3]) >=
	    (int)sizeof(path))
		die("control path");
	control_pin = open(path, O_PATH | O_CLOEXEC);
	control_write = open(path, O_WRONLY | O_CLOEXEC);
	if (control_pin < 0 || control_write < 0)
		die("control pins");
	config = (struct pc_config){ .tgid = getpid(),
				     .admin_tid = (__u32)syscall(SYS_gettid),
				     .control_fd = control_pin };
	if (getrandom(&config.nonce, sizeof(config.nonce), 0) !=
		    (ssize_t)sizeof(config.nonce) ||
	    !config.nonce)
		die("nonce");
	load(argv[1], argv[2]);
	require(invoke_nonce((struct pc_command){ .op = PC_PIN }, true) ==
			-EPERM,
		"wrong nonce cannot authenticate control endpoint");
	require(invoke((struct pc_command){ .op = PC_PIN }) == 0,
		"physical admin authenticates retained control kernfs object");
	require(invoke((struct pc_command){ .op = PC_REGISTER, .slot = 0 }) ==
			0,
		"admin registers bounded task row");
	start_workers();
	require(invoke((struct pc_command){ .op = PC_REGISTER, .slot = 0 }) < 0,
		"duplicate task slot cannot change inventory");
	new_candidate(1, 0, PC_AUDIT, 1, 2);
	write_candidate(true);
	require(operation(PC_SEAL) == -EINVAL,
		"incomplete program stamp never seals");
	write_candidate(false);
	seal_candidate();
	stage_all();
	require(operation(PC_CERTIFY) == 0,
		"complete real task bank inventory certifies");
	require(operation(PC_ARM) == -EOPNOTSUPP,
		"syscall command cannot commit outside cgroup mutex");
	candidate.uid1 = 999;
	arm(false, false);
	candidate.uid1 = 2;
	query(1, 2);
	require(stats().query0 == 0 && stats().query1 == 0 &&
			!stats().active_attempt,
		"missing second catalogue pointer cannot partially accept first UID");
	candidate.extra_uids[5] = 999;
	arm(false, false);
	candidate.extra_uids[5] = 8;
	for (unsigned i = 1; i <= 8; i += 2) {
		query(i, i + 1);
		require(stats().query0 == 0 && stats().query1 == 0 &&
				!stats().active_attempt && !stats().accepted,
			"missing eighth target leaves ALL eight epochs and descriptor untouched");
	}
	candidate.extra_uids[5] = 7;
	arm(false, false);
	candidate.extra_uids[5] = 8;
	for (unsigned i = 1; i <= 8; i += 2) {
		query(i, i + 1);
		require(stats().query0 == 0 && stats().query1 == 0 &&
				!stats().active_attempt && !stats().accepted,
			"existing but invalid eighth target leaves ALL eight epochs and descriptor untouched");
	}
	arm(true, false);
	for (unsigned i = 1; i <= 8; i += 2) {
		query(i, i + 1);
		require(stats().query0 == 1 && stats().query1 == 1 &&
				stats().accepted == 8 &&
				stats().query_attempt == 1 &&
				stats().query_bank == 0 &&
				stats().query_mode == PC_AUDIT &&
				stats().phase == PC_COMMITTED,
			"all eight sealed UID epochs accepted with matching COMMITTED descriptor");
	}
	require(invoke((struct pc_command){ .op = PC_EVAL, .arg0 = 101 }) == 0,
		"real deny rule in immutable audit class remains nonblocking");
	require(stats().audit_denials == 1 && stats().denials == 0,
		"audit classification comes from committed complete program");
	query(1, 2);
	require(stats().query0 == 1 && stats().query1 == 1,
		"both new UID epochs committed with first descriptor");
	new_candidate(2, 1, PC_STRICT, 1, 2);
	/* The second worker owns a latched audit read before loading begins and
  * cannot finish it until explicitly requested after SEAL. The first worker
  * also loops evaluations, but scheduling of that stress loop is not proof. */
	require(call_worker(1, (struct pc_command){ .op = PC_READ_BEGIN }) ==
				0 &&
			stats().readers == 1,
		"latched old-generation reader is owned before inactive loading starts");
	looping(true, 1);
	write_candidate(false);
	seal_candidate();
	looping(false, 1);
	struct pc_stats held = stats();
	require(held.readers == 1 && held.phase == PC_SEALED &&
			held.active_attempt == 1 && held.active_bank == 0 &&
			held.active_mode == PC_AUDIT,
		"old-generation reader ownership spans the complete inactive write and SEAL");
	require(call_worker(1, (struct pc_command){ .op = PC_READ_END,
						    .arg0 = 101 }) == 0,
		"spanning reader evaluates its latched real deny rule under the old audit class");
	struct pc_stats released = stats();
	require(!released.readers && released.evals == held.evals + 1 &&
			released.audit_denials == held.audit_denials + 1 &&
			released.denials == held.denials,
		"spanning read completes exactly once with coherent audit outcome after SEAL");
	require(!atomic_load(&eval_errors) && stats().incoherent == 0,
		"concurrent evaluations never observe staging or mixed program/history content");
	stage_all();
	struct pc_command q = candidate;
	q.op = PC_STAGE;
	struct pc_stats before_bad_bank = stats();
	q.bank = 2;
	require(call_worker(0, q) == -EINVAL,
		"invalid staging bank is rejected, not normalized");
	struct pc_stats after_bad_bank = stats();
	require(after_bad_bank.readers == before_bad_bank.readers &&
			after_bad_bank.writers == before_bad_bank.writers &&
			after_bad_bank.staged_mask ==
				before_bad_bank.staged_mask &&
			after_bad_bank.receipt_serial ==
				before_bad_bank.receipt_serial &&
			after_bad_bank.active_attempt ==
				before_bad_bank.active_attempt &&
			after_bad_bank.accepted == before_bad_bank.accepted,
		"invalid staging bank leaves ownership, receipt and active authority unchanged");
	q = candidate;
	q.op = PC_STAGE;
	q.unknown_mask = 1;
	require(call_worker(0, q) == -EAGAIN &&
			operation(PC_CERTIFY) == -EAGAIN,
		"unknown required UID blocks strict certification without replacing active audit");
	q.unknown_mask = 0;
	require(call_worker(0, q) == 0 && operation(PC_CERTIFY) == 0,
		"restaging unchanged known active facts repairs candidate only");
	q = (struct pc_command){ .op = PC_READ_BEGIN };
	require(call_worker(0, q) == 0 && call_worker(1, q) == 0,
		"two native threads hold overlapping admission ownership");
	require(stats().readers == 2 && stats().max_readers >= 2,
		"overlap is count-proven, not inferred from elapsed time");
	arm(false, false);
	q.op = PC_READ_END;
	q.arg0 = 101;
	require(call_worker(0, q) == 0 && call_worker(1, q) == 0,
		"owned readers retain old audit descriptor and release exactly once");
	require(call_worker(0, q) == -EPERM,
		"duplicate reader release cannot refund another count");
	require(stats().readers == 0 &&
			stats().receipt_serial != stats().serial,
		"drained ownership still leaves a stale serial receipt");
	arm(false, false);
	require(operation(PC_CERTIFY) == -EAGAIN,
		"old candidate cannot recertify without a fresh snapshot");
	stage_all();
	require(operation(PC_CERTIFY) == 0,
		"fresh task snapshots recertify after admission finishes");
	arm(true,
	    true); // Deliberately lose the userspace ACK; reconcile by counted readback.
	query(1, 2);
	require(stats().query_attempt == 2 && stats().query_bank == 1 &&
			stats().query_mode == PC_STRICT,
		"lost ACK resolves committed descriptor, not rollback");
	for (unsigned i = 1; i <= 8; i += 2) {
		query(i, i + 1);
		require(stats().query0 == 1 && stats().query1 == 1 &&
				stats().accepted == 8 &&
				stats().query_attempt == 2,
			"same-UID reload preserves all eight accepted epochs");
	}
	require(operation(PC_ABORT) == -EALREADY,
		"committed attempt cannot be aborted");
	require(invoke((struct pc_command){ .op = PC_EVAL, .arg0 = 101 }) ==
			-EPERM,
		"real role/argument rule denies in strict class");
	require(invoke((struct pc_command){ .op = PC_EVAL, .arg0 = 303 }) == 0,
		"nonmatching input remains allowed");
	/* Aborted never-accepted IDs consume bounded metadata, never authority. */
	for (unsigned i = 0; i < 3; i++) {
		__u64 a = 9 + 8 * i;
		new_candidate(3 + i, 0, PC_AUDIT, a, a + 1);
		require(operation(PC_ABORT) == 0,
			"precommit abort leaves permanent UID reservations unaccepted");
		for (unsigned j = 0; j < 8; j += 2) {
			query(a + j, a + j + 1);
			require(stats().query0 == 0 && stats().query1 == 0 &&
					stats().active_attempt == 2,
				"all eight aborted reservations cannot grant epochs or replace active program");
		}
	}
	candidate =
		(struct pc_command){ .attempt = 6,
				     .bank = 0,
				     .mode = PC_AUDIT,
				     .uid0 = 33,
				     .uid1 = 34,
				     .extra_uids = { 35, 36, 37, 38, 39, 40 },
				     .arg0 = 101,
				     .arg1 = 202,
				     .deny_bits = 3 };
	require(operation(PC_BEGIN) == -ENOSPC && stats().reserved == PC_UIDS &&
			stats().accepted == 8 && stats().active_attempt == 2,
		"bounded catalogue exhaustion retains last-good strict enforcement");
	new_candidate(7, 0, PC_AUDIT, 1, 2);
	write_candidate(false);
	seal_candidate();
	stage_all();
	require(operation(PC_CERTIFY) == 0,
		"same-UID reload remains possible at metadata capacity");
	arm(true, false);
	require(invoke((struct pc_command){ .op = PC_EVAL, .arg0 = 101 }) == 0,
		"strict-to-audit transition uses naturally quiescent coherent descriptor");
	require(stats().incoherent == 0 && !stats().readers &&
			!stats().writers &&
			stats().registered_mask == PC_ALL_TASKS,
		"final exact ownership, inventory and coherence invariants hold");
	stop_workers();
	cleanup();
	puts("PASS: publication primitive suite; not full owner/lineage/policy proof");
	return 0;
}
