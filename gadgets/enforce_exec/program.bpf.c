// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
// Execution enforcement; maps remain empty until a validated target is bound.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <gadget/macros.h>

#define MAX_RULES 128
#define PATH_SIZE 256

extern int bpf_path_d_path(const struct path *path, char *buf,
			   size_t buf__sz) __ksym;

// Slot 0 contains the generation header; remaining slots contain path rules.
struct exec_policy_entry {
	__u64 generation;
	__u32 mode; // 0 off, 1 audit, 2 enforce
	__u32 default_deny;
	__u32 count;
	__u32 deny;
	__u32 prefix;
	__u32 length;
	char path[PATH_SIZE];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES + 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct exec_policy_entry);
} policy SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	// Zero selects strict cgroup scope; otherwise the pinned host mount ns inode.
	__type(value, __u64);
} bindings SEC(".maps");

struct exec_path_scratch {
	char path[PATH_SIZE];
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct exec_path_scratch);
} scratch_space SEC(".maps");

struct event {
	__u64 generation;
	__u64 cgroup;
	__u32 deny;
	__u32 mode;
	__s32 path_result;
	__u32 host_pid;
	char path[PATH_SIZE];
};
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");
GADGET_TRACER(verdict, events, event);

// denied decisions, submitted events, dropped events, allowed decisions, path errors, rate limited
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 6);
	__type(key, __u32);
	__type(value, __u64);
} counters SEC(".maps");

static __always_inline void count(__u32 key)
{
	__u64 *value = bpf_map_lookup_elem(&counters, &key);
	if (value)
		(*value)++;
}

// At most 100 report attempts per CPU per second; enforcement is never throttled.
struct report_window {
	__u64 second;
	__u32 attempts;
};
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct report_window);
} report_windows SEC(".maps");

static __always_inline bool report_allowed(void)
{
	__u32 zero = 0;
	struct report_window *window =
		bpf_map_lookup_elem(&report_windows, &zero);
	if (!window)
		return false;
	__u64 second = bpf_ktime_get_ns() / 1000000000;
	if (window->second != second) {
		window->second = second;
		window->attempts = 0;
	}
	if (window->attempts >= 100)
		return false;
	window->attempts++;
	return true;
}

struct compare_ctx {
	struct exec_path_scratch *scratch;
	struct exec_policy_entry *rule;
	__u32 length;
	bool match;
};

static long compare_char(__u32 index, void *data)
{
	struct compare_ctx *ctx = data;
	__u64 offset = index;
	// Keep the bounds check and pointer arithmetic on the same 64-bit scalar.
	asm volatile("" : "+r"(offset));
	if (offset >= PATH_SIZE || offset >= ctx->length)
		return 1;
	if (ctx->scratch->path[offset] != ctx->rule->path[offset]) {
		ctx->match = false;
		return 1;
	}
	return 0;
}

// A bounded callback avoids verifier state expansion proportional to the policy
// size. Mode zero in a rule inherits the policy mode (legacy map ABI).
struct evaluate_ctx {
	struct exec_path_scratch *scratch;
	__u32 count;
	__u32 policy_mode;
	__u32 deny_mode;
	__u32 error_mode;
	__s32 path_length;
	bool allow_match;
	bool invalid;
};

static long evaluate_rule(__u32 index, void *data)
{
	struct evaluate_ctx *ctx = data;
	if (index >= ctx->count || index >= MAX_RULES)
		return 1;
	__u32 key = index + 1;
	struct exec_policy_entry *rule = bpf_map_lookup_elem(&policy, &key);
	if (!rule || rule->length == 0 || rule->length >= PATH_SIZE ||
	    rule->mode > 2) {
		ctx->invalid = true;
		return 0;
	}
	__u32 mode = rule->mode ? rule->mode : ctx->policy_mode;
	if (mode > ctx->error_mode)
		ctx->error_mode = mode;
	if (ctx->path_length <= 0)
		return 0;
	struct compare_ctx comparison = {
		.scratch = ctx->scratch,
		.rule = rule,
		.length = rule->length,
		.match = true,
	};
	if (bpf_loop(PATH_SIZE, compare_char, &comparison, 0) < 0) {
		ctx->invalid = true;
		return 0;
	}
	if (!rule->prefix && ctx->path_length != rule->length + 1)
		comparison.match = false;
	if (comparison.match) {
		if (rule->deny) {
			if (mode > ctx->deny_mode)
				ctx->deny_mode = mode;
		} else {
			ctx->allow_match = true;
		}
	}
	return 0;
}

SEC("lsm/bprm_check_security")
long BPF_PROG(enforce_exec, struct linux_binprm *bprm, long ret)
{
	if (ret)
		return ret;
	__u64 cgroup = bpf_get_current_cgroup_id();
	__u32 zero = 0;
	__u64 *host_mntns = bpf_map_lookup_elem(&bindings, &cgroup);
	if (!host_mntns)
		return 0;
	if (*host_mntns) {
		struct task_struct *task = (void *)bpf_get_current_task_btf();
		__u32 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
		// Only native owner-admitted restricted bindings carry an exception.
		// Unknown/child mount namespaces continue through ordinary enforcement.
		if (mntns && mntns == *host_mntns)
			return 0;
	}
	struct exec_policy_entry *header = bpf_map_lookup_elem(&policy, &zero);
	if (!header)
		return -1;
	__u32 mode = header->mode;
	if (!mode)
		return 0;
	__u64 generation = header->generation;
	__u32 rule_count = header->count;
	bool deny = header->default_deny;
	struct exec_path_scratch *scratch =
		bpf_map_lookup_elem(&scratch_space, &zero);
	if (!scratch)
		return -1; // Cannot safely resolve possible enforced rule overrides.

	__builtin_memset(scratch->path, 0, PATH_SIZE);
	// Preserve verifier trust: do not copy the file pointer through probe reads.
	int length =
		bpf_path_d_path(&bprm->file->f_path, scratch->path, PATH_SIZE);
	struct evaluate_ctx evaluation = {
		.scratch = scratch,
		.count = rule_count,
		.policy_mode = mode,
		.error_mode = mode,
		.path_length = length,
	};
	long evaluated = bpf_loop(MAX_RULES, evaluate_rule, &evaluation, 0);
	if (length <= 0 || evaluated < 0 || evaluation.invalid ||
	    rule_count > MAX_RULES) {
		deny = true;
		// An unresolved path may match an enforced override even when the
		// policy default is audit. Never silently downgrade it to audit.
		mode = evaluation.error_mode;
		if (evaluated < 0 || evaluation.invalid ||
		    rule_count > MAX_RULES)
			mode = 2;
		count(4);
	} else if (evaluation.deny_mode) {
		deny = true;
		mode = evaluation.deny_mode;
	} else if (evaluation.allow_match) {
		deny = false;
	}
	count(deny ? 0 : 3);
	bool reporting = report_allowed();
	struct event *event =
		reporting ? bpf_ringbuf_reserve(&events, sizeof(*event), 0) : 0;
	if (event) {
		event->generation = generation;
		event->cgroup = cgroup;
		event->deny = deny;
		event->mode = mode;
		event->path_result = length;
		event->host_pid = bpf_get_current_pid_tgid() >> 32;
		// No stale path bytes on resolution failure.
		if (length > 0)
			__builtin_memcpy(event->path, scratch->path, PATH_SIZE);
		else
			__builtin_memset(event->path, 0, PATH_SIZE);
		bpf_ringbuf_submit(event, 0);
		count(1);
	} else {
		count(reporting ? 2 : 5);
	}
	// Keep explicit signed errno branches visible to the 6.12 verifier.
	volatile long result = 0;
	if (deny && mode == 2)
		result = -1;
	return result; // -EPERM or allow
}

char LICENSE[] SEC("license") = "GPL";
