// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Opt-in evidence-only probe. It grants no TASK eligibility or policy role. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

struct birth_identity_observation {
	__u32 parent_tgid, hits;
	__u64 parent, child, current;
	__u32 child_pid, reserved;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct birth_identity_observation);
} birth_identity_observation SEC(".maps");

SEC("raw_tp/sched_process_fork")
int observe_successful_fork(struct bpf_raw_tracepoint_args *ctx)
{
	__u32 zero = 0;
	struct birth_identity_observation *o =
		bpf_map_lookup_elem(&birth_identity_observation, &zero);
	if (!o || o->parent_tgid != bpf_get_current_pid_tgid() >> 32)
		return 0;
	struct task_struct *parent = (void *)ctx->args[0];
	struct task_struct *child = (void *)ctx->args[1];
	if (!parent || !child)
		return 0;
	o->parent = (__u64)parent;
	o->child = (__u64)child;
	o->current = (__u64)bpf_get_current_task_btf();
	o->child_pid = BPF_CORE_READ(child, pid);
	o->hits++;
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
