// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Observation-only exact-pidfd target primitive; no TASK or role authority. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct opaque_pidfd_witness_request {
	__u64 target_cgroup;
	__u32 target_tid, sender_tid;
};
struct opaque_pidfd_witness_result {
	__u64 physical, target_cgroup;
	__u32 target_tid, target_tgid, sender_tid, observed;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_pidfd_witness_request);
} opaque_pidfd_witness_request SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct opaque_pidfd_witness_result);
} opaque_pidfd_witness_result SEC(".maps");

SEC("lsm/task_kill")
int BPF_PROG(opaque_pidfd_task_kill_witness, struct task_struct *target,
	     struct kernel_siginfo *info, int signal, const struct cred *cred,
	     int prior)
{
	(void)info;
	(void)cred;
	if (prior || signal != 0 || !target)
		return prior;
	__u32 zero = 0;
	const struct opaque_pidfd_witness_request *request =
		bpf_map_lookup_elem(&opaque_pidfd_witness_request, &zero);
	struct opaque_pidfd_witness_result *result =
		bpf_map_lookup_elem(&opaque_pidfd_witness_result, &zero);
	if (!request || !result || !request->target_cgroup ||
	    !request->target_tid || !request->sender_tid)
		return 0;
	__u32 sender = (__u32)bpf_get_current_pid_tgid();
	if (sender != request->sender_tid)
		return 0;
	__u32 tid = 0, tgid = 0;
	__u64 cgroup = 0;
	if (BPF_CORE_READ_INTO(&tid, target, pid) ||
	    BPF_CORE_READ_INTO(&tgid, target, tgid) ||
	    BPF_CORE_READ_INTO(&cgroup, target, cgroups, dfl_cgrp, kn, id) ||
	    tid != request->target_tid || cgroup != request->target_cgroup)
		return 0;
	result->physical = (__u64)target;
	result->target_cgroup = cgroup;
	result->target_tid = tid;
	result->target_tgid = tgid;
	result->sender_tid = sender;
	result->observed++;
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
