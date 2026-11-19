// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Diagnostic only: actual recovered physical-admin admission for a signal-0
 * target. No TASK, route, role, policy or product authority is published. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "shared_recovery_kernel.h"

struct recovery_pidfd_request {
	__u64 node_cookie, admin_generation, target_cgroup;
	__u32 target_tgid, enabled;
};
struct recovery_pidfd_result {
	/* Test-only physical pointer; never expose this in a selected image. */
	__u64 physical, target_cgroup, admin_generation;
	__u32 target_tgid, observed;
};
struct recovery_alloc_observation {
	__u64 current, child, flags, guardian, candidate;
	__u32 prior, recovery_phase;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 32);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct recovery_alloc_observation);
} recovery_alloc_observation SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u32);
} recovery_alloc_count SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct recovery_pidfd_request);
} recovery_pidfd_request SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u32);
} recovery_pidfd_consumed SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct recovery_pidfd_result);
} recovery_pidfd_result SEC(".maps");

SEC("lsm/task_alloc")
long BPF_PROG(recovery_pidfd_task_alloc, struct task_struct *child,
	      unsigned long clone_flags, int prior)
{
	__s64 previous = (__s64)ctx[2];
	if (previous < 0)
		return previous;
	if (previous)
		return -1;
	__u32 zero = 0;
	struct rm_control *control = bpf_map_lookup_elem(&se_rm_control, &zero);
	__u64 current = bpf_get_current_task();
	struct recovery_alloc_observation *observation = 0;
	__u32 *count = bpf_map_lookup_elem(&recovery_alloc_count, &zero);
	if (count) {
		__u32 index = __sync_fetch_and_add(count, 1) & 31;
		observation = bpf_map_lookup_elem(&recovery_alloc_observation,
						  &index);
	}
	if (observation) {
		observation->current = current;
		observation->child = (__u64)child;
		observation->flags = clone_flags;
		observation->guardian = control ? control->guardian_task : 0;
		observation->prior = prior;
		observation->recovery_phase =
			control ? control->recovery_phase : 0;
	}
	volatile int result = se_rm_capture(child, clone_flags, 0);
	/* The only nonzero transition result is intentional -EPERM; keep the
	 * verifier's LSM return range explicit on kernels with stricter scalar
	 * tracking instead of widening an unconstrained helper return. */
	return result ? -1 : 0;
}
SEC("lsm/task_free")
int BPF_PROG(recovery_pidfd_task_free, struct task_struct *dying)
{
	se_rm_close(dying);
	return 0;
}
SEC("lsm/task_kill")
int BPF_PROG(recovery_pidfd_task_kill, struct task_struct *target,
	     struct kernel_siginfo *info, int signal, const struct cred *cred,
	     int prior)
{
	(void)info;
	(void)cred;
	if (prior || signal || !target)
		return prior;
	__u32 zero = 0;
	const struct recovery_pidfd_request *request =
		bpf_map_lookup_elem(&recovery_pidfd_request, &zero);
	__u32 *consumed = bpf_map_lookup_elem(&recovery_pidfd_consumed, &zero);
	struct recovery_pidfd_result *result =
		bpf_map_lookup_elem(&recovery_pidfd_result, &zero);
	if (!request || !consumed || !result || request->enabled != 1 ||
	    !request->node_cookie || !request->admin_generation ||
	    !request->target_cgroup || !request->target_tgid ||
	    !se_rm_reap_authorized(request->node_cookie,
				   request->admin_generation))
		return 0;
	__u32 tid = 0, tgid = 0;
	__u64 cgroup = 0;
	if (BPF_CORE_READ_INTO(&tid, target, pid) ||
	    BPF_CORE_READ_INTO(&tgid, target, tgid) ||
	    BPF_CORE_READ_INTO(&cgroup, target, cgroups, dfl_cgrp, kn, id) ||
	    tid != tgid || tgid != request->target_tgid ||
	    cgroup != request->target_cgroup)
		return 0;
	if (__sync_val_compare_and_swap(consumed, 0, 1) != 0)
		return 0;
	result->physical = (__u64)target;
	result->target_cgroup = cgroup;
	result->admin_generation = request->admin_generation;
	result->target_tgid = tgid;
	result->observed = 1;
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
