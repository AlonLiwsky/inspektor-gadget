// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Disposable observation only. No policy, receipt, or cleanup authority. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct primitive_gate {
	__u64 cgroup;
	__u32 tgid, return_bits;
};
struct primitive_witness {
	struct bpf_spin_lock lock;
	__u32 reserved;
	__u64 calls, physical, pid_tgid;
	__s64 result;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct primitive_gate);
} fexit_primitive_gate SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct primitive_witness);
} fexit_primitive_witness SEC(".maps");

/* The loader selects an explicit BTF FUNC and validates its signed return
 * width. No argument layout or compiled-clone signature is assumed. */
SEC("fexit/bprm_execve")
int opaque_fexit_failure_primitive(__u64 *ctx)
{
	__u32 zero = 0;
	const struct primitive_gate *gate =
		bpf_map_lookup_elem(&fexit_primitive_gate, &zero);
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (!gate || !gate->cgroup || !gate->tgid ||
	    bpf_get_current_cgroup_id() != gate->cgroup ||
	    (pid_tgid >> 32) != gate->tgid ||
	    (gate->return_bits != 32 && gate->return_bits != 64))
		return 0;
	__u64 raw = 0;
	if (bpf_get_func_ret(ctx, &raw))
		return 0;
	__s64 result = gate->return_bits == 32 ? (__s64)(__s32)raw : (__s64)raw;
	__u64 physical = (__u64)bpf_get_current_task_btf();
	struct primitive_witness *witness =
		bpf_map_lookup_elem(&fexit_primitive_witness, &zero);
	if (!witness)
		return 0;
	bpf_spin_lock(&witness->lock);
	witness->calls++;
	witness->physical = physical;
	witness->pid_tgid = pid_tgid;
	witness->result = result;
	bpf_spin_unlock(&witness->lock);
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
