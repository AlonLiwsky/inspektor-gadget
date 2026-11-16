// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Load-only verifier probe. Never attach: the HASH has no lifecycle protocol.
 * It tests opaque typed task-key bytes, preallocated HASH storage and scalar
 * value cmpxchg. It does not implement safe publication or deletion. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__uint(map_flags, BPF_F_WRONLY);
	__type(key, __u64);
	__type(value, __u64);
} opaque_task_keys SEC(".maps");

SEC("lsm/task_alloc")
int BPF_PROG(opaque_task_key_alloc_probe, struct task_struct *child,
	     unsigned long clone_flags, int prior)
{
	(void)clone_flags;
	if (prior)
		return prior;
	__u64 zero = 0;
	/* &child is eight opaque bytes. Do not dereference or cast to an integer. */
	if (bpf_map_update_elem(&opaque_task_keys, &child, &zero, BPF_NOEXIST))
		return prior;
	__u64 *value = bpf_map_lookup_elem(&opaque_task_keys, &child);
	if (value)
		__sync_val_compare_and_swap(value, 0, 1);
	return prior;
}

SEC("lsm/task_free")
int BPF_PROG(opaque_task_key_free_probe, struct task_struct *dying)
{
	/* Only the scalar value is an atomic operand. This is not a product
	 * cleanup path: no hold/relookup or durable withdrawal receipt exists. */
	__u64 *value = bpf_map_lookup_elem(&opaque_task_keys, &dying);
	if (value && __sync_val_compare_and_swap(value, 1, 0) == 1)
		bpf_map_delete_elem(&opaque_task_keys, &dying);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
