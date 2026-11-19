// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Load-only test of helper-mediated copying of a typed task pointer's opaque
 * bytes into an ARRAY value. Never attach or expose this map as product state. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_WRONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_task_archive SEC(".maps");

SEC("lsm/task_alloc")
int BPF_PROG(opaque_task_archive_alloc_probe, struct task_struct *child,
	     unsigned long clone_flags, int prior)
{
	(void)clone_flags;
	if (prior)
		return prior;
	__u32 zero = 0;
	/* The helper copies eight bytes; BPF code never casts or hashes child. */
	bpf_map_update_elem(&opaque_task_archive, &zero, &child, BPF_ANY);
	return prior;
}

char LICENSE[] SEC("license") = "GPL";
