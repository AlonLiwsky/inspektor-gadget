// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Kubescape Authors

// Kernel test of ../../../root_barrier.h: a task is covered when its own
// cgroup is in covered_cgroups (an exact, enforcing binding).

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16);
	__type(key, __u64);
	__type(value, __u32);
} covered_cgroups SEC(".maps");

static __always_inline bool covered(struct task_struct *task)
{
	__u64 cgroup = bpf_get_current_cgroup_id();

	return bpf_map_lookup_elem(&covered_cgroups, &cgroup) != NULL;
}

#define ROOT_BARRIER_COVERED(task) covered(task)
#include "../../../root_barrier.h"
