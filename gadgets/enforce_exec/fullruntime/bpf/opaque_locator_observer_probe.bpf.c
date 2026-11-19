// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Load-only verifier probe for the unselected opaque-key observer header.
 * It must never attach: there is no constructor, archive, charge or writer
 * protocol to make a successful observation authoritative. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE 1
#define SE_OL_TASKS 4
struct se_ol_meta;
static const __u64 *opaque_lookup(const void *key);
static struct se_ol_meta *meta_lookup(__u32 slot);
#define SE_OL_LOOKUP(key) opaque_lookup(key)
#define SE_OL_META_LOOKUP(slot) meta_lookup(slot)
#include "shared_pool_opaque_lookup_candidate.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4);
	__uint(map_flags, BPF_F_WRONLY);
	__type(key, __u64);
	__type(value, __u64);
} opaque_task_keys SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_OL_TASKS);
	__uint(map_flags, BPF_F_WRONLY);
	__type(key, __u32);
	__type(value, struct se_ol_meta);
} opaque_task_meta SEC(".maps");

static const __u64 *opaque_lookup(const void *key)
{
	return bpf_map_lookup_elem(&opaque_task_keys, key);
}
static struct se_ol_meta *meta_lookup(__u32 slot)
{
	return bpf_map_lookup_elem(&opaque_task_meta, &slot);
}
static int observe_only(const void *opaque_key)
{
	struct se_ol_observation observation = {};
	struct se_ol_lease lease = {};
	if (se_ol_observe(opaque_key, &observation) != SE_OL_OK)
		return 0;
	if (se_ol_read_observation(&observation) != SE_OL_OK)
		return 0;
	if (se_ol_hold_observation(&observation) != SE_OL_OK)
		return 0;
	if (se_ol_relookup_convert(&observation, &lease) == SE_OL_OK)
		se_ol_release_lease(&lease);
	return 0;
}

SEC("lsm/task_alloc")
int BPF_PROG(opaque_locator_observer_alloc_probe, struct task_struct *child,
	     unsigned long clone_flags, int prior)
{
	(void)clone_flags;
	if (!prior)
		observe_only(&child);
	return prior;
}

SEC("lsm/task_free")
int BPF_PROG(opaque_locator_observer_free_probe, struct task_struct *dying)
{
	observe_only(&dying);
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
