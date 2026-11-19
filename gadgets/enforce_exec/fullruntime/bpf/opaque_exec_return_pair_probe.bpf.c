// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Isolated feasibility probe only. No policy decision or product receipt.
 * A kretprobe has no bprm argument; its corresponding entry must retain it.
 * A separate LSM observation registers a BPF-only test receipt between entry
 * and return, so a failed return can be matched to that exact bprm. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct pair_gate {
	__u64 cgroup;
	__u32 armed;
	__u32 reserved;
};
struct pair_entry {
	__u64 bprm;
	__u64 physical;
	__u32 depth;
	__u32 uncertain;
};
struct pair_outer_entry {
	__u64 physical;
	__u64 bprm;
	__u32 depth;
	__u32 uncertain;
};
struct pair_observation {
	__u64 entries;
	__u64 returns;
	__u64 failed;
	__u64 paired;
	__u64 missing;
	__u64 nested;
	__u64 last_bprm;
	__s64 last_return;
	__u64 registered;
	__u64 finalized;
};
struct pair_receipt {
	__u64 physical;
	__u64 bprm;
	__u32 phase;
	__u32 reserved;
};
struct pair_final_observation {
	__u64 execve_returns;
	__s64 execve_return;
	__u64 execveat_returns;
	__s64 execveat_return;
	__u64 common_returns;
	__s64 common_return;
	__u64 outer_entries;
	__u64 outer_missing;
};
#define PAIR_REGISTERED 1U
#define PAIR_SUCCESS 2U
#define PAIR_FAILED 3U
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct pair_gate);
} opaque_return_pair_gate SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct pair_entry);
} opaque_return_pair_entries SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct pair_outer_entry);
} opaque_return_pair_outer_entries SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct pair_observation);
} opaque_return_pair_observations SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__uint(map_flags, BPF_F_NO_PREALLOC | BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct pair_receipt);
} opaque_return_pair_receipts SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct pair_final_observation);
} opaque_return_pair_final_observation SEC(".maps");

/* The exact-build common entry is a lexical outer invocation marker. A
 * handler's negative return alone is not a final outcome. */
SEC("kprobe/do_execveat_common.isra.38")
int BPF_KPROBE(opaque_return_pair_common_enter)
{
	__u32 zero = 0;
	const struct pair_gate *gate =
		bpf_map_lookup_elem(&opaque_return_pair_gate, &zero);
	if (!gate || gate->armed != 1 || !gate->cgroup ||
	    gate->cgroup != bpf_get_current_cgroup_id())
		return 0;
	struct pair_final_observation *obs = bpf_map_lookup_elem(
		&opaque_return_pair_final_observation, &zero);
	if (obs)
		__sync_fetch_and_add(&obs->outer_entries, 1);
	__u64 key = bpf_get_current_pid_tgid();
	struct pair_outer_entry *existing =
		bpf_map_lookup_elem(&opaque_return_pair_outer_entries, &key);
	if (existing) {
		existing->uncertain = 1;
		if (existing->depth < 255)
			existing->depth++;
		return 0;
	}
	struct pair_outer_entry frame = {
		.physical = (__u64)bpf_get_current_task_btf(),
		.depth = 1,
	};
	if (!frame.physical ||
	    bpf_map_update_elem(&opaque_return_pair_outer_entries, &key, &frame,
				BPF_NOEXIST)) {
		if (obs)
			__sync_fetch_and_add(&obs->outer_missing, 1);
	}
	return 0;
}

/* Wrapper probes remain observation only. This exact kernel's user exec
 * path bypasses them; keep that negative result visible in the fixture. */
SEC("kretprobe/do_execve")
int BPF_KRETPROBE(opaque_return_pair_execve_final, int ret)
{
	__u32 zero = 0;
	const struct pair_gate *gate =
		bpf_map_lookup_elem(&opaque_return_pair_gate, &zero);
	if (!gate || gate->armed != 1 || !gate->cgroup ||
	    gate->cgroup != bpf_get_current_cgroup_id())
		return 0;
	struct pair_final_observation *obs = bpf_map_lookup_elem(
		&opaque_return_pair_final_observation, &zero);
	if (obs) {
		__sync_fetch_and_add(&obs->execve_returns, 1);
		obs->execve_return = ret;
	}
	return 0;
}
SEC("kretprobe/do_execveat")
int BPF_KRETPROBE(opaque_return_pair_execveat_final, int ret)
{
	__u32 zero = 0;
	const struct pair_gate *gate =
		bpf_map_lookup_elem(&opaque_return_pair_gate, &zero);
	if (!gate || gate->armed != 1 || !gate->cgroup ||
	    gate->cgroup != bpf_get_current_cgroup_id())
		return 0;
	struct pair_final_observation *obs = bpf_map_lookup_elem(
		&opaque_return_pair_final_observation, &zero);
	if (obs) {
		__sync_fetch_and_add(&obs->execveat_returns, 1);
		obs->execveat_return = ret;
	}
	return 0;
}
/* This symbol is specific to the tested stock Rocky build. It is not a
 * portable attach target or an authorization contract. */
SEC("kretprobe/do_execveat_common.isra.38")
int BPF_KRETPROBE(opaque_return_pair_common_final, int ret)
{
	__u32 zero = 0;
	const struct pair_gate *gate =
		bpf_map_lookup_elem(&opaque_return_pair_gate, &zero);
	if (!gate || gate->armed != 1 || !gate->cgroup ||
	    gate->cgroup != bpf_get_current_cgroup_id())
		return 0;
	struct pair_final_observation *obs = bpf_map_lookup_elem(
		&opaque_return_pair_final_observation, &zero);
	if (obs) {
		__sync_fetch_and_add(&obs->common_returns, 1);
		obs->common_return = ret;
	}
	__u64 key = bpf_get_current_pid_tgid();
	struct pair_outer_entry *frame =
		bpf_map_lookup_elem(&opaque_return_pair_outer_entries, &key);
	if (!frame)
		return 0;
	if (frame->depth > 1) {
		frame->depth--;
		return 0;
	}
	if (ret <= 0 && frame->depth == 1 && !frame->uncertain &&
	    frame->physical == (__u64)bpf_get_current_task_btf() &&
	    frame->bprm) {
		struct pair_receipt *receipt = bpf_map_lookup_elem(
			&opaque_return_pair_receipts, &frame->physical);
		if (receipt && receipt->physical == frame->physical &&
		    receipt->bprm == frame->bprm && !receipt->reserved &&
		    __sync_val_compare_and_swap(
			    &receipt->phase, PAIR_REGISTERED,
			    ret == 0 ? PAIR_SUCCESS : PAIR_FAILED) ==
			    PAIR_REGISTERED) {
			struct pair_observation *paired_obs =
				bpf_map_lookup_elem(
					&opaque_return_pair_observations,
					&zero);
			if (paired_obs)
				__sync_fetch_and_add(&paired_obs->finalized, 1);
		}
	}
	(void)bpf_map_delete_elem(&opaque_return_pair_outer_entries, &key);
	return 0;
}

SEC("kprobe/search_binary_handler")
int BPF_KPROBE(opaque_return_pair_enter, struct linux_binprm *bprm)
{
	__u32 zero = 0;
	const struct pair_gate *gate =
		bpf_map_lookup_elem(&opaque_return_pair_gate, &zero);
	if (!gate || gate->armed != 1 || !gate->cgroup ||
	    gate->cgroup != bpf_get_current_cgroup_id())
		return 0;
	struct pair_observation *obs =
		bpf_map_lookup_elem(&opaque_return_pair_observations, &zero);
	if (obs)
		__sync_fetch_and_add(&obs->entries, 1);
	__u64 key = bpf_get_current_pid_tgid();
	struct pair_entry *existing =
		bpf_map_lookup_elem(&opaque_return_pair_entries, &key);
	if (existing) {
		/* A nested or stale entry cannot authenticate an outer return.
		 * Keep the first pointer for diagnostic comparison only. */
		existing->uncertain = 1;
		if (existing->depth < 255)
			existing->depth++;
		if (obs)
			__sync_fetch_and_add(&obs->nested, 1);
		return 0;
	}
	struct pair_entry entry = {
		.bprm = (__u64)bprm,
		.physical = (__u64)bpf_get_current_task_btf(),
		.depth = 1,
	};
	if (!entry.bprm || !entry.physical ||
	    bpf_map_update_elem(&opaque_return_pair_entries, &key, &entry,
				BPF_NOEXIST)) {
		if (obs)
			__sync_fetch_and_add(&obs->missing, 1);
	}
	return 0;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_return_pair_register, struct linux_binprm *bprm, int prior)
{
	if (prior)
		return prior;
	__u32 zero = 0;
	const struct pair_gate *gate =
		bpf_map_lookup_elem(&opaque_return_pair_gate, &zero);
	if (!gate || gate->armed != 1 || !gate->cgroup ||
	    gate->cgroup != bpf_get_current_cgroup_id())
		return 0;
	__u64 key = bpf_get_current_pid_tgid();
	struct pair_entry *entry =
		bpf_map_lookup_elem(&opaque_return_pair_entries, &key);
	struct pair_outer_entry *outer =
		bpf_map_lookup_elem(&opaque_return_pair_outer_entries, &key);
	__u64 physical = (__u64)bpf_get_current_task_btf();
	if (!entry || entry->uncertain || entry->depth != 1 ||
	    entry->physical != physical || entry->bprm != (__u64)bprm ||
	    !outer || outer->uncertain || outer->depth != 1 ||
	    outer->physical != physical || outer->bprm)
		return 0;
	struct pair_receipt receipt = {
		.physical = physical,
		.bprm = (__u64)bprm,
		.phase = PAIR_REGISTERED,
	};
	if (!bpf_map_update_elem(&opaque_return_pair_receipts, &physical,
				 &receipt, BPF_NOEXIST)) {
		outer->bprm = (__u64)bprm;
		struct pair_observation *obs = bpf_map_lookup_elem(
			&opaque_return_pair_observations, &zero);
		if (obs)
			__sync_fetch_and_add(&obs->registered, 1);
	}
	return 0;
}

SEC("kretprobe/search_binary_handler")
int BPF_KRETPROBE(opaque_return_pair_exit, int ret)
{
	__u64 key = bpf_get_current_pid_tgid();
	struct pair_entry *entry =
		bpf_map_lookup_elem(&opaque_return_pair_entries, &key);
	if (!entry)
		return 0;
	__u32 zero = 0;
	struct pair_observation *obs =
		bpf_map_lookup_elem(&opaque_return_pair_observations, &zero);
	if (obs) {
		__sync_fetch_and_add(&obs->returns, 1);
		if (ret < 0)
			__sync_fetch_and_add(&obs->failed, 1);
	}
	if (entry->depth > 1) {
		entry->depth--;
		return 0;
	}
	if (entry->depth == 1 && !entry->uncertain &&
	    entry->physical == (__u64)bpf_get_current_task_btf() &&
	    entry->bprm && ret < 0) {
		struct pair_receipt *receipt = bpf_map_lookup_elem(
			&opaque_return_pair_receipts, &entry->physical);
		if (receipt && receipt->physical == entry->physical &&
		    receipt->bprm == entry->bprm && !receipt->reserved &&
		    receipt->phase == PAIR_REGISTERED && obs) {
			__sync_fetch_and_add(&obs->paired, 1);
			obs->last_bprm = entry->bprm;
			obs->last_return = ret;
		}
	}
	(void)bpf_map_delete_elem(&opaque_return_pair_entries, &key);
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
