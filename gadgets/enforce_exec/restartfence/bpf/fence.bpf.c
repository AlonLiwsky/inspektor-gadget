/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "fence.h"

#define EPERM 1L
#define FENCE_RETIRED (~(__u64)0)
#define FENCE_READ(x) (*(volatile typeof(x) *)&(x))
/* Each helper call respects Linux's BPF_MAX_LOOPS. Together the chunks
 * cover every nonnegative signed-int cgroup level, not a policy depth cap.
 */
#define FENCE_LEVELS_PER_CHUNK (1U << 23)
#define FENCE_LEVEL_CHUNKS (1U << 8)

/* live == 0 is always fenced, including an unassigned binding (owner == 0). */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} fence_state SEC(".maps");

/* Replace as a hash element, so a reader never sees a partially written identity. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fence_identity);
} fence_owner SEC(".maps");

/* Hash replacement publishes a complete challenge in one step. An ARRAY
 * value is copied in place, so a reader could observe a new incarnation
 * paired with old nonce words during userspace's update.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fence_challenge);
} fence_nonce SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, FENCE_MAX_PODS);
	__type(key, __u64);
	__type(value, struct fence_binding);
} fence_cgroups SEC(".maps");

/* Userspace provisions totals before publishing a binding; no LRU eviction.
 * Key zero is reserved for infrastructure faults or lost per-pod accounting.
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_HASH);
	__uint(max_entries, FENCE_MAX_PODS + 1);
	__type(key, __u64);
	__type(value, struct fence_totals);
} fence_counts SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 20);
} fence_events SEC(".maps");

static __always_inline bool read_start(struct task_struct *task, __u64 *start)
{
	return !BPF_CORE_READ_INTO(start, task, group_leader, start_boottime) &&
	       *start;
}

static __always_inline void arm_owner(struct task_struct *task, bool exiting)
{
	__u32 zero = 0;
	__u64 *state = bpf_map_lookup_elem(&fence_state, &zero);
	if (!state)
		return;

	__u64 incarnation = FENCE_READ(*state);
	if (!incarnation || incarnation == FENCE_RETIRED)
		return;

	struct fence_identity *owner = bpf_map_lookup_elem(&fence_owner, &zero);
	if (!owner || owner->incarnation != incarnation) {
		/* Inconsistent owner state cannot justify leaving protection off. */
		__sync_val_compare_and_swap(state, incarnation, 0);
		return;
	}

	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	if (tgid != owner->tgid)
		return;
	int task_tgid;
	if (!BPF_CORE_READ_INTO(&task_tgid, task, tgid) &&
	    (__u32)task_tgid != owner->tgid)
		return;

	__u64 start = 0;
	if (read_start(task, &start) && start != owner->start_boottime)
		return;

	/* These tracepoints run in the indicated task. A failed read of the
	 * authenticated TGID is treated conservatively, not as proof it is live.
	 */
	int remaining;
	if (exiting &&
	    !BPF_CORE_READ_INTO(&remaining, task, signal, live.counter) &&
	    remaining > 0)
		return;

	/* A delayed callback from a previous owner must not clear its successor. */
	__sync_val_compare_and_swap(state, incarnation, 0);
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(fence_exit, struct task_struct *task)
{
#ifndef FENCE_TEST_NO_EXIT_ARM
	arm_owner(task, true);
#endif
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(fence_selfexec, struct task_struct *task)
{
	arm_owner(task, false);
	return 0;
}

SEC("tp_btf/sys_enter")
int BPF_PROG(fence_reg, struct pt_regs *regs, long syscall)
{
	if (syscall != FENCE_NR_PRCTL ||
	    PT_REGS_PARM1_CORE(regs) != FENCE_PRCTL)
		return 0;

#ifndef FENCE_TEST_NO_NONCE
	__u64 lo = PT_REGS_PARM2_CORE(regs);
	__u64 hi = PT_REGS_PARM3_CORE(regs);
#endif
#ifdef __TARGET_ARCH_x86
	/* The fourth x86-64 syscall argument is in r10, not the C ABI's cx. */
	__u64 incarnation = BPF_CORE_READ(regs, r10);
#else
	__u64 incarnation = PT_REGS_PARM4_CORE(regs);
#endif
	if (!incarnation || incarnation == FENCE_RETIRED ||
	    PT_REGS_PARM5_CORE(regs))
		return 0;

	__u32 zero = 0;
	__u64 *live = bpf_map_lookup_elem(&fence_state, &zero);
	struct fence_challenge *challenge =
		bpf_map_lookup_elem(&fence_nonce, &zero);
	if (!live || !challenge || FENCE_READ(*live))
		return 0;

#ifndef FENCE_TEST_NO_NONCE
	if (!(lo | hi) || FENCE_READ(challenge->incarnation) != incarnation ||
	    FENCE_READ(challenge->lo) != lo || FENCE_READ(challenge->hi) != hi)
		return 0;
#endif

	struct fence_identity next = {
		.incarnation = incarnation,
		.tgid = bpf_get_current_pid_tgid() >> 32,
	};
	if (!next.tgid ||
	    !read_start(bpf_get_current_task_btf(), &next.start_boottime))
		return 0;

	struct fence_identity *previous =
		bpf_map_lookup_elem(&fence_owner, &zero);
	if (previous && (incarnation <= previous->incarnation ||
			 (next.tgid == previous->tgid &&
			  next.start_boottime == previous->start_boottime)))
		return 0;

#ifndef FENCE_TEST_NO_NONCE
	/* Only one invocation may consume this challenge and publish an owner. */
	if (__sync_val_compare_and_swap(&challenge->incarnation, incarnation,
					0) != incarnation)
		return 0;
#endif
	challenge->lo = 0;
	challenge->hi = 0;
	if (!bpf_map_update_elem(&fence_owner, &zero, &next, BPF_ANY))
		__sync_val_compare_and_swap(live, 0, incarnation);
	/* The tracepoint does not change prctl behavior. Userspace attests
	 * the postcondition in the maps, not the syscall return.
	 */
	return 0;
}

static __always_inline struct fence_totals *infra_counts(void)
{
	__u64 key = 0;
	return bpf_map_lookup_elem(&fence_counts, &key);
}

static __always_inline long lookup_fault(void)
{
	struct fence_totals *counts = infra_counts();
	if (counts)
		__sync_fetch_and_add(&counts->denied, 1);
	return -EPERM;
}

static __always_inline void account(__u64 cgid, __u64 pod_uid_hash, __u32 mode)
{
	struct fence_totals *totals = bpf_map_lookup_elem(&fence_counts, &cgid);
	if (!totals) {
		totals = infra_counts();
		if (totals)
			__sync_fetch_and_add(&totals->lost, 1);
	}
	if (totals) {
		if (mode == FENCE_AUDIT)
			__sync_fetch_and_add(&totals->audit, 1);
		else
			__sync_fetch_and_add(&totals->denied, 1);
	}

	struct fence_event event = {
		.ktime = bpf_ktime_get_ns(),
		.cgroup_id = cgid,
		.pod_uid_hash = pod_uid_hash,
		.tgid = bpf_get_current_pid_tgid() >> 32,
		.mode = mode,
	};
	if (bpf_ringbuf_output(&fence_events, &event, sizeof(event), 0) &&
	    totals)
		__sync_fetch_and_add(&totals->lost, 1);
}

struct binding_walk {
	struct fence_binding *binding;
	__u64 leaf;
	__u64 cgid;
	__u32 first_level;
	__u8 complete;
	__u8 fault;
};

static long walk_bindings(__u32 offset, void *data)
{
	struct binding_walk *walk = data;
	if (offset >= FENCE_LEVELS_PER_CHUNK ||
	    walk->first_level > 0x7f800000U) {
		walk->fault = true;
		return 1;
	}
	__u32 level = walk->first_level + offset;
	__u64 id = bpf_get_current_ancestor_cgroup_id(level);
	if (!id) {
		walk->fault = true;
		return 1;
	}
	struct fence_binding *candidate =
		bpf_map_lookup_elem(&fence_cgroups, &id);
	if (candidate &&
	    ((candidate->strict_sections | candidate->audit_sections) &
	     FENCE_SECTION_EXEC)) {
		walk->binding = candidate;
		walk->cgid = id;
	}
	if (id == walk->leaf) {
		walk->complete = true;
		return 1;
	}
	return 0;
}

static long walk_binding_chunks(__u32 chunk, void *data)
{
	struct binding_walk *walk = data;
	if (chunk >= FENCE_LEVEL_CHUNKS) {
		walk->fault = true;
		return 1;
	}
	walk->first_level = chunk * FENCE_LEVELS_PER_CHUNK;
	long result = bpf_loop(FENCE_LEVELS_PER_CHUNK, walk_bindings, data, 0);
	if (result <= 0 || result > FENCE_LEVELS_PER_CHUNK)
		walk->fault = true;
	return walk->complete || walk->fault;
}

SEC("lsm/bprm_check_security")
long BPF_PROG(fence_exec, struct linux_binprm *bprm, int prior)
{
	/* Use the signed full slot, not a truncated 32-bit result: AL2023
	 * 6.12 otherwise loses the verifier's [-4095, 0] return bounds.
	 */
	__s64 ret = (__s64)ctx[1];
	/* Only explicit uninstall can retire this guard, even when other
	 * processes still hold descriptors for its pinned links.
	 */
	__u32 zero = 0;
	__u64 *state = bpf_map_lookup_elem(&fence_state, &zero);
	if (state && FENCE_READ(*state) == FENCE_RETIRED)
		return ret;

	/* Arm before CLOEXEC, including execs that never reach sched_process_exec. */
	arm_owner(bpf_get_current_task_btf(), false);
	if (ret)
		return ret;

	__u64 leaf = bpf_get_current_cgroup_id();
	if (!leaf)
		return lookup_fault();

	/* The helper's level is absolute (root is level 0). Keep the nearest
	 * binding, but don't mistake a partial ancestor walk for no binding.
	 */
	struct binding_walk walk = { .leaf = leaf };
	long walked =
		bpf_loop(FENCE_LEVEL_CHUNKS, walk_binding_chunks, &walk, 0);
	if (walked <= 0 || walked > FENCE_LEVEL_CHUNKS || walk.fault ||
	    !walk.complete)
		return lookup_fault();
	struct fence_binding *binding = walk.binding;
	__u64 cgid = walk.cgid;
	if (!binding)
		return 0;
	bool strict = (binding->strict_sections & FENCE_SECTION_EXEC) != 0;
	bool audit = (binding->audit_sections & FENCE_SECTION_EXEC) != 0;
	if (strict == audit || !binding->pod_uid_hash || binding->reserved)
		return lookup_fault();
	__u32 mode = audit ? FENCE_AUDIT : FENCE_STRICT;

	__u64 live = state ? FENCE_READ(*state) : 0;
	if (live == FENCE_RETIRED)
		return 0;
	struct fence_identity *owner = bpf_map_lookup_elem(&fence_owner, &zero);
	if (live && (binding->bound_sections & FENCE_SECTION_EXEC) &&
	    binding->owner == live && owner && owner->incarnation == live)
		return 0;

	account(cgid, binding->pod_uid_hash, mode);
	return mode == FENCE_AUDIT ? 0 : -EPERM;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
