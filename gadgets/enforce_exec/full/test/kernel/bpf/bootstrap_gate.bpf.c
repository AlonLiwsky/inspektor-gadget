// SPDX-License-Identifier: GPL-2.0
// Hook/lifetime SPIKE ONLY: one scalar policy/role sample, not inventory or Ready.
// Source matrix: Linux 6b4b543fa18757297ac756a6fe6e64f506b7844a/kernel/fork.c:
// task_alloc precedes fallible copies; task_newtask follows publication and
// cgroup_post_fork, before runnable wakeup. create_io_thread calls copy_process
// directly, bypassing sched_process_fork. The latter is intentionally NOT used.
//
// This fixture proves selected admission/completion paths and late attachment;
// it does not implement A/B inventory, root-lineage authority, RootEpoch
// activation,16-slot production merging, arbitrary ingress or full failure
// injection coverage. Every seed is an explicit fixture PIDFD write.
// Rendezvous loops are bounded test instrumentation, not production waits.
// A timeout invalidates a race proof; it is never interpreted as success.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../../../../fullruntime/bpf/gate.h"
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
static long bg_wait(__u32, void *);
struct bg_seed {
	__u64 owner, uid, role, epoch;
};
struct bg_state {
	struct bpf_spin_lock lock;
	__u32 owned;
	struct bg_seed role;
	__u64 child, original_cgroup;
	__u32 slot, pad;
	__u64 token_owner;
};
struct bg_gate {
	__u64 word, faults, credits, admitted, success, failed, late, io, exits,
		completion_cgroup, owner;
};
struct bg_pause {
	__u64 cgroup;
	__u32 hold, phase, timedout, pad;
};
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct bg_seed);
} bg_seeds SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct bg_state);
} bg_states SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, __u64);
	__type(value, __u32);
} bg_bindings SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, struct bg_gate);
} bg_gates SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct bg_pause);
} bg_pauses SEC(".maps");

static __always_inline struct bg_state *bg_get(struct task_struct *task,
					       struct bg_gate *g)
{
	struct bg_state *s = bpf_task_storage_get(&bg_states, task, 0, 0);
	if (s)
		return s;
	int reserved = 0;
#pragma clang loop unroll(disable)
	for (int i = 0; i < 64; i++) {
		__u64 old = fg_read(&g->credits);
		if (old >= 4096)
			break;
		if (__sync_val_compare_and_swap(&g->credits, old, old + 1) ==
		    old) {
			reserved = 1;
			break;
		}
	}
	if (!reserved) {
		__sync_fetch_and_or(&g->faults, 1);
		return 0;
	}
	s = bpf_task_storage_get(&bg_states, task, 0,
				 BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!s)
		__sync_fetch_and_or(&g->faults, 2);
	return s;
}
/* Existing accepted scalar role is never reset by a changed seed. This fixture
 * handles one UID; production16-slot epoch-authorized merge is out of scope. */
static __always_inline void bg_merge(struct bg_state *s, struct bg_seed *seed)
{
	if (!seed)
		return;
	struct bg_seed copy = *seed;
	bpf_spin_lock(&s->lock);
	if (!s->role.uid)
		s->role = copy;
	bpf_spin_unlock(&s->lock);
}
SEC("lsm.s/task_alloc")
int BPF_PROG(bg_admit, struct task_struct *child, __u64 flags, int ret)
{
	if (ret)
		return ret;
	__u64 cg = bpf_get_current_cgroup_id();
	__u32 *slot = bpf_map_lookup_elem(&bg_bindings, &cg);
	if (!slot)
		return 0;
	__u32 index = *slot;
	struct bg_gate *g = bpf_map_lookup_elem(&bg_gates, &index);
	if (!g || !g->owner || g->faults)
		return -1;
	struct task_struct *parent = bpf_get_current_task_btf();
	struct bg_state *s = bg_get(parent, g);
	if (!s)
		return -1;
	struct bg_seed snapshot = {};
	bpf_rcu_read_lock();
	struct bg_seed *seed = bpf_task_storage_get(&bg_seeds, parent, 0, 0);
	if (seed)
		snapshot = *seed;
	bpf_rcu_read_unlock();
	bg_merge(s, &snapshot);
	if (s->owned) {
		__sync_fetch_and_or(&g->faults, 4);
		return -1;
	}
	if (fg_enter(&g->word))
		return -11;
	bpf_spin_lock(&s->lock);
	s->owned = 1;
	s->child = (__u64)child;
	s->original_cgroup = cg;
	s->slot = index;
	s->token_owner = g->owner;
	bpf_spin_unlock(&s->lock);
	__sync_fetch_and_add(&g->admitted, 1);
	/* Sleepable hook: no ordinary RCU read lock is held across this migration
  * rendezvous. A non-sleepable fexit hold would block percpu_down_write's
  * RCU synchronization in cgroup.procs and force its own timeout. */
	__u32 zero = 0;
	struct bg_pause *pause = bpf_map_lookup_elem(&bg_pauses, &zero);
	if (pause && pause->pad == 1 && pause->cgroup == cg && pause->hold) {
		*(volatile __u32 *)&pause->phase = 1;
		bpf_loop(1U << 22, bg_wait, 0, 0);
		if (*(volatile __u32 *)&pause->hold)
			pause->timedout = 1;
	}
	return 0;
}
static long bg_wait(__u32 i, void *unused)
{
	__u32 zero = 0;
	struct bg_pause *p = bpf_map_lookup_elem(&bg_pauses, &zero);
	return !p || !*(volatile __u32 *)&p->hold;
}
/* Hold AFTER the security allocation hook has completed: late installation
 * therefore cannot retroactively count this task allocation. Bounded only. */
SEC("fexit/security_task_alloc")
int BPF_PROG(bg_hold, struct task_struct *child, __u64 flags, int ret)
{
	__u32 zero = 0;
	struct bg_pause *p = bpf_map_lookup_elem(&bg_pauses, &zero);
	if (ret || !p || p->pad == 1 ||
	    p->cgroup != bpf_get_current_cgroup_id() || !p->hold)
		return 0;
	*(volatile __u32 *)&p->phase = 1;
	bpf_loop(1U << 22, bg_wait, 0, 0);
	if (*(volatile __u32 *)&p->hold)
		p->timedout = 1;
	return 0;
}
static __always_inline int bg_finish(struct task_struct *parent,
				     struct task_struct *child, int failed,
				     int exiting)
{
	struct bg_state *p = bpf_task_storage_get(&bg_states, parent, 0, 0);
	__u64 cg = bpf_get_current_cgroup_id();
	__u32 index = 0;
	int owned = p && p->owned;
	if (owned)
		index = p->slot;
	else {
		__u32 *slot = bpf_map_lookup_elem(&bg_bindings, &cg);
		if (!slot)
			return 0;
		index = *slot;
	}
	struct bg_gate *g = bpf_map_lookup_elem(&bg_gates, &index);
	if (!g)
		return 0;
	if (owned && p->token_owner != g->owner) {
		__sync_fetch_and_or(&g->faults, 32);
		return 0;
	}
	if (!p && !failed)
		p = bg_get(parent, g);
	if (!p)
		return 0;
	if (!failed) {
		struct bg_seed *seed =
			bpf_task_storage_get(&bg_seeds, parent, 0, 0);
		bg_merge(p, seed);
		struct bg_seed snapshot = {};
		bpf_spin_lock(&p->lock);
		snapshot = p->role;
		bpf_spin_unlock(&p->lock);
		struct bg_state *c = bg_get(child, g);
		if (!c)
			__sync_fetch_and_or(&g->faults, 8);
		else
			bg_merge(c, &snapshot);
	}
	__u32 claimed = 0;
	bpf_spin_lock(&p->lock);
	if (p->owned && (failed || p->child == (__u64)child)) {
		p->owned = 0;
		p->child = 0;
		claimed = 1;
	}
	bpf_spin_unlock(&p->lock);
	if (claimed) {
		if (failed)
			__sync_fetch_and_add(&g->failed, 1);
		else
			__sync_fetch_and_add(&g->success, 1);
		if (exiting)
			__sync_fetch_and_add(&g->exits, 1);
		g->completion_cgroup = cg;
	} else if (!failed)
		__sync_fetch_and_add(&g->late, 1);
	fg_leave_owned(&g->word, claimed, &g->faults);
	return 0;
}
SEC("tp_btf/task_newtask")
int BPF_PROG(bg_newtask, struct task_struct *child, __u64 clone_flags)
{
	return bg_finish(bpf_get_current_task_btf(), child, 0, 0);
}
/* Exact pinned prototype: copy_process(pid*, trace, node, args*) -> task*. */
SEC("fexit/copy_process")
int BPF_PROG(bg_copy_done, struct pid *pid, int trace, int node,
	     struct kernel_clone_args *args, struct task_struct *result)
{
	if ((__u64)result >= ~4094ULL)
		return bg_finish(bpf_get_current_task_btf(), 0, 1, 0);
	return 0;
}
SEC("tp_btf/sched_process_exit")
int BPF_PROG(bg_exit, struct task_struct *task)
{
	return bg_finish(task, 0, 1, 1);
}
SEC("fexit/create_io_thread")
int BPF_PROG(bg_io_done, void *fn, void *arg, int node,
	     struct task_struct *child)
{
	if (!child || (__u64)child >= ~4094ULL)
		return 0;
	struct bg_state *p = bpf_task_storage_get(
		&bg_states, bpf_get_current_task_btf(), 0, 0);
	if (!p)
		return 0;
	__u32 index = p->slot;
	struct bg_gate *g = bpf_map_lookup_elem(&bg_gates, &index);
	if (!g)
		return 0;
	struct bg_state *c = bpf_task_storage_get(&bg_states, child, 0, 0);
	if (!c || !c->role.uid || c->owned)
		__sync_fetch_and_or(&g->faults, 16);
	else
		__sync_fetch_and_add(&g->io, 1);
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
