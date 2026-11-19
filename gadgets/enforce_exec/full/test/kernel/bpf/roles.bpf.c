// SPDX-License-Identifier: GPL-2.0
// Isolated role lifecycle spike, not the production policy owner.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "../../../roles.h"
#include "../../../transaction.h"
#include "../../../../fullruntime/bpf/gate.h"
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
struct fr_task_state {
	struct bpf_spin_lock lock;
	__u32 initialized;
	struct fr_entry entries[FR_SLOTS];
	struct fr_transaction tx;
	__u64 commits, failures, inherited, identity;
};
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct fr_task_state);
} roles SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct fr_seed);
} seeds SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct fr_merge_work);
} merge_work SEC(".maps");
struct fr_config {
	__u64 cgroup, uid, actor, grant, inode, interpreter, generation;
	__u32 limit, audit, deny, conflict;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fr_config);
} configuration SEC(".maps");
struct fr_totals {
	__u64 credits, faults, gate, commits, failures, exits, forks;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fr_totals);
} totals SEC(".maps");
static __always_inline struct fr_task_state *
get_state(struct task_struct *task, struct fr_totals *t, __u32 limit)
{
	struct fr_task_state *s = bpf_task_storage_get(&roles, task, 0, 0);
	if (s)
		return s;
	if (!limit || limit > 4096)
		return 0;
	int claimed = 0;
#pragma clang loop unroll(disable)
	for (int i = 0; i < 64; i++) {
		__u64 old = fg_read(&t->credits);
		if (old >= limit)
			return 0;
		if (__sync_val_compare_and_swap(&t->credits, old, old + 1) ==
		    old) {
			claimed = 1;
			break;
		}
	}
	if (!claimed)
		return 0;
	return bpf_task_storage_get(&roles, task, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
}
static __always_inline int merge_seed(struct task_struct *task,
				      struct fr_task_state *s)
{
	struct fr_merge_work *w = bpf_task_storage_get(
		&merge_work, task, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!w)
		return -1;
	bpf_rcu_read_lock();
	struct fr_seed *seed = bpf_task_storage_get(&seeds, task, 0, 0);
	w->seed.revision = seed ? seed->revision : 0;
#pragma clang loop unroll(full)
	for (int i = 0; i < FR_SLOTS; i++) {
		w->seed.entries[i].uid = seed ? seed->entries[i].uid : 0;
		w->seed.entries[i].roles = seed ? seed->entries[i].roles : 0;
	}
	bpf_rcu_read_unlock();
	bpf_spin_lock(&s->lock);
#pragma clang loop unroll(full)
	for (int i = 0; i < FR_SLOTS; i++)
		w->entries[i] = s->entries[i];
	bpf_spin_unlock(&s->lock);
	if (fr_merge(w))
		return -1;
	bpf_spin_lock(&s->lock);
#pragma clang loop unroll(full)
	for (int i = 0; i < FR_SLOTS; i++)
		s->entries[i] = w->entries[i];
	s->initialized = 1;
	s->identity = (__u64)task;
	bpf_spin_unlock(&s->lock);
	return 0;
}
SEC("lsm.s/bprm_check_security")
int BPF_PROG(role_check, struct linux_binprm *bprm, int ret)
{
	__u32 zero = 0;
	struct fr_config *c = bpf_map_lookup_elem(&configuration, &zero);
	struct fr_totals *t = bpf_map_lookup_elem(&totals, &zero);
	if (!c || !t)
		return ret;
	struct task_struct *task = bpf_get_current_task_btf();
	struct fr_task_state *s = bpf_task_storage_get(&roles, task, 0, 0);
	/* Existing admission always retains its original binding, even after move. */
	int active = s && s->tx.owned;
	if (!active && c->cgroup != bpf_get_current_cgroup_id())
		return ret;
	struct inode *inode = 0;
	__u64 ino = 0;
	if (BPF_CORE_READ_INTO(&inode, bprm, file, f_inode) || !inode ||
	    BPF_CORE_READ_INTO(&ino, inode, i_ino))
		return -1;
	if (!active && ino != c->inode && ino != c->interpreter)
		return ret;
	if (t->faults)
		return -1;
	if (!s)
		s = get_state(task, t, c->limit);
	if (!s || merge_seed(task, s))
		return -1;
	if (!active) {
		if (fg_enter(&t->gate))
			return -1;
		bpf_spin_lock(&s->lock);
		s->tx.bprm = (__u64)bprm;
		s->tx.cgroup = c->cgroup;
		s->tx.generation = c->generation;
		s->tx.slot = 0;
		s->tx.owned = 1;
		s->tx.suppress = 0;
		s->tx.checks = 0;
		fr_clear_pending(&s->tx);
		bpf_spin_unlock(&s->lock);
	}
	bpf_spin_lock(&s->lock);
	int deny = ret || s->tx.bprm != (__u64)bprm ||
		   s->tx.generation != c->generation ||
		   !fr_lookup(s->entries, c->uid) ||
		   (fr_lookup(s->entries, c->uid) & c->actor) != c->actor ||
		   c->deny;
	s->tx.checks++;
	if (deny)
		s->tx.suppress = 1;
	__u64 proposed = c->grant;
	if (c->conflict && s->tx.checks > 1)
		proposed ^= 4;
	if (!deny && fr_propose(&s->tx, c->uid, proposed))
		deny = 1;
	bpf_spin_unlock(&s->lock);
	if (ret)
		return ret;
	return deny && !c->audit ? -1 : 0;
}
static __always_inline int complete(struct task_struct *task,
				    struct linux_binprm *bprm, int success,
				    int exiting)
{
	__u32 zero = 0;
	struct fr_totals *t = bpf_map_lookup_elem(&totals, &zero);
	struct fr_task_state *s = bpf_task_storage_get(&roles, task, 0, 0);
	if (!t || !s)
		return 0;
	unsigned int claimed = 0, commit = 0;
	bpf_spin_lock(&s->lock);
	if (s->tx.owned && (!bprm || s->tx.bprm == (__u64)bprm)) {
		if (success && !s->tx.suppress) {
#pragma clang loop unroll(disable)
			for (int i = 0; i < FR_ACTIVE; i++) {
				__u64 uid = s->tx.pending[i].uid;
				if (!uid)
					continue;
#pragma clang loop unroll(disable)
				for (int j = 0; j < FR_SLOTS; j++)
					if (s->entries[j].uid == uid)
						s->entries[j].roles =
							s->tx.pending[i].roles;
			}
			s->commits++;
			commit = 1;
		} else
			s->failures++;
		fr_clear_pending(&s->tx);
		s->tx.bprm = 0;
		s->tx.owned = 0;
		s->tx.suppress = 0;
		claimed = 1;
	}
	bpf_spin_unlock(&s->lock);
	if (claimed) {
		if (commit)
			__sync_fetch_and_add(&t->commits, 1);
		else
			__sync_fetch_and_add(&t->failures, 1);
		if (exiting)
			__sync_fetch_and_add(&t->exits, 1);
	}
	/* All task state, counters and unlock precede final count release. */
	fg_leave_owned(&t->gate, claimed, &t->faults);
	return 0;
}
SEC("tp_btf/sched_process_exec")
int BPF_PROG(role_exec, struct task_struct *task, int old_pid,
	     struct linux_binprm *bprm)
{
	return complete(task, bprm, 1, 0);
}
SEC("fexit/bprm_execve")
int BPF_PROG(role_completion, struct linux_binprm *bprm, int ret)
{
	/* Fixture fault injection ONLY: defer failed completion to task-exit so its
  * fallback is exercised with a genuinely counted outstanding admission. */
	__u32 zero = 0;
	struct fr_config *c = bpf_map_lookup_elem(&configuration, &zero);
	if (c && c->audit == 2 && ret < 0)
		return 0;
	return complete(bpf_get_current_task_btf(), bprm, 0, 0);
}
SEC("tp_btf/sched_process_exit")
int BPF_PROG(role_exit, struct task_struct *task)
{
	return complete(task, 0, 0, 1);
}
SEC("tp_btf/sched_process_fork")
int BPF_PROG(role_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 zero = 0;
	struct fr_totals *t = bpf_map_lookup_elem(&totals, &zero);
	struct fr_config *c = bpf_map_lookup_elem(&configuration, &zero);
	if (!t || !c)
		return 0;
	struct fr_task_state *p = bpf_task_storage_get(&roles, parent, 0, 0);
	if (!p) {
		/* Explicit parent seed may precede its first exec; no cgroup-wide roots. */
		struct fr_seed *request =
			bpf_task_storage_get(&seeds, parent, 0, 0);
		if (!request)
			return 0;
		p = get_state(parent, t, c->limit);
	}
	if (!p || merge_seed(parent, p))
		return 0;
	struct fr_task_state *s = get_state(child, t, c->limit);
	if (!s)
		return 0;
	struct fr_merge_work *w = bpf_task_storage_get(
		&merge_work, child, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!w)
		return 0;
	bpf_spin_lock(&p->lock);
#pragma clang loop unroll(full)
	for (int i = 0; i < FR_SLOTS; i++)
		w->entries[i] = p->entries[i];
	bpf_spin_unlock(&p->lock);
	bpf_spin_lock(&s->lock);
#pragma clang loop unroll(full)
	for (int i = 0; i < FR_SLOTS; i++)
		s->entries[i] = w->entries[i];
	s->initialized = 1;
	s->inherited = 1;
	s->identity = (__u64)child;
	bpf_spin_unlock(&s->lock);
	__sync_fetch_and_add(&t->forks, 1);
	return 0;
}
char LICENSE[] SEC("license") = "GPL";
