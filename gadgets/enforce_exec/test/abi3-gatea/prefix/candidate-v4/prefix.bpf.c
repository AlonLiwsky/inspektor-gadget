// SPDX-License-Identifier: GPL-2.0
// Test-only prefix observation. NEVER authority or a production history ledger.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "prefix.h"
#include "../ingress/lsm_result.h"
#define CGROUP2_MAGIC 0x63677270
#define PATH_FLAG 0x200000
struct control {
	struct bpf_spin_lock lock;
	__u32 pad;
	PX_STATE_FIELDS
};
struct row {
	struct bpf_spin_lock lock;
	__u32 pad;
	PX_ROW_FIELDS
};
_Static_assert(sizeof(struct control) == sizeof(struct px_state), "state ABI");
_Static_assert(sizeof(struct row) == sizeof(struct px_row), "row ABI");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct px_config);
} config SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct px_command);
} command SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct control);
} state SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, PX_LIMIT);
	__type(key, __u64);
	__type(value, struct row);
} tasks SEC(".maps");
struct held_ref {
	struct task_struct __kptr *task;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, PX_LIMIT);
	__type(key, __u32);
	__type(value, struct held_ref);
} refs SEC(".maps");
extern struct task_struct *bpf_task_from_pid(__s32) __ksym;
extern struct task_struct *bpf_task_acquire(struct task_struct *) __ksym;
extern void bpf_task_release(struct task_struct *) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
extern int bpf_iter_css_task_new(struct bpf_iter_css_task *,
				 struct cgroup_subsys_state *,
				 unsigned int) __ksym;
extern struct task_struct *
bpf_iter_css_task_next(struct bpf_iter_css_task *) __ksym;
extern void bpf_iter_css_task_destroy(struct bpf_iter_css_task *) __ksym;
extern struct cgroup *bpf_cgroup_from_id(__u64) __ksym;
extern void bpf_cgroup_release(struct cgroup *) __ksym;
static __always_inline struct control *ctl(void)
{
	__u32 z = 0;
	return bpf_map_lookup_elem(&state, &z);
}
static __always_inline struct row *current(void)
{
	__u64 k = (__u64)bpf_get_current_task_btf();
	return bpf_map_lookup_elem(&tasks, &k);
}
static __always_inline int target(struct task_struct *t, struct control *s)
{
	return (__u64)BPF_CORE_READ(t, cgroups, dfl_cgrp, procs_file.kn) ==
	       s->target_kn;
}
static __noinline int pinned_node(__u32 fd, __u64 *kn, __u64 *sb)
{
	if (fd >= 1024)
		return -22;
	struct task_struct *t = bpf_get_current_task_btf();
	struct file **fds = 0, *file = 0;
	struct fdtable *table = 0;
	struct inode *inode = 0;
	struct super_block *super = 0;
	struct kernfs_node *node = 0;
	__u32 limit = 0, flags = 0;
	unsigned long magic = 0;
	char *name = 0;
	int err = -22;
	bpf_rcu_read_lock();
	if (BPF_CORE_READ_INTO(&table, t, files, fdt) || !table)
		goto done;
	if (BPF_CORE_READ_INTO(&limit, table, max_fds) || fd >= limit)
		goto done;
	if (BPF_CORE_READ_INTO(&fds, table, fd) || !fds)
		goto done;
	if (bpf_probe_read_kernel(&file, sizeof(file), &fds[fd]) || !file)
		goto done;
	if (BPF_CORE_READ_INTO(&flags, file, f_flags) || !(flags & PATH_FLAG))
		goto done;
	if (BPF_CORE_READ_INTO(&inode, file, f_inode) || !inode)
		goto done;
	if (BPF_CORE_READ_INTO(&super, inode, i_sb) || !super)
		goto done;
	if (BPF_CORE_READ_INTO(&magic, super, s_magic) ||
	    magic != CGROUP2_MAGIC)
		goto done;
	if (BPF_CORE_READ_INTO(&node, inode, i_private) || !node)
		goto done;
	if (BPF_CORE_READ_INTO(&name, node, name) || !name)
		goto done;
	char text[13] = {};
	if (bpf_probe_read_kernel_str(text, sizeof(text), name) != 13 ||
	    __builtin_memcmp(text, "cgroup.procs", 13))
		goto done;
	*kn = (__u64)node;
	*sb = (__u64)super;
	err = 0;
done:
	bpf_rcu_read_unlock();
	return err;
}
/* No helpers or row locks while holding control lock. Audit never waits for
 * writers: concurrent changes invalidate receipts, not workload admission. */
static __always_inline int mutation_begin(struct control *s)
{
	int ok = 0;
	bpf_spin_lock(&s->lock);
	s->inventory_serial = 0;
	s->refusal_serial = 0;
	if (s->serial < ~0ULL - 1 && s->writers != ~0ULL) {
		s->serial++;
		s->writers++;
		ok = 1;
	} else
		s->errors |= 1;
	bpf_spin_unlock(&s->lock);
	return ok;
}
static __always_inline void mutation_end(struct control *s)
{
	bpf_spin_lock(&s->lock);
	if (s->writers)
		s->writers--;
	else
		s->errors |= 1;
	bpf_spin_unlock(&s->lock);
}
/* Caller owns task lifetime (iterator, current task, or typed lifecycle hook). */
static __noinline int insert(struct task_struct *t, struct control *s,
			     __u64 origin, __u64 parent)
{
	struct row r = { .origin = origin,
			 .owns_slot = 1,
			 .parent_cookie = parent };
	__u64 key = (__u64)t;
	r.pid = BPF_CORE_READ(t, pid);
	bpf_spin_lock(&s->lock);
	if (s->next_cookie != ~0ULL && s->retained < PX_LIMIT) {
		r.cookie = ++s->next_cookie;
		s->retained++;
	} else
		s->errors |= 1;
	bpf_spin_unlock(&s->lock);
	if (!r.cookie)
		return -7;
	int err = bpf_map_update_elem(&tasks, &key, &r, BPF_NOEXIST);
	if (err) {
		bpf_spin_lock(&s->lock);
		s->retained--;
		if (err != -17)
			s->errors |= 1;
		bpf_spin_unlock(&s->lock);
	}
	return err;
}
SEC("lsm.s/task_alloc")
long BPF_PROG(px_alloc, struct task_struct *child, __u64 flags, int ret)
{
	long prior = in_lsm_result(ret);
	struct control *s = ctl();
	struct row *p = current();
	if (ret || !s || !s->enabled || !p)
		return prior;
	if (!mutation_begin(s))
		return prior;
	__u64 key = (__u64)child, cookie = 0;
	int busy;
	bpf_spin_lock(&p->lock);
	cookie = p->cookie;
	busy = p->child != 0;
	bpf_spin_unlock(&p->lock);
	if (busy) {
		__sync_fetch_and_or(&s->errors, 1);
		mutation_end(s);
		return prior;
	}
	if (insert(child, s, PX_OWNED_BIRTH, cookie)) {
		mutation_end(s);
		return prior;
	}
	struct row *r = bpf_map_lookup_elem(&tasks, &key);
	if (!r) {
		__sync_fetch_and_or(&s->errors, 1);
		mutation_end(s);
		return prior;
	}
	bpf_spin_lock(&r->lock);
	r->alloc_seen = 1;
	cookie = r->cookie;
	bpf_spin_unlock(&r->lock);
	bpf_spin_lock(&p->lock);
	p->child = key;
	p->child_cookie = cookie;
	bpf_spin_unlock(&p->lock);
	bpf_spin_lock(&s->lock);
	s->allocs++;
	s->inflight++;
	bpf_spin_unlock(&s->lock);
	mutation_end(s);
	return prior;
}
SEC("tp_btf/task_newtask")
int BPF_PROG(px_birth, struct task_struct *child, __u64 flags)
{
	struct control *s = ctl();
	if (!s || !s->enabled)
		return 0;
	__u64 key = (__u64)child, owned = 0, cookie = 0;
	struct row *p = current();
	if (!p && !target(child, s))
		return 0;
	if (!mutation_begin(s))
		return 0;
	if (p) {
		bpf_spin_lock(&p->lock);
		if (p->child == key) {
			owned = 1;
			cookie = p->child_cookie;
			p->child = 0;
			p->child_cookie = 0;
		}
		bpf_spin_unlock(&p->lock);
	}
	struct row *r = bpf_map_lookup_elem(&tasks, &key);
	if (!owned && !target(child, s)) {
		mutation_end(s);
		return 0;
	}
	if (!r) {
		insert(child, s, PX_LATE, 0);
		r = bpf_map_lookup_elem(&tasks, &key);
	}
	/* security_task_alloc precedes p->pid assignment; only now is it final.
  * Read the typed child before locking, never use this diagnostic as authority. */
	__u64 child_pid = BPF_CORE_READ(child, pid);
	int valid = 0;
	if (r) {
		bpf_spin_lock(&r->lock);
		if (owned && r->cookie == cookie &&
		    r->origin == PX_OWNED_BIRTH && r->alloc_seen) {
			px_birth_diagnostic_pid(&r->pid, r->cookie, cookie,
						child_pid);
			r->live = 1;
			r->new_seen = 1;
			valid = 1;
		} else {
			r->birth_uncertain = 1;
			r->prefix_qualified = 0;
			r->live = 1;
			r->new_seen = 1;
		}
		bpf_spin_unlock(&r->lock);
	}
	bpf_spin_lock(&s->lock);
	if (owned) {
		if (s->inflight)
			s->inflight--;
		else
			s->errors |= 1;
		if (valid)
			s->births++;
		else
			s->errors |= 1;
	} else
		s->unowned++;
	bpf_spin_unlock(&s->lock);
	mutation_end(s);
	return 0;
}
SEC("fexit/copy_process")
int BPF_PROG(px_failed, struct pid *pid, int trace, int node,
	     struct kernel_clone_args *args, struct task_struct *result)
{
	if ((__u64)result < ~4094ULL)
		return 0;
	struct control *s = ctl();
	struct row *p = current();
	if (!s || !p || !s->enabled)
		return 0;
	if (!mutation_begin(s))
		return 0;
	int owned = 0;
	bpf_spin_lock(&p->lock);
	if (p->child) {
		owned = 1;
		p->child = 0;
		p->child_cookie = 0;
	}
	bpf_spin_unlock(&p->lock);
	if (owned) {
		bpf_spin_lock(&s->lock);
		if (s->inflight)
			s->inflight--;
		else
			s->errors |= 1;
		s->failed++;
		bpf_spin_unlock(&s->lock);
	}
	mutation_end(s);
	return 0;
}
SEC("lsm/task_free") int BPF_PROG(px_free, struct task_struct *task)
{
	__u64 key = (__u64)task;
	struct control *s = ctl();
	struct row *r = bpf_map_lookup_elem(&tasks, &key);
	if (!r || !s)
		return 0;
	if (!mutation_begin(s))
		return 0;
	int owned;
	bpf_spin_lock(&r->lock);
	owned = r->owns_slot;
	r->owns_slot = 0;
	bpf_spin_unlock(&r->lock);
	if (!owned) {
		mutation_end(s);
		return 0;
	}
	int err = bpf_map_delete_elem(&tasks, &key);
	bpf_spin_lock(&s->lock);
	if (err || !s->retained)
		s->errors |= 1;
	else {
		s->retained--;
		s->frees++;
	}
	bpf_spin_unlock(&s->lock);
	mutation_end(s);
	return 0;
}
SEC("fentry/ret_from_fork")
int BPF_PROG(px_retfork, struct task_struct *prev, struct pt_regs *regs,
	     void *fn, void *arg)
{
	struct control *s = ctl();
	struct row *r = current();
	if (!s || !s->enabled || !r || fn)
		return 0;
	if (!mutation_begin(s))
		return 0;
	bpf_spin_lock(&r->lock);
	if (r->origin == PX_OWNED_BIRTH && r->live && r->new_seen &&
	    !r->birth_uncertain) {
		r->retfork_seen = 1;
		r->retfork_entries = r->entries;
	}
	bpf_spin_unlock(&r->lock);
	mutation_end(s);
	return 0;
}
SEC("tp_btf/sys_enter") int BPF_PROG(px_enter, struct pt_regs *regs, long id)
{
	struct control *s = ctl();
	struct row *r = current();
	if (!s || !s->enabled || !r)
		return 0;
	if (!mutation_begin(s))
		return 0;
	bpf_spin_lock(&r->lock);
	r->entries++;
	if (id == 0)
		r->read_enter++;
	bpf_spin_unlock(&r->lock);
	mutation_end(s);
	return 0;
}
SEC("tp_btf/sys_exit") int BPF_PROG(px_exit, struct pt_regs *regs, long ret)
{
	struct control *s = ctl();
	struct row *r = current();
	if (!s || !s->enabled || !s->barrier || !r)
		return 0;
	long id = BPF_CORE_READ(regs, orig_ax);
	if (!mutation_begin(s))
		return 0;
	bpf_spin_lock(&r->lock);
	r->exits++;
	if (id == 0)
		r->read_exit++;
	if (!r->boundary_seen) {
		r->boundary_seen = 1;
		r->first_exit_entries = r->entries;
	}
	if (!r->prefix_qualified &&
	    (r->origin != PX_OWNED_BIRTH || r->exits == 1) &&
	    px_eligible(r->origin, r->birth_uncertain, r->live, r->retfork_seen,
			r->entries, r->retfork_entries, s->initial_done,
			r->child, r->child_cookie))
		r->prefix_qualified = 1;
	bpf_spin_unlock(&r->lock);
	mutation_end(s);
	return 0;
}
SEC("fexit/cgroup_kn_lock_live")
int BPF_PROG(px_barrier, struct kernfs_node *kn, bool drain,
	     struct cgroup *result)
{
	__u32 z = 0;
	struct px_config *c = bpf_map_lookup_elem(&config, &z);
	struct px_command *q = bpf_map_lookup_elem(&command, &z);
	struct control *s = ctl();
	if (!result || (__u64)result >= ~4095ULL || !c || !q || !s ||
	    !s->enabled || !c->nonce || q->nonce != c->nonce ||
	    q->operation != PX_BARRIER ||
	    c->admin != bpf_get_current_pid_tgid() ||
	    s->admin_task != (__u64)bpf_get_current_task_btf() ||
	    s->control_kn != (__u64)kn)
		return 0;
	if (!mutation_begin(s))
		return 0;
	bpf_spin_lock(&s->lock);
	if (q->argument > s->barrier)
		s->barrier = q->argument;
	bpf_spin_unlock(&s->lock);
	mutation_end(s);
	return 0;
}
/* Diagnostic stall is one-shot, exact-task scoped, and NEVER owns a child row. */
SEC("fexit/copy_thread")
int BPF_PROG(px_copy_thread, struct task_struct *child,
	     struct kernel_clone_args *args, int ret)
{
	__u32 z = 0;
	struct control *s = ctl();
	struct px_config *c = bpf_map_lookup_elem(&config, &z);
	if (ret || !s || !c || !s->diagnostic_nonce ||
	    s->diagnostic_nonce != c->nonce || s->diagnostic_used ||
	    s->diagnostic_task != (__u64)bpf_get_current_task_btf() ||
	    BPF_CORE_READ(args, fn))
		return 0;
	s->diagnostic_used = 1;
	s->diagnostic_child = (__u64)child;
	s->diagnostic_cpu = bpf_get_smp_processor_id();
	if (s->diagnostic_cpu != c->creator_cpu ||
	    s->diagnostic_cpu == c->admin_cpu) {
		s->diagnostic_timeout = 1;
		return 0;
	}
	__u64 start = bpf_ktime_get_ns();
	s->diagnostic_enter = 1;
#pragma clang loop unroll(disable)
	for (__u32 i = 0; i < 65536; i++) {
		__u64 now = bpf_ktime_get_ns();
		if (now - start >= 10000000ULL)
			break;
		if (*(volatile __u64 *)&s->diagnostic_release) {
			s->diagnostic_exit = 1;
			return 0;
		}
	}
	s->diagnostic_timeout = 1;
	s->diagnostic_exit = 1;
	return 0;
}
/* Exact protected CSS walk, flags=0 includes every thread. No inventory repair. */
static __noinline int inventory(struct control *s, __u64 id)
{
	int rc = 0, initial = 0;
	__u64 expected = 0, n = 0, missing = 0, unknown = 0;
	/* Consume the sole INITIAL-origin window even if acquiring/creating fails. */
	bpf_spin_lock(&s->lock);
	initial = !s->initial_started;
	s->initial_started = 1;
	bpf_spin_unlock(&s->lock);
	if (!mutation_begin(s))
		return -11;
	bpf_spin_lock(&s->lock);
	expected = s->serial;
	if (s->writers != 1)
		rc = -11;
	bpf_spin_unlock(&s->lock);
	if (rc)
		goto finish;
	struct cgroup *g = bpf_cgroup_from_id(id);
	if (!g) {
		rc = -2;
		goto finish;
	}
	if ((__u64)BPF_CORE_READ(g, procs_file.kn) != s->target_kn) {
		bpf_cgroup_release(g);
		rc = -22;
		goto finish;
	}
	struct bpf_iter_css_task it;
	rc = bpf_iter_css_task_new(&it, &g->self, 0);
	if (rc)
		goto done;
	for (int i = 0; i <= PX_LIMIT; i++) {
		struct task_struct *t = bpf_iter_css_task_next(&it);
		if (!t)
			break;
		if (i == PX_LIMIT) {
			rc = -7;
			break;
		}
		__u64 key = (__u64)t;
		struct row *r = bpf_map_lookup_elem(&tasks, &key);
		if (!r) {
			int err =
				insert(t, s, initial ? PX_INITIAL : PX_LATE, 0);
			if (err && err != -17) {
				rc = err;
				break;
			}
		}
		r = bpf_map_lookup_elem(&tasks, &key);
		if (!r) {
			rc = -2;
			break;
		}
		bpf_spin_lock(&r->lock);
		if (!r->prefix_qualified || r->birth_uncertain || r->child ||
		    r->child_cookie)
			missing++;
		if (!r->history_complete)
			unknown++;
		bpf_spin_unlock(&r->lock);
		n++;
	}
done:
	bpf_iter_css_task_destroy(&it);
	bpf_cgroup_release(g);
finish:
	bpf_spin_lock(&s->lock);
	if (!px_snapshot_valid(s->serial, expected, s->writers, 1) ||
	    s->inventory_generation == ~0ULL)
		rc = -11;
	if (s->writers)
		s->writers--;
	else
		s->errors |= 1;
	if (!rc) {
		if (initial)
			s->initial_done = 1;
		s->inventory = n;
		s->target_id = id;
		s->prefix_missing = missing;
		s->history_unknown = unknown;
		s->inventory_generation++;
		s->inventory_serial = s->serial;
	}
	bpf_spin_unlock(&s->lock);
	return rc;
}
SEC("syscall") int px_command(void *ctx)
{
	__u32 z = 0;
	struct px_config *c = bpf_map_lookup_elem(&config, &z);
	struct px_command *q = bpf_map_lookup_elem(&command, &z);
	struct control *s = ctl();
	if (!c || !q || !s || !c->nonce || q->nonce != c->nonce ||
	    c->admin != bpf_get_current_pid_tgid())
		return -1;
	if (q->operation == PX_PIN) {
		if (s->pinned)
			return -17;
		__u64 t = 0, k = 0, ts = 0, cs = 0;
		if (pinned_node(c->target_fd, &t, &ts) ||
		    pinned_node(c->control_fd, &k, &cs) || t == k)
			return -22;
		s->admin_task = (__u64)bpf_get_current_task_btf();
		s->target_kn = t;
		s->control_kn = k;
		s->target_sb = ts;
		s->control_sb = cs;
		s->pinned = 1;
		return 0;
	}
	if (!s->pinned || s->admin_task != (__u64)bpf_get_current_task_btf())
		return -1;
	if (q->operation == PX_DIAG_ARM) {
		if (s->enabled || s->diagnostic_task || s->diagnostic_used ||
		    !q->argument || q->argument > 0x7fffffff)
			return -22;
		struct task_struct *t = bpf_task_from_pid(q->argument);
		if (!t)
			return -2;
		if ((__u64)BPF_CORE_READ(t, real_parent) != s->admin_task ||
		    !target(t, s)) {
			bpf_task_release(t);
			return -22;
		}
		/* PX_HOLD must already have pinned this exact task; validate the kptr identity. */
		int held = 0;
		bpf_rcu_read_lock();
		for (__u32 i = 0; i < PX_LIMIT; i++) {
			struct held_ref *h = bpf_map_lookup_elem(&refs, &i);
			if (h && h->task == t)
				held = 1;
		}
		bpf_rcu_read_unlock();
		if (!held) {
			bpf_task_release(t);
			return -22;
		}
		s->diagnostic_task = (__u64)t;
		s->diagnostic_nonce = c->nonce;
		bpf_task_release(t);
		return 0;
	}
	if (q->operation == PX_DIAG_RELEASE) {
		__u64 cpu = bpf_get_smp_processor_id();
		int rc = -11;
		bpf_spin_lock(&s->lock);
		if (s->diagnostic_enter && !s->diagnostic_timeout &&
		    !s->diagnostic_exit && s->enabled && s->initial_done &&
		    s->inventory && s->prefix_missing &&
		    s->diagnostic_nonce == c->nonce && cpu == c->admin_cpu &&
		    s->inventory_serial == s->serial &&
		    px_refusal_valid(
			    q->argument, s->refusals, s->inventory_generation,
			    s->refusal_inventory, s->serial, s->refusal_serial,
			    s->barrier, s->refusal_barrier, s->writers)) {
			s->admin_cpu = cpu;
			s->diagnostic_release = 1;
			rc = 0;
		}
		bpf_spin_unlock(&s->lock);
		return rc;
	}
	if (q->operation == PX_ENABLE) {
		if (s->enabled)
			return -17;
		s->enabled = 1;
		return 0;
	}
	if (q->operation == PX_HOLD) {
		if (s->held >= PX_LIMIT || !q->argument ||
		    q->argument > 0x7fffffff)
			return -22;
		__u32 slot = s->held;
		struct held_ref *h = bpf_map_lookup_elem(&refs, &slot);
		if (!h)
			return -2;
		struct task_struct *t = bpf_task_from_pid(q->argument);
		if (!t)
			return -2;
		if ((__u64)BPF_CORE_READ(t, real_parent) != s->admin_task ||
		    !target(t, s)) {
			bpf_task_release(t);
			return -22;
		}
		struct task_struct *old = bpf_kptr_xchg(&h->task, t);
		if (old) {
			bpf_task_release(old);
			return -17;
		}
		s->held++;
		return 0;
	}
	if (q->operation == PX_RELEASE_REFS) {
		for (__u32 i = 0; i < PX_LIMIT; i++) {
			struct held_ref *h = bpf_map_lookup_elem(&refs, &i);
			if (h) {
				struct task_struct *t =
					bpf_kptr_xchg(&h->task, 0);
				if (t)
					bpf_task_release(t);
			}
		}
		return 0;
	}
	if (!s->enabled || !s->barrier)
		return -11;
	if (q->operation == PX_INVENTORY)
		return inventory(s, q->argument);
	/* No history-complete producer exists in this prefix fixture. */
	if (q->operation == PX_REFUSE) {
		int rc = -11;
		bpf_spin_lock(&s->lock);
		if (s->initial_done && q->argument &&
		    q->argument == s->inventory_generation &&
		    px_snapshot_valid(s->serial, s->inventory_serial,
				      s->writers, 0) &&
		    s->refusals != ~0ULL) {
			if (s->prefix_missing || s->history_unknown ||
			    s->errors || s->inflight) {
				s->refusals++;
				s->strict_ready = 0;
				s->refusal_serial = s->serial;
				s->refusal_inventory = s->inventory_generation;
				s->refusal_barrier = s->barrier;
			} else
				rc = -95;
		}
		bpf_spin_unlock(&s->lock);
		return rc;
	}
	return -22;
}
char LICENSE[] SEC("license") = "GPL";
