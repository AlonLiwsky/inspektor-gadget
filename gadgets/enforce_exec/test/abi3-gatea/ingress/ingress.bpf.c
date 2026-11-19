// SPDX-License-Identifier: GPL-2.0
// Test-only exact-target permission, owned ingress and ARM primitives.
// This records compact completion facts, NOT full production role history.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "ingress.h"
#include "lsm_result.h"
#define CGROUP2_MAGIC 0x63677270
#define PATH_FLAG 0x200000
#define MAY_WRITE 2
#define CLONE_INTO (1ULL << 33)
struct kernel_state {
	struct bpf_spin_lock lock;
	__u32 pinned;
	__u64 admin_task, target_kn, control_kn, target_sb, control_sb;
	__u64 mode, active_attempt, pending_attempt, pending_mode;
	__u64 permission_hits, denials, audit_hits, inspection_errors, arms;
	__u64 last_sb, last_kn, last_tid, last_mask, wrong_control;
	__u64 hook_calls, prior_returns, zero_inputs, cgroup_inodes,
		write_requests, node_matches;
	__u64 observed_magic, observed_sb, observed_kn, observed_mask,
		observed_tid;
	__u64 serial, pending_serial, next_token, ingress_inflight, uncertain;
	__u64 ingress_admitted, ingress_completed, ingress_cancelled,
		unowned_completions;
	__u64 token_failures, arm_refusals, last_arm_reason;
	__u64 last_fact_cookie, last_fact_child, last_fact_kind;
	__u64 test_task, test_nonce, test_armed, signal_requests, signal_errors;
	__u64 overlap_nonce, overlap_ready, overlap_entry, overlap_release,
		overlap_exit, overlap_failed;
	__u64 overlap_used, overlap_creator_cpu, overlap_admin_cpu,
		overlap_child, overlap_cookie, overlap_inflight, overlap_serial,
		overlap_receipt, overlap_reason;
};
_Static_assert(sizeof(struct kernel_state) == sizeof(struct in_state),
	       "state ABI");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct in_config);
} config SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct in_command);
} command SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kernel_state);
} state SEC(".maps");
struct ingress_token {
	struct bpf_spin_lock lock;
	__u32 owned;
	__u64 cookie, creator, nonce, target_kn;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, IN_TOKENS);
	__type(key, __u64);
	__type(value, struct ingress_token);
} tokens SEC(".maps");
// Test-only reference: the cancellation target cannot be recycled while armed.
struct cancellation_ref {
	struct task_struct __kptr *task;
	__u64 nonce;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct cancellation_ref);
} cancel_ref SEC(".maps");
extern struct task_struct *bpf_task_from_pid(__s32) __ksym;
extern void bpf_task_release(struct task_struct *) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
// The single-threaded harness keeps every authenticated O_PATH FD open until
// all links detach. RCU protects table lookup; the retained FD pins its object.
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
SEC("syscall") int in_command(void *ctx)
{
	__u32 z = 0;
	struct in_config *c = bpf_map_lookup_elem(&config, &z);
	struct in_command *q = bpf_map_lookup_elem(&command, &z);
	struct kernel_state *s = bpf_map_lookup_elem(&state, &z);
	if (!c || !q || !s || !c->nonce || q->nonce != c->nonce ||
	    (__u32)bpf_get_current_pid_tgid() != c->tid)
		return -1;
	if (q->operation == IN_RETURN_TEST)
		return in_lsm_result((int)q->mode);
	if (q->operation == IN_BAD_PIN) {
		__u64 kn = 0, sb = 0;
		return pinned_node(c->bad_fd, &kn, &sb);
	}
	if (q->operation == IN_PIN) {
		__u64 target = 0, control = 0, tsb = 0, csb = 0;
		if (pinned_node(c->target_fd, &target, &tsb) ||
		    pinned_node(c->control_fd, &control, &csb) ||
		    target == control)
			return -22;
		__u64 task = (__u64)bpf_get_current_task_btf();
		int result = -17;
		bpf_spin_lock(&s->lock);
		if (!s->pinned) {
			s->admin_task = task;
			s->target_kn = target;
			s->control_kn = control;
			s->target_sb = tsb;
			s->control_sb = csb;
			s->serial = 1;
			s->pinned = 1;
			result = 0;
		}
		bpf_spin_unlock(&s->lock);
		return result;
	}
	if (q->operation == IN_STAGE) {
		__u64 task = (__u64)bpf_get_current_task_btf();
		int result = -22;
		bpf_spin_lock(&s->lock);
		if (s->pinned && s->admin_task == task &&
		    q->mode <= IN_STRICT && q->attempt > s->active_attempt &&
		    !s->pending_attempt) {
			if (s->ingress_inflight || s->uncertain ||
			    s->serial == ~0ULL)
				result = -11;
			else {
				s->pending_attempt = q->attempt;
				s->pending_mode = q->mode;
				s->pending_serial = s->serial;
				result = 0;
			}
		}
		bpf_spin_unlock(&s->lock);
		return result;
	}
	if (q->operation == IN_CANCEL_ARM || q->operation == IN_OVERLAP_ARM) {
		// Only a pipe-stalled direct child of the exact admin task, still in its
		// control cgroup, may become the physical test target. No generic PID trigger.
		if (!q->attempt || !q->mode || q->mode > 0x7fffffff)
			return -22;
		__u64 admin = (__u64)bpf_get_current_task_btf();
		int busy;
		bpf_spin_lock(&s->lock);
		busy = !s->pinned || s->admin_task != admin || s->test_task ||
		       (q->operation == IN_OVERLAP_ARM && s->overlap_used);
		bpf_spin_unlock(&s->lock);
		if (busy)
			return -16;
		struct cancellation_ref *held =
			bpf_map_lookup_elem(&cancel_ref, &z);
		if (!held)
			return -2;
		struct task_struct *worker = bpf_task_from_pid(q->mode);
		if (!worker)
			return -2;
		__u32 pid = 0, tgid = 0;
		struct task_struct *parent = 0;
		struct kernfs_node *group = 0;
		if (BPF_CORE_READ_INTO(&pid, worker, pid) ||
		    BPF_CORE_READ_INTO(&tgid, worker, tgid) ||
		    BPF_CORE_READ_INTO(&parent, worker, real_parent) ||
		    BPF_CORE_READ_INTO(&group, worker, cgroups, dfl_cgrp,
				       procs_file.kn) ||
		    pid != q->mode || tgid != pid || (__u64)parent != admin ||
		    (__u64)group != s->control_kn) {
			bpf_task_release(worker);
			return -22;
		}
		__u64 identity = (__u64)worker;
		struct task_struct *old = bpf_kptr_xchg(&held->task, worker);
		if (old) {
			bpf_task_release(old);
			struct task_struct *installed =
				bpf_kptr_xchg(&held->task, 0);
			if (installed)
				bpf_task_release(installed);
			held->nonce = 0;
			return -16;
		}
		held->nonce = q->attempt;
		bpf_spin_lock(&s->lock);
		s->test_task = identity;
		s->test_nonce = q->attempt;
		s->test_armed = q->operation == IN_CANCEL_ARM;
		if (q->operation == IN_OVERLAP_ARM) {
			s->overlap_used = 1;
			s->overlap_nonce = q->attempt;
			s->overlap_ready = 0;
			s->overlap_entry = 0;
			s->overlap_release = 0;
			s->overlap_exit = 0;
			s->overlap_failed = 0;
		}
		bpf_spin_unlock(&s->lock);
		return 0;
	}
	if (q->operation == IN_CANCEL_RELEASE) {
		struct cancellation_ref *held =
			bpf_map_lookup_elem(&cancel_ref, &z);
		if (!held)
			return -2;
		__u64 admin = (__u64)bpf_get_current_task_btf();
		int valid = 0;
		bpf_spin_lock(&s->lock);
		if (s->admin_task == admin && s->test_task && q->attempt &&
		    s->test_nonce == q->attempt) {
			s->test_task = 0;
			s->test_nonce = 0;
			s->test_armed = 0;
			s->overlap_nonce = 0;
			valid = 1;
		}
		bpf_spin_unlock(&s->lock);
		if (!valid)
			return -22;
		held->nonce = 0;
		struct task_struct *worker = bpf_kptr_xchg(&held->task, 0);
		if (worker)
			bpf_task_release(worker);
		return 0;
	}
	if (q->operation == IN_ABORT) {
		__u64 task = (__u64)bpf_get_current_task_btf();
		int result = -22;
		bpf_spin_lock(&s->lock);
		if (s->admin_task == task && q->attempt &&
		    s->pending_attempt == q->attempt) {
			s->pending_attempt = 0;
			s->pending_serial = 0;
			result = 0;
		}
		bpf_spin_unlock(&s->lock);
		return result;
	}
	return -22;
}
SEC("lsm/inode_permission")
long BPF_PROG(in_permission, const struct mnt_idmap *idmap, struct inode *inode,
	      int mask, int ret)
{
	long prior = in_lsm_result(ret);
	__u32 z = 0;
	struct kernel_state *s = bpf_map_lookup_elem(&state, &z);
	if (!s)
		return prior;
	__u64 tid = bpf_get_current_pid_tgid();
	bpf_spin_lock(&s->lock);
	s->hook_calls++;
	if (prior)
		s->prior_returns++;
	else
		s->zero_inputs++;
	s->observed_mask = mask;
	s->observed_tid = tid;
	bpf_spin_unlock(&s->lock);
	if (prior)
		return prior;
	struct super_block *super = 0;
	struct kernfs_node *kn = 0;
	unsigned long magic = 0;
	if (BPF_CORE_READ_INTO(&super, inode, i_sb) || !super ||
	    BPF_CORE_READ_INTO(&magic, super, s_magic) ||
	    BPF_CORE_READ_INTO(&kn, inode, i_private)) {
		bpf_spin_lock(&s->lock);
		s->inspection_errors++;
		bpf_spin_unlock(&s->lock);
		return 0;
	}
	int deny = 0;
	bpf_spin_lock(&s->lock);
	s->observed_magic = magic;
	s->observed_sb = (__u64)super;
	s->observed_kn = (__u64)kn;
	if (magic == CGROUP2_MAGIC) {
		s->cgroup_inodes++;
		if (mask & MAY_WRITE)
			s->write_requests++;
		if (s->pinned && s->target_kn == (__u64)kn)
			s->node_matches++;
	}
	if (magic == CGROUP2_MAGIC && (mask & MAY_WRITE) && s->pinned &&
	    s->target_kn == (__u64)kn) {
		s->permission_hits++;
		s->last_sb = (__u64)super;
		s->last_kn = (__u64)kn;
		s->last_tid = tid;
		s->last_mask = mask;
		if (s->mode == IN_STRICT) {
			s->denials++;
			deny = 1;
		} else
			s->audit_hits++;
	}
	bpf_spin_unlock(&s->lock);
	return deny ? -1 : 0;
}
// Test-only bounded rendezvous. Each observation takes/releases the dispatch
// lock; neither the loop nor ktime helper runs with a spinlock held.
struct overlap_wait {
	struct kernel_state *s;
	__u64 deadline;
	__u32 completion, seen;
};
static long overlap_poll(__u32 index, void *opaque)
{
	struct overlap_wait *w = opaque;
	struct kernel_state *s = w->s;
	(void)index;
	if (bpf_ktime_get_ns() >= w->deadline)
		return 1;
	bpf_spin_lock(&s->lock);
	w->seen = w->completion ? s->overlap_exit : s->overlap_entry;
	bpf_spin_unlock(&s->lock);
	return w->seen ? 1 : 0;
}
static __always_inline void overlap_wait_for(struct kernel_state *s,
					     int completion)
{
	struct overlap_wait w = { .s = s,
				  .deadline =
					  bpf_ktime_get_ns() + IN_OVERLAP_NS,
				  .completion = completion };
	bpf_loop(IN_OVERLAP_ITERATIONS, overlap_poll, &w, 0);
	bpf_spin_lock(&s->lock);
	if (!w.seen)
		s->overlap_failed = 1;
	if (!completion) {
		if (s->overlap_exit)
			s->overlap_failed = 1;
		s->overlap_release = 1;
	}
	bpf_spin_unlock(&s->lock);
}
SEC("fentry/cgroup_kn_lock_live")
int BPF_PROG(in_arm_enter, struct kernfs_node *kn, bool drain)
{
	__u32 z = 0;
	struct in_config *c = bpf_map_lookup_elem(&config, &z);
	struct in_command *q = bpf_map_lookup_elem(&command, &z);
	struct kernel_state *s = bpf_map_lookup_elem(&state, &z);
	if (!c || !q || !s || q->nonce != c->nonce || !c->nonce ||
	    q->operation != IN_STAGE ||
	    (__u32)bpf_get_current_pid_tgid() != c->tid ||
	    bpf_get_smp_processor_id() != c->admin_cpu)
		return 0;
	__u64 task = (__u64)bpf_get_current_task_btf();
	bpf_spin_lock(&s->lock);
	if (s->overlap_nonce && s->overlap_ready && s->admin_task == task &&
	    s->control_kn == (__u64)kn && s->pending_attempt == q->attempt &&
	    s->pending_mode == q->mode) {
		if (s->overlap_release || s->overlap_exit)
			s->overlap_failed = 1;
		s->overlap_admin_cpu = c->admin_cpu;
		s->overlap_entry = 1;
	}
	bpf_spin_unlock(&s->lock);
	return 0;
}
SEC("fexit/cgroup_kn_lock_live")
int BPF_PROG(in_arm, struct kernfs_node *kn, bool drain, struct cgroup *result)
{
	if (!result || (__u64)result >= ~4095ULL)
		return 0;
	__u32 z = 0;
	struct in_config *c = bpf_map_lookup_elem(&config, &z);
	struct in_command *q = bpf_map_lookup_elem(&command, &z);
	struct kernel_state *s = bpf_map_lookup_elem(&state, &z);
	if (!c || !q || !s || (__u32)bpf_get_current_pid_tgid() != c->tid ||
	    !c->nonce || q->nonce != c->nonce || q->operation != IN_STAGE)
		return 0;
	__u64 task = (__u64)bpf_get_current_task_btf();
	bpf_spin_lock(&s->lock);
	if (s->pinned && s->admin_task == task && s->pending_attempt &&
	    s->pending_attempt == q->attempt && s->pending_mode == q->mode &&
	    (!s->pending_mode || !s->inspection_errors)) {
		if (s->control_kn == (__u64)kn) {
			if (s->overlap_nonce && s->overlap_entry) {
				if (!s->overlap_release || !s->ingress_inflight)
					s->overlap_failed = 1;
				s->overlap_exit = 1;
			}
			__u64 reason = 0;
			if (s->ingress_inflight)
				reason |= IN_ARM_BUSY;
			if (s->serial != s->pending_serial)
				reason |= IN_ARM_STALE;
			if (s->uncertain || s->serial == ~0ULL)
				reason |= IN_ARM_UNCERTAIN;
			if (reason) {
				s->arm_refusals++;
				s->last_arm_reason = reason;
				if (s->overlap_nonce && s->overlap_entry) {
					s->overlap_inflight =
						s->ingress_inflight;
					s->overlap_serial = s->serial;
					s->overlap_receipt = s->pending_serial;
					s->overlap_reason = reason;
				}
			} else {
				// All potentially refusing checks precede the first publication store.
				s->mode = s->pending_mode;
				s->active_attempt = s->pending_attempt;
				s->pending_attempt = 0;
				s->pending_serial = 0;
				s->serial++;
				s->arms++;
				s->last_arm_reason = 0;
			}
		} else
			s->wrong_control++;
	}
	bpf_spin_unlock(&s->lock);
	return 0;
}

static __always_inline struct kernel_state *ingress_state(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&state, &zero);
}
// Valid only while cgroup_can_fork/post_fork/cancel_fork retains kargs->cgrp.
// Completion exits instead use their owned token: kargs->cgrp may be cleared.
static __always_inline int is_target_clone(struct kernel_clone_args *args,
					   struct kernel_state *s)
{
	__u64 flags = 0;
	struct cgroup *group = 0;
	struct kernfs_node *kn = 0;
	if (BPF_CORE_READ_INTO(&flags, args, flags))
		return -1;
	if (!(flags & CLONE_INTO))
		return 0;
	if (BPF_CORE_READ_INTO(&group, args, cgrp) || !group)
		return -1;
	if (BPF_CORE_READ_INTO(&kn, group, procs_file.kn) || !kn)
		return -1;
	return s->pinned && s->target_kn == (__u64)kn;
}
static __always_inline void ingress_uncertain(struct kernel_state *s)
{
	bpf_spin_lock(&s->lock);
	s->uncertain = 1;
	if (s->serial < ~0ULL)
		s->serial++;
	bpf_spin_unlock(&s->lock);
}
SEC("fexit/cgroup_can_fork")
int BPF_PROG(in_can_fork, struct task_struct *child,
	     struct kernel_clone_args *args, int ret)
{
	if (ret)
		return 0;
	struct kernel_state *s = ingress_state();
	if (!s || !s->pinned)
		return 0;
	int target = is_target_clone(args, s);
	if (!target)
		return 0;
	if (target < 0) {
		ingress_uncertain(s);
		return 0;
	}
	__u32 zero = 0;
	struct in_config *c = bpf_map_lookup_elem(&config, &zero);
	if (!c) {
		ingress_uncertain(s);
		return 0;
	}
	__u64 key = (__u64)child, creator = (__u64)bpf_get_current_task_btf();
	struct ingress_token token = { .owned = 1,
				       .creator = creator,
				       .nonce = c->nonce,
				       .target_kn = s->target_kn };
	// Successful can_fork still owns cgroup_mutex. ARM cannot pass this boundary
	// while registration is between the dispatch lock and the map helper.
	bpf_spin_lock(&s->lock);
	if (s->next_token == ~0ULL || s->serial >= ~0ULL - 1 ||
	    s->ingress_inflight >= IN_TOKENS) {
		s->uncertain = 1;
		s->token_failures++;
	} else {
		token.cookie = ++s->next_token;
		s->ingress_inflight++;
		s->serial++;
	}
	bpf_spin_unlock(&s->lock);
	if (!token.cookie)
		return 0; // Audit is never denied for observer capacity/faults.
	if (bpf_map_update_elem(&tokens, &key, &token, BPF_NOEXIST)) {
		// A retained row at the same physical child address is structural stale
		// state, not ownership for this birth. Quarantine it without refunding it.
		struct ingress_token *old = bpf_map_lookup_elem(&tokens, &key);
		if (old) {
			bpf_spin_lock(&old->lock);
			old->owned = 2;
			bpf_spin_unlock(&old->lock);
		}
		bpf_spin_lock(&s->lock);
		s->uncertain = 1;
		s->token_failures++;
		if (s->ingress_inflight)
			s->ingress_inflight--;
		if (s->serial < ~0ULL)
			s->serial++;
		bpf_spin_unlock(&s->lock);
		return 0;
	}
	struct cancellation_ref *held = bpf_map_lookup_elem(&cancel_ref, &zero);
	int inject = 0, overlap = 0;
	__u32 cpu = bpf_get_smp_processor_id();
	bpf_spin_lock(&s->lock);
	s->ingress_admitted++;
	if (held && !s->overlap_ready && s->overlap_nonce &&
	    s->test_task == creator && s->overlap_nonce == held->nonce &&
	    cpu == c->creator_cpu && cpu != c->admin_cpu) {
		s->overlap_creator_cpu = cpu;
		s->overlap_child = key;
		s->overlap_cookie = token.cookie;
		s->overlap_ready = 1;
		overlap = 1;
	}
	if (held && s->test_armed && s->test_task == creator && s->test_nonce &&
	    s->test_nonce == held->nonce) {
		s->test_armed = 0;
		s->signal_requests++;
		inject = 1;
	}
	bpf_spin_unlock(&s->lock);
	// Test fault injection only, AFTER genuine successful registration. A held
	// task reference plus exact admin-child provenance and nonce scope the signal.
	// Helper success is not proof of cancellation: the native test requires the
	// real cancel hook, count reclamation and this worker's SIGKILL exit status.
	if (overlap)
		overlap_wait_for(s, 0);
	if (inject) {
		long result = bpf_send_signal(9);
		if (result) {
			bpf_spin_lock(&s->lock);
			s->signal_errors++;
			s->uncertain = 1;
			bpf_spin_unlock(&s->lock);
		}
	}
	return 0;
}
static __always_inline int ingress_enter(struct task_struct *child,
					 struct kernel_clone_args *args)
{
	struct kernel_state *s = ingress_state();
	if (!s || !s->pinned)
		return 0;
	int target = is_target_clone(args, s);
	if (!target)
		return 0;
	if (target < 0) {
		ingress_uncertain(s);
		return 0;
	}
	__u64 key = (__u64)child;
	if (bpf_map_lookup_elem(&tokens, &key))
		return 0;
	// An unowned historical/failed-observation completion cannot refund another
	// birth's count. Publish prefix uncertainty before this operation can finish.
	bpf_spin_lock(&s->lock);
	s->uncertain = 1;
	s->unowned_completions++;
	if (s->serial < ~0ULL)
		s->serial++;
	bpf_spin_unlock(&s->lock);
	return 0;
}
SEC("fentry/cgroup_post_fork")
int BPF_PROG(in_post_enter, struct task_struct *child,
	     struct kernel_clone_args *args)
{
	return ingress_enter(child, args);
}
SEC("fentry/cgroup_cancel_fork")
int BPF_PROG(in_cancel_enter, struct task_struct *child,
	     struct kernel_clone_args *args)
{
	return ingress_enter(child, args);
}
static __always_inline int ingress_finish(struct task_struct *child,
					  int cancelled)
{
	struct kernel_state *s = ingress_state();
	if (!s)
		return 0;
	__u64 key = (__u64)child;
	struct ingress_token *token = bpf_map_lookup_elem(&tokens, &key);
	if (!token)
		return 0; // No ownership, no decrement.
	__u32 zero = 0;
	struct in_config *c = bpf_map_lookup_elem(&config, &zero);
	if (!c) {
		ingress_uncertain(s);
		return 0;
	}
	__u64 creator = (__u64)bpf_get_current_task_btf(), cookie = 0;
	bpf_spin_lock(&token->lock);
	if (token->owned == 1 && token->creator == creator &&
	    token->nonce == c->nonce && token->target_kn == s->target_kn) {
		cookie = token->cookie;
		token->owned = 0;
	}
	bpf_spin_unlock(&token->lock);
	if (!cookie) {
		ingress_uncertain(s);
		return 0;
	}
	int overlap = 0;
	bpf_spin_lock(&s->lock);
	overlap = s->overlap_nonce && s->test_task == creator &&
		  s->overlap_ready && s->overlap_child == key &&
		  s->overlap_cookie == cookie;
	bpf_spin_unlock(&s->lock);
	// Real post/cancel fexit: kernel has released cgroup_mutex, but this
	// owned token remains inflight until factual publication below.
	if (overlap)
		overlap_wait_for(s, 1);
	int unknown = 0;
	if (!cancelled) {
		struct kernfs_node *actual = 0;
		if (BPF_CORE_READ_INTO(&actual, child, cgroups, dfl_cgrp,
				       procs_file.kn) ||
		    (__u64)actual != s->target_kn)
			unknown = 1;
	}
	// No pointer to token is used after delete, which immediately recycles its
	// preallocated cell. Child lifetime is protected by the fork/cancel call.
	if (bpf_map_delete_elem(&tokens, &key)) {
		ingress_uncertain(s);
		return 0; // Retain the count on structural deletion fault.
	}
	bpf_spin_lock(&s->lock);
	// Compact fact/unknown publication precedes owned release under the same lock
	// used by ARM. Full retained role history is deliberately not implemented here.
	if (unknown)
		s->uncertain = 1;
	s->last_fact_cookie = cookie;
	s->last_fact_child = key;
	s->last_fact_kind = unknown ? 3 : (cancelled ? 2 : 1);
	if (cancelled)
		s->ingress_cancelled++;
	else
		s->ingress_completed++;
	if (s->serial < ~0ULL)
		s->serial++;
	else
		s->uncertain = 1;
	if (s->ingress_inflight)
		s->ingress_inflight--;
	else
		s->uncertain = 1;
	bpf_spin_unlock(&s->lock);
	return 0;
}
SEC("fexit/cgroup_post_fork")
int BPF_PROG(in_post_exit, struct task_struct *child,
	     struct kernel_clone_args *args)
{
	return ingress_finish(child, 0);
}
SEC("fexit/cgroup_cancel_fork")
int BPF_PROG(in_cancel_exit, struct task_struct *child,
	     struct kernel_clone_args *args)
{
	return ingress_finish(child, 1);
}

char LICENSE[] SEC("license") = "GPL";
