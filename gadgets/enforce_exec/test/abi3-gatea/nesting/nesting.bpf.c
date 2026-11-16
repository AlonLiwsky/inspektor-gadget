// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "nesting.h"
#include "../ingress/lsm_result.h"
struct kernel_state {
	struct bpf_spin_lock lock;
	__u32 initialized;
	__u64 task, inode, cookie, sequence, active, outer_sequence;
	__u64 outer_hits, inner_hits, inner_sequence, acquired, released,
		failures;
	__u64 outer_intact, inner_clean, uncertain, errors;
	__s64 helper_result, insertion_error;
	__u64 order, op_fault;
};
_Static_assert(sizeof(struct kernel_state) == sizeof(struct nest_state),
	       "state ABI");
struct scratch {
	__u64 sentinel;
	char data[32];
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct nest_config);
} config SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u64);
} command SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct kernel_state);
} state SEC(".maps");
/* No NO_PREALLOC and no LRU: a live owner is never evicted. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 2);
	__type(key, struct nest_key);
	__type(value, struct scratch);
} scratch SEC(".maps");
extern int bpf_get_file_xattr(struct file *, const char *,
			      struct bpf_dynptr *) __ksym;
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;
SEC("syscall") int nest_init(void *ctx)
{
	__u32 z = 0;
	struct nest_config *c = bpf_map_lookup_elem(&config, &z);
	__u64 *nonce = bpf_map_lookup_elem(&command, &z);
	struct kernel_state *s = bpf_map_lookup_elem(&state, &z);
	if (!c || !nonce || !s || !c->nonce || *nonce != c->nonce ||
	    c->pid_tgid != bpf_get_current_pid_tgid() || s->initialized ||
	    c->fd >= 1024)
		return -22;
	struct task_struct *t = bpf_get_current_task_btf();
	struct fdtable *ft = 0;
	struct file **fds = 0, *f = 0;
	struct inode *inode = 0;
	__u32 limit = 0;
	bpf_rcu_read_lock();
	int err = BPF_CORE_READ_INTO(&ft, t, files, fdt);
	if (!err && ft)
		err = BPF_CORE_READ_INTO(&limit, ft, max_fds);
	else
		err = -22;
	if (!err && c->fd < limit)
		err = BPF_CORE_READ_INTO(&fds, ft, fd);
	else
		err = -22;
	if (!err && fds)
		err = bpf_probe_read_kernel(&f, sizeof(f), &fds[c->fd]);
	else
		err = -22;
	if (!err && f)
		err = BPF_CORE_READ_INTO(&inode, f, f_inode);
	else
		err = -22;
	if (!err && inode) {
		s->task = (__u64)t;
		s->inode = (__u64)inode;
		s->cookie =
			1 /* first and only nonzero physical-task cookie in this fresh object */
			;
		s->sequence = c->seed;
		s->initialized = 1;
	} else
		err = -22;
	bpf_rcu_read_unlock();
	return err;
}
static __always_inline int next(struct kernel_state *s, struct nest_key *k)
{
	int ok = 0;
	bpf_spin_lock(&s->lock);
	if (s->sequence != ~0ULL) {
		k->cookie = s->cookie;
		k->sequence = ++s->sequence;
		ok = 1;
	}
	bpf_spin_unlock(&s->lock);
	return ok;
}
static __always_inline int acquire(struct kernel_state *s, struct nest_key *k)
{
	struct scratch zero = { .sentinel = k->sequence };
	long error = bpf_map_update_elem(&scratch, k, &zero, BPF_NOEXIST);
	if (error) {
		s->insertion_error = error;
		s->failures++;
		s->uncertain = 1;
		s->op_fault = 1;
		return 0;
	}
	s->acquired++;
	return 1;
}
static __always_inline void release(struct kernel_state *s, struct nest_key *k,
				    int owned)
{
	if (!owned)
		return;
	if (bpf_map_delete_elem(&scratch, k)) {
		s->errors++;
		s->uncertain = 1;
		s->op_fault = 1;
	} else
		s->released++;
}
SEC("lsm/inode_permission")
long BPF_PROG(nest_inner, struct mnt_idmap *idmap, struct inode *inode,
	      int mask, int prior)
{
	__u32 z = 0;
	struct kernel_state *s = bpf_map_lookup_elem(&state, &z);
	struct nest_config *c = bpf_map_lookup_elem(&config, &z);
	if (!s || !c || !s->initialized || !s->active || !(mask & 4) ||
	    s->cookie != 1 || s->task != (__u64)bpf_get_current_task_btf() ||
	    s->inode != (__u64)inode)
		return in_lsm_result(prior);
	__u64 *nonce = bpf_map_lookup_elem(&command, &z);
	if (!nonce || *nonce != c->nonce)
		return in_lsm_result(prior);
	s->order = (s->order << 4) | 2;
	s->inner_hits++;
	struct nest_key k = {};
	int owned = 0;
	if (next(s, &k)) {
		s->inner_sequence = k.sequence;
		owned = acquire(s, &k);
	} else {
		s->failures++;
		s->uncertain = 1;
		s->op_fault = 1;
	}
	s->order = (s->order << 4) | (owned ? 3 : 4);
	struct nest_key outer = { .cookie = s->cookie,
				  .sequence = s->outer_sequence };
	struct scratch *v = bpf_map_lookup_elem(&scratch, &outer);
	if (v && v->sentinel == outer.sequence &&
	    (!k.sequence || k.sequence != outer.sequence))
		s->outer_intact++;
	else {
		s->errors++;
		s->uncertain = 1;
		s->op_fault = 1;
	}
	release(s, &k, owned);
	s->order = (s->order << 4) | 5;
	if (!k.sequence || !bpf_map_lookup_elem(&scratch, &k))
		s->inner_clean++;
	else {
		s->errors++;
		s->uncertain = 1;
		s->op_fault = 1;
	}
	return in_lsm_result(nest_result(prior, c->strict, s->op_fault));
}
SEC("lsm.s/file_open") long BPF_PROG(nest_outer, struct file *file, int prior)
{
	__u32 z = 0;
	struct kernel_state *s = bpf_map_lookup_elem(&state, &z);
	struct nest_config *c = bpf_map_lookup_elem(&config, &z);
	if (!s || !c || !s->initialized ||
	    s->task != (__u64)bpf_get_current_task_btf() ||
	    s->inode != (__u64)BPF_CORE_READ(file, f_inode))
		return in_lsm_result(prior);
	s->op_fault = 0;
	s->outer_hits++;
	struct nest_key k = {};
	int owned = 0;
	if (!next(s, &k)) {
		s->failures++;
		s->uncertain = 1;
		s->op_fault = 1;
		goto done;
	}
	owned = acquire(s, &k);
	if (!owned)
		goto done;
	s->order = (s->order << 4) | 1;
	struct scratch *v = bpf_map_lookup_elem(&scratch, &k);
	if (!v) {
		s->errors++;
		s->uncertain = 1;
		s->op_fault = 1;
		goto done;
	}
	struct bpf_dynptr ptr;
	if (bpf_dynptr_from_mem(v->data, sizeof(v->data), 0, &ptr)) {
		s->errors++;
		s->uncertain = 1;
		s->op_fault = 1;
		goto done;
	}
	s->outer_sequence = k.sequence;
	s->active = 1;
	s->helper_result = bpf_get_file_xattr(file, "user.ig15_probe", &ptr);
	s->active = 0;
	s->order = (s->order << 4) | 6;
	/* Re-lookup after real nesting; never trust a stale pointer after release. */
	v = bpf_map_lookup_elem(&scratch, &k);
	if (v && v->sentinel == k.sequence)
		s->outer_intact++;
	else {
		s->errors++;
		s->uncertain = 1;
		s->op_fault = 1;
	}
	if (!s->inner_hits) {
		s->errors++;
		s->uncertain = 1;
		s->op_fault = 1;
	}
done:
	release(s, &k, owned);
	if (owned)
		s->order = (s->order << 4) | 7;
	return in_lsm_result(nest_result(prior, c->strict, s->op_fault));
}
char LICENSE[] SEC("license") = "GPL";
