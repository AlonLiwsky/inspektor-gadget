// SPDX-License-Identifier: GPL-2.0
// Physical-task inventory ABI spike only: no role writes, lineage grants or Ready.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
extern struct cgroup *bpf_cgroup_from_id(__u64 id) __ksym;
extern void bpf_cgroup_release(struct cgroup *cgroup) __ksym;
extern int bpf_iter_css_task_new(struct bpf_iter_css_task *,
				 struct cgroup_subsys_state *,
				 unsigned int) __ksym;
extern struct task_struct *
bpf_iter_css_task_next(struct bpf_iter_css_task *) __ksym;
extern void bpf_iter_css_task_destroy(struct bpf_iter_css_task *) __ksym;
#define INVENTORY_LIMIT 4096
struct inventory_identity {
	__u64 cookie;
};
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct inventory_identity);
} identities SEC(".maps");
struct inventory_config {
	__u64 cgroup, epoch;
	__u32 owner_pid, limit;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct inventory_config);
} configuration SEC(".maps");
struct inventory_result {
	__u64 credits, epoch;
	__u32 count, status;
	__u64 busy;
};
// status: 0 complete, 1 config, 2 cgroup, 3 iterator, 4 budget, 5 allocation, 6 unstable/unarmed movement.
// Credits never decrease, even after task exit or failed allocation: finite lifetime bound.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct inventory_result);
} results SEC(".maps");
struct inventory_row {
	__u64 cookie;
	__u32 tid, tgid;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, INVENTORY_LIMIT);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct inventory_row);
} rows SEC(".maps");
// Fixture-only owner host TID; production PID namespace qualification is separate.
struct movement_control {
	__u32 owner_tid, arm, hold, release;
};
struct movement_state {
	__u64 sequence, armed, fault, reached;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct movement_control);
} movement_control SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct movement_state);
} movement_state SEC(".maps");
static __always_inline int movement_change(int entering)
{
	__u32 k = 0;
	struct movement_state *s = bpf_map_lookup_elem(&movement_state, &k);
	if (!s || !s->armed || s->fault)
		return 0;
	// Both outer migration functions are serialized by cgroup_mutex.
	__u64 seq = __sync_fetch_and_add(&s->sequence, 0);
	if (seq >= ~0ULL - 1 || ((seq & 1) != (!entering))) {
		s->fault = 1;
		return 0;
	}
	__sync_fetch_and_add(&s->sequence, 1);
	return 0;
}
SEC("fentry/cgroup_migrate") int BPF_PROG(migrate_enter)
{
	return movement_change(1);
}
SEC("fexit/cgroup_migrate") int BPF_PROG(migrate_exit)
{
	return movement_change(0);
}
SEC("fentry/cgroup_update_dfl_csses") int BPF_PROG(reconfigure_enter)
{
	return movement_change(1);
}
SEC("fexit/cgroup_update_dfl_csses") int BPF_PROG(reconfigure_exit)
{
	return movement_change(0);
}
SEC("fexit/cgroup_kn_lock_live")
int BPF_PROG(movement_arm, struct kernfs_node *kn, bool drain,
	     struct cgroup *result)
{
	__u32 k = 0;
	struct movement_control *c = bpf_map_lookup_elem(&movement_control, &k);
	struct movement_state *s = bpf_map_lookup_elem(&movement_state, &k);
	if (!c || !s || !c->arm || s->armed ||
	    c->owner_tid != (__u32)bpf_get_current_pid_tgid())
		return 0;
	if (!result || (__u64)result >= ~4095ULL)
		return 0;
	// Successful return still holds cgroup_mutex: pre-attachment migrations drained.
	s->sequence = 0;
	s->fault = 0;
	s->armed = 1;
	return 0;
}
static long hold_step(__u32 index, void *unused)
{
	__u32 k = 0;
	struct movement_control *c = bpf_map_lookup_elem(&movement_control, &k);
	return !c || c->release;
}
struct deny_config {
	__u32 owner_tid, target_tgid;
	__u64 cookie;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct deny_config);
} deny_config SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} denied SEC(".maps");
SEC("lsm/task_setscheduler")
int BPF_PROG(deny_fixture_attach, struct task_struct *task, int ret)
{
	if (ret)
		return ret;
	__u32 k = 0;
	struct deny_config *c = bpf_map_lookup_elem(&deny_config, &k);
	struct movement_state *s = bpf_map_lookup_elem(&movement_state, &k);
	if (!c || !s || !c->cookie ||
	    c->owner_tid != (__u32)bpf_get_current_pid_tgid() ||
	    task->tgid != c->target_tgid || !s->armed || s->fault ||
	    !(s->sequence & 1))
		return 0;
	struct inventory_identity *id =
		bpf_task_storage_get(&identities, task, 0, 0);
	if (!id || id->cookie != c->cookie)
		return 0;
	__u64 *n = bpf_map_lookup_elem(&denied, &k);
	if (n)
		__sync_fetch_and_add(n, 1);
	return -1;
}
struct drain_control {
	__u32 writer_tid, release, target_tgid, padding;
};
struct drain_state {
	__u64 reached, expired, barrier_attempt;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct drain_control);
} drain_control SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct drain_state);
} drain_state SEC(".maps");
static long drain_step(__u32 index, void *ctx)
{
	__u32 k = 0;
	struct drain_control *c = bpf_map_lookup_elem(&drain_control, &k);
	__u64 *deadline = ctx;
	return !c || c->release || bpf_ktime_get_ns() >= *deadline;
}
// Test only: cpuset can_attach calls this sleepable LSM outside css_set_lock.
SEC("lsm.s/task_setscheduler")
int BPF_PROG(drain_hold, struct task_struct *task, int ret)
{
	if (ret)
		return ret;
	__u32 k = 0;
	struct drain_control *c = bpf_map_lookup_elem(&drain_control, &k);
	struct drain_state *s = bpf_map_lookup_elem(&drain_state, &k);
	if (!c || !s || !c->writer_tid ||
	    c->writer_tid != (__u32)bpf_get_current_pid_tgid() ||
	    task->tgid != c->target_tgid || c->release)
		return 0;
	s->reached = 1;
	__u64 deadline = bpf_ktime_get_ns() + 1000000000ULL;
	bpf_loop(8388608, drain_step, &deadline, 0);
	c = bpf_map_lookup_elem(&drain_control, &k);
	if (!c || !c->release)
		s->expired = 1;
	return 0;
}
SEC("fentry/cgroup_kn_lock_live") int BPF_PROG(drain_barrier_entry)
{
	__u32 k = 0;
	struct movement_control *c = bpf_map_lookup_elem(&movement_control, &k);
	struct drain_state *s = bpf_map_lookup_elem(&drain_state, &k);
	if (c && s && c->arm &&
	    c->owner_tid == (__u32)bpf_get_current_pid_tgid())
		s->barrier_attempt = 1;
	return 0;
}
static __always_inline int inventory_run(void)
{
	__u32 zero = 0;
	struct inventory_config *c = bpf_map_lookup_elem(&configuration, &zero);
	struct inventory_result *r = bpf_map_lookup_elem(&results, &zero);
	if (!c || !r || c->owner_pid != (bpf_get_current_pid_tgid() >> 32))
		return 0;
	if (__sync_val_compare_and_swap(&r->busy, 0, 1))
		return 0;
	r->count = 0;
	r->status = 1;
	r->epoch = c->epoch;
	struct movement_state *s = bpf_map_lookup_elem(&movement_state, &zero);
	if (!s || !s->armed || s->fault) {
		r->status = 6;
		goto done;
	}
	__u64 sequence = __sync_fetch_and_add(&s->sequence, 0);
	if (sequence & 1) {
		r->status = 6;
		goto done;
	}
	if (!c->epoch || !c->cgroup || !c->limit || c->limit > INVENTORY_LIMIT)
		goto done;
	struct cgroup *group = bpf_cgroup_from_id(c->cgroup);
	if (!group) {
		r->status = 2;
		goto done;
	}
	struct bpf_iter_css_task iterator;
	int ret = bpf_iter_css_task_new(&iterator, &group->self, 0);
	if (ret) {
		r->status = 3;
		goto destroy;
	}
	r->status = 4;
	for (__u32 i = 0; i <= INVENTORY_LIMIT; i++) {
		struct task_struct *task = bpf_iter_css_task_next(&iterator);
		if (!task) {
			r->status = 0;
			break;
		}
		if (i >= INVENTORY_LIMIT)
			break;
		if (i == 0) {
			struct movement_control *control =
				bpf_map_lookup_elem(&movement_control, &zero);
			if (control && control->hold) {
				s->reached = 1;
				bpf_loop(8388608, hold_step, 0, 0);
				control = bpf_map_lookup_elem(&movement_control,
							      &zero);
				if (!control || !control->release) {
					r->status = 7;
					break;
				}
			}
		}
		struct inventory_identity *identity =
			bpf_task_storage_get(&identities, task, 0, 0);
		if (!identity) {
			if (r->credits >= c->limit)
				break;
			// Owner invocation is serialized; the global fixture counter never wraps.
			__u64 cookie = __sync_add_and_fetch(&r->credits, 1);
			if (!cookie || cookie > INVENTORY_LIMIT)
				break;
			identity = bpf_task_storage_get(
				&identities, task, 0,
				BPF_LOCAL_STORAGE_GET_F_CREATE);
			if (!identity) {
				r->status = 5;
				break;
			}
			__sync_val_compare_and_swap(&identity->cookie, 0,
						    cookie);
		}
		if (!identity->cookie) {
			r->status = 5;
			break;
		}
		struct inventory_row *row = bpf_map_lookup_elem(&rows, &i);
		if (!row) {
			r->status = 5;
			break;
		}
		row->cookie = identity->cookie;
		row->tid = task->pid;
		row->tgid = task->tgid;
		r->count = i + 1;
	}
destroy:
	bpf_iter_css_task_destroy(&iterator);
	bpf_cgroup_release(group);
	if (s->fault || __sync_fetch_and_add(&s->sequence, 0) != sequence)
		r->status = 6;
done:
	__sync_lock_test_and_set(&r->busy, 0);
	return 0;
}
SEC("syscall") int inventory_syscall(void *unused)
{
	return inventory_run();
}
// Fallback ABI probe only if syscall program type lacks required helpers.
SEC("fentry.s/__x64_sys_getpgid") int BPF_PROG(inventory_trace)
{
	return inventory_run();
}
char LICENSE[] SEC("license") = "GPL";
