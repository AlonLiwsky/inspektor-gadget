/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
struct bpf_spin_lock {
	__u32 val;
};
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define EO_ABI 3
#define EO_VERIFIED 1U
#define EO_QUARANTINED 2U
#define EO_PENDING_BIRTH 8U
#define EO_FAULT_STATE 8
#define EO_FAULT_STORAGE 1
#define EO_FAULT_VERSION 32
#define EO_FAULT_LINEAGE 4
#define BPF_NOEXIST 1
static __u64 accepted[64];
#define ER_ACCEPTED_EPOCH(uid) ((uid) < 64 ? accepted[uid] : ~(__u64)0)
#include "epoch_roles.h"
struct fm_blob;
static const struct fm_blob *unused_blob(void *, unsigned int);
#define FM_BLOB_LOOKUP(ctx, key) unused_blob(ctx, key)
#include "../fullpolicy/bpf/evaluator.h"
static const struct fm_blob *unused_blob(void *ctx, unsigned int key)
{
	(void)ctx;
	(void)key;
	return 0;
}
static __u64 eo_accepted_epoch(__u64 uid)
{
	return ER_ACCEPTED_EPOCH(uid);
}
static struct fe_header active_header = { .generation = 1,
					  .policies = 1,
					  .rule_base = 9 };
static struct fe_policy active_policy = { .uid = 11,
					  .root_epoch = 1,
					  .root_role = 10,
					  .mode = 2 };
static const void *eo_program_blob(__u32 bank, __u32 key, __u64 generation)
{
	assert(bank == 0 && generation == 1);
	return key == 0 ? (const void *)&active_header :
	       key == 1 ? (const void *)&active_policy :
			  0;
}

/* ACTUAL_DISPATCH_TYPES */
/* ACTUAL_TASK_TYPES */
struct task_struct {
	__u64 group;
};
struct eo_config {
	__u64 cookie, cgroup;
	__u32 abi, gate_slot;
};
struct eo_health {
	__u64 authority_version, faults;
	__u32 retired;
};
static struct eo_config config = { 7, 42, EO_ABI, 0 };
static struct eo_health health = { .authority_version = 9 };
static struct eo_dispatch dispatch;
static struct eo_task parent, child;
static struct eo_work work;
static struct task_struct parent_physical = { 42 }, child_physical = { 42 };
static int locks, faults, fail_work;
static int eo_birth_groups;
static void (*before_parent_lock)(void);
static void bpf_spin_lock(struct bpf_spin_lock *lock)
{
	if (lock == &parent.lock && before_parent_lock && work.merge.prepared) {
		void (*inject)(void) = before_parent_lock;
		before_parent_lock = 0;
		inject();
	}
	assert(!locks && !lock->val);
	locks = lock->val = 1;
}
static void bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	assert(locks && lock->val);
	locks = lock->val = 0;
}
static struct eo_config *eo_config(void)
{
	assert(!locks);
	return &config;
}
static struct eo_health *eo_status(void)
{
	assert(!locks);
	return &health;
}
static struct eo_dispatch *eo_dispatch_state(void)
{
	assert(!locks);
	return &dispatch;
}
static struct task_struct *bpf_get_current_task_btf(void)
{
	return &parent_physical;
}
static __u64 bpf_get_current_cgroup_id(void)
{
	return 42;
}
static struct eo_task *eo_lookup_task(struct task_struct *task)
{
	return task == &parent_physical ? &parent : &child;
}
static struct eo_task *eo_get_task(struct task_struct *task)
{
	return eo_lookup_task(task);
}
static __u64 eo_task_cgroup(struct task_struct *task)
{
	return task->group;
}
static __u64 eo_group(struct task_struct *task)
{
	return task->group;
}
static void eo_fault(int bit)
{
	faults |= bit;
}
static int bpf_map_update_elem(void *map, void *key, void *value, int flags)
{
	(void)key;
	(void)value;
	assert(map == &eo_birth_groups && flags == BPF_NOEXIST);
	return 0;
}
static struct eo_work *eo_get_work(void)
{
	if (fail_work || work.busy)
		return 0;
	work.busy = 1;
	return &work;
}
static void eo_put_work(struct eo_work *w)
{
	assert(!w->reader.owned);
	w->busy = 0;
}
/* ACTUAL_TRANSITIONS */
/* ACTUAL_MUTATION */
/* ACTUAL_QUARANTINE */
/* ACTUAL_RELEASE */
/* ACTUAL_FORK */
static void reset(void)
{
	memset(&parent, 0, sizeof(parent));
	memset(&child, 0, sizeof(child));
	memset(&work, 0, sizeof(work));
	parent.cookie = 1;
	child.cookie = 2;
	parent.flags = EO_VERIFIED;
	parent.committed.version = 5;
	parent.committed.rows[0] = er_known_row(11, 1, 10);
	parent.committed.rows[1] =
		er_known_row(22, 1, 20); /* Removed policy, retained fact. */
	parent.committed.rows[2] = er_known_row(
		33, 2, 30); /* Provisional until catalogue accepts. */
	parent.exec.pending[0] =
		er_known_row(11, 1, 999); /* Never inherited. */
	memset(accepted, 0, sizeof(accepted));
	accepted[11] = accepted[22] = 1;
	dispatch = (struct eo_dispatch){ .scope_state = EO_SCOPE_ACTIVE,
					 .session_cookie = 7,
					 .cgroup = 42,
					 .serial = 1,
					 .active = { .generation = 1,
						     .execution_class = 1,
						     .policy_count = 1 } };
	faults = fail_work = 0;
	active_policy.mode = 1;
	before_parent_lock = 0;
}

static int mutation_kind;
static void mutate_parent(void)
{
	if (mutation_kind == 0) {
		eo_quarantine(&parent);
		return;
	}
	struct eo_reader_claim claim = {};
	assert(!eo_mutation_begin(&claim));
	bpf_spin_lock(&parent.lock);
	if (mutation_kind == 1)
		parent.committed.version++;
	if (mutation_kind == 2)
		parent.flags |= EO_PENDING_BIRTH;
	bpf_spin_unlock(&parent.lock);
	eo_mutation_end(&claim);
}
static void fork_missing_matrix(void)
{
	for (int mode = 1; mode <= 2; mode++)
		for (int missing = 0; missing < 4; missing++) {
			reset();
			dispatch.active.execution_class = mode;
			active_policy.mode = mode;
			if (missing == 1)
				memset(parent.committed.rows, 0,
				       sizeof(parent.committed.rows));
			if (missing == 2)
				parent.committed.rows[0].knowledge =
					ER_ROLE_UNKNOWN;
			if (missing == 3)
				parent.committed.rows[0].epoch = 3;
			int result = eo_fork_begin(&child_physical, 0, 0);
			assert(result == ((mode == 2 && missing) ? -1 : 0));
			if (result)
				assert(!eo_release_fork(&parent, 0, 1));
			else
				assert(!eo_fork_complete(&child_physical, 0));
			assert(!dispatch.fork_inflight &&
			       !dispatch.bank_readers[0] &&
			       !parent.fork.reader.owned);
			if (!missing)
				assert(child.flags == EO_VERIFIED);
			if (mode == 1 && missing == 1)
				assert(child.flags == EO_VERIFIED &&
				       !child.committed.rows[0].uid);
			if (mode == 1 && missing == 2)
				assert(child.flags == EO_VERIFIED &&
				       child.committed.rows[0].knowledge ==
					       ER_ROLE_UNKNOWN);
			if (mode == 1 && missing == 3)
				assert(!(child.flags & EO_VERIFIED));
		}
}
static void fork_mutation_matrix(void)
{
	for (mutation_kind = 0; mutation_kind < 3; mutation_kind++) {
		reset();
		assert(!eo_fork_begin(&child_physical, 0, 0));
		before_parent_lock = mutate_parent;
		assert(!eo_fork_complete(&child_physical, 0));
		assert(!before_parent_lock);
		assert(!(child.flags & EO_VERIFIED) &&
		       (child.flags & EO_QUARANTINED));
		for (int i = 0; i < ER_SLOTS; i++)
			assert(!child.committed.rows[i].uid);
		assert(!dispatch.fork_inflight && !dispatch.mutation_writers &&
		       !dispatch.bank_readers[0] && !parent.fork.reader.owned &&
		       !locks);
	}
}
int main(void)
{
	fork_mutation_matrix();
	fork_missing_matrix();
	for (int newly_accepted = 0; newly_accepted < 2; newly_accepted++) {
		reset();
		if (newly_accepted)
			accepted[33] = 2;
		assert(eo_fork_begin(&child_physical, 0, -13) == -13 &&
		       !dispatch.fork_inflight);
		assert(!eo_fork_begin(&child_physical, 0, 0));
		assert(parent.fork.reader.owned &&
		       dispatch.fork_inflight == 1 &&
		       dispatch.bank_readers[0] == 1);
		assert(!eo_fork_complete(&child_physical, 0));
		assert(child.flags == EO_VERIFIED &&
		       child.committed.version == 1);
		assert(child.committed.rows[0].role == 10 &&
		       child.committed.rows[1].role == 20);
		assert(child.committed.rows[2].uid ==
		       (newly_accepted ? 33 : 0));
		assert(!dispatch.fork_inflight && !dispatch.bank_readers[0] &&
		       !parent.fork.reader.owned && !faults);
		struct er_state saved = child.committed;
		assert(!eo_release_fork(&parent, &child_physical, 0));
		assert(!memcmp(&saved, &child.committed, sizeof(saved)));
		assert(eo_initialize_child_locked(&child, &work, child.cookie));
		assert(!memcmp(&saved, &child.committed, sizeof(saved)));
	}
	reset();
	assert(!eo_fork_begin(&child_physical, 0, 0));
	struct eo_reader_claim other = {};
	assert(!eo_dispatch_claim_begin_locked(&dispatch, &other, 77,
					       EO_READER_EXEC));
	assert(!eo_release_fork(&parent, 0, 1));
	assert(!eo_release_fork(&parent, 0, 1));
	assert(dispatch.exec_inflight == 1 && dispatch.bank_readers[0] == 1);
	assert(!eo_dispatch_claim_end_locked(&dispatch, &other));
	reset();
	parent.committed.rows[1].knowledge = ER_ROLE_UNKNOWN;
	assert(!eo_fork_begin(&child_physical, 0, 0));
	assert(!eo_fork_complete(&child_physical, 0));
	assert(child.committed.rows[1].knowledge == ER_ROLE_UNKNOWN &&
	       child.committed.rows[1].role == 20);
	/* Eligibility mutation is counted and changes serial, without nested locks. */
	__u64 serial = dispatch.serial;
	eo_quarantine(&parent);
	assert(parent.flags & EO_QUARANTINED);
	assert(dispatch.serial > serial && !dispatch.mutation_writers &&
	       !dispatch.bank_readers[0] && !locks);
	return 0;
}
