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
#define EO_VERIFIED 1U
#define EO_QUARANTINED 2U
#define EO_PENDING_BIRTH 8U
#define ER_ACCEPTED_EPOCH(uid) ((uid) == 11 || (uid) == 22 ? 1 : 0)
#include "epoch_roles.h"
/* ACTUAL_DISPATCH_TYPES */
/* ACTUAL_TASK_TYPES */
struct task_struct {
	int unused;
};
struct eo_health {
	__u64 authority_version;
	__u32 retired;
};
struct eo_config {
	__u64 cookie;
};
static struct eo_health health = { .authority_version = 9 };
static struct eo_config config = { .cookie = 7 };
static struct eo_dispatch dispatch;
static struct eo_work work;
static int locks;
static void bpf_spin_lock(struct bpf_spin_lock *lock)
{
	assert(!locks && !lock->val);
	locks = lock->val = 1;
}
static void bpf_spin_unlock(struct bpf_spin_lock *lock)
{
	assert(locks && lock->val);
	locks = lock->val = 0;
}
static struct eo_health *eo_status(void)
{
	assert(!locks);
	return &health;
}
static struct eo_config *eo_config(void)
{
	assert(!locks);
	return &config;
}
static struct eo_dispatch *eo_dispatch_state(void)
{
	assert(!locks);
	return &dispatch;
}
static struct eo_work *eo_borrow_work(void)
{
	return &work;
}
static int eo_current_admin(__u64 cookie)
{
	return cookie == 7;
}
/* ACTUAL_TRANSITIONS */
/* ACTUAL_TASK_STAGE */
/* ACTUAL_STAGE_WRAPPER */
int main(void)
{
	_Static_assert(sizeof(struct eo_task) == 1088, "canonical task ABI");
	_Static_assert(sizeof(struct eo_work) == 2648, "canonical scratch ABI");
	dispatch = (struct eo_dispatch){ .scope_state = EO_SCOPE_ACTIVE,
					 .session_cookie = 7,
					 .cgroup = 42,
					 .serial = 1,
					 .active = { .generation = 1,
						     .execution_class = 1,
						     .policy_count = 2 } };
	assert(!eo_candidate_begin_locked(&dispatch, 7, 2, 11));
	assert(!eo_candidate_seal_begin_locked(&dispatch, 7, 2));
	assert(!eo_candidate_seal_finish_locked(&dispatch, 7, 2, 1, 3, 4, 1,
						1));
	assert(!eo_candidate_snapshot_locked(&dispatch, 7, 2));
	struct eo_writer_token writer = {};
	assert(!eo_candidate_stage_begin_locked(&dispatch, 7, 2, &writer,
						&work.reader,
						&work.source_descriptor));
	work.busy = 1;
	work.authority = 9;
	work.stage_request.pass_id = dispatch.candidate.pass_id;
	work.stage_request.pass_start_serial =
		dispatch.candidate.pass_start_serial;
	work.candidate =
		(struct er_candidate){ .count = 3,
				       .active = { { 11, 1, 99, 0, 0 },
						   { 22, 1, 88, 0, 0 },
						   { 33, 2, 30, 1, 0 } } };
	struct eo_task task = { .cookie = 8, .flags = EO_VERIFIED };
	task.committed.version = 5;
	task.committed.rows[0] = er_known_row(11, 1, 10);
	task.committed.rows[1] = er_known_row(22, 1, 20);
	task.committed.rows[1].knowledge = ER_ROLE_UNKNOWN;
	struct task_struct physical = {};
	assert(!eo_stage_candidate_task(&physical, &task, &work, 1));
	assert(task.committed.version == 5 &&
	       task.committed.rows[0].role == 10 &&
	       task.committed.rows[1].knowledge == ER_ROLE_UNKNOWN &&
	       task.committed.rows[2].uid == 33);
	assert(task.staged.pass_id == dispatch.candidate.pass_id &&
	       task.staged.fact_version == 5);
	assert(dispatch.candidate.inventory_count == 1);
	assert(eo_stage_candidate_task(&physical, &task, &work, 1) == 1);
	assert(dispatch.candidate.inventory_count == 1);
	struct eo_task before = task;
	assert(eo_stage_candidate_task(&physical, &task, &work, 2) < 0);
	assert(!memcmp(&before, &task, sizeof(task)));
	task.flags = 0;
	before = task;
	assert(eo_stage_candidate_task(&physical, &task, &work, 1) < 0);
	assert(!memcmp(&before, &task,
		       sizeof(task))); /* No lineage adoption. */
	task.flags = EO_VERIFIED;
	/* A factual completion after staging preserves provisional and the stamp. */
	struct er_canonical_view view = {};
	er_snapshot(&view.work, &task.committed, 9);
	assert(!er_canonical_classify(&view));
	struct er_row desired = er_known_row(11, 1, 77);
	struct er_fact_patch patch;
	assert(!er_canonical_patch_prepare(&view, &desired, 1, &patch));
	struct eo_stage_stamp stamp = task.staged;
	assert(!er_canonical_patch_publish(&task.committed, &patch, 9));
	assert(task.committed.rows[2].uid == 33 &&
	       !memcmp(&stamp, &task.staged, sizeof(stamp)));
	before = task;
	assert(eo_stage_task_locked(&task, &work, 8, 2, 0, 9, 1) < 0);
	assert(!memcmp(&before, &task, sizeof(task)));
	/* An admission invalidates rolling serial even after its count is released. */
	struct eo_reader_claim admitted = {};
	assert(!eo_dispatch_claim_begin_locked(&dispatch, &admitted, 99,
					       EO_READER_EXEC));
	assert(!eo_dispatch_claim_end_locked(&dispatch, &admitted));
	assert(eo_stage_candidate_task(&physical, &task, &work, 1) < 0);
	assert(!memcmp(&before, &task, sizeof(task)));
	assert(!eo_candidate_stage_end_locked(&dispatch, &writer, &work.reader,
					      &work.source_descriptor));
	assert(eo_candidate_certify_locked(&dispatch, 7, 2, 1, 1));
	assert(eo_stage_candidate_task(&physical, &task, &work, 1) <
	       0); /* Released scratch. */
	assert(!eo_candidate_snapshot_locked(&dispatch, 7, 2));
	assert(dispatch.candidate.pass_id == 2 &&
	       dispatch.candidate.inventory_count == 0);
	assert(!locks);
	return 0;
}
