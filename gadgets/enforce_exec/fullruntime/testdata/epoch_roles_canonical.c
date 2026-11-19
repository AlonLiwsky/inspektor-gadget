/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
static __u64 catalogue[64];
#define ER_ACCEPTED_EPOCH(uid) ((uid) < 64 ? catalogue[uid] : ~(__u64)0)
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#include "epoch_roles.h"

static void snapshot(struct er_canonical_view *view,
		     const struct er_state *state)
{
	memset(view, 0, sizeof(*view));
	er_snapshot(&view->work, state, 7);
	assert(!er_canonical_classify(view));
}
static struct er_candidate candidate(__u64 uid, __u64 epoch, __u64 root,
				     int fresh)
{
	return (struct er_candidate){ .count = 1,
				      .active = { { .uid = uid,
						    .epoch = epoch,
						    .root = root,
						    .new_uid = fresh } } };
}
static void stage(struct er_state *state, struct er_candidate c)
{
	struct er_canonical_view view;
	snapshot(&view, state);
	assert(!er_canonical_stage_prepare(&view, &c, 1));
	assert(!er_canonical_stage_publish(state, &view, 7));
}
static void malformed_late_patch_index(void)
{
	const __u32 invalid_indices[] = { 16, UINT32_MAX };
	struct er_state state = { .version = 7 };
	state.rows[0] = er_known_row(60, 1, 10);
	state.rows[1] = er_known_row(61, 1, 20);
	/* An unaccepted candidate at the other masked index must survive too. */
	state.rows[15] = er_known_row(62, 2, 30);
	catalogue[60] = catalogue[61] = 1;
	struct er_canonical_view view;
	snapshot(&view, &state);
	assert(view.accepted_mask == 3);
	struct er_row desired[] = { er_known_row(60, 1, 11),
				    er_known_row(61, 1, 21) };
	struct er_state saved = state;
	for (unsigned int i = 0;
	     i < sizeof(invalid_indices) / sizeof(invalid_indices[0]); i++) {
		struct er_fact_patch patch;
		assert(!er_canonical_patch_prepare(&view, desired, 2, &patch));
		assert(patch.count == 2 && patch.changes[0].index == 0 &&
		       patch.changes[1].index == 1);
		/* The first target changes a fact, but the late invalid index must
		 * reject before any store, not alias through the publisher's mask. */
		patch.changes[1].index = invalid_indices[i];
		assert(er_canonical_patch_publish(&state, &patch, 7) ==
		       ER_INVALID);
		assert(!memcmp(&saved, &state, sizeof(state)));
	}
	catalogue[60] = catalogue[61] = 0;
}
int main(void)
{
	malformed_late_patch_index();
	catalogue[1] = 1;
	for (int schedule = 0; schedule < 3; schedule++) {
		struct er_state state = { .version = 1 };
		state.rows[0] = er_known_row(1, 1, 10);
		struct er_canonical_view view;
		struct er_fact_patch patch;
		struct er_row desired = er_known_row(1, 1, 11);
		if (schedule == 0)
			stage(&state, candidate(2, 2, 20, 1));
		snapshot(&view, &state);
		if (schedule == 1)
			stage(&state, candidate(2, 2, 20, 1));
		assert(!er_canonical_patch_prepare(&view, &desired, 1, &patch));
		if (schedule == 2)
			stage(&state, candidate(2, 2, 20, 1));
		assert(state.version == 1);
		assert(!er_canonical_patch_publish(&state, &patch, 7));
		assert(state.version == 2 && state.rows[0].role == 11 &&
		       state.rows[1].uid == 2);
		/* Failed exec/known deny publish no transition, preserving all bytes. */
		struct er_state saved = state;
		snapshot(&view, &state);
		assert(!er_canonical_patch_prepare(&view, 0, 0, &patch));
		assert(!er_canonical_patch_publish(&state, &patch, 7));
		assert(!memcmp(&saved, &state, sizeof(state)));
		/* Stale stage cannot roll back a completed factual transition. */
		assert(!er_canonical_stage_prepare(
			&view, &(struct er_candidate){}, 1));
		state.version++;
		saved = state;
		assert(er_canonical_stage_publish(&state, &view, 7) ==
		       ER_STALE);
		assert(!memcmp(&saved, &state, sizeof(state)));
	}
	struct er_state state = { .version = 1 };
	state.rows[0] = er_known_row(1, 1, 10);
	state.rows[0].knowledge = ER_ROLE_UNKNOWN;
	stage(&state,
	      candidate(1, 1, 999, 0)); /* Root edits do not repair UNKNOWN. */
	assert(state.rows[0].role == 10 &&
	       state.rows[0].knowledge == ER_ROLE_UNKNOWN);
	stage(&state, (struct er_candidate){}); /* Removed history retained. */
	stage(&state, candidate(1, 1, 888, 0));
	assert(state.rows[0].role == 10 && state.version == 1);
	stage(&state, candidate(2, 2, 20, 1));
	stage(&state,
	      candidate(2, 3, 30,
			1)); /* Failed A, retry B reuses unaccepted cell. */
	assert(state.rows[1].epoch == 3 && state.rows[1].role == 30);
	struct er_canonical_view view;
	snapshot(&view, &state);
	struct er_work inherited;
	assert(!er_canonical_project(&view, &inherited));
	assert(inherited.rows[0].uid == 1 && !inherited.rows[1].uid);
	struct er_canonical_view stale_abort;
	snapshot(&stale_abort, &state);
	assert(!er_canonical_stage_prepare(&stale_abort,
					   &(struct er_candidate){}, 1));
	catalogue[2] =
		3; /* ARM acceptance in place; old candidate stamp is irrelevant. */
	struct er_state accepted = state;
	assert(er_canonical_stage_publish(&state, &stale_abort, 8) == ER_STALE);
	assert(!memcmp(&accepted, &state, sizeof(state)));
	snapshot(&view, &state);
	assert(!er_canonical_project(&view, &inherited));
	assert(inherited.rows[1].uid == 2 && inherited.rows[1].role == 30);
	stage(&state,
	      (struct er_candidate){}); /* Abort/reclamation never erases accepted. */
	assert(state.rows[1].uid == 2);
	struct er_state saved = state;
	struct er_fact_patch patch;
	struct er_row desired[2] = { er_known_row(1, 1, 12),
				     er_known_row(2, 3, 31) };
	snapshot(&view, &state);
	assert(!er_canonical_patch_prepare(&view, desired, 2, &patch));
	patch.changes[1].before.epoch =
		999; /* Last target refuses before first store. */
	assert(er_canonical_patch_publish(&state, &patch, 7));
	assert(!memcmp(&saved, &state, sizeof(state)));
	assert(!er_canonical_patch_prepare(&view, desired, 2, &patch));
	assert(er_canonical_patch_publish(&state, &patch, 8));
	assert(!memcmp(&saved, &state, sizeof(state)));
	desired[0].epoch = 9;
	assert(er_canonical_patch_prepare(&view, desired, 1, &patch));
	desired[0] = er_known_row(3, 3, 3);
	assert(er_canonical_patch_prepare(&view, desired, 1, &patch));
	for (int malformed = 0; malformed < 3; malformed++) {
		catalogue[1] = malformed == 0 ? ER_UNKNOWN :
			       malformed == 1 ? 9 :
						1;
		if (malformed == 2)
			state.rows[0].reserved = 1;
		er_snapshot(&view.work, &state, 7);
		struct er_state before = state;
		assert(er_canonical_classify(&view));
		assert(!memcmp(&before, &state, sizeof(state)));
	}
	state = saved;
	catalogue[1] = 1;
	/* Missing accepted row does not get a root, even from a new root spelling. */
	state.rows[0] = (struct er_row){};
	stage(&state, candidate(1, 1, 99, 0));
	assert(!state.rows[0].uid);
	/* All sixteen accepted slots persist; no capacity shrink, seventeenth fails. */
	memset(&state, 0, sizeof(state));
	state.version = 5;
	for (int i = 0; i < 16; i++) {
		catalogue[i + 1] = 1;
		state.rows[i] = er_known_row(i + 1, 1, i + 10);
	}
	stage(&state, candidate(1, 1, 999, 0));
	saved = state;
	snapshot(&view, &state);
	struct er_candidate extra = candidate(17, 6, 17, 1);
	assert(er_canonical_stage_prepare(&view, &extra, 1) == ER_CAPACITY);
	assert(er_canonical_stage_publish(&state, &view, 7) == ER_CAPACITY);
	assert(!memcmp(&saved, &state, sizeof(state)));
	/* Retrying and aborting the same UID set does not consume new cells. */
	memset(&state.rows[15], 0, sizeof(state.rows[15]));
	catalogue[16] = 0;
	for (int retry = 0; retry < 100; retry++) {
		stage(&state, candidate(17, 100 + retry, 1000 + retry, 1));
		assert(state.rows[15].uid == 17 && state.version == 5);
		stage(&state, (struct er_candidate){});
		assert(!state.rows[15].uid && state.version == 5);
	}
	/* Factual overflow is a refusal, never wrapping authority. */
	state.version = ER_UNKNOWN - 1;
	snapshot(&view, &state);
	desired[0] = er_known_row(1, 1, 77);
	assert(!er_canonical_patch_prepare(&view, desired, 1, &patch));
	saved = state;
	assert(er_canonical_patch_publish(&state, &patch, 7) == ER_STALE);
	assert(!memcmp(&saved, &state, sizeof(state)));
	return 0;
}
