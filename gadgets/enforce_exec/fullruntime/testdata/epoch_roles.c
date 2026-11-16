#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
static __u64 history[64];
static __u64 accepted(__u64 uid)
{
	return uid < 64 ? history[uid] : UINT64_MAX;
}
#define ER_ACCEPTED_EPOCH(uid) accepted(uid)
#include "epoch_roles.h"
static struct er_candidate candidate(__u64 uid, __u64 epoch, __u64 root,
				     int isnew)
{
	return (struct er_candidate){
		.count = 1, .active = { { uid, epoch, root, isnew, 0 } }
	};
}
static void unchanged(struct er_state *state, struct er_state before,
		      struct er_work *work, int want)
{
	assert(er_publish(state, work, 100) == want);
	assert(!memcmp(state, &before, sizeof(before)));
}
int main(void)
{
	struct er_state state = { 0 }, before;
	struct er_work work, old;
	struct er_candidate c = candidate(1, 9, 90, 1);
	er_snapshot(&work, &state, 100);
	assert(!er_stage_roots(&work, &c, 1));
	assert(!er_publish(&state, &work, 100));
	assert(state.rows[0].role == 90);
	/* Failed A has no successful-history entry. Retry B may reclaim A. */
	c = candidate(1, 10, 100, 1);
	er_snapshot(&work, &state, 100);
	assert(!er_stage_roots(&work, &c, 1));
	assert(!er_publish(&state, &work, 100));
	assert(state.rows[0].epoch == 10 && state.rows[0].role == 100);
	/* Successful activation makes retained scalar roles authoritative forever,
     * including removal and re-addition with a newly authored root role. */
	history[1] = 10;
	state.rows[0].role = 777;
	state.version++;
	c = candidate(1, 10, 999, 0);
	er_snapshot(&work, &state, 100);
	assert(!er_stage_roots(&work, &c, 1));
	assert(!er_publish(&state, &work, 100));
	assert(state.rows[0].role == 777);
	c = (struct er_candidate){};
	er_snapshot(&work, &state, 100);
	assert(!er_stage_roots(&work, &c, 1));
	assert(!er_publish(&state, &work, 100));
	assert(state.rows[0].role == 777);
	c = candidate(1, 10, 999, 0);
	er_snapshot(&work, &state, 100);
	assert(!er_stage_roots(&work, &c, 1));
	assert(!er_publish(&state, &work, 100));
	assert(state.rows[0].role == 777);
	/* Accepted UID with absent state never receives an implicit root. */
	state = (struct er_state){};
	er_snapshot(&work, &state, 100);
	assert(!er_stage_roots(&work, &c, 1));
	assert(!er_publish(&state, &work, 100));
	assert(!state.rows[0].uid);
	/* Inherit committed scalar values, not destination overwrite. */
	struct er_row source[ER_SLOTS] = { { 1, 10, 444 } };
	state.rows[0] = (struct er_row){ 1, 10, 777 };
	er_snapshot(&work, &state, 100);
	assert(!er_inherit(&work, &c, source));
	assert(!er_publish(&state, &work, 100));
	assert(state.rows[0].role == 777);
	state = (struct er_state){};
	er_snapshot(&work, &state, 100);
	assert(!er_inherit(&work, &c, source));
	assert(!er_publish(&state, &work, 100));
	assert(state.rows[0].role == 444);
	/* Stale failed epoch cannot replace accepted state, or silently disappear. */
	source[0].epoch = 9;
	before = state;
	er_snapshot(&work, &state, 100);
	assert(er_inherit(&work, &c, source) == ER_INVALID);
	unchanged(&state, before, &work, ER_INVALID);
	/* New staged roots inherit only for this candidate; pending-like role is
     * invalid. Unactivated rows from older attempts are ignored/reclaimed. */
	c = candidate(2, 12, 120, 1);
	source[0] = (struct er_row){ 2, 12, 120 };
	er_snapshot(&work, &state, 100);
	assert(!er_inherit(&work, &c, source));
	assert(!er_publish(&state, &work, 100));
	assert(state.rows[1].uid == 2 && state.rows[1].role == 120);
	source[0].role = 121;
	before = state;
	er_snapshot(&work, &state, 100);
	assert(er_inherit(&work, &c, source) == ER_INVALID);
	unchanged(&state, before, &work, ER_INVALID);
	source[0] = (struct er_row){ 3, 11, 110 };
	er_snapshot(&work, &state, 100);
	assert(!er_inherit(&work, &c, source));
	assert(!er_publish(&state, &work, 100));
	assert(state.rows[1].uid == 2 && !state.rows[2].uid);
	/* Unknown lineage refuses even an otherwise valid root. */
	for (int lineage = -1; lineage <= 2; lineage++)
		if (lineage != 1) {
			before = state;
			er_snapshot(&work, &state, 100);
			assert(er_stage_roots(&work, &c, lineage) ==
			       ER_LINEAGE);
			unchanged(&state, before, &work, ER_LINEAGE);
		}
	/* Retained 16-row history cannot be evicted for a 17th accepted/new UID. */
	memset(history, 0, sizeof(history));
	state = (struct er_state){};
	for (int i = 0; i < ER_SLOTS; i++) {
		history[i + 1] = 2;
		state.rows[i] = (struct er_row){ i + 1, 2, 100 + i };
	}
	c = candidate(17, 30, 300, 1);
	before = state;
	er_snapshot(&work, &state, 100);
	assert(er_stage_roots(&work, &c, 1) == ER_CAPACITY);
	unchanged(&state, before, &work, ER_CAPACITY);
	/* Full sixteen-row inheritance includes accepted policies absent from the
     * candidate. A seventeenth accepted source must not displace any row. */
	memcpy(source, state.rows, sizeof(source));
	state = (struct er_state){};
	c = (struct er_candidate){};
	er_snapshot(&work, &state, 100);
	assert(!er_inherit(&work, &c, source));
	assert(!er_publish(&state, &work, 100));
	for (int i = 0; i < ER_SLOTS; i++)
		assert(state.rows[i].uid == (__u64)(i + 1));
	memset(source, 0, sizeof(source));
	source[0] = (struct er_row){ 17, 2, 170 };
	history[17] = 2;
	before = state;
	er_snapshot(&work, &state, 100);
	assert(er_inherit(&work, &c, source) == ER_CAPACITY);
	unchanged(&state, before, &work, ER_CAPACITY);
	/* Eight active authorities are supported; nine cannot access out of bounds. */
	state = (struct er_state){};
	memset(history, 0, sizeof(history));
	c = (struct er_candidate){ .count = ER_ACTIVE };
	for (int i = 0; i < ER_ACTIVE; i++)
		c.active[i] = (struct er_authority){ i + 1, 40, 400 + i, 1, 0 };
	er_snapshot(&work, &state, 100);
	assert(!er_stage_roots(&work, &c, 1));
	assert(!er_publish(&state, &work, 100));
	for (int i = 0; i < ER_ACTIVE; i++)
		assert(state.rows[i].role == (__u64)(400 + i));
	c.count++;
	before = state;
	er_snapshot(&work, &state, 100);
	assert(er_stage_roots(&work, &c, 1) == ER_INVALID);
	unchanged(&state, before, &work, ER_INVALID);
	c.count--;
	/* Mid-operation capacity failure may change work, never live state. */
	state = (struct er_state){};
	memset(history, 0, sizeof(history));
	for (int i = 0; i < 15; i++) {
		history[i + 1] = 2;
		state.rows[i] = (struct er_row){ i + 1, 2, 100 + i };
	}
	c = (struct er_candidate){ .count = 2,
				   .active = { { 20, 40, 400, 1, 0 },
					       { 21, 40, 401, 1, 0 } } };
	before = state;
	er_snapshot(&work, &state, 100);
	assert(er_stage_roots(&work, &c, 1) == ER_CAPACITY);
	assert(work.rows[15].uid == 20);
	unchanged(&state, before, &work, ER_CAPACITY);
	/* Version mismatch and authority changes refuse stale publication. */
	c = (struct er_candidate){};
	er_snapshot(&work, &state, 100);
	assert(!er_stage_roots(&work, &c, 1));
	old = work;
	assert(!er_stage_roots(&work, &c, 1));
	assert(!er_publish(&state, &work, 100));
	before = state;
	unchanged(&state, before, &old, ER_STALE);
	er_snapshot(&work, &state, 99);
	assert(!er_stage_roots(&work, &c, 1));
	unchanged(&state, before, &work, ER_STALE);
	state.version = UINT64_MAX;
	before = state;
	er_snapshot(&work, &state, 100);
	assert(!er_stage_roots(&work, &c, 1));
	unchanged(&state, before, &work, ER_STALE);
	/* Malformed/duplicate rows, forged accepted epochs/newness and unavailable
     * history all fail without publishing a partially sanitized work copy. */
	for (int failure = 0; failure < 7; failure++) {
		state = (struct er_state){};
		memset(history, 0, sizeof(history));
		c = candidate(1, 2, 20, 1);
		switch (failure) {
		case 0:
			state.rows[0] = (struct er_row){ 0, 2, 3 };
			break;
		case 1:
			state.rows[0] = state.rows[1] =
				(struct er_row){ 1, 2, 20 };
			break;
		case 2:
			history[1] = 1;
			break;
		case 3:
			c.active[0].new_uid = 0;
			break;
		case 4:
			c.active[0].uid = 64;
			break;
		case 5:
			c.active[0].epoch = UINT64_MAX;
			break;
		case 6:
			c.count = 2;
			c.active[1] = c.active[0];
			break;
		}
		before = state;
		er_snapshot(&work, &state, 100);
		assert(er_stage_roots(&work, &c, 1) == ER_INVALID);
		unchanged(&state, before, &work, ER_INVALID);
	}
	puts("epoch roles: rollback, retained16/active8, stale publication and lineage refusal PASS");
	return 0;
}
