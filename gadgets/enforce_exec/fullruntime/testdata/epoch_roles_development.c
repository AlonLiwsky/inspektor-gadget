/* SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
static __u64 accepted(__u64 uid)
{
	return uid == 1 ? 10 : 0;
}
#define ER_ACCEPTED_EPOCH(uid) accepted(uid)
#include "epoch_roles.h"
_Static_assert(sizeof(struct er_row) == 32, "development role ABI");
_Static_assert(sizeof(struct er_state) == 520, "development state ABI");
_Static_assert(sizeof(struct er_work) == 536, "development work ABI");
int main(void)
{
	struct er_state s = { .version = 1 };
	s.rows[0] = (struct er_row){
		.uid = 1, .epoch = 10, .role = 777, .knowledge = ER_ROLE_UNKNOWN
	};
	struct er_candidate c = {
		.count = 1, .active = { { .uid = 1, .epoch = 10, .root = 999 } }
	};
	struct er_work w;
	er_snapshot(&w, &s, 1);
	assert(!er_stage_roots(&w, &c, 1));
	assert(!er_publish(&s, &w, 1));
	assert(s.rows[0].role == 777 && s.rows[0].knowledge == ER_ROLE_UNKNOWN);
	// Remove/re-add and inheritance retain accepted UNKNOWN, never reroot it.
	c.count = 0;
	memset(c.active, 0, sizeof(c.active));
	er_snapshot(&w, &s, 1);
	assert(!er_stage_roots(&w, &c, 1));
	assert(!er_publish(&s, &w, 1));
	struct er_state child = {};
	er_snapshot(&w, &child, 1);
	assert(!er_inherit(&w, &c, s.rows));
	assert(!er_publish(&child, &w, 1));
	assert(child.rows[0].uid == 1 && child.rows[0].epoch == 10 &&
	       child.rows[0].role == 777 &&
	       child.rows[0].knowledge == ER_ROLE_UNKNOWN);
	c.count = 1;
	c.active[0] = (struct er_authority){ 1, 10, 999, 0, 0 };
	er_snapshot(&w, &child, 1);
	assert(!er_stage_roots(&w, &c, 1));
	assert(!er_publish(&child, &w, 1));
	assert(child.rows[0].knowledge == ER_ROLE_UNKNOWN &&
	       child.rows[0].role == 777);
	// Accepted epoch mismatch and missing/invalid knowledge fail, never bootstrap.
	for (int failure = 0; failure < 4; failure++) {
		struct er_row row = child.rows[0];
		if (failure == 0)
			row.epoch++;
		if (failure == 1)
			row.knowledge = ER_ROLE_EMPTY;
		if (failure == 2)
			row.reserved = 1;
		if (failure == 3)
			row.role = 0;
		assert(er_row_kind(&row, &c) == ER_INVALID);
	}
	// A genuinely new UID receives a typed KNOWN root only with lineage proof.
	c.active[0] = (struct er_authority){ 2, 11, 888, 1, 0 };
	er_snapshot(&w, &child, 1);
	assert(!er_stage_roots(&w, &c, 1));
	assert(!er_publish(&child, &w, 1));
	assert(child.rows[1].knowledge == ER_ROLE_KNOWN &&
	       child.rows[1].role == 888);
	return 0;
}
