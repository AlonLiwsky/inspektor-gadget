// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "prefix.h"
#include "../ingress/lsm_result.h"
static void diagnostic_pid_regression(void)
{
	/* task_alloc precedes PID assignment: zero and inherited PID are not final. */
	const __u64 early_pids[] = { 0, 1404 };
	for (unsigned i = 0; i < 2; i++) {
		struct {
			__u64 physical_key;
			struct px_row row;
		} before = { .physical_key = 0x12340000,
			     .row = { .cookie = 7,
				      .origin = PX_OWNED_BIRTH,
				      .owns_slot = 1,
				      .parent_cookie = 3,
				      .alloc_seen = 1,
				      .pid = early_pids[i],
				      .history = { 11, 22, 33, 44 } } },
		  after = before, expected = before;
		px_birth_diagnostic_pid(&after.row.pid, after.row.cookie, 6,
					1405);
		assert(!memcmp(&before, &after,
			       sizeof(before))); /* wrong cookie cannot write */
		px_birth_diagnostic_pid(&after.row.pid, after.row.cookie, 7,
					1405);
		expected.row.pid = 1405;
		assert(!memcmp(&expected, &after,
			       sizeof(after))); /* only diagnostic PID changes */
		assert(after.physical_key == before.physical_key &&
		       after.row.cookie == 7);
		assert(!after.row.prefix_qualified &&
		       !after.row.history_complete);
	}
	struct px_row late = { .cookie = 8,
			       .origin = PX_LATE,
			       .pid = 1405,
			       .birth_uncertain = 1 };
	struct px_row unchanged = late;
	px_birth_diagnostic_pid(&late.pid, late.cookie, 0, 9999);
	assert(!memcmp(&late, &unchanged,
		       sizeof(late))); /* unowned birth cannot repair */
	puts("PASS birth diagnostic PID refresh: zero/inherited IDs, exact cookie, all other bytes unchanged");
}
int main(void)
{
	diagnostic_pid_regression();
	assert(px_eligible(PX_INITIAL, 0, 0, 0, 0, 0, 1, 0, 0));
	assert(!px_eligible(PX_INITIAL, 1, 1, 1, 0, 0, 1, 0, 0));
	assert(!px_eligible(PX_LATE, 0, 1, 1, 0, 0, 1, 0, 0));
	assert(!px_eligible(PX_OWNED_BIRTH, 0, 0, 1, 0, 0, 1, 0, 0));
	assert(!px_eligible(PX_OWNED_BIRTH, 0, 1, 0, 0, 0, 1, 0, 0));
	assert(px_eligible(PX_OWNED_BIRTH, 0, 1, 1, 0, 0, 1, 0, 0));
	assert(!px_eligible(PX_OWNED_BIRTH, 0, 1, 1, 1, 0, 1, 0, 0));
	assert(!px_eligible(PX_OWNED_BIRTH, 1, 1, 1, 0, 0, 1, 0, 0));
	assert(!px_eligible(PX_INITIAL, 0, 0, 0, 0, 0, 0, 0, 0));
	assert(!px_eligible(PX_INITIAL, 0, 0, 0, 0, 0, 1, 9, 0));
	assert(!px_eligible(PX_INITIAL, 0, 0, 0, 0, 0, 1, 0, 9));
	/* An early ineligible observation cannot consume a later eligible boundary. */
	int qualified = 0;
	if (px_eligible(PX_INITIAL, 0, 0, 0, 0, 0, 0, 0, 0))
		qualified = 1;
	assert(!qualified);
	if (px_eligible(PX_INITIAL, 0, 0, 0, 0, 0, 1, 0, 0))
		qualified = 1;
	assert(qualified);
	assert(px_snapshot_valid(2, 2, 0, 0));
	assert(!px_snapshot_valid(3, 2, 0, 0));
	assert(!px_snapshot_valid(2, 2, 1, 0));
	assert(!px_snapshot_valid(~0ULL, ~0ULL, 0, 0));
	assert(px_refusal_valid(1, 1, 2, 2, 3, 3, 1, 1, 0));
	assert(!px_refusal_valid(1, 2, 2, 2, 3, 3, 1, 1, 0));
	assert(!px_refusal_valid(1, 1, 3, 2, 3, 3, 1, 1, 0));
	assert(!px_refusal_valid(1, 1, 2, 2, 4, 3, 1, 1, 0));
	assert(!px_refusal_valid(1, 1, 2, 2, 3, 3, 2, 1, 0));
	assert(!px_refusal_valid(1, 1, 2, 2, 3, 3, 1, 1, 1));
	assert(in_lsm_result(-13) == -13);
	assert(in_lsm_result(-4095) == -4095);
	assert(in_lsm_result(-4096) == -1);
	assert(in_lsm_result(0) == 0);
	assert(in_lsm_result(1) == -1);
	puts("PASS pure prefix eligibility truth table; not kernel evidence");
	return 0;
}
