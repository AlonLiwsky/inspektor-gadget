// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <stdio.h>
#include "prefix.h"
#include "../ingress/lsm_result.h"
int main(void)
{
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
