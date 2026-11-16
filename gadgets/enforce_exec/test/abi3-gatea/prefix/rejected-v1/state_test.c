// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <stdio.h>
#include "prefix.h"
int main(void)
{
	assert(px_eligible(PX_INITIAL, 0, 0, 0, 0, 0));
	assert(!px_eligible(PX_INITIAL, 1, 1, 1, 0, 0));
	assert(!px_eligible(PX_LATE, 0, 1, 1, 0, 0));
	assert(!px_eligible(PX_OWNED_BIRTH, 0, 0, 1, 0, 0));
	assert(!px_eligible(PX_OWNED_BIRTH, 0, 1, 0, 0, 0));
	assert(px_eligible(PX_OWNED_BIRTH, 0, 1, 1, 0, 0));
	assert(!px_eligible(PX_OWNED_BIRTH, 0, 1, 1, 1, 0));
	assert(!px_eligible(PX_OWNED_BIRTH, 1, 1, 1, 0, 0));
	puts("PASS pure prefix eligibility truth table; not kernel evidence");
	return 0;
}
