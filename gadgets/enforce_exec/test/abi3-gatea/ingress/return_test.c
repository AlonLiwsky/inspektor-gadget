// SPDX-License-Identifier: GPL-2.0
#include <limits.h>
#include <stdio.h>
#include "lsm_result.h"
_Static_assert(sizeof(long) == 8, "BPF result requires 64-bit long");
int main(void)
{
	for (int prior = -4095; prior <= 0; prior++) {
		long result = in_lsm_result(prior);
		if (result != prior) {
			fprintf(stderr, "valid prior=%d changed to %ld\n",
				prior, result);
			return 1;
		}
	}
	const int invalid[] = { INT_MIN, -65536, -4096, 1,
				4095,	 4096,	 65536, INT_MAX };
	for (unsigned i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		long result = in_lsm_result(invalid[i]);
		if (result != -1) {
			fprintf(stderr,
				"invalid prior=%d produced %ld instead of denial\n",
				invalid[i], result);
			return 1;
		}
	}
	puts("PASS: zero preserved, all 4095 valid denials preserved, invalid nonzero results deny within verifier range");
	return 0;
}
