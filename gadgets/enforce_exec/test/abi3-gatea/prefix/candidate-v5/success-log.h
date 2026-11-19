// SPDX-License-Identifier: GPL-2.0
#ifndef IG_PREFIX_SUCCESS_LOG_H
#define IG_PREFIX_SUCCESS_LOG_H
#include <stdio.h>
/* Quiet affects only successful diagnostic output, never an assertion. */
static inline void px_log_check(FILE *out, int quiet, int ok,
				const char *message)
{
	if (!quiet || !ok)
		fprintf(out, "%s %s\n", ok ? "PASS" : "FAIL", message);
}
#endif
