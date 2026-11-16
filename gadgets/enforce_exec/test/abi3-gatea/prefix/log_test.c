// SPDX-License-Identifier: GPL-2.0
#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "success-log.h"
int main(void)
{
	char *text = NULL;
	size_t length = 0;
	FILE *out = open_memstream(&text, &length);
	assert(out);
	for (unsigned i = 0; i < 1000; i++)
		px_log_check(out, 1, 1, "critical success");
	assert(!fflush(out) &&
	       length == 0); /* No successful diagnostic output. */
	px_log_check(out, 1, 0, "critical failure");
	assert(!fflush(out));
	assert(!strcmp(text, "FAIL critical failure\n"));
	px_log_check(out, 0, 1, "outside interval");
	assert(!fclose(out));
	assert(!strcmp(text, "FAIL critical failure\nPASS outside interval\n"));
	free(text);
	puts("PASS quiet success logger: 1000 successes emit zero bytes; failure stays visible");
	return 0;
}
