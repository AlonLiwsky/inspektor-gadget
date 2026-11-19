// SPDX-License-Identifier: GPL-2.0
#include <assert.h>
#include <string.h>
#include "failure-diagnostic.h"
int main(void)
{
	struct px_state s = { .inventory = 3,
			      .prefix_missing = 3,
			      .history_unknown = 3,
			      .serial = ~0ULL,
			      .diagnostic_exit = 1,
			      .diagnostic_timeout = 1,
			      .diagnostic_cpu = 17,
			      .admin_cpu = 19,
			      .diagnostic_child = 0x12345678 };
	struct px_state before = s;
	px_dump_initial_failure(stdout, &s);
	assert(!memcmp(&s, &before, sizeof(s)));
	return 0;
}
