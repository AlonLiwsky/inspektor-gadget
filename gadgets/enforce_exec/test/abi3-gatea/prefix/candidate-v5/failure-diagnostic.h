// SPDX-License-Identifier: GPL-2.0
#ifndef IG_PREFIX_FAILURE_DIAGNOSTIC_H
#define IG_PREFIX_FAILURE_DIAGNOSTIC_H
#include <stdio.h>
#include "prefix.h"
/* Failure-only formatting of the ALREADY READ snapshot: no BPF/map/clock reads. */
static inline void px_dump_failure_snapshot(FILE *out, const struct px_state *s,
					    const char *event)
{
	fprintf(out, "{\"event\":\"%s\",\"actual\":{", event);
#define PX_PRINT(field) \
	fprintf(out, "\"" #field "\":%llu,", (unsigned long long)s->field)
	PX_PRINT(inventory);
	PX_PRINT(prefix_missing);
	PX_PRINT(history_unknown);
	PX_PRINT(inflight);
	PX_PRINT(allocs);
	PX_PRINT(births);
	PX_PRINT(errors);
	PX_PRINT(serial);
	PX_PRINT(writers);
	PX_PRINT(retained);
	PX_PRINT(next_cookie);
	PX_PRINT(frees);
	PX_PRINT(failed);
	PX_PRINT(unowned);
	PX_PRINT(enabled);
	PX_PRINT(barrier);
	PX_PRINT(initial_started);
	PX_PRINT(initial_done);
	PX_PRINT(inventory_serial);
	PX_PRINT(inventory_generation);
	PX_PRINT(refusals);
	PX_PRINT(refusal_serial);
	PX_PRINT(refusal_inventory);
	PX_PRINT(refusal_barrier);
	PX_PRINT(strict_ready);
	PX_PRINT(held);
	PX_PRINT(diagnostic_task);
	PX_PRINT(diagnostic_nonce);
	PX_PRINT(diagnostic_enter);
	PX_PRINT(diagnostic_exit);
	PX_PRINT(diagnostic_timeout);
	PX_PRINT(diagnostic_release);
	PX_PRINT(diagnostic_cpu);
	PX_PRINT(admin_cpu);
	PX_PRINT(diagnostic_child);
#undef PX_PRINT
	fprintf(out,
		"\"diagnostic_used\":%llu},\"expected_assertion\":{\"inventory\":2,\"prefix_missing\":2,\"history_unknown\":2,\"inflight\":0,\"allocs\":0,\"births\":0,\"errors\":0}}\n",
		(unsigned long long)s->diagnostic_used);
}
static inline void px_dump_initial_failure(FILE *out, const struct px_state *s)
{
	px_dump_failure_snapshot(out, s, "initial_counts_failure");
}
static inline void px_dump_critical_failure(FILE *out, const struct px_state *s)
{
	px_dump_failure_snapshot(out, s, "critical_interval_last_snapshot");
}
#endif
