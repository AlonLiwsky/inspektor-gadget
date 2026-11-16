/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_TASK_OPEN_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_TASK_OPEN_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque TASK open is candidate-only"
#endif
#include "shared_pool_opaque_payload_handle_candidate.h"

#ifndef SE_OL_TASK_OPEN_AFTER_HOLD
#define SE_OL_TASK_OPEN_AFTER_HOLD() ((void)0)
#endif

/* One callback-local observation of the ORIGINAL opaque task key. The key
 * argument points to the typed task pointer's bytes, never a mixed address
 * hash. Successful return transfers one exact locator lease to handle;
 * caller must close it on every branch and bracket semantic access with
 * payload begin/end. This proves physical identity only, not roles/policy.
 * Failed conversion releases its speculative hold unless a contradictory
 * metadata generation makes that impossible; then the hold stays fault-held
 * rather than authorizing another task. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_OPEN_INLINE_CANDIDATE
#define SE_OL_TASK_OPEN_ATTR __attribute__((always_inline)) inline
#else
#define SE_OL_TASK_OPEN_ATTR __attribute__((noinline))
#endif
static SE_OL_TASK_OPEN_ATTR int
se_ol_task_open(const void *original_key, struct se_ol_payload_handle *handle)
{
	if (!original_key || !handle || handle->lease.held ||
	    handle->lease.meta || handle->payload || handle->locked)
		return SE_OL_CORRUPT;
	struct se_ol_observation observation = {};
	int result = se_ol_observe(original_key, &observation);
	if (result != SE_OL_OK)
		return result;
	result = se_ol_read_observation(&observation);
	if (result != SE_OL_OK)
		return result;
	result = se_ol_hold_observation(&observation);
	if (result != SE_OL_OK)
		return result;
	SE_OL_TASK_OPEN_AFTER_HOLD();
	struct se_ol_lease lease = {};
	result = se_ol_relookup_convert(&observation, &lease);
	if (result != SE_OL_OK) {
		if (observation.stage == SE_OL_HELD &&
		    se_ol_cancel_observation(&observation) != SE_OL_OK)
			return SE_OL_CORRUPT;
		return result;
	}
	result = se_ol_payload_open(&lease, handle);
	if (result != SE_OL_OK && se_ol_release_lease(&lease) != SE_OL_OK)
		return SE_OL_CORRUPT;
	return result;
}
#undef SE_OL_TASK_OPEN_ATTR
#endif
