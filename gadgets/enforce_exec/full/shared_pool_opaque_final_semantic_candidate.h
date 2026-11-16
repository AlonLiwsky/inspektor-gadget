/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_FINAL_SEMANTIC_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_FINAL_SEMANTIC_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque final-free semantic view is candidate-only"
#endif
#ifndef SE_OL_PAYLOAD_LOOKUP
#error "provide the fixed TASK payload ARRAY lookup"
#endif

#include "shared_pool_opaque_final_free_candidate.h"
#include "shared_pool_task_wire.h"

/* A live TASK accessor must refuse after se_of_record_death. This separate
 * lexical view is usable only through that actual final-free lease and only
 * for source-owned cleanup, never for a new exec/role decision. The lease
 * pins the exact TASK slot until end and se_of_release; its locked bit
 * prevents accidental release while the metadata lock is held. */
struct se_of_semantic_handle {
	struct se_of_lease *lease;
	struct se_pool_task_wire *payload;
	__u32 locked;
};

static __attribute__((always_inline)) inline int
se_of_semantic_begin(struct se_of_lease *lease, struct task_struct *physical,
		     struct se_of_semantic_handle *handle,
		     struct se_pool_task_wire **payload_out)
{
	if (!lease || lease->held != 1 || lease->locked || !lease->meta ||
	    !physical || lease->physical != physical || !handle ||
	    handle->lease || handle->payload || handle->locked ||
	    !payload_out || *payload_out)
		return SE_OL_CORRUPT;
	__u32 slot = 0;
	if (se_ol_decode(lease->locator, &slot) != SE_OL_OK ||
	    slot != lease->slot)
		return SE_OL_CORRUPT;
	struct se_pool_task_wire *payload = SE_OL_PAYLOAD_LOOKUP(slot);
	if (!payload)
		return SE_OL_CORRUPT;
	struct se_ol_meta *meta = lease->meta;
	bpf_spin_lock(&meta->lock);
	int exact =
		meta->locator == lease->locator &&
		meta->cookie == lease->cookie && meta->active_leases &&
		(meta->phase == SE_OL_DEAD || meta->phase == SE_OL_CLEANING) &&
		meta->directory_state == SE_OL_PUBLISHED &&
		meta->archive_ready == 1 && !meta->exclusive &&
		!meta->exclusive_owner && !meta->reserved &&
		meta->account_scope && meta->account_incarnation &&
		meta->account_slot < SE_OC_ACCOUNTS &&
		lease->slot / SE_OC_QUOTA == meta->account_slot &&
		!payload->identity.reserved_lock &&
		!payload->identity.identity_reserved &&
		(payload->identity.flags & SE_OL_TASK_LIVE) &&
		payload->identity.physical_cookie == lease->cookie &&
		payload->identity.scope_cookie == meta->account_scope &&
		payload->identity.scope_slot == meta->account_slot;
	if (!exact) {
		bpf_spin_unlock(&meta->lock);
		return SE_OL_CORRUPT;
	}
	lease->locked = 1;
	*handle = (struct se_of_semantic_handle){
		.lease = lease,
		.payload = payload,
		.locked = 1,
	};
	*payload_out = payload;
	return SE_OL_OK;
}

static __attribute__((always_inline)) inline int
se_of_semantic_end(struct se_of_semantic_handle *handle,
		   struct se_pool_task_wire **payload_out)
{
	if (!handle || handle->locked != 1 || !handle->lease ||
	    !handle->payload || !payload_out ||
	    *payload_out != handle->payload || handle->lease->held != 1 ||
	    handle->lease->locked != 1 || !handle->lease->meta)
		return SE_OL_CORRUPT;
	struct se_ol_meta *meta = handle->lease->meta;
	*payload_out = 0;
	handle->lease->locked = 0;
	*handle = (struct se_of_semantic_handle){};
	bpf_spin_unlock(&meta->lock);
	return SE_OL_OK;
}
#endif
