/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
#error "opaque WORK semantic accessor requires its explicit candidate flag"
#endif
#include "shared_pool_opaque_work_candidate.h"

/* The ACTIVE WORK ticket and exact held TASK lease jointly own this pointer.
 * No extra map reference is an authority. The WORK lease remains live until
 * semantic_done, so the WORK-first reaper cannot zero these bytes while the
 * callback reads them. The callback must not pass the pointer beyond this
 * lexical bracket or call se_owk_done separately. */
struct se_owk_semantic_handle {
	struct se_ol_payload_handle *owner;
	struct se_owk_ticket *ticket;
	struct se_owk_payload *payload;
	__u32 held;
};

/* The verifier cannot write a map-value pointer into a caller's stack frame;
 * both handle operations must stay in the callback's lexical BPF frame. */
static __attribute__((always_inline)) inline int se_owk_semantic_open(
	struct se_ol_payload_handle *owner, struct se_owk_ticket *ticket,
	struct se_owk_semantic_handle *handle, struct se_invocation **semantic)
{
	if (!owner || !ticket || !handle || !semantic || *semantic ||
	    handle->held || handle->owner || handle->ticket ||
	    handle->payload || ticket->held != 1 || ticket->stage != 3 ||
	    !ticket->cookie || !ticket->invocation_sequence ||
	    ticket->account_slot >= SE_OWK_ACCOUNTS ||
	    ticket->work_slot >= SE_OWK_WORKS ||
	    ticket->owner_slot >= SE_OL_TASKS || owner->locked ||
	    owner->lease.held != 1 || !owner->lease.meta || !owner->payload ||
	    owner->lease.locator != ticket->owner_locator ||
	    owner->lease.cookie != ticket->owner_cookie ||
	    owner->lease.slot != ticket->owner_slot ||
	    ticket->work_slot / SE_OWK_QUOTA != ticket->account_slot ||
	    ticket->owner_slot / SE_OC_QUOTA != ticket->account_slot)
		return SE_OL_CORRUPT;

	/* The TASK may die after this check, but the exact held lease and
	 * persistent WORK owner ref prevent reuse until semantic_done. */
	void *task_payload = 0;
	int result = se_ol_payload_begin(owner, &task_payload);
	if (result != SE_OL_OK)
		return result;
	/* begin succeeded and this function changed no handle identity field.
	 * Release unconditionally; a fallible end would leave a verifier-visible
	 * path into WORK failure cleanup with the TASK spinlock still held. */
	task_payload = 0;
	owner->locked = 0;
	bpf_spin_unlock(&owner->lease.meta->lock);

	struct se_owk_account *account =
		SE_OWK_ACCOUNT_LOOKUP(ticket->account_slot);
	struct se_owk_charge *charge = SE_OWK_CHARGE_LOOKUP(ticket->work_slot);
	struct se_owk_meta *work = SE_OWK_META_LOOKUP(ticket->work_slot);
	struct se_owk_payload *payload =
		SE_OWK_PAYLOAD_LOOKUP(ticket->work_slot);
	if (!account || !charge || !work || !payload) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	__u32 local = ticket->work_slot - ticket->account_slot * SE_OWK_QUOTA;
	if (local >= SE_OWK_QUOTA) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	bpf_spin_lock(&account->lock);
	int charged = !account->fault && !account->reserved &&
		      account->scope == ticket->scope &&
		      account->incarnation == ticket->incarnation &&
		      account->used && account->used <= SE_OWK_QUOTA &&
		      se_owk_count(account->bits) == account->used &&
		      (account->bits & (1ULL << local)) &&
		      charge->state == SE_OWK_OWNED &&
		      charge->cookie == ticket->cookie &&
		      charge->scope == ticket->scope &&
		      charge->incarnation == ticket->incarnation &&
		      charge->owner_locator == ticket->owner_locator &&
		      charge->owner_cookie == ticket->owner_cookie &&
		      charge->owner_slot == ticket->owner_slot;
	bpf_spin_unlock(&account->lock);
	bpf_spin_lock(&work->lock);
	int active = charged && work->phase == SE_OWK_ACTIVE &&
		     work->active_leases == 1 && work->owner_ref_held == 1 &&
		     work->cookie == ticket->cookie &&
		     work->owner_locator == ticket->owner_locator &&
		     work->owner_cookie == ticket->owner_cookie &&
		     work->owner_slot == ticket->owner_slot &&
		     work->scope == ticket->scope &&
		     work->account_slot == ticket->account_slot &&
		     work->incarnation == ticket->incarnation &&
		     work->invocation_sequence == ticket->invocation_sequence &&
		     work->continuation_stage == ticket->continuation_stage &&
		     !work->continuation_reserved && !ticket->reserved &&
		     payload->semantic.scope == ticket->scope &&
		     payload->semantic.cookie == ticket->cookie &&
		     payload->semantic.sequence ==
			     ticket->invocation_sequence &&
		     payload->semantic.slot == ticket->work_slot &&
		     !payload->semantic.reserved;
	bpf_spin_unlock(&work->lock);
	if (!active) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	*handle = (struct se_owk_semantic_handle){
		.owner = owner,
		.ticket = ticket,
		.payload = payload,
		.held = 1,
	};
	*semantic = &payload->semantic;
	return SE_OL_OK;
}

/* Clear the caller's semantic pointer before the exact DONE transition.
 * On failure the charge is fault-held, never silently reused or refunded. */
static __attribute__((always_inline)) inline int
se_owk_semantic_done(struct se_owk_semantic_handle *handle,
		     struct se_invocation **semantic)
{
	if (!handle || handle->held != 1 || !handle->owner || !handle->ticket ||
	    !handle->payload || !semantic ||
	    *semantic != &handle->payload->semantic)
		return SE_OL_CORRUPT;
	*semantic = 0;
	int result = se_owk_done(handle->owner, handle->ticket);
	if (result != SE_OL_OK)
		se_owk_fault_ticket(handle->ticket);
	*handle = (struct se_owk_semantic_handle){};
	return result;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE
/* Consume the lexical semantic pointer while transferring the exact charged
 * WORK to a tail-call successor. A failed suspension leaves the pointer and
 * handle with this caller for explicit cleanup; it grants no new authority. */
static __attribute__((always_inline)) inline int
se_owk_semantic_suspend(struct se_owk_semantic_handle *handle,
			struct se_invocation **semantic, __u32 next_stage)
{
	if (!handle || handle->held != 1 || !handle->owner || !handle->ticket ||
	    !handle->payload || !semantic ||
	    *semantic != &handle->payload->semantic)
		return SE_OL_CORRUPT;
	int result = se_owk_suspend(handle->owner, handle->ticket, next_stage);
	if (result != SE_OL_OK)
		return result;
	*semantic = 0;
	*handle = (struct se_owk_semantic_handle){};
	return SE_OL_OK;
}
#endif
#endif
