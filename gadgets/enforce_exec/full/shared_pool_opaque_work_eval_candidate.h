/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_EVAL_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_EVAL_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
#error "opaque WORK evaluator resolver requires its explicit candidate flag"
#endif
#include "shared_pool_opaque_work_semantic_candidate.h"

/* Scalar callback lookup only, never an acquisition or transfer of WORK
 * authority. The caller must retain the exact TASK lease, ACTIVE WORK ticket
 * and immutable policy/snapshot pins through the LAST nested matcher lookup.
 * The token is made from that ticket, not a current-task address or cgroup.
 * Rechecking exact fixed-slot identity prevents a stale callback from reading
 * a recycled payload. No map helper runs under a spinlock. */
static __attribute__((always_inline)) inline struct se_policy_view *
se_owk_view_from_identity(__u32 slot, __u64 cookie)
{
	if (slot >= SE_OWK_WORKS || !cookie || cookie > SE_OWK_COOKIE_LIMIT)
		return 0;
	struct se_owk_meta *meta = SE_OWK_META_LOOKUP(slot);
	struct se_owk_charge *charge = SE_OWK_CHARGE_LOOKUP(slot);
	struct se_owk_payload *payload = SE_OWK_PAYLOAD_LOOKUP(slot);
	if (!meta || !charge || !payload)
		return 0;
	bpf_spin_lock(&meta->lock);
	int active = meta->phase == SE_OWK_ACTIVE && meta->active_leases == 1 &&
		     meta->owner_ref_held == 1 && !meta->cleanup_done &&
		     meta->cookie == cookie && meta->scope &&
		     meta->invocation_sequence && meta->owner_locator &&
		     meta->owner_cookie && meta->owner_slot < SE_OL_TASKS &&
		     meta->account_slot < SE_OWK_ACCOUNTS &&
		     meta->owner_slot / SE_OC_QUOTA == meta->account_slot &&
		     slot / SE_OWK_QUOTA == meta->account_slot &&
		     charge->state == SE_OWK_OWNED &&
		     charge->cookie == cookie && charge->scope == meta->scope &&
		     charge->incarnation == meta->incarnation &&
		     charge->owner_locator == meta->owner_locator &&
		     charge->owner_cookie == meta->owner_cookie &&
		     charge->owner_slot == meta->owner_slot &&
		     payload->semantic.scope == meta->scope &&
		     payload->semantic.cookie == cookie &&
		     payload->semantic.sequence == meta->invocation_sequence &&
		     payload->semantic.slot == slot &&
		     !payload->semantic.reserved &&
		     payload->semantic.view.scope_cookie == meta->scope &&
		     payload->semantic.view.ready == 1;
	bpf_spin_unlock(&meta->lock);
	return active ? &payload->semantic.view : 0;
}

#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
/* Nested evaluator lookup ONLY after se_owk_evaluator_token issued from an
 * exact lexical ACTIVE ticket in the SAME callback. The held ticket pins the
 * WORK charge and policy refs; this lighter relookup checks phase/cookie and
 * payload identity against ABA on every nested access. It is not an entry
 * authenticator and does not authorize suspended-WORK reads. */
static __attribute__((always_inline)) inline struct se_policy_view *
se_owk_view_from_lexical_token(__u32 slot, __u64 cookie)
{
	if (slot >= SE_OWK_WORKS || !cookie || cookie > SE_OWK_COOKIE_LIMIT)
		return 0;
	struct se_owk_meta *meta = SE_OWK_META_LOOKUP(slot);
	struct se_owk_payload *payload = SE_OWK_PAYLOAD_LOOKUP(slot);
	if (!meta || !payload)
		return 0;
	bpf_spin_lock(&meta->lock);
	int exact = meta->phase == SE_OWK_ACTIVE && meta->active_leases == 1 &&
		    meta->owner_ref_held == 1 && !meta->cleanup_done &&
		    meta->cookie == cookie && meta->scope &&
		    meta->invocation_sequence &&
		    payload->semantic.scope == meta->scope &&
		    payload->semantic.cookie == cookie &&
		    payload->semantic.sequence == meta->invocation_sequence &&
		    payload->semantic.slot == slot &&
		    !payload->semantic.reserved &&
		    payload->semantic.view.scope_cookie == meta->scope &&
		    payload->semantic.view.ready == 1;
	bpf_spin_unlock(&meta->lock);
	return exact ? &payload->semantic.view : 0;
}
#endif

/* Issue the callback context only from the lexical WORK handle. A pair
 * copied from a map or reconstructed from the current task is not enough.
 * The caller must keep this same handle, TASK lease and policy pins through
 * the last nested evaluator lookup; the token grants no additional lease. */
static __attribute__((always_inline)) inline int
se_owk_evaluator_token(const struct se_owk_semantic_handle *handle,
		       struct fm_global_token *token)
{
	if (!token)
		return SE_OL_CORRUPT;
	*token = (struct fm_global_token){};
	if (!handle || handle->held != 1 || !handle->owner || !handle->ticket ||
	    !handle->payload || handle->owner->locked ||
	    handle->owner->lease.held != 1 || handle->ticket->held != 1 ||
	    handle->ticket->stage != 3 ||
	    handle->owner->lease.locator != handle->ticket->owner_locator ||
	    handle->owner->lease.cookie != handle->ticket->owner_cookie ||
	    handle->owner->lease.slot != handle->ticket->owner_slot ||
	    handle->ticket->work_slot >= SE_OWK_WORKS ||
	    !handle->ticket->cookie ||
	    handle->payload->semantic.scope != handle->ticket->scope ||
	    handle->payload->semantic.cookie != handle->ticket->cookie ||
	    handle->payload->semantic.sequence !=
		    handle->ticket->invocation_sequence ||
	    handle->payload->semantic.slot != handle->ticket->work_slot ||
	    !handle->payload->semantic.view.ready ||
	    handle->payload->semantic.view.scope_cookie !=
		    handle->ticket->scope ||
	    se_owk_view_from_identity(handle->ticket->work_slot,
				      handle->ticket->cookie) !=
		    &handle->payload->semantic.view)
		return SE_OL_CORRUPT;
	*token = (struct fm_global_token){
		.slot = handle->ticket->work_slot,
		.cookie = handle->ticket->cookie,
	};
	return SE_OL_OK;
}
#endif
