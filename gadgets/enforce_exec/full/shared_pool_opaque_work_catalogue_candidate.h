/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_CATALOGUE_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_CATALOGUE_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
#error "opaque WORK catalogue requires its explicit candidate flag"
#endif
#ifndef SE_OWK_CATALOGUE_EPOCH
#error "provide explicit (scope, uid) COMPLETE successful-activation lookup"
#endif
#include "shared_pool_opaque_work_semantic_candidate.h"
#include "shared_pool_catalogue_pure.h"

/* Called inside the lexical semantic_open/done bracket, with the exact TASK
 * lease and ACTIVE WORK ticket still retained. The caller must keep the route
 * claim stable through final publication, and abort/fault the WORK on any
 * non-OK result. The lookup must return ER_UNKNOWN on unavailable evidence;
 * zero means COMPLETE history proves the UID was never accepted. No helper is
 * called under a spinlock. Scope/generation publish only after all rows: the
 * cache is tagged with the reader's (or the parked birth claim's) own
 * generation, which may be a RETIRING record's (G019 gap 3), and every
 * consumer (se_pool_catalogue_classify_after_authority,
 * se_pool_catalogue_projection_matches) refuses another scope or generation.
 * The rows stay valid across a later commit of the same binding: the product
 * catalogue is write-once per (scope, UID) for the binding's lifetime (the
 * revision refuses a UID, class or root epoch change; real_owner_epoch_bind
 * inserts BPF_NOEXIST into the index; real_owner_epoch_cell_ready accepts
 * only an equal epoch; real_owner_recycle_clean clears a scope with both
 * records FREE); a mismatch fails closed (CORRUPT). */
static __attribute__((always_inline)) inline int
se_owk_catalogue_fill_after_authority(struct se_owk_semantic_handle *handle,
				      __u64 scope, __u64 generation)
{
	if (!handle || handle->held != 1 || !handle->owner || !handle->ticket ||
	    !handle->payload || !scope || !generation)
		return SE_OL_CORRUPT;
	struct se_ol_payload_handle *owner = handle->owner;
	struct se_owk_ticket *ticket = handle->ticket;
	struct se_owk_payload *payload = handle->payload;
	struct se_invocation *semantic = &payload->semantic;
	struct se_pool_epoch_cache *cache = &payload->catalogue;
	if (owner->locked || owner->lease.held != 1 || !owner->lease.meta ||
	    !owner->payload || ticket->held != 1 || ticket->stage != 3 ||
	    !ticket->cookie || !ticket->invocation_sequence ||
	    ticket->scope != scope ||
	    owner->lease.locator != ticket->owner_locator ||
	    owner->lease.cookie != ticket->owner_cookie ||
	    owner->lease.slot != ticket->owner_slot ||
	    semantic->scope != ticket->scope ||
	    semantic->cookie != ticket->cookie ||
	    semantic->sequence != ticket->invocation_sequence ||
	    semantic->slot != ticket->work_slot || semantic->reserved ||
	    semantic->history.scope_cookie != scope ||
	    semantic->history.view.work.authority_version != generation ||
	    cache->scope || cache->generation)
		return SE_OL_CORRUPT;
	const struct er_work *snapshot = &semantic->history.view.work;
	for (__u32 i = 0; i < ER_SLOTS; i++) {
		__u64 uid = snapshot->rows[i].uid;
		__u64 accepted = uid ? SE_OWK_CATALOGUE_EPOCH(scope, uid) : 0;
		cache->rows[i].uid = uid;
		cache->rows[i].accepted_epoch = accepted;
		if (accepted == ER_UNKNOWN)
			return SE_OL_CORRUPT;
	}
	cache->scope = scope;
	cache->generation = generation;
	return SE_OL_OK;
}
static __attribute__((always_inline)) inline int
se_owk_catalogue_fill(struct se_owk_semantic_handle *handle,
		      const struct se_route_claim *claim)
{
	if (!claim || !claim->owned || claim->reserved)
		return SE_OL_CORRUPT;
	return se_owk_catalogue_fill_after_authority(handle, claim->scope,
						     claim->generation);
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE
#ifndef SE_OWK_BINDING_LOOKUP
#error "reader catalogue requires fixed original-binding ARRAY lookup"
#endif
/* The exact lexical TASK lease and ACTIVE WORK ticket are the source owner.
 * The reader fields are route-lock-owned. The callback must retain these same
 * handles, and not issue a concurrent source completion, through the LAST
 * cache lookup. This predicate issues no lease and must not be used with a
 * copied reader token or current-cgroup tuple. */
static __attribute__((always_inline)) inline int
se_owk_reader_catalogue_authority(const struct se_owk_semantic_handle *handle,
				  __u64 generation)
{
	if (!handle || handle->held != 1 || !handle->owner || !handle->ticket ||
	    !handle->payload || !generation || handle->owner->locked ||
	    handle->owner->lease.held != 1 || !handle->owner->lease.meta ||
	    !handle->owner->payload || handle->ticket->held != 1 ||
	    handle->ticket->stage != 3 ||
	    handle->ticket->account_slot >= SE_OWK_ACCOUNTS ||
	    handle->ticket->owner_slot >= SE_OL_TASKS ||
	    handle->owner->lease.slot != handle->ticket->owner_slot ||
	    handle->owner->lease.cookie != handle->ticket->owner_cookie ||
	    handle->owner->lease.locator != handle->ticket->owner_locator ||
	    handle->ticket->scope != handle->owner->lease.meta->account_scope ||
	    handle->ticket->incarnation !=
		    handle->owner->lease.meta->account_incarnation)
		return SE_OL_CORRUPT;
	const struct se_exec_work *history = &handle->payload->semantic.history;
	if (history->physical_cookie != handle->ticket->owner_cookie ||
	    history->scope_cookie != handle->ticket->scope ||
	    !history->transaction.owned || !history->transaction.bprm ||
	    !history->transaction.sequence ||
	    history->transaction.generation != generation ||
	    history->transaction.execution_class < 1 ||
	    history->transaction.execution_class > 2)
		return SE_OL_CORRUPT;
	__u32 slot = handle->ticket->account_slot;
	struct se_route_anchor *route = SE_OC_ROUTE_LOOKUP(slot);
	struct se_binding_snapshots *binding = SE_OWK_BINDING_LOOKUP(slot);
	if (!route || !binding)
		return SE_OL_CORRUPT;
	struct se_pool_task_wire *task_payload = handle->owner->payload;
	bpf_spin_lock(&route->lock);
	int valid = route->incarnation == handle->ticket->incarnation &&
		    se_exec_reader_authority_locked(
			    route, binding, &task_payload->semantic, slot,
			    handle->ticket->scope, generation,
			    handle->ticket->owner_cookie,
			    history->transaction.sequence,
			    history->transaction.execution_class);
	bpf_spin_unlock(&route->lock);
	return valid ? SE_OL_OK : SE_OL_STALE;
}
static __attribute__((always_inline)) inline int
se_owk_catalogue_fill_reader(struct se_owk_semantic_handle *handle)
{
	if (!handle || !handle->payload)
		return SE_OL_CORRUPT;
	__u64 generation =
		handle->payload->semantic.history.view.work.authority_version;
	int status = se_owk_reader_catalogue_authority(handle, generation);
	if (status != SE_OL_OK)
		return status;
	return se_owk_catalogue_fill_after_authority(
		handle, handle->ticket->scope, generation);
}
static __attribute__((always_inline)) inline int
se_owk_catalogue_classify_reader(struct se_owk_semantic_handle *handle)
{
	if (!handle || !handle->payload)
		return SE_OL_CORRUPT;
	__u64 generation =
		handle->payload->semantic.history.view.work.authority_version;
	int status = se_owk_reader_catalogue_authority(handle, generation);
	if (status != SE_OL_OK)
		return status;
	return se_pool_catalogue_classify_after_authority(
		       &handle->payload->semantic.history.view,
		       &handle->payload->catalogue, handle->ticket->scope,
		       generation) ?
		       SE_OL_CORRUPT :
		       SE_OL_OK;
}

#endif
#endif
