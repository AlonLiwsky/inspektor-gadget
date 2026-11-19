/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_CATALOGUE_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_CATALOGUE_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_DEVELOPMENT) ||            \
	!defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY) || \
	!defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE)
#error "explicit pool catalogue is candidate-only"
#endif
#ifndef SE_POOL_CATALOGUE_EPOCH
#error "provide explicit (scope, uid) successful-activation lookup"
#endif

/* WORK ticket exclusivity owns its payload extension. The early route claim
 * must exclude catalogue publication through the later parent-locked commit.
 * Zero is valid only when the trusted COMPLETE catalogue proves never
 * accepted; UNKNOWN means unavailable/contradictory evidence and refuses. */
SE_POOL_INLINE int
se_pool_catalogue_fill(struct se_pool_work_semantic_handle *work,
		       const struct se_route_claim *claim)
{
	if (!work || !claim || !claim->owned || claim->reserved ||
	    !claim->scope || !claim->generation || work->held != 1 ||
	    !work->payload || !work->ticket ||
	    work->ticket->scope != claim->scope ||
	    work->payload->semantic.history.scope_cookie != claim->scope ||
	    work->payload->semantic.history.view.work.authority_version !=
		    claim->generation ||
	    work->payload->catalogue.scope ||
	    work->payload->catalogue.generation)
		return SE_POOL_CORRUPT;
	if (se_pool_work_semantic_active(
		    work->task, work->task_lease, work->work, work->payload,
		    work->ticket, work->route, work->charge) != SE_PW_OK)
		return SE_POOL_CORRUPT;
	struct se_pool_epoch_cache *cache = &work->payload->catalogue;
	const struct er_work *snapshot =
		&work->payload->semantic.history.view.work;
	for (__u32 i = 0; i < 16; i++) {
		__u64 uid = snapshot->rows[i].uid;
		__u64 accepted =
			uid ? SE_POOL_CATALOGUE_EPOCH(claim->scope, uid) : 0;
		cache->rows[i].uid = uid;
		cache->rows[i].accepted_epoch = accepted;
		if (accepted == ER_UNKNOWN)
			return SE_POOL_CORRUPT;
	}
	cache->scope = claim->scope;
	cache->generation = claim->generation; /* publish complete cache last */
	return SE_POOL_OK;
}

#include "shared_pool_catalogue_pure.h"
#endif
