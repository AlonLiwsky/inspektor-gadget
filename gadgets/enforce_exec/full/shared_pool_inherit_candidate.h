/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_INHERIT_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_INHERIT_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_DEVELOPMENT) ||            \
	!defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY) || \
	!defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE)
#error "pool inheritance commit is candidate-only"
#endif
#ifndef SE_TASK_QUALIFIED
#error "pool inheritance commit requires shared task qualification semantics"
#endif
#ifndef ENFORCE_EXEC_SHARED_POOL_CATALOGUE_CANDIDATE_H
#error "pool inheritance commit requires explicit-scope catalogue preflight"
#endif
#ifndef ENFORCE_EXEC_SHARED_INHERIT_SNAPSHOT_H
#error "pool inheritance commit requires the actual shared final mutation"
#endif

/* Final store only, after the caller has acquired the exact parent TASK and
 * WORK handles, canonical-projected the WORK view, and validated the binding
 * snapshot/accepted catalogue. This does not perform those earlier steps.
 * The child remains unpublished and constructor-held. No BPF helper or child
 * lock is used inside the final parent metadata-lock bracket. */
SE_POOL_INLINE int
se_pool_inherit_child_commit(struct se_pool_task_semantic_handle *parent,
			     struct se_pool_task_birth_candidate *birth,
			     struct se_pool_work_semantic_handle *work,
			     const struct se_route_claim *claim)
{
	if (!parent || !birth || !work || !claim || !claim->owned ||
	    claim->reserved || !claim->scope || !claim->generation ||
	    claim->slot >= SE_POOL_B || parent->locked ||
	    parent->lease.held != 1 || parent->work_borrows != 1 ||
	    !parent->meta || !parent->payload || work->held != 1 ||
	    work->task != parent->meta || !work->payload || !work->task_lease ||
	    !work->ticket ||
	    work->task_lease->slot != parent->lease.token.slot ||
	    work->task_lease->cookie != parent->lease.token.cookie ||
	    work->task_lease->physical_address != parent->lease.token.address ||
	    work->ticket->owner_slot != parent->lease.token.slot ||
	    work->ticket->owner_cookie != parent->lease.token.cookie ||
	    birth->reservation.account.scope != claim->scope ||
	    birth->reservation.account.route_slot != claim->slot)
		return SE_POOL_CORRUPT;
	if (se_pool_work_semantic_active(
		    work->task, work->task_lease, work->work, work->payload,
		    work->ticket, work->route, work->charge) != SE_PW_OK)
		return SE_POOL_CORRUPT;
	struct se_exec_work *history = &work->payload->semantic.history;
	const struct er_work *projected = &work->payload->semantic.inherited;
	if (history->flags != SE_TASK_QUALIFIED ||
	    history->scope_cookie != claim->scope ||
	    history->physical_cookie != parent->lease.token.cookie ||
	    !history->eligibility_version || history->view.work.error ||
	    !history->view.work.prepared || projected->error ||
	    !projected->prepared ||
	    projected->base_version != history->view.work.base_version ||
	    projected->authority_version != claim->generation ||
	    history->view.work.authority_version != claim->generation ||
	    !se_pool_catalogue_projection_matches(&history->view, projected,
						  &work->payload->catalogue,
						  claim))
		return SE_POOL_STALE;
	struct er_state *child = 0;
	int status = se_pool_task_birth_child_view(birth, &child);
	if (status != SE_POOL_OK)
		return status;
	status = se_pool_task_semantic_begin(parent);
	if (status != SE_POOL_OK)
		return status;
	const struct se_task_state *semantic = &parent->payload->semantic;
	int same = parent->meta->account_slot == claim->slot &&
		   parent->meta->account_scope == claim->scope &&
		   birth->refs.payload->semantic.reader_invocation == 0 &&
		   !birth->refs.payload->semantic.reader.owned;
	int committed = same ? se_inherit_child_commit_locked(
				       semantic, &birth->refs.payload->semantic,
				       claim, history, projected) :
			       SE_INHERIT_COMMIT_STALE;
	int result = committed == SE_INHERIT_COMMIT_STALE ? SE_POOL_STALE :
		     committed == SE_INHERIT_COMMIT_PUBLISH_FAULT ?
							    SE_POOL_CORRUPT :
							    SE_POOL_OK;
	int ended = se_pool_task_semantic_end(parent);
	if (ended != SE_POOL_OK)
		return ended;
	return result;
}
#endif
