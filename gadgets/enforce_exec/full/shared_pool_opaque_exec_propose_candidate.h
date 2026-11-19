/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_EXEC_PROPOSE_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_EXEC_PROPOSE_CANDIDATE_H
#if !defined(ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE) ||                      \
	!defined(ENFORCE_EXEC_FULLPOLICY_EVALUATOR_STAGE_CANDIDATE_H) ||      \
	!defined(ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_EVAL_CANDIDATE_H) ||    \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE) || \
	!defined(ENFORCE_EXEC_SHARED_POOL_OPAQUE_EXEC_READER_CANDIDATE_H)
#error "opaque proposal requires staged evaluation and exact WORK/reader handles"
#endif

/* Consume one completed evaluation, not the exec transaction: interpreter
 * checks may evaluate again in a different WORK. This scalar state issues no
 * ownership and cannot replace the source-certified evaluator/receipt path. */
enum { SE_OWK_PROPOSAL_CONSUMED = FE_STAGE_FINISHED + 1 };

/* The caller retains the original TASK lease, ACTIVE WORK and immutable
 * policy/snapshot pins through this call and its final cleanup. A registered
 * source receipt binds the observation to an exec; it does not grant a lease.
 * WORK's sequence identifies an allocation, while history.transaction.sequence
 * identifies an exec. They deliberately need not have the same value.
 *
 * This only proposes roles. It does not return an LSM verdict, commit roles,
 * release readers, retire receipts or complete WORK. In particular the caller
 * must preserve prior verbatim and settle success only from an actual terminal
 * producer. Every failure leaves the exact handles with the caller. */
static __attribute__((always_inline)) inline int
se_owk_exec_propose_reader(struct se_owk_semantic_handle *handle,
			   const struct se_exec_terminal_receipt *receipt,
			   __u64 physical, int prior)
{
	if (!handle || !receipt || !physical || !handle->payload ||
	    receipt->physical != physical || !receipt->cookie ||
	    !receipt->locator || !receipt->bprm || !receipt->invocation ||
	    !receipt->scope || !receipt->generation || receipt->reserved ||
	    receipt->phase != SE_EXEC_TERMINAL_REGISTERED)
		return SE_OL_CORRUPT;
	struct fm_global_token token = {};
	if (se_owk_evaluator_token(handle, &token) != SE_OL_OK)
		return SE_OL_CORRUPT;
	struct se_ol_payload_handle *owner = handle->owner;
	struct se_invocation *work = &handle->payload->semantic;
	struct se_exec_work *history = &work->history;
	struct se_policy_view *view = &work->view;
	struct fe_stage_cursor *cursor = &work->observation.stage_cursor;
	/* An audit-unknown result is not permission to skip remaining rules. */
	if (owner->lease.cookie != receipt->cookie ||
	    owner->lease.locator != receipt->locator ||
	    work->scope != receipt->scope ||
	    view->header.generation != receipt->generation ||
	    !view->header.policies || view->header.policies > 8 ||
	    view->header.rules > 256 || view->header.rule_base != 9 ||
	    cursor->state != FE_STAGE_FINISHED ||
	    cursor->generation != receipt->generation ||
	    cursor->policies != view->header.policies ||
	    cursor->rules != view->header.rules ||
	    cursor->next_rule != cursor->rules || history->reserved ||
	    history->physical_cookie != receipt->cookie ||
	    history->scope_cookie != receipt->scope ||
	    history->view.work.authority_version != receipt->generation ||
	    !history->transaction.owned ||
	    history->transaction.bprm != receipt->bprm ||
	    history->transaction.sequence != receipt->invocation ||
	    history->transaction.generation != receipt->generation ||
	    history->transaction.policy_count != view->header.policies)
		return SE_OL_CORRUPT;
	/* Bounded behind a compiler barrier (se_policy_bound). */
	for (__u32 i = 0, bound = se_policy_bound(view->header.policies);
	     i < bound && i < 8; i++) {
		if (view->policies[i].uid !=
			    history->transaction.policies[i].uid ||
		    view->policies[i].root_epoch !=
			    history->transaction.policies[i].epoch)
			return SE_OL_CORRUPT;
	}
	int status =
		se_owk_reader_catalogue_authority(handle, receipt->generation);
	if (status != SE_OL_OK)
		return status;
	struct se_task_state *task = 0;
	status = se_op_task_semantic_begin(owner, &task);
	if (status != SE_OL_OK)
		return status;
	int exact = task->physical_cookie == receipt->cookie &&
		    task->scope_cookie == receipt->scope &&
		    task->eligibility_version == history->eligibility_version &&
		    task->flags == history->flags &&
		    task->committed.version ==
			    history->view.work.base_version &&
		    task->exec.owned &&
		    !__builtin_memcmp(&task->exec, &history->transaction,
				      sizeof(task->exec));
	if (!exact) {
		se_op_task_semantic_end(owner, &task);
		return SE_OL_STALE;
	}
	struct fe_decision *decision = &work->observation.evaluator.decision;
	int error = 0;
	if (prior)
		se_exec_note_prior_deny_locked(task, receipt->bprm);
	else if (decision->error && decision->error != FE_AUDIT_UNKNOWN) {
		se_exec_fault_locked(&task->exec);
		error = 1;
	} else
		error = se_exec_propose_locked(&task->exec, decision);
	/* Even a malformed decision may have faulted the transaction. It cannot
	 * be retried as a fresh proposal, but keeps all cleanup authority. */
	cursor->state = SE_OWK_PROPOSAL_CONSUMED;
	se_op_task_semantic_end(owner, &task);
	return error ? SE_OL_CORRUPT : SE_OL_OK;
}
#endif
