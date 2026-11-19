/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_EXEC_PREPARE_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_EXEC_PREPARE_CANDIDATE_H
#if !defined(ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_EVAL_CANDIDATE_H) ||        \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE) || \
	!defined(ENFORCE_EXEC_SHARED_POOL_OPAQUE_EXEC_READER_CANDIDATE_H)
#error "opaque preparation requires exact WORK, reader and scoped catalogue"
#endif

/* Prepare one fresh ACTIVE WORK for an already registered exec iteration.
 * The source authenticates physical as its original current TASK and retains
 * the exact TASK/WORK handles and immutable policy pins through evaluation.
 * A receipt is evidence, never a lease. This snapshots history and classifies
 * role facts only: no verdict, proposal, terminal or cleanup is issued here.
 * Failure may leave scratch partially prepared, but preserves every cleanup
 * handle and never mutates TASK history. Use a fresh WORK after failure. */
static __attribute__((always_inline)) inline int
se_owk_exec_prepare_reader(struct se_owk_semantic_handle *handle,
			   const struct se_exec_terminal_receipt *receipt,
			   __u64 physical)
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
	struct se_policy_view *view = &work->view;
	if (owner->lease.cookie != receipt->cookie ||
	    owner->lease.locator != receipt->locator ||
	    work->scope != receipt->scope ||
	    view->header.generation != receipt->generation ||
	    !view->header.policies || view->header.policies > 8 ||
	    view->header.rules > 256 || view->header.rule_base != 9 ||
	    work->history.physical_cookie || handle->payload->catalogue.scope ||
	    handle->payload->catalogue.generation ||
	    work->observation.stage_cursor.state ||
	    work->observation.facts.role_count)
		return SE_OL_CORRUPT;
	struct se_task_state *task = 0;
	int status = se_op_task_semantic_begin(owner, &task);
	if (status != SE_OL_OK)
		return status;
	int exact = task->physical_cookie == receipt->cookie &&
		    task->scope_cookie == receipt->scope && task->exec.owned &&
		    task->exec.bprm == receipt->bprm &&
		    task->exec.sequence == receipt->invocation &&
		    task->exec.generation == receipt->generation &&
		    task->exec.policy_count == view->header.policies;
	for (__u32 i = 0; i < 8; i++) {
		if (i >= view->header.policies)
			break;
		if (view->policies[i].uid != task->exec.policies[i].uid ||
		    view->policies[i].root_epoch !=
			    task->exec.policies[i].epoch)
			exact = 0;
	}
	if (exact)
		se_exec_snapshot_locked(task, receipt->generation,
					&work->history);
	se_op_task_semantic_end(owner, &task);
	if (!exact)
		return SE_OL_STALE;
	status = se_owk_catalogue_fill_reader(handle);
	if (status != SE_OL_OK)
		return status;
	status = se_owk_catalogue_classify_reader(handle);
	if (status != SE_OL_OK)
		return status;
	if (se_exec_fill_roles_preclassified(&work->history,
					     &work->observation.facts)) {
		work->observation.facts.role_count = 0;
		return SE_OL_CORRUPT;
	}
	return SE_OL_OK;
}
#endif
