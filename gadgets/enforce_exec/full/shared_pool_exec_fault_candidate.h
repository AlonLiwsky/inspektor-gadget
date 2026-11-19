/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_EXEC_FAULT_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_EXEC_FAULT_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_DEVELOPMENT) ||            \
	!defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY) || \
	!defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE)
#error "typed exec fault is candidate-only"
#endif

/* These are synchronous semantic mutations. The caller retains the exact
 * TASK lease, and neither helper performs a map lookup or sleeps while the
 * metadata lock is held. A missing/dead task is not silently re-admitted. */
SE_POOL_INLINE int
se_pool_owned_exec_fault(struct se_pool_task_semantic_handle *handle,
			 __u64 bprm)
{
	if (!handle || !bprm)
		return SE_POOL_CORRUPT;
	int status = se_pool_task_semantic_begin(handle);
	if (status != SE_POOL_OK)
		return status;
	struct se_task_state *task = &handle->payload->semantic;
	if (task->exec.owned && task->exec.bprm == bprm)
		se_exec_fault_locked(&task->exec);
	else if (!task->exec.owned) {
		task->flags |= SE_TASK_QUARANTINED;
		if (task->eligibility_version < ~0ULL - 1)
			task->eligibility_version++;
	}
	return se_pool_task_semantic_end(handle);
}

/* Preserve an existing LSM denial in the exact in-flight transaction. The
 * caller still returns the prior errno; this helper does not decide a verdict. */
SE_POOL_INLINE int
se_pool_note_prior_exec_deny(struct se_pool_task_semantic_handle *handle,
			     __u64 bprm)
{
	if (!handle || !bprm)
		return SE_POOL_CORRUPT;
	int status = se_pool_task_semantic_begin(handle);
	if (status != SE_POOL_OK)
		return status;
	struct se_exec_transaction *exec = &handle->payload->semantic.exec;
	if (exec->owned && exec->bprm == bprm) {
		exec->known_deny = 1;
		exec->grants = 0;
	}
	return se_pool_task_semantic_end(handle);
}
#endif
