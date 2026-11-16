/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_EXEC_WORK_COMPLETION_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_EXEC_WORK_COMPLETION_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE) ||    \
	!defined(ENFORCE_EXEC_SHARED_POOL_OPAQUE_EXEC_READER_CANDIDATE_H) || \
	!defined(ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_CATALOGUE_CANDIDATE_H)
#error "prepared exec WORK completion needs exact reader and scoped catalogue"
#endif

/* A plain trace receipt is only terminal evidence. It becomes usable after
 * the caller opens and locks this exact charged live TASK; reader authority is
 * additionally checked by the scoped catalogue path before publication. */
static __attribute__((always_inline)) inline int
se_owk_terminal_receipt_identity(const struct se_exec_terminal_receipt *receipt,
				 __u64 physical,
				 const struct se_ol_payload_handle *owner,
				 const struct se_task_state *task, int success)
{
	return receipt && physical && owner && task &&
	       (success == 0 || success == 1) &&
	       receipt->phase == (success ? SE_EXEC_TERMINAL_SUCCESS :
					    SE_EXEC_TERMINAL_FAILURE) &&
	       !receipt->reserved && receipt->physical == physical &&
	       receipt->bprm && receipt->invocation && receipt->scope &&
	       receipt->generation && owner->lease.held == 1 &&
	       owner->lease.meta && owner->payload &&
	       owner->lease.cookie == receipt->cookie &&
	       owner->lease.locator == receipt->locator &&
	       owner->lease.meta->phase == SE_OL_LIVE &&
	       owner->lease.meta->cookie == receipt->cookie &&
	       owner->lease.meta->locator == receipt->locator &&
	       owner->lease.meta->account_scope == receipt->scope &&
	       task->physical_cookie == receipt->cookie &&
	       task->scope_cookie == receipt->scope &&
	       task->scope_slot < SE_OC_ACCOUNTS &&
	       (task->flags & SE_TASK_LIVE) &&
	       task->exec.bprm == receipt->bprm &&
	       task->exec.sequence == receipt->invocation &&
	       task->exec.generation == receipt->generation;
}
static __attribute__((always_inline)) inline int
se_owk_terminal_receipt_matches(const struct se_exec_terminal_receipt *receipt,
				__u64 physical,
				const struct se_ol_payload_handle *owner,
				const struct se_task_state *task, int success)
{
	return se_owk_terminal_receipt_identity(receipt, physical, owner, task,
						success) &&
	       task->exec.owned && task->reader.owned &&
	       task->reader_invocation == receipt->invocation;
}

/* Retry only AFTER a normal completion consumed exec ownership. This path
 * cannot apply a second patch, cannot abort an owned transaction, and leaves
 * the source receipt intact on any mismatch. The caller deletes that receipt
 * only after successful exact reader settlement while holding its TASK lease. */
static __attribute__((noinline)) int se_owk_exec_settle_committed_reader(
	struct se_ol_payload_handle *owner,
	const struct se_exec_terminal_receipt *receipt, __u64 physical)
{
	if (!owner || !receipt || !physical)
		return SE_OL_CORRUPT;
	struct se_task_state *task = 0;
	int status = se_op_task_semantic_begin(owner, &task);
	if (status != SE_OL_OK)
		return status;
	__u32 slot = task->scope_slot;
	__u32 execution_class = task->exec.execution_class;
	int reader = task->reader.owned;
	int exact = receipt &&
		    (se_owk_terminal_receipt_identity(receipt, physical, owner,
						      task, 1) ||
		     se_owk_terminal_receipt_identity(receipt, physical, owner,
						      task, 0)) &&
		    !task->exec.owned &&
		    (reader ? task->reader_invocation == receipt->invocation :
			      !task->reader_invocation);
	se_op_task_semantic_end(owner, &task);
	if (!exact)
		return SE_OL_CORRUPT;
	if (!reader)
		return SE_OL_OK;
	struct se_route_anchor *route = SE_OC_ROUTE_LOOKUP(slot);
	struct se_binding_snapshots *binding = SE_OWK_BINDING_LOOKUP(slot);
	if (!route || !binding)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&route->lock);
	int authority = se_exec_reader_authority_locked(
		route, binding,
		&((struct se_pool_task_wire *)owner->payload)->semantic, slot,
		receipt->scope, receipt->generation, owner->lease.cookie,
		receipt->invocation, execution_class);
	int released =
		authority ?
			se_exec_reader_release_locked(
				binding,
				&((struct se_pool_task_wire *)owner->payload)
					 ->semantic,
				owner->lease.cookie, receipt->invocation) :
			-1;
	bpf_spin_unlock(&route->lock);
	return released ? SE_OL_CORRUPT : SE_OL_OK;
}

/* One policy's exact accepted row. Avoid multiplying verifier states across
 * the eight policy slots: every row contributes a scalar match bit, with one
 * decision only after the bounded scan. The retained catalogue already proved
 * which physical rows are accepted for this scope and generation. */
static __attribute__((always_inline)) inline int
se_owk_scoped_policy_row(const struct er_canonical_view *view, __u64 uid,
			 __u64 epoch)
{
	__u32 seen = 0, duplicate = 0, index = 0;
	for (__u32 j = 0; j < ER_SLOTS; j++) {
		const struct er_row *row = &view->work.rows[j];
		__u32 match = ((view->accepted_mask >> j) & 1U) &
			      (1U ^ se_pool_catalogue_ne64(row->uid, uid)) &
			      (1U ^ se_pool_catalogue_ne64(row->epoch, epoch));
		__u32 select = 0U - match;
		asm volatile("" : "+r"(select));
		duplicate |= seen & match;
		seen |= match;
		index = (index & ~select) | (j & select);
	}
	return seen && !duplicate ? (int)index : -1;
}

/* The legacy preparer re-queries the global epoch index and cannot be used
 * with a retained scoped catalogue. Build the same accepted-only patch from
 * the exact classified rows. The TASK commit still compares every transaction
 * byte against the validated source snapshot, including unique policy UIDs. */
static __attribute__((always_inline)) inline int
se_owk_exec_prepare_scoped(struct se_exec_work *work, int success)
{
	struct se_exec_transaction *tx = &work->transaction;
	struct er_canonical_view *view = &work->view;
	struct er_fact_patch *patch = &work->patch;
	patch->prepared = patch->count = 0;
	if (!tx->owned ||
	    tx->eligibility_version != work->eligibility_version ||
	    tx->policy_count > 8 || view->work.error || !view->work.prepared)
		return -1;
	patch->base_version = view->work.base_version;
	patch->authority_version = view->work.authority_version;
	if (success && !tx->known_deny) {
		for (__u32 i = 0, bound = se_policy_bound(tx->policy_count);
		     i < bound && i < 8; i++) {
			int unknown = !!(tx->uncertain & (1U << i));
			if (!unknown && !(tx->grants & (1U << i)))
				continue;
			const struct se_exec_policy *policy = &tx->policies[i];
			int index = se_owk_scoped_policy_row(view, policy->uid,
							     policy->epoch);
			if (index < 0 || index >= ER_SLOTS ||
			    patch->count >= ER_ACTIVE)
				return -1;
			/* Rocky's 4.18 verifier loses the callee's unsigned bound
			 * after sign extension. Keep the map offset explicitly bounded. */
			__u32 row_index = (__u32)index & (ER_SLOTS - 1);
			struct er_row before = view->work.rows[row_index];
			struct er_row after = before;
			if (unknown)
				after.knowledge = ER_ROLE_UNKNOWN;
			else {
				if (!tx->witnesses[i])
					return -1;
				after.role = tx->witnesses[i];
				after.knowledge = ER_ROLE_KNOWN;
			}
			if (!after.uid || !after.epoch ||
			    after.epoch == ER_UNKNOWN || !after.role ||
			    after.reserved)
				return -1;
			__u32 next = patch->count++;
			patch->changes[next] = (struct er_fact_change){
				.before = before,
				.after = after,
				.index = row_index,
			};
		}
	}
	patch->prepared = 1;
	return 0;
}

/* Rocky 4.18 cannot preserve the bounds of the generic publisher's dynamic
 * change loop. A fixed eight-slot preflight and store keep the same
 * all-or-nothing contract without a verifier-visible dynamic patch pointer. */
static __attribute__((always_inline)) inline int
se_owk_patch_validate_one(const struct er_state *state,
			  const struct er_fact_change *change)
{
	if (change->index >= ER_SLOTS)
		return ER_INVALID;
	const struct er_row *row = &state->rows[change->index & (ER_SLOTS - 1)];
	if (row->uid != change->before.uid ||
	    row->epoch != change->before.epoch ||
	    row->role != change->before.role ||
	    row->knowledge != change->before.knowledge ||
	    row->reserved != change->before.reserved)
		return ER_STALE;
	if (change->after.uid != row->uid ||
	    change->after.epoch != row->epoch || !change->after.role ||
	    change->after.reserved ||
	    (change->after.knowledge != ER_ROLE_KNOWN &&
	     change->after.knowledge != ER_ROLE_UNKNOWN))
		return ER_INVALID;
	return row->role != change->after.role ||
	       row->knowledge != change->after.knowledge;
}
static __attribute__((always_inline)) inline void
se_owk_patch_store_one(struct er_state *state,
		       const struct er_fact_change *change)
{
	__u32 index = change->index & (ER_SLOTS - 1);
	state->rows[index].role = change->after.role;
	state->rows[index].knowledge = change->after.knowledge;
}
static __attribute__((always_inline)) inline int
se_owk_patch_publish_scoped(struct er_state *state,
			    const struct er_fact_patch *patch, __u64 authority)
{
	if (!patch->prepared || patch->count > ER_ACTIVE || !authority ||
	    authority != patch->authority_version ||
	    state->version != patch->base_version)
		return ER_STALE;
	int changed = 0, result;
#define SE_OWK_VALIDATE_SLOT(N)                                                \
	if (patch->count > (N)) {                                              \
		result = se_owk_patch_validate_one(state, &patch->changes[N]); \
		if (result < 0)                                                \
			return result;                                         \
		changed |= result;                                             \
	}
	SE_OWK_VALIDATE_SLOT(0)
	SE_OWK_VALIDATE_SLOT(1)
	SE_OWK_VALIDATE_SLOT(2)
	SE_OWK_VALIDATE_SLOT(3)
	SE_OWK_VALIDATE_SLOT(4)
	SE_OWK_VALIDATE_SLOT(5)
	SE_OWK_VALIDATE_SLOT(6)
	SE_OWK_VALIDATE_SLOT(7)
#undef SE_OWK_VALIDATE_SLOT
	if (changed && state->version >= ER_UNKNOWN - 1)
		return ER_STALE;
#define SE_OWK_STORE_SLOT(N)    \
	if (patch->count > (N)) \
		se_owk_patch_store_one(state, &patch->changes[N]);
	SE_OWK_STORE_SLOT(0)
	SE_OWK_STORE_SLOT(1)
	SE_OWK_STORE_SLOT(2)
	SE_OWK_STORE_SLOT(3)
	SE_OWK_STORE_SLOT(4)
	SE_OWK_STORE_SLOT(5)
	SE_OWK_STORE_SLOT(6)
	SE_OWK_STORE_SLOT(7)
#undef SE_OWK_STORE_SLOT
	if (changed)
		state->version++;
	return 0;
}
static __attribute__((always_inline)) inline int
se_owk_exec_complete_scoped_locked(struct se_task_state *task,
				   const struct se_exec_work *work,
				   __u64 authority)
{
	if (task->physical_cookie != work->physical_cookie ||
	    task->scope_cookie != work->scope_cookie ||
	    task->eligibility_version != work->eligibility_version ||
	    task->flags != work->flags || !task->exec.owned ||
	    __builtin_memcmp(&task->exec, &work->transaction,
			     sizeof(task->exec)))
		return -1;
	if (se_owk_patch_publish_scoped(&task->committed, &work->patch,
					authority))
		return -1;
	task->exec.owned = 0;
	return 0;
}

/* Normal prepared-WORK completion, not the allocation-independent emergency
 * fallback. The caller owns an ACTIVE charged WORK and exact live TASK lease,
 * and has snapshotted the current transaction and filled the catalogue.
 * Prepare outside the TASK lock; publish only after locked revalidation.
 * A failed postcommit reader release requires an exact TASK/invocation retry. */
static __attribute__((noinline)) int
se_owk_exec_complete_reader(struct se_owk_semantic_handle *handle, __u64 bprm,
			    __u64 invocation, int success)
{
	if (!handle || handle->held != 1 || !handle->owner || !handle->ticket ||
	    !handle->payload || !bprm || !invocation ||
	    (success != 0 && success != 1))
		return SE_OL_CORRUPT;
	struct se_exec_work *history = &handle->payload->semantic.history;
	if (!history->transaction.owned || history->transaction.bprm != bprm ||
	    history->transaction.sequence != invocation ||
	    history->transaction.generation !=
		    history->view.work.authority_version ||
	    se_owk_catalogue_classify_reader(handle) != SE_OL_OK ||
	    se_owk_exec_prepare_scoped(history, success))
		return SE_OL_CORRUPT;
	struct se_ol_payload_handle *owner = handle->owner;
	struct se_task_state *task = 0;
	int status = se_op_task_semantic_begin(owner, &task);
	if (status != SE_OL_OK)
		return status;
	int committed = !se_owk_exec_complete_scoped_locked(
		task, history, history->transaction.generation);
	se_op_task_semantic_end(owner, &task);
	if (!committed)
		return SE_OL_STALE;
	__u32 slot = handle->ticket->account_slot;
	struct se_route_anchor *route = SE_OC_ROUTE_LOOKUP(slot);
	struct se_binding_snapshots *binding = SE_OWK_BINDING_LOOKUP(slot);
	if (!route || !binding)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&route->lock);
	int released = se_exec_reader_release_locked(
		binding,
		&((struct se_pool_task_wire *)owner->payload)->semantic,
		owner->lease.cookie, invocation);
	bpf_spin_unlock(&route->lock);
	return released ? SE_OL_CORRUPT : SE_OL_OK;
}
#endif
