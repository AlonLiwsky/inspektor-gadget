/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_EVAL_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_EVAL_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_DEVELOPMENT) ||            \
	!defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY) || \
	!defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE)
#error "typed WORK evaluator resolver is candidate-only"
#endif

/* A scalar token is a lookup context, not a WORK lease. The selected caller
 * must hold its exact TASK semantic handle and WORK ticket through every
 * evaluator callback. This function does not acquire a second lease, infer
 * one from current task address, or extend payload lifetime. */
static __always_inline struct se_policy_view *
se_pool_view_from_token(const struct fm_global_token *token)
{
	if (!token || token->reserved || !token->cookie ||
	    token->cookie > SE_PW_U64_LIMIT || token->slot >= SE_POOL_W)
		return 0;
	__u32 slot = token->slot;
	struct se_pool_work_meta *meta =
		bpf_map_lookup_elem(&se_pool_work_meta, &slot);
	struct se_pool_work_payload *payload =
		bpf_map_lookup_elem(&se_pool_work_payload, &slot);
	if (!meta || !payload)
		return 0;
	bpf_spin_lock(&meta->lock);
	int valid =
		meta->phase == SE_PW_ACTIVE && meta->cookie == token->cookie &&
		meta->active_leases == 1 && meta->owner_ref_held == 1 &&
		!meta->cleanup_done && meta->owner_task_cookie &&
		meta->owner_task_address && meta->owner_task_slot < SE_POOL_T &&
		meta->account_scope && meta->account_slot < SE_POOL_B &&
		meta->account_incarnation && meta->invocation_sequence &&
		payload->semantic.scope == meta->account_scope &&
		payload->semantic.cookie == token->cookie &&
		payload->semantic.sequence == meta->invocation_sequence &&
		payload->semantic.slot == slot && !payload->semantic.reserved;
	bpf_spin_unlock(&meta->lock);
	return valid ? &payload->semantic.view : 0;
}
#endif
