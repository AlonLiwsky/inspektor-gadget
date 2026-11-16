/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_SUSPENDED_READ_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_SUSPENDED_READ_CANDIDATE_H
#ifndef ENFORCE_EXEC_SUSPENDED_WORK_READ_CANDIDATE
#error "suspended WORK reader is an explicit test-only candidate"
#endif
#ifndef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE
#error "suspended WORK reader requires charged continuation lifecycle"
#endif
#ifndef SE_OWK_CURRENT_TASK
#error "supply the actual current task, not a caller-selected task key"
#endif
#include "shared_pool_opaque_work_continuation_candidate.h"

/* Same-callback observation (operation=0), exclusive stage claim (1),
 * release of that claim for immediate terminal close (2), or read-only
 * reauthentication of the claimed WORK after one same-task tail call (3),
 * NOT a transferable WORK lease. The
 * caller must be the current physical task inside its own exec LSM callback.
 * Exact source ordering makes task_free of that task impossible before this
 * callback returns; the suspended charge/owner ref excludes ordinary reaping.
 * A claim reserves only a nonfinal evaluator stage, after authenticating the
 * physical current TASK; a caller-supplied payload is never claim authority.
 * This helper returns no authority to resume, finish or refund WORK. It must
 * never be used from a timer, reaper, or another task. Operation 3 alone is
 * permitted after a tail call; it rederives every TASK/charge/WORK fact. */
static __attribute__((noinline)) struct se_owk_payload *
se_owk_suspended_current(__u64 expected_scope, __u32 expected_stage,
			 __u32 operation)
{
#ifdef SE_OWK_STAGE_CLASSES
	/* A class token (pass p, residue r) admits any one stage of its class;
	 * the claim then rechecks exactly the stage the first read observed. */
	if (!expected_scope || operation > 3 ||
	    !se_owk_stage_expected_valid(expected_stage))
		return 0;
#else
	if (!expected_scope || !expected_stage || operation > 3 ||
	    expected_stage > SE_OWK_CONTINUATION_MAX)
		return 0;
#endif
#ifndef ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC
	/* The standalone suspended reader remains strictly observational. */
	if (operation)
		return 0;
#endif
	if (operation && expected_stage == SE_OWK_CONTINUATION_MAX)
		return 0;
	__u64 physical = (__u64)SE_OWK_CURRENT_TASK();
	if (!physical)
		return 0;
	const __u64 *first = SE_OL_LOOKUP(&physical);
	if (!first)
		return 0;
	__u64 locator = se_ol_load_scalar(first);
	__u32 task_slot = 0;
	if (se_ol_decode(locator, &task_slot) != SE_OL_OK)
		return 0;
	struct se_ol_meta *task = SE_OL_META_LOOKUP(task_slot);
	struct se_pool_task_wire *task_payload =
		SE_OL_PAYLOAD_LOOKUP(task_slot);
	if (!task || !task_payload)
		return 0;
	__u64 task_cookie = 0, work_cookie = 0, invocation = 0;
	__u32 work_slot = 0, account_slot = 0, incarnation = 0;
	bpf_spin_lock(&task->lock);
	int live = task->phase == SE_OL_LIVE &&
		   task->directory_state == SE_OL_PUBLISHED &&
		   task->archive_ready == 1 && !task->reserved &&
		   !task->exclusive && !task->exclusive_owner &&
		   task->locator == locator && task->cookie &&
		   task->account_scope == expected_scope &&
		   task->account_slot < SE_OC_ACCOUNTS &&
		   task->account_incarnation && task->work_refs &&
		   task->current_work_owned == 1 &&
		   task->current_work_slot < SE_OWK_WORKS &&
		   task->current_work_cookie && task->next_work_sequence &&
		   !task_payload->identity.reserved_lock &&
		   !task_payload->identity.identity_reserved &&
		   (task_payload->identity.flags & SE_OL_TASK_LIVE) &&
		   task_payload->identity.physical_cookie == task->cookie &&
		   task_payload->identity.scope_cookie == expected_scope &&
		   task_payload->identity.scope_slot == task->account_slot;
	if (live) {
		task_cookie = task->cookie;
		work_cookie = task->current_work_cookie;
		work_slot = task->current_work_slot;
		account_slot = task->account_slot;
		incarnation = task->account_incarnation;
		invocation = task->next_work_sequence;
	}
	bpf_spin_unlock(&task->lock);
	if (!live || task_slot / SE_OC_QUOTA != account_slot ||
	    work_slot / SE_OWK_QUOTA != account_slot)
		return 0;
	/* A first HASH value may have been recycled. Never derive authority from
	 * it without relooking up the ORIGINAL current-task key. */
	const __u64 *second = SE_OL_LOOKUP(&physical);
	if (!second || se_ol_load_scalar(second) != locator)
		return 0;
	__u32 task_local = task_slot - account_slot * SE_OC_QUOTA;
	__u32 work_local = work_slot - account_slot * SE_OWK_QUOTA;
	if (task_local >= SE_OC_QUOTA || work_local >= SE_OWK_QUOTA)
		return 0;
	struct se_oc_account *task_account = SE_OC_ACCOUNT_LOOKUP(account_slot);
	struct se_oc_charge *task_charge = SE_OC_CHARGE_LOOKUP(task_slot);
	struct se_owk_account *work_account =
		SE_OWK_ACCOUNT_LOOKUP(account_slot);
	struct se_owk_charge *work_charge = SE_OWK_CHARGE_LOOKUP(work_slot);
	struct se_owk_meta *work = SE_OWK_META_LOOKUP(work_slot);
	struct se_owk_payload *payload = SE_OWK_PAYLOAD_LOOKUP(work_slot);
	if (!task_account || !task_charge || !work_account || !work_charge ||
	    !work || !payload)
		return 0;
	bpf_spin_lock(&task_account->lock);
	int task_charged =
		!task_account->fault && !task_account->reserved &&
		task_account->scope == expected_scope &&
		task_account->incarnation == incarnation &&
		task_account->used && task_account->used <= SE_OC_QUOTA &&
		se_oc_bitmap_count(task_account) == task_account->used &&
		(task_account->bits[SE_OC_WORD(task_local)] &
		 (1ULL << (task_local % 64U))) &&
		task_charge->state == SE_OC_OWNED &&
		task_charge->cookie == task_cookie &&
		task_charge->scope == expected_scope &&
		task_charge->incarnation == incarnation &&
		task_charge->locator == locator;
	bpf_spin_unlock(&task_account->lock);
	if (!task_charged)
		return 0;
	bpf_spin_lock(&work_account->lock);
	int work_charged =
		!work_account->fault && !work_account->reserved &&
		work_account->scope == expected_scope &&
		work_account->incarnation == incarnation &&
		work_account->used && work_account->used <= SE_OWK_QUOTA &&
		se_owk_count(work_account->bits) == work_account->used &&
		(work_account->bits & (1ULL << work_local)) &&
		work_charge->state == SE_OWK_OWNED &&
		work_charge->cookie == work_cookie &&
		work_charge->scope == expected_scope &&
		work_charge->incarnation == incarnation &&
		work_charge->owner_locator == locator &&
		work_charge->owner_cookie == task_cookie &&
		work_charge->owner_slot == task_slot;
	bpf_spin_unlock(&work_account->lock);
	if (!work_charged)
		return 0;
	bpf_spin_lock(&work->lock);
	int suspended =
		work->phase == SE_OWK_SUSPENDED && work->active_leases == 0 &&
		work->owner_ref_held == 1 && !work->cleanup_done &&
		work->continuation_reserved ==
			(operation == 2 || operation == 3) &&
#ifdef SE_OWK_STAGE_CLASSES
		se_owk_stage_matches(work->continuation_stage,
				     expected_stage) &&
#else
		work->continuation_stage == expected_stage &&
#endif
		work->cookie == work_cookie && work->scope == expected_scope &&
		work->account_slot == account_slot &&
		work->incarnation == incarnation &&
		work->owner_locator == locator &&
		work->owner_cookie == task_cookie &&
		work->owner_slot == task_slot &&
		work->invocation_sequence == invocation &&
		payload->semantic.scope == expected_scope &&
		payload->semantic.cookie == work_cookie &&
		payload->semantic.sequence == invocation &&
		payload->semantic.slot == work_slot &&
		!payload->semantic.reserved &&
		payload->semantic.view.scope_cookie == expected_scope &&
		payload->semantic.view.ready == 1;
#ifdef SE_OWK_STAGE_CLASSES
	__u32 stage_seen = work->continuation_stage;
#endif
	bpf_spin_unlock(&work->lock);
	if (!suspended)
		return 0;
	/* Close the observation with a fresh TASK snapshot. No lock or borrowed
	 * map pointer is carried into the evaluator's nested callbacks. */
	bpf_spin_lock(&task->lock);
	live = task->phase == SE_OL_LIVE && task->locator == locator &&
	       task->cookie == task_cookie &&
	       task->account_scope == expected_scope &&
	       task->current_work_owned == 1 &&
	       task->current_work_slot == work_slot &&
	       task->current_work_cookie == work_cookie &&
	       task->next_work_sequence == invocation;
	bpf_spin_unlock(&task->lock);
	if (!live || operation == 0 || operation == 3)
		return live ? payload : 0;
	/* The first WORK read was deliberately non-mutating. Claim only after
	 * both independent TASK snapshots and both account charges succeeded;
	 * recheck the exact suspended identity under the WORK lock before the
	 * single transition. This leaves no caller-controlled claim API. */
	bpf_spin_lock(&work->lock);
	suspended =
		work->phase == SE_OWK_SUSPENDED && work->active_leases == 0 &&
		work->owner_ref_held == 1 && !work->cleanup_done &&
		work->continuation_reserved == (operation == 2) &&
#ifdef SE_OWK_STAGE_CLASSES
		work->continuation_stage == stage_seen &&
#else
		work->continuation_stage == expected_stage &&
#endif
		work->cookie == work_cookie && work->scope == expected_scope &&
		work->account_slot == account_slot &&
		work->incarnation == incarnation &&
		work->owner_locator == locator &&
		work->owner_cookie == task_cookie &&
		work->owner_slot == task_slot &&
		work->invocation_sequence == invocation &&
		payload->semantic.scope == expected_scope &&
		payload->semantic.cookie == work_cookie &&
		payload->semantic.sequence == invocation &&
		payload->semantic.slot == work_slot &&
		!payload->semantic.reserved &&
		payload->semantic.view.scope_cookie == expected_scope &&
		payload->semantic.view.ready == 1;
	if (suspended)
		work->continuation_reserved = operation == 1;
	bpf_spin_unlock(&work->lock);
	return suspended ? payload : 0;
}

#ifdef ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC
static __attribute__((noinline)) int
se_owk_commit_suspended_stage(struct se_owk_payload *payload, __u64 scope,
			      __u32 stage)
{
	if (!payload || !scope || !stage || stage >= SE_OWK_CONTINUATION_MAX)
		return SE_OL_CORRUPT;
	__u32 slot = payload->semantic.slot;
	__u64 cookie = payload->semantic.cookie;
	if (slot >= SE_OWK_WORKS || !cookie ||
	    SE_OWK_PAYLOAD_LOOKUP(slot) != payload)
		return SE_OL_CORRUPT;
	struct se_owk_meta *meta = SE_OWK_META_LOOKUP(slot);
	if (!meta)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact =
		meta->phase == SE_OWK_SUSPENDED && meta->active_leases == 0 &&
		meta->owner_ref_held == 1 && !meta->cleanup_done &&
		meta->continuation_reserved == 1 &&
		meta->continuation_stage == stage && meta->cookie == cookie &&
		meta->scope == scope && meta->invocation_sequence &&
		payload->semantic.scope == scope &&
		payload->semantic.cookie == cookie &&
		payload->semantic.sequence == meta->invocation_sequence &&
		payload->semantic.slot == slot && !payload->semantic.reserved;
	if (exact) {
		meta->continuation_stage = stage + 1;
		meta->continuation_reserved = 0;
	}
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_STALE;
}

/* Nested scalar relookup for the unarmed stack experiment only. The entry
 * program must first claim with se_owk_suspended_current(..., 1) in this callback;
 * this read does not authenticate entry, claim a stage or own cleanup. */
/* Continuation stage whose suspended WORK the evaluator view resolves. The
 * verdict candidate inserts a prepare stage and evaluates at stage 2. */
#ifndef SE_OWK_EVAL_VIEW_STAGE
#define SE_OWK_EVAL_VIEW_STAGE 1
#endif
static __attribute__((always_inline)) inline struct se_policy_view *
se_owk_suspended_view_from_token(__u32 slot, __u64 cookie)
{
	if (slot >= SE_OWK_WORKS || !cookie || cookie > SE_OWK_COOKIE_LIMIT)
		return 0;
	struct se_owk_meta *meta = SE_OWK_META_LOOKUP(slot);
	struct se_owk_payload *payload = SE_OWK_PAYLOAD_LOOKUP(slot);
	if (!meta || !payload)
		return 0;
	bpf_spin_lock(&meta->lock);
	int exact = meta->phase == SE_OWK_SUSPENDED &&
		    meta->active_leases == 0 && meta->owner_ref_held == 1 &&
		    !meta->cleanup_done && meta->continuation_reserved == 1 &&
#ifdef SE_OWK_STAGE_CLASSES
		    se_owk_stage_matches(meta->continuation_stage,
					 SE_OWK_EVAL_VIEW_STAGE) &&
#else
		    meta->continuation_stage == SE_OWK_EVAL_VIEW_STAGE &&
#endif
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
#endif
