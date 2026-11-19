/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE
#error "WORK continuation is an explicit candidate only"
#endif
#ifndef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
#error "WORK continuation requires the typed opaque WORK semantic"
#endif
#include "shared_pool_opaque_work_candidate.h"
#ifndef SE_OWK_RESUME_AFTER_CLAIM
#define SE_OWK_RESUME_AFTER_CLAIM() ((void)0)
#endif

/* The first callback has an ACTIVE lexical ticket; no map-value pointer or
 * BPF stack address may cross a tail call. Suspension retains the charged
 * WORK and its TASK owner reference, but drops this callback's WORK lease.
 * Exactly one successor can resume a particular stage. The stage is bounded
 * here for testing, not a claim that 32 product programs suffice. */
#define SE_OWK_CONTINUATION_MAX 32U
/* G019 gap 4 (review H1): stage classes for the same-bprm interpreter
 * continuation. One bprm_execve runs at most SE_OWK_EXEC_PASSES
 * search_binary_handler passes (exec_binprm depth 0..5; depth 6 is -ELOOP
 * before any bprm_check), and pass p uses stages 3p+1 (prepare), 3p+2
 * (evaluation) and 3p+3 (terminal). A class token names the residue r
 * (stage % 3) and the highest admitted pass; it matches exactly the stages
 * {3p + (r ? r : 3) : 0 <= p <= max_pass}. A plain stage still matches only
 * itself. A class match never changes the monotone +1 suspension rule: the
 * resumed ticket carries the actual stage, so every successor suspends to
 * exactly the next one. Objects without SE_OWK_STAGE_CLASSES keep the exact
 * single-stage comparisons (and their bytes). */
#ifdef SE_OWK_STAGE_CLASSES
#define SE_OWK_EXEC_PASSES 6U
#define SE_OWK_STAGE_CLASS_FLAG 0x100U
#define SE_OWK_STAGE_CLASS(residue, max_pass) \
	(SE_OWK_STAGE_CLASS_FLAG | ((__u32)(max_pass) << 2) | (__u32)(residue))
static __attribute__((always_inline)) inline __u32
se_owk_stage_class_last(__u32 token)
{
	__u32 residue = token & 3U;
	return 3U * ((token >> 2) & 0x3fU) + (residue ? residue : 3U);
}
/* A valid expected stage: a plain stage 1..MAX, or a class token with a
 * residue 0..2, a pass bound below SE_OWK_EXEC_PASSES and no other bits. */
static __attribute__((always_inline)) inline int
se_owk_stage_expected_valid(__u32 expected)
{
	if (!(expected & SE_OWK_STAGE_CLASS_FLAG))
		return expected && expected <= SE_OWK_CONTINUATION_MAX;
	return !(expected & ~(SE_OWK_STAGE_CLASS_FLAG | 0xffU)) &&
	       (expected & 3U) < 3U &&
	       ((expected >> 2) & 0x3fU) < SE_OWK_EXEC_PASSES &&
	       se_owk_stage_class_last(expected) < SE_OWK_CONTINUATION_MAX;
}
static __attribute__((always_inline)) inline int
se_owk_stage_matches(__u32 stage, __u32 expected)
{
	if (!(expected & SE_OWK_STAGE_CLASS_FLAG))
		return stage == expected;
	return stage && stage <= se_owk_stage_class_last(expected) &&
	       stage % 3U == (expected & 3U);
}
#else
#define se_owk_stage_expected_valid(expected) \
	((expected) && (expected) <= SE_OWK_CONTINUATION_MAX)
#define se_owk_stage_matches(stage, expected) ((stage) == (expected))
#endif
static __attribute__((noinline)) int
se_owk_suspend(struct se_ol_payload_handle *owner, struct se_owk_ticket *ticket,
	       __u32 next_stage)
{
	if (!owner || !ticket || owner->locked || owner->lease.held != 1 ||
	    !owner->lease.meta || !owner->payload || ticket->held != 1 ||
	    ticket->stage != 3 || ticket->reserved || !next_stage ||
	    next_stage > SE_OWK_CONTINUATION_MAX ||
	    next_stage != ticket->continuation_stage + 1U ||
	    ticket->work_slot >= SE_OWK_WORKS ||
	    ticket->account_slot >= SE_OWK_ACCOUNTS ||
	    ticket->owner_slot != owner->lease.slot ||
	    ticket->owner_locator != owner->lease.locator ||
	    ticket->owner_cookie != owner->lease.cookie ||
	    ticket->work_slot / SE_OWK_QUOTA != ticket->account_slot)
		return SE_OL_CORRUPT;
	__u32 local = ticket->work_slot - ticket->account_slot * SE_OWK_QUOTA;
	if (local >= SE_OWK_QUOTA)
		return SE_OL_CORRUPT;
	struct se_owk_account *account =
		SE_OWK_ACCOUNT_LOOKUP(ticket->account_slot);
	struct se_owk_charge *charge = SE_OWK_CHARGE_LOOKUP(ticket->work_slot);
	struct se_owk_meta *work = SE_OWK_META_LOOKUP(ticket->work_slot);
	struct se_owk_payload *payload =
		SE_OWK_PAYLOAD_LOOKUP(ticket->work_slot);
	if (!account || !charge || !work || !payload) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	__u64 bit = 1ULL << local;
	bpf_spin_lock(&account->lock);
	int charged = !account->fault && !account->reserved &&
		      account->scope == ticket->scope &&
		      account->incarnation == ticket->incarnation &&
		      account->used && account->used <= SE_OWK_QUOTA &&
		      se_owk_count(account->bits) == account->used &&
		      (account->bits & bit) && charge->state == SE_OWK_OWNED &&
		      charge->cookie == ticket->cookie &&
		      charge->scope == ticket->scope &&
		      charge->incarnation == ticket->incarnation &&
		      charge->owner_locator == ticket->owner_locator &&
		      charge->owner_cookie == ticket->owner_cookie &&
		      charge->owner_slot == ticket->owner_slot;
	bpf_spin_unlock(&account->lock);
	struct se_ol_meta *task = owner->lease.meta;
	bpf_spin_lock(&task->lock);
	int task_exact = task->phase == SE_OL_LIVE &&
			 task->locator == ticket->owner_locator &&
			 task->cookie == ticket->owner_cookie &&
			 task->active_leases &&
			 task->account_scope == ticket->scope &&
			 task->account_slot == ticket->account_slot &&
			 task->account_incarnation == ticket->incarnation &&
			 task->work_refs && task->current_work_owned == 1 &&
			 task->current_work_cookie == ticket->cookie &&
			 task->current_work_slot == ticket->work_slot;
	bpf_spin_unlock(&task->lock);
	bpf_spin_lock(&work->lock);
	int exact = charged && task_exact && work->phase == SE_OWK_ACTIVE &&
		    work->active_leases == 1 && work->owner_ref_held == 1 &&
		    !work->cleanup_done && work->cookie == ticket->cookie &&
		    work->owner_locator == ticket->owner_locator &&
		    work->owner_cookie == ticket->owner_cookie &&
		    work->owner_slot == ticket->owner_slot &&
		    work->scope == ticket->scope &&
		    work->account_slot == ticket->account_slot &&
		    work->incarnation == ticket->incarnation &&
		    work->invocation_sequence == ticket->invocation_sequence &&
		    work->continuation_stage == ticket->continuation_stage &&
		    !work->continuation_reserved &&
		    payload->scope == ticket->scope &&
		    payload->cookie == ticket->cookie &&
		    payload->sequence == ticket->invocation_sequence &&
		    payload->slot == ticket->work_slot && !payload->reserved;
	if (exact) {
		work->phase = SE_OWK_SUSPENDED;
		work->active_leases = 0;
		work->continuation_stage = next_stage;
	}
	bpf_spin_unlock(&work->lock);
	if (!exact) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	ticket->held = 0;
	ticket->stage = 6;
	ticket->continuation_stage = next_stage;
	return SE_OL_OK;
}

/* The successor first opens the ORIGINAL physical TASK key. The held exact
 * TASK lease prevents reuse; its current-WORK field only locates a candidate.
 * Account charge, WORK metadata, payload identity and monotone stage must all
 * agree before one ACTIVE lease/ticket is issued. A replay cannot acquire it. */
#if defined(ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC) && \
	!defined(ENFORCE_EXEC_STAGE2_SOURCE_OBJECT)
#define SE_OWK_RESUME_ATTR __attribute__((always_inline)) inline
#else
#define SE_OWK_RESUME_ATTR __attribute__((noinline))
#endif
static SE_OWK_RESUME_ATTR int se_owk_resume(struct se_ol_payload_handle *owner,
					    __u32 expected_stage,
					    struct se_owk_ticket *ticket)
{
	if (!owner || !ticket || ticket->held || ticket->cookie ||
	    owner->locked || owner->lease.held != 1 || !owner->lease.meta ||
#ifdef SE_OWK_STAGE_CLASSES
	    !owner->payload || !se_owk_stage_expected_valid(expected_stage))
#else
	    !owner->payload || !expected_stage ||
	    expected_stage > SE_OWK_CONTINUATION_MAX)
#endif
		return SE_OL_CORRUPT;
	struct se_ol_meta *task = owner->lease.meta;
	__u64 scope = 0, cookie = 0, invocation = 0;
	__u32 account_slot = 0, incarnation = 0, work_slot = 0;
	bpf_spin_lock(&task->lock);
	int live = task->phase == SE_OL_LIVE &&
		   task->directory_state == SE_OL_PUBLISHED &&
		   task->archive_ready == 1 && !task->reserved &&
		   !task->exclusive && !task->exclusive_owner &&
		   task->locator == owner->lease.locator &&
		   task->cookie == owner->lease.cookie && task->active_leases &&
		   task->current_work_owned == 1 && task->work_refs &&
		   task->current_work_cookie &&
		   task->current_work_slot < SE_OWK_WORKS;
	if (live) {
		scope = task->account_scope;
		account_slot = task->account_slot;
		incarnation = task->account_incarnation;
		cookie = task->current_work_cookie;
		work_slot = task->current_work_slot;
		invocation = task->next_work_sequence;
	}
	bpf_spin_unlock(&task->lock);
	if (!live || !scope || !incarnation || !cookie || !invocation ||
	    account_slot >= SE_OWK_ACCOUNTS ||
	    work_slot / SE_OWK_QUOTA != account_slot ||
	    owner->lease.slot / SE_OC_QUOTA != account_slot)
		return SE_OL_STALE;
	__u32 local = work_slot - account_slot * SE_OWK_QUOTA;
	if (local >= SE_OWK_QUOTA)
		return SE_OL_CORRUPT;
	struct se_owk_account *account = SE_OWK_ACCOUNT_LOOKUP(account_slot);
	struct se_owk_charge *charge = SE_OWK_CHARGE_LOOKUP(work_slot);
	struct se_owk_meta *work = SE_OWK_META_LOOKUP(work_slot);
	struct se_owk_payload *payload = SE_OWK_PAYLOAD_LOOKUP(work_slot);
	if (!account || !charge || !work || !payload)
		return SE_OL_CORRUPT;
	__u64 bit = 1ULL << local;
	bpf_spin_lock(&account->lock);
	int charged = !account->fault && !account->reserved &&
		      account->scope == scope &&
		      account->incarnation == incarnation && account->used &&
		      account->used <= SE_OWK_QUOTA &&
		      se_owk_count(account->bits) == account->used &&
		      (account->bits & bit) && charge->state == SE_OWK_OWNED &&
		      charge->cookie == cookie && charge->scope == scope &&
		      charge->incarnation == incarnation &&
		      charge->owner_locator == owner->lease.locator &&
		      charge->owner_cookie == owner->lease.cookie &&
		      charge->owner_slot == owner->lease.slot;
	bpf_spin_unlock(&account->lock);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_RESUME_OUTPUT_TICKET_DIAGNOSTIC
	struct se_owk_ticket *candidate = ticket;
#define SE_OWK_RESUME_CLEAR_RETURN(code)            \
	do {                                        \
		*ticket = (struct se_owk_ticket){}; \
		return (code);                      \
	} while (0)
#else
	struct se_owk_ticket local_candidate;
	struct se_owk_ticket *candidate = &local_candidate;
#define SE_OWK_RESUME_CLEAR_RETURN(code) return (code)
#endif
	*candidate = (struct se_owk_ticket){
		.cookie = cookie,
		.scope = scope,
		.owner_locator = owner->lease.locator,
		.owner_cookie = owner->lease.cookie,
		.account_slot = account_slot,
		.incarnation = incarnation,
		.work_slot = work_slot,
		.owner_slot = owner->lease.slot,
		.invocation_sequence = invocation,
		.held = 1,
		.stage = 3,
		.continuation_stage = expected_stage,
	};
	if (!charged) {
		bpf_spin_lock(&task->lock);
		int dead = task->phase == SE_OL_DEAD &&
			   task->locator == owner->lease.locator &&
			   task->cookie == owner->lease.cookie;
		bpf_spin_unlock(&task->lock);
		if (dead)
			return SE_OL_STALE;
		se_owk_fault_ticket(candidate);
		SE_OWK_RESUME_CLEAR_RETURN(SE_OL_CORRUPT);
	}
	bpf_spin_lock(&work->lock);
	int identity =
		work->cookie == cookie &&
		work->owner_locator == owner->lease.locator &&
		work->owner_cookie == owner->lease.cookie &&
		work->owner_slot == owner->lease.slot && work->scope == scope &&
		work->account_slot == account_slot &&
		work->incarnation == incarnation &&
		work->invocation_sequence == invocation &&
		work->owner_ref_held == 1 && !work->cleanup_done &&
		!work->continuation_reserved && payload->scope == scope &&
		payload->cookie == cookie && payload->sequence == invocation &&
		payload->slot == work_slot && !payload->reserved;
#ifdef SE_OWK_STAGE_CLASSES
	/* A class mismatch is a non-mutating STALE replay, like a stage one. */
	__u32 stage_seen = work->continuation_stage;
	int stage_match = se_owk_stage_matches(stage_seen, expected_stage);
	int pending = identity && work->phase == SE_OWK_SUSPENDED &&
		      work->active_leases == 0 && stage_match;
	int replay = identity && (work->phase == SE_OWK_ACTIVE ||
				  work->phase == SE_OWK_DEATH_FINALIZING ||
				  work->phase == SE_OWK_DONE || !stage_match);
#else
	int pending = identity && work->phase == SE_OWK_SUSPENDED &&
		      work->active_leases == 0 &&
		      work->continuation_stage == expected_stage;
	int replay = identity && (work->phase == SE_OWK_ACTIVE ||
				  work->phase == SE_OWK_DEATH_FINALIZING ||
				  work->phase == SE_OWK_DONE ||
				  work->continuation_stage != expected_stage);
#endif
	if (pending) {
		work->phase = SE_OWK_ACTIVE;
		work->active_leases = 1;
	}
	bpf_spin_unlock(&work->lock);
#ifdef SE_OWK_STAGE_CLASSES
	/* The successor suspends to exactly the observed stage + 1. */
	if (pending)
		candidate->continuation_stage = (__u16)stage_seen;
#endif
	if (!pending) {
		if (!replay)
			se_owk_fault_ticket(candidate);
		SE_OWK_RESUME_CLEAR_RETURN(replay ? SE_OL_STALE :
						    SE_OL_CORRUPT);
	}
	SE_OWK_RESUME_AFTER_CLAIM();
	/* task_free may have marked DEAD after the first TASK snapshot but
     * before this WORK claim. In that case the successor owns the ACTIVE
     * ticket and must finish it, not leave a charge the death callback could
     * only have observed as ACTIVE. */
	bpf_spin_lock(&task->lock);
	int still_live = task->phase == SE_OL_LIVE &&
			 task->locator == owner->lease.locator &&
			 task->cookie == owner->lease.cookie &&
			 task->active_leases;
	int died = task->phase == SE_OL_DEAD &&
		   task->locator == owner->lease.locator &&
		   task->cookie == owner->lease.cookie && task->active_leases;
	bpf_spin_unlock(&task->lock);
	if (!still_live) {
		if (died && se_owk_done(owner, candidate) == SE_OL_OK)
			SE_OWK_RESUME_CLEAR_RETURN(SE_OL_STALE);
		se_owk_fault_ticket(candidate);
		SE_OWK_RESUME_CLEAR_RETURN(SE_OL_CORRUPT);
	}
#ifndef ENFORCE_EXEC_POOL_OPAQUE_RESUME_OUTPUT_TICKET_DIAGNOSTIC
	*ticket = *candidate;
#endif
#undef SE_OWK_RESUME_CLEAR_RETURN
	return SE_OL_OK;
}
#undef SE_OWK_RESUME_ATTR

/* Only the typed task_free callback's exact death lease may terminate a
 * suspended WORK after its producer's stack ticket has been consumed. The
 * TASK current-WORK tuple locates a candidate, never authorizes its cleanup.
 * Charge, metadata, semantic payload and death identity must all match. */
static __attribute__((noinline)) int
se_owk_finish_suspended_death(struct se_of_lease *dying)
{
	if (!dying || dying->held != 1 || dying->locked || !dying->meta ||
	    !dying->physical || dying->slot >= SE_OL_TASKS || !dying->locator ||
	    !dying->cookie)
		return SE_OL_CORRUPT;
	struct se_ol_meta *task = dying->meta;
	__u64 scope = 0, cookie = 0, invocation = 0;
	__u32 account_slot = 0, incarnation = 0, work_slot = 0;
	bpf_spin_lock(&task->lock);
	int dead = task->phase == SE_OL_DEAD &&
		   task->locator == dying->locator &&
		   task->cookie == dying->cookie && task->active_leases &&
		   task->current_work_owned == 1 && task->work_refs &&
		   task->current_work_cookie &&
		   task->current_work_slot < SE_OWK_WORKS &&
		   task->account_scope && task->account_incarnation;
	if (dead) {
		scope = task->account_scope;
		account_slot = task->account_slot;
		incarnation = task->account_incarnation;
		cookie = task->current_work_cookie;
		work_slot = task->current_work_slot;
		invocation = task->next_work_sequence;
	}
	bpf_spin_unlock(&task->lock);
	if (!dead)
		return SE_OL_STALE;
	if (!invocation || account_slot >= SE_OWK_ACCOUNTS ||
	    dying->slot / SE_OC_QUOTA != account_slot ||
	    work_slot / SE_OWK_QUOTA != account_slot)
		return SE_OL_CORRUPT;
	__u32 local = work_slot - account_slot * SE_OWK_QUOTA;
	if (local >= SE_OWK_QUOTA)
		return SE_OL_CORRUPT;
	struct se_owk_account *account = SE_OWK_ACCOUNT_LOOKUP(account_slot);
	struct se_owk_charge *charge = SE_OWK_CHARGE_LOOKUP(work_slot);
	struct se_owk_meta *work = SE_OWK_META_LOOKUP(work_slot);
	struct se_owk_payload *payload = SE_OWK_PAYLOAD_LOOKUP(work_slot);
	if (!account || !charge || !work || !payload)
		return SE_OL_CORRUPT;
	struct se_owk_ticket witness = {
		.cookie = cookie,
		.scope = scope,
		.owner_locator = dying->locator,
		.owner_cookie = dying->cookie,
		.account_slot = account_slot,
		.incarnation = incarnation,
		.work_slot = work_slot,
		.owner_slot = dying->slot,
		.invocation_sequence = invocation,
		.held = 1,
	};
	__u64 bit = 1ULL << local;
	bpf_spin_lock(&account->lock);
	int charged = !account->fault && !account->reserved &&
		      account->scope == scope &&
		      account->incarnation == incarnation && account->used &&
		      account->used <= SE_OWK_QUOTA &&
		      se_owk_count(account->bits) == account->used &&
		      (account->bits & bit) && charge->state == SE_OWK_OWNED &&
		      charge->cookie == cookie && charge->scope == scope &&
		      charge->incarnation == incarnation &&
		      charge->owner_locator == dying->locator &&
		      charge->owner_cookie == dying->cookie &&
		      charge->owner_slot == dying->slot;
	bpf_spin_unlock(&account->lock);
	if (!charged) {
		se_owk_fault_ticket(&witness);
		return SE_OL_CORRUPT;
	}
	bpf_spin_lock(&work->lock);
	int identity = work->cookie == cookie && work->scope == scope &&
		       work->incarnation == incarnation &&
		       work->account_slot == account_slot &&
		       work->owner_locator == dying->locator &&
		       work->owner_cookie == dying->cookie &&
		       work->owner_slot == dying->slot &&
		       work->invocation_sequence == invocation &&
		       work->owner_ref_held == 1 && !work->cleanup_done &&
		       !work->continuation_reserved &&
		       payload->scope == scope && payload->cookie == cookie &&
		       payload->sequence == invocation &&
		       payload->slot == work_slot && !payload->reserved;
	int suspended = identity && work->phase == SE_OWK_SUSPENDED &&
			!work->active_leases && work->continuation_stage &&
			work->continuation_stage <= SE_OWK_CONTINUATION_MAX;
	int active = identity && work->phase == SE_OWK_ACTIVE &&
		     work->active_leases == 1;
	if (suspended)
		work->phase = SE_OWK_DEATH_FINALIZING;
	bpf_spin_unlock(&work->lock);
	if (!suspended) {
		if (!active)
			se_owk_fault_ticket(&witness);
		return active ? SE_OL_CONTENDED : SE_OL_CORRUPT;
	}
	bpf_spin_lock(&task->lock);
	int exact = task->phase == SE_OL_DEAD &&
		    task->locator == dying->locator &&
		    task->cookie == dying->cookie && task->active_leases &&
		    task->account_scope == scope &&
		    task->account_slot == account_slot &&
		    task->account_incarnation == incarnation &&
		    task->work_refs && task->current_work_owned == 1 &&
		    task->current_work_cookie == cookie &&
		    task->current_work_slot == work_slot;
	if (exact) {
		task->current_work_owned = 0;
		task->current_work_cookie = 0;
		task->current_work_slot = 0;
	}
	bpf_spin_unlock(&task->lock);
	if (!exact) {
		se_owk_fault_ticket(&witness);
		return SE_OL_CORRUPT;
	}
	bpf_spin_lock(&work->lock);
	exact = work->phase == SE_OWK_DEATH_FINALIZING &&
		!work->active_leases && work->owner_ref_held == 1 &&
		work->cookie == cookie &&
		work->owner_locator == dying->locator &&
		work->owner_cookie == dying->cookie;
	if (exact) {
		work->phase = SE_OWK_DONE;
		work->continuation_stage = 0;
	}
	bpf_spin_unlock(&work->lock);
	if (!exact) {
		se_owk_fault_ticket(&witness);
		return SE_OL_CORRUPT;
	}
#ifdef SE_REAP_EVENT
	/* Product reaper wakeup only (G019 M1); never authority. */
	SE_REAP_EVENT(WORK_DONE, work_slot, cookie);
#endif
	return SE_OL_OK;
}
#endif
