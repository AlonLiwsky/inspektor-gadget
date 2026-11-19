/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_REAP_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_REAP_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque WORK reaper is candidate-only"
#endif
#include "shared_pool_opaque_work_candidate.h"

enum se_owk_reap_result {
	SE_OWK_PROGRESS = 0,
	SE_OWK_RETURNED,
	SE_OWK_PENDING,
	SE_OWK_STALE,
	SE_OWK_ALREADY_RETURNED,
	SE_OWK_CORRUPT,
};
enum { SE_OWK_OWNER_RELEASED = 1, SE_OWK_PAYLOAD_ZEROED = 2 };
#ifndef SE_OWK_FAULT_SITE
#define SE_OWK_FAULT_SITE(site) \
	do {                    \
	} while (0)
#endif
static inline int se_owk_fault_exact(struct se_owk_account *account,
				     struct se_owk_charge *charge, __u64 bit,
				     __u64 cookie)
{
	bpf_spin_lock(&account->lock);
	if (charge->cookie == cookie && charge->state != SE_OWK_FREE &&
	    (account->bits & bit)) {
		account->fault = 1;
		SE_OWK_FAULT_SITE(9);
		charge->state = SE_OWK_FAULT_HELD;
	}
	bpf_spin_unlock(&account->lock);
	return SE_OWK_CORRUPT;
}
struct se_owk_identity {
	__u64 cookie, scope, owner_locator, owner_cookie;
	__u32 incarnation, account_slot, owner_slot;
};

/* Only the actual callback's done/abort phase is cleanup authority. This
 * reaper never manufactures that phase. A selected caller must serialize
 * visits to a WORK slot and retain the original TASK map until WORK is done. */
static __attribute__((always_inline)) inline int
se_owk_meta_identity(const struct se_owk_meta *work,
		     const struct se_owk_identity *id)
{
	return work->cookie == id->cookie && work->scope == id->scope &&
	       work->incarnation == id->incarnation &&
	       work->account_slot == id->account_slot &&
	       work->owner_locator == id->owner_locator &&
	       work->owner_cookie == id->owner_cookie &&
	       work->owner_slot == id->owner_slot &&
	       work->invocation_sequence &&
	       work->invocation_sequence <= SE_OWK_COOKIE_LIMIT &&
	       !(work->cleanup_done &
		 ~(SE_OWK_OWNER_RELEASED | SE_OWK_PAYLOAD_ZEROED));
}

/* One non-return group: exact TASK ref decrement and WORK receipt. There is
 * no map helper, fallible branch or second account credit between them.
 * TASK WORK_DONE is source-owned only when the last WORK ref is gone after
 * real TASK death; a live TASK may still create future WORK. The independent
 * TASK reaper may already have advanced DEAD through CLEANING to
 * ARCHIVE_ZEROED while this WORK ref still pins the charged TASK. */
static __attribute__((noinline)) int
se_owk_release_owner(struct se_ol_meta *task, struct se_owk_meta *work,
		     const struct se_owk_identity *id)
{
	if (!task || !work)
		return SE_OWK_CORRUPT;
	bpf_spin_lock(&work->lock);
	int work_ready = work->phase == SE_OWK_CLEANING &&
			 !work->active_leases && work->owner_ref_held == 1 &&
			 !(work->cleanup_done & SE_OWK_OWNER_RELEASED) &&
			 se_owk_meta_identity(work, id);
	bpf_spin_unlock(&work->lock);
	if (!work_ready)
		return SE_OWK_CORRUPT;
	bpf_spin_lock(&task->lock);
	int exact = task->locator == id->owner_locator &&
		    task->cookie == id->owner_cookie &&
		    task->account_scope == id->scope &&
		    task->account_slot == id->account_slot &&
		    task->account_incarnation == id->incarnation &&
		    task->work_refs && work->owner_ref_held == 1 &&
		    !(task->current_work_owned &&
		      task->current_work_cookie == id->cookie);
	if (exact) {
		work->owner_ref_held = 0;
		task->work_refs--;
		if ((task->phase == SE_OL_DEAD ||
		     task->phase == SE_OL_CLEANING ||
		     task->phase == SE_OL_ARCHIVE_ZEROED) &&
		    !task->work_refs && !task->current_work_owned &&
		    !task->current_work_cookie && !task->current_work_slot)
			task->cleanup_done |= SE_OL_WORK_DONE;
	}
	bpf_spin_unlock(&task->lock);
	if (!exact)
		return SE_OWK_CORRUPT;
	/* No return/helper/fallible check between decrement and receipt. */
	bpf_spin_lock(&work->lock);
	work->cleanup_done |= SE_OWK_OWNER_RELEASED;
	bpf_spin_unlock(&work->lock);
	return SE_OWK_PROGRESS;
}

/* The frozen all-zero WORK template is the only source for payload wiping.
 * Failed zero keeps the bit/charge and may be retried; no refund receipt is
 * issued until the exact post-update metadata is rechecked. */
static __attribute__((noinline)) int
se_owk_zero_payload_step(struct se_owk_meta *work, __u32 slot, __u64 cookie)
{
	if (!work || slot >= SE_OWK_WORKS)
		return SE_OWK_CORRUPT;
	bpf_spin_lock(&work->lock);
	int ready = work->phase == SE_OWK_CLEANING && work->cookie == cookie &&
		    !work->active_leases && !work->owner_ref_held &&
		    (work->cleanup_done & SE_OWK_OWNER_RELEASED) &&
		    !(work->cleanup_done & SE_OWK_PAYLOAD_ZEROED);
	bpf_spin_unlock(&work->lock);
	if (!ready)
		return SE_OWK_CORRUPT;
	if (SE_OWK_PAYLOAD_ZERO(slot))
		return SE_OWK_PENDING;
	bpf_spin_lock(&work->lock);
	ready = work->phase == SE_OWK_CLEANING && work->cookie == cookie &&
		!work->active_leases && !work->owner_ref_held &&
		(work->cleanup_done & SE_OWK_OWNER_RELEASED) &&
		!(work->cleanup_done & SE_OWK_PAYLOAD_ZEROED);
	if (ready)
		work->cleanup_done |= SE_OWK_PAYLOAD_ZEROED;
	bpf_spin_unlock(&work->lock);
	return ready ? SE_OWK_PROGRESS : SE_OWK_CORRUPT;
}

/* One durable stage per visit. Account bitmap is the only WORK credit; the
 * final return is account-locked after metadata is FREE and fully wiped.
 * Fault-held charges may finish source cleanup but never regain admission or
 * refund without a separately reviewed recovery transition. */
static __attribute__((noinline)) int se_owk_reap_step(__u32 slot,
						      __u64 expected_cookie)
{
	if (slot >= SE_OWK_WORKS || !expected_cookie)
		return SE_OWK_CORRUPT;
	__u32 account_slot = slot / SE_OWK_QUOTA;
	__u32 local = slot - account_slot * SE_OWK_QUOTA;
	if (local >= SE_OWK_QUOTA)
		return SE_OWK_CORRUPT;
	struct se_owk_account *account = SE_OWK_ACCOUNT_LOOKUP(account_slot);
	struct se_owk_charge *charge = SE_OWK_CHARGE_LOOKUP(slot);
	struct se_owk_meta *work = SE_OWK_META_LOOKUP(slot);
	if (!account || !charge || !work)
		return SE_OWK_CORRUPT;
	__u64 bit = 1ULL << local;
	__u64 cookie, last, scope, owner_locator, owner_cookie;
	__u32 incarnation, state, owner_slot, used, fault;
	bpf_spin_lock(&account->lock);
	cookie = charge->cookie;
	last = charge->last_returned;
	scope = charge->scope;
	incarnation = charge->incarnation;
	state = charge->state;
	owner_locator = charge->owner_locator;
	owner_cookie = charge->owner_cookie;
	owner_slot = charge->owner_slot;
	used = account->used;
	fault = account->fault;
	int account_shape =
		!account->reserved && !(account->bits & ~se_owk_valid_mask()) &&
		used <= SE_OWK_QUOTA && se_owk_count(account->bits) == used;
	int occupied = !!(account->bits & bit);
	int account_exact =
		account_shape && occupied && used && account->scope == scope &&
		account->incarnation == incarnation && scope && incarnation &&
		cookie > last && owner_locator && owner_cookie &&
		owner_slot < SE_OL_TASKS &&
		owner_slot / SE_OC_QUOTA == account_slot && !charge->reserved;
	bpf_spin_unlock(&account->lock);
	if (state == SE_OWK_FREE) {
		if (cookie || scope || incarnation || owner_locator ||
		    owner_cookie || owner_slot || occupied || !account_shape ||
		    fault || last != expected_cookie)
			return SE_OWK_STALE;
		bpf_spin_lock(&work->lock);
		int free_shape =
			work->phase == SE_OWK_META_FREE &&
			work->cookie == last && !work->owner_locator &&
			!work->owner_cookie && !work->scope &&
			!work->invocation_sequence && !work->owner_slot &&
			!work->account_slot && !work->incarnation &&
			!work->active_leases && !work->owner_ref_held &&
			work->cleanup_done == 3 && !work->continuation_stage &&
			!work->continuation_reserved;
		bpf_spin_unlock(&work->lock);
		if (free_shape)
			return SE_OWK_ALREADY_RETURNED;
		/* Reuse-aware returns (any returner): a visit of a
		 * cookie another visitor already returned can race the slot's
		 * next charge, which re-initializes the metadata after the charge
		 * snapshot above found it FREE. If the slot now carries a NEWER
		 * charge, or is free again after a NEWER return, that is a
		 * reuse: STALE, never a fault. Anything else (this exact
		 * return with a non-free metadata, an older or equal cookie or
		 * return, a free slot still holding a cookie) is CORRUPT. */
		bpf_spin_lock(&account->lock);
		int reused = (charge->cookie > expected_cookie &&
			      charge->state != SE_OWK_FREE) ||
			     (charge->state == SE_OWK_FREE && !charge->cookie &&
			      charge->last_returned > expected_cookie);
		bpf_spin_unlock(&account->lock);
		return reused ? SE_OWK_STALE : SE_OWK_CORRUPT;
	}
	if (cookie != expected_cookie)
		return SE_OWK_STALE;
	if (!account_exact ||
	    (state != SE_OWK_BUILDING && state != SE_OWK_OWNED &&
	     state != SE_OWK_RETURN_READY && state != SE_OWK_FAULT_HELD))
		return se_owk_fault_exact(account, charge, bit, cookie);
	if (state == SE_OWK_BUILDING)
		return SE_OWK_PENDING;
	struct se_owk_identity id = {
		.cookie = cookie,
		.scope = scope,
		.owner_locator = owner_locator,
		.owner_cookie = owner_cookie,
		.incarnation = incarnation,
		.account_slot = account_slot,
		.owner_slot = owner_slot,
	};
	struct se_ol_meta *task = SE_OL_META_LOOKUP(owner_slot);
	if (!task)
		return SE_OWK_CORRUPT;
	bpf_spin_lock(&work->lock);
	__u32 phase = work->phase;
	int meta_exact = se_owk_meta_identity(work, &id);
	__u32 done = work->cleanup_done;
	__u32 leases = work->active_leases;
	__u32 ref = work->owner_ref_held;
	bpf_spin_unlock(&work->lock);
	if (phase == SE_OWK_META_FREE && state == SE_OWK_RETURN_READY &&
	    !leases && !ref && done == 3) {
		bpf_spin_lock(&work->lock);
		int free_shape =
			work->phase == SE_OWK_META_FREE &&
			work->cookie == cookie && !work->owner_locator &&
			!work->owner_cookie && !work->scope &&
			!work->invocation_sequence && !work->owner_slot &&
			!work->account_slot && !work->incarnation &&
			!work->active_leases && !work->owner_ref_held &&
			work->cleanup_done == 3 && !work->continuation_stage &&
			!work->continuation_reserved;
		bpf_spin_unlock(&work->lock);
		if (!free_shape || fault)
			return se_owk_fault_exact(account, charge, bit, cookie);
		bpf_spin_lock(&account->lock);
		int exact =
			!account->fault && !account->reserved &&
			account->scope == scope &&
			account->incarnation == incarnation && account->used &&
			se_owk_count(account->bits) == account->used &&
			(account->bits & bit) &&
			charge->state == SE_OWK_RETURN_READY &&
			charge->cookie == cookie && charge->scope == scope &&
			charge->incarnation == incarnation &&
			charge->owner_locator == owner_locator &&
			charge->owner_cookie == owner_cookie &&
			charge->owner_slot == owner_slot;
		if (exact) {
			charge->last_returned = cookie;
			charge->cookie = 0;
			charge->scope = 0;
			charge->incarnation = 0;
			charge->owner_locator = 0;
			charge->owner_cookie = 0;
			charge->owner_slot = 0;
			charge->state = SE_OWK_FREE;
			account->bits &= ~bit;
			account->used--;
		}
		bpf_spin_unlock(&account->lock);
		return exact ? SE_OWK_RETURNED : SE_OWK_STALE;
	}
	if (!meta_exact)
		return se_owk_fault_exact(account, charge, bit, cookie);
	if (phase == SE_OWK_OWNER_ATTACHED || phase == SE_OWK_ACTIVE ||
	    phase == SE_OWK_SUSPENDED || phase == SE_OWK_DEATH_FINALIZING ||
	    phase == SE_OWK_INITIALIZING)
		return SE_OWK_PENDING;
	if ((phase == SE_OWK_DONE || phase == SE_OWK_ABORTED) && !leases &&
	    ref == 1 && !done) {
		bpf_spin_lock(&work->lock);
		int exact = work->phase == phase && !work->active_leases &&
			    work->owner_ref_held == 1 && !work->cleanup_done &&
			    work->cookie == cookie;
		if (exact)
			work->phase = SE_OWK_CLEANING;
		bpf_spin_unlock(&work->lock);
		return exact ? SE_OWK_PROGRESS : SE_OWK_PENDING;
	}
	if (phase == SE_OWK_CLEANING && !leases) {
		if (!(done & SE_OWK_OWNER_RELEASED))
			return se_owk_release_owner(task, work, &id);
		if (!(done & SE_OWK_PAYLOAD_ZEROED))
			return se_owk_zero_payload_step(work, slot, cookie);
		if (state == SE_OWK_FAULT_HELD || fault)
			return SE_OWK_CORRUPT;
		bpf_spin_lock(&work->lock);
		int exact = work->phase == SE_OWK_CLEANING &&
			    !work->active_leases && !work->owner_ref_held &&
			    work->cleanup_done == 3 && work->cookie == cookie;
		if (exact)
			work->phase = SE_OWK_REFUND_PENDING;
		bpf_spin_unlock(&work->lock);
		return exact ? SE_OWK_PROGRESS : SE_OWK_CORRUPT;
	}
	if (state == SE_OWK_FAULT_HELD || fault)
		return SE_OWK_CORRUPT;
	if (phase == SE_OWK_REFUND_PENDING && !leases && !ref && done == 3) {
		if (state == SE_OWK_OWNED) {
			bpf_spin_lock(&account->lock);
			int exact = !account->fault && !account->reserved &&
				    account->scope == scope &&
				    account->incarnation == incarnation &&
				    account->used &&
				    se_owk_count(account->bits) ==
					    account->used &&
				    (account->bits & bit) &&
				    charge->state == SE_OWK_OWNED &&
				    charge->cookie == cookie &&
				    charge->scope == scope &&
				    charge->incarnation == incarnation &&
				    charge->owner_locator == owner_locator &&
				    charge->owner_cookie == owner_cookie &&
				    charge->owner_slot == owner_slot;
			if (exact)
				charge->state = SE_OWK_RETURN_READY;
			bpf_spin_unlock(&account->lock);
			return exact ? SE_OWK_PROGRESS : SE_OWK_PENDING;
		}
		if (state == SE_OWK_RETURN_READY) {
			bpf_spin_lock(&work->lock);
			int exact = work->phase == SE_OWK_REFUND_PENDING &&
				    !work->active_leases &&
				    !work->owner_ref_held &&
				    work->cleanup_done == 3 &&
				    work->cookie == cookie &&
				    se_owk_meta_identity(work, &id);
			if (exact) {
				work->phase = SE_OWK_META_FREE;
				work->owner_locator = 0;
				work->owner_cookie = 0;
				work->scope = 0;
				work->invocation_sequence = 0;
				work->owner_slot = 0;
				work->account_slot = 0;
				work->incarnation = 0;
			}
			bpf_spin_unlock(&work->lock);
			return exact ? SE_OWK_PROGRESS : SE_OWK_CORRUPT;
		}
	}
	return SE_OWK_CORRUPT;
}
#endif
