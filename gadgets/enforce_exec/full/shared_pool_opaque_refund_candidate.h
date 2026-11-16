/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_REFUND_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_REFUND_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque-key refund is candidate-only"
#endif

#include "shared_pool_opaque_charge_candidate.h"

enum se_oc_reap_result {
	SE_OC_PROGRESS = 0,
	SE_OC_RETURNED,
	SE_OC_PENDING,
	SE_OC_STALE,
	SE_OC_ALREADY_RETURNED,
	SE_OC_CORRUPT,
};

/* These are checks, not producers. No generic setter may fabricate a source
 * cleanup bit. The caller must arrive here through the trusted reaper after
 * actual exec/construction/WORK/native/directory/payload owners complete. */
static __attribute__((always_inline)) inline int
se_oc_ready_meta(const struct se_ol_meta *meta, __u32 account_slot,
		 __u32 incarnation, __u64 scope, __u64 cookie, __u64 locator)
{
	return meta->cookie == cookie && meta->locator == locator &&
	       meta->account_scope == scope &&
	       meta->account_slot == account_slot &&
	       meta->account_incarnation == incarnation &&
	       meta->directory_state == SE_OL_DELETED && !meta->archive_ready &&
	       !meta->reader_holds && !meta->active_leases &&
	       !meta->exclusive && !meta->exclusive_owner && !meta->reserved &&
	       !meta->work_refs && !meta->native_refs && !meta->cleanup_error &&
	       !meta->current_work_slot && !meta->current_work_owned &&
	       !meta->current_work_cookie && !meta->reserved2 &&
	       !(meta->cleanup_done & ~SE_OL_ALL_DONE);
}

static __attribute__((always_inline)) inline int
se_oc_free_meta(const struct se_ol_meta *meta, __u32 slot, __u64 locator)
{
	__u32 decoded = 0;
	return se_ol_decode(locator, &decoded) == SE_OL_OK && decoded == slot &&
	       meta->phase == SE_OL_FREE && meta->locator == locator &&
	       !meta->cookie && !meta->reader_holds && !meta->active_leases &&
	       !meta->exclusive && !meta->exclusive_owner && !meta->reserved &&
	       !meta->archive_ready && meta->directory_state == SE_OL_DELETED &&
	       !meta->account_scope && !meta->account_slot &&
	       !meta->account_incarnation && !meta->work_refs &&
	       !meta->native_refs && !meta->cleanup_done &&
	       !meta->cleanup_error && !meta->current_work_slot &&
	       !meta->current_work_owned && !meta->current_work_cookie &&
	       !meta->next_work_sequence && !meta->last_reap_sequence &&
	       !meta->reserved2;
}

static inline int se_oc_fault_exact(struct se_oc_account *account,
				    struct se_oc_charge *charge, __u32 local,
				    __u64 cookie)
{
	__u64 bit = 1ULL << (local % 64U);
	bpf_spin_lock(&account->lock);
	int exact = charge->cookie == cookie && charge->state != SE_OC_FREE &&
		    (account->bits[SE_OC_WORD(local)] & bit);
	if (exact) {
		account->fault = 1;
		charge->state = SE_OC_FAULT_HELD;
	}
	bpf_spin_unlock(&account->lock);
	return exact ? SE_OC_CORRUPT : SE_OC_STALE;
}

/* One durable boundary per call. The account bit and charge remain occupied
 * until the final account-locked return; metadata is reset first while the
 * RETURN_READY charge still excludes new construction. A retry after the
 * final return recognizes last_returned_cookie, never reclaims a successor.
 * No helper is called while either spinlock is held, and locks are not nested.
 * This is not a source-cleanup producer or a selected product reaper. */
static __attribute__((noinline)) int se_oc_refund_step(__u32 slot,
						       __u64 expected_cookie)
{
	if (slot >= SE_OL_TASKS || !expected_cookie)
		return SE_OC_CORRUPT;
	__u32 account_slot = slot / SE_OC_QUOTA;
	__u32 local = slot - account_slot * SE_OC_QUOTA;
	struct se_oc_account *account = SE_OC_ACCOUNT_LOOKUP(account_slot);
	struct se_oc_charge *charge = SE_OC_CHARGE_LOOKUP(slot);
	struct se_ol_meta *meta = SE_OL_META_LOOKUP(slot);
	if (!account || !charge || !meta)
		return SE_OC_CORRUPT;
	__u64 bit = 1ULL << (local % 64U);
	__u64 cookie, last, scope, locator;
	__u32 incarnation, state;
	bpf_spin_lock(&account->lock);
	cookie = charge->cookie;
	last = charge->last_returned;
	scope = charge->scope;
	locator = charge->locator;
	incarnation = charge->incarnation;
	state = charge->state;
	int occupied = !!(account->bits[SE_OC_WORD(local)] & bit);
	int account_exact = !account->reserved && !account->fault &&
			    account->used <= SE_OC_QUOTA &&
			    se_oc_bitmap_count(account) == account->used;
	if (state == SE_OC_FREE) {
		int replay = !cookie && !scope && !incarnation && !locator &&
			     !occupied && account_exact &&
			     last == expected_cookie;
		bpf_spin_unlock(&account->lock);
		if (!replay)
			return SE_OC_STALE;
		bpf_spin_lock(&meta->lock);
		int free_shape = se_oc_free_meta(meta, slot, meta->locator);
		bpf_spin_unlock(&meta->lock);
		return free_shape ? SE_OC_ALREADY_RETURNED : SE_OC_CORRUPT;
	}
	if (cookie != expected_cookie) {
		bpf_spin_unlock(&account->lock);
		return SE_OC_STALE;
	}
	int exact = account_exact && occupied && account->used &&
		    account->scope == scope &&
		    account->incarnation == incarnation && scope &&
		    incarnation && last < cookie &&
		    (state == SE_OC_BUILDING || state == SE_OC_OWNED ||
		     state == SE_OC_RETURN_READY) &&
		    (state == SE_OC_BUILDING ? !locator : !!locator);
	bpf_spin_unlock(&account->lock);
	if (!exact)
		return se_oc_fault_exact(account, charge, local, cookie);
	__u32 decoded = 0;
	if (state == SE_OC_BUILDING)
		return SE_OC_PENDING;
	if (se_ol_decode(locator, &decoded) != SE_OL_OK || decoded != slot)
		return se_oc_fault_exact(account, charge, local, cookie);
	bpf_spin_lock(&meta->lock);
	__u32 phase = meta->phase;
	int meta_identity = meta->cookie == cookie &&
			    meta->locator == locator &&
			    meta->account_scope == scope &&
			    meta->account_slot == account_slot &&
			    meta->account_incarnation == incarnation;
	int ready = se_oc_ready_meta(meta, account_slot, incarnation, scope,
				     cookie, locator);
	int free_shape = se_oc_free_meta(meta, slot, locator);
	__u32 done = meta->cleanup_done;
	if (phase == SE_OL_ARCHIVE_ZEROED && state == SE_OC_OWNED && ready &&
	    done == SE_OL_ALL_DONE) {
		meta->phase = SE_OL_REFUND_PENDING;
		bpf_spin_unlock(&meta->lock);
		return SE_OC_PROGRESS;
	}
	bpf_spin_unlock(&meta->lock);
	if (state == SE_OC_OWNED && meta_identity &&
	    (phase == SE_OL_INITIALIZING || phase == SE_OL_PENDING_BIRTH ||
	     phase == SE_OL_LIVE || phase == SE_OL_DEAD ||
	     phase == SE_OL_ABORTED || phase == SE_OL_CLEANING))
		return SE_OC_PENDING;
	if (phase == SE_OL_ARCHIVE_ZEROED && state == SE_OC_OWNED && ready &&
	    done != SE_OL_ALL_DONE)
		return SE_OC_PENDING;
	if (phase == SE_OL_REFUND_PENDING && ready && done == SE_OL_ALL_DONE) {
		if (state == SE_OC_OWNED) {
			bpf_spin_lock(&account->lock);
			exact = !account->fault && !account->reserved &&
				account->scope == scope &&
				account->incarnation == incarnation &&
				account->used &&
				se_oc_bitmap_count(account) == account->used &&
				(account->bits[SE_OC_WORD(local)] & bit) &&
				charge->cookie == cookie &&
				charge->scope == scope &&
				charge->incarnation == incarnation &&
				charge->locator == locator &&
				charge->state == SE_OC_OWNED;
			if (exact)
				charge->state = SE_OC_RETURN_READY;
			bpf_spin_unlock(&account->lock);
			return exact ? SE_OC_PROGRESS : SE_OC_PENDING;
		}
		bpf_spin_lock(&meta->lock);
		exact = meta->phase == SE_OL_REFUND_PENDING &&
			se_oc_ready_meta(meta, account_slot, incarnation, scope,
					 cookie, locator) &&
			meta->cleanup_done == SE_OL_ALL_DONE;
		if (exact) {
			meta->phase = SE_OL_FREE;
			meta->cookie = 0;
			meta->account_scope = 0;
			meta->account_slot = 0;
			meta->account_incarnation = 0;
			meta->cleanup_done = 0;
			meta->next_work_sequence = 0;
			meta->last_reap_sequence = 0;
		}
		bpf_spin_unlock(&meta->lock);
		return exact ? SE_OC_PROGRESS : SE_OC_PENDING;
	}
	if (phase == SE_OL_FREE && state == SE_OC_RETURN_READY && free_shape) {
		bpf_spin_lock(&account->lock);
		exact = !account->fault && !account->reserved &&
			account->scope == scope &&
			account->incarnation == incarnation && account->used &&
			se_oc_bitmap_count(account) == account->used &&
			(account->bits[SE_OC_WORD(local)] & bit) &&
			charge->cookie == cookie && charge->scope == scope &&
			charge->incarnation == incarnation &&
			charge->locator == locator &&
			charge->state == SE_OC_RETURN_READY;
		if (exact) {
			charge->last_returned = cookie;
			charge->cookie = 0;
			charge->scope = 0;
			charge->incarnation = 0;
			charge->locator = 0;
			charge->state = SE_OC_FREE;
			account->bits[SE_OC_WORD(local)] &= ~bit;
			account->used--;
		}
		bpf_spin_unlock(&account->lock);
		return exact ? SE_OC_RETURNED : SE_OC_STALE;
	}
	/* Cross-lock snapshots can straddle another reaper's durable stage.
	 * Refuse credit return, but do not poison the account from a snapshot
	 * that cannot prove a persistent contradiction. */
	return SE_OC_CORRUPT;
}

#endif
