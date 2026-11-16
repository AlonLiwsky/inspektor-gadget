/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_REAPER_VISIT_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_REAPER_VISIT_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE) || \
	(!defined(ENFORCE_EXEC_SHARED_RECOVERY) &&          \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE))
#error "opaque reaper visitors require the recovered or reap-events candidate"
#endif

/* These are outcomes of actual fixed-slot visits, not cleanup authority.
 * Only the source callback may issue EXEC/CONSTRUCTION/WORK/NATIVE receipts;
 * TASK payload zero and the exact WORK reaper own their own receipts. */
enum se_or_visit_result {
	SE_OR_EMPTY = 0,
	SE_OR_PROGRESS,
	SE_OR_RETURNED,
	SE_OR_PENDING,
	SE_OR_FAULT,
};

static __attribute__((noinline)) int se_or_work_free_shape(__u32 slot,
							   __u64 last)
{
	struct se_owk_meta *work = work_meta_lookup(slot);
	if (!work)
		return 0;
	bpf_spin_lock(&work->lock);
	int common = work->phase == SE_OWK_META_FREE && work->cookie == last &&
		     !work->owner_locator && !work->owner_cookie &&
		     !work->scope && !work->invocation_sequence &&
		     !work->owner_slot && !work->account_slot &&
		     !work->incarnation && !work->active_leases &&
		     !work->owner_ref_held && !work->continuation_stage &&
		     !work->continuation_reserved;
	int shape = common && work->cleanup_done == (last ? 3U : 0U);
	bpf_spin_unlock(&work->lock);
	return shape;
}

static __attribute__((noinline)) int
se_or_task_free_shape(struct se_ol_meta *meta, __u32 slot, __u64 last)
{
	if (!meta)
		return 0;
	bpf_spin_lock(&meta->lock);
	int shape;
	if (last) {
		shape = se_oc_free_meta(meta, slot, meta->locator);
	} else {
		shape = meta->phase == SE_OL_FREE && !meta->locator &&
			!meta->cookie && !meta->reader_holds &&
			!meta->active_leases && !meta->exclusive &&
			!meta->reserved &&
			meta->directory_state == SE_OL_NO_ENTRY &&
			!meta->archive_ready && !meta->exclusive_owner &&
			!meta->account_scope && !meta->account_slot &&
			!meta->account_incarnation && !meta->work_refs &&
			!meta->native_refs && !meta->cleanup_done &&
			!meta->cleanup_error && !meta->current_work_slot &&
			!meta->current_work_owned &&
			!meta->current_work_cookie &&
			!meta->next_work_sequence &&
			!meta->last_reap_sequence && !meta->reserved2;
	}
	bpf_spin_unlock(&meta->lock);
	return shape;
}

static __attribute__((noinline)) int se_or_work_visit(__u32 slot)
{
	if (slot >= SE_OWK_WORKS)
		return SE_OR_FAULT;
	__u32 account_slot = slot / SE_OWK_QUOTA;
	__u32 local = slot - account_slot * SE_OWK_QUOTA;
	struct se_owk_account *account = work_account_lookup(account_slot);
	struct se_owk_charge *charge = work_charge_lookup(slot);
	if (!account || !charge || local >= SE_OWK_QUOTA)
		return SE_OR_FAULT;
	__u64 cookie, last;
	__u32 state;
	bpf_spin_lock(&account->lock);
	cookie = charge->cookie;
	last = charge->last_returned;
	state = charge->state;
	int occupied = !!(account->bits & (1ULL << local));
	int account_ok = !account->reserved && !account->fault &&
			 account->used <= SE_OWK_QUOTA &&
			 se_owk_count(account->bits) == account->used;
	int free_charge_ok = !occupied && !cookie && !charge->scope &&
			     !charge->incarnation && !charge->owner_locator &&
			     !charge->owner_cookie && !charge->owner_slot &&
			     !charge->reserved;
	int charge_ok = occupied && cookie && charge->last_returned < cookie &&
			charge->scope && charge->incarnation &&
			charge->scope == account->scope &&
			charge->incarnation == account->incarnation &&
			charge->owner_locator && charge->owner_cookie &&
			charge->owner_slot < SE_OL_TASKS && !charge->reserved;
	bpf_spin_unlock(&account->lock);
	if (!account_ok)
		return SE_OR_FAULT;
	if (state == SE_OWK_FREE) {
		if (!free_charge_ok)
			return SE_OR_FAULT;
		if (se_or_work_free_shape(slot, last))
			return SE_OR_EMPTY;
		bpf_spin_lock(&account->lock);
		int changed = charge->state != SE_OWK_FREE ||
			      charge->last_returned != last ||
			      (account->bits & (1ULL << local));
		bpf_spin_unlock(&account->lock);
		return changed ? SE_OR_PENDING : SE_OR_FAULT;
	}
	if (!charge_ok || state == SE_OWK_FAULT_HELD)
		return SE_OR_FAULT;
	if (state == SE_OWK_BUILDING)
		return SE_OR_PENDING;
	if (state != SE_OWK_OWNED && state != SE_OWK_RETURN_READY)
		return SE_OR_FAULT;
	int result = se_owk_reap_step(slot, cookie);
	if (result == SE_OWK_RETURNED)
		return SE_OR_RETURNED;
	if (result == SE_OWK_PROGRESS)
		return SE_OR_PROGRESS;
	if (result == SE_OWK_PENDING || result == SE_OWK_STALE ||
	    result == SE_OWK_ALREADY_RETURNED)
		return SE_OR_PENDING;
	return SE_OR_FAULT;
}

/* Select the exact cookie under its original account lock. The metadata
 * snapshot only chooses a stage; each stage rechecks the charged identity
 * before mutation, and the final account-locked refund owns the credit.
 * The snapshot is not held across the stage: a concurrent visit of the same
 * charge may complete the stage first, and this stage's exact recheck then
 * reports CORRUPT against a state that already moved on. So a CORRUPT stage
 * is a fault only when directory_state, re-read under the lock, still equals
 * the snapshot that selected it; a moved state is PENDING (the next visit
 * selects its stage from a fresh snapshot). A real fault leaves the state
 * where it was and is still reported. */
static __attribute__((noinline)) int
se_or_task_directory_step(struct se_ol_meta *meta, __u32 slot, __u64 cookie,
			  __u32 directory)
{
	const __u64 *archive = archive_lookup(slot);
	int result = SE_OL_CONTENDED;
	if (directory == SE_OL_PUBLISHED)
		result = se_ow_claim_withdraw(meta, cookie);
	else if (directory == SE_OL_WITHDRAW_CLAIM && archive)
		result = se_ow_advance_withdraw(meta, cookie, archive);
	else if (directory == SE_OL_WITHDRAWN_ZERO && archive)
		result = se_ow_delete_withdrawn_zero(meta, cookie, archive);
	else if (directory == SE_OL_PUBLISH_INTENT && archive)
		result = se_ow_reconcile_publish_intent(meta, cookie, archive);
	else if (directory == SE_OL_NO_ENTRY)
		result = se_ow_mark_absent_deleted(meta, cookie);
	else if (directory == SE_OL_ZERO_OWNED)
		result = se_ow_claim_aborted_zero(meta, cookie);
	else if (directory == SE_OL_DELETED)
		result = se_ow_zero_archive(meta, cookie);
	else
		return SE_OR_FAULT;
	if (result == SE_OL_OK)
		return SE_OR_PROGRESS;
	if (result == SE_OL_CONTENDED || result == SE_OL_STALE)
		return SE_OR_PENDING;
	bpf_spin_lock(&meta->lock);
	int moved = meta->directory_state != directory;
	bpf_spin_unlock(&meta->lock);
	return moved ? SE_OR_PENDING : SE_OR_FAULT;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
/* A receipt is not cleanup authority, but its still-registered original key
 * must survive until an authenticated consumer has settled the reader. This
 * guard prevents the ordinary directory/archive/reuse reaper from destroying
 * that key first. A receipt for another cookie at the same address belongs to
 * another charge: it neither blocks nor authorizes this slot's retirement. */
static __attribute__((noinline)) int
se_or_task_terminal_guard(__u32 slot, __u64 cookie, __u64 locator)
{
	const __u64 *original = archive_lookup(slot);
	if (!original || !*original)
		return SE_OR_EMPTY;
	const struct se_exec_terminal_receipt *receipt =
		bpf_map_lookup_elem(&se_exec_terminal_receipts, original);
	if (!receipt)
		return SE_OR_EMPTY;
	if (receipt->physical != *original || !receipt->cookie ||
	    !receipt->locator || !receipt->bprm || !receipt->invocation ||
	    !receipt->scope || !receipt->generation || receipt->reserved ||
	    (receipt->phase != SE_EXEC_TERMINAL_REGISTERED &&
	     receipt->phase != SE_EXEC_TERMINAL_SUCCESS &&
	     receipt->phase != SE_EXEC_TERMINAL_FAILURE))
		return SE_OR_FAULT;
	/* A live success needs the full authenticated WORK/TASK completion path.
	 * Physical death is different: task_free alone owns EXEC_DONE and has
	 * already released the exact reader. Its source-owned receipt permits
	 * retirement without granting a role to a successor at this address. */
	if (receipt->cookie != cookie)
		return SE_OR_EMPTY; /* same address, different charged lifetime */
	if (receipt->locator != locator)
		return SE_OR_FAULT; /* cookie cannot adopt a different slot */
	struct se_ol_meta *meta = meta_lookup(slot);
	struct se_pool_task_wire *payload = payload_lookup(slot);
	if (!meta || !payload)
		return SE_OR_FAULT;
	bpf_spin_lock(&meta->lock);
	const struct se_task_state *task = &payload->semantic;
	int dead_done = se_exec_terminal_dead_retirable(meta, task, receipt,
							*original, cookie,
							locator,
							slot / SE_OC_QUOTA);
	bpf_spin_unlock(&meta->lock);
	if (!dead_done)
		return SE_OR_PENDING;
	/* Reaper single-flight excludes a second deletion. Delete only after the
	 * exact source proof; a failed delete retains the charged TASK. */
	return bpf_map_delete_elem(&se_exec_terminal_receipts, original) == 0 ?
		       SE_OR_PROGRESS :
		       SE_OR_PENDING;
}
#endif

static __attribute__((noinline)) int se_or_task_visit(__u32 slot)
{
	if (slot >= SE_OL_TASKS)
		return SE_OR_FAULT;
	__u32 account_slot = slot / SE_OC_QUOTA;
	__u32 local = slot - account_slot * SE_OC_QUOTA;
	struct se_oc_account *account = account_lookup(account_slot);
	struct se_oc_charge *charge = charge_lookup(slot);
	struct se_ol_meta *meta = meta_lookup(slot);
	if (!account || !charge || !meta || local >= SE_OC_QUOTA)
		return SE_OR_FAULT;
	__u64 cookie, locator, scope, last;
	__u32 state, incarnation;
	bpf_spin_lock(&account->lock);
	cookie = charge->cookie;
	last = charge->last_returned;
	locator = charge->locator;
	scope = charge->scope;
	incarnation = charge->incarnation;
	state = charge->state;
	int occupied =
		!!(account->bits[SE_OC_WORD(local)] & (1ULL << (local % 64U)));
	int account_ok = !account->reserved && !account->fault &&
			 account->used <= SE_OC_QUOTA &&
			 se_oc_bitmap_count(account) == account->used;
	int charge_ok = occupied && cookie && charge->last_returned < cookie &&
			scope && incarnation && scope == account->scope &&
			incarnation == account->incarnation;
	bpf_spin_unlock(&account->lock);
	if (!account_ok)
		return SE_OR_FAULT;
	if (state == SE_OC_FREE) {
		if (occupied || cookie || locator || scope || incarnation)
			return SE_OR_FAULT;
		if (se_or_task_free_shape(meta, slot, last))
			return SE_OR_EMPTY;
		bpf_spin_lock(&account->lock);
		int changed = charge->state != SE_OC_FREE ||
			      charge->last_returned != last ||
			      (account->bits[SE_OC_WORD(local)] &
			       (1ULL << (local % 64U)));
		bpf_spin_unlock(&account->lock);
		return changed ? SE_OR_PENDING : SE_OR_FAULT;
	}
	if (!charge_ok || state == SE_OC_FAULT_HELD)
		return SE_OR_FAULT;
	if (state == SE_OC_BUILDING)
		return SE_OR_PENDING;
	if (state != SE_OC_OWNED && state != SE_OC_RETURN_READY)
		return SE_OR_FAULT;
	__u32 decoded = 0;
	if (se_ol_decode(locator, &decoded) != SE_OL_OK || decoded != slot)
		return SE_OR_FAULT;
	bpf_spin_lock(&meta->lock);
	__u32 phase = meta->phase;
	__u32 directory = meta->directory_state;
	__u32 done = meta->cleanup_done;
	__u32 leases = meta->active_leases;
	int same = meta->cookie == cookie && meta->locator == locator &&
		   meta->account_scope == scope &&
		   meta->account_slot == account_slot &&
		   meta->account_incarnation == incarnation;
	bpf_spin_unlock(&meta->lock);
	if (!same && !(phase == SE_OL_FREE && state == SE_OC_RETURN_READY))
		return SE_OR_FAULT;
	/* A DEAD charge whose death lease is held (read in the same lock
	 * section as the stage snapshot) is not the reaper's yet: the exit or
	 * task_free holding it is between its own withdrawal stages
	 * (se_of_withdraw_directory) or keeps it for a later resume, and every
	 * reaper directory stage requires !active_leases. No lease is taken on
	 * a DEAD charge (se_of_record_death's own sets DEAD), so DEAD with no
	 * lease stays lease-free for this cookie. SE_OR_TASK_HELD may witness
	 * a lease that stays held without an accounted holder; the candidate
	 * defines it with credit at exit, which its product reap command
	 * requires (a build without it has no such witness and is
	 * qualification-only). */
	if (phase == SE_OL_DEAD && leases) {
#ifdef SE_OR_TASK_HELD
		SE_OR_TASK_HELD(slot, cookie, locator, leases);
#endif
		return SE_OR_PENDING;
	}
#ifdef SE_OR_TASK_PRE_VISIT
	/* Caller-owned exact-charge step before any directory/archive step
	 * (the G019 credit-at-exit tombstone retirement). Never reached while
	 * a DEAD charge's lease is held (above). */
	int pre = SE_OR_TASK_PRE_VISIT(slot, cookie, locator);
	if (pre != SE_OR_EMPTY)
		return pre;
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_READER_LIFECYCLE_PROBE
	int terminal = se_or_task_terminal_guard(slot, cookie, locator);
	if (terminal != SE_OR_EMPTY)
		return terminal;
#endif
	if (phase == SE_OL_FREE || phase == SE_OL_REFUND_PENDING ||
	    (phase == SE_OL_ARCHIVE_ZEROED &&
	     (done & SE_OL_PAYLOAD_ZERO_DONE))) {
		int result = se_oc_refund_step(slot, cookie);
		return result == SE_OC_RETURNED ? SE_OR_RETURNED :
		       result == SE_OC_PROGRESS ? SE_OR_PROGRESS :
		       result == SE_OC_PENDING || result == SE_OC_STALE ||
				       result == SE_OC_ALREADY_RETURNED ?
						  SE_OR_PENDING :
						  SE_OR_FAULT;
	}
	if (phase == SE_OL_ARCHIVE_ZEROED) {
		int result = se_op_zero_payload(slot, cookie);
		return result == SE_OC_PROGRESS ? SE_OR_PROGRESS :
		       result == SE_OC_PENDING || result == SE_OC_STALE ?
						  SE_OR_PENDING :
						  SE_OR_FAULT;
	}
	if (phase != SE_OL_ABORTED && phase != SE_OL_DEAD &&
	    phase != SE_OL_CLEANING)
		return SE_OR_PENDING;
	return se_or_task_directory_step(meta, slot, cookie, directory);
}
#endif
