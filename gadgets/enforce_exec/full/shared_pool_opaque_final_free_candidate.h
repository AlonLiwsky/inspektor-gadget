/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_FINAL_FREE_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_FINAL_FREE_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque-key final-free is candidate-only"
#endif

#include "shared_pool_opaque_lookup_candidate.h"
struct task_struct;

/* Stack-only death capability. Only an actual task_free wrapper may call
 * se_of_record_death with its typed hook argument; C cannot attest callback
 * provenance. Keep the exact lease until source-owned cleanup completes. */
struct se_of_lease {
	struct se_ol_meta *meta;
	struct task_struct *physical;
	__u64 locator, cookie;
	__u32 slot, held, locked;
};

/* The local typed pointer is used only as eight opaque HASH key bytes. Its
 * stack address never escapes this inline function. First backing read is
 * untrusted; a speculative hold and fresh original-key lookup precede the
 * DEAD write. No task-address arithmetic, map update or helper under lock. */
static inline int se_of_record_death(struct task_struct *physical,
				     struct se_of_lease *lease)
{
	if (!physical || !lease || lease->held || lease->meta ||
	    lease->physical)
		return SE_OL_CORRUPT;
	struct task_struct *opaque_key = physical;
	struct se_ol_observation observation = {};
	int result = se_ol_observe(&opaque_key, &observation);
	if (result != SE_OL_OK)
		return result;
	result = se_ol_read_observation(&observation);
	if (result != SE_OL_OK)
		return result;
	struct se_ol_meta *meta = SE_OL_META_LOOKUP(observation.slot);
	if (!meta)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	if (meta->locator != observation.observed_locator)
		result = SE_OL_STALE;
	/* A LIVE/PENDING_BIRTH TASK is always PUBLISHED and not exclusive
	 * (only DEAD/CLEANING/ABORTED can be claimed). CONTENDED therefore
	 * means the key still names another charge that is being withdrawn:
	 * this physical task never owned it (its own constructor aborted),
	 * so there is nothing to settle and nothing is written. */
	else if ((meta->phase != SE_OL_LIVE &&
		  meta->phase != SE_OL_PENDING_BIRTH) ||
		 meta->directory_state != SE_OL_PUBLISHED || meta->exclusive)
		result = SE_OL_CONTENDED;
	else if (!meta->cookie || meta->archive_ready != 1 || meta->reserved ||
		 meta->exclusive_owner)
		result = SE_OL_CORRUPT;
	else if (meta->reader_holds == SE_OL_U32_MAX)
		result = SE_OL_LIMIT;
	else {
		meta->reader_holds++;
		observation.meta = meta;
		observation.held_cookie = meta->cookie;
		observation.stage = SE_OL_HELD;
		result = SE_OL_OK;
	}
	bpf_spin_unlock(&meta->lock);
	if (result != SE_OL_OK)
		return result;
	const __u64 *fresh = SE_OL_LOOKUP(&opaque_key);
	__u64 value = fresh ? se_ol_load_scalar(fresh) : 0;
	bpf_spin_lock(&meta->lock);
	if (meta->locator != observation.observed_locator ||
	    meta->cookie != observation.held_cookie || !meta->reader_holds ||
	    meta->reserved || meta->exclusive_owner)
		result =
			SE_OL_CORRUPT; /* retain charged hold on contradiction */
	else if (value != observation.observed_locator ||
		 (meta->phase != SE_OL_LIVE &&
		  meta->phase != SE_OL_PENDING_BIRTH) ||
		 meta->exclusive || meta->directory_state != SE_OL_PUBLISHED) {
		meta->reader_holds--;
		result = SE_OL_STALE;
	} else if (meta->active_leases == SE_OL_U32_MAX) {
		meta->reader_holds--;
		result = SE_OL_LIMIT;
	} else {
		meta->reader_holds--;
		meta->active_leases++;
		meta->phase = SE_OL_DEAD;
		/* task_free is the source for no-WORK completion. If WORK is
		 * still held, its source-owned reaper issues the bit only after
		 * the last exact owner reference is released. */
		if (!meta->work_refs && !meta->current_work_owned &&
		    !meta->current_work_cookie && !meta->current_work_slot)
			meta->cleanup_done |= SE_OL_WORK_DONE;
		*lease = (struct se_of_lease){
			.meta = meta,
			.physical = physical,
			.locator = observation.observed_locator,
			.cookie = observation.held_cookie,
			.slot = observation.slot,
			.held = 1,
		};
		result = SE_OL_OK;
	}
	bpf_spin_unlock(&meta->lock);
	return result;
}

/* Only the source-owned task_free lease can certify that this TASK has no
 * native owner. A future native reference producer must acquire under the
 * metadata lock while LIVE and arrange its own post-death completion when
 * refs remain; zero is not a userspace-supplied cleanup receipt. */
static inline int se_of_complete_native_unheld(struct se_of_lease *lease,
					       struct task_struct *physical)
{
	if (!lease || lease->held != 1 || lease->locked || !lease->meta ||
	    !physical || lease->physical != physical)
		return SE_OL_CORRUPT;
	__u32 slot = 0;
	if (se_ol_decode(lease->locator, &slot) != SE_OL_OK ||
	    slot != lease->slot)
		return SE_OL_CORRUPT;
	struct se_ol_meta *meta = lease->meta;
	bpf_spin_lock(&meta->lock);
	int exact = meta->phase == SE_OL_DEAD &&
		    meta->locator == lease->locator &&
		    meta->cookie == lease->cookie && meta->active_leases &&
		    meta->directory_state == SE_OL_PUBLISHED &&
		    meta->archive_ready == 1 && !meta->reserved &&
		    !meta->exclusive && !meta->exclusive_owner &&
		    !meta->cleanup_error;
	int result;
	if (!exact ||
	    (meta->native_refs && (meta->cleanup_done & SE_OL_NATIVE_DONE)))
		result = SE_OL_CORRUPT;
	else if (meta->native_refs)
		result = SE_OL_CONTENDED;
	else if (meta->cleanup_done & SE_OL_NATIVE_DONE)
		result = SE_OL_STALE;
	else {
		meta->cleanup_done |= SE_OL_NATIVE_DONE;
		result = SE_OL_OK;
	}
	bpf_spin_unlock(&meta->lock);
	return result;
}

/* The three stages of se_of_withdraw_directory below, shared verbatim with
 * the G019 credit-at-exit callers: the free-time resume of a withdrawal the
 * exit left at WITHDRAW_CLAIM or WITHDRAWN_ZERO
 * (real_owner_exit_withdraw_resume) and the test-only partial withdrawal of
 * the exit injector. The caller holds the exact death lease
 * (active_leases == 1); stages 2 and 3 also hold the claim
 * (exclusive_owner == locator), and archive is this slot's archive entry
 * holding the lease's physical key bytes. */
static __always_inline int se_of_withdraw_claim(struct se_ol_meta *meta,
						__u64 cookie, __u64 locator);
static __always_inline int se_of_withdraw_advance(struct se_ol_meta *meta,
						  const __u64 *archive,
						  __u64 cookie, __u64 locator);
static __always_inline int se_of_withdraw_delete(struct se_ol_meta *meta,
						 const __u64 *archive,
						 __u64 cookie);
#include "shared_pool_opaque_writer_candidate.h"
/* Physical-reuse fix (G025 batch F). A correctness fix of every real-map
 * final-free build under ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE, never a
 * witness option: SE_OF_WITHDRAW_DIRECTORY lets the final-free program
 * refuse to compile without it. The reaper withdraws a DEAD TASK's
 * directory entry in three stages, one per visit (se_ow_claim_withdraw,
 * se_ow_advance_withdraw, se_ow_delete_withdrawn_zero via
 * se_or_task_directory_step). A newborn at the same task address that meets
 * WITHDRAW_CLAIM (CONTENDED, se_ow_hold_replacement/se_ow_claim_replacement)
 * or WITHDRAWN_ZERO/no key (STALE, se_ol_observe/se_ol_read_observation) aborts and is refused. security_task_free runs before the
 * slab free, so while this callback runs the address cannot be reused. Doing
 * the same three stages here, under the exact death lease, leaves the key
 * DELETED before any successor exists; the reaper then resumes unchanged at
 * se_ow_zero_archive, which accepts DEAD.
 *
 * Exactness is the writer's with one difference: active_leases == 1 is this
 * callback's own lease (meta->cookie == lease->cookie, locator equal) instead
 * of !active_leases. The phase stays DEAD (the reaper's claim would write
 * CLEANING): DEAD-only receipts such as se_owk_rollback_pin's WORK_DONE must
 * keep working, and zero_archive, the visit filter (se_or_task_visit's phase check) and
 * se_of_release all accept DEAD. Any failed stage returns with the state as
 * it is; every stage is resumable by the reaper (claim, advance or delete),
 * since exclusive_owner == meta->locator is exactly what se_ow_claim_withdraw
 * writes.
 *
 * Single deleter. bpf_map_delete_elem is unconditional, so a stale delete
 * would erase a successor's entry; at most one actor may reach SE_OW_DELETE:
 * - the reaper cannot claim while this lease is held: se_ow_claim_withdraw
 *   requires !active_leases, and so do the se_ow_advance_withdraw and
 *   se_ow_delete_withdrawn_zero prechecks. Before se_of_record_death the phase is
 *   LIVE/PENDING_BIRTH, which the claim (se_ow_claim_withdraw's exact phase
 *   check) and the visit (se_or_task_visit) refuse;
 * - this hook cannot claim once the reaper (or a replacement) has claimed:
 *   both set exclusive under the lock, and the claim below requires
 *   !exclusive && !exclusive_owner && directory PUBLISHED. The reaper can only
 *   claim after se_of_release, i.e. after this function returned;
 * - a replacement claim needs !active_leases and reader_holds == 1
 *   (se_ow_claim_replacement), and no successor at this address exists yet.
 * Each stage re-checks exclusive == 1 && exclusive_owner == locator under the
 * lock before its helper, and only this callback holds that claim. */
#define SE_OF_WITHDRAW_DIRECTORY 1
static inline int se_of_withdraw_directory(struct se_of_lease *lease,
					   struct task_struct *physical)
{
	if (!lease || lease->held != 1 || lease->locked || !lease->meta ||
	    !physical || lease->physical != physical || !lease->cookie)
		return SE_OL_CORRUPT;
	__u32 slot = 0;
	if (se_ol_decode(lease->locator, &slot) != SE_OL_OK ||
	    slot != lease->slot)
		return SE_OL_CORRUPT;
	/* The archive of this exact slot is the key the reaper would use. It
	 * must still hold this physical key's bytes. */
	const __u64 *archive = SE_OW_ARCHIVE_LOOKUP(slot);
	if (!archive || *archive != (__u64)(unsigned long)physical)
		return SE_OL_CONTENDED;
	struct se_ol_meta *meta = lease->meta;
	__u64 locator = lease->locator, cookie = lease->cookie;
	if (se_of_withdraw_claim(meta, cookie, locator) != SE_OL_OK)
		return SE_OL_CONTENDED;
	int advanced = se_of_withdraw_advance(meta, archive, cookie, locator);
	if (advanced != SE_OL_OK)
		return advanced;
	return se_of_withdraw_delete(meta, archive, cookie);
}

static __always_inline int se_of_withdraw_claim(struct se_ol_meta *meta,
						__u64 cookie, __u64 locator)
{
	/* Stage 1: se_ow_claim_withdraw. */
	bpf_spin_lock(&meta->lock);
	int exact = meta->phase == SE_OL_DEAD && meta->cookie == cookie &&
		    meta->locator == locator && meta->archive_ready == 1 &&
		    meta->directory_state == SE_OL_PUBLISHED &&
		    !meta->reader_holds && meta->active_leases == 1 &&
		    !meta->exclusive && !meta->exclusive_owner &&
		    !meta->reserved;
	if (exact) {
		meta->exclusive = 1;
		meta->exclusive_owner = meta->locator;
		meta->directory_state = SE_OL_WITHDRAW_CLAIM;
	}
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CONTENDED;
}
static __always_inline int se_of_withdraw_advance(struct se_ol_meta *meta,
						  const __u64 *archive,
						  __u64 cookie, __u64 locator)
{
	/* Stage 2: se_ow_advance_withdraw. */
	__u64 *value = SE_OW_LOOKUP(archive);
	if (!value)
		return SE_OL_CORRUPT;
	__u64 observed = se_ol_load_scalar(value);
	if (observed == locator && SE_OW_CAS(value, locator, 0) != locator)
		return SE_OL_CONTENDED;
	if (observed != locator && observed != 0)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = meta->cookie == cookie && meta->locator == locator &&
		    meta->exclusive == 1 && meta->exclusive_owner == locator &&
		    meta->directory_state == SE_OL_WITHDRAW_CLAIM &&
		    !meta->reader_holds && meta->active_leases == 1 &&
		    !meta->reserved;
	if (exact)
		meta->directory_state = SE_OL_WITHDRAWN_ZERO;
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}
static __always_inline int se_of_withdraw_delete(struct se_ol_meta *meta,
						 const __u64 *archive,
						 __u64 cookie)
{
	/* Stage 3: se_ow_delete_withdrawn_zero. */
	bpf_spin_lock(&meta->lock);
	int exact = meta->cookie == cookie && meta->exclusive == 1 &&
		    meta->exclusive_owner == meta->locator &&
		    meta->directory_state == SE_OL_WITHDRAWN_ZERO &&
		    meta->archive_ready == 1 && !meta->reader_holds &&
		    meta->active_leases == 1 && !meta->reserved;
	bpf_spin_unlock(&meta->lock);
	if (!exact)
		return SE_OL_CORRUPT;
	__u64 *value = SE_OW_LOOKUP(archive);
	if (!value || se_ol_load_scalar(value) != 0)
		return SE_OL_CORRUPT;
	int deleted = SE_OW_DELETE(archive);
	if (deleted != SE_OL_OK)
		return deleted; /* still WITHDRAWN_ZERO: the reaper retries */
	/* Infallible receipt group, as in se_ow_delete_withdrawn_zero. */
	bpf_spin_lock(&meta->lock);
	meta->directory_state = SE_OL_DELETED;
	meta->exclusive = 0;
	meta->exclusive_owner = 0;
	meta->cleanup_done |= SE_OL_DIR_DONE;
	bpf_spin_unlock(&meta->lock);
	return SE_OL_OK;
}

static inline int se_of_release(struct se_of_lease *lease,
				struct task_struct *physical)
{
	if (!lease || lease->held != 1 || lease->locked || !lease->meta ||
	    !physical || lease->physical != physical)
		return SE_OL_CORRUPT;
	/* The held, callback-local lease already retains the exact metadata
	 * pointer. A second map lookup adds no authority and produces a nullable
	 * pointer that stock Rocky 4.18 cannot refine by pointer equality. */
	__u32 slot = 0;
	if (se_ol_decode(lease->locator, &slot) != SE_OL_OK ||
	    slot != lease->slot)
		return SE_OL_CORRUPT;
	struct se_ol_meta *meta = lease->meta;
	bpf_spin_lock(&meta->lock);
	int exact =
		meta->locator == lease->locator &&
		meta->cookie == lease->cookie &&
		(meta->phase == SE_OL_DEAD || meta->phase == SE_OL_CLEANING) &&
		meta->active_leases && !meta->reserved;
	if (exact) {
		meta->active_leases--;
		lease->held = 0;
		lease->meta = 0;
		lease->physical = 0;
	}
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}

#endif
