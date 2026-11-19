/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_REPLACE_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_REPLACE_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque-key replacement is candidate-only"
#endif

#include "shared_pool_opaque_writer_candidate.h"

/* Replacement observes a DEAD/CLEANING, still-published task. Its hold is
 * speculative until the original typed key and new constructor archive are
 * independently relooked up. No payload/death/refund authority follows from
 * this hold alone. */
static inline int se_ow_hold_replacement(struct se_ol_observation *observation)
{
	if (!observation || observation->stage != SE_OL_READ)
		return SE_OL_CORRUPT;
	struct se_ol_meta *meta = SE_OL_META_LOOKUP(observation->slot);
	if (!meta)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int result = SE_OL_OK;
	if (meta->locator != observation->observed_locator)
		result = SE_OL_STALE;
	else if ((meta->phase != SE_OL_DEAD && meta->phase != SE_OL_CLEANING) ||
		 meta->directory_state != SE_OL_PUBLISHED || meta->exclusive)
		result = SE_OL_CONTENDED;
	else if (!meta->cookie || meta->reserved || meta->exclusive_owner ||
		 meta->archive_ready != 1)
		result = SE_OL_CORRUPT;
	else if (meta->reader_holds == SE_OL_U32_MAX)
		result = SE_OL_LIMIT;
	else {
		meta->reader_holds++;
		observation->meta = meta;
		observation->held_cookie = meta->cookie;
		observation->stage = SE_OL_HELD;
	}
	bpf_spin_unlock(&meta->lock);
	return result;
}

/* Successful claim consumes exactly this actor's sole reader hold into an
 * exclusive successor-locator owner. A failed original-key/archive relookup
 * releases the hold; structural damage to held metadata does not. */
static __attribute__((noinline)) int
se_ow_claim_replacement(struct se_ol_meta *new_meta, __u64 new_cookie,
			struct se_ol_observation *observation,
			const void *archived_key)
{
	if (!new_meta || !new_cookie || !observation ||
	    observation->stage != SE_OL_HELD || !observation->meta ||
	    !observation->original_key || !archived_key ||
	    new_meta == observation->meta)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&new_meta->lock);
	int new_exact = new_meta->phase == SE_OL_INITIALIZING &&
			new_meta->cookie == new_cookie &&
			new_meta->active_leases == 1 &&
			new_meta->archive_ready == 1 &&
			new_meta->directory_state == SE_OL_NO_ENTRY &&
			!new_meta->reader_holds && !new_meta->exclusive &&
			!new_meta->exclusive_owner && !new_meta->reserved;
	__u64 new_locator = new_meta->locator;
	bpf_spin_unlock(&new_meta->lock);
	if (!new_exact || new_locator == observation->observed_locator) {
		int released = se_ol_cancel_observation(observation);
		return released == SE_OL_OK ? SE_OL_CONTENDED : SE_OL_CORRUPT;
	}
	if (!se_ow_archive_key_exact(new_meta, archived_key)) {
		se_ol_cancel_observation(observation);
		return SE_OL_CORRUPT;
	}
	const __u64 *original = SE_OL_LOOKUP(observation->original_key);
	const __u64 *archived = SE_OW_LOOKUP(archived_key);
	__u64 original_locator = original ? se_ol_load_scalar(original) : 0;
	__u64 archive_locator = archived ? se_ol_load_scalar(archived) : 0;
	if (original_locator != observation->observed_locator ||
	    archive_locator != observation->observed_locator) {
		int released = se_ol_cancel_observation(observation);
		return released == SE_OL_OK ? SE_OL_STALE : SE_OL_CORRUPT;
	}
	struct se_ol_meta *old = observation->meta;
	bpf_spin_lock(&old->lock);
	int result = SE_OL_OK;
	if (old->locator != observation->observed_locator ||
	    old->cookie != observation->held_cookie || !old->reader_holds ||
	    old->reserved || old->exclusive_owner)
		result =
			SE_OL_CORRUPT; /* held identity contradiction: retain */
	else if ((old->phase != SE_OL_DEAD && old->phase != SE_OL_CLEANING) ||
		 old->directory_state != SE_OL_PUBLISHED || old->exclusive ||
		 old->active_leases || old->reader_holds != 1) {
		old->reader_holds--; /* only this actor's hold */
		observation->stage = SE_OL_RELEASED;
		result = SE_OL_CONTENDED;
	} else {
		old->reader_holds--;
		old->exclusive = 1;
		old->exclusive_owner = new_locator;
		observation->stage = SE_OL_EXCLUSIVE;
	}
	bpf_spin_unlock(&old->lock);
	return result;
}

/* Cancellation is permitted only before the scalar replacement CAS is
 * attempted. A post-attempt fault keeps the exact old/new charges pinned. */
static inline int
se_ow_cancel_replacement_claim(struct se_ol_observation *observation,
			       __u64 new_locator)
{
	if (!observation || observation->stage != SE_OL_EXCLUSIVE ||
	    !observation->meta || !new_locator)
		return SE_OL_CORRUPT;
	struct se_ol_meta *old = observation->meta;
	bpf_spin_lock(&old->lock);
	int exact = old->locator == observation->observed_locator &&
		    old->cookie == observation->held_cookie &&
		    old->directory_state == SE_OL_PUBLISHED &&
		    old->exclusive == 1 &&
		    old->exclusive_owner == new_locator && !old->reserved;
	if (exact) {
		old->exclusive = 0;
		old->exclusive_owner = 0;
		observation->stage = SE_OL_RELEASED;
	}
	bpf_spin_unlock(&old->lock);
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}

/* No fallible helper or early return follows successful old->new CAS before both
 * metadata receipts. The old exclusive owner stays pinned until the new
 * PENDING_BIRTH state is recorded; old cleanup never deletes a successor's
 * key. The caller still must finish/abort its charged constructor. */
static __attribute__((noinline)) int
se_ow_publish_replacement(struct se_ol_meta *new_meta, __u64 new_cookie,
			  struct se_ol_observation *observation,
			  const void *archived_key)
{
	if (!new_meta || !new_cookie || !observation ||
	    observation->stage != SE_OL_EXCLUSIVE || !observation->meta ||
	    !archived_key || new_meta == observation->meta)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&new_meta->lock);
	int exact = new_meta->phase == SE_OL_INITIALIZING &&
		    new_meta->cookie == new_cookie &&
		    new_meta->active_leases == 1 &&
		    new_meta->archive_ready == 1 &&
		    new_meta->directory_state == SE_OL_NO_ENTRY &&
		    !new_meta->reader_holds && !new_meta->exclusive &&
		    !new_meta->exclusive_owner && !new_meta->reserved;
	__u64 new_locator = new_meta->locator;
	bpf_spin_unlock(&new_meta->lock);
	if (!exact || !se_ow_archive_key_exact(new_meta, archived_key))
		return SE_OL_CORRUPT;
	struct se_ol_meta *old = observation->meta;
	bpf_spin_lock(&old->lock);
	exact = old->locator == observation->observed_locator &&
		old->cookie == observation->held_cookie &&
		old->exclusive == 1 && old->exclusive_owner == new_locator &&
		old->directory_state == SE_OL_PUBLISHED && !old->reader_holds &&
		!old->active_leases && !old->reserved;
	bpf_spin_unlock(&old->lock);
	if (!exact)
		return SE_OL_CORRUPT;
	observation->stage = SE_OL_CAS_ATTEMPTED;
	__u64 *value = SE_OW_LOOKUP(archived_key);
	if (!value || SE_OW_CAS(value, observation->observed_locator,
				new_locator) != observation->observed_locator)
		return SE_OL_CORRUPT; /* retain exact exclusive owner */
	/* Infallible non-return receipt group begins after successful CAS. */
	bpf_spin_lock(&old->lock);
	old->directory_state = SE_OL_DELETED;
	old->cleanup_done |= SE_OL_DIR_DONE;
	bpf_spin_unlock(&old->lock);
	bpf_spin_lock(&new_meta->lock);
	new_meta->directory_state = SE_OL_PUBLISHED;
	new_meta->phase = SE_OL_PENDING_BIRTH;
	bpf_spin_unlock(&new_meta->lock);
	bpf_spin_lock(&old->lock);
	old->exclusive = 0;
	old->exclusive_owner = 0;
	bpf_spin_unlock(&old->lock);
	observation->stage = SE_OL_REPLACED;
	return SE_OL_OK;
}

#endif
