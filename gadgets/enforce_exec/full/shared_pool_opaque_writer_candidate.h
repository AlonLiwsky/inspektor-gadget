/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_WRITER_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_WRITER_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque-key writer is candidate-only"
#endif
#ifndef SE_OW_ARCHIVE_COPY
#error "provide helper-mediated copy into an immutable charged-slot archive"
#endif
#ifndef SE_OW_ARCHIVE_ZERO
#error "provide helper-mediated zeroing of the charged-slot archive"
#endif
#ifndef SE_OW_ARCHIVE_LOOKUP
#error "provide exact charged-slot archive lookup"
#endif
#ifndef SE_OW_INSERT_ZERO
#error "provide BPF_NOEXIST insertion of an all-zero HASH value"
#endif
#ifndef SE_OW_LOOKUP
#error "provide lookup by the archived original opaque key"
#endif
#ifndef SE_OW_CAS
#error "provide scalar cmpxchg on the HASH locator value"
#endif
#ifndef SE_OW_DELETE
#error "provide key-only deletion without holding a BPF spinlock"
#endif
#ifndef SE_OW_ADVANCE_DIAG
#define SE_OW_ADVANCE_DIAG(stage, locator, observed, previous, exact) ((void)0)
#endif

/* Observer + writer share the exact stable metadata lock and locator. This
 * header is an unselected model-to-C candidate, not a product ABI. The
 * caller still owes charge/account and source-reference proof. In particular
 * an unexpected fault cannot be converted to successful cleanup/refund. */
#include "shared_pool_opaque_lookup_candidate.h"

/* A caller-provided key pointer is not archive authority. Bind it to the
 * stable per-slot ARRAY value before any helper uses its opaque bytes. No
 * lookup is performed under a metadata spinlock. Exact charge ownership and
 * writable-FD custody remain separate obligations. */
static inline int se_ow_archive_key_exact(const struct se_ol_meta *meta,
					  const void *archived_key)
{
	__u32 slot = 0;
	return meta && archived_key &&
	       se_ol_decode(meta->locator, &slot) == SE_OL_OK &&
	       SE_OW_ARCHIVE_LOOKUP(slot) == archived_key;
}

static inline int se_ow_begin(struct se_ol_meta *meta, __u32 slot,
			      __u64 charged_cookie, __u64 *locator)
{
	if (!meta || !charged_cookie || !locator || slot >= SE_OL_TASKS)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int result = SE_OL_OK;
	__u64 next = 0;
	if (meta->phase != SE_OL_FREE || meta->cookie || meta->reader_holds ||
	    meta->active_leases || meta->exclusive || meta->exclusive_owner ||
	    meta->reserved || meta->archive_ready || meta->account_scope ||
	    meta->account_slot || meta->account_incarnation ||
	    meta->work_refs || meta->native_refs || meta->cleanup_done ||
	    meta->cleanup_error || meta->current_work_slot ||
	    meta->current_work_owned || meta->current_work_cookie ||
	    meta->next_work_sequence || meta->last_reap_sequence ||
	    meta->reserved2 ||
	    (meta->directory_state != SE_OL_NO_ENTRY &&
	     meta->directory_state != SE_OL_DELETED))
		result = SE_OL_CONTENDED;
	else
		result = se_ol_next_locator(slot, meta->locator, &next);
	if (result == SE_OL_OK) {
		meta->locator = next; /* generation survives eventual refund */
		meta->cookie = charged_cookie;
		meta->phase = SE_OL_INITIALIZING;
		meta->directory_state = SE_OL_NO_ENTRY;
		meta->active_leases =
			1; /* constructor lease, not a reader hold */
		*locator = next;
	}
	bpf_spin_unlock(&meta->lock);
	return result;
}

/* The archive helper copies the typed task argument as opaque bytes. State
 * 2 is COPY_INTENT and must be wiped even when the helper reports failure:
 * no caller may infer that failed copy left no pointer bytes. It is called
 * before any HASH insertion and outside the metadata spinlock. */
static inline int se_ow_archive(struct se_ol_meta *meta, __u32 slot,
				__u64 cookie, const void *opaque_key)
{
	if (!meta || !opaque_key || slot >= SE_OL_TASKS || !cookie)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = meta->phase == SE_OL_INITIALIZING &&
		    meta->cookie == cookie && meta->active_leases == 1 &&
		    meta->directory_state == SE_OL_NO_ENTRY &&
		    meta->archive_ready == 0 && !meta->exclusive &&
		    !meta->exclusive_owner && !meta->reserved;
	if (exact)
		meta->archive_ready = 2; /* COPY_INTENT precedes helper */
	bpf_spin_unlock(&meta->lock);
	if (!exact)
		return SE_OL_CONTENDED;
	if (SE_OW_ARCHIVE_COPY(slot, opaque_key))
		return SE_OL_CONTENDED;
	bpf_spin_lock(&meta->lock);
	exact = meta->phase == SE_OL_INITIALIZING && meta->cookie == cookie &&
		meta->active_leases == 1 &&
		meta->directory_state == SE_OL_NO_ENTRY &&
		meta->archive_ready == 2 && !meta->exclusive &&
		!meta->exclusive_owner && !meta->reserved;
	if (exact)
		meta->archive_ready = 1;
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}

/* Preclaim before the fallible insertion. A successful helper must be
 * followed by ZERO_OWNED receipt in the same callback without return/tail
 * call; the constructor lease excludes reaping in between. A helper failure
 * creates no ownership and returns to NO_ENTRY. */
static inline int se_ow_insert_zero(struct se_ol_meta *meta, __u64 cookie,
				    const void *archived_key)
{
	if (!meta || !archived_key || !cookie ||
	    !se_ow_archive_key_exact(meta, archived_key))
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = meta->phase == SE_OL_INITIALIZING &&
		    meta->cookie == cookie && meta->active_leases == 1 &&
		    meta->archive_ready == 1 &&
		    meta->directory_state == SE_OL_NO_ENTRY &&
		    !meta->reader_holds && !meta->exclusive &&
		    !meta->exclusive_owner && !meta->reserved;
	if (exact)
		meta->directory_state = SE_OL_INSERT_INTENT;
	bpf_spin_unlock(&meta->lock);
	if (!exact)
		return SE_OL_CONTENDED;
	int inserted = SE_OW_INSERT_ZERO(archived_key);
	bpf_spin_lock(&meta->lock);
	exact = meta->phase == SE_OL_INITIALIZING && meta->cookie == cookie &&
		meta->active_leases == 1 &&
		meta->directory_state == SE_OL_INSERT_INTENT &&
		meta->archive_ready == 1 && !meta->exclusive &&
		!meta->exclusive_owner && !meta->reserved;
	if (exact)
		meta->directory_state = inserted == SE_OL_OK ?
						SE_OL_ZERO_OWNED :
						SE_OL_NO_ENTRY;
	bpf_spin_unlock(&meta->lock);
	if (!exact)
		return SE_OL_CORRUPT; /* charged, possibly inserted; retain intent */
	return inserted;
}

/* The locator's only nonzero first-publication write is scalar CAS. A
 * missing/mismatched value retains PUBLISH_INTENT for fault-held recovery. */
static inline int se_ow_publish_zero(struct se_ol_meta *meta, __u64 cookie,
				     const void *archived_key)
{
	if (!meta || !archived_key || !cookie ||
	    !se_ow_archive_key_exact(meta, archived_key))
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = meta->phase == SE_OL_INITIALIZING &&
		    meta->cookie == cookie && meta->active_leases == 1 &&
		    meta->directory_state == SE_OL_ZERO_OWNED &&
		    meta->archive_ready == 1 && !meta->reader_holds &&
		    !meta->exclusive && !meta->exclusive_owner &&
		    !meta->reserved;
	__u64 locator = meta->locator;
	if (exact)
		meta->directory_state = SE_OL_PUBLISH_INTENT;
	bpf_spin_unlock(&meta->lock);
	if (!exact)
		return SE_OL_CONTENDED;
	__u64 *value = SE_OW_LOOKUP(archived_key);
	if (!value || SE_OW_CAS(value, 0, locator) != 0)
		return SE_OL_CORRUPT;
	/* Non-return receipt after successful CAS. Constructor lease pins meta. */
	bpf_spin_lock(&meta->lock);
	exact = meta->phase == SE_OL_INITIALIZING && meta->cookie == cookie &&
		meta->locator == locator &&
		meta->directory_state == SE_OL_PUBLISH_INTENT &&
		meta->active_leases == 1 && !meta->exclusive &&
		!meta->exclusive_owner && !meta->reserved;
	if (exact) {
		meta->directory_state = SE_OL_PUBLISHED;
		meta->phase = SE_OL_PENDING_BIRTH;
	}
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}

/* An external exact charge transition must precede this call. It does not
 * claim to validate the charge itself. */
static inline int se_ow_finish_birth(struct se_ol_meta *meta, __u64 cookie)
{
	if (!meta || !cookie)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int pending = meta->phase == SE_OL_PENDING_BIRTH;
	int exact = (pending || meta->phase == SE_OL_DEAD) &&
		    meta->cookie == cookie && meta->active_leases >= 1 &&
		    (!pending || meta->active_leases == 1) &&
		    meta->directory_state == SE_OL_PUBLISHED &&
		    meta->archive_ready == 1 && !meta->exclusive &&
		    !meta->exclusive_owner && !meta->reserved;
	if (exact) {
		meta->active_leases--;
		/* The successful task_alloc constructor owns this lease. Its
		 * completion is the only authority for this receipt. */
		meta->cleanup_done |= SE_OL_CONSTRUCTION_DONE;
		if (pending)
			meta->phase = SE_OL_LIVE;
	}
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}

/* A failed task_alloc owns its constructor even if no task_free callback
 * follows. INSERT_INTENT is not safely abortable: helper insertion may have
 * succeeded without an ownership receipt, so it must remain fault-held.
 * PUBLISH_INTENT can be reconciled from a fresh original-key lookup after
 * the constructor lease is released. */
static inline int se_ow_abort_constructor(struct se_ol_meta *meta, __u64 cookie)
{
	if (!meta || !cookie)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = (meta->phase == SE_OL_INITIALIZING ||
		     meta->phase == SE_OL_PENDING_BIRTH) &&
		    meta->cookie == cookie && meta->active_leases == 1 &&
		    !meta->reader_holds && !meta->exclusive &&
		    !meta->exclusive_owner && !meta->reserved &&
		    (meta->directory_state == SE_OL_NO_ENTRY ||
		     meta->directory_state == SE_OL_ZERO_OWNED ||
		     meta->directory_state == SE_OL_PUBLISH_INTENT ||
		     meta->directory_state == SE_OL_PUBLISHED);
	if (exact) {
		meta->phase = SE_OL_ABORTED;
		meta->active_leases = 0;
		/* A failed task_alloc has no later task_free obligation for its
		 * constructor; abort releases that exact constructor lease. */
		meta->cleanup_done |= SE_OL_CONSTRUCTION_DONE;
	}
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}

/* A failed publication may have left zero or its own locator. Neither is
 * policy authority. The exact aborted charge remains retained until the
 * reaper observes the archived key and chooses the matching cleanup path. */
static inline int se_ow_reconcile_publish_intent(struct se_ol_meta *meta,
						 __u64 cookie,
						 const void *archived_key)
{
	if (!meta || !cookie || !archived_key ||
	    !se_ow_archive_key_exact(meta, archived_key))
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = meta->phase == SE_OL_ABORTED && meta->cookie == cookie &&
		    !meta->active_leases && !meta->reader_holds &&
		    !meta->exclusive && !meta->exclusive_owner &&
		    meta->archive_ready == 1 && !meta->reserved &&
		    meta->directory_state == SE_OL_PUBLISH_INTENT;
	__u64 locator = meta->locator;
	bpf_spin_unlock(&meta->lock);
	if (!exact)
		return SE_OL_CORRUPT;
	const __u64 *value = SE_OW_LOOKUP(archived_key);
	if (!value)
		return SE_OL_CORRUPT;
	__u64 observed = se_ol_load_scalar(value);
	if (observed && observed != locator)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	exact = meta->phase == SE_OL_ABORTED && meta->cookie == cookie &&
		meta->locator == locator && !meta->active_leases &&
		!meta->reader_holds && !meta->exclusive &&
		!meta->exclusive_owner && meta->archive_ready == 1 &&
		!meta->reserved &&
		meta->directory_state == SE_OL_PUBLISH_INTENT;
	if (exact)
		meta->directory_state = observed ? SE_OL_PUBLISHED :
						   SE_OL_ZERO_OWNED;
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}

/* An aborted constructor with no entry has no HASH cleanup to perform.
 * Archive zero and charge refund are still mandatory before slot reuse. */
static inline int se_ow_mark_absent_deleted(struct se_ol_meta *meta,
					    __u64 cookie)
{
	if (!meta || !cookie)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = meta->phase == SE_OL_ABORTED && meta->cookie == cookie &&
		    !meta->active_leases && !meta->reader_holds &&
		    !meta->exclusive && !meta->exclusive_owner &&
		    !meta->reserved && meta->directory_state == SE_OL_NO_ENTRY;
	if (exact) {
		meta->phase = SE_OL_CLEANING;
		meta->directory_state = SE_OL_DELETED;
		meta->cleanup_done |= SE_OL_DIR_DONE;
	}
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CONTENDED;
}

/* A ZERO_OWNED entry came only from this constructor's successful
 * BPF_NOEXIST. It can be claimed for the same zero-delete path without
 * ever publishing a locator or authorizing a borrower. */
static inline int se_ow_claim_aborted_zero(struct se_ol_meta *meta,
					   __u64 cookie)
{
	if (!meta || !cookie)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = meta->phase == SE_OL_ABORTED && meta->cookie == cookie &&
		    !meta->active_leases && !meta->reader_holds &&
		    !meta->exclusive && !meta->exclusive_owner &&
		    meta->archive_ready == 1 && !meta->reserved &&
		    meta->directory_state == SE_OL_ZERO_OWNED;
	if (exact) {
		meta->phase = SE_OL_CLEANING;
		meta->exclusive = 1;
		meta->exclusive_owner = meta->locator;
		meta->directory_state = SE_OL_WITHDRAWN_ZERO;
	}
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CONTENDED;
}

/* The caller must have actual task_free authority to set DEAD and must
 * release source WORK/native/reader obligations before invoking this stage.
 * The claim is durable across a failed CAS or lost receipt. */
static inline int se_ow_claim_withdraw(struct se_ol_meta *meta, __u64 cookie)
{
	if (!meta || !cookie)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact =
		(meta->phase == SE_OL_DEAD || meta->phase == SE_OL_CLEANING ||
		 meta->phase == SE_OL_ABORTED) &&
		meta->cookie == cookie && meta->archive_ready == 1 &&
		meta->directory_state == SE_OL_PUBLISHED &&
		!meta->reader_holds && !meta->active_leases &&
		!meta->exclusive && !meta->exclusive_owner && !meta->reserved;
	if (exact) {
		meta->phase = SE_OL_CLEANING;
		meta->exclusive = 1;
		meta->exclusive_owner = meta->locator;
		meta->directory_state = SE_OL_WITHDRAW_CLAIM;
	}
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CONTENDED;
}

/* Repeating this stage after locator->zero CAS is safe: the same archived
 * key and exact claim persist, and zero promotes to WITHDRAWN_ZERO. */
static inline int se_ow_advance_withdraw(struct se_ol_meta *meta, __u64 cookie,
					 const void *archived_key)
{
	if (!meta || !cookie || !archived_key ||
	    !se_ow_archive_key_exact(meta, archived_key))
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = meta->cookie == cookie && meta->exclusive == 1 &&
		    meta->exclusive_owner == meta->locator &&
		    meta->directory_state == SE_OL_WITHDRAW_CLAIM &&
		    meta->archive_ready == 1 && !meta->reader_holds &&
		    !meta->active_leases && !meta->reserved;
	__u64 locator = meta->locator;
	bpf_spin_unlock(&meta->lock);
	if (!exact) {
		SE_OW_ADVANCE_DIAG(1, locator, 0, 0, exact);
		return SE_OL_CORRUPT;
	}
	__u64 *value = SE_OW_LOOKUP(archived_key);
	if (!value) {
		SE_OW_ADVANCE_DIAG(2, locator, 0, 0, exact);
		return SE_OL_CORRUPT;
	}
	__u64 observed = se_ol_load_scalar(value);
	if (observed == locator) {
		__u64 previous = SE_OW_CAS(value, locator, 0);
		if (previous != locator) {
			SE_OW_ADVANCE_DIAG(3, locator, observed, previous,
					   exact);
			return SE_OL_CONTENDED;
		}
	}
	if (observed != locator && observed != 0)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	exact = meta->cookie == cookie && meta->locator == locator &&
		meta->exclusive == 1 && meta->exclusive_owner == locator &&
		meta->directory_state == SE_OL_WITHDRAW_CLAIM &&
		!meta->reader_holds && !meta->active_leases && !meta->reserved;
	if (exact)
		meta->directory_state = SE_OL_WITHDRAWN_ZERO;
	bpf_spin_unlock(&meta->lock);
	SE_OW_ADVANCE_DIAG(4, locator, observed, observed, exact);
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}

/* Successful key delete and metadata receipt are an infallible non-return
 * group: no fallible helper/tail call/early exit between them. That prevents
 * the old zero from being confused with a new zero at the same opaque key. */
static inline int se_ow_delete_withdrawn_zero(struct se_ol_meta *meta,
					      __u64 cookie,
					      const void *archived_key)
{
	if (!meta || !cookie || !archived_key ||
	    !se_ow_archive_key_exact(meta, archived_key))
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = meta->cookie == cookie && meta->exclusive == 1 &&
		    meta->exclusive_owner == meta->locator &&
		    meta->directory_state == SE_OL_WITHDRAWN_ZERO &&
		    meta->archive_ready == 1 && !meta->reader_holds &&
		    !meta->active_leases && !meta->reserved;
	bpf_spin_unlock(&meta->lock);
	if (!exact)
		return SE_OL_CORRUPT;
	__u64 *value = SE_OW_LOOKUP(archived_key);
	if (!value || se_ol_load_scalar(value) != 0)
		return SE_OL_CORRUPT;
	int deleted = SE_OW_DELETE(archived_key);
	if (deleted != SE_OL_OK)
		return deleted; /* still charged and WITHDRAWN_ZERO */
	/* The exclusive owner and charged slot forbid internal metadata reuse.
	 * Do not insert a second guard, return, fallible call or relookup here:
	 * unlike the post-CAS claim, a lost delete receipt cannot be replayed
	 * safely with only a zero-valued HASH entry. */
	bpf_spin_lock(&meta->lock);
	meta->directory_state = SE_OL_DELETED;
	meta->exclusive = 0;
	meta->exclusive_owner = 0;
	meta->cleanup_done |= SE_OL_DIR_DONE;
	bpf_spin_unlock(&meta->lock);
	return SE_OL_OK;
}

/* Wipe archived pointer bytes only after directory deletion. A failed
 * helper leaves the charged metadata retryable. ARCHIVE_ZEROED is not a refund
 * receipt: source-owned exec/construction/WORK/native/UID cleanup must be
 * proven before a separate reaper may advance to REFUND_PENDING. */
static inline int se_ow_zero_archive(struct se_ol_meta *meta, __u64 cookie)
{
	if (!meta || !cookie)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = (meta->phase == SE_OL_ABORTED ||
		     meta->phase == SE_OL_CLEANING ||
		     meta->phase == SE_OL_DEAD) &&
		    meta->cookie == cookie && !meta->active_leases &&
		    !meta->reader_holds && !meta->exclusive &&
		    !meta->exclusive_owner && !meta->reserved &&
		    meta->directory_state == SE_OL_DELETED;
	__u64 locator = meta->locator;
	int ready = meta->archive_ready;
	bpf_spin_unlock(&meta->lock);
	if (!exact)
		return SE_OL_CONTENDED;
	__u32 slot = 0;
	if (se_ol_decode(locator, &slot) != SE_OL_OK)
		return SE_OL_CORRUPT;
	if (ready && SE_OW_ARCHIVE_ZERO(slot))
		return SE_OL_CONTENDED;
	bpf_spin_lock(&meta->lock);
	exact = meta->cookie == cookie && meta->locator == locator &&
		meta->directory_state == SE_OL_DELETED &&
		!meta->active_leases && !meta->reader_holds &&
		!meta->exclusive && !meta->exclusive_owner && !meta->reserved;
	if (exact) {
		meta->archive_ready = 0;
		meta->phase = SE_OL_ARCHIVE_ZEROED;
	}
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}

#endif
