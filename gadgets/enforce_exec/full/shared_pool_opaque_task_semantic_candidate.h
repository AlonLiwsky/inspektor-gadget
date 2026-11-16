/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque semantic constructor is candidate-only"
#endif
#ifndef SE_OP_PAYLOAD_INIT
#error "provide an authenticated frozen-zero TASK payload update"
#endif
#ifndef FULL_EPOCH_ROLES_H
#error "opaque child-role view requires the real epoch-role wire"
#endif
#ifndef ENFORCE_EXEC_ABI3_DEVELOPMENT
#error "opaque child-role view requires the selected ABI3 role wire"
#endif

#include "shared_pool_opaque_payload_handle_candidate.h"

#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE
/* Selected hook bodies need the real TASK semantic member, not an alias of
 * the identity prefix or a second spinlock. This bracket transfers no
 * authority: the exact original-key lease remains in owner, and its metadata
 * lock protects every semantic access until end. Keep both calls in the same
 * BPF frame; no helper, return, or WORK operation is allowed between them. */
static __attribute__((always_inline)) inline int
se_op_task_semantic_begin(struct se_ol_payload_handle *owner,
			  struct se_task_state **semantic)
{
	if (!semantic || *semantic)
		return SE_OL_CORRUPT;
	void *raw = 0;
	int result = se_ol_payload_begin(owner, &raw);
	if (result == SE_OL_OK)
		*semantic = &((struct se_pool_task_wire *)raw)->semantic;
	return result;
}

/* A successful begin must reach this exact end with its pointer unchanged.
 * As with child_roles_end, release cannot have a fallible branch: the BPF
 * verifier would then see a helper/return path while the spinlock is held.
 * Clear the borrow before the exact metadata lock is released. */
static __attribute__((always_inline)) inline void
se_op_task_semantic_end(struct se_ol_payload_handle *owner,
			struct se_task_state **semantic)
{
	*semantic = 0;
	owner->locked = 0;
	bpf_spin_unlock(&owner->lease.meta->lock);
}

/* These use the same semantic bodies as the selected legacy exec callback.
 * Failure to acquire an exact live TASK lease is reported to the caller;
 * it must classify that failure under its immutable admission class. */
static __attribute__((always_inline)) inline int
se_op_task_owned_fault(struct se_ol_payload_handle *owner, __u64 bprm)
{
	if (!bprm)
		return SE_OL_CORRUPT;
	struct se_task_state *task = 0;
	int result = se_op_task_semantic_begin(owner, &task);
	if (result != SE_OL_OK)
		return result;
	se_exec_owned_fault_locked(task, bprm);
	se_op_task_semantic_end(owner, &task);
	return SE_OL_OK;
}
static __attribute__((always_inline)) inline int
se_op_task_note_prior_deny(struct se_ol_payload_handle *owner, __u64 bprm)
{
	if (!bprm)
		return SE_OL_CORRUPT;
	struct se_task_state *task = 0;
	int result = se_op_task_semantic_begin(owner, &task);
	if (result != SE_OL_OK)
		return result;
	se_exec_note_prior_deny_locked(task, bprm);
	se_op_task_semantic_end(owner, &task);
	return SE_OL_OK;
}
#endif

/* Constructor-owned role access before HASH publication. The exact charged
 * reservation owns one unpublished child; no address lookup grants this view.
 * The metadata lock is the sole TASK semantic lock, and begin/end are one
 * lexical bracket with no helper call while locked. The caller still must
 * authenticate its parent WORK projection before publishing roles. */
_Static_assert(sizeof(struct er_state) == 520 &&
		       sizeof(struct er_state) <=
			       sizeof(((struct se_pool_task_wire *)0)->bytes),
	       "ABI3 child roles must fit the selected TASK semantic offset");
struct se_op_child_roles_handle {
	struct se_ol_meta *meta;
	struct se_pool_task_wire *payload;
	__u64 cookie;
	__u32 locked;
};

/* The reservation is a callback-local capability, not a map-sourced tuple.
 * Account and charge are checked before every metadata transition. The
 * constructor lease prevents refund/reuse between that check and transition;
 * an independently faulted account must also stop admission at the owner. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_OWNED_INLINE_DIAGNOSTIC
#define SE_OP_OWNED_ATTR __attribute__((always_inline)) inline
#else
#define SE_OP_OWNED_ATTR __attribute__((noinline))
#endif
static SE_OP_OWNED_ATTR int
se_op_reservation_owned(const struct se_oc_reservation *reservation)
{
	if (!reservation || reservation->held || reservation->terminal ||
	    !reservation->account || !reservation->charge ||
	    !reservation->meta || !reservation->scope || !reservation->cookie ||
	    !reservation->locator || !reservation->incarnation ||
	    reservation->account_slot >= SE_OC_ACCOUNTS ||
	    reservation->task_slot >= SE_OL_TASKS ||
	    reservation->task_slot / SE_OC_QUOTA != reservation->account_slot ||
	    SE_OC_ACCOUNT_LOOKUP(reservation->account_slot) !=
		    reservation->account ||
	    SE_OC_CHARGE_LOOKUP(reservation->task_slot) !=
		    reservation->charge ||
	    SE_OL_META_LOOKUP(reservation->task_slot) != reservation->meta)
		return 0;
	__u32 local = reservation->task_slot -
		      reservation->account_slot * SE_OC_QUOTA;
	/* The verifier does not preserve the quotient relationship across this
	 * noinline boundary; bound the bitmap subscript independently. */
	if (local >= SE_OC_QUOTA)
		return 0;
	__u64 bit = 1ULL << (local % 64U);
	struct se_oc_account *account = reservation->account;
	struct se_oc_charge *charge = reservation->charge;
	bpf_spin_lock(&account->lock);
	int owned = !account->fault && !account->reserved &&
		    account->scope == reservation->scope &&
		    account->incarnation == reservation->incarnation &&
		    account->used && account->used <= SE_OC_QUOTA &&
		    se_oc_bitmap_count(account) == account->used &&
		    (account->bits[SE_OC_WORD(local)] & bit) &&
		    charge->state == SE_OC_OWNED &&
		    charge->cookie == reservation->cookie &&
		    charge->last_returned < reservation->cookie &&
		    charge->scope == reservation->scope &&
		    charge->incarnation == reservation->incarnation &&
		    charge->locator == reservation->locator;
	bpf_spin_unlock(&account->lock);
	return owned;
}
#undef SE_OP_OWNED_ATTR

static __attribute__((always_inline)) inline int
se_op_child_roles_begin(const struct se_oc_reservation *reservation,
			struct se_op_child_roles_handle *handle,
			struct er_state **roles)
{
	if (!handle || !roles || *roles || handle->locked || handle->meta ||
	    handle->payload || handle->cookie ||
	    !se_op_reservation_owned(reservation))
		return SE_OL_CORRUPT;
	struct se_pool_task_wire *payload =
		SE_OL_PAYLOAD_LOOKUP(reservation->task_slot);
	if (!payload)
		return SE_OL_CORRUPT;
	struct se_ol_meta *meta = reservation->meta;
	bpf_spin_lock(&meta->lock);
	int exact = meta->phase == SE_OL_INITIALIZING &&
		    meta->cookie == reservation->cookie &&
		    meta->locator == reservation->locator &&
		    meta->active_leases == 1 &&
		    meta->account_scope == reservation->scope &&
		    meta->account_slot == reservation->account_slot &&
		    meta->account_incarnation == reservation->incarnation &&
		    meta->directory_state == SE_OL_NO_ENTRY &&
		    !meta->archive_ready && !meta->exclusive &&
		    !meta->exclusive_owner && !meta->reserved &&
		    payload->identity.reserved_lock == 0 &&
		    payload->identity.identity_reserved == 0 &&
		    payload->identity.flags == SE_OL_TASK_LIVE &&
		    payload->identity.physical_cookie == reservation->cookie &&
		    payload->identity.scope_cookie == reservation->scope &&
		    payload->identity.scope_slot == reservation->account_slot;
	if (!exact) {
		bpf_spin_unlock(&meta->lock);
		return SE_OL_CORRUPT;
	}
	*handle = (struct se_op_child_roles_handle){
		.meta = meta,
		.payload = payload,
		.cookie = reservation->cookie,
		.locked = 1,
	};
	*roles = (struct er_state *)payload->bytes;
	return SE_OL_OK;
}

/* The successful begin path always calls this before any helper/return.
 * Clear the borrowed pointer before releasing the metadata lock. */
static __attribute__((always_inline)) inline void
se_op_child_roles_end(struct se_op_child_roles_handle *handle,
		      struct er_state **roles)
{
	*roles = 0;
	bpf_spin_unlock(&handle->meta->lock);
	*handle = (struct se_op_child_roles_handle){};
}

/* Initialize the semantic identity before HASH publication. The frozen-zero
 * update is outside every lock, and its pointer is relooked up afterwards.
 * On any post-charge failure the caller still owns the charged constructor;
 * it must abort/reap rather than return an untracked child. */
static __attribute__((noinline)) int
se_op_initialize_task_semantic(const struct se_oc_reservation *reservation)
{
	if (!se_op_reservation_owned(reservation))
		return SE_OL_CORRUPT;
	__u32 slot = reservation->task_slot;
	struct se_ol_meta *meta = reservation->meta;
	struct se_ol_task_identity *before = SE_OL_PAYLOAD_LOOKUP(slot);
	if (!before)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = meta->phase == SE_OL_INITIALIZING &&
		    meta->cookie == reservation->cookie &&
		    meta->locator == reservation->locator &&
		    meta->active_leases == 1 &&
		    meta->account_scope == reservation->scope &&
		    meta->account_slot == reservation->account_slot &&
		    meta->account_incarnation == reservation->incarnation &&
		    meta->directory_state == SE_OL_NO_ENTRY &&
		    !meta->archive_ready && !meta->reader_holds &&
		    !meta->exclusive && !meta->exclusive_owner &&
		    !meta->reserved && !meta->cleanup_done &&
		    !before->reserved_lock && !before->flags &&
		    !before->physical_cookie && !before->scope_cookie &&
		    !before->eligibility_version && !before->next_invocation &&
		    !before->scope_slot && !before->identity_reserved;
	bpf_spin_unlock(&meta->lock);
	if (!exact || SE_OP_PAYLOAD_INIT(slot))
		return SE_OL_CORRUPT;
	struct se_ol_task_identity *identity = SE_OL_PAYLOAD_LOOKUP(slot);
	if (!identity)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	exact = meta->phase == SE_OL_INITIALIZING &&
		meta->cookie == reservation->cookie &&
		meta->locator == reservation->locator &&
		meta->active_leases == 1 &&
		meta->account_scope == reservation->scope &&
		meta->account_slot == reservation->account_slot &&
		meta->account_incarnation == reservation->incarnation &&
		meta->directory_state == SE_OL_NO_ENTRY &&
		!meta->archive_ready && !meta->reader_holds &&
		!meta->exclusive && !meta->exclusive_owner && !meta->reserved &&
		!meta->cleanup_done && !identity->reserved_lock &&
		!identity->flags && !identity->physical_cookie &&
		!identity->scope_cookie && !identity->eligibility_version &&
		!identity->next_invocation && !identity->scope_slot &&
		!identity->identity_reserved;
	if (exact) {
		identity->physical_cookie = reservation->cookie;
		identity->scope_cookie = reservation->scope;
		identity->scope_slot = reservation->account_slot;
		identity->eligibility_version = 1;
		identity->flags = SE_OL_TASK_LIVE;
	}
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}

/* Only task_alloc may issue CONSTRUCTION_DONE. This replaces, rather than
 * follows, the generic locator finish for a semantic-bearing TASK. It also
 * handles task_free racing after publication: DEAD remains DEAD. */
static __attribute__((noinline)) int
se_op_finish_semantic_birth(struct se_oc_reservation *reservation)
{
	if (!se_op_reservation_owned(reservation))
		return SE_OL_CORRUPT;
	struct se_ol_task_identity *identity =
		SE_OL_PAYLOAD_LOOKUP(reservation->task_slot);
	if (!identity)
		return SE_OL_CORRUPT;
	struct se_ol_meta *meta = reservation->meta;
	bpf_spin_lock(&meta->lock);
	int pending = meta->phase == SE_OL_PENDING_BIRTH;
	int exact = (pending || meta->phase == SE_OL_DEAD) &&
		    meta->cookie == reservation->cookie &&
		    meta->locator == reservation->locator &&
		    meta->active_leases >= 1 &&
		    (!pending || meta->active_leases == 1) &&
		    meta->account_scope == reservation->scope &&
		    meta->account_slot == reservation->account_slot &&
		    meta->account_incarnation == reservation->incarnation &&
		    meta->directory_state == SE_OL_PUBLISHED &&
		    meta->archive_ready == 1 && !meta->exclusive &&
		    !meta->exclusive_owner && !meta->reserved &&
		    !(meta->cleanup_done & SE_OL_CONSTRUCTION_DONE) &&
		    !identity->reserved_lock && !identity->identity_reserved &&
		    (identity->flags & SE_OL_TASK_LIVE) &&
		    identity->physical_cookie == reservation->cookie &&
		    identity->scope_cookie == reservation->scope &&
		    identity->scope_slot == reservation->account_slot &&
		    identity->eligibility_version;
	if (exact) {
		meta->active_leases--;
		meta->cleanup_done |= SE_OL_CONSTRUCTION_DONE;
		if (pending)
			meta->phase = SE_OL_LIVE;
	}
	bpf_spin_unlock(&meta->lock);
	if (exact)
		reservation->terminal = 1;
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}

/* Failed task_alloc cannot rely on a later task_free. Abort the exact charged
 * constructor and certify absent exec/WORK/native owners only from this
 * unpublished-child source; DIR and PAYLOAD_ZERO remain reaper-owned. If
 * the directory is in ambiguous INSERT_INTENT or another structural
 * contradiction prevents abort, stop this account and retain the charge for
 * recovery diagnosis instead of releasing the bit or admitting a child. */
static __attribute__((noinline)) int
se_op_abort_semantic_birth(struct se_oc_reservation *reservation)
{
	if (!se_op_reservation_owned(reservation))
		return SE_OL_CORRUPT;
	/* A denied task_alloc may never receive task_free. This constructor is
	 * the only source that can certify the unpublished child never acquired
	 * exec, WORK or native owners. Issue their empty-owner receipts in the
	 * SAME metadata transition as ABORTED so a concurrent reaper cannot
	 * observe ABORTED before those receipts exist. */
	struct se_pool_task_wire *payload =
		SE_OL_PAYLOAD_LOOKUP(reservation->task_slot);
	struct se_ol_meta *meta = reservation->meta;
	int exact = 0;
	if (payload) {
		bpf_spin_lock(&meta->lock);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE
		int no_semantic_owner = !payload->semantic.exec.owned &&
					!payload->semantic.reader.owned &&
					!payload->semantic.reader_invocation;
#else
		int no_semantic_owner = 1;
#endif
		int empty_identity = !payload->identity.flags &&
				     !payload->identity.physical_cookie &&
				     !payload->identity.scope_cookie &&
				     !payload->identity.eligibility_version &&
				     !payload->identity.next_invocation &&
				     !payload->identity.scope_slot;
		int live_identity =
			payload->identity.flags == SE_OL_TASK_LIVE &&
			payload->identity.physical_cookie ==
				reservation->cookie &&
			payload->identity.scope_cookie == reservation->scope &&
			payload->identity.scope_slot ==
				reservation->account_slot &&
			payload->identity.eligibility_version == 1 &&
			!payload->identity.next_invocation;
		exact = (meta->phase == SE_OL_INITIALIZING ||
			 meta->phase == SE_OL_PENDING_BIRTH) &&
			meta->cookie == reservation->cookie &&
			meta->locator == reservation->locator &&
			meta->account_scope == reservation->scope &&
			meta->account_slot == reservation->account_slot &&
			meta->account_incarnation == reservation->incarnation &&
			meta->active_leases == 1 && !meta->reader_holds &&
			!meta->exclusive && !meta->exclusive_owner &&
			!meta->reserved && !meta->cleanup_done &&
			!meta->cleanup_error && !meta->work_refs &&
			!meta->native_refs && !meta->current_work_slot &&
			!meta->current_work_owned &&
			!meta->current_work_cookie &&
			!meta->next_work_sequence && !meta->reserved2 &&
			(meta->directory_state == SE_OL_NO_ENTRY ||
			 meta->directory_state == SE_OL_ZERO_OWNED ||
			 meta->directory_state == SE_OL_PUBLISH_INTENT ||
			 meta->directory_state == SE_OL_PUBLISHED) &&
			!payload->identity.reserved_lock &&
			!payload->identity.identity_reserved &&
			(empty_identity || live_identity) && no_semantic_owner;
		if (exact) {
			meta->phase = SE_OL_ABORTED;
			meta->active_leases = 0;
			meta->cleanup_done = SE_OL_CONSTRUCTION_DONE |
					     SE_OL_EXEC_DONE | SE_OL_WORK_DONE |
					     SE_OL_NATIVE_DONE;
		}
		bpf_spin_unlock(&meta->lock);
	}
	if (exact) {
		reservation->terminal = 1;
#ifdef SE_OP_ABORTED_WITNESS
		SE_OP_ABORTED_WITNESS(); /* test-only exact-abort count */
#endif
#ifdef SE_REAP_EVENT
		/* Product reaper wakeup only (G019 M1); never authority. */
		SE_REAP_EVENT(TASK_ABORTED, reservation->task_slot,
			      reservation->cookie);
#endif
		return SE_OL_OK;
	}
	__u32 local = reservation->task_slot -
		      reservation->account_slot * SE_OC_QUOTA;
	if (local >= SE_OC_QUOTA)
		return SE_OL_CORRUPT;
	__u64 bit = 1ULL << (local % 64U);
	struct se_oc_account *account = reservation->account;
	struct se_oc_charge *charge = reservation->charge;
	bpf_spin_lock(&account->lock);
	if (charge->state == SE_OC_OWNED &&
	    charge->cookie == reservation->cookie &&
	    charge->locator == reservation->locator &&
	    (account->bits[SE_OC_WORD(local)] & bit)) {
		account->fault = 1;
		charge->state = SE_OC_FAULT_HELD;
	}
	bpf_spin_unlock(&account->lock);
	return SE_OL_CORRUPT;
}
#endif
