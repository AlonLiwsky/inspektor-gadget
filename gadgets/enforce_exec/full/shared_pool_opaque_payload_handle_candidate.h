/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_PAYLOAD_HANDLE_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_PAYLOAD_HANDLE_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque payload handle is candidate-only"
#endif
#ifndef SE_OL_PAYLOAD_LOOKUP
#error "provide fixed-slot TASK payload ARRAY lookup"
#endif

#include "shared_pool_opaque_charge_candidate.h"

/* The same wire shape is used by the typed TASK pool candidate and this
 * opaque candidate. No policy field is inferred from the prefix alone. */
#include "shared_pool_task_wire.h"
#define SE_OL_TASK_LIVE 4U

/* An existing exact locator lease is moved into this lexical handle. The
 * caller still owns a failed lease and must release it. The payload pointer
 * is never policy authority by itself: begin checks its exact live task
 * identity under the metadata lock; consumers must still retain original-
 * scope and policy authority. */
struct se_ol_payload_handle {
	struct se_ol_lease lease;
	void *payload;
	__u32 locked;
};

static __attribute__((noinline)) int
se_ol_payload_open(struct se_ol_lease *lease,
		   struct se_ol_payload_handle *handle)
{
	if (!lease || lease->held != 1 || !lease->meta || !handle ||
	    handle->lease.held || handle->lease.meta || handle->payload ||
	    handle->locked)
		return SE_OL_CORRUPT;
	__u32 slot = 0;
	if (se_ol_decode(lease->locator, &slot) != SE_OL_OK ||
	    slot != lease->slot)
		return SE_OL_CORRUPT;
	struct se_ol_meta *meta = lease->meta;
	__u32 account_slot, incarnation;
	__u64 scope;
	bpf_spin_lock(&meta->lock);
	int live = meta->locator == lease->locator &&
		   meta->cookie == lease->cookie && meta->active_leases &&
		   meta->phase == SE_OL_LIVE &&
		   meta->directory_state == SE_OL_PUBLISHED &&
		   meta->archive_ready == 1 && !meta->exclusive &&
		   !meta->exclusive_owner && !meta->reserved &&
		   meta->account_scope && meta->account_incarnation &&
		   meta->account_slot < SE_OC_ACCOUNTS;
	account_slot = meta->account_slot;
	incarnation = meta->account_incarnation;
	scope = meta->account_scope;
	bpf_spin_unlock(&meta->lock);
	if (!live || slot / SE_OC_QUOTA != account_slot)
		return SE_OL_STALE;
	struct se_oc_account *account = SE_OC_ACCOUNT_LOOKUP(account_slot);
	struct se_oc_charge *charge = SE_OC_CHARGE_LOOKUP(slot);
	if (!account || !charge)
		return SE_OL_CORRUPT;
	__u32 local = slot - account_slot * SE_OC_QUOTA;
	/* At B2/T128 the verifier loses the quotient relation at this helper
	 * boundary. Bound the ARRAY bitmap subscript independently. */
	if (local >= SE_OC_QUOTA)
		return SE_OL_CORRUPT;
	__u64 bit = 1ULL << (local % 64U);
	bpf_spin_lock(&account->lock);
	int charged = !account->fault && !account->reserved &&
		      account->scope == scope &&
		      account->incarnation == incarnation && account->used &&
		      account->used <= SE_OC_QUOTA &&
		      se_oc_bitmap_count(account) == account->used &&
		      (account->bits[SE_OC_WORD(local)] & bit) &&
		      charge->state == SE_OC_OWNED &&
		      charge->cookie == lease->cookie &&
		      charge->scope == scope &&
		      charge->incarnation == incarnation &&
		      charge->locator == lease->locator;
	bpf_spin_unlock(&account->lock);
	if (!charged)
		return SE_OL_CORRUPT;
	void *payload = SE_OL_PAYLOAD_LOOKUP(slot);
	if (!payload)
		return SE_OL_CORRUPT;
	/* Death may race the account and payload lookups. The lease prevents
	 * physical reuse; begin rechecks LIVE before exposing any bytes. */
	*handle = (struct se_ol_payload_handle){ .lease = *lease,
						 .payload = payload };
	lease->held = 0;
	lease->meta = 0;
	return SE_OL_OK;
}

static __attribute__((always_inline)) inline int
se_ol_payload_begin(struct se_ol_payload_handle *handle, void **payload)
{
	if (!handle || !payload || *payload || handle->locked ||
	    handle->lease.held != 1 || !handle->lease.meta || !handle->payload)
		return SE_OL_CORRUPT;
	struct se_ol_meta *meta = handle->lease.meta;
	bpf_spin_lock(&meta->lock);
	int live = meta->locator == handle->lease.locator &&
		   meta->cookie == handle->lease.cookie &&
		   meta->active_leases && meta->phase == SE_OL_LIVE &&
		   meta->directory_state == SE_OL_PUBLISHED &&
		   meta->archive_ready == 1 && !meta->exclusive &&
		   !meta->exclusive_owner && !meta->reserved;
	if (!live) {
		bpf_spin_unlock(&meta->lock);
		return SE_OL_STALE;
	}
	struct se_ol_task_identity *identity = handle->payload;
	if (identity->reserved_lock || identity->identity_reserved ||
	    !(identity->flags & SE_OL_TASK_LIVE) ||
	    identity->physical_cookie != handle->lease.cookie ||
	    identity->scope_cookie != meta->account_scope ||
	    identity->scope_slot != meta->account_slot) {
		bpf_spin_unlock(&meta->lock);
		return SE_OL_CORRUPT;
	}
	handle->locked = 1;
	*payload = handle->payload;
	return SE_OL_OK;
}

/* Host regression convenience only. A BPF callback that has successfully
 * begun this lexical borrow must clear it and unlock unconditionally: a
 * fallible end leaves a verifier-visible return under the spinlock. */
static __attribute__((always_inline)) inline int
se_ol_payload_end(struct se_ol_payload_handle *handle, void **payload)
{
	if (!handle || !payload || handle->locked != 1 ||
	    *payload != handle->payload || handle->lease.held != 1 ||
	    !handle->lease.meta)
		return SE_OL_CORRUPT;
	*payload = 0;
	handle->locked = 0;
	bpf_spin_unlock(&handle->lease.meta->lock);
	return SE_OL_OK;
}

static __attribute__((noinline)) int
se_ol_payload_close(struct se_ol_payload_handle *handle)
{
	if (!handle || handle->locked || handle->lease.held != 1 ||
	    !handle->payload)
		return SE_OL_CORRUPT;
	int released = se_ol_release_lease(&handle->lease);
	if (released == SE_OL_OK) {
		handle->payload = 0;
		handle->lease.meta = 0;
	}
	return released;
}

#endif
