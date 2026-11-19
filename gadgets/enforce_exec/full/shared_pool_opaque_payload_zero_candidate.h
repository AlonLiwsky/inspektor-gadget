/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_PAYLOAD_ZERO_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_PAYLOAD_ZERO_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque payload zero is candidate-only"
#endif
#ifndef SE_OP_PAYLOAD_ZERO
#error "provide an actual fixed-slot payload zero helper"
#endif

#include "shared_pool_opaque_refund_candidate.h"

/* This source owns only PAYLOAD_ZERO_DONE. The first five receipts must have
 * been issued by their independent source owners. An exact original charge
 * and archive/deletion state must still exist before a fallible map update.
 * The temporary metadata lease excludes refund/reuse during the helper; no
 * map helper runs while locked. A post-helper contradiction retains the
 * lease and charge rather than claiming an unsafe zero receipt. */
static __attribute__((noinline)) int se_op_zero_payload(__u32 slot,
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
	__u64 scope, locator;
	__u32 incarnation;
	bpf_spin_lock(&account->lock);
	scope = charge->scope;
	locator = charge->locator;
	incarnation = charge->incarnation;
	int charged = !account->fault && !account->reserved &&
		      account->scope == scope &&
		      account->incarnation == incarnation && account->used &&
		      account->used <= SE_OC_QUOTA &&
		      se_oc_bitmap_count(account) == account->used &&
		      (account->bits[SE_OC_WORD(local)] & bit) &&
		      charge->state == SE_OC_OWNED &&
		      charge->cookie == expected_cookie &&
		      charge->last_returned < expected_cookie && scope &&
		      incarnation && locator;
	bpf_spin_unlock(&account->lock);
	if (!charged)
		return SE_OC_PENDING;
	__u32 decoded = 0;
	if (se_ol_decode(locator, &decoded) != SE_OL_OK || decoded != slot)
		return SE_OC_CORRUPT;
	const __u32 prerequisite = SE_OL_ALL_DONE ^ SE_OL_PAYLOAD_ZERO_DONE;
	bpf_spin_lock(&meta->lock);
	int exact = meta->phase == SE_OL_ARCHIVE_ZEROED &&
		    se_oc_ready_meta(meta, account_slot, incarnation, scope,
				     expected_cookie, locator) &&
		    meta->cleanup_done == prerequisite;
	if (exact)
		meta->active_leases = 1;
	bpf_spin_unlock(&meta->lock);
	if (!exact)
		return SE_OC_PENDING;
	int zeroed = SE_OP_PAYLOAD_ZERO(slot) == 0;
	bpf_spin_lock(&meta->lock);
	exact = meta->phase == SE_OL_ARCHIVE_ZEROED &&
		meta->cookie == expected_cookie && meta->locator == locator &&
		meta->account_scope == scope &&
		meta->account_slot == account_slot &&
		meta->account_incarnation == incarnation &&
		meta->directory_state == SE_OL_DELETED &&
		!meta->archive_ready && meta->active_leases == 1 &&
		!meta->reader_holds && !meta->exclusive &&
		!meta->exclusive_owner && !meta->reserved && !meta->work_refs &&
		!meta->native_refs && !meta->cleanup_error &&
		!meta->current_work_owned && !meta->current_work_slot &&
		!meta->current_work_cookie && !meta->reserved2 &&
		meta->cleanup_done == prerequisite;
	if (exact) {
		meta->active_leases = 0;
		if (zeroed)
			meta->cleanup_done |= SE_OL_PAYLOAD_ZERO_DONE;
	}
	bpf_spin_unlock(&meta->lock);
	if (!exact)
		return SE_OC_CORRUPT;
	return zeroed ? SE_OC_PROGRESS : SE_OC_PENDING;
}

#endif
