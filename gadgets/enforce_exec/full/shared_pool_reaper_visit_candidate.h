/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_REAPER_VISIT_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_REAPER_VISIT_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_DEVELOPMENT) ||            \
	!defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY) || \
	!defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE)
#error "reaper visit requires the typed pool candidate"
#endif

/* Keep per-slot visitor bodies out of the scan chunk: the verifier can then
 * reason about each stage without multiplying its paths by four. */

/* Select one fixed WORK slot from its original account. The owner pointer is
 * prefetched from the WORK row's saved TASK slot, not a current address or
 * cgroup. A changed owner identity before entry is contention; the full
 * visitor validates the charge, bitmap, saved owner and release obligations.
 * This is a per-slot body only: a selected driver must call it for exactly
 * min(32,W) slots and must retain a single-flight reaper permit. */
static __attribute__((noinline)) int se_pool_reap_work_visit_slot(__u32 slot)
{
	if (slot >= SE_POOL_W)
		return SE_PW_FAULT;
	__u32 account = slot / SE_POOL_QW;
	__u32 charge_slot = SE_POOL_T + slot, zero = 0;
	struct se_route_anchor *route = se_route_anchor_lookup(&account);
	struct se_pool_bitmap *bits =
		bpf_map_lookup_elem(&se_pool_bitmaps, &account);
	struct se_pool_charge *charge =
		bpf_map_lookup_elem(&se_pool_charges, &charge_slot);
	struct se_pool_work_meta *work =
		bpf_map_lookup_elem(&se_pool_work_meta, &slot);
	const struct se_pool_work_payload *empty =
		bpf_map_lookup_elem(&se_pool_work_zero, &zero);
	if (!route || !bits || !charge || !work || !empty)
		return SE_PW_FAULT;
	bpf_spin_lock(&work->lock);
	__u32 owner_slot = work->owner_task_slot;
	__u64 cookie = work->cookie;
	bpf_spin_unlock(&work->lock);
	if (owner_slot >= SE_POOL_T)
		return SE_PW_FAULT;
	struct se_pool_task_meta *owner =
		bpf_map_lookup_elem(&se_pool_task_meta, &owner_slot);
	if (!owner)
		return SE_PW_FAULT;
	bpf_spin_lock(&work->lock);
	int stable = work->owner_task_slot == owner_slot &&
		     work->cookie == cookie;
	bpf_spin_unlock(&work->lock);
	if (!stable)
		return SE_PW_CONTENDED;
	return se_pw_visit(route, bits, charge, work, owner, empty, slot);
}

/* A fixed TASK slot is selected by the reaper cursor, never by an address
 * supplied from userspace. The token is a snapshot of the charged row; every
 * mutating stage rechecks the exact token and original account under its own
 * lock. Five iterations cover the maximum recorded refund boundaries without
 * requiring a later birth to advance cleanup. An unmet exec/WORK/native
 * obligation remains charged and reports pending, not a fabricated DONE bit. */
static __attribute__((noinline)) int se_pool_reap_task_visit_slot(__u32 slot)
{
	if (slot >= SE_POOL_T)
		return SE_POOL_CORRUPT;
	__u32 account = slot / SE_POOL_QT;
	struct se_route_anchor *route = se_route_anchor_lookup(&account);
	struct se_pool_bitmap *bits =
		bpf_map_lookup_elem(&se_pool_bitmaps, &account);
	struct se_pool_charge *charge =
		bpf_map_lookup_elem(&se_pool_charges, &slot);
	struct se_pool_task_meta *meta =
		bpf_map_lookup_elem(&se_pool_task_meta, &slot);
	if (!route || !bits || !charge || !meta)
		return SE_POOL_CORRUPT;
	bpf_spin_lock(&route->lock);
	__u32 charge_state = charge->state;
	bpf_spin_unlock(&route->lock);
	if (charge_state == SE_POOL_CH_FREE)
		return se_pool_task_refund_tail(route, bits, charge, meta,
						slot);
	if (charge_state == SE_POOL_CH_BUILDING)
		return SE_POOL_PENDING_CLEANUP;
	if (charge_state != SE_POOL_CH_OWNED &&
	    charge_state != SE_POOL_CH_RETURN_READY)
		return SE_POOL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	struct se_pool_token token = {
		.address = meta->physical_address,
		.cookie = meta->cookie,
		.slot = meta->slot,
	};
	__u32 phase = meta->phase, flags = meta->flags;
	int exact = se_pool_meta_valid(meta) && meta->slot == slot &&
		    meta->account_slot == account &&
		    se_pool_token_valid(&token);
	bpf_spin_unlock(&meta->lock);
	if (!exact)
		return SE_POOL_CORRUPT;
	if (charge_state == SE_POOL_CH_RETURN_READY &&
	    phase != SE_POOL_REFUND_PENDING && phase != SE_POOL_FREE)
		return SE_POOL_CORRUPT;
	if (!(flags & SE_POOL_PUBLISHED)) {
		if (flags)
			return SE_POOL_CORRUPT;
		if (phase != SE_POOL_ABORTED && phase != SE_POOL_CLEANING &&
		    phase != SE_POOL_REFUND_PENDING && phase != SE_POOL_FREE)
			return SE_POOL_PENDING_CLEANUP;
		int status = SE_POOL_PENDING_CLEANUP;
#ifdef __clang__
#pragma unroll
#endif
		for (__u32 i = 0; i < 5; i++) {
			status = se_pool_task_abort_reap_step(slot);
			if (status != SE_POOL_PENDING_CLEANUP)
				break;
		}
		return status;
	}
	if (flags != SE_POOL_PUBLISHED &&
	    flags != (SE_POOL_PUBLISHED | SE_POOL_DIR_CLAIM))
		return SE_POOL_CORRUPT;
	if (phase != SE_POOL_DEAD && phase != SE_POOL_CLEANING &&
	    phase != SE_POOL_REFUND_PENDING && phase != SE_POOL_FREE)
		return SE_POOL_PENDING_CLEANUP;
	if (phase == SE_POOL_DEAD || phase == SE_POOL_CLEANING) {
		int status = se_pool_task_exec_reap_step(&token);
		if (status != SE_POOL_OK)
			return status;
		status = se_pool_task_work_reap_step(&token);
		if (status != SE_POOL_OK)
			return status;
	}
	int status = SE_POOL_PENDING_CLEANUP;
#ifdef __clang__
#pragma unroll
#endif
	for (__u32 i = 0; i < 5; i++) {
		status = se_pool_task_live_reap_step(&token);
		if (status != SE_POOL_PENDING_CLEANUP)
			break;
	}
	return status;
}
#endif
