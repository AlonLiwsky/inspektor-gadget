/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_TASK_SEMANTIC_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_TASK_SEMANTIC_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_DEVELOPMENT) ||            \
	!defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY) || \
	!defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE)
#error "typed TASK handle is candidate-only"
#endif

/* Requires the pool ABI and TASK core. This is a lexical, stack-only lease:
 * payload.semantic may be accessed only until close. The fixed ARRAY pointer
 * is obtained from the exact directory token, never cast from a HASH row or
 * rediscovered from an address after the lease is acquired. The pool metadata
 * lock, not the reserved semantic first word, protects semantic mutation. */
struct se_pool_task_semantic_handle {
	struct se_pool_lease lease;
	struct se_pool_task_meta *meta;
	struct se_pool_task_payload *payload;
	__u32 locked;
	__u32 work_borrows;
};
#define SE_POOL_TASK_SEMANTIC_HANDLE_AVAILABLE 1

/* Called only for the unpublished constructor lease returned by
 * se_pool_task_reserve. The authenticated frozen zero ARRAY is copied into
 * the no-spinlock payload by a map helper, outside every lock. Re-fetch the
 * ARRAY pointer after update; a retained pre-update pointer is not authority.
 * The caller must run se_pool_task_complete on every charged failure. */
SE_POOL_INLINE int
se_pool_task_semantic_initialize(struct se_pool_task_refs *refs,
				 struct se_pool_reservation *reservation)
{
	if (!refs || !reservation || !se_pool_charged_slot_valid(reservation) ||
	    !se_pool_reservation_valid(reservation) || !refs->meta ||
	    !refs->payload || refs->charge != reservation->charged_charge)
		return SE_POOL_CORRUPT;
	__u32 slot = reservation->charged_slot, zero = 0;
	if (refs->meta != bpf_map_lookup_elem(&se_pool_task_meta, &slot) ||
	    refs->payload != bpf_map_lookup_elem(&se_pool_task_payload, &slot))
		return SE_POOL_CORRUPT;
	struct se_pool_token token = se_pool_reservation_token(reservation);
	bpf_spin_lock(&refs->meta->lock);
	int valid = se_pool_match(refs->meta, &token) &&
		    se_pool_meta_valid(refs->meta) &&
		    refs->meta->phase == SE_POOL_INITIALIZING &&
		    refs->meta->active_leases == 1 && !refs->meta->flags &&
		    !refs->meta->cleanup_done &&
		    refs->meta->account_scope == reservation->account.scope &&
		    refs->meta->account_slot ==
			    reservation->account.route_slot &&
		    refs->meta->account_incarnation ==
			    reservation->account.incarnation;
	bpf_spin_unlock(&refs->meta->lock);
	if (!valid)
		return SE_POOL_CORRUPT;
	const struct se_pool_task_payload *empty =
		bpf_map_lookup_elem(&se_pool_task_zero, &zero);
	if (!empty ||
	    bpf_map_update_elem(&se_pool_task_payload, &slot, empty, BPF_ANY))
		return SE_POOL_CORRUPT;
	struct se_pool_task_payload *payload =
		bpf_map_lookup_elem(&se_pool_task_payload, &slot);
	if (!payload)
		return SE_POOL_CORRUPT;
	bpf_spin_lock(&refs->meta->lock);
	valid = se_pool_match(refs->meta, &token) &&
		se_pool_meta_valid(refs->meta) &&
		refs->meta->phase == SE_POOL_INITIALIZING &&
		refs->meta->active_leases == 1 && !refs->meta->flags &&
		!refs->meta->cleanup_done;
	if (valid) {
		payload->semantic.physical_cookie = token.cookie;
		payload->semantic.scope_cookie = reservation->account.scope;
		payload->semantic.scope_slot = reservation->account.route_slot;
		payload->semantic.eligibility_version = 1;
		payload->semantic.flags = SE_TASK_LIVE;
	}
	bpf_spin_unlock(&refs->meta->lock);
	if (!valid)
		return SE_POOL_CORRUPT;
	refs->payload = payload;
	return SE_POOL_OK;
}

/* The unpublished child still belongs to the task_alloc callback. Invoke
 * only after successful publication, any parent inheritance, and successful
 * se_pool_task_complete. That epilogue has dropped the constructor lease but
 * leaves PENDING_BIRTH; no helper or payload lookup is allowed between it and
 * this fixed-pointer transition. This marks only constructor completion, not
 * exec/work/native/directory/payload-zero cleanup. */
SE_POOL_INLINE int se_pool_task_semantic_finish_birth(
	struct se_pool_task_refs *refs,
	const struct se_pool_reservation *reservation)
{
	if (!refs || !reservation || !refs->route || !refs->meta ||
	    !refs->payload || reservation->held ||
	    reservation->kind != SE_POOL_KIND_TASK ||
	    reservation->charged_charge != refs->charge ||
	    reservation->charged_slot != reservation->pool_slot ||
	    reservation->charged_slot_inverse != ~reservation->charged_slot) {
		if (refs && refs->route) {
			bpf_spin_lock(&refs->route->lock);
			refs->route->reserved = 1;
			bpf_spin_unlock(&refs->route->lock);
		}
		return SE_POOL_CORRUPT;
	}
	struct se_pool_token token = se_pool_reservation_token(reservation);
	if (!se_pool_token_valid(&token)) {
		bpf_spin_lock(&refs->route->lock);
		refs->route->reserved = 1;
		bpf_spin_unlock(&refs->route->lock);
		return SE_POOL_CORRUPT;
	}
	bpf_spin_lock(&refs->meta->lock);
	int valid = se_pool_match(refs->meta, &token) &&
		    se_pool_meta_valid(refs->meta) &&
		    refs->meta->phase == SE_POOL_PENDING_BIRTH &&
		    refs->meta->flags == SE_POOL_PUBLISHED &&
		    !refs->meta->active_leases && !refs->meta->cleanup_done &&
		    refs->meta->account_scope == reservation->account.scope &&
		    refs->meta->account_slot ==
			    reservation->account.route_slot &&
		    refs->meta->account_incarnation ==
			    reservation->account.incarnation &&
		    refs->payload->semantic.physical_cookie == token.cookie &&
		    refs->payload->semantic.scope_cookie ==
			    reservation->account.scope &&
		    refs->payload->semantic.scope_slot ==
			    reservation->account.route_slot &&
		    (refs->payload->semantic.flags & SE_TASK_LIVE) &&
		    !refs->payload->semantic.identity_reserved;
	if (valid) {
		refs->meta->cleanup_done = SE_POOL_CONSTRUCTION_DONE;
		refs->meta->phase = SE_POOL_LIVE;
	}
	bpf_spin_unlock(&refs->meta->lock);
	if (!valid) {
		bpf_spin_lock(&refs->route->lock);
		refs->route->reserved = 1;
		bpf_spin_unlock(&refs->route->lock);
	}
	return valid ? SE_POOL_OK : SE_POOL_CORRUPT;
}

/* Constructor-owned, stack-only TASK transaction for the actual task_alloc
 * callback. prepare leaves one held constructor lease and no directory row.
 * The caller performs parent inheritance before finish publishes the row.
 * An inheritance failure calls abort while unpublished; it cannot rely on
 * task_free because a denied security_task_alloc may bypass that hook. */
struct se_pool_task_birth_candidate {
	struct se_pool_reservation reservation;
	struct se_pool_task_refs refs;
	struct se_pool_token token;
	__u32 state; /* 0 empty, 1 unpublished constructor, 2 completed */
};

/* Only the unpublished child's committed role state is writable through this
 * constructor-owned view. Do not expose exec/reader fields to an inheritance
 * caller: ABORTED cleanup certifies those obligations without task_free.
 * The pointer is lexical and must not escape task_alloc or survive finish.
 * Parent inheritance still needs a held parent handle, canonical WORK
 * projection, and final parent-locked revalidation. */
SE_POOL_INLINE int
se_pool_task_birth_child_view(struct se_pool_task_birth_candidate *birth,
			      struct er_state **child)
{
	if (!birth || !child || *child || birth->state != 1 ||
	    birth->reservation.held != 1 || !birth->refs.route ||
	    !birth->refs.meta || !birth->refs.payload ||
	    !se_pool_reservation_valid(&birth->reservation) ||
	    !se_pool_charged_slot_valid(&birth->reservation) ||
	    !se_pool_token_valid(&birth->token) ||
	    birth->token.address != birth->reservation.physical_address ||
	    birth->token.cookie != birth->reservation.cookie ||
	    birth->token.slot != birth->reservation.pool_slot ||
	    birth->reservation.charged_slot != birth->token.slot ||
	    birth->reservation.charged_charge != birth->refs.charge)
		return SE_POOL_CORRUPT;
	__u32 slot = birth->token.slot;
	if (birth->refs.meta !=
		    bpf_map_lookup_elem(&se_pool_task_meta, &slot) ||
	    birth->refs.payload !=
		    bpf_map_lookup_elem(&se_pool_task_payload, &slot))
		return SE_POOL_CORRUPT;
	bpf_spin_lock(&birth->refs.meta->lock);
	int valid = se_pool_match(birth->refs.meta, &birth->token) &&
		    se_pool_meta_valid(birth->refs.meta) &&
		    birth->refs.meta->phase == SE_POOL_INITIALIZING &&
		    birth->refs.meta->active_leases == 1 &&
		    !birth->refs.meta->flags &&
		    !birth->refs.meta->cleanup_done &&
		    birth->refs.payload->semantic.physical_cookie ==
			    birth->token.cookie &&
		    birth->refs.payload->semantic.scope_cookie ==
			    birth->reservation.account.scope &&
		    birth->refs.payload->semantic.scope_slot ==
			    birth->reservation.account.route_slot &&
		    birth->refs.payload->semantic.flags == SE_TASK_LIVE &&
		    !birth->refs.payload->semantic.identity_reserved;
	bpf_spin_unlock(&birth->refs.meta->lock);
	if (!valid)
		return SE_POOL_CORRUPT;
	*child = &birth->refs.payload->semantic.committed;
	return SE_POOL_OK;
}

SE_POOL_INLINE int
se_pool_task_birth_prepare(struct se_route_anchor *route,
			   const struct se_route_claim *claim, __u64 address,
			   struct se_pool_task_birth_candidate *birth)
{
	if (!route || !claim || !birth || !address || birth->state ||
	    birth->reservation.held || birth->refs.route)
		return SE_POOL_CORRUPT;
	*birth = (struct se_pool_task_birth_candidate){};
	int status = se_pool_task_reserve(route, claim, address,
					  &birth->reservation, &birth->refs);
	if (status != SE_POOL_OK)
		return status;
	birth->token = se_pool_reservation_token(&birth->reservation);
	status = se_pool_task_semantic_initialize(&birth->refs,
						  &birth->reservation);
	if (status != SE_POOL_OK)
		goto abort;
	birth->state = 1;
	return SE_POOL_OK;
abort:
	if (se_pool_task_complete(route, birth->refs.bitmap, birth->refs.charge,
				  birth->refs.meta,
				  &birth->reservation) != SE_POOL_OK)
		return SE_POOL_CORRUPT; /* retain the fault-held reservation */
	birth->state = 2;
	return status;
}

/* Caller has rejected inheritance while the child is still unpublished.
 * Complete the charge to ABORTED before returning a denial. A later
 * authenticated reaper must clear this charged row; no task_free is assumed. */
SE_POOL_INLINE int
se_pool_task_birth_abort(struct se_pool_task_birth_candidate *birth)
{
	if (!birth || birth->state != 1 || birth->reservation.held != 1 ||
	    !birth->refs.route)
		return SE_POOL_CORRUPT;
	int status = se_pool_task_complete(birth->refs.route,
					   birth->refs.bitmap,
					   birth->refs.charge, birth->refs.meta,
					   &birth->reservation);
	if (status == SE_POOL_OK)
		birth->state = 2;
	return status;
}

SE_POOL_INLINE int
se_pool_task_birth_finish(struct se_pool_task_birth_candidate *birth)
{
	if (!birth || birth->state != 1 || birth->reservation.held != 1 ||
	    !birth->refs.route)
		return SE_POOL_CORRUPT;
	int status = se_pool_publish_first(birth->refs.directory,
					   birth->refs.meta, &birth->token);
	if (status == SE_POOL_CONTENDED) {
		struct se_pool_token old = {};
		status = se_pool_lookup(birth->refs.directory,
					birth->token.address, &old);
		if (status == SE_POOL_OK) {
			__u32 old_slot = old.slot;
			struct se_pool_task_meta *old_meta =
				bpf_map_lookup_elem(&se_pool_task_meta,
						    &old_slot);
			if (!old_meta)
				status = SE_POOL_CORRUPT;
			else {
				struct se_pool_hold hold = {};
				status = se_pool_hold_old(birth->refs.meta,
							  old_meta,
							  &birth->token, &old,
							  &hold);
				if (status == SE_POOL_OK)
					status = se_pool_replace(
						birth->refs.directory,
						birth->refs.meta, old_meta,
						&hold);
				if (hold.held &&
				    se_pool_drop_hold(old_meta, &hold) !=
					    SE_POOL_OK)
					status = SE_POOL_CORRUPT;
			}
		}
	}
	if (status != SE_POOL_OK) {
		int completed = se_pool_task_birth_abort(birth);
		return completed == SE_POOL_OK ? status : completed;
	}
	status = se_pool_task_complete(birth->refs.route, birth->refs.bitmap,
				       birth->refs.charge, birth->refs.meta,
				       &birth->reservation);
	if (status != SE_POOL_OK)
		return status;
	status = se_pool_task_semantic_finish_birth(&birth->refs,
						    &birth->reservation);
	if (status == SE_POOL_OK)
		birth->state = 2;
	return status;
}

SE_POOL_INLINE int
se_pool_task_semantic_open(__u64 address,
			   struct se_pool_task_semantic_handle *handle)
{
	if (!address || !handle || handle->lease.held || handle->locked ||
	    handle->work_borrows || handle->meta || handle->payload)
		return SE_POOL_CORRUPT;
	__u32 bucket = se_pool_bucket(address);
	struct se_pool_directory *directory =
		bpf_map_lookup_elem(&se_pool_directory, &bucket);
	if (!directory)
		return SE_POOL_CORRUPT;
	struct se_pool_token token = {};
	int status = se_pool_lookup(directory, address, &token);
	if (status != SE_POOL_OK)
		return status;
	__u32 slot = token.slot;
	struct se_pool_task_meta *meta =
		bpf_map_lookup_elem(&se_pool_task_meta, &slot);
	struct se_pool_task_payload *payload =
		bpf_map_lookup_elem(&se_pool_task_payload, &slot);
	if (!meta || !payload)
		return SE_POOL_CORRUPT;
	status = se_pool_borrow(meta, &token, &handle->lease);
	if (status != SE_POOL_OK)
		return status;
	/* Lease excludes slot reuse and payload zero. Recheck the exact semantic
	 * identity under its actual metadata lock; no helper runs while locked. */
	bpf_spin_lock(&meta->lock);
	int valid = se_pool_match(meta, &token) &&
		    meta->phase == SE_POOL_LIVE &&
		    payload->semantic.physical_cookie == token.cookie &&
		    payload->semantic.scope_cookie == meta->account_scope &&
		    payload->semantic.scope_slot == meta->account_slot &&
		    (payload->semantic.flags & SE_TASK_LIVE) &&
		    !payload->semantic.identity_reserved;
	bpf_spin_unlock(&meta->lock);
	if (!valid) {
		status = se_pool_release(meta, &handle->lease);
		return status == SE_POOL_OK ? SE_POOL_CORRUPT : status;
	}
	handle->meta = meta;
	handle->payload = payload;
	return SE_POOL_OK;
}

/* begin/end bracket a synchronous semantic operation. The caller must not
 * invoke a BPF helper, close the handle, or retain a semantic pointer while
 * this metadata lock is held. A DEAD transition between open and begin is
 * ordinary ineligibility; a mismatched token or semantic identity is a fault. */
SE_POOL_INLINE int
se_pool_task_semantic_begin(struct se_pool_task_semantic_handle *handle)
{
	if (!handle || handle->locked || handle->lease.held != 1 ||
	    !handle->meta || !handle->payload ||
	    !se_pool_token_valid(&handle->lease.token))
		return SE_POOL_CORRUPT;
	struct se_pool_task_meta *meta = handle->meta;
	struct se_task_state *semantic = &handle->payload->semantic;
	bpf_spin_lock(&meta->lock);
	int status = SE_POOL_OK;
	if (!se_pool_match(meta, &handle->lease.token) ||
	    !se_pool_meta_valid(meta) || !meta->active_leases ||
	    semantic->physical_cookie != handle->lease.token.cookie ||
	    semantic->scope_cookie != meta->account_scope ||
	    semantic->scope_slot != meta->account_slot ||
	    semantic->identity_reserved)
		status = SE_POOL_CORRUPT;
	else if (meta->phase != SE_POOL_LIVE ||
		 !(semantic->flags & SE_TASK_LIVE))
		status = SE_POOL_NOT_ELIGIBLE;
	if (status != SE_POOL_OK) {
		bpf_spin_unlock(&meta->lock);
		return status;
	}
	handle->locked = 1;
	return SE_POOL_OK;
}

SE_POOL_INLINE int
se_pool_task_semantic_end(struct se_pool_task_semantic_handle *handle)
{
	if (!handle || handle->locked != 1 || handle->lease.held != 1 ||
	    !handle->meta || !handle->payload)
		return SE_POOL_CORRUPT;
	handle->locked = 0;
	bpf_spin_unlock(&handle->meta->lock);
	return SE_POOL_OK;
}

SE_POOL_INLINE int
se_pool_task_semantic_close(struct se_pool_task_semantic_handle *handle)
{
	if (!handle || !handle->meta || !handle->payload ||
	    handle->lease.held != 1 || handle->locked || handle->work_borrows)
		return SE_POOL_CORRUPT;
	int status = se_pool_release(handle->meta, &handle->lease);
	if (status == SE_POOL_OK) {
		handle->meta = 0;
		handle->payload = 0;
	}
	return status;
}
#endif
