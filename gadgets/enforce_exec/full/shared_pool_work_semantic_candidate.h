/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_WORK_SEMANTIC_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_WORK_SEMANTIC_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_DEVELOPMENT) ||            \
	!defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY) || \
	!defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE)
#error "typed WORK semantic adapter is candidate-only"
#endif

#ifdef SE_POOL_TASK_SEMANTIC_HANDLE_AVAILABLE
/* The only candidate bridge that may mint a WORK-core TASK lease. The parent
 * exact TASK handle owns the physical pool lease; work_borrows prevents its
 * close until the WORK ticket has reached done/abort. No second TASK charge
 * or active_leases increment is invented. */
SE_PW_INLINE int
se_pool_work_lease_from_task(struct se_pool_task_semantic_handle *task_handle,
			     struct se_pw_task_lease *lease)
{
	if (!task_handle || !lease || task_handle->lease.held != 1 ||
	    task_handle->locked || task_handle->work_borrows ||
	    !task_handle->meta || !task_handle->payload || lease->held)
		return SE_PW_FAULT;
	struct se_pool_task_meta *meta = task_handle->meta;
	struct se_pool_token token = task_handle->lease.token;
	bpf_spin_lock(&meta->lock);
	int valid = se_pool_match(meta, &token) && se_pool_meta_valid(meta) &&
		    meta->phase == SE_POOL_LIVE && meta->active_leases &&
		    task_handle->payload->semantic.physical_cookie ==
			    token.cookie &&
		    task_handle->payload->semantic.scope_cookie ==
			    meta->account_scope &&
		    task_handle->payload->semantic.scope_slot ==
			    meta->account_slot &&
		    (task_handle->payload->semantic.flags & SE_TASK_LIVE) &&
		    !task_handle->payload->semantic.identity_reserved;
	if (valid) {
		*lease = (struct se_pw_task_lease){
			.cookie = token.cookie,
			.physical_address = token.address,
			.scope = meta->account_scope,
			.slot = token.slot,
			.account_slot = meta->account_slot,
			.account_incarnation = meta->account_incarnation,
			.held = 1,
		};
		task_handle->work_borrows = 1;
	}
	bpf_spin_unlock(&meta->lock);
	return valid ? SE_PW_OK : SE_PW_FAULT;
}

/* Close only after the exact WORK ticket has been consumed by done/abort.
 * The zero ticket is permitted only when selection/begin failed before charge;
 * product callers must source-audit that branch rather than fabricate zero. */
SE_PW_INLINE int
se_pool_work_lease_to_task(struct se_pool_task_semantic_handle *task_handle,
			   struct se_pw_task_lease *lease,
			   const struct se_pw_ticket *ticket)
{
	if (!task_handle || !lease || !ticket || task_handle->lease.held != 1 ||
	    task_handle->locked || task_handle->work_borrows != 1 ||
	    lease->held != 1 || !task_handle->meta || !task_handle->payload ||
	    ticket->held ||
	    (ticket->cookie &&
	     (ticket->reserved || ticket->cookie > SE_PW_U64_LIMIT ||
	      ticket->scope != lease->scope ||
	      ticket->account_slot != lease->account_slot ||
	      ticket->account_incarnation != lease->account_incarnation ||
	      ticket->slot >= SE_POOL_W ||
	      ticket->owner_cookie != lease->cookie ||
	      ticket->owner_address != lease->physical_address ||
	      ticket->owner_slot != lease->slot)))
		return SE_PW_FAULT;
	struct se_pool_task_meta *meta = task_handle->meta;
	bpf_spin_lock(&meta->lock);
	int valid = se_pool_match(meta, &task_handle->lease.token) &&
		    se_pool_meta_valid(meta) && meta->active_leases &&
		    se_pw_lease_matches(meta, lease) &&
		    !meta->current_work_owned;
	if (valid) {
		lease->held = 0;
		task_handle->work_borrows = 0;
	}
	bpf_spin_unlock(&meta->lock);
	return valid ? SE_PW_OK : SE_PW_FAULT;
}
#endif

/* Prefetch every fixed owner for a selected WORK slot before any charge.
 * Charge indices share one ARRAY with TASK: WORK slot s is T+s. The old
 * owner TASK slot is needed when a FREE WORK row retains prior identity;
 * observing it does not grant authority, and se_pw_begin must revalidate. */
struct se_pool_work_refs {
	struct se_route_anchor *route;
	struct se_pool_bitmap *bitmap;
	struct se_pool_charge *charge;
	struct se_pool_sequence *sequence;
	struct se_pool_task_meta *task;
	struct se_pool_task_meta *previous_task;
	struct se_pool_work_meta *work;
	struct se_pool_work_payload *payload;
	const struct se_pool_work_payload *zero;
};

SE_PW_INLINE int se_pool_work_prefetch(const struct se_pw_task_lease *lease,
				       __u32 slot,
				       struct se_pool_work_refs *refs)
{
	if (!lease || !refs || lease->held != 1 || lease->slot >= SE_POOL_T ||
	    lease->account_slot >= SE_POOL_B || slot >= SE_POOL_W ||
	    slot / SE_POOL_QW != lease->account_slot)
		return SE_PW_STALE;
	if (refs->route || refs->bitmap || refs->charge || refs->sequence ||
	    refs->task || refs->previous_task || refs->work || refs->payload ||
	    refs->zero)
		return SE_PW_FAULT;
	__u32 account = lease->account_slot, zero = 0;
	__u32 task_slot = lease->slot, charge_slot = SE_POOL_T + slot;
	struct se_pool_work_refs found = {
		.route = se_route_anchor_lookup(&account),
		.bitmap = bpf_map_lookup_elem(&se_pool_bitmaps, &account),
		.charge = bpf_map_lookup_elem(&se_pool_charges, &charge_slot),
		.sequence = bpf_map_lookup_elem(&se_pool_sequence, &zero),
		.task = bpf_map_lookup_elem(&se_pool_task_meta, &task_slot),
		.work = bpf_map_lookup_elem(&se_pool_work_meta, &slot),
		.payload = bpf_map_lookup_elem(&se_pool_work_payload, &slot),
		.zero = bpf_map_lookup_elem(&se_pool_work_zero, &zero),
	};
	if (!found.route || !found.bitmap || !found.charge || !found.sequence ||
	    !found.task || !found.work || !found.payload || !found.zero)
		return SE_PW_FAULT;
	bpf_spin_lock(&found.work->lock);
	__u64 old_cookie = found.work->cookie;
	__u32 old_slot = found.work->owner_task_slot;
	bpf_spin_unlock(&found.work->lock);
	if (old_cookie && old_slot >= SE_POOL_T)
		return SE_PW_FAULT;
	found.previous_task =
		old_cookie ?
			bpf_map_lookup_elem(&se_pool_task_meta, &old_slot) :
			found.task;
	if (!found.previous_task)
		return SE_PW_FAULT;
	*refs = found;
	return SE_PW_OK;
}

/* Requires the pool ABI and WORK core. The caller retains an exact TASK
 * lease and one charged WORK ticket through attach, this initialization,
 * commit, the last semantic read and done/abort. No address is authority. */
SE_PW_INLINE int se_pool_work_semantic_initialize(
	struct se_pool_task_meta *task, struct se_pool_work_meta *work,
	struct se_pool_charge *charge, struct se_pool_work_payload **payload,
	const struct se_pw_task_lease *lease, const struct se_pw_ticket *ticket)
{
	if (!task || !work || !charge || !payload || !*payload ||
	    !se_pw_ticket_valid(ticket) || !lease ||
	    ticket->owner_cookie != lease->cookie ||
	    ticket->owner_address != lease->physical_address ||
	    ticket->owner_slot != lease->slot ||
	    ticket->account_slot != lease->account_slot ||
	    ticket->account_incarnation != lease->account_incarnation ||
	    ticket->scope != lease->scope)
		return SE_PW_FAULT;
	__u32 slot = ticket->slot, task_slot = lease->slot, zero = 0;
	__u32 charge_slot = SE_POOL_T + slot;
	if (task != bpf_map_lookup_elem(&se_pool_task_meta, &task_slot) ||
	    work != bpf_map_lookup_elem(&se_pool_work_meta, &slot) ||
	    charge != bpf_map_lookup_elem(&se_pool_charges, &charge_slot) ||
	    *payload != bpf_map_lookup_elem(&se_pool_work_payload, &slot))
		return SE_PW_FAULT;
	bpf_spin_lock(&task->lock);
	int owner = se_pw_lease_matches(task, lease) &&
		    task->phase == SE_PW_TASK_LIVE && task->active_leases &&
		    task->current_work_owned == 1 &&
		    task->current_work_cookie == ticket->cookie &&
		    task->current_work_slot == slot && task->work_refs;
	bpf_spin_unlock(&task->lock);
	if (!owner)
		return SE_PW_FAULT;
	bpf_spin_lock(&work->lock);
	int valid =
		work->phase == SE_PW_INITIALIZING && work->active_leases == 1 &&
		work->owner_ref_held == 1 && se_pw_same_work(work, ticket) &&
		work->cookie == ticket->cookie && work->invocation_sequence &&
		work->invocation_sequence <= SE_PW_U64_LIMIT;
	bpf_spin_unlock(&work->lock);
	if (!valid)
		return SE_PW_FAULT;
	const struct se_pool_work_payload *empty =
		bpf_map_lookup_elem(&se_pool_work_zero, &zero);
	if (!empty ||
	    bpf_map_update_elem(&se_pool_work_payload, &slot, empty, BPF_ANY))
		return SE_PW_FAULT;
	struct se_pool_work_payload *fresh =
		bpf_map_lookup_elem(&se_pool_work_payload, &slot);
	if (!fresh)
		return SE_PW_FAULT;
	bpf_spin_lock(&work->lock);
	valid = work->phase == SE_PW_INITIALIZING && work->active_leases == 1 &&
		work->owner_ref_held == 1 && se_pw_same_work(work, ticket) &&
		work->invocation_sequence &&
		work->invocation_sequence <= SE_PW_U64_LIMIT;
	if (valid) {
		fresh->semantic.scope = ticket->scope;
		fresh->semantic.cookie = ticket->cookie;
		fresh->semantic.sequence = work->invocation_sequence;
		fresh->semantic.slot = slot;
		fresh->semantic.reserved = 0;
	}
	bpf_spin_unlock(&work->lock);
	if (!valid)
		return SE_PW_FAULT;
	*payload = fresh;
	return SE_PW_OK;
}

/* No extra semantic lease is minted: this validates the exact live ticket.
 * The callback must finish every semantic use before se_pw_done or abort. */
SE_PW_INLINE int se_pool_work_semantic_active(
	struct se_pool_task_meta *task, const struct se_pw_task_lease *lease,
	struct se_pool_work_meta *work,
	const struct se_pool_work_payload *payload,
	const struct se_pw_ticket *ticket, struct se_route_anchor *route,
	struct se_pool_charge *charge)
{
	if (!route || !charge)
		return SE_PW_FAULT;
	int valid = task && lease && work && payload &&
		    se_pw_ticket_valid(ticket);
	if (valid) {
		bpf_spin_lock(&task->lock);
		valid = se_pw_lease_matches(task, lease) &&
			task->phase == SE_PW_TASK_LIVE && task->active_leases &&
			task->work_refs && work->owner_ref_held == 1 &&
			ticket->owner_cookie == lease->cookie &&
			ticket->owner_address == lease->physical_address &&
			ticket->owner_slot == lease->slot;
		bpf_spin_unlock(&task->lock);
	}
	if (valid) {
		bpf_spin_lock(&work->lock);
		valid = work->phase == SE_PW_ACTIVE &&
			work->active_leases == 1 && work->owner_ref_held == 1 &&
			se_pw_same_work(work, ticket) &&
			payload->semantic.scope == ticket->scope &&
			payload->semantic.cookie == ticket->cookie &&
			payload->semantic.sequence ==
				work->invocation_sequence &&
			payload->semantic.slot == ticket->slot &&
			!payload->semantic.reserved;
		bpf_spin_unlock(&work->lock);
	}
	bpf_spin_lock(&route->lock);
	if (valid)
		valid = route->scope == ticket->scope &&
			route->incarnation == ticket->account_incarnation &&
			route->payload_slot == ticket->account_slot &&
			!route->reserved && route->scratch_used &&
			se_pw_charge_matches(charge, ticket) &&
			charge->state == SE_PW_CH_OWNED;
	if (!valid) {
		if (se_pw_ticket_valid(ticket) &&
		    se_pw_charge_matches(charge, ticket) &&
		    (charge->state == SE_PW_CH_OWNED ||
		     charge->state == SE_PW_CH_BUILDING))
			charge->state = SE_PW_CH_FAULT_HELD;
		route->reserved = 1;
	}
	bpf_spin_unlock(&route->lock);
	return valid ? SE_PW_OK : SE_PW_FAULT;
}

/* A WORK semantic pointer is usable only while this stack-local handle and
 * its caller-owned TASK lease and WORK ticket remain live. Closing calls
 * se_pw_done after the last read; a failed close retains the handle and
 * faults the exact charge/account rather than inventing a refund. */
struct se_pool_work_semantic_handle {
	struct se_pool_task_meta *task;
	struct se_pool_work_meta *work;
	struct se_pool_work_payload *payload;
	struct se_route_anchor *route;
	struct se_pool_charge *charge;
	struct se_pw_task_lease *task_lease;
	struct se_pw_ticket *ticket;
	__u32 held;
};

SE_PW_INLINE int se_pool_work_semantic_open(
	struct se_pool_task_meta *task, struct se_pw_task_lease *lease,
	struct se_pool_work_meta *work, struct se_pool_work_payload *payload,
	struct se_pw_ticket *ticket, struct se_route_anchor *route,
	struct se_pool_charge *charge,
	struct se_pool_work_semantic_handle *handle)
{
	if (!handle || handle->held || handle->task || handle->work ||
	    handle->payload || handle->route || handle->charge ||
	    handle->task_lease || handle->ticket)
		return SE_PW_FAULT;
	int status = se_pool_work_semantic_active(task, lease, work, payload,
						  ticket, route, charge);
	if (status != SE_PW_OK)
		return status;
	handle->task = task;
	handle->work = work;
	handle->payload = payload;
	handle->route = route;
	handle->charge = charge;
	handle->task_lease = lease;
	handle->ticket = ticket;
	handle->held = 1;
	return SE_PW_OK;
}

SE_PW_INLINE int
se_pool_work_semantic_done(struct se_pool_work_semantic_handle *handle)
{
	if (!handle || handle->held != 1 || !handle->task || !handle->work ||
	    !handle->payload || !handle->route || !handle->charge ||
	    !handle->task_lease || !handle->ticket)
		return SE_PW_FAULT;
	int status = se_pool_work_semantic_active(
		handle->task, handle->task_lease, handle->work, handle->payload,
		handle->ticket, handle->route, handle->charge);
	int closed = se_pw_done(handle->task, handle->work, handle->task_lease,
				handle->ticket);
	if (closed != SE_PW_OK) {
		bpf_spin_lock(&handle->route->lock);
		if (se_pw_ticket_valid(handle->ticket) &&
		    se_pw_charge_matches(handle->charge, handle->ticket) &&
		    (handle->charge->state == SE_PW_CH_OWNED ||
		     handle->charge->state == SE_PW_CH_BUILDING))
			handle->charge->state = SE_PW_CH_FAULT_HELD;
		handle->route->reserved = 1;
		bpf_spin_unlock(&handle->route->lock);
		return SE_PW_FAULT;
	}
	*handle = (struct se_pool_work_semantic_handle){};
	return status;
}
#endif
