/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_WORK_CORE_H
#define ENFORCE_EXEC_SHARED_POOL_WORK_CORE_H
#if !defined(ENFORCE_EXEC_POOL_DEVELOPMENT) || \
	!defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY)
#error "work core is candidate-only"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "address-token WORK owner cannot be used with opaque TASK locator; port WORK charge and owner receipts"
#endif
/* Include after shared_route.h and shared_pool_abi_candidate.h. All pointers
 * are prefetched fixed ARRAY values. No function accepts an address as owner
 * authority. The caller supplies a retained exact task lease and must finish
 * every successful begin in this same synchronous invocation. */
#define SE_PW_INLINE static __attribute__((always_inline)) inline
#define SE_PW_U64_LIMIT (~(__u64)0 - 1)
#define SE_PW_U32_LIMIT ((__u32)~0u)
enum se_pw_status {
	SE_PW_OK = 0,
	SE_PW_PENDING = 1,
	SE_PW_FREE = 2,
	SE_PW_RETURNED = 3,
	SE_PW_ALREADY = 4,
	SE_PW_STALE = -1,
	SE_PW_FAULT = -2,
	SE_PW_BUSY = -3,
	SE_PW_CAPACITY = -4,
	SE_PW_CONTENDED = -5
};
enum se_pw_phase {
	SE_PW_FREE_PHASE = 0,
	SE_PW_INITIALIZING = 1,
	SE_PW_ACTIVE = 2,
	SE_PW_DONE = 3,
	SE_PW_ABORTED = 4,
	SE_PW_CLEANING = 5,
	SE_PW_REFUND_PENDING = 6
};
enum se_pw_charge_phase {
	SE_PW_CH_FREE = 0,
	SE_PW_CH_BUILDING = 1,
	SE_PW_CH_OWNED = 2,
	SE_PW_CH_RETURN_READY = 3,
	SE_PW_CH_FAULT_HELD = 4
};
enum { SE_PW_OWNER_RELEASED = 1, SE_PW_PAYLOAD_ZERO = 2 };
enum { SE_PW_TASK_LIVE = 4 }; /* typed reconciliation point: TASK peer phase */
/* Stack-only lease minted by the TASK-side exact borrow adapter. Its held
 * field is lexical, not a userspace or persistent authorization bit. */
struct se_pw_task_lease {
	__u64 cookie, physical_address, scope;
	__u32 slot, account_slot, account_incarnation, held;
};
struct se_pw_ticket {
	__u64 cookie, scope, owner_cookie, owner_address;
	__u32 slot, account_slot, account_incarnation, owner_slot;
	__u32 held, reserved;
};
_Static_assert(sizeof(struct se_pw_task_lease) == 40, "work task lease size");
_Static_assert(sizeof(struct se_pw_ticket) == 56, "work ticket size");
_Static_assert(SE_PW_CH_FREE == 0 && SE_PW_CH_FAULT_HELD == 4 &&
		       SE_PW_FREE_PHASE == 0 && SE_PW_REFUND_PENDING == 6,
	       "work enum values");

SE_PW_INLINE int se_pw_lease_matches(const struct se_pool_task_meta *task,
				     const struct se_pw_task_lease *lease)
{
	return task && lease && lease->held == 1 && lease->cookie &&
	       lease->cookie <= SE_PW_U64_LIMIT && lease->physical_address &&
	       lease->scope && lease->scope <= SE_PW_U64_LIMIT &&
	       lease->slot < SE_POOL_T && lease->account_slot < SE_POOL_B &&
	       lease->account_incarnation && task->cookie == lease->cookie &&
	       task->physical_address == lease->physical_address &&
	       task->slot == lease->slot &&
	       task->account_scope == lease->scope &&
	       task->account_slot == lease->account_slot &&
	       task->account_incarnation == lease->account_incarnation;
}
SE_PW_INLINE int se_pw_ticket_valid(const struct se_pw_ticket *t)
{
	return t && t->held == 1 && !t->reserved && t->cookie &&
	       t->cookie <= SE_PW_U64_LIMIT && t->scope &&
	       t->scope <= SE_PW_U64_LIMIT && t->account_slot < SE_POOL_B &&
	       t->account_incarnation && t->slot < SE_POOL_W &&
	       t->slot / SE_POOL_QW == t->account_slot && t->owner_cookie &&
	       t->owner_cookie <= SE_PW_U64_LIMIT && t->owner_address &&
	       t->owner_slot < SE_POOL_T;
}
SE_PW_INLINE int se_pw_charge_matches(const struct se_pool_charge *ch,
				      const struct se_pw_ticket *t)
{
	return ch->current_cookie == t->cookie &&
	       ch->account_scope == t->scope &&
	       ch->account_incarnation == t->account_incarnation;
}
SE_PW_INLINE __u32 se_pw_popcount(__u64 v, __u32 width)
{
	__u32 n = 0;
	for (__u32 i = 0; i < width; i++)
		n += (__u32)((v >> i) & 1u);
	return n;
}
/* Selection scans the entire partition under the ORIGINAL route lock. A
 * full bitmap is capacity only when its count agrees with the account. */
SE_PW_INLINE int se_pw_select(struct se_route_anchor *route,
			      const struct se_pool_bitmap *bits,
			      const struct se_pw_task_lease *lease, __u32 *slot)
{
	if (!route || !bits || !lease || !slot || !lease->held ||
	    lease->account_slot >= SE_POOL_B)
		return SE_PW_STALE;
	int result = SE_PW_OK;
	__u32 candidate = SE_POOL_QW, count = 0;
	bpf_spin_lock(&route->lock);
	if (route->scope != lease->scope ||
	    route->incarnation != lease->account_incarnation ||
	    route->payload_slot != lease->account_slot ||
	    route->phase != SE_ROUTE_ACTIVE)
		result = SE_PW_STALE;
	else if (route->reserved || bits->header.reserved0 ||
		 bits->header.reserved1 ||
		 bits->header.work_hint >= SE_POOL_QW ||
		 bits->header.task_hint >= SE_POOL_QT)
		result = SE_PW_FAULT;
	else {
#ifdef __clang__
#pragma unroll
#endif
		for (__u32 w = 0; w < SE_POOL_WORK_WORDS; w++) {
			__u32 remaining = SE_POOL_QW - w * 64u;
			__u64 mask = remaining >= 64u ?
					     ~0ULL :
					     ((1ULL << remaining) - 1);
			__u64 occupied = bits->words[SE_POOL_TASK_WORDS + w];
			if (occupied & ~mask)
				result = SE_PW_FAULT;
			count += se_pw_popcount(occupied & mask,
						remaining >= 64u ? 64u :
								   remaining);
			if (candidate == SE_POOL_QW) {
				__u64 freebits = (~occupied) & mask;
				for (__u32 bit = 0; bit < 64; bit++)
					if (freebits & (1ULL << bit)) {
						candidate = w * 64u + bit;
						break;
					}
			}
		}
		if (count != route->scratch_used || count > SE_POOL_QW)
			result = SE_PW_FAULT;
		else if (candidate == SE_POOL_QW && result == SE_PW_OK)
			result = SE_PW_CAPACITY;
		else if (candidate >= SE_POOL_QW)
			result = SE_PW_FAULT;
		else if (result == SE_PW_OK)
			*slot = lease->account_slot * SE_POOL_QW + candidate;
	}
	if (result == SE_PW_FAULT)
		route->reserved = 1;
	bpf_spin_unlock(&route->lock);
	return result;
}
/* The caller prefetches metadata, payload and charge for selected slot before
 * calling begin. A contention retry must reselect and prefetch. */
SE_PW_INLINE int
se_pw_begin(struct se_route_anchor *route, struct se_pool_bitmap *bits,
	    struct se_pool_charge *ch, struct se_pool_sequence *seq,
	    struct se_pool_task_meta *task, struct se_pool_work_meta *work,
	    struct se_pool_work_payload *payload,
	    struct se_pool_task_meta *previous_task,
	    const struct se_pw_task_lease *lease, __u32 slot,
	    struct se_pw_ticket *ticket)
{
	if (!route || !bits || !ch || !seq || !task || !work || !payload ||
	    !lease || !ticket || ticket->held || slot >= SE_POOL_W ||
	    slot / SE_POOL_QW != lease->account_slot)
		return SE_PW_STALE;
	bpf_spin_lock(&task->lock);
	int owner = se_pw_lease_matches(task, lease) &&
		    task->phase == SE_PW_TASK_LIVE && task->active_leases &&
		    !(task->flags & ~3u);
	bpf_spin_unlock(&task->lock);
	if (!owner)
		return SE_PW_STALE;
	__u64 cookie = 0;
	bpf_spin_lock(&seq->lock);
	if (!seq->reserved && seq->next < SE_PW_U64_LIMIT)
		cookie = ++seq->next;
	bpf_spin_unlock(&seq->lock);
	if (!cookie)
		return SE_PW_FAULT;
	__u32 local = slot - lease->account_slot * SE_POOL_QW;
	__u32 word = SE_POOL_TASK_WORDS + local / 64u;
	__u64 bit = 1ULL << (local % 64u);
	__u64 last_returned = 0;
	int result = SE_PW_OK;
	bpf_spin_lock(&route->lock);
	if (route->scope != lease->scope ||
	    route->incarnation != lease->account_incarnation ||
	    route->payload_slot != lease->account_slot ||
	    route->phase != SE_ROUTE_ACTIVE)
		result = SE_PW_STALE;
	else if (bits->words[word] & bit)
		result = SE_PW_CONTENDED;
	else if (route->reserved || route->scratch_used >= SE_POOL_QW ||
		 ch->state != SE_PW_CH_FREE || ch->current_cookie ||
		 ch->account_scope || ch->account_incarnation ||
		 ch->last_returned_cookie > SE_PW_U64_LIMIT ||
		 cookie <= ch->last_returned_cookie)
		result = SE_PW_FAULT;
	else {
		bits->words[word] |= bit;
		route->scratch_used++;
		bits->header.work_hint = (local + 1u) % SE_POOL_QW;
		ch->current_cookie = cookie;
		ch->account_scope = lease->scope;
		last_returned = ch->last_returned_cookie;
		ch->account_incarnation = lease->account_incarnation;
		ch->state = SE_PW_CH_BUILDING;
		*ticket = (struct se_pw_ticket){
			.cookie = cookie,
			.scope = lease->scope,
			.owner_cookie = lease->cookie,
			.owner_address = lease->physical_address,
			.slot = slot,
			.account_slot = lease->account_slot,
			.account_incarnation = lease->account_incarnation,
			.owner_slot = lease->slot,
			.held = 1
		};
	}
	if (result == SE_PW_FAULT)
		route->reserved = 1;
	bpf_spin_unlock(&route->lock);
	if (result != SE_PW_OK)
		return result;
	/* FREE may retain the last cookie/completion after refund. The old owner
  * reference is gone at that point, so the physical TASK slot may already
  * hold a different task. Its lock protects only owner_ref_held here. */
	struct se_pool_task_meta *old_task = work->cookie ? previous_task :
							    task;
	int owner_clean = 0;
	if (old_task) {
		bpf_spin_lock(&old_task->lock);
		owner_clean = !work->owner_ref_held &&
			      (!work->cookie ||
			       old_task->slot == work->owner_task_slot);
		bpf_spin_unlock(&old_task->lock);
	}
	bpf_spin_lock(&work->lock);
	int clean =
		owner_clean && work->phase == SE_PW_FREE_PHASE &&
		!work->active_leases &&
		(work->cookie ?
			 (work->cookie <= SE_PW_U64_LIMIT &&
			  work->cookie == last_returned &&
			  work->cleanup_done == 3 && work->owner_task_cookie &&
			  work->owner_task_cookie <= SE_PW_U64_LIMIT &&
			  work->owner_task_address && work->account_scope &&
			  work->account_scope <= SE_PW_U64_LIMIT &&
			  work->invocation_sequence &&
			  work->invocation_sequence <= SE_PW_U64_LIMIT &&
			  work->owner_task_slot < SE_POOL_T &&
			  work->account_slot < SE_POOL_B &&
			  work->account_slot == slot / SE_POOL_QW &&
			  work->account_incarnation) :
			 (!work->owner_task_cookie &&
			  !work->owner_task_address && !work->account_scope &&
			  !work->invocation_sequence &&
			  !work->owner_task_slot && !work->account_slot &&
			  !work->account_incarnation && !work->cleanup_done &&
			  !last_returned));
	if (clean) {
		work->phase = SE_PW_INITIALIZING;
		work->cookie = cookie;
		work->owner_task_cookie = lease->cookie;
		work->owner_task_address = lease->physical_address;
		work->account_scope = lease->scope;
		work->invocation_sequence = 0;
		work->owner_task_slot = lease->slot;
		work->account_slot = lease->account_slot;
		work->account_incarnation = lease->account_incarnation;
		work->active_leases = 1;
		work->cleanup_done = 0;
		work->last_reap_sequence = 0;
	}
	bpf_spin_unlock(&work->lock);
	if (clean)
		return SE_PW_OK;
	bpf_spin_lock(&route->lock);
	if (se_pw_charge_matches(ch, ticket) && ch->state == SE_PW_CH_BUILDING)
		ch->state = SE_PW_CH_FAULT_HELD;
	route->reserved = 1;
	bpf_spin_unlock(&route->lock);
	ticket->held = 0;
	return SE_PW_FAULT;
}

SE_PW_INLINE int se_pw_same_work(const struct se_pool_work_meta *w,
				 const struct se_pw_ticket *t)
{
	return w->cookie == t->cookie &&
	       w->owner_task_cookie == t->owner_cookie &&
	       w->owner_task_address == t->owner_address &&
	       w->owner_task_slot == t->owner_slot &&
	       w->account_scope == t->scope &&
	       w->account_slot == t->account_slot &&
	       w->account_incarnation == t->account_incarnation;
}
SE_PW_INLINE int se_pw_attach(struct se_pool_task_meta *task,
			      struct se_pool_work_meta *work,
			      const struct se_pw_task_lease *lease,
			      const struct se_pw_ticket *t)
{
	if (!task || !work || !se_pw_ticket_valid(t) || !lease ||
	    work->phase != SE_PW_INITIALIZING || !se_pw_same_work(work, t) ||
	    work->active_leases != 1)
		return SE_PW_FAULT;
	int result = SE_PW_OK;
	bpf_spin_lock(&task->lock);
	if (!se_pw_lease_matches(task, lease) ||
	    task->phase != SE_PW_TASK_LIVE || !task->active_leases ||
	    task->current_work_owned || task->current_work_cookie ||
	    task->current_work_slot || work->owner_ref_held ||
	    task->work_refs == SE_PW_U32_LIMIT ||
	    task->next_work_sequence >= SE_PW_U64_LIMIT)
		result = SE_PW_BUSY;
	else {
		task->work_refs++;
		work->owner_ref_held = 1;
		work->invocation_sequence = ++task->next_work_sequence;
		task->current_work_cookie = t->cookie;
		task->current_work_slot = t->slot;
		task->current_work_owned = 1;
	}
	bpf_spin_unlock(&task->lock);
	return result;
}
SE_PW_INLINE int se_pw_promote(struct se_route_anchor *route,
			       struct se_pool_bitmap *bits,
			       struct se_pool_charge *ch,
			       const struct se_pw_ticket *t)
{
	if (!route || !bits || !ch || !se_pw_ticket_valid(t))
		return SE_PW_FAULT;
	__u32 local = t->slot - t->account_slot * SE_POOL_QW;
	__u64 bit = 1ULL << (local % 64u);
	int result = SE_PW_OK;
	bpf_spin_lock(&route->lock);
	if (ch->current_cookie && ch->current_cookie != t->cookie)
		result = SE_PW_STALE;
	else if (route->scope != t->scope ||
		 route->incarnation != t->account_incarnation ||
		 route->payload_slot != t->account_slot ||
		 !route->scratch_used || route->scratch_used > SE_POOL_QW ||
		 !(bits->words[SE_POOL_TASK_WORDS + local / 64u] & bit) ||
		 !se_pw_charge_matches(ch, t) || ch->state != SE_PW_CH_BUILDING)
		result = SE_PW_FAULT;
	if (se_pw_charge_matches(ch, t) && ch->state == SE_PW_CH_BUILDING)
		ch->state = result == SE_PW_OK ? SE_PW_CH_OWNED :
						 SE_PW_CH_FAULT_HELD;
	if (result == SE_PW_FAULT)
		route->reserved = 1;
	bpf_spin_unlock(&route->lock);
	return result;
}
SE_PW_INLINE void se_pw_fault_charge(struct se_route_anchor *route,
				     struct se_pool_charge *ch,
				     const struct se_pw_ticket *t)
{
	if (!route || !ch || !t)
		return;
	bpf_spin_lock(&route->lock);
	if (se_pw_charge_matches(ch, t) && ch->state == SE_PW_CH_BUILDING)
		ch->state = SE_PW_CH_FAULT_HELD;
	route->reserved = 1;
	bpf_spin_unlock(&route->lock);
}
/* Commit follows successful payload initialization. If it fails, the exact
 * charge is fault held; no caller may treat the slot as available. */
SE_PW_INLINE int se_pw_commit(struct se_pool_work_meta *work,
			      struct se_route_anchor *route,
			      struct se_pool_bitmap *bits,
			      struct se_pool_charge *ch,
			      const struct se_pw_ticket *t)
{
	if (!work || !se_pw_ticket_valid(t) ||
	    work->phase != SE_PW_INITIALIZING || !se_pw_same_work(work, t) ||
	    work->active_leases != 1 || !work->invocation_sequence) {
		if (se_pw_ticket_valid(t))
			se_pw_fault_charge(route, ch, t);
		return SE_PW_FAULT;
	}
	int result = se_pw_promote(route, bits, ch, t);
	if (result != SE_PW_OK)
		return result;
	bpf_spin_lock(&work->lock);
	work->phase = SE_PW_ACTIVE;
	bpf_spin_unlock(&work->lock);
	return SE_PW_OK;
}
/* Abort is the sole normal failed-constructor exit. It retains an attached
 * owner ref for the reaper and clears only its own current-work token. */
SE_PW_INLINE int
se_pw_abort(struct se_pool_task_meta *task, struct se_pool_work_meta *work,
	    struct se_route_anchor *route, struct se_pool_bitmap *bits,
	    struct se_pool_charge *ch, const struct se_pw_task_lease *lease,
	    struct se_pw_ticket *t)
{
	if (!task || !work || !se_pw_ticket_valid(t) || !lease ||
	    work->phase != SE_PW_INITIALIZING || !se_pw_same_work(work, t) ||
	    work->active_leases != 1) {
		if (se_pw_ticket_valid(t))
			se_pw_fault_charge(route, ch, t);
		return SE_PW_FAULT;
	}
	int valid = 1;
	int attached = 0;
	bpf_spin_lock(&task->lock);
	if (!se_pw_lease_matches(task, lease) || !task->active_leases)
		valid = 0;
	else if (work->owner_ref_held) {
		if (!task->work_refs || !task->current_work_owned ||
		    task->current_work_cookie != t->cookie ||
		    task->current_work_slot != t->slot)
			valid = 0;
		else {
			task->current_work_cookie = 0;
			task->current_work_slot = 0;
			task->current_work_owned = 0;
			attached = 1;
		}
	} else if (work->invocation_sequence ||
		   task->next_work_sequence >= SE_PW_U64_LIMIT)
		valid = 0;
	else
		work->invocation_sequence = ++task->next_work_sequence;
	bpf_spin_unlock(&task->lock);
	if (!valid) {
		se_pw_fault_charge(route, ch, t);
		return SE_PW_FAULT;
	}
	bpf_spin_lock(&work->lock);
	work->phase = SE_PW_ABORTED;
	work->active_leases = 0;
	if (!attached)
		work->cleanup_done = SE_PW_OWNER_RELEASED;
	bpf_spin_unlock(&work->lock);
	int result = se_pw_promote(route, bits, ch, t);
	t->held = 0;
	return result;
}
SE_PW_INLINE int se_pw_done(struct se_pool_task_meta *task,
			    struct se_pool_work_meta *work,
			    const struct se_pw_task_lease *lease,
			    struct se_pw_ticket *t)
{
	if (!task || !work || !lease || !se_pw_ticket_valid(t) ||
	    work->phase != SE_PW_ACTIVE || !se_pw_same_work(work, t) ||
	    work->active_leases != 1)
		return SE_PW_FAULT;
	int valid = 1;
	bpf_spin_lock(&task->lock);
	if (!se_pw_lease_matches(task, lease) || !task->active_leases ||
	    !task->work_refs || work->owner_ref_held != 1 ||
	    task->current_work_owned != 1 ||
	    task->current_work_cookie != t->cookie ||
	    task->current_work_slot != t->slot)
		valid = 0;
	else {
		task->current_work_cookie = 0;
		task->current_work_slot = 0;
		task->current_work_owned = 0;
	}
	bpf_spin_unlock(&task->lock);
	if (!valid)
		return SE_PW_FAULT;
	bpf_spin_lock(&work->lock);
	work->phase = SE_PW_DONE;
	work->active_leases = 0;
	bpf_spin_unlock(&work->lock);
	t->held = 0;
	return SE_PW_OK;
}
/* Single-flight reaper only. owner_ref_held is read and changed under the
 * exact TASK lock. The decrement-to-completion group has no fallible step. */
SE_PW_INLINE int se_pw_release_owner(struct se_pool_task_meta *task,
				     struct se_pool_work_meta *work)
{
	if (!work || work->phase != SE_PW_CLEANING || work->active_leases)
		return SE_PW_PENDING;
	if (work->cleanup_done & SE_PW_OWNER_RELEASED) {
		if (!task || task->slot != work->owner_task_slot)
			return SE_PW_FAULT;
		bpf_spin_lock(&task->lock);
		int already = !work->owner_ref_held;
		bpf_spin_unlock(&task->lock);
		return already ? SE_PW_ALREADY : SE_PW_FAULT;
	}
	if (!task)
		return SE_PW_FAULT;
	int valid = 1;
	bpf_spin_lock(&task->lock);
	if (!task->cookie || task->cookie != work->owner_task_cookie ||
	    task->physical_address != work->owner_task_address ||
	    task->slot != work->owner_task_slot ||
	    task->account_scope != work->account_scope ||
	    task->account_slot != work->account_slot ||
	    task->account_incarnation != work->account_incarnation ||
	    !work->cookie || !work->invocation_sequence ||
	    work->owner_ref_held != 1 || !task->work_refs ||
	    (task->current_work_owned &&
	     task->current_work_cookie == work->cookie))
		valid = 0;
	if (valid) {
		work->owner_ref_held = 0;
		task->work_refs--;
	}
	bpf_spin_unlock(&task->lock);
	if (!valid)
		return SE_PW_FAULT;
	/* NON-RETURN GROUP: no helper, task access, or fallible branch here. */
	bpf_spin_lock(&work->lock);
	work->cleanup_done |= SE_PW_OWNER_RELEASED;
	bpf_spin_unlock(&work->lock);
	return SE_PW_OK;
}

/* An adapter must provide a zero operation on the fixed ARRAY value, using
 * the frozen zero template. It must be called outside all locks. */
#ifndef SE_PW_ZERO_PAYLOAD
#define SE_PW_ZERO_PAYLOAD(slot, zero) \
	bpf_map_update_elem(&se_pool_work_payload, &(slot), (zero), BPF_ANY)
#endif
/* The caller provides the prefetched exact owner TASK slot, even if its
 * identity has since been recycled. A held reference requires that the old
 * identity still matches and its TASK reference count is positive. */
SE_PW_INLINE int se_pw_owner_proof(struct se_pool_task_meta *task,
				   const struct se_pool_work_meta *work,
				   int released)
{
	if (!task || (work->cookie && (work->owner_task_slot >= SE_POOL_T ||
				       task->slot != work->owner_task_slot)))
		return 0;
	bpf_spin_lock(&task->lock);
	__u32 held = work->owner_ref_held;
	int exact = task->cookie == work->owner_task_cookie &&
		    task->physical_address == work->owner_task_address &&
		    task->slot == work->owner_task_slot &&
		    task->account_scope == work->account_scope &&
		    task->account_slot == work->account_slot &&
		    task->account_incarnation == work->account_incarnation;
	int valid = held <= 1 && (!held || (exact && task->work_refs));
	bpf_spin_unlock(&task->lock);
	return valid && (released ? !held : held == 1);
}
SE_PW_INLINE int se_pw_fault_visit(struct se_route_anchor *route,
				   struct se_pool_charge *ch, __u64 cookie,
				   __u64 scope, __u32 incarnation)
{
	bpf_spin_lock(&route->lock);
	if (ch->current_cookie == cookie && ch->account_scope == scope &&
	    ch->account_incarnation == incarnation &&
	    ch->state != SE_PW_CH_FREE)
		ch->state = SE_PW_CH_FAULT_HELD;
	route->reserved = 1;
	bpf_spin_unlock(&route->lock);
	return SE_PW_FAULT;
}
/* Full work visit is single-flight reaper work. The caller prefetches the
 * original route, bitset, charge, work, exact owner slot and zero template. */
SE_PW_INLINE int
se_pw_visit(struct se_route_anchor *route, struct se_pool_bitmap *bits,
	    struct se_pool_charge *ch, struct se_pool_work_meta *work,
	    struct se_pool_task_meta *task,
	    const struct se_pool_work_payload *zero, __u32 slot)
{
	if (!route)
		return SE_PW_FAULT;
	if (!bits || !ch || !work || !zero || slot >= SE_POOL_W) {
		bpf_spin_lock(&route->lock);
		if (ch && slot < SE_POOL_W && ch->state != SE_PW_CH_FREE)
			ch->state = SE_PW_CH_FAULT_HELD;
		route->reserved = 1;
		bpf_spin_unlock(&route->lock);
		return SE_PW_FAULT;
	}
	__u32 account = slot / SE_POOL_QW, local = slot - account * SE_POOL_QW;
	__u64 mask = 1ULL << (local % 64u);
	__u32 word = SE_POOL_TASK_WORDS + local / 64u;
	__u64 cookie, scope, last_returned;
	__u32 incarnation, charge_phase, bit, count;
	bpf_spin_lock(&route->lock);
	cookie = ch->current_cookie;
	scope = ch->account_scope;
	last_returned = ch->last_returned_cookie;
	incarnation = ch->account_incarnation;
	charge_phase = ch->state;
	bit = !!(bits->words[word] & mask);
	count = route->scratch_used;
	bpf_spin_unlock(&route->lock);
	bpf_spin_lock(&work->lock);
	__u32 observed_phase = work->phase;
	bpf_spin_unlock(&work->lock);
	bpf_spin_lock(&route->lock);
	int stable = ch->current_cookie == cookie &&
		     ch->account_scope == scope &&
		     ch->account_incarnation == incarnation &&
		     ch->last_returned_cookie == last_returned &&
		     ch->state == charge_phase &&
		     !!(bits->words[word] & mask) == bit &&
		     route->scratch_used == count;
	int account_valid = route->scope == scope &&
			    route->incarnation == incarnation &&
			    route->payload_slot == account;
	__u32 bitmap_count = 0;
	int bitmap_bad = 0;
#ifdef __clang__
#pragma unroll
#endif
	for (__u32 w = 0; w < SE_POOL_WORK_WORDS; w++) {
		__u32 remaining = SE_POOL_QW - w * 64u;
		__u64 valid_mask = remaining >= 64u ? ~0ULL :
						      ((1ULL << remaining) - 1);
		__u64 occupied = bits->words[SE_POOL_TASK_WORDS + w];
		bitmap_bad |= !!(occupied & ~valid_mask);
		bitmap_count +=
			se_pw_popcount(occupied & valid_mask,
				       remaining >= 64u ? 64u : remaining);
	}
	int count_bad = charge_phase != SE_PW_CH_FREE &&
			(!count || count > SE_POOL_QW || bitmap_bad ||
			 count != bitmap_count);
	if (stable && count_bad) {
		if (ch->current_cookie == cookie &&
		    ch->account_scope == scope &&
		    ch->account_incarnation == incarnation &&
		    ch->state != SE_PW_CH_FREE)
			ch->state = SE_PW_CH_FAULT_HELD;
		route->reserved = 1;
	}
	bpf_spin_unlock(&route->lock);
	if (!stable)
		return SE_PW_PENDING;
	if (count_bad)
		return SE_PW_FAULT;
	if (charge_phase == SE_PW_CH_FREE) {
		if (bit || cookie || scope || incarnation)
			return se_pw_fault_visit(route, ch, cookie, scope,
						 incarnation);
		bpf_spin_lock(&work->lock);
		int clean = observed_phase == SE_PW_FREE_PHASE &&
			    work->phase == SE_PW_FREE_PHASE &&
			    !work->active_leases &&
			    work->cookie == last_returned &&
			    (work->cookie ? work->cleanup_done == 3 :
					    !work->cleanup_done);
		bpf_spin_unlock(&work->lock);
		if (clean && !se_pw_owner_proof(task, work, 1))
			return se_pw_fault_visit(route, ch, cookie, scope,
						 incarnation);
		if (clean)
			return SE_PW_FREE;
		bpf_spin_lock(&route->lock);
		int still_free = ch->state == SE_PW_CH_FREE &&
				 !ch->current_cookie &&
				 !(bits->words[word] & mask);
		bpf_spin_unlock(&route->lock);
		return still_free ? se_pw_fault_visit(route, ch, cookie, scope,
						      incarnation) :
				    SE_PW_PENDING;
	}
	if (!account_valid || !bit || !cookie || !scope || !incarnation ||
	    charge_phase == SE_PW_CH_FAULT_HELD ||
	    charge_phase > SE_PW_CH_FAULT_HELD)
		return se_pw_fault_visit(route, ch, cookie, scope, incarnation);
	if (cookie <= last_returned)
		return se_pw_fault_visit(route, ch, cookie, scope, incarnation);
	if (charge_phase == SE_PW_CH_BUILDING)
		return SE_PW_PENDING;
	bpf_spin_lock(&work->lock);
	__u32 phase = work->phase;
	int exact = work->cookie == cookie && work->account_scope == scope &&
		    work->account_slot == account &&
		    work->account_incarnation == incarnation &&
		    work->owner_task_cookie && work->owner_task_address &&
		    work->invocation_sequence &&
		    work->invocation_sequence <= SE_PW_U64_LIMIT &&
		    work->owner_task_slot < SE_POOL_T &&
		    !(work->cleanup_done & ~3u);
	if (phase == SE_PW_REFUND_PENDING || phase == SE_PW_FREE_PHASE)
		exact = exact && work->cleanup_done == 3 &&
			!work->active_leases;
	bpf_spin_unlock(&work->lock);
	if (!exact || (phase == SE_PW_FREE_PHASE &&
		       charge_phase != SE_PW_CH_RETURN_READY))
		return se_pw_fault_visit(route, ch, cookie, scope, incarnation);
	if (charge_phase == SE_PW_CH_RETURN_READY &&
	    phase != SE_PW_REFUND_PENDING && phase != SE_PW_FREE_PHASE)
		return se_pw_fault_visit(route, ch, cookie, scope, incarnation);
	if (phase == SE_PW_DONE || phase == SE_PW_ABORTED ||
	    phase == SE_PW_CLEANING || phase == SE_PW_REFUND_PENDING ||
	    phase == SE_PW_FREE_PHASE) {
		int released = !!(work->cleanup_done & SE_PW_OWNER_RELEASED);
		if (!se_pw_owner_proof(task, work, released))
			return se_pw_fault_visit(route, ch, cookie, scope,
						 incarnation);
	}
	if (charge_phase == SE_PW_CH_OWNED &&
	    (phase == SE_PW_DONE || phase == SE_PW_ABORTED) &&
	    !work->active_leases) {
		bpf_spin_lock(&work->lock);
		work->phase = SE_PW_CLEANING;
		bpf_spin_unlock(&work->lock);
		phase = SE_PW_CLEANING;
	}
	if (phase == SE_PW_INITIALIZING || phase == SE_PW_ACTIVE ||
	    phase == SE_PW_DONE || phase == SE_PW_ABORTED)
		return SE_PW_PENDING;
	if (phase == SE_PW_CLEANING) {
		if (!(work->cleanup_done & SE_PW_OWNER_RELEASED)) {
			int released = se_pw_release_owner(task, work);
			if (released == SE_PW_FAULT)
				return se_pw_fault_visit(route, ch, cookie,
							 scope, incarnation);
			if (released != SE_PW_OK && released != SE_PW_ALREADY)
				return released;
		}
		if (!(work->cleanup_done & SE_PW_PAYLOAD_ZERO)) {
			if (SE_PW_ZERO_PAYLOAD(slot, zero))
				return SE_PW_PENDING;
			bpf_spin_lock(&work->lock);
			work->cleanup_done |= SE_PW_PAYLOAD_ZERO;
			bpf_spin_unlock(&work->lock);
		}
		bpf_spin_lock(&work->lock);
		if (work->cleanup_done != 3 || work->active_leases) {
			bpf_spin_unlock(&work->lock);
			return se_pw_fault_visit(route, ch, cookie, scope,
						 incarnation);
		}
		work->phase = SE_PW_REFUND_PENDING;
		bpf_spin_unlock(&work->lock);
		phase = SE_PW_REFUND_PENDING;
	}
	if (phase == SE_PW_REFUND_PENDING) {
		if (!se_pw_owner_proof(task, work, 1))
			return se_pw_fault_visit(route, ch, cookie, scope,
						 incarnation);
		bpf_spin_lock(&route->lock);
		int valid = route->scope == scope &&
			    route->incarnation == incarnation &&
			    route->payload_slot == account &&
			    route->scratch_used &&
			    (route->phase == SE_ROUTE_ACTIVE ||
			     route->phase == SE_ROUTE_WITHDRAWN) &&
			    (bits->words[word] & mask) &&
			    ch->current_cookie == cookie &&
			    ch->account_scope == scope &&
			    ch->account_incarnation == incarnation &&
			    cookie > ch->last_returned_cookie;
		if (valid && ch->state == SE_PW_CH_OWNED)
			ch->state = SE_PW_CH_RETURN_READY;
		else if (!valid || ch->state != SE_PW_CH_RETURN_READY)
			valid = 0;
		if (!valid) {
			if (ch->current_cookie == cookie &&
			    ch->account_scope == scope &&
			    ch->account_incarnation == incarnation &&
			    ch->state != SE_PW_CH_FREE)
				ch->state = SE_PW_CH_FAULT_HELD;
			route->reserved = 1;
		}
		bpf_spin_unlock(&route->lock);
		if (!valid)
			return SE_PW_FAULT;
		if (!se_pw_owner_proof(task, work, 1))
			return se_pw_fault_visit(route, ch, cookie, scope,
						 incarnation);
		bpf_spin_lock(&work->lock);
		if (work->phase != SE_PW_REFUND_PENDING ||
		    work->cookie != cookie || work->active_leases ||
		    work->cleanup_done != 3) {
			bpf_spin_unlock(&work->lock);
			return se_pw_fault_visit(route, ch, cookie, scope,
						 incarnation);
		}
		work->phase = SE_PW_FREE_PHASE;
		bpf_spin_unlock(&work->lock);
		phase = SE_PW_FREE_PHASE;
	}
	if (phase != SE_PW_FREE_PHASE)
		return se_pw_fault_visit(route, ch, cookie, scope, incarnation);
	if (!se_pw_owner_proof(task, work, 1))
		return se_pw_fault_visit(route, ch, cookie, scope, incarnation);
	/* This is the last slot access. Exact account and charge precede refund. */
	bpf_spin_lock(&route->lock);
	int valid =
		route->scope == scope && route->incarnation == incarnation &&
		route->payload_slot == account && route->scratch_used &&
		route->scratch_used <= SE_POOL_QW &&
		(route->phase == SE_ROUTE_ACTIVE ||
		 route->phase == SE_ROUTE_WITHDRAWN) &&
		(bits->words[word] & mask) &&
		ch->state == SE_PW_CH_RETURN_READY &&
		ch->current_cookie == cookie && ch->account_scope == scope &&
		ch->account_incarnation == incarnation &&
		cookie > ch->last_returned_cookie;
	if (valid) {
		bits->words[word] &= ~mask;
		route->scratch_used--;
		ch->last_returned_cookie = cookie;
		ch->current_cookie = 0;
		ch->account_scope = 0;
		ch->account_incarnation = 0;
		ch->state = SE_PW_CH_FREE;
	} else {
		if (ch->state != SE_PW_CH_FREE &&
		    ch->current_cookie == cookie &&
		    ch->account_scope == scope &&
		    ch->account_incarnation == incarnation)
			ch->state = SE_PW_CH_FAULT_HELD;
		route->reserved = 1;
	}
	bpf_spin_unlock(&route->lock);
	return valid ? SE_PW_RETURNED : SE_PW_FAULT;
}
#endif
