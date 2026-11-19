/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_EXEC_READER_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_EXEC_READER_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE) ||           \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE) || \
	!defined(SE_OC_ROUTE_LOOKUP)
#error "opaque exec reader requires the exact TASK and original route candidates"
#endif

/* Convert one original, lexical route claim into the persistent reader of an
 * exact live TASK. The claim pins the immutable snapshot until transfer; the
 * physical lease pins the TASK. Never nest metadata and route locks. This is
 * only a begin adapter: the source must still finish or abort the invocation
 * and release the reader under the original route lock. */
static __attribute__((always_inline)) inline int se_op_exec_reader_begin(
	struct se_ol_payload_handle *owner, struct se_route_claim *claim,
	struct se_binding_snapshots *binding, __u64 bprm, __u64 *invocation_out)
{
	if (!owner || !claim || !binding || !invocation_out ||
	    *invocation_out || !bprm || !claim->owned || claim->reserved ||
	    claim->record >= 2 || claim->slot >= SE_OC_ACCOUNTS ||
	    !claim->scope || !claim->generation || !claim->serial ||
	    owner->lease.held != 1 || !owner->lease.cookie ||
	    !owner->lease.meta || !owner->payload ||
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	    /* G019 gap 3: the claim's own record (ACTIVE or RETIRING). */
	    binding->scope != claim->scope)
		return SE_OL_CORRUPT;
	struct se_snapshot *snapshot =
		&binding->records[se_route_rec_index(claim->record)];
	if ((snapshot->phase != SE_SNAPSHOT_ACTIVE &&
	     snapshot->phase != SE_SNAPSHOT_RETIRING) ||
#else
	    binding->scope != claim->scope ||
	    binding->generation != claim->generation ||
	    binding->active_record != claim->record ||
	    binding->active_serial != claim->serial)
		return SE_OL_CORRUPT;
	struct se_snapshot *snapshot = &binding->records[claim->record];
	if (snapshot->phase != SE_SNAPSHOT_ACTIVE ||
#endif
	    snapshot->scope != claim->scope ||
	    snapshot->serial != claim->serial ||
	    snapshot->generation != claim->generation ||
	    snapshot->execution_class != claim->execution_class)
		return SE_OL_CORRUPT;
	struct se_task_state *task = 0;
	int result = se_op_task_semantic_begin(owner, &task);
	if (result != SE_OL_OK)
		return result;
	int reserved = se_exec_begin_snapshot_locked(task, owner->lease.cookie,
						     bprm, snapshot);
	__u64 invocation = reserved == 0 ? task->exec.sequence : 0;
	se_op_task_semantic_end(owner, &task);
	/* A repeated begin belongs to the original owner path, not a second
	 * transfer. In particular, never abort or quarantine its live transaction. */
	if (reserved != 0 || !invocation)
		return SE_OL_CORRUPT;

	struct se_route_anchor *route = SE_OC_ROUTE_LOOKUP(claim->slot);
	if (!route)
		goto abort;
	bpf_spin_lock(&route->lock);
	result = se_exec_reader_attach_locked(
		route, binding,
		&((struct se_pool_task_wire *)owner->payload)->semantic, claim,
		owner->lease.cookie, invocation);
	bpf_spin_unlock(&route->lock);
	if (result)
		goto abort;
	*invocation_out = invocation;
	return SE_OL_OK;

abort:
	/* The transaction must not be reused as a healthy reader after a failed
	 * handoff. The lexical claim remains with the caller for exact release. */
	task = 0;
	if (se_op_task_semantic_begin(owner, &task) == SE_OL_OK) {
		se_exec_owned_fault_locked(task, bprm);
		se_exec_abort_locked(task, owner->lease.cookie, bprm,
				     invocation);
		task->flags |= SE_TASK_QUARANTINED;
		se_op_task_semantic_end(owner, &task);
	}
	return SE_OL_CORRUPT;
}

/* Repeated bprm entry recovers only the original physical TASK invocation.
 * A copied current-cgroup tuple, invocation number, or map-stored token is
 * never sufficient. Absence of an owned transaction is STALE (new begin may
 * follow); a matching transaction without its original reader is CORRUPT. */
static __attribute__((always_inline)) inline int
se_op_exec_reader_recover(struct se_ol_payload_handle *owner,
			  struct se_binding_snapshots *binding, __u64 bprm,
			  __u64 *invocation_out)
{
	if (!owner || !binding || !bprm || !invocation_out || *invocation_out ||
	    owner->lease.held != 1 || !owner->lease.meta || !owner->payload)
		return SE_OL_CORRUPT;
	struct se_task_state *task = 0;
	int result = se_op_task_semantic_begin(owner, &task);
	if (result != SE_OL_OK)
		return result;
	int matching = task->exec.owned && task->exec.bprm == bprm;
	__u32 slot = task->scope_slot;
	__u64 scope = task->scope_cookie;
	__u64 generation = task->exec.generation;
	__u32 execution_class = task->exec.execution_class;
	__u64 invocation = task->exec.sequence;
	se_op_task_semantic_end(owner, &task);
	if (!matching)
		return SE_OL_STALE;
	if (slot >= SE_OC_ACCOUNTS || binding->scope != scope || !generation ||
	    !invocation)
		return SE_OL_CORRUPT;
	struct se_route_anchor *route = SE_OC_ROUTE_LOOKUP(slot);
	if (!route)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&route->lock);
	int valid = se_exec_reader_authority_locked(
		route, binding,
		&((struct se_pool_task_wire *)owner->payload)->semantic, slot,
		scope, generation, owner->lease.cookie, invocation,
		execution_class);
	bpf_spin_unlock(&route->lock);
	if (!valid)
		return SE_OL_CORRUPT;
	*invocation_out = invocation;
	return SE_OL_OK;
}

/* Emergency terminal when the source cannot certify a completed policy
 * evaluation. Mark the whole TASK history unusable rather than silently
 * carrying known roles across an unobserved successful exec. Audit remains
 * nonblocking; a strict source must already have denied the exec. This is
 * not the normal success path or a replacement for WORK completion. */
static __attribute__((always_inline)) inline int
se_op_exec_reader_abort_quarantined(struct se_ol_payload_handle *owner,
				    struct se_binding_snapshots *binding,
				    __u64 bprm, __u64 invocation)
{
	/* Authentication of the route may fail before recovery can return its
	 * invocation. Invalidate the exact live TASK history first, so an Audit
	 * exec cannot continue with trusted roles while its reader is retained.
	 * A mismatched caller must not quarantine a different invocation. */
	if (!owner || !binding || !bprm || !invocation ||
	    owner->lease.held != 1 || !owner->lease.cookie)
		return SE_OL_CORRUPT;
	struct se_task_state *task = 0;
	int status = se_op_task_semantic_begin(owner, &task);
	if (status != SE_OL_OK)
		return status;
	int exact = task->physical_cookie == owner->lease.cookie &&
		    task->exec.owned && task->exec.bprm == bprm &&
		    task->exec.sequence == invocation && task->reader.owned &&
		    task->reader_invocation == invocation;
	if (exact) {
		se_exec_owned_fault_locked(task, bprm);
		if (!(task->flags & SE_TASK_QUARANTINED)) {
			task->flags |= SE_TASK_QUARANTINED;
			if (task->eligibility_version < ~0ULL - 1)
				task->eligibility_version++;
		}
	}
	se_op_task_semantic_end(owner, &task);
	if (!exact)
		return SE_OL_CORRUPT;
	__u64 recovered = 0;
	if (se_op_exec_reader_recover(owner, binding, bprm, &recovered) !=
		    SE_OL_OK ||
	    recovered != invocation)
		return SE_OL_CORRUPT;
	task = 0;
	status = se_op_task_semantic_begin(owner, &task);
	if (status != SE_OL_OK)
		return status;
	__u32 slot = task->scope_slot;
	se_exec_owned_fault_locked(task, bprm);
	int aborted = se_exec_abort_locked(task, owner->lease.cookie, bprm,
					   invocation);
	if (!aborted) {
		task->flags |= SE_TASK_QUARANTINED;
	}
	se_op_task_semantic_end(owner, &task);
	if (aborted || slot >= SE_OC_ACCOUNTS)
		return SE_OL_CORRUPT;
	struct se_route_anchor *route = SE_OC_ROUTE_LOOKUP(slot);
	if (!route)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&route->lock);
	int released = se_exec_reader_release_locked(
		binding,
		&((struct se_pool_task_wire *)owner->payload)->semantic,
		owner->lease.cookie, invocation);
	bpf_spin_unlock(&route->lock);
	return released ? SE_OL_CORRUPT : SE_OL_OK;
}

/* Allocation-independent last resort for an already-owned invocation when
 * its WORK completion cannot run. Successful exec conservatively turns only
 * causal accepted rows UNKNOWN; failed exec changes no role. This is not a
 * normal-path evaluator or a substitute for its exact WORK completion. */
static __attribute__((always_inline)) inline int
se_op_exec_reader_finish_bounded(struct se_ol_payload_handle *owner,
				 struct se_binding_snapshots *binding,
				 __u64 bprm, __u64 invocation, int success)
{
	if (!owner || !binding || !bprm || !invocation ||
	    owner->lease.held != 1 || !owner->lease.meta || !owner->payload)
		return SE_OL_CORRUPT;
	struct se_task_state *task = 0;
	int result = se_op_task_semantic_begin(owner, &task);
	if (result != SE_OL_OK)
		return result;
	__u32 slot = task->scope_slot;
	__u64 scope = task->scope_cookie;
	__u64 generation = task->exec.generation;
	__u32 execution_class = task->exec.execution_class;
	se_op_task_semantic_end(owner, &task);
	if (slot >= SE_OC_ACCOUNTS || binding->scope != scope) {
		(void)se_op_task_owned_fault(owner, bprm);
		return SE_OL_CORRUPT;
	}
	struct se_route_anchor *route = SE_OC_ROUTE_LOOKUP(slot);
	if (!route) {
		(void)se_op_task_owned_fault(owner, bprm);
		return SE_OL_CORRUPT;
	}
	bpf_spin_lock(&route->lock);
	int authority = se_exec_reader_authority_locked(
		route, binding,
		&((struct se_pool_task_wire *)owner->payload)->semantic, slot,
		scope, generation, owner->lease.cookie, invocation,
		execution_class);
	bpf_spin_unlock(&route->lock);
	if (!authority) {
		(void)se_op_task_owned_fault(owner, bprm);
		return SE_OL_CORRUPT;
	}
	result = se_op_task_semantic_begin(owner, &task);
	if (result != SE_OL_OK)
		return result;
	int finished = se_exec_finish_bounded_locked(task, owner->lease.cookie,
						     bprm, invocation, success);
	se_op_task_semantic_end(owner, &task);
	if (finished < 0) {
		(void)se_op_task_owned_fault(owner, bprm);
		return SE_OL_CORRUPT;
	}
	bpf_spin_lock(&route->lock);
	int released = se_exec_reader_release_locked(
		binding,
		&((struct se_pool_task_wire *)owner->payload)->semantic,
		owner->lease.cookie, invocation);
	bpf_spin_unlock(&route->lock);
	if (released) {
		(void)se_op_task_owned_fault(owner, bprm);
		return SE_OL_CORRUPT;
	}
	return SE_OL_OK;
}

/* A terminal producer can outlive the callback that first settled its TASK.
 * Reopening the exact charged TASK permits a retry after the TASK mutation or
 * reader release, but never permits a different invocation to adopt the old
 * terminal. The caller must separately authenticate the source-owned receipt
 * and keep a new begin out until that receipt has been removed. A successful
 * return says the original transaction and reader are both settled; only then
 * may the caller delete the terminal receipt. */
static __attribute__((always_inline)) inline int
se_op_exec_reader_settle_success(struct se_ol_payload_handle *owner,
				 struct se_binding_snapshots *binding,
				 __u64 bprm, __u64 invocation, __u64 scope,
				 __u64 generation)
{
	if (!owner || !binding || !bprm || !invocation || !scope ||
	    !generation || owner->lease.held != 1 || !owner->lease.cookie ||
	    !owner->lease.meta || !owner->payload)
		return SE_OL_CORRUPT;
	struct se_task_state *task = 0;
	int result = se_op_task_semantic_begin(owner, &task);
	if (result != SE_OL_OK)
		return result;
	__u32 slot = task->scope_slot;
	__u32 execution_class = task->exec.execution_class;
	int owned = task->exec.owned;
	int reader = task->reader.owned;
	int exact = task->physical_cookie == owner->lease.cookie &&
		    task->scope_cookie == scope && task->exec.bprm == bprm &&
		    task->exec.sequence == invocation &&
		    task->exec.generation == generation &&
		    binding->scope == scope &&
#ifndef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
		    /* (product: the reader authority checks its own record) */
		    binding->generation == generation &&
#endif
		    slot < SE_OC_ACCOUNTS &&
		    (reader ? task->reader_invocation == invocation :
			      !task->reader_invocation) &&
		    (!owned || reader);
	se_op_task_semantic_end(owner, &task);
	if (!exact)
		return SE_OL_CORRUPT;
	if (owned)
		return se_op_exec_reader_finish_bounded(owner, binding, bprm,
							invocation, 1);
	if (!reader)
		return SE_OL_OK;
	struct se_route_anchor *route = SE_OC_ROUTE_LOOKUP(slot);
	if (!route)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&route->lock);
	int authority = se_exec_reader_authority_locked(
		route, binding,
		&((struct se_pool_task_wire *)owner->payload)->semantic, slot,
		scope, generation, owner->lease.cookie, invocation,
		execution_class);
	int released =
		authority ?
			se_exec_reader_release_locked(
				binding,
				&((struct se_pool_task_wire *)owner->payload)
					 ->semantic,
				owner->lease.cookie, invocation) :
			-1;
	bpf_spin_unlock(&route->lock);
	return released ? SE_OL_CORRUPT : SE_OL_OK;
}

/* Plain diagnostic terminal wire. The receipt is evidence of an observed
 * terminal, not permission to clean up a TASK. Physical death's EXEC_DONE bit
 * is granted only by the actual task_free source after the exact reader is
 * settled. Keep this predicate pure so host regressions exercise the same
 * decision as the verifier-visible reaper branch. */
#define SE_EXEC_TERMINAL_REGISTERED 1U
#define SE_EXEC_TERMINAL_SUCCESS 2U
#define SE_EXEC_TERMINAL_FAILURE 3U
struct se_exec_terminal_receipt {
	__u64 physical, bprm, cookie, locator, invocation, scope, generation;
	__u32 phase, reserved;
};
_Static_assert(sizeof(struct se_exec_terminal_receipt) == 64,
	       "plain exec terminal receipt wire");

/* Classification is not an ownership transfer or a verdict. The source must
 * open owner with its original current-task key and retain that lease plus
 * exclusive source lifecycle access through the selected operation. Binding
 * must be the original fixed-slot binding, not a copied snapshot. In
 * particular, physical/receipt bytes supplied by an untrusted caller cannot
 * establish source identity. No lock is nested and no state is changed here.
 * A terminal is always settled before a new begin, even if its bprm address
 * happens to equal the next attempt's address. */
enum se_exec_reader_class {
	SE_EXEC_READER_RETAIN = 0,
	SE_EXEC_READER_NEW,
	SE_EXEC_READER_CONTINUE,
	SE_EXEC_READER_TERMINAL,
};
/* suspended_work (G019 gap 4, review H1) relaxes exactly one premise and
 * only for CONTINUE: the TASK may own a current WORK. NEW and TERMINAL are
 * never returned in that mode. The caller (the interpreter continuation)
 * must then prove that current WORK is the receipt's own suspended terminal
 * WORK, by resuming it at a terminal-class stage and checking its proposed
 * history against the receipt, before relying on the classification. */
static __attribute__((always_inline)) inline int
se_op_exec_reader_classify_core(struct se_ol_payload_handle *owner,
				struct se_binding_snapshots *binding,
				const struct se_exec_terminal_receipt *receipt,
				__u64 physical, __u64 incoming_bprm,
				int suspended_work)
{
	if (!owner || !binding || !physical)
		return SE_EXEC_READER_RETAIN;
	struct se_task_state *task = 0;
	if (se_op_task_semantic_begin(owner, &task) != SE_OL_OK)
		return SE_EXEC_READER_RETAIN;
	__u32 slot = task->scope_slot;
	__u64 scope = task->scope_cookie;
	__u64 generation = task->exec.generation;
	__u64 invocation = task->exec.sequence;
	__u32 execution_class = task->exec.execution_class;
	int owned = task->exec.owned;
	int exact = slot < SE_OC_ACCOUNTS && scope &&
		    task->physical_cookie == owner->lease.cookie &&
		    (suspended_work || !owner->lease.meta->current_work_owned);
	int classification = SE_EXEC_READER_RETAIN;
	if (exact && !suspended_work && !receipt && incoming_bprm && !owned)
		classification = SE_EXEC_READER_NEW;
	if (exact && receipt && receipt->physical == physical &&
	    receipt->cookie == owner->lease.cookie &&
	    receipt->locator == owner->lease.locator && receipt->bprm &&
	    receipt->bprm == task->exec.bprm && receipt->invocation &&
	    receipt->invocation == invocation && receipt->scope == scope &&
	    receipt->generation && receipt->generation == generation &&
	    !receipt->reserved) {
		if (receipt->phase == SE_EXEC_TERMINAL_REGISTERED && owned &&
		    receipt->bprm == incoming_bprm)
			classification = SE_EXEC_READER_CONTINUE;
		else if (!suspended_work &&
			 (receipt->phase == SE_EXEC_TERMINAL_SUCCESS ||
			  receipt->phase == SE_EXEC_TERMINAL_FAILURE))
			classification = SE_EXEC_READER_TERMINAL;
	}
	se_op_task_semantic_end(owner, &task);
	if (classification == SE_EXEC_READER_RETAIN)
		return classification;
	struct se_route_anchor *route = SE_OC_ROUTE_LOOKUP(slot);
	if (!route || binding->scope != scope)
		return SE_EXEC_READER_RETAIN;
	struct se_pool_task_wire *payload = owner->payload;
	bpf_spin_lock(&route->lock);
	int reader = payload->semantic.reader.owned;
	int valid = route->incarnation ==
		    owner->lease.meta->account_incarnation;
	if (classification == SE_EXEC_READER_NEW || !reader) {
		valid = valid && !owned && !reader &&
			!payload->semantic.reader_invocation &&
			classification != SE_EXEC_READER_CONTINUE;
	} else {
		valid = valid &&
			se_exec_reader_authority_locked(
				route, binding, &payload->semantic, slot, scope,
				generation, owner->lease.cookie, invocation,
				execution_class);
	}
	bpf_spin_unlock(&route->lock);
	return valid ? classification : SE_EXEC_READER_RETAIN;
}
static __attribute__((always_inline)) inline int
se_op_exec_reader_classify(struct se_ol_payload_handle *owner,
			   struct se_binding_snapshots *binding,
			   const struct se_exec_terminal_receipt *receipt,
			   __u64 physical, __u64 incoming_bprm)
{
	return se_op_exec_reader_classify_core(owner, binding, receipt,
					       physical, incoming_bprm, 0);
}
/* CONTINUE or RETAIN only; see suspended_work above. */
static __attribute__((always_inline)) inline int
se_op_exec_reader_classify_continue(
	struct se_ol_payload_handle *owner,
	struct se_binding_snapshots *binding,
	const struct se_exec_terminal_receipt *receipt, __u64 physical,
	__u64 incoming_bprm)
{
	return se_op_exec_reader_classify_core(owner, binding, receipt,
					       physical, incoming_bprm, 1);
}

static __attribute__((always_inline)) inline int
se_exec_terminal_dead_retirable(const struct se_ol_meta *meta,
				const struct se_task_state *task,
				const struct se_exec_terminal_receipt *receipt,
				__u64 physical, __u64 cookie, __u64 locator,
				__u32 account_slot)
{
	return meta && task && receipt && physical && cookie && locator &&
	       account_slot < SE_OC_ACCOUNTS && receipt->physical == physical &&
	       receipt->cookie == cookie && receipt->locator == locator &&
	       receipt->bprm && receipt->invocation && receipt->scope &&
	       receipt->generation && !receipt->reserved &&
	       (receipt->phase == SE_EXEC_TERMINAL_REGISTERED ||
		receipt->phase == SE_EXEC_TERMINAL_SUCCESS ||
		receipt->phase == SE_EXEC_TERMINAL_FAILURE) &&
	       meta->phase == SE_OL_DEAD && meta->locator == locator &&
	       meta->cookie == cookie && !meta->active_leases &&
	       meta->directory_state == SE_OL_PUBLISHED &&
	       meta->archive_ready == 1 &&
	       meta->account_scope == receipt->scope &&
	       meta->account_slot == account_slot && !meta->cleanup_error &&
	       (meta->cleanup_done & SE_OL_EXEC_DONE) &&
	       (task->flags & SE_TASK_LIVE) &&
	       task->physical_cookie == cookie &&
	       task->scope_cookie == receipt->scope &&
	       task->scope_slot == account_slot &&
	       task->exec.bprm == receipt->bprm &&
	       task->exec.sequence == receipt->invocation &&
	       task->exec.generation == receipt->generation &&
	       !task->exec.owned;
}

#endif
