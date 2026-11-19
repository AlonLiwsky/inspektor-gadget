/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque WORK is candidate-only"
#endif
#if !defined(SE_OWK_ACCOUNTS) || !defined(SE_OWK_QUOTA) ||                    \
	!defined(SE_OWK_WORKS) || !defined(SE_OWK_ACCOUNT_LOOKUP) ||          \
	!defined(SE_OWK_CHARGE_LOOKUP) || !defined(SE_OWK_SEQUENCE_LOOKUP) || \
	!defined(SE_OWK_META_LOOKUP) || !defined(SE_OWK_PAYLOAD_LOOKUP) ||    \
	!defined(SE_OWK_PAYLOAD_ZERO)
#error "provide fixed WORK geometry and ARRAY lookups"
#endif
#ifndef SE_OC_ROUTE_LOOKUP
#error "include original-route adapter before opaque WORK"
#endif

#include "shared_pool_opaque_task_open_candidate.h"

/* WORK has one independent credit. No route scratch counter, address token,
 * or copied cgroup tuple is WORK ownership. A BUILDING charge is not ready
 * for execution; its eventual attach/cleanup must be source-owned. */
_Static_assert(SE_OWK_ACCOUNTS == SE_OC_ACCOUNTS && SE_OWK_QUOTA > 0 &&
		       SE_OWK_QUOTA <= 64 &&
		       (__u64)SE_OWK_ACCOUNTS * SE_OWK_QUOTA == SE_OWK_WORKS,
	       "opaque WORK partition");
#define SE_OWK_COOKIE_LIMIT (~(__u64)0 - 1ULL)
#ifndef SE_OWK_AFTER_PIN
#define SE_OWK_AFTER_PIN() ((void)0)
#endif
/* Diagnostic hooks of one accepted WORK charge (test builds only; a product
 * build leaves all three empty): SE_OWK_CHARGED_DECL declares the caller's
 * scalar, SE_OWK_CHARGED_LOCKED(used) copies the account's used count inside
 * the account lock right after the charge, SE_OWK_CHARGED(slot) runs after
 * the unlock. */
/* Charge-time payload zero. The synchronous WORK return (G019 option C)
 * zeroes once, at return (reaper stage 3, which every path to META_FREE
 * passes), and defines this to 0; the header-is-zero check after it stays
 * as the verifier of that invariant. */
#ifndef SE_OWK_INIT_PAYLOAD_ZERO
#define SE_OWK_INIT_PAYLOAD_ZERO(slot) SE_OWK_PAYLOAD_ZERO(slot)
#endif
#ifndef SE_OWK_CHARGED
#define SE_OWK_CHARGED_DECL
#define SE_OWK_CHARGED_LOCKED(used) ((void)0)
#define SE_OWK_CHARGED(slot) ((void)0)
#endif
enum se_owk_charge_state {
	SE_OWK_FREE = 0,
	SE_OWK_BUILDING,
	SE_OWK_OWNED,
	SE_OWK_RETURN_READY,
	SE_OWK_FAULT_HELD,
};
struct se_owk_account {
	struct bpf_spin_lock lock;
	__u32 used, fault, incarnation, reserved;
	__u64 scope, bits;
};
struct se_owk_charge {
	__u64 cookie, last_returned, scope;
	__u64 owner_locator, owner_cookie;
	__u32 incarnation, state, owner_slot, reserved;
};
struct se_owk_sequence {
	struct bpf_spin_lock lock;
	__u32 reserved;
	__u64 next_cookie;
};
enum se_owk_phase {
	SE_OWK_META_FREE = 0,
	SE_OWK_INITIALIZING,
	SE_OWK_OWNER_ATTACHED,
	SE_OWK_ACTIVE,
	SE_OWK_DONE,
	SE_OWK_ABORTED,
	SE_OWK_CLEANING,
	SE_OWK_REFUND_PENDING,
	SE_OWK_SUSPENDED,
	SE_OWK_DEATH_FINALIZING,
};
struct se_owk_meta {
	struct bpf_spin_lock lock;
	__u32 phase;
	__u64 cookie, owner_locator, owner_cookie, scope, invocation_sequence;
	__u32 owner_slot, account_slot, incarnation;
	__u32 active_leases, owner_ref_held, cleanup_done;
	/* The previously unused zero tail now records a source-owned evaluator
     * continuation. It is zero again before DONE/reaper publication. */
	__u32 continuation_stage, continuation_reserved;
};
_Static_assert(sizeof(struct se_owk_meta) == 80,
	       "opaque WORK metadata geometry");
/* The selected invocation semantic starts with these 32 bytes. WORK has no
 * added prefix: its full 19,456-byte wire retains the selected field offsets. */
#include "shared_pool_opaque_work_wire.h"
/* Callback-local, non-transferable ticket: the caller must keep the TASK
 * payload handle open until it either attaches WORK or faults the charge. */
struct se_owk_ticket {
	__u64 cookie, scope, owner_locator, owner_cookie;
	__u32 account_slot, incarnation, work_slot, owner_slot;
	__u64 invocation_sequence;
	/* Callback-local small states; no map or wire layout depends on this
     * ticket. Keep the lexical handle within one 64-byte BPF stack quantum. */
	__u16 held, stage; /* 0=BUILDING, 1=attached, 2=initialized, 3=ACTIVE */
	__u16 continuation_stage, reserved;
};
_Static_assert(sizeof(struct se_owk_ticket) == 64,
	       "callback-local WORK ticket must fit one stack quantum");
#ifdef ENFORCE_EXEC_POOL_OPAQUE_FAULT_INLINE_DIAGNOSTIC
#define SE_OWK_FAULT_ATTR __attribute__((always_inline)) inline
#else
#define SE_OWK_FAULT_ATTR __attribute__((noinline))
#endif
static SE_OWK_FAULT_ATTR void
se_owk_fault_ticket(const struct se_owk_ticket *ticket);

/* Test-only WORK account fault-site witness (the including object's
 * ENFORCE_EXEC_POOL_OPAQUE_WORK_FAULT_SITE_DIAGNOSTIC): each site that sets
 * account->fault ORs its own bit (1U << site) into the fault word while it
 * holds the account lock.
 * Empty by default: no code. */
#ifndef SE_OWK_FAULT_SITE
#define SE_OWK_FAULT_SITE(site) \
	do {                    \
	} while (0)
#endif
/* A site reached only while the account was not yet faulted (its own
 * branch requires a clean account): the witness may store the word. */
#ifndef SE_OWK_FAULT_SITE_CLEAN
#define SE_OWK_FAULT_SITE_CLEAN(site) SE_OWK_FAULT_SITE(site)
#endif
static inline __u64 se_owk_valid_mask(void)
{
#if SE_OWK_QUOTA == 64
	return ~0ULL;
#else
	return (1ULL << SE_OWK_QUOTA) - 1ULL;
#endif
}
static inline __u32 se_owk_count(__u64 bits)
{
	bits -= (bits >> 1) & 0x5555555555555555ULL;
	bits = (bits & 0x3333333333333333ULL) +
	       ((bits >> 2) & 0x3333333333333333ULL);
	bits = (bits + (bits >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
	return (__u32)((bits * 0x0101010101010101ULL) >> 56);
}

/* Read owner identity only inside the lexical TASK bracket. The held exact
 * locator lease prevents physical reuse after this check, but TASK death may
 * race the WORK charge. A later attach must recheck LIVE and retain/fault the
 * charge on failure; it may not silently refund a BUILDING charge. */
static __attribute__((noinline)) int
se_owk_owner_snapshot(struct se_ol_payload_handle *owner, __u64 *scope,
		      __u32 *account_slot, __u32 *incarnation)
{
	if (!owner || !scope || !account_slot || !incarnation ||
	    owner->locked || owner->lease.held != 1 || !owner->lease.meta ||
	    !owner->payload || !owner->lease.cookie || !owner->lease.locator)
		return SE_OL_CORRUPT;
	void *payload = 0;
	int result = se_ol_payload_begin(owner, &payload);
	if (result != SE_OL_OK)
		return result;
	struct se_ol_meta *meta = owner->lease.meta;
	*scope = meta->account_scope;
	*account_slot = meta->account_slot;
	*incarnation = meta->account_incarnation;
	int busy = meta->current_work_owned || meta->current_work_cookie ||
		   meta->current_work_slot;
	int exhausted = meta->work_refs == SE_OL_U32_MAX ||
			meta->next_work_sequence >= SE_OWK_COOKIE_LIMIT;
	/* begin succeeded and this function has not modified either handle
     * identity field. Release unconditionally: a conditional end path is
     * verifier-visible as a possible return with the spinlock still held. */
	payload = 0;
	owner->locked = 0;
	bpf_spin_unlock(&meta->lock);
	if (busy)
		return SE_OL_CONTENDED;
	if (exhausted)
		return SE_OL_LIMIT;
	if (!*scope || !*incarnation || *account_slot >= SE_OC_ACCOUNTS ||
	    owner->lease.slot >= SE_OL_TASKS ||
	    owner->lease.slot / SE_OC_QUOTA != *account_slot)
		return SE_OL_CORRUPT;
	__u32 local = owner->lease.slot - *account_slot * SE_OC_QUOTA;
	if (local >= SE_OC_QUOTA)
		return SE_OL_CORRUPT;
	struct se_oc_account *task_account =
		SE_OC_ACCOUNT_LOOKUP(*account_slot);
	struct se_oc_charge *task_charge =
		SE_OC_CHARGE_LOOKUP(owner->lease.slot);
	if (!task_account || !task_charge)
		return SE_OL_CORRUPT;
	__u64 bit = 1ULL << (local % 64U);
	bpf_spin_lock(&task_account->lock);
	/* Both branches test the same condition; only the evaluation order
     * differs, chosen per word count to bound the verifier stack. */
#if SE_OC_WORDS > 1
	int charged = se_oc_bitmap_count(task_account) == task_account->used &&
		      !task_account->fault && !task_account->reserved &&
		      task_account->scope == *scope &&
		      task_account->incarnation == *incarnation &&
		      task_account->used && task_account->used <= SE_OC_QUOTA &&
		      (task_account->bits[SE_OC_WORD(local)] & bit) &&
#else
	int charged = !task_account->fault && !task_account->reserved &&
		      task_account->scope == *scope &&
		      task_account->incarnation == *incarnation &&
		      task_account->used && task_account->used <= SE_OC_QUOTA &&
		      se_oc_bitmap_count(task_account) == task_account->used &&
		      (task_account->bits[SE_OC_WORD(local)] & bit) &&
#endif
		      task_charge->state == SE_OC_OWNED &&
		      task_charge->cookie == owner->lease.cookie &&
		      task_charge->scope == *scope &&
		      task_charge->incarnation == *incarnation &&
		      task_charge->locator == owner->lease.locator;
	bpf_spin_unlock(&task_account->lock);
	return charged ? SE_OL_OK : SE_OL_CORRUPT;
}

/* The account may follow a new incarnation only when no old WORK credit is
 * present. The caller supplies a currently held TASK owner, not a scalar
 * route tuple. No map helper or nested lock occurs inside the account lock. */
static __attribute__((noinline)) int
se_owk_bind_owner(struct se_ol_payload_handle *owner)
{
	__u64 scope = 0;
	__u32 slot = 0, incarnation = 0;
	int result = se_owk_owner_snapshot(owner, &scope, &slot, &incarnation);
	if (result != SE_OL_OK)
		return result;
	if (!scope || !incarnation || slot >= SE_OWK_ACCOUNTS)
		return SE_OL_CORRUPT;
	struct se_owk_account *account = SE_OWK_ACCOUNT_LOOKUP(slot);
	if (!account)
		return SE_OL_CORRUPT;
	bpf_spin_lock(&account->lock);
	if (account->fault || account->reserved ||
	    (account->bits & ~se_owk_valid_mask()) ||
	    se_owk_count(account->bits) != account->used ||
	    account->used > SE_OWK_QUOTA ||
	    (!!account->scope != !!account->incarnation)) {
		account->fault = 1;
		SE_OWK_FAULT_SITE(1);
		result = SE_OL_CORRUPT;
	} else if (account->scope == scope &&
		   account->incarnation == incarnation) {
		result = SE_OL_OK;
	} else if (account->used) {
		result = SE_OL_CONTENDED;
	} else {
		account->scope = scope;
		account->incarnation = incarnation;
	}
	bpf_spin_unlock(&account->lock);
	return result;
}

/* Selection is only an observation. begin rechecks the exact bit/charge
 * under the account lock; a lost race returns CONTENDED for bounded retry. */
static __attribute__((noinline)) int
se_owk_choose(struct se_ol_payload_handle *owner, __u32 *work_slot)
{
	if (!work_slot || *work_slot)
		return SE_OL_CORRUPT;
	__u64 scope = 0;
	__u32 slot = 0, incarnation = 0;
	int result = se_owk_owner_snapshot(owner, &scope, &slot, &incarnation);
	if (result != SE_OL_OK)
		return result;
	if (slot >= SE_OWK_ACCOUNTS || !scope || !incarnation)
		return SE_OL_CORRUPT;
	struct se_owk_account *account = SE_OWK_ACCOUNT_LOOKUP(slot);
	if (!account)
		return SE_OL_CORRUPT;
	__u32 chosen = SE_OWK_QUOTA;
	bpf_spin_lock(&account->lock);
	if (account->fault || account->reserved ||
	    (account->bits & ~se_owk_valid_mask()) ||
	    se_owk_count(account->bits) != account->used ||
	    account->used > SE_OWK_QUOTA) {
		account->fault = 1;
		SE_OWK_FAULT_SITE(2);
		result = SE_OL_CORRUPT;
	} else if (account->scope != scope ||
		   account->incarnation != incarnation) {
		result = SE_OL_STALE;
	} else if (account->used == SE_OWK_QUOTA) {
		result = SE_OL_LIMIT;
	} else {
		chosen = se_oc_first_bit(~account->bits & se_owk_valid_mask());
		if (chosen >= SE_OWK_QUOTA) {
			account->fault = 1;
			SE_OWK_FAULT_SITE(3);
			result = SE_OL_CORRUPT;
		}
	}
	bpf_spin_unlock(&account->lock);
	if (result != SE_OL_OK)
		return result;
	*work_slot = slot * SE_OWK_QUOTA + chosen;
	return *work_slot < SE_OWK_WORKS ? SE_OL_OK : SE_OL_CORRUPT;
}

/* Roll back only this callback's precharge TASK pin. A death racing between
 * pin and rollback gets its source WORK_DONE receipt at the last ref. An
 * impossible token contradiction retains the ref and faults the TASK; it
 * must never release another WORK owner. */
static __attribute__((always_inline)) inline int
se_owk_rollback_pin(struct se_ol_payload_handle *owner, __u64 cookie,
		    __u32 work_slot, __u64 scope, __u32 account_slot,
		    __u32 incarnation)
{
	if (!owner || owner->lease.held != 1 || !owner->lease.meta)
		return SE_OL_CORRUPT;
	struct se_ol_meta *task = owner->lease.meta;
	bpf_spin_lock(&task->lock);
	int exact = task->locator == owner->lease.locator &&
		    task->cookie == owner->lease.cookie &&
		    task->account_scope == scope &&
		    task->account_slot == account_slot &&
		    task->account_incarnation == incarnation &&
		    task->active_leases && task->work_refs &&
		    task->current_work_owned == 1 &&
		    task->current_work_cookie == cookie &&
		    task->current_work_slot == work_slot;
	if (exact) {
		task->current_work_owned = 0;
		task->current_work_cookie = 0;
		task->current_work_slot = 0;
		task->work_refs--;
		if (task->phase == SE_OL_DEAD && !task->work_refs)
			task->cleanup_done |= SE_OL_WORK_DONE;
	} else {
		task->cleanup_error = 1;
	}
	bpf_spin_unlock(&task->lock);
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}

/* Claim a persistent TASK owner ref/current token BEFORE the sole WORK
 * account credit. Precharge failures roll that exact pin back; postcharge
 * failures retain both the pin and charge for abort/reaper or quarantine.
 * A successful return is initialized BUILDING only, not executable WORK. */
static __attribute__((noinline)) int
se_owk_begin(struct se_ol_payload_handle *owner, __u32 work_slot,
	     struct se_owk_ticket *ticket)
{
	if (!ticket || ticket->held || ticket->cookie || ticket->stage)
		return SE_OL_CORRUPT;
	__u64 scope = 0;
	__u32 slot = 0, incarnation = 0;
	int result = se_owk_owner_snapshot(owner, &scope, &slot, &incarnation);
	if (result != SE_OL_OK)
		return result;
	if (slot >= SE_OWK_ACCOUNTS || !scope || !incarnation ||
	    work_slot >= SE_OWK_WORKS || work_slot / SE_OWK_QUOTA != slot)
		return SE_OL_CORRUPT;
	__u32 local = work_slot - slot * SE_OWK_QUOTA;
	if (local >= SE_OWK_QUOTA)
		return SE_OL_CORRUPT;
	struct se_owk_account *account = SE_OWK_ACCOUNT_LOOKUP(slot);
	struct se_owk_charge *charge = SE_OWK_CHARGE_LOOKUP(work_slot);
	struct se_owk_sequence *sequence = SE_OWK_SEQUENCE_LOOKUP();
	struct se_owk_meta *work = SE_OWK_META_LOOKUP(work_slot);
	if (!account || !charge || !sequence || !work)
		return SE_OL_CORRUPT;
	__u64 cookie = 0;
	bpf_spin_lock(&sequence->lock);
	if (sequence->reserved)
		result = SE_OL_CORRUPT;
	else if (sequence->next_cookie >= SE_OWK_COOKIE_LIMIT)
		result = SE_OL_LIMIT;
	else
		cookie = ++sequence->next_cookie;
	bpf_spin_unlock(&sequence->lock);
	if (result != SE_OL_OK)
		return result;
	struct se_ol_meta *task = owner->lease.meta;
	__u64 invocation_sequence = 0;
	bpf_spin_lock(&task->lock);
	int owner_live =
		task->phase == SE_OL_LIVE &&
		task->directory_state == SE_OL_PUBLISHED &&
		task->archive_ready == 1 && !task->reserved &&
		!task->exclusive && !task->exclusive_owner &&
		task->locator == owner->lease.locator &&
		task->cookie == owner->lease.cookie && task->active_leases &&
		task->account_scope == scope && task->account_slot == slot &&
		task->account_incarnation == incarnation &&
		!task->current_work_owned && !task->current_work_cookie &&
		!task->current_work_slot && task->work_refs < SE_OL_U32_MAX &&
		task->next_work_sequence < SE_OWK_COOKIE_LIMIT;
	if (owner_live) {
		task->work_refs++;
		task->current_work_owned = 1;
		task->current_work_cookie = cookie;
		task->current_work_slot = work_slot;
		invocation_sequence = ++task->next_work_sequence;
	}
	bpf_spin_unlock(&task->lock);
	if (!owner_live)
		return SE_OL_STALE;
	SE_OWK_AFTER_PIN();
	__u64 bit = 1ULL << local;
	SE_OWK_CHARGED_DECL;
	bpf_spin_lock(&account->lock);
	if (account->fault || account->reserved ||
	    (account->bits & ~se_owk_valid_mask()) ||
	    se_owk_count(account->bits) != account->used ||
	    account->used > SE_OWK_QUOTA) {
		account->fault = 1;
		result = SE_OL_CORRUPT;
		SE_OWK_FAULT_SITE(4);
	} else if (account->scope != scope ||
		   account->incarnation != incarnation) {
		result = SE_OL_STALE;
	} else if (account->bits & bit) {
		result = SE_OL_CONTENDED;
	} else if (account->used == SE_OWK_QUOTA) {
		result = SE_OL_LIMIT;
	} else if (charge->state == SE_OWK_FREE && !charge->cookie &&
		   !charge->scope && !charge->owner_locator &&
		   !charge->owner_cookie && !charge->incarnation &&
		   !charge->owner_slot && !charge->reserved &&
		   charge->last_returned > cookie &&
		   charge->last_returned < SE_OWK_COOKIE_LIMIT) {
		/* Reuse-aware reserve (any returner: the synchronous WORK
		 * return or the reaper): between this caller's slot choice and
		 * cookie allocation and this reserve, another WORK with a newer
		 * cookie was charged, settled and returned at this very slot.
		 * The slot is free and intact; only this cookie is older than
		 * its last return. Not a fault: retry with a fresh cookie
		 * (per-slot cookies stay increasing, as every reaper identity
		 * check requires). Without this, a delayed caller faulted the
		 * whole account (chain10 with sync return; chain15 with the
		 * reaper, burst-nosync-s6). Strictly newer and in range only:
		 * cookies are unique, so a return equal to this cookie, or one
		 * beyond the cookie limit, is corruption and faults below. */
		result = SE_OL_CONTENDED;
	} else if (charge->state != SE_OWK_FREE || charge->cookie ||
		   charge->scope || charge->owner_locator ||
		   charge->owner_cookie || charge->incarnation ||
		   charge->owner_slot || charge->reserved ||
		   charge->last_returned >= cookie) {
		account->fault = 1;
		result = SE_OL_CORRUPT;
		SE_OWK_FAULT_SITE_CLEAN(5);
	} else {
		account->bits |= bit;
		account->used++;
		SE_OWK_CHARGED_LOCKED(account->used);
		charge->cookie = cookie;
		charge->scope = scope;
		charge->incarnation = incarnation;
		charge->owner_locator = owner->lease.locator;
		charge->owner_cookie = owner->lease.cookie;
		charge->owner_slot = owner->lease.slot;
		charge->state = SE_OWK_BUILDING;
		*ticket = (struct se_owk_ticket){
			.cookie = cookie,
			.scope = scope,
			.owner_locator = owner->lease.locator,
			.owner_cookie = owner->lease.cookie,
			.account_slot = slot,
			.incarnation = incarnation,
			.work_slot = work_slot,
			.owner_slot = owner->lease.slot,
			.invocation_sequence = invocation_sequence,
			.held = 1,
		};
	}
	bpf_spin_unlock(&account->lock);
	if (result != SE_OL_OK) {
		if (se_owk_rollback_pin(owner, cookie, work_slot, scope, slot,
					incarnation) != SE_OL_OK)
			return SE_OL_CORRUPT;
		return result;
	}
	SE_OWK_CHARGED(slot);
	bpf_spin_lock(&work->lock);
	int empty =
		work->phase == SE_OWK_META_FREE && !work->active_leases &&
		!work->owner_ref_held && !work->owner_locator &&
		!work->owner_cookie && !work->scope &&
		!work->invocation_sequence && !work->owner_slot &&
		!work->account_slot && !work->incarnation &&
		!work->continuation_stage && !work->continuation_reserved &&
		work->cookie == charge->last_returned &&
		(work->cookie ? work->cleanup_done == 3 : !work->cleanup_done);
	if (empty) {
		work->phase = SE_OWK_INITIALIZING;
		work->cookie = cookie;
		work->owner_locator = owner->lease.locator;
		work->owner_cookie = owner->lease.cookie;
		work->scope = scope;
		work->owner_slot = owner->lease.slot;
		work->account_slot = slot;
		work->incarnation = incarnation;
		work->invocation_sequence = invocation_sequence;
		work->active_leases = 1;
		work->owner_ref_held = 1;
		work->cleanup_done = 0;
	}
	bpf_spin_unlock(&work->lock);
	if (!empty) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	return SE_OL_OK;
}

static inline int se_owk_ticket_exact(const struct se_owk_ticket *ticket,
				      const struct se_ol_payload_handle *owner)
{
	return ticket && owner && ticket->held == 1 && ticket->stage == 0 &&
	       !ticket->continuation_stage && !ticket->reserved &&
	       ticket->cookie && ticket->cookie <= SE_OWK_COOKIE_LIMIT &&
	       ticket->invocation_sequence &&
	       ticket->invocation_sequence <= SE_OWK_COOKIE_LIMIT &&
	       ticket->scope && ticket->incarnation &&
	       ticket->account_slot < SE_OWK_ACCOUNTS &&
	       ticket->work_slot < SE_OWK_WORKS &&
	       ticket->work_slot / SE_OWK_QUOTA == ticket->account_slot &&
	       ticket->owner_slot < SE_OL_TASKS &&
	       ticket->owner_slot / SE_OC_QUOTA == ticket->account_slot &&
	       owner->lease.held == 1 && !owner->locked && owner->lease.meta &&
	       owner->payload && owner->lease.slot == ticket->owner_slot &&
	       owner->lease.locator == ticket->owner_locator &&
	       owner->lease.cookie == ticket->owner_cookie;
}

/* Preserve an exact failed post-charge transaction for source cleanup. A
 * contradicted account is quarantined; no branch clears a bitmap bit. */
static SE_OWK_FAULT_ATTR void
se_owk_fault_ticket(const struct se_owk_ticket *ticket)
{
	if (!ticket || !ticket->held ||
	    ticket->account_slot >= SE_OWK_ACCOUNTS ||
	    ticket->work_slot >= SE_OWK_WORKS)
		return;
	struct se_owk_account *account =
		SE_OWK_ACCOUNT_LOOKUP(ticket->account_slot);
	struct se_owk_charge *charge = SE_OWK_CHARGE_LOOKUP(ticket->work_slot);
	if (!account || !charge)
		return;
	bpf_spin_lock(&account->lock);
	if (charge->cookie == ticket->cookie &&
	    charge->scope == ticket->scope &&
	    charge->incarnation == ticket->incarnation &&
	    charge->owner_locator == ticket->owner_locator &&
	    charge->owner_cookie == ticket->owner_cookie &&
	    charge->owner_slot == ticket->owner_slot &&
	    (charge->state == SE_OWK_BUILDING || charge->state == SE_OWK_OWNED))
		charge->state = SE_OWK_FAULT_HELD;
	account->fault = 1;
	SE_OWK_FAULT_SITE(6);
	bpf_spin_unlock(&account->lock);
}
#undef SE_OWK_FAULT_ATTR

/* The exact held TASK handle is the only constructor authority. This checks
 * the already-pinned owner ref; the selected caller must initialize the
 * WORK semantic payload before promoting OWNER_ATTACHED to ACTIVE.
 * Every failed post-charge branch retains/faults the WORK credit. */
static __attribute__((noinline)) int
se_owk_attach_owner(struct se_ol_payload_handle *owner,
		    struct se_owk_ticket *ticket)
{
	if (!se_owk_ticket_exact(ticket, owner))
		return SE_OL_CORRUPT;
	struct se_owk_account *account =
		SE_OWK_ACCOUNT_LOOKUP(ticket->account_slot);
	struct se_owk_charge *charge = SE_OWK_CHARGE_LOOKUP(ticket->work_slot);
	struct se_owk_meta *work = SE_OWK_META_LOOKUP(ticket->work_slot);
	if (!account || !charge || !work) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	__u32 local = ticket->work_slot - ticket->account_slot * SE_OWK_QUOTA;
	if (local >= SE_OWK_QUOTA) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	struct se_ol_meta *task = owner->lease.meta;
	bpf_spin_lock(&task->lock);
	int owner_exact =
		task->locator == ticket->owner_locator &&
		task->cookie == ticket->owner_cookie && task->active_leases &&
		task->account_scope == ticket->scope &&
		task->account_slot == ticket->account_slot &&
		task->account_incarnation == ticket->incarnation &&
		task->work_refs && task->current_work_owned == 1 &&
		task->current_work_cookie == ticket->cookie &&
		task->current_work_slot == ticket->work_slot &&
		task->next_work_sequence >= ticket->invocation_sequence;
	int live = task->phase == SE_OL_LIVE &&
		   task->directory_state == SE_OL_PUBLISHED &&
		   task->archive_ready == 1 && !task->reserved &&
		   !task->exclusive && !task->exclusive_owner;
	bpf_spin_unlock(&task->lock);
	if (!owner_exact) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	if (!live)
		return SE_OL_STALE; /* caller must source-abort BUILDING */
	bpf_spin_lock(&work->lock);
	int exact = work->phase == SE_OWK_INITIALIZING &&
		    work->active_leases == 1 && work->owner_ref_held == 1 &&
		    work->cookie == ticket->cookie &&
		    work->owner_locator == ticket->owner_locator &&
		    work->owner_cookie == ticket->owner_cookie &&
		    work->owner_slot == ticket->owner_slot &&
		    work->scope == ticket->scope &&
		    work->account_slot == ticket->account_slot &&
		    work->incarnation == ticket->incarnation &&
		    work->invocation_sequence == ticket->invocation_sequence &&
		    !work->cleanup_done;
	bpf_spin_unlock(&work->lock);
	if (!exact) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	__u64 bit = 1ULL << local;
	bpf_spin_lock(&account->lock);
	exact = !account->fault && !account->reserved &&
		account->scope == ticket->scope &&
		account->incarnation == ticket->incarnation && account->used &&
		account->used <= SE_OWK_QUOTA &&
		se_owk_count(account->bits) == account->used &&
		(account->bits & bit) && charge->state == SE_OWK_BUILDING &&
		charge->cookie == ticket->cookie &&
		charge->last_returned < ticket->cookie &&
		charge->scope == ticket->scope &&
		charge->incarnation == ticket->incarnation &&
		charge->owner_locator == ticket->owner_locator &&
		charge->owner_cookie == ticket->owner_cookie &&
		charge->owner_slot == ticket->owner_slot && !charge->reserved;
	if (exact)
		charge->state = SE_OWK_OWNED;
	bpf_spin_unlock(&account->lock);
	if (!exact) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	bpf_spin_lock(&work->lock);
	exact = work->phase == SE_OWK_INITIALIZING &&
		work->active_leases == 1 && work->owner_ref_held == 1 &&
		work->cookie == ticket->cookie &&
		work->owner_locator == ticket->owner_locator &&
		work->owner_cookie == ticket->owner_cookie &&
		work->invocation_sequence == ticket->invocation_sequence;
	if (exact)
		work->phase = SE_OWK_OWNER_ATTACHED;
	bpf_spin_unlock(&work->lock);
	if (!exact) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	ticket->stage = 1;
	return SE_OL_OK;
}

/* Source callback abort for a charged, initialized BUILDING WORK whose TASK
 * died before attach or whose attach could not be completed. It clears only
 * this current token, leaves the persistent TASK ref and WORK account bit,
 * and promotes a healthy BUILDING charge to OWNED for the normal reaper.
 * A fault-held charge remains quarantined but its exact owner can be reaped. */
static __attribute__((noinline)) int
se_owk_abort_building(struct se_ol_payload_handle *owner,
		      struct se_owk_ticket *ticket)
{
	if (!se_owk_ticket_exact(ticket, owner))
		return SE_OL_CORRUPT;
	struct se_owk_meta *work = SE_OWK_META_LOOKUP(ticket->work_slot);
	struct se_owk_account *account =
		SE_OWK_ACCOUNT_LOOKUP(ticket->account_slot);
	struct se_owk_charge *charge = SE_OWK_CHARGE_LOOKUP(ticket->work_slot);
	if (!work || !account || !charge) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	bpf_spin_lock(&work->lock);
	int exact = work->phase == SE_OWK_INITIALIZING &&
		    work->active_leases == 1 && work->owner_ref_held == 1 &&
		    work->cookie == ticket->cookie &&
		    work->owner_locator == ticket->owner_locator &&
		    work->owner_cookie == ticket->owner_cookie &&
		    work->owner_slot == ticket->owner_slot &&
		    work->scope == ticket->scope &&
		    work->account_slot == ticket->account_slot &&
		    work->incarnation == ticket->incarnation &&
		    work->invocation_sequence == ticket->invocation_sequence;
	bpf_spin_unlock(&work->lock);
	if (!exact) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	struct se_ol_meta *task = owner->lease.meta;
	bpf_spin_lock(&task->lock);
	exact = task->locator == ticket->owner_locator &&
		task->cookie == ticket->owner_cookie && task->active_leases &&
		task->account_scope == ticket->scope &&
		task->account_slot == ticket->account_slot &&
		task->account_incarnation == ticket->incarnation &&
		task->work_refs && task->current_work_owned == 1 &&
		task->current_work_cookie == ticket->cookie &&
		task->current_work_slot == ticket->work_slot;
	if (exact) {
		task->current_work_owned = 0;
		task->current_work_cookie = 0;
		task->current_work_slot = 0;
	} else {
		task->cleanup_error = 1;
	}
	bpf_spin_unlock(&task->lock);
	if (!exact) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	bpf_spin_lock(&work->lock);
	exact = work->phase == SE_OWK_INITIALIZING &&
		work->active_leases == 1 && work->owner_ref_held == 1 &&
		work->cookie == ticket->cookie &&
		work->owner_locator == ticket->owner_locator &&
		work->owner_cookie == ticket->owner_cookie;
	if (exact) {
		work->phase = SE_OWK_ABORTED;
		work->active_leases = 0;
	}
	bpf_spin_unlock(&work->lock);
	if (!exact) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	__u32 local = ticket->work_slot - ticket->account_slot * SE_OWK_QUOTA;
	if (local >= SE_OWK_QUOTA) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	__u64 bit = 1ULL << local;
	bpf_spin_lock(&account->lock);
	int charge_exact = charge->cookie == ticket->cookie &&
			   charge->scope == ticket->scope &&
			   charge->incarnation == ticket->incarnation &&
			   charge->owner_locator == ticket->owner_locator &&
			   charge->owner_cookie == ticket->owner_cookie &&
			   charge->owner_slot == ticket->owner_slot &&
			   (charge->state == SE_OWK_BUILDING ||
			    charge->state == SE_OWK_OWNED ||
			    charge->state == SE_OWK_FAULT_HELD);
	int account_shape = !account->reserved &&
			    account->scope == ticket->scope &&
			    account->incarnation == ticket->incarnation &&
			    !(account->bits & ~se_owk_valid_mask()) &&
			    account->used && account->used <= SE_OWK_QUOTA &&
			    se_owk_count(account->bits) == account->used &&
			    (account->bits & bit);
	exact = charge_exact && account_shape;
	if (!exact) {
		account->fault = 1;
		SE_OWK_FAULT_SITE(7);
	}
	if (charge_exact && charge->state == SE_OWK_BUILDING)
		charge->state = exact && !account->fault ? SE_OWK_OWNED :
							   SE_OWK_FAULT_HELD;
	if (charge_exact && charge->state == SE_OWK_FAULT_HELD) {
		account->fault = 1;
		SE_OWK_FAULT_SITE(8);
	}
	bpf_spin_unlock(&account->lock);
	ticket->held = 0;
	ticket->stage = 4;
#ifdef SE_REAP_EVENT
	/* Product reaper wakeup only (G019 M1); never authority. */
	if (exact)
		SE_REAP_EVENT(WORK_ABORTED, ticket->work_slot, ticket->cookie);
#endif
	return exact ? SE_OL_OK : SE_OL_CORRUPT;
}

/* The ticket alone is not permission to expose semantic bytes. WORK payload
 * must be overwritten from the frozen all-zero source outside locks, then
 * bound to the exact owner/sequence under the WORK metadata lock. */
static __attribute__((noinline)) int
se_owk_initialize_payload(struct se_ol_payload_handle *owner,
			  struct se_owk_ticket *ticket)
{
	if (!owner || !ticket || ticket->held != 1 || ticket->stage != 1 ||
	    !owner->lease.meta || owner->lease.held != 1 || owner->locked ||
	    owner->lease.locator != ticket->owner_locator ||
	    owner->lease.cookie != ticket->owner_cookie ||
	    owner->lease.slot != ticket->owner_slot ||
	    ticket->work_slot >= SE_OWK_WORKS)
		return SE_OL_CORRUPT;
	struct se_owk_meta *work = SE_OWK_META_LOOKUP(ticket->work_slot);
	if (!work) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	struct se_ol_meta *task = owner->lease.meta;
	bpf_spin_lock(&task->lock);
	int task_exact = task->locator == ticket->owner_locator &&
			 task->cookie == ticket->owner_cookie &&
			 task->active_leases &&
			 task->account_scope == ticket->scope &&
			 task->account_slot == ticket->account_slot &&
			 task->account_incarnation == ticket->incarnation &&
			 task->work_refs && task->current_work_owned == 1 &&
			 task->current_work_cookie == ticket->cookie &&
			 task->current_work_slot == ticket->work_slot;
	bpf_spin_unlock(&task->lock);
	bpf_spin_lock(&work->lock);
	int work_exact = work->phase == SE_OWK_OWNER_ATTACHED &&
			 work->active_leases == 1 &&
			 work->owner_ref_held == 1 &&
			 work->cookie == ticket->cookie &&
			 work->owner_locator == ticket->owner_locator &&
			 work->owner_cookie == ticket->owner_cookie &&
			 work->owner_slot == ticket->owner_slot &&
			 work->scope == ticket->scope &&
			 work->account_slot == ticket->account_slot &&
			 work->incarnation == ticket->incarnation &&
			 work->invocation_sequence &&
			 work->invocation_sequence <= SE_OWK_COOKIE_LIMIT;
	bpf_spin_unlock(&work->lock);
	if (!task_exact || !work_exact ||
	    SE_OWK_INIT_PAYLOAD_ZERO(ticket->work_slot)) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	struct se_owk_payload *payload =
		SE_OWK_PAYLOAD_LOOKUP(ticket->work_slot);
	if (!payload) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	bpf_spin_lock(&work->lock);
	work_exact = work->phase == SE_OWK_OWNER_ATTACHED &&
		     work->active_leases == 1 && work->owner_ref_held == 1 &&
		     work->cookie == ticket->cookie &&
		     work->owner_locator == ticket->owner_locator &&
		     work->owner_cookie == ticket->owner_cookie &&
		     work->invocation_sequence && !payload->scope &&
		     !payload->cookie && !payload->sequence && !payload->slot &&
		     !payload->reserved;
	if (work_exact) {
		payload->scope = ticket->scope;
		payload->cookie = ticket->cookie;
		payload->sequence = work->invocation_sequence;
		payload->slot = ticket->work_slot;
	}
	bpf_spin_unlock(&work->lock);
	if (!work_exact) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	ticket->stage = 2;
	return SE_OL_OK;
}

/* No policy may read WORK semantic bytes before this final exact commit.
 * The callback still owns the TASK lease and must call done/abort later. */
static __attribute__((noinline)) int
se_owk_commit(struct se_ol_payload_handle *owner, struct se_owk_ticket *ticket)
{
	if (!owner || !ticket || ticket->held != 1 || ticket->stage != 2 ||
	    owner->lease.held != 1 || owner->locked ||
	    owner->lease.locator != ticket->owner_locator ||
	    owner->lease.cookie != ticket->owner_cookie ||
	    owner->lease.slot != ticket->owner_slot ||
	    ticket->account_slot >= SE_OWK_ACCOUNTS ||
	    ticket->work_slot >= SE_OWK_WORKS)
		return SE_OL_CORRUPT;
	struct se_owk_account *account =
		SE_OWK_ACCOUNT_LOOKUP(ticket->account_slot);
	struct se_owk_charge *charge = SE_OWK_CHARGE_LOOKUP(ticket->work_slot);
	struct se_owk_meta *work = SE_OWK_META_LOOKUP(ticket->work_slot);
	struct se_owk_payload *payload =
		SE_OWK_PAYLOAD_LOOKUP(ticket->work_slot);
	if (!account || !charge || !work || !payload) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	__u32 local = ticket->work_slot - ticket->account_slot * SE_OWK_QUOTA;
	if (local >= SE_OWK_QUOTA) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	bpf_spin_lock(&account->lock);
	int charged = !account->fault && !account->reserved &&
		      account->scope == ticket->scope &&
		      account->incarnation == ticket->incarnation &&
		      account->used && account->used <= SE_OWK_QUOTA &&
		      se_owk_count(account->bits) == account->used &&
		      (account->bits & (1ULL << local)) &&
		      charge->state == SE_OWK_OWNED &&
		      charge->cookie == ticket->cookie &&
		      charge->scope == ticket->scope &&
		      charge->incarnation == ticket->incarnation &&
		      charge->owner_locator == ticket->owner_locator &&
		      charge->owner_cookie == ticket->owner_cookie &&
		      charge->owner_slot == ticket->owner_slot;
	bpf_spin_unlock(&account->lock);
	struct se_ol_meta *task = owner->lease.meta;
	bpf_spin_lock(&task->lock);
	int task_exact = task->phase == SE_OL_LIVE &&
			 task->locator == ticket->owner_locator &&
			 task->cookie == ticket->owner_cookie &&
			 task->active_leases && task->work_refs &&
			 task->current_work_owned == 1 &&
			 task->current_work_cookie == ticket->cookie &&
			 task->current_work_slot == ticket->work_slot &&
			 task->account_scope == ticket->scope &&
			 task->account_slot == ticket->account_slot &&
			 task->account_incarnation == ticket->incarnation;
	bpf_spin_unlock(&task->lock);
	bpf_spin_lock(&work->lock);
	int exact =
		charged && task_exact && work->phase == SE_OWK_OWNER_ATTACHED &&
		work->active_leases == 1 && work->owner_ref_held == 1 &&
		work->cookie == ticket->cookie &&
		work->owner_locator == ticket->owner_locator &&
		work->owner_cookie == ticket->owner_cookie &&
		work->invocation_sequence && !work->continuation_stage &&
		!work->continuation_reserved && !ticket->continuation_stage &&
		!ticket->reserved && payload->scope == ticket->scope &&
		payload->cookie == ticket->cookie &&
		payload->sequence == work->invocation_sequence &&
		payload->slot == ticket->work_slot && !payload->reserved;
	if (exact)
		work->phase = SE_OWK_ACTIVE;
	bpf_spin_unlock(&work->lock);
	if (!exact) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	ticket->stage = 3;
	return SE_OL_OK;
}

/* The synchronous callback releases only its current-WORK token and lexical
 * WORK lease. The persistent owner reference and account charge remain for
 * source-owned reaper cleanup. TASK may have become DEAD, but its exact held
 * locator lease still forbids physical reuse during this transition. */
static __attribute__((noinline)) int
se_owk_finish(struct se_ol_payload_handle *owner, struct se_owk_ticket *ticket,
	      int aborting)
{
	if (!owner || !ticket || ticket->held != 1 ||
	    (aborting ? (ticket->stage != 1 && ticket->stage != 2) :
			ticket->stage != 3) ||
	    owner->lease.held != 1 || owner->locked ||
	    owner->lease.locator != ticket->owner_locator ||
	    owner->lease.cookie != ticket->owner_cookie ||
	    owner->lease.slot != ticket->owner_slot ||
	    ticket->work_slot >= SE_OWK_WORKS)
		return SE_OL_CORRUPT;
	struct se_owk_meta *work = SE_OWK_META_LOOKUP(ticket->work_slot);
	struct se_owk_payload *payload =
		aborting ? 0 : SE_OWK_PAYLOAD_LOOKUP(ticket->work_slot);
	if (!work) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	bpf_spin_lock(&work->lock);
	int exact = work->phase == (aborting ? SE_OWK_OWNER_ATTACHED :
					       SE_OWK_ACTIVE) &&
		    work->active_leases == 1 && work->owner_ref_held == 1 &&
		    work->cookie == ticket->cookie &&
		    work->owner_locator == ticket->owner_locator &&
		    work->owner_cookie == ticket->owner_cookie &&
		    work->owner_slot == ticket->owner_slot &&
		    work->scope == ticket->scope &&
		    work->account_slot == ticket->account_slot &&
		    work->incarnation == ticket->incarnation &&
		    work->invocation_sequence &&
		    work->continuation_stage == ticket->continuation_stage &&
		    !work->continuation_reserved && !ticket->reserved;
	int semantic_exact = aborting ||
			     (payload && payload->scope == ticket->scope &&
			      payload->cookie == ticket->cookie &&
			      payload->sequence == work->invocation_sequence &&
			      payload->slot == ticket->work_slot &&
			      !payload->reserved);
	bpf_spin_unlock(&work->lock);
	if (!exact) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	struct se_ol_meta *task = owner->lease.meta;
	bpf_spin_lock(&task->lock);
	exact = task->locator == ticket->owner_locator &&
		task->cookie == ticket->owner_cookie && task->active_leases &&
		task->account_scope == ticket->scope &&
		task->account_slot == ticket->account_slot &&
		task->account_incarnation == ticket->incarnation &&
		task->work_refs && task->current_work_owned == 1 &&
		task->current_work_cookie == ticket->cookie &&
		task->current_work_slot == ticket->work_slot;
	if (exact) {
		task->current_work_owned = 0;
		task->current_work_cookie = 0;
		task->current_work_slot = 0;
	}
	bpf_spin_unlock(&task->lock);
	if (!exact) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	bpf_spin_lock(&work->lock);
	exact = work->phase ==
			(aborting ? SE_OWK_OWNER_ATTACHED : SE_OWK_ACTIVE) &&
		work->active_leases == 1 && work->owner_ref_held == 1 &&
		work->cookie == ticket->cookie &&
		work->owner_locator == ticket->owner_locator &&
		work->owner_cookie == ticket->owner_cookie &&
		work->continuation_stage == ticket->continuation_stage &&
		!work->continuation_reserved;
	if (exact) {
		work->phase = aborting ? SE_OWK_ABORTED : SE_OWK_DONE;
		work->active_leases = 0;
		work->continuation_stage = 0;
	}
	bpf_spin_unlock(&work->lock);
	if (!exact) {
		se_owk_fault_ticket(ticket);
		return SE_OL_CORRUPT;
	}
	if (!semantic_exact)
		se_owk_fault_ticket(ticket);
	ticket->held = 0;
	ticket->stage = aborting ? 4 : 5;
#ifdef SE_REAP_EVENT
	/* Product reaper wakeup only (G019 M1); never authority. */
	if (semantic_exact) {
		if (aborting)
			SE_REAP_EVENT(WORK_ABORTED, ticket->work_slot,
				      ticket->cookie);
		else
			SE_REAP_EVENT(WORK_DONE, ticket->work_slot,
				      ticket->cookie);
	}
#endif
	return semantic_exact ? SE_OL_OK : SE_OL_CORRUPT;
}

static inline int se_owk_done(struct se_ol_payload_handle *owner,
			      struct se_owk_ticket *ticket)
{
	return se_owk_finish(owner, ticket, 0);
}
static inline int se_owk_abort(struct se_ol_payload_handle *owner,
			       struct se_owk_ticket *ticket)
{
	return se_owk_finish(owner, ticket, 1);
}

/* TASK account zero is checked first: its refund requires no active TASK
 * lease or WORK owner ref, so a source-compliant caller cannot mint a new
 * WORK credit afterward while this route is withdrawn/no-claims. The WORK
 * zero observation is then monotonic. The original adapter revalidates the
 * same route and TASK account before recycling. Never bypass this wrapper
 * once WORK charges are selected. */
static __attribute__((noinline)) int
se_owk_route_recycle(__u32 slot, const struct se_binding_snapshots *snapshots)
{
	if (slot >= SE_OWK_ACCOUNTS || !snapshots)
		return SE_OL_CORRUPT;
	struct se_route_anchor *route = SE_OC_ROUTE_LOOKUP(slot);
	struct se_oc_account *task_account = SE_OC_ACCOUNT_LOOKUP(slot);
	struct se_owk_account *work_account = SE_OWK_ACCOUNT_LOOKUP(slot);
	if (!route || !task_account || !work_account)
		return SE_OL_CORRUPT;
	__u64 scope = 0;
	__u32 incarnation = 0;
	bpf_spin_lock(&route->lock);
	int withdrawn = route->phase == SE_ROUTE_WITHDRAWN &&
			!route->early_claims && route->payload_slot == slot &&
			route->scope && route->incarnation && !route->reserved;
	scope = route->scope;
	incarnation = route->incarnation;
	bpf_spin_unlock(&route->lock);
	if (!withdrawn)
		return SE_OL_STALE;
	bpf_spin_lock(&task_account->lock);
	int task_healthy =
		!task_account->fault && !task_account->reserved &&
		task_account->used <= SE_OC_QUOTA &&
		se_oc_bitmap_count(task_account) == task_account->used &&
		((!task_account->scope && !task_account->incarnation) ||
		 (task_account->scope == scope &&
		  task_account->incarnation == incarnation));
	int task_occupied = task_account->used;
	bpf_spin_unlock(&task_account->lock);
	if (!task_healthy)
		return SE_OL_CORRUPT;
	if (task_occupied)
		return SE_OL_CONTENDED;
	bpf_spin_lock(&work_account->lock);
	int work_healthy =
		!work_account->fault && !work_account->reserved &&
		work_account->used <= SE_OWK_QUOTA &&
		!(work_account->bits & ~se_owk_valid_mask()) &&
		se_owk_count(work_account->bits) == work_account->used &&
		((!work_account->scope && !work_account->incarnation) ||
		 (work_account->scope == scope &&
		  work_account->incarnation == incarnation));
	int work_occupied = work_account->used;
	bpf_spin_unlock(&work_account->lock);
	if (!work_healthy)
		return SE_OL_CORRUPT;
	if (work_occupied)
		return SE_OL_CONTENDED;
	return se_oc_route_recycle(slot, snapshots);
}
#endif
