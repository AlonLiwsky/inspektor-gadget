/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_CHARGE_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_CHARGE_CANDIDATE_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "opaque-key charge is candidate-only"
#endif
#ifndef SE_OC_ACCOUNTS
#error "provide fixed account count"
#endif
#ifndef SE_OC_QUOTA
#error "provide fixed per-account task quota"
#endif
#ifndef SE_OC_ACCOUNT_LOOKUP
#error "provide trusted account ARRAY lookup"
#endif
#ifndef SE_OC_CHARGE_LOOKUP
#error "provide fixed task charge ARRAY lookup"
#endif
#ifndef SE_OC_SEQUENCE_LOOKUP
#error "provide nonwrapping global cookie sequence lookup"
#endif

#include "shared_pool_opaque_writer_candidate.h"

#ifndef SE_OC_AFTER_CHOOSE
#define SE_OC_AFTER_CHOOSE(slot) ((void)(slot))
#endif

#define SE_OC_WORDS ((SE_OC_QUOTA + 63U) / 64U)
/* Bitmap word of a slot-local TASK index.
 * Precondition: local < SE_OC_QUOTA. Every caller checks it first; the
 * clamp only keeps the offset in bounds, it does not make an out-of-quota
 * index correct. The barrier keeps the clamp verifier-visible (the compiler
 * would otherwise drop it as redundant and the verifier, which has lost the
 * subtraction's bound, rejects the variable map-value offset). It is used
 * for one word too: the plain local / 64U form (TASK quota <= 64) lost
 * state pruning in the task_alloc birth and adoption roots (q(64,8):
 * adopt_task > 1M, child_target 918k/928k; with the barrier 37k/86k). */
static __attribute__((always_inline)) inline __u32 se_oc_word(__u32 local)
{
	__u32 word = local / 64U;
	asm volatile("" : "+r"(word));
	if (word > SE_OC_WORDS - 1U)
		word = SE_OC_WORDS - 1U;
	asm volatile("" : "+r"(word));
	return word;
}
#define SE_OC_WORD(local) se_oc_word(local)
#define SE_OC_COOKIE_LIMIT (~(__u64)0 - 1ULL)
_Static_assert(SE_OC_ACCOUNTS > 0 && SE_OC_QUOTA > 0 &&
		       (__u64)SE_OC_ACCOUNTS * SE_OC_QUOTA == SE_OL_TASKS,
	       "test-only charged task partition");

enum se_oc_charge_state {
	SE_OC_FREE = 0,
	SE_OC_BUILDING,
	SE_OC_OWNED,
	SE_OC_RETURN_READY,
	SE_OC_FAULT_HELD,
};
struct se_oc_account {
	struct bpf_spin_lock lock;
	__u32 used, fault, incarnation, reserved;
	__u64 scope;
	__u64 bits[SE_OC_WORDS];
};
struct se_oc_charge {
	__u64 cookie, last_returned, scope, locator;
	__u32 incarnation, state;
};
struct se_oc_sequence {
	struct bpf_spin_lock lock;
	__u32 reserved;
	__u64 next_cookie;
};
/* Callback-local capability, never a map or wire value. The exact pointers
 * are obtained before charging; a bitmap bit and BUILDING charge survive
 * every post-charge failure. A separate candidate refund tail requires
 * source-owned cleanup receipts not produced by this constructor. */
struct se_oc_reservation {
	struct se_oc_account *account;
	struct se_oc_charge *charge;
	struct se_ol_meta *meta;
	__u64 scope, cookie, locator;
	__u32 account_slot, incarnation, task_slot;
	/* Callback-local booleans, never a map/wire value. Keeping them narrow
	 * avoids a second 32-byte BPF stack quantum in held birth callbacks. */
	__u16 held, terminal;
};
_Static_assert(
	sizeof(struct se_oc_reservation) == 64,
	"callback-local charged TASK reservation must fit one stack quantum");

static __attribute__((always_inline)) inline __u32
se_oc_bitmap_count(const struct se_oc_account *account)
{
	__u32 count = 0;
	/* Above 4 words (a TASK quota above 256) the loop stays a loop: unrolled,
	 * each word's popcount keeps its own registers and spills, which grows
	 * every caller's frame by about 16 bytes per word and pushes the fork
	 * source and the task_alloc target past 512 bytes. 4 words or fewer
	 * keep the unrolled form (token-identical objects). */
#if SE_OC_WORDS > 4
#pragma clang loop unroll(disable)
#endif
	for (__u32 i = 0; i < SE_OC_WORDS; i++) {
		__u64 bits = account->bits[i];
#if SE_OC_QUOTA % 64U
		if (i == SE_OC_WORDS - 1 && (bits >> (SE_OC_QUOTA % 64U)))
			return SE_OC_QUOTA + 1;
#endif
		bits -= (bits >> 1) & 0x5555555555555555ULL;
		bits = (bits & 0x3333333333333333ULL) +
		       ((bits >> 2) & 0x3333333333333333ULL);
		bits = (bits + (bits >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
		count += (__u32)((bits * 0x0101010101010101ULL) >> 56);
	}
	return count;
}

static __attribute__((always_inline)) inline __u32 se_oc_first_bit(__u64 bits)
{
	__u32 bit = 0;
	if (!(bits & 0xffffffffULL)) {
		bit += 32;
		bits >>= 32;
	}
	if (!(bits & 0xffffULL)) {
		bit += 16;
		bits >>= 16;
	}
	if (!(bits & 0xffULL)) {
		bit += 8;
		bits >>= 8;
	}
	if (!(bits & 0xfULL)) {
		bit += 4;
		bits >>= 4;
	}
	if (!(bits & 3ULL)) {
		bit += 2;
		bits >>= 2;
	}
	if (!(bits & 1ULL))
		bit++;
	return bit;
}

/* Caller must hold an authenticated original-route claim for this account
 * across binding and any subsequent reservation. This transition alone is
 * not admission authority. An empty, healthy account may follow a recycled
 * route incarnation; a charged or faulted old account cannot be relabelled.
 * No map helper or route lock is taken while the account lock is held. */
static __attribute__((noinline)) int
se_oc_bind_account(__u32 account_slot, __u64 scope, __u32 incarnation)
{
	if (account_slot >= SE_OC_ACCOUNTS || !scope || !incarnation)
		return SE_OL_CORRUPT;
	struct se_oc_account *account = SE_OC_ACCOUNT_LOOKUP(account_slot);
	if (!account)
		return SE_OL_CORRUPT;
	int result = SE_OL_OK;
	bpf_spin_lock(&account->lock);
	if (account->reserved || account->fault ||
	    account->used > SE_OC_QUOTA ||
	    se_oc_bitmap_count(account) != account->used ||
	    (!!account->scope != !!account->incarnation)) {
		account->fault = 1;
		result = SE_OL_CORRUPT;
	} else if (account->scope == scope &&
		   account->incarnation == incarnation) {
		/* Existing exact account, including one with live TASK charges. */
	} else if (account->used) {
		result = SE_OL_CONTENDED;
	} else {
		account->scope = scope;
		account->incarnation = incarnation;
	}
	bpf_spin_unlock(&account->lock);
	return result;
}

/* Selection is an observation, not a reservation. The caller must pass the
 * returned slot to se_oc_reserve and handle CONTENDED if another constructor
 * won the account lock in between. No map helper runs under the account lock. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_CHOOSE_INLINE_DIAGNOSTIC
#define SE_OC_CHOOSE_ATTR __attribute__((always_inline)) inline
#else
#define SE_OC_CHOOSE_ATTR __attribute__((noinline))
#endif
static SE_OC_CHOOSE_ATTR int se_oc_choose_task(__u32 account_slot, __u64 scope,
					       __u32 incarnation,
					       __u32 *task_slot)
{
	if (!task_slot || *task_slot || !scope || !incarnation ||
	    account_slot >= SE_OC_ACCOUNTS)
		return SE_OL_CORRUPT;
	struct se_oc_account *account = SE_OC_ACCOUNT_LOOKUP(account_slot);
	if (!account)
		return SE_OL_CORRUPT;
	__u32 selected = SE_OC_QUOTA;
	int result = SE_OL_OK;
	bpf_spin_lock(&account->lock);
	if (account->fault || account->reserved ||
	    account->used > SE_OC_QUOTA ||
	    se_oc_bitmap_count(account) != account->used) {
		account->fault = 1;
		result = SE_OL_CORRUPT;
	} else if (account->scope != scope ||
		   account->incarnation != incarnation) {
		result = SE_OL_STALE;
	} else if (account->used == SE_OC_QUOTA) {
		result = SE_OL_LIMIT;
	} else {
#ifdef __clang__
#pragma unroll
#endif
		for (__u32 i = 0; i < SE_OC_WORDS; i++) {
			__u64 free = ~account->bits[i];
#if SE_OC_QUOTA % 64U
			if (i == SE_OC_WORDS - 1)
				free &= (1ULL << (SE_OC_QUOTA % 64U)) - 1ULL;
#endif
			if (free && selected == SE_OC_QUOTA)
				selected = i * 64U + se_oc_first_bit(free);
		}
		if (selected >= SE_OC_QUOTA) {
			account->fault = 1;
			result = SE_OL_CORRUPT;
		}
	}
	bpf_spin_unlock(&account->lock);
	if (result != SE_OL_OK)
		return result;
	*task_slot = account_slot * SE_OC_QUOTA + selected;
	return *task_slot < SE_OL_TASKS ? SE_OL_OK : SE_OL_CORRUPT;
}
#undef SE_OC_CHOOSE_ATTR

static inline int se_oc_reserve(__u32 account_slot, __u64 scope,
				__u32 incarnation, __u32 task_slot,
				struct se_oc_reservation *reservation)
{
	if (!reservation || reservation->held || reservation->terminal ||
	    reservation->account || reservation->charge || reservation->meta ||
	    !scope || !incarnation || account_slot >= SE_OC_ACCOUNTS ||
	    task_slot >= SE_OL_TASKS || task_slot / SE_OC_QUOTA != account_slot)
		return SE_OL_CORRUPT;
	__u32 local = task_slot - account_slot * SE_OC_QUOTA;
	if (local >= SE_OC_QUOTA)
		return SE_OL_CORRUPT;
	struct se_oc_account *account = SE_OC_ACCOUNT_LOOKUP(account_slot);
	struct se_oc_charge *charge = SE_OC_CHARGE_LOOKUP(task_slot);
	struct se_ol_meta *meta = SE_OL_META_LOOKUP(task_slot);
	struct se_oc_sequence *sequence = SE_OC_SEQUENCE_LOOKUP();
	if (!account || !charge || !meta || !sequence)
		return SE_OL_CORRUPT;
	__u64 cookie = 0;
	bpf_spin_lock(&sequence->lock);
	int result = SE_OL_OK;
	if (sequence->reserved)
		result = SE_OL_CORRUPT;
	else if (sequence->next_cookie >= SE_OC_COOKIE_LIMIT)
		result = SE_OL_LIMIT;
	else
		cookie = ++sequence->next_cookie;
	bpf_spin_unlock(&sequence->lock);
	if (result != SE_OL_OK)
		return result;
	__u64 bit = 1ULL << (local % 64U);
	bpf_spin_lock(&account->lock);
	if (account->reserved || account->fault ||
	    account->used > SE_OC_QUOTA ||
	    se_oc_bitmap_count(account) != account->used) {
		account->fault = 1;
		result = SE_OL_CORRUPT;
	} else if (account->scope != scope ||
		   account->incarnation != incarnation)
		result = SE_OL_STALE;
	else if (account->bits[SE_OC_WORD(local)] & bit)
		result = SE_OL_CONTENDED;
	else if (account->used == SE_OC_QUOTA)
		result = SE_OL_LIMIT;
	else if (charge->state != SE_OC_FREE || charge->cookie ||
		 charge->scope || charge->incarnation || charge->locator) {
		account->fault = 1;
		result = SE_OL_CORRUPT;
	} else if (charge->last_returned >= cookie) {
		account->fault = 1;
		result = SE_OL_CORRUPT;
	} else {
		account->bits[SE_OC_WORD(local)] |= bit;
		account->used++;
		charge->cookie = cookie;
		charge->scope = scope;
		charge->incarnation = incarnation;
		charge->state = SE_OC_BUILDING;
		*reservation = (struct se_oc_reservation){
			account,      charge,	   meta,      scope, cookie, 0,
			account_slot, incarnation, task_slot, 1,     0,
		};
	}
	bpf_spin_unlock(&account->lock);
	return result;
}

/* Bind the exact BUILDING reservation to the writer's nonwrapping locator.
 * Failure after the account bit is set is not an unsuccessful reservation:
 * retain the bit/charge as FAULT_HELD and stop this account. */
static inline int se_oc_begin_charged(struct se_oc_reservation *reservation)
{
	if (!reservation || reservation->held != 1 || reservation->terminal ||
	    !reservation->account || !reservation->charge ||
	    !reservation->meta || !reservation->cookie ||
	    reservation->account_slot >= SE_OC_ACCOUNTS ||
	    reservation->task_slot >= SE_OL_TASKS ||
	    reservation->task_slot / SE_OC_QUOTA != reservation->account_slot ||
	    SE_OC_ACCOUNT_LOOKUP(reservation->account_slot) !=
		    reservation->account ||
	    SE_OC_CHARGE_LOOKUP(reservation->task_slot) !=
		    reservation->charge ||
	    SE_OL_META_LOOKUP(reservation->task_slot) != reservation->meta)
		return SE_OL_CORRUPT;
	struct se_oc_account *account = reservation->account;
	struct se_oc_charge *charge = reservation->charge;
	__u32 local = reservation->task_slot -
		      reservation->account_slot * SE_OC_QUOTA;
	if (local >= SE_OC_QUOTA)
		return SE_OL_CORRUPT;
	__u64 bit = 1ULL << (local % 64U);
	bpf_spin_lock(&account->lock);
	int exact = !account->reserved && !account->fault &&
		    account->scope == reservation->scope &&
		    account->incarnation == reservation->incarnation &&
		    account->used && account->used <= SE_OC_QUOTA &&
		    se_oc_bitmap_count(account) == account->used &&
		    (account->bits[SE_OC_WORD(local)] & bit) &&
		    charge->state == SE_OC_BUILDING &&
		    charge->cookie == reservation->cookie &&
		    charge->scope == reservation->scope &&
		    charge->incarnation == reservation->incarnation &&
		    !charge->locator;
	if (!exact) {
		account->fault = 1;
		if (charge->state == SE_OC_BUILDING &&
		    charge->cookie == reservation->cookie)
			charge->state = SE_OC_FAULT_HELD;
	}
	bpf_spin_unlock(&account->lock);
	if (!exact)
		return SE_OL_CORRUPT;
	__u64 locator = 0;
	int begun = se_ow_begin(reservation->meta, reservation->task_slot,
				reservation->cookie, &locator);
	int bound = 0;
	if (begun == SE_OL_OK) {
		struct se_ol_meta *meta = reservation->meta;
		bpf_spin_lock(&meta->lock);
		bound = meta->phase == SE_OL_INITIALIZING &&
			meta->cookie == reservation->cookie &&
			meta->locator == locator && meta->active_leases == 1 &&
			!meta->account_scope && !meta->account_slot &&
			!meta->account_incarnation && !meta->reserved2;
		if (bound) {
			meta->account_scope = reservation->scope;
			meta->account_slot = reservation->account_slot;
			meta->account_incarnation = reservation->incarnation;
		}
		bpf_spin_unlock(&meta->lock);
	}
	bpf_spin_lock(&account->lock);
	exact = !account->reserved && !account->fault &&
		account->scope == reservation->scope &&
		account->incarnation == reservation->incarnation &&
		account->used && account->used <= SE_OC_QUOTA &&
		se_oc_bitmap_count(account) == account->used &&
		(account->bits[SE_OC_WORD(local)] & bit) &&
		charge->state == SE_OC_BUILDING &&
		charge->cookie == reservation->cookie &&
		charge->scope == reservation->scope &&
		charge->incarnation == reservation->incarnation &&
		!charge->locator;
	if (exact && begun == SE_OL_OK && bound) {
		charge->locator = locator;
		charge->state = SE_OC_OWNED;
		reservation->locator = locator;
		reservation->held = 0;
	} else {
		account->fault = 1;
		if (charge->state == SE_OC_BUILDING &&
		    charge->cookie == reservation->cookie)
			charge->state = SE_OC_FAULT_HELD;
	}
	bpf_spin_unlock(&account->lock);
	return exact && begun == SE_OL_OK && bound ? SE_OL_OK : SE_OL_CORRUPT;
}

/* A selector observation can lose its slot before the charge lock. Retry
 * boundedly without ever treating a CONTENDED observation as a reservation.
 * Exhausted attempts remain recoverable contention, distinct from a full
 * account and from a structural fault. Each failed reserve burns only a
 * nonwrapping sequence number; no account bit or charge is refunded here. */
static __attribute__((noinline)) int
se_oc_reserve_any(__u32 account_slot, __u64 scope, __u32 incarnation,
		  struct se_oc_reservation *reservation)
{
	if (!reservation || reservation->held || reservation->terminal ||
	    reservation->account || reservation->charge || reservation->meta)
		return SE_OL_CORRUPT;
#ifdef __clang__
#pragma unroll
#endif
	for (int attempt = 0; attempt < 8; attempt++) {
		__u32 task_slot = 0;
		int result = se_oc_choose_task(account_slot, scope, incarnation,
					       &task_slot);
		if (result != SE_OL_OK)
			return result;
		/* Host-only interleaving seam; production default is a no-op. */
		SE_OC_AFTER_CHOOSE(task_slot);
		result = se_oc_reserve(account_slot, scope, incarnation,
				       task_slot, reservation);
		if (result != SE_OL_CONTENDED)
			return result;
	}
	return SE_OL_CONTENDED;
}

#endif
