/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_TASK_REAP_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_TASK_REAP_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_DEVELOPMENT) || \
	!defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY)
#error "task refund tail is candidate-only"
#endif
#include "shared_pool_task_core.h"

/* Keep the five bounded lifecycle stages as BPF subprograms. Inlining them
 * through the reaper visitor exceeds the stock Rocky 8 verifier's processed
 * instruction budget; each call stays within BPF's five-register ABI. */

#ifndef SE_POOL_TASK_TAIL_AFTER_CHARGE
#define SE_POOL_TASK_TAIL_AFTER_CHARGE() \
	do {                             \
	} while (0)
#endif
#ifndef SE_POOL_TASK_TAIL_AFTER_META
#define SE_POOL_TASK_TAIL_AFTER_META() \
	do {                           \
	} while (0)
#endif
#ifndef SE_POOL_TASK_TAIL_BEFORE_META_FREE
#define SE_POOL_TASK_TAIL_BEFORE_META_FREE() \
	do {                                 \
	} while (0)
#endif

SE_POOL_INLINE int se_pool_task_initial_zero(const struct se_pool_task_meta *m)
{
	return !m->cookie && !m->physical_address && !m->account_scope &&
	       !m->slot && !m->account_slot && !m->account_incarnation &&
	       !m->active_leases && !m->work_refs && !m->native_refs &&
	       !m->cleanup_done && !m->flags && !m->directory_holds &&
	       !m->reserved0 && !m->next_work_sequence &&
	       !m->current_work_cookie && !m->current_work_slot &&
	       !m->current_work_owned && !m->cleanup_error && !m->reserved1 &&
	       !m->last_reap_sequence && !m->reserved2 && !m->reserved3;
}

/* Single-flight reaper tail. The caller must have completed real semantic,
 * constructor, work, native, directory and payload-zero obligations before
 * publishing REFUND_PENDING plus all six bits. This helper cannot manufacture
 * those proofs. It does not run from task_free or from an untrusted command.
 *
 * Each invocation advances at most one durable boundary. The charge bit and
 * original account remain occupied until the final route-locked refund. No
 * helper runs under a spinlock and the two locks are never nested. */
static __attribute__((noinline)) int
se_pool_task_refund_tail(struct se_route_anchor *route,
			 struct se_pool_bitmap *bits,
			 struct se_pool_charge *charge,
			 struct se_pool_task_meta *meta, __u32 slot)
{
	if (slot >= SE_POOL_T)
		return SE_POOL_CORRUPT;
	__u32 account = slot / SE_POOL_QT;
	struct se_route_anchor *exact_route = se_route_anchor_lookup(&account);
	struct se_pool_bitmap *exact_bits =
		bpf_map_lookup_elem(&se_pool_bitmaps, &account);
	struct se_pool_charge *exact_charge =
		bpf_map_lookup_elem(&se_pool_charges, &slot);
	struct se_pool_task_meta *exact_meta =
		bpf_map_lookup_elem(&se_pool_task_meta, &slot);
	if (!exact_route || !exact_bits || !exact_charge || !exact_meta ||
	    route != exact_route || bits != exact_bits ||
	    charge != exact_charge || meta != exact_meta)
		return SE_POOL_CORRUPT;

	__u32 local = slot - account * SE_POOL_QT;
	/* Keep the bitmap access explicitly bounded for the BPF verifier. */
	if (local >= SE_POOL_QT)
		return SE_POOL_CORRUPT;
	__u32 word = local / 64u;
#ifdef __BPF__
	barrier_var(word);
#endif
	if (word >= SE_POOL_TASK_WORDS)
		return SE_POOL_CORRUPT;
	__u64 bit = 1ULL << (local % 64u);
	__u64 cookie, last, scope, route_scope;
	__u32 incarnation, state, used, occupied, route_incarnation;
	bpf_spin_lock(&route->lock);
	cookie = charge->current_cookie;
	last = charge->last_returned_cookie;
	scope = charge->account_scope;
	incarnation = charge->account_incarnation;
	state = charge->state;
	used = route->tasks_used;
	occupied = !!(bits->words[word] & bit);
	route_scope = route->scope;
	route_incarnation = route->incarnation;
	bpf_spin_unlock(&route->lock);
	SE_POOL_TASK_TAIL_AFTER_CHARGE();

	__u32 phase, done, initial_zero, task_account, task_incarnation;
	__u64 task_cookie, task_scope;
	bpf_spin_lock(&meta->lock);
	phase = meta->phase;
	task_cookie = meta->cookie;
	task_scope = meta->account_scope;
	task_account = meta->account_slot;
	task_incarnation = meta->account_incarnation;
	done = !meta->active_leases && !meta->work_refs && !meta->native_refs &&
	       !meta->directory_holds && !meta->current_work_owned &&
	       !meta->current_work_cookie && !meta->current_work_slot &&
	       !meta->cleanup_error && meta->cleanup_done == 63u;
	int meta_valid = task_cookie && se_pool_meta_valid(meta) &&
			 meta->slot == slot && task_account == account;
	initial_zero = se_pool_task_initial_zero(meta);
	bpf_spin_unlock(&meta->lock);
	SE_POOL_TASK_TAIL_AFTER_META();

	bpf_spin_lock(&route->lock);
	if (charge->current_cookie != cookie ||
	    charge->last_returned_cookie != last ||
	    charge->account_scope != scope ||
	    charge->account_incarnation != incarnation ||
	    charge->state != state || route->tasks_used != used ||
	    !!(bits->words[word] & bit) != occupied ||
	    route->scope != route_scope ||
	    route->incarnation != route_incarnation) {
		bpf_spin_unlock(&route->lock);
		return SE_POOL_PENDING_CLEANUP;
	}
	if (route->reserved) {
		bpf_spin_unlock(&route->lock);
		return SE_POOL_CORRUPT;
	}
	if (state == SE_POOL_CH_FREE) {
		int free_meta = phase == SE_POOL_FREE &&
				((initial_zero && !last) ||
				 (meta_valid && done && task_cookie == last));
		if (!cookie && !scope && !incarnation && !occupied &&
		    last <= SE_POOL_LIMIT && free_meta) {
			bpf_spin_unlock(&route->lock);
			return SE_POOL_ALREADY_RETURNED;
		}
		goto fault;
	}
	if (!occupied || !used || used > SE_POOL_QT || !cookie ||
	    cookie > SE_POOL_LIMIT || last >= cookie || !scope ||
	    scope != route_scope || !incarnation ||
	    incarnation != route_incarnation || route->payload_slot != account)
		goto fault;
	if (state == SE_POOL_CH_BUILDING) {
		if (se_pool_task_bits_locked(bits) != used)
			goto fault;
		bpf_spin_unlock(&route->lock);
		return SE_POOL_PENDING_CLEANUP;
	}
	if (state != SE_POOL_CH_OWNED && state != SE_POOL_CH_RETURN_READY)
		goto fault;
	if (!meta_valid || task_cookie != cookie || task_scope != scope ||
	    task_incarnation != incarnation ||
	    se_pool_task_bits_locked(bits) != used)
		goto fault;
	if (phase != SE_POOL_REFUND_PENDING && phase != SE_POOL_FREE) {
		if (state != SE_POOL_CH_OWNED)
			goto fault;
		bpf_spin_unlock(&route->lock);
		return SE_POOL_PENDING_CLEANUP;
	}
	if (!done ||
	    (phase == SE_POOL_FREE && state != SE_POOL_CH_RETURN_READY))
		goto fault;
	if (state == SE_POOL_CH_OWNED) {
		charge->state = SE_POOL_CH_RETURN_READY;
		bpf_spin_unlock(&route->lock);
		return SE_POOL_PENDING_CLEANUP;
	}
	if (phase == SE_POOL_REFUND_PENDING) {
		bpf_spin_unlock(&route->lock);
		SE_POOL_TASK_TAIL_BEFORE_META_FREE();
		bpf_spin_lock(&meta->lock);
		int still_done =
			meta->phase == SE_POOL_REFUND_PENDING &&
			se_pool_meta_valid(meta) && meta->cookie == cookie &&
			meta->account_scope == scope &&
			meta->account_incarnation == incarnation &&
			meta->slot == slot && meta->account_slot == account &&
			!meta->active_leases && !meta->work_refs &&
			!meta->native_refs && !meta->directory_holds &&
			!meta->current_work_owned &&
			!meta->current_work_cookie &&
			!meta->current_work_slot && !meta->cleanup_error &&
			meta->cleanup_done == 63u;
		if (still_done)
			meta->phase = SE_POOL_FREE;
		bpf_spin_unlock(&meta->lock);
		if (still_done)
			return SE_POOL_PENDING_CLEANUP;
		/* A terminal metadata contradiction cannot leave RETURN_READY
		 * eligible for a later false refund. Fault only the still-exact
		 * original charge; an intervening charge change is inconclusive. */
		bpf_spin_lock(&route->lock);
		if (charge->current_cookie == cookie &&
		    charge->account_scope == scope &&
		    charge->account_incarnation == incarnation &&
		    charge->state == SE_POOL_CH_RETURN_READY &&
		    (bits->words[word] & bit)) {
			route->reserved = 1;
			charge->state = SE_POOL_CH_FAULT_HELD;
		}
		bpf_spin_unlock(&route->lock);
		return SE_POOL_CORRUPT;
	}
	charge->last_returned_cookie = cookie;
	charge->current_cookie = 0;
	charge->account_scope = 0;
	charge->account_incarnation = 0;
	charge->state = SE_POOL_CH_FREE;
	bits->words[word] &= ~bit;
	route->tasks_used--;
	bpf_spin_unlock(&route->lock);
	return SE_POOL_OK;
fault:
	route->reserved = 1;
	charge->state = SE_POOL_CH_FAULT_HELD;
	bpf_spin_unlock(&route->lock);
	return SE_POOL_CORRUPT;
}

/* Reclaim only an unpublished, completed constructor abort. A denied
 * security_task_alloc need not receive task_free, so this path derives its
 * authority from the ABORTED phase and never assumes a final-free callback.
 * Each invocation advances one durable boundary. The zero-write claim blocks
 * concurrent refund/reuse while a fallible map helper runs without locks. */
static __attribute__((noinline)) int se_pool_task_abort_reap_step(__u32 slot)
{
	if (slot >= SE_POOL_T)
		return SE_POOL_CORRUPT;
	__u32 account = slot / SE_POOL_QT, zero = 0;
	struct se_route_anchor *route = se_route_anchor_lookup(&account);
	struct se_pool_bitmap *bits =
		bpf_map_lookup_elem(&se_pool_bitmaps, &account);
	struct se_pool_charge *charge =
		bpf_map_lookup_elem(&se_pool_charges, &slot);
	struct se_pool_task_meta *meta =
		bpf_map_lookup_elem(&se_pool_task_meta, &slot);
	struct se_pool_task_payload *payload =
		bpf_map_lookup_elem(&se_pool_task_payload, &slot);
	if (!route || !bits || !charge || !meta || !payload)
		return SE_POOL_CORRUPT;

	bpf_spin_lock(&meta->lock);
	__u32 phase = meta->phase;
	__u64 cookie = meta->cookie, scope = meta->account_scope;
	__u32 incarnation = meta->account_incarnation;
	__u32 leases = meta->active_leases, flags = meta->flags;
	__u32 cleanup_done = meta->cleanup_done;
	int unpublished = se_pool_meta_valid(meta) && meta->slot == slot &&
			  meta->account_slot == account && !meta->flags &&
			  !meta->active_leases && !meta->directory_holds &&
			  !meta->work_refs && !meta->native_refs &&
			  !meta->current_work_owned &&
			  !meta->current_work_cookie &&
			  !meta->current_work_slot && !meta->cleanup_error;
	bpf_spin_unlock(&meta->lock);
	if (phase == SE_POOL_REFUND_PENDING || phase == SE_POOL_FREE)
		return se_pool_task_refund_tail(route, bits, charge, meta,
						slot);
	if (phase != SE_POOL_ABORTED && phase != SE_POOL_CLEANING)
		return SE_POOL_NOT_ELIGIBLE;
	if (!unpublished && phase == SE_POOL_CLEANING && leases == 1 &&
	    !flags &&
	    cleanup_done == (SE_POOL_EXEC_DONE | SE_POOL_CONSTRUCTION_DONE |
			     SE_POOL_WORK_DONE | SE_POOL_NATIVE_DONE |
			     SE_POOL_DIR_DONE))
		return SE_POOL_PENDING_CLEANUP;
	if (!unpublished)
		return SE_POOL_CORRUPT;
	__u32 local = slot - account * SE_POOL_QT;
	if (local >= SE_POOL_QT)
		return SE_POOL_CORRUPT;
	__u32 word = local / 64u;
#ifdef __BPF__
	barrier_var(word);
#endif
	if (word >= SE_POOL_TASK_WORDS)
		return SE_POOL_CORRUPT;
	__u64 bit = 1ULL << (local % 64u);
	bpf_spin_lock(&route->lock);
	int charged = !route->reserved && route->scope == scope &&
		      route->incarnation == incarnation &&
		      route->payload_slot == account && route->tasks_used &&
		      route->tasks_used <= SE_POOL_QT &&
		      (bits->words[word] & bit) &&
		      charge->current_cookie == cookie &&
		      charge->last_returned_cookie < cookie &&
		      charge->account_scope == scope &&
		      charge->account_incarnation == incarnation &&
		      charge->state == SE_POOL_CH_OWNED;
	bpf_spin_unlock(&route->lock);
	if (!charged)
		return SE_POOL_CORRUPT;

	if (phase == SE_POOL_ABORTED) {
		bpf_spin_lock(&meta->lock);
		int valid = se_pool_meta_valid(meta) && meta->slot == slot &&
			    meta->phase == SE_POOL_ABORTED &&
			    meta->cookie == cookie &&
			    meta->account_scope == scope &&
			    meta->account_incarnation == incarnation &&
			    !meta->flags && !meta->cleanup_done &&
			    !meta->active_leases && !meta->directory_holds &&
			    !meta->work_refs && !meta->native_refs &&
			    !meta->current_work_owned && !meta->cleanup_error;
		if (valid) {
			meta->cleanup_done =
				SE_POOL_EXEC_DONE | SE_POOL_CONSTRUCTION_DONE |
				SE_POOL_WORK_DONE | SE_POOL_NATIVE_DONE |
				SE_POOL_DIR_DONE;
			meta->phase = SE_POOL_CLEANING;
		}
		bpf_spin_unlock(&meta->lock);
		return valid ? SE_POOL_PENDING_CLEANUP : SE_POOL_CORRUPT;
	}

	/* Claim the zero operation under the metadata lock, then run the map
	 * helper outside it. This claim is a real lease, not a terminal bit. */
	bpf_spin_lock(&meta->lock);
	int valid = se_pool_meta_valid(meta) && meta->slot == slot &&
		    meta->phase == SE_POOL_CLEANING && meta->cookie == cookie &&
		    meta->account_scope == scope &&
		    meta->account_incarnation == incarnation && !meta->flags &&
		    meta->cleanup_done ==
			    (SE_POOL_EXEC_DONE | SE_POOL_CONSTRUCTION_DONE |
			     SE_POOL_WORK_DONE | SE_POOL_NATIVE_DONE |
			     SE_POOL_DIR_DONE) &&
		    !meta->active_leases && !meta->directory_holds &&
		    !meta->work_refs && !meta->native_refs &&
		    !meta->current_work_owned && !meta->cleanup_error;
	if (valid)
		meta->active_leases = 1;
	bpf_spin_unlock(&meta->lock);
	if (!valid)
		return SE_POOL_PENDING_CLEANUP;
	const struct se_pool_task_payload *empty =
		bpf_map_lookup_elem(&se_pool_task_zero, &zero);
	int zeroed = empty && !bpf_map_update_elem(&se_pool_task_payload, &slot,
						   empty, BPF_ANY);
	bpf_spin_lock(&meta->lock);
	valid = se_pool_meta_valid(meta) && meta->slot == slot &&
		meta->phase == SE_POOL_CLEANING && meta->cookie == cookie &&
		meta->account_scope == scope &&
		meta->account_incarnation == incarnation && !meta->flags &&
		meta->active_leases == 1 &&
		meta->cleanup_done ==
			(SE_POOL_EXEC_DONE | SE_POOL_CONSTRUCTION_DONE |
			 SE_POOL_WORK_DONE | SE_POOL_NATIVE_DONE |
			 SE_POOL_DIR_DONE);
	if (valid) {
		meta->active_leases = 0;
		if (zeroed) {
			meta->cleanup_done |= SE_POOL_ZERO_DONE;
			meta->phase = SE_POOL_REFUND_PENDING;
		}
	}
	bpf_spin_unlock(&meta->lock);
	if (!valid || !zeroed)
		return SE_POOL_CORRUPT;
	return SE_POOL_PENDING_CLEANUP;
}

#ifdef ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE
/* One independently justified live-task obligation. The token must come from
 * the actual final-free path or a trusted reaper's frozen slot observation;
 * an address-only or userspace-supplied token is not authority. DEAD and no
 * active lease exclude a new exec/reader owner. Reader state is observed only
 * under the original route lock, then task identity/exec state is rechecked
 * under its metadata lock. No locks are nested and no helper runs under one.
 * This does not certify WORK, native/source, directory or payload cleanup. */
static __attribute__((noinline)) int
se_pool_task_exec_reap_step(const struct se_pool_token *token)
{
	if (!se_pool_token_valid(token))
		return SE_POOL_STALE;
	__u32 slot = token->slot, account = slot / SE_POOL_QT;
	struct se_pool_task_meta *meta =
		bpf_map_lookup_elem(&se_pool_task_meta, &slot);
	struct se_pool_task_payload *payload =
		bpf_map_lookup_elem(&se_pool_task_payload, &slot);
	struct se_route_anchor *route = se_route_anchor_lookup(&account);
	struct se_pool_bitmap *bits =
		bpf_map_lookup_elem(&se_pool_bitmaps, &account);
	struct se_pool_charge *charge =
		bpf_map_lookup_elem(&se_pool_charges, &slot);
	if (!meta || !payload || !route || !bits || !charge)
		return SE_POOL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = se_pool_match(meta, token) && se_pool_meta_valid(meta) &&
		    meta->account_slot == account &&
		    payload->semantic.physical_cookie == token->cookie &&
		    payload->semantic.scope_cookie == meta->account_scope &&
		    payload->semantic.scope_slot == account;
	__u32 phase = meta->phase, leases = meta->active_leases;
	__u32 done = meta->cleanup_done;
	__u64 scope = meta->account_scope;
	__u32 incarnation = meta->account_incarnation;
	int exec_owned = payload->semantic.exec.owned;
	bpf_spin_unlock(&meta->lock);
	if (!exact)
		return SE_POOL_STALE;
	if (phase != SE_POOL_DEAD && phase != SE_POOL_CLEANING)
		return SE_POOL_NOT_ELIGIBLE;
	if (leases || exec_owned || !(done & SE_POOL_CONSTRUCTION_DONE))
		return SE_POOL_PENDING_CLEANUP;
	__u32 local = slot - account * SE_POOL_QT;
	if (local >= SE_POOL_QT)
		return SE_POOL_CORRUPT;
	__u32 word = local / 64u;
#ifdef __BPF__
	barrier_var(word);
#endif
	if (word >= SE_POOL_TASK_WORDS)
		return SE_POOL_CORRUPT;
	__u64 bit = 1ULL << (local % 64u);
	bpf_spin_lock(&route->lock);
	int charged = !route->reserved && route->scope == scope &&
		      route->incarnation == incarnation &&
		      route->payload_slot == account && route->tasks_used &&
		      (bits->words[word] & bit) &&
		      charge->current_cookie == token->cookie &&
		      charge->account_scope == scope &&
		      charge->account_incarnation == incarnation &&
		      charge->state == SE_POOL_CH_OWNED;
	int reader_clear = !payload->semantic.reader.owned &&
			   !payload->semantic.reader.reserved &&
			   !payload->semantic.reader_invocation;
	int reader_inconsistent =
		!!payload->semantic.reader.owned !=
			!!payload->semantic.reader_invocation ||
		payload->semantic.reader.reserved;
	bpf_spin_unlock(&route->lock);
	if (!charged || reader_inconsistent)
		return SE_POOL_CORRUPT;
	if (!reader_clear)
		return SE_POOL_PENDING_CLEANUP;
	bpf_spin_lock(&meta->lock);
	exact = se_pool_match(meta, token) && se_pool_meta_valid(meta) &&
		meta->account_slot == account && meta->account_scope == scope &&
		meta->account_incarnation == incarnation &&
		(meta->phase == SE_POOL_DEAD ||
		 meta->phase == SE_POOL_CLEANING) &&
		!meta->active_leases &&
		(meta->cleanup_done & SE_POOL_CONSTRUCTION_DONE) &&
		payload->semantic.physical_cookie == token->cookie &&
		payload->semantic.scope_cookie == scope &&
		payload->semantic.scope_slot == account &&
		!payload->semantic.exec.owned;
	if (exact) {
		meta->cleanup_done |= SE_POOL_EXEC_DONE;
		meta->phase = SE_POOL_CLEANING;
	}
	bpf_spin_unlock(&meta->lock);
	return exact ? SE_POOL_OK : SE_POOL_PENDING_CLEANUP;
}

/* WORK_DONE is a separate obligation after EXEC_DONE. The sole authorized
 * producer of EXEC_DONE proved the exact original charge; DEAD forbids new
 * WORK borrows, and every attached WORK keeps work_refs until its exact owner
 * release. A charged but unattached constructor retains the TASK lease until
 * abort, so zero leases plus zero owner refs/current token is decisive here.
 * WORK payload and credit reclamation remain the WORK visitor's job. */
static __attribute__((noinline)) int
se_pool_task_work_reap_step(const struct se_pool_token *token)
{
	if (!se_pool_token_valid(token))
		return SE_POOL_STALE;
	__u32 slot = token->slot;
	struct se_pool_task_meta *meta =
		bpf_map_lookup_elem(&se_pool_task_meta, &slot);
	struct se_pool_task_payload *payload =
		bpf_map_lookup_elem(&se_pool_task_payload, &slot);
	if (!meta || !payload)
		return SE_POOL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = se_pool_match(meta, token) && se_pool_meta_valid(meta) &&
		    payload->semantic.physical_cookie == token->cookie &&
		    payload->semantic.scope_cookie == meta->account_scope &&
		    payload->semantic.scope_slot == meta->account_slot;
	int ready = meta->phase == SE_POOL_CLEANING &&
		    (meta->cleanup_done &
		     (SE_POOL_EXEC_DONE | SE_POOL_CONSTRUCTION_DONE)) ==
			    (SE_POOL_EXEC_DONE | SE_POOL_CONSTRUCTION_DONE) &&
		    !meta->active_leases && !meta->work_refs &&
		    !meta->current_work_owned && !meta->current_work_cookie &&
		    !meta->current_work_slot;
	if (exact && ready)
		meta->cleanup_done |= SE_POOL_WORK_DONE;
	bpf_spin_unlock(&meta->lock);
	return !exact ? SE_POOL_STALE :
	       ready  ? SE_POOL_OK :
			SE_POOL_PENDING_CLEANUP;
}

/* Terminal live-TASK path after the separate exec, construction, WORK and
 * native/source producers have certified their obligations. The native bit
 * has no producer here: zero native_refs alone is deliberately insufficient.
 * A trusted single-flight reaper must retain this exact token across calls.
 * Each call advances at most one durable boundary. */
static __attribute__((noinline)) int
se_pool_task_live_reap_step(const struct se_pool_token *token)
{
	if (!se_pool_token_valid(token))
		return SE_POOL_STALE;
	__u32 slot = token->slot, account = slot / SE_POOL_QT;
	struct se_route_anchor *route = se_route_anchor_lookup(&account);
	struct se_pool_bitmap *bits =
		bpf_map_lookup_elem(&se_pool_bitmaps, &account);
	struct se_pool_charge *charge =
		bpf_map_lookup_elem(&se_pool_charges, &slot);
	struct se_pool_task_meta *meta =
		bpf_map_lookup_elem(&se_pool_task_meta, &slot);
	struct se_pool_task_payload *payload =
		bpf_map_lookup_elem(&se_pool_task_payload, &slot);
	__u32 bucket = se_pool_bucket(token->address), zero = 0;
	struct se_pool_directory *directory =
		bpf_map_lookup_elem(&se_pool_directory, &bucket);
	if (!route || !bits || !charge || !meta || !payload || !directory)
		return SE_POOL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	int exact = se_pool_match(meta, token) && se_pool_meta_valid(meta) &&
		    meta->account_slot == account &&
		    (meta->flags & SE_POOL_PUBLISHED);
	__u32 phase = meta->phase, done = meta->cleanup_done;
	__u64 scope = meta->account_scope;
	__u32 incarnation = meta->account_incarnation;
	int refs_clear = !meta->active_leases && !meta->work_refs &&
			 !meta->native_refs && !meta->directory_holds &&
			 !meta->current_work_owned &&
			 !meta->current_work_cookie &&
			 !meta->current_work_slot && !meta->cleanup_error;
	bpf_spin_unlock(&meta->lock);
	if (!exact)
		return SE_POOL_STALE;
	if (phase == SE_POOL_REFUND_PENDING || phase == SE_POOL_FREE)
		return se_pool_task_refund_tail(route, bits, charge, meta,
						slot);
	if (phase != SE_POOL_CLEANING)
		return SE_POOL_NOT_ELIGIBLE;
	const __u32 obligations = SE_POOL_EXEC_DONE |
				  SE_POOL_CONSTRUCTION_DONE |
				  SE_POOL_WORK_DONE | SE_POOL_NATIVE_DONE;
	if ((done & obligations) != obligations)
		return SE_POOL_PENDING_CLEANUP;
	if (!refs_clear)
		return SE_POOL_PENDING_CLEANUP;
	__u32 local = slot - account * SE_POOL_QT;
	if (local >= SE_POOL_QT)
		return SE_POOL_CORRUPT;
	__u32 word = local / 64u;
#ifdef __BPF__
	barrier_var(word);
#endif
	if (word >= SE_POOL_TASK_WORDS)
		return SE_POOL_CORRUPT;
	__u64 bit = 1ULL << (local % 64u);
	bpf_spin_lock(&route->lock);
	int charged = !route->reserved && route->scope == scope &&
		      route->incarnation == incarnation &&
		      route->payload_slot == account && route->tasks_used &&
		      (bits->words[word] & bit) &&
		      charge->current_cookie == token->cookie &&
		      charge->account_scope == scope &&
		      charge->account_incarnation == incarnation &&
		      charge->state == SE_POOL_CH_OWNED;
	bpf_spin_unlock(&route->lock);
	if (!charged)
		return SE_POOL_CORRUPT;
	if (!(done & SE_POOL_DIR_DONE)) {
		bpf_spin_lock(&meta->lock);
		int claimed = !!(meta->flags & SE_POOL_DIR_CLAIM);
		bpf_spin_unlock(&meta->lock);
		if (claimed)
			return SE_POOL_CORRUPT; /* unresolved unlink, never retry blind */
		int status = se_pool_dir_cleanup(directory, meta, token);
		return status == SE_POOL_OK ? SE_POOL_PENDING_CLEANUP : status;
	}
	const struct se_pool_task_payload *empty =
		bpf_map_lookup_elem(&se_pool_task_zero, &zero);
	if (!empty)
		return SE_POOL_CORRUPT;
	bpf_spin_lock(&meta->lock);
	exact = se_pool_match(meta, token) && se_pool_meta_valid(meta) &&
		meta->phase == SE_POOL_CLEANING &&
		meta->account_scope == scope &&
		meta->account_incarnation == incarnation &&
		meta->cleanup_done == (obligations | SE_POOL_DIR_DONE) &&
		!meta->active_leases && !meta->work_refs &&
		!meta->native_refs && !meta->directory_holds &&
		!meta->current_work_owned && !meta->current_work_cookie &&
		!meta->current_work_slot && !meta->cleanup_error &&
		payload->semantic.physical_cookie == token->cookie &&
		payload->semantic.scope_cookie == scope &&
		payload->semantic.scope_slot == account;
	if (exact)
		meta->active_leases = 1; /* exclusive zero-write claim */
	bpf_spin_unlock(&meta->lock);
	if (!exact)
		return SE_POOL_PENDING_CLEANUP;
	int zeroed = !bpf_map_update_elem(&se_pool_task_payload, &slot, empty,
					  BPF_ANY);
	bpf_spin_lock(&meta->lock);
	exact = se_pool_match(meta, token) && se_pool_meta_valid(meta) &&
		meta->phase == SE_POOL_CLEANING &&
		meta->account_scope == scope &&
		meta->account_incarnation == incarnation &&
		meta->active_leases == 1 &&
		meta->cleanup_done == (obligations | SE_POOL_DIR_DONE);
	if (exact) {
		meta->active_leases = 0;
		if (zeroed) {
			meta->cleanup_done |= SE_POOL_ZERO_DONE;
			meta->phase = SE_POOL_REFUND_PENDING;
		}
	}
	bpf_spin_unlock(&meta->lock);
	return exact && zeroed ? SE_POOL_PENDING_CLEANUP : SE_POOL_CORRUPT;
}
#endif
#endif
