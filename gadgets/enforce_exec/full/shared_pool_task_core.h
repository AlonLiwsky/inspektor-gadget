/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_TASK_CORE_H
#define ENFORCE_EXEC_SHARED_POOL_TASK_CORE_H
#if !defined(ENFORCE_EXEC_POOL_DEVELOPMENT) || \
	!defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY)
#error "task core is candidate-only"
#endif
/* Requires shared_route.h and shared_pool_abi_candidate.h. Caller prefetches
 * fixed ARRAY pointers before any lock. No helper is called while locked.
 * Every post-charge failure must invoke se_pool_task_complete. */
#define SE_POOL_LIMIT (~(__u64)0 - 1)
#define SE_POOL_U32MAX ((__u32)~0u)
enum se_pool_phase {
	SE_POOL_FREE = 0,
	SE_POOL_RESERVED,
	SE_POOL_INITIALIZING,
	SE_POOL_PENDING_BIRTH,
	SE_POOL_LIVE,
	SE_POOL_DEAD,
	SE_POOL_ABORTED,
	SE_POOL_CLEANING,
	SE_POOL_REFUND_PENDING
};
enum se_pool_status {
	SE_POOL_OK = 0,
	SE_POOL_MISSING,
	SE_POOL_STALE,
	SE_POOL_NOT_ELIGIBLE,
	SE_POOL_LIMITED,
	SE_POOL_CORRUPT,
	SE_POOL_CONTENDED,
	SE_POOL_PENDING_CLEANUP,
	SE_POOL_CAPACITY,
	SE_POOL_DIRECTORY_CAPACITY,
	SE_POOL_ALREADY_RETURNED
};
enum {
	SE_POOL_PUBLISHED = 1,
	SE_POOL_DIR_CLAIM = 2,
	SE_POOL_EXEC_DONE = 1,
	SE_POOL_CONSTRUCTION_DONE = 2,
	SE_POOL_WORK_DONE = 4,
	SE_POOL_NATIVE_DONE = 8,
	SE_POOL_DIR_DONE = 16,
	SE_POOL_ZERO_DONE = 32
};
struct se_pool_token {
	__u64 address, cookie;
	__u32 slot, reserved;
};
struct se_pool_lease {
	struct se_pool_token token;
	__u32 held, reserved;
};
struct task_struct;
/* Stack-local final-free capability. The actual hook argument is retained as a
 * pointer, and the full slot/cookie/address token is never rediscovered. */
struct se_pool_final_free_lease {
	struct se_pool_token token;
	struct task_struct *physical;
	__u32 held, death_recorded;
};
struct se_pool_hold {
	struct se_pool_token old, new;
	__u32 held, reserved;
};
#define SE_POOL_INLINE static __attribute__((always_inline)) inline

_Static_assert(SE_POOL_RESERVED == 1 && SE_POOL_INITIALIZING == 2 &&
		       SE_POOL_PENDING_BIRTH == 3 && SE_POOL_LIVE == 4 &&
		       SE_POOL_DEAD == 5 && SE_POOL_ABORTED == 6 &&
		       SE_POOL_CLEANING == 7,
	       "task phase values");
_Static_assert(SE_POOL_MISSING == 1 && SE_POOL_STALE == 2 &&
		       SE_POOL_NOT_ELIGIBLE == 3 && SE_POOL_LIMITED == 4 &&
		       SE_POOL_CORRUPT == 5 && SE_POOL_CONTENDED == 6,
	       "status values");
_Static_assert(SE_POOL_PUBLISHED == 1 && SE_POOL_DIR_CLAIM == 2 &&
		       SE_POOL_EXEC_DONE == 1 &&
		       SE_POOL_CONSTRUCTION_DONE == 2 &&
		       SE_POOL_WORK_DONE == 4 && SE_POOL_NATIVE_DONE == 8 &&
		       SE_POOL_DIR_DONE == 16 && SE_POOL_ZERO_DONE == 32,
	       "task flags and cleanup bits");
_Static_assert(SE_POOL_FREE == 0 && SE_POOL_REFUND_PENDING == 8 &&
		       SE_POOL_OK == 0 && SE_POOL_PENDING_CLEANUP == 7 &&
		       SE_POOL_CAPACITY == 8 &&
		       SE_POOL_DIRECTORY_CAPACITY == 9 &&
		       SE_POOL_ALREADY_RETURNED == 10,
	       "frozen enum values");
_Static_assert(SE_POOL_D && !(SE_POOL_D & (SE_POOL_D - 1)),
	       "power of two buckets");
_Static_assert(SE_POOL_TASK_WORDS <= 128, "bounded task bitmap scan");
SE_POOL_INLINE __u32 se_pool_bucket(__u64 x)
{
	x ^= x >> 30;
	x *= 0xbf58476d1ce4e5b9ULL;
	x ^= x >> 27;
	x *= 0x94d049bb133111ebULL;
	x ^= x >> 31;
	return (__u32)(x & (SE_POOL_D - 1u));
}
/* Map lookups precede locks. Lease/hold objects are caller-owned stack
 * capabilities, never wire inputs. */
SE_POOL_INLINE int se_pool_token_valid(const struct se_pool_token *t)
{
	return t && t->address && t->cookie && t->cookie <= SE_POOL_LIMIT &&
	       t->slot < SE_POOL_T && !t->reserved;
}
SE_POOL_INLINE int se_pool_same(const struct se_pool_token *a,
				const struct se_pool_token *b)
{
	return a->address == b->address && a->cookie == b->cookie &&
	       a->slot == b->slot && !a->reserved && !b->reserved;
}
SE_POOL_INLINE int se_pool_match(const struct se_pool_task_meta *m,
				 const struct se_pool_token *t)
{
	return m->cookie == t->cookie && m->physical_address == t->address &&
	       m->slot == t->slot;
}
SE_POOL_INLINE int se_pool_meta_valid(const struct se_pool_task_meta *m)
{
	return m->phase <= SE_POOL_REFUND_PENDING && m->cookie &&
	       m->cookie <= SE_POOL_LIMIT && m->physical_address &&
	       m->slot < SE_POOL_T && m->account_slot < SE_POOL_B &&
	       m->account_scope && m->account_incarnation &&
	       !(m->flags & ~3u) && !(m->cleanup_done & ~63u) &&
	       !m->reserved0 && !m->reserved1 && !m->reserved2 &&
	       !m->reserved3 && m->current_work_owned <= 1 &&
	       (!m->current_work_owned ?
			(!m->current_work_cookie && !m->current_work_slot) :
			(m->current_work_cookie &&
			 m->current_work_cookie <= SE_POOL_LIMIT &&
			 m->current_work_slot < SE_POOL_W));
}
SE_POOL_INLINE int se_pool_find_locked(const struct se_pool_directory *d,
				       __u64 address, int *index)
{
	int found = -1;
	if (d->reserved)
		return SE_POOL_CORRUPT;
#ifdef __clang__
#pragma unroll
#endif
	for (int i = 0; i < 16; i++) {
		const struct se_pool_way *w = &d->ways[i];
		if (!w->cookie) {
			if (w->address || w->slot || w->reserved)
				return SE_POOL_CORRUPT;
			continue;
		}
		if (!w->address || w->cookie > SE_POOL_LIMIT ||
		    w->slot >= SE_POOL_T || w->reserved)
			return SE_POOL_CORRUPT;
		if (w->address == address) {
			if (found >= 0)
				return SE_POOL_CORRUPT;
			found = i;
		}
	}
	*index = found;
	return found < 0 ? SE_POOL_MISSING : SE_POOL_OK;
}
SE_POOL_INLINE int se_pool_lookup(struct se_pool_directory *d, __u64 address,
				  struct se_pool_token *out)
{
	if (!d || !out || !address)
		return SE_POOL_MISSING;
	int index = -1;
	bpf_spin_lock(&d->lock);
	int r = se_pool_find_locked(d, address, &index);
	if (r == SE_POOL_OK) {
		out->address = d->ways[index].address;
		out->cookie = d->ways[index].cookie;
		out->slot = d->ways[index].slot;
		out->reserved = 0;
	}
	bpf_spin_unlock(&d->lock);
	return r;
}
SE_POOL_INLINE int se_pool_borrow(struct se_pool_task_meta *m,
				  const struct se_pool_token *t,
				  struct se_pool_lease *l)
{
	if (!m || !se_pool_token_valid(t) || !l || l->held || l->reserved)
		return SE_POOL_STALE;
	int r = SE_POOL_OK;
	bpf_spin_lock(&m->lock);
	if (!se_pool_match(m, t) || m->phase == SE_POOL_FREE)
		r = SE_POOL_STALE;
	else if (!se_pool_meta_valid(m))
		r = SE_POOL_CORRUPT;
	else if (m->phase != SE_POOL_LIVE)
		r = SE_POOL_NOT_ELIGIBLE;
	else if (m->active_leases == SE_POOL_U32MAX)
		r = SE_POOL_LIMITED;
	else {
		m->active_leases++;
		l->token = *t;
		l->held = 1;
	}
	bpf_spin_unlock(&m->lock);
	return r;
}
SE_POOL_INLINE int se_pool_release(struct se_pool_task_meta *m,
				   struct se_pool_lease *l)
{
	if (!m || !l || l->held != 1 || l->reserved ||
	    !se_pool_token_valid(&l->token))
		return SE_POOL_CORRUPT;
	int r = SE_POOL_OK;
	bpf_spin_lock(&m->lock);
	if (!se_pool_match(m, &l->token) || !se_pool_meta_valid(m) ||
	    !m->active_leases ||
	    (m->phase != SE_POOL_LIVE && m->phase != SE_POOL_PENDING_BIRTH &&
	     m->phase != SE_POOL_DEAD && m->phase != SE_POOL_CLEANING))
		r = SE_POOL_CORRUPT;
	else {
		m->active_leases--;
		l->held = 0;
	}
	bpf_spin_unlock(&m->lock);
	return r;
}
/* Only the actual task_free adapter can supply physical. Capture the full
 * lifetime token before this call; a directory lookup by address is not proof. */
SE_POOL_INLINE int
se_pool_final_free_acquire(struct task_struct *physical,
			   struct se_pool_task_meta *m,
			   const struct se_pool_token *captured,
			   struct se_pool_final_free_lease *lease)
{
	if (!physical || !m || !se_pool_token_valid(captured) || !lease ||
	    lease->held || lease->death_recorded || lease->physical ||
	    (__u64)physical != captured->address)
		return SE_POOL_STALE;
	__u32 slot = captured->slot;
	if (m != bpf_map_lookup_elem(&se_pool_task_meta, &slot))
		return SE_POOL_STALE;
	int r = SE_POOL_OK;
	bpf_spin_lock(&m->lock);
	if (!se_pool_match(m, captured) || m->phase == SE_POOL_FREE)
		r = SE_POOL_STALE;
	else if (!se_pool_meta_valid(m))
		r = SE_POOL_CORRUPT;
	else if (m->phase != SE_POOL_LIVE && m->phase != SE_POOL_PENDING_BIRTH)
		r = SE_POOL_NOT_ELIGIBLE;
	else if (m->active_leases == SE_POOL_U32MAX)
		r = SE_POOL_LIMITED;
	else {
		m->active_leases++;
		lease->token = *captured;
		lease->physical = physical;
		lease->held = 1;
	}
	bpf_spin_unlock(&m->lock);
	return r;
}
/* Record DEAD before dropping this independent lease. A constructor may still
 * hold its own lease while the child is PENDING_BIRTH. */
SE_POOL_INLINE int
se_pool_death_at_final_free(struct task_struct *physical,
			    struct se_pool_task_meta *m,
			    struct se_pool_final_free_lease *lease)
{
	if (!physical || !m || !lease || lease->held != 1 ||
	    lease->death_recorded || lease->physical != physical ||
	    !se_pool_token_valid(&lease->token) ||
	    (__u64)physical != lease->token.address)
		return SE_POOL_STALE;
	__u32 slot = lease->token.slot;
	if (m != bpf_map_lookup_elem(&se_pool_task_meta, &slot))
		return SE_POOL_STALE;
	int r = SE_POOL_OK;
	bpf_spin_lock(&m->lock);
	if (!se_pool_match(m, &lease->token) || m->phase == SE_POOL_FREE)
		r = SE_POOL_STALE;
	else if (!se_pool_meta_valid(m) || !m->active_leases)
		r = SE_POOL_CORRUPT;
	else if (m->phase != SE_POOL_LIVE && m->phase != SE_POOL_PENDING_BIRTH)
		r = SE_POOL_NOT_ELIGIBLE;
	else {
		m->phase = SE_POOL_DEAD;
		lease->death_recorded = 1;
	}
	bpf_spin_unlock(&m->lock);
	return r;
}
SE_POOL_INLINE int
se_pool_final_free_release(struct se_pool_task_meta *m,
			   struct se_pool_final_free_lease *lease)
{
	if (!m || !lease || lease->held != 1 || lease->death_recorded != 1 ||
	    !lease->physical || !se_pool_token_valid(&lease->token) ||
	    (__u64)lease->physical != lease->token.address)
		return SE_POOL_CORRUPT;
	__u32 slot = lease->token.slot;
	if (m != bpf_map_lookup_elem(&se_pool_task_meta, &slot))
		return SE_POOL_CORRUPT;
	int r = SE_POOL_OK;
	bpf_spin_lock(&m->lock);
	if (!se_pool_match(m, &lease->token) || !se_pool_meta_valid(m) ||
	    (m->phase != SE_POOL_DEAD && m->phase != SE_POOL_CLEANING) ||
	    !m->active_leases)
		r = SE_POOL_CORRUPT;
	else {
		m->active_leases--;
		lease->held = 0;
		lease->physical = 0;
	}
	bpf_spin_unlock(&m->lock);
	return r;
}
SE_POOL_INLINE int se_pool_hold_old(struct se_pool_task_meta *n,
				    struct se_pool_task_meta *o,
				    const struct se_pool_token *nt,
				    const struct se_pool_token *ot,
				    struct se_pool_hold *h)
{
	if (!n || !o || n == o || !se_pool_token_valid(nt) ||
	    !se_pool_token_valid(ot) || nt->address != ot->address ||
	    nt->slot == ot->slot || nt->cookie == ot->cookie || !h || h->held ||
	    h->reserved)
		return SE_POOL_CORRUPT;
	bpf_spin_lock(&n->lock);
	int valid = se_pool_match(n, nt) && se_pool_meta_valid(n) &&
		    n->phase == SE_POOL_INITIALIZING && n->active_leases &&
		    n->flags == 0 && n->cleanup_done == 0;
	bpf_spin_unlock(&n->lock);
	if (!valid)
		return SE_POOL_CORRUPT;
	int r = SE_POOL_OK;
	bpf_spin_lock(&o->lock);
	/* This old locator was observed without a lifetime hold: retirement/reuse
  * before acquisition is ordinary contention, not protected-state corruption. */
	if (!se_pool_match(o, ot))
		r = SE_POOL_CONTENDED;
	else if (!se_pool_meta_valid(o))
		r = SE_POOL_CORRUPT;
	else if ((o->phase != SE_POOL_DEAD && o->phase != SE_POOL_CLEANING) ||
		 o->flags != SE_POOL_PUBLISHED ||
		 (o->cleanup_done & SE_POOL_DIR_DONE))
		r = SE_POOL_CONTENDED;
	else if (o->directory_holds == SE_POOL_U32MAX)
		r = SE_POOL_LIMITED;
	else {
		o->directory_holds++;
		h->old = *ot;
		h->new = *nt;
		h->held = 1;
	}
	bpf_spin_unlock(&o->lock);
	return r;
}
SE_POOL_INLINE int se_pool_drop_hold(struct se_pool_task_meta *o,
				     struct se_pool_hold *h)
{
	if (!o || !h || h->held != 1 || h->reserved ||
	    !se_pool_token_valid(&h->old))
		return SE_POOL_CORRUPT;
	int r = SE_POOL_OK;
	bpf_spin_lock(&o->lock);
	if (!se_pool_match(o, &h->old) || !se_pool_meta_valid(o) ||
	    !o->directory_holds)
		r = SE_POOL_CORRUPT;
	else {
		o->directory_holds--;
		h->held = 0;
	}
	bpf_spin_unlock(&o->lock);
	return r;
}
SE_POOL_INLINE int se_pool_replace(struct se_pool_directory *d,
				   struct se_pool_task_meta *n,
				   struct se_pool_task_meta *o,
				   struct se_pool_hold *h)
{
	if (!d || !n || !o || n == o || !h || h->held != 1 || h->reserved ||
	    !se_pool_token_valid(&h->old) || !se_pool_token_valid(&h->new) ||
	    h->old.address != h->new.address || h->old.slot == h->new.slot)
		return SE_POOL_CORRUPT;
	bpf_spin_lock(&n->lock);
	int nv = se_pool_match(n, &h->new) && se_pool_meta_valid(n) &&
		 n->phase == SE_POOL_INITIALIZING && n->active_leases &&
		 n->flags == 0 && n->cleanup_done == 0;
	bpf_spin_unlock(&n->lock);
	bpf_spin_lock(&o->lock);
	int ov = se_pool_match(o, &h->old) && se_pool_meta_valid(o) &&
		 o->directory_holds &&
		 (o->phase == SE_POOL_DEAD || o->phase == SE_POOL_CLEANING) &&
		 o->flags == SE_POOL_PUBLISHED;
	bpf_spin_unlock(&o->lock);
	if (!nv || !ov)
		return SE_POOL_CORRUPT; /* Owned hold remains explicit for caller abort. */
	int index = -1;
	bpf_spin_lock(&d->lock);
	int r = se_pool_find_locked(d, h->old.address, &index);
	if (r == SE_POOL_OK) {
		struct se_pool_way *w = &d->ways[index];
		if (w->cookie != h->old.cookie || w->slot != h->old.slot)
			r = SE_POOL_CONTENDED;
		else {
			w->address = h->new.address;
			w->cookie = h->new.cookie;
			w->slot = h->new.slot;
			w->reserved = 0;
		}
	} else if (r == SE_POOL_MISSING)
		r = SE_POOL_CONTENDED;
	bpf_spin_unlock(&d->lock);
	if (r != SE_POOL_OK) {
		int dropped = se_pool_drop_hold(o, h);
		return dropped == SE_POOL_OK ? r : SE_POOL_CORRUPT;
	}
	/* NON-RETURN GROUP after successful comparison. Stable old hold/new constructor
  * lease protect identities. No lookup, fallible helper or early return. */
	bpf_spin_lock(&o->lock);
	o->cleanup_done |= SE_POOL_DIR_DONE;
	o->directory_holds--;
	bpf_spin_unlock(&o->lock);
	bpf_spin_lock(&n->lock);
	n->flags |= SE_POOL_PUBLISHED;
	n->phase = SE_POOL_PENDING_BIRTH;
	bpf_spin_unlock(&n->lock);
	h->held = 0;
	return SE_POOL_OK;
}
SE_POOL_INLINE int se_pool_dir_cleanup(struct se_pool_directory *d,
				       struct se_pool_task_meta *m,
				       const struct se_pool_token *t)
{
	if (!d || !m || !se_pool_token_valid(t))
		return SE_POOL_CORRUPT;
	int published = 0;
	bpf_spin_lock(&m->lock);
	if (!se_pool_match(m, t) || !se_pool_meta_valid(m) ||
	    m->phase != SE_POOL_CLEANING) {
		bpf_spin_unlock(&m->lock);
		return SE_POOL_CORRUPT;
	}
	/* Holds must gate ALL cleanup, even after another contender recorded DIR_DONE. */
	if (m->active_leases || m->directory_holds || m->work_refs ||
	    m->native_refs || m->current_work_owned ||
	    (m->cleanup_done & 15u) != 15u) {
		bpf_spin_unlock(&m->lock);
		return SE_POOL_PENDING_CLEANUP;
	}
	if (m->cleanup_done & SE_POOL_DIR_DONE) {
		bpf_spin_unlock(&m->lock);
		return SE_POOL_OK;
	}
	published = !!(m->flags & SE_POOL_PUBLISHED);
	m->flags |= SE_POOL_DIR_CLAIM;
	if (!published) {
		m->cleanup_done |= SE_POOL_DIR_DONE;
		bpf_spin_unlock(&m->lock);
		return SE_POOL_OK;
	}
	bpf_spin_unlock(&m->lock);
	int index = -1;
	bpf_spin_lock(&d->lock);
	int r = se_pool_find_locked(d, t->address, &index);
	if (r == SE_POOL_OK) {
		struct se_pool_way *w = &d->ways[index];
		if (w->cookie != t->cookie || w->slot != t->slot)
			r = SE_POOL_CORRUPT;
		else {
			w->address = 0;
			w->cookie = 0;
			w->slot = 0;
			w->reserved = 0;
		}
	} else
		r = SE_POOL_CORRUPT;
	bpf_spin_unlock(&d->lock);
	if (r != SE_POOL_OK)
		return r; /* Claimed+charged state remains for structural diagnosis. */
	bpf_spin_lock(&m->lock);
	m->cleanup_done |= SE_POOL_DIR_DONE;
	bpf_spin_unlock(&m->lock);
	return SE_POOL_OK;
}

struct se_pool_account_token {
	__u64 scope;
	__u32 route_slot, incarnation;
};
struct se_pool_reservation {
	struct se_pool_account_token account;
	__u64 cookie, physical_address;
	__u32 pool_slot, kind, held, reserved;
	/* Stack-only charge capability. Set once with held at the successful charge;
  * never sourced from a map or wire value. The pointer and inverse detect an
  * independently damaged slot/anchor before any post-charge write. */
	__u32 charged_slot, charged_slot_inverse;
	struct se_pool_charge *charged_charge;
};
enum se_pool_charge_state {
	SE_POOL_CH_FREE = 0,
	SE_POOL_CH_BUILDING = 1,
	SE_POOL_CH_OWNED = 2,
	SE_POOL_CH_RETURN_READY = 3,
	SE_POOL_CH_FAULT_HELD = 4
};
enum { SE_POOL_KIND_INVALID = 0, SE_POOL_KIND_TASK = 1, SE_POOL_KIND_WORK = 2 };

SE_POOL_INLINE __u32 se_pool_first_bit(__u64 x)
{
	__u32 n = 0;
	if (!(x & 0xffffffffULL)) {
		n += 32;
		x >>= 32;
	}
	if (!(x & 0xffffULL)) {
		n += 16;
		x >>= 16;
	}
	if (!(x & 0xffULL)) {
		n += 8;
		x >>= 8;
	}
	if (!(x & 0xfULL)) {
		n += 4;
		x >>= 4;
	}
	if (!(x & 3ULL)) {
		n += 2;
		x >>= 2;
	}
	if (!(x & 1ULL))
		n++;
	return n;
}
SE_POOL_INLINE int
se_pool_reservation_valid(const struct se_pool_reservation *r)
{
	return r && r->kind == SE_POOL_KIND_TASK && !r->reserved &&
	       r->physical_address && r->physical_address <= SE_POOL_LIMIT &&
	       r->account.scope && r->account.scope <= SE_POOL_LIMIT &&
	       r->account.incarnation && r->account.route_slot < SE_POOL_B &&
	       r->pool_slot >= r->account.route_slot * SE_POOL_QT &&
	       r->pool_slot < (r->account.route_slot + 1) * SE_POOL_QT;
}
SE_POOL_INLINE int
se_pool_charged_slot_valid(const struct se_pool_reservation *r)
{
	return r && r->held == 1 && r->charged_slot < SE_POOL_T &&
	       r->charged_slot < SE_POOL_B * SE_POOL_QT &&
	       r->charged_slot_inverse == ~r->charged_slot &&
	       r->pool_slot == r->charged_slot && r->charged_charge;
}
SE_POOL_INLINE int se_pool_task_select(struct se_route_anchor *a,
				       const struct se_route_claim *c,
				       struct se_pool_bitmap *b, __u64 address,
				       struct se_pool_reservation *r)
{
	if (!a || !c || !b || !r || !address || address > SE_POOL_LIMIT ||
	    r->held || r->reserved)
		return SE_POOL_CORRUPT;
	int status = SE_POOL_OK;
	__u32 selected = SE_POOL_QT;
	bpf_spin_lock(&a->lock);
	if (!se_route_claim_valid(a, c))
		status = SE_POOL_STALE;
	else if (a->reserved || b->header.reserved0 || b->header.reserved1 ||
		 b->header.task_hint >= SE_POOL_QT ||
		 b->header.work_hint >= SE_POOL_QW ||
		 a->tasks_used > SE_POOL_QT)
		status = SE_POOL_CORRUPT;
	else {
		__u64 available_word = 0;
		__u32 selected_word = SE_POOL_TASK_WORDS;
#if SE_POOL_QT % 64u
		if (b->words[SE_POOL_TASK_WORDS - 1] &
		    (~0ULL << (SE_POOL_QT % 64u)))
			status = SE_POOL_CORRUPT;
#endif
#ifdef __clang__
#pragma unroll
#endif
		for (__u32 i = 0; i < SE_POOL_TASK_WORDS; i++) {
			__u64 mask = ~0ULL;
#if SE_POOL_QT % 64u
			if (i == SE_POOL_TASK_WORDS - 1)
				mask >>= (64u - SE_POOL_QT % 64u);
#endif
			__u64 available = ~b->words[i] & mask;
			if (available) {
				selected_word = i;
				available_word = available;
				break;
			}
		}
		if (available_word)
			selected = selected_word * 64u +
				   se_pool_first_bit(available_word);
		if (status == SE_POOL_OK) {
			if (selected == SE_POOL_QT)
				status = a->tasks_used == SE_POOL_QT ?
						 SE_POOL_CAPACITY :
						 SE_POOL_CORRUPT;
			else if (a->tasks_used >= SE_POOL_QT)
				status = SE_POOL_CORRUPT;
			else
				*r = (struct se_pool_reservation){
					.account = { a->scope, c->slot,
						     a->incarnation },
					.physical_address = address,
					.pool_slot =
						c->slot * SE_POOL_QT + selected,
					.kind = SE_POOL_KIND_TASK
				};
		}
	}
	bpf_spin_unlock(&a->lock);
	return status;
}
SE_POOL_INLINE int se_pool_next_cookie(struct se_pool_sequence *s,
				       struct se_pool_reservation *r)
{
	if (!s || !se_pool_reservation_valid(r) || r->held || r->cookie)
		return SE_POOL_CORRUPT;
	int status = SE_POOL_OK;
	bpf_spin_lock(&s->lock);
	if (s->reserved)
		status = SE_POOL_CORRUPT;
	else if (s->next >= SE_POOL_LIMIT)
		status = SE_POOL_LIMITED;
	else
		r->cookie = ++s->next;
	bpf_spin_unlock(&s->lock);
	return status;
}
/* The account's ARRAY value, not a matching scalar tuple, owns this lock. */
SE_POOL_INLINE int se_pool_task_charge(struct se_route_anchor *a,
				       const struct se_route_claim *c,
				       struct se_pool_bitmap *b,
				       struct se_pool_charge *ch,
				       struct se_pool_reservation *r)
{
	if (!c || !se_pool_reservation_valid(r) || !r->cookie ||
	    r->cookie > SE_POOL_LIMIT || r->held || r->charged_charge ||
	    r->charged_slot || r->charged_slot_inverse)
		return SE_POOL_CORRUPT;
	__u32 slot = r->pool_slot, account = r->account.route_slot;
	struct se_route_anchor *exact_a = se_route_anchor_lookup(&account);
	struct se_pool_charge *exact_ch =
		bpf_map_lookup_elem(&se_pool_charges, &slot);
	struct se_pool_bitmap *exact_b =
		bpf_map_lookup_elem(&se_pool_bitmaps, &account);
	if (!exact_a)
		return SE_POOL_CORRUPT;
	if (!exact_ch || !exact_b || a != exact_a || ch != exact_ch ||
	    b != exact_b) {
		bpf_spin_lock(&exact_a->lock);
		exact_a->reserved = 1;
		bpf_spin_unlock(&exact_a->lock);
		return SE_POOL_CORRUPT;
	}
	__u32 local = slot - account * SE_POOL_QT, word = local / 64u;
	__u64 mask = 1ULL << (local % 64u);
	int status = SE_POOL_OK;
	bpf_spin_lock(&exact_a->lock);
	if (!se_route_claim_valid(exact_a, c) ||
	    exact_a->scope != r->account.scope ||
	    exact_a->incarnation != r->account.incarnation ||
	    exact_a->payload_slot != account)
		status = SE_POOL_STALE;
	else if (exact_ch->last_returned_cookie > SE_POOL_LIMIT ||
		 r->cookie <= exact_ch->last_returned_cookie) {
		status = SE_POOL_CORRUPT;
		exact_a->reserved = 1;
	} else if (exact_b->words[word] & mask)
		status = SE_POOL_CONTENDED;
	else if (exact_a->reserved || exact_b->header.reserved0 ||
		 exact_b->header.reserved1 ||
		 exact_b->header.task_hint >= SE_POOL_QT ||
		 exact_b->header.work_hint >= SE_POOL_QW ||
		 exact_a->tasks_used >= SE_POOL_QT ||
		 exact_ch->state != SE_POOL_CH_FREE ||
		 exact_ch->current_cookie || exact_ch->account_scope ||
		 exact_ch->account_incarnation)
		status = SE_POOL_CORRUPT;
	else {
		exact_b->words[word] |= mask;
		exact_a->tasks_used++;
		exact_b->header.task_hint = (local + 1) % SE_POOL_QT;
		exact_ch->current_cookie = r->cookie;
		exact_ch->account_scope = r->account.scope;
		exact_ch->account_incarnation = r->account.incarnation;
		exact_ch->state = SE_POOL_CH_BUILDING;
		r->charged_slot = slot;
		r->charged_slot_inverse = ~slot;
		r->charged_charge = exact_ch;
		r->held = 1;
	}
	bpf_spin_unlock(&exact_a->lock);
	return status;
}
SE_POOL_INLINE struct se_pool_token
se_pool_reservation_token(const struct se_pool_reservation *r)
{
	return (struct se_pool_token){ r->physical_address, r->cookie,
				       r->pool_slot, 0 };
}
SE_POOL_INLINE int se_pool_task_initialize(struct se_pool_task_meta *m,
					   const struct se_pool_reservation *r)
{
	if (!m || !se_pool_charged_slot_valid(r) ||
	    !se_pool_reservation_valid(r) || !r->cookie ||
	    r->cookie > SE_POOL_LIMIT)
		return SE_POOL_CORRUPT;
	__u32 slot = r->charged_slot;
	if (r->charged_charge != bpf_map_lookup_elem(&se_pool_charges, &slot) ||
	    m != bpf_map_lookup_elem(&se_pool_task_meta, &slot))
		return SE_POOL_CORRUPT;
	int status = SE_POOL_OK;
	bpf_spin_lock(&m->lock);
	if (m->phase != SE_POOL_FREE || m->active_leases || m->work_refs ||
	    m->native_refs || m->directory_holds || m->current_work_owned ||
	    m->current_work_cookie || m->current_work_slot || m->reserved0 ||
	    m->reserved1 || m->reserved2 || m->reserved3 ||
	    m->cookie > SE_POOL_LIMIT || (m->flags & ~3u) ||
	    (m->cookie ?
		     (m->slot != r->pool_slot || m->cleanup_done != 63u) :
		     (m->physical_address || m->account_scope || m->slot ||
		      m->account_slot || m->account_incarnation ||
		      m->cleanup_done || m->flags || m->next_work_sequence ||
		      m->cleanup_error || m->last_reap_sequence)))
		status = SE_POOL_CORRUPT;
	else {
		/* Do not overwrite live lock; all other fixed metadata is constructor owned. */
		m->phase = SE_POOL_INITIALIZING;
		m->cookie = r->cookie;
		m->physical_address = r->physical_address;
		m->account_scope = r->account.scope;
		m->slot = r->pool_slot;
		m->account_slot = r->account.route_slot;
		m->account_incarnation = r->account.incarnation;
		m->active_leases = 1;
		m->work_refs = 0;
		m->native_refs = 0;
		m->cleanup_done = 0;
		m->flags = 0;
		m->directory_holds = 0;
		m->reserved0 = 0;
		m->next_work_sequence = 0;
		m->current_work_cookie = 0;
		m->current_work_slot = 0;
		m->current_work_owned = 0;
		m->cleanup_error = 0;
		m->reserved1 = 0;
		m->last_reap_sequence = 0;
		m->reserved2 = 0;
		m->reserved3 = 0;
	}
	bpf_spin_unlock(&m->lock);
	return status;
}
SE_POOL_INLINE int se_pool_publish_first(struct se_pool_directory *d,
					 struct se_pool_task_meta *m,
					 const struct se_pool_token *t)
{
	if (!d || !m || !se_pool_token_valid(t))
		return SE_POOL_CORRUPT;
	bpf_spin_lock(&m->lock);
	int valid = se_pool_match(m, t) && se_pool_meta_valid(m) &&
		    m->phase == SE_POOL_INITIALIZING && m->active_leases == 1 &&
		    !m->flags && !m->cleanup_done;
	bpf_spin_unlock(&m->lock);
	if (!valid)
		return SE_POOL_CORRUPT;
	int index = -1, empty = -1;
	bpf_spin_lock(&d->lock);
	int status = se_pool_find_locked(d, t->address, &index);
	if (status == SE_POOL_OK)
		status = SE_POOL_CONTENDED;
	else if (status == SE_POOL_MISSING) {
#ifdef __clang__
#pragma unroll
#endif
		for (int i = 0; i < 16; i++)
			if (!d->ways[i].cookie && empty < 0)
				empty = i;
		if (empty < 0)
			status = SE_POOL_DIRECTORY_CAPACITY;
		else {
			d->ways[empty] = (struct se_pool_way){ t->address,
							       t->cookie,
							       t->slot, 0 };
			status = SE_POOL_OK;
		}
	}
	bpf_spin_unlock(&d->lock);
	/* No fallible operation or return between publication and its record. */
	if (status == SE_POOL_OK) {
		bpf_spin_lock(&m->lock);
		m->flags |= SE_POOL_PUBLISHED;
		m->phase = SE_POOL_PENDING_BIRTH;
		bpf_spin_unlock(&m->lock);
	}
	return status;
}
/* Synchronous epilogue for EVERY held reservation. Unpublished legitimate
 * failure becomes ABORTED. Structural fault is retained, never refunded. */
/* At most 128 words in B2/T16384. Kept as a bounded loop, not unrolled
 * into a verifier-hostile instruction block. Count only task bits. */
SE_POOL_INLINE __u32 se_pool_popcount64(__u64 x)
{
	x = x - ((x >> 1) & 0x5555555555555555ULL);
	x = (x & 0x3333333333333333ULL) + ((x >> 2) & 0x3333333333333333ULL);
	x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0fULL;
	return (__u32)((x * 0x0101010101010101ULL) >> 56);
}
SE_POOL_INLINE __u32 se_pool_task_bits_locked(const struct se_pool_bitmap *b)
{
	__u32 count = 0;
	for (__u32 i = 0; i < SE_POOL_TASK_WORDS; i++) {
		__u64 x = b->words[i];
#if SE_POOL_QT % 64u
		if (i == SE_POOL_TASK_WORDS - 1)
			x &= (1ULL << (SE_POOL_QT % 64u)) - 1;
#endif
		count += se_pool_popcount64(x);
	}
	return count;
}
SE_POOL_INLINE int se_pool_task_complete(struct se_route_anchor *a,
					 struct se_pool_bitmap *b,
					 struct se_pool_charge *ch,
					 struct se_pool_task_meta *m,
					 struct se_pool_reservation *r)
{
	if (!r || r->held != 1)
		return SE_POOL_CORRUPT;
	/* A changed slot or unauthentic anchor is a defensive HOLD: no route,
  * metadata, charge, or bitmap write can be justified. The retained caller
  * charge pointer is checked against the independently bound ARRAY pointer. */
	if (!se_pool_charged_slot_valid(r))
		return SE_POOL_CORRUPT;
	__u32 slot = r->charged_slot, account = slot / SE_POOL_QT;
	struct se_pool_charge *exact_ch =
		bpf_map_lookup_elem(&se_pool_charges, &slot);
	if (!exact_ch || exact_ch != r->charged_charge)
		return SE_POOL_CORRUPT;
	struct se_route_anchor *exact_a = se_route_anchor_lookup(&account);
	struct se_pool_bitmap *exact_b =
		bpf_map_lookup_elem(&se_pool_bitmaps, &account);
	struct se_pool_task_meta *exact_m =
		bpf_map_lookup_elem(&se_pool_task_meta, &slot);
	if (!exact_a)
		return SE_POOL_CORRUPT;
	if (!exact_ch || !exact_b) {
		bpf_spin_lock(&exact_a->lock);
		exact_a->reserved = 1;
		bpf_spin_unlock(&exact_a->lock);
		return SE_POOL_CORRUPT; /* Lookup failed: retain BUILDING and reservation. */
	}
	int status = SE_POOL_OK;
	if (!se_pool_reservation_valid(r) || r->account.route_slot != account ||
	    !r->cookie || r->cookie > SE_POOL_LIMIT || a != exact_a ||
	    ch != exact_ch || b != exact_b || m != exact_m || !exact_m)
		status = SE_POOL_CORRUPT;
	if (status == SE_POOL_OK) {
		struct se_pool_token t = se_pool_reservation_token(r);
		bpf_spin_lock(&exact_m->lock);
		if (!se_pool_match(exact_m, &t) ||
		    !se_pool_meta_valid(exact_m) || !exact_m->active_leases ||
		    (exact_m->phase != SE_POOL_INITIALIZING &&
		     exact_m->phase != SE_POOL_PENDING_BIRTH &&
		     exact_m->phase != SE_POOL_DEAD) ||
		    (exact_m->phase == SE_POOL_INITIALIZING ?
			     (exact_m->flags || exact_m->cleanup_done) :
			     !(exact_m->flags & SE_POOL_PUBLISHED)))
			status = SE_POOL_CORRUPT;
		else {
			if (exact_m->phase == SE_POOL_INITIALIZING)
				exact_m->phase = SE_POOL_ABORTED;
			exact_m->active_leases--;
		}
		bpf_spin_unlock(&exact_m->lock);
	}
	__u32 local = slot - account * SE_POOL_QT;
	__u64 bit = 1ULL << (local % 64u);
	bpf_spin_lock(&exact_a->lock);
	int identity_valid = se_pool_reservation_valid(r) &&
			     r->account.route_slot == account &&
			     exact_ch->current_cookie == r->cookie &&
			     exact_ch->last_returned_cookie < r->cookie &&
			     exact_ch->account_scope == r->account.scope &&
			     exact_ch->account_incarnation ==
				     r->account.incarnation;
	if (exact_a->reserved || exact_a->scope != r->account.scope ||
	    exact_a->incarnation != r->account.incarnation ||
	    exact_a->payload_slot != account || !exact_a->tasks_used ||
	    exact_a->tasks_used > SE_POOL_QT ||
	    !(exact_b->words[local / 64u] & bit) ||
	    se_pool_task_bits_locked(exact_b) != exact_a->tasks_used ||
	    !identity_valid || exact_ch->state != SE_POOL_CH_BUILDING)
		status = SE_POOL_CORRUPT;
	if (status != SE_POOL_OK) {
		exact_a->reserved = 1;
		/* A structural contradiction cannot release the exact charged bit/count. */
		exact_b->words[local / 64u] |= bit;
		if (!exact_a->tasks_used)
			exact_a->tasks_used = 1;
	}
	int was_building = exact_ch->state == SE_POOL_CH_BUILDING;
	if (was_building)
		exact_ch->state = status == SE_POOL_OK ? SE_POOL_CH_OWNED :
							 SE_POOL_CH_FAULT_HELD;
	else if (!identity_valid && (exact_ch->state == SE_POOL_CH_OWNED ||
				     exact_ch->state == SE_POOL_CH_FAULT_HELD))
		exact_ch->state = SE_POOL_CH_FAULT_HELD;
	/* Contradictory identity cannot discharge this reservation merely because
  * the slot already has a terminal-looking state. Retain it for diagnosis. */
	if (was_building ||
	    (identity_valid && (exact_ch->state == SE_POOL_CH_OWNED ||
				exact_ch->state == SE_POOL_CH_FAULT_HELD)))
		r->held = 0;
	bpf_spin_unlock(&exact_a->lock);
	return status;
}

/* Map-backed candidate entry: all ARRAY pointers are obtained before charge.
 * Success owns BUILDING plus a constructor lease. The caller must initialize
 * the payload, publish or abort, and call task_complete in the same callback.
 * No hook calls this entry while the old HASH ownership remains selected. */
struct se_pool_task_refs {
	struct se_route_anchor *route;
	struct se_pool_bitmap *bitmap;
	struct se_pool_charge *charge;
	struct se_pool_task_meta *meta;
	struct se_pool_task_payload *payload;
	struct se_pool_directory *directory;
};
SE_POOL_INLINE int se_pool_task_reserve(struct se_route_anchor *route,
					const struct se_route_claim *claim,
					__u64 address,
					struct se_pool_reservation *reservation,
					struct se_pool_task_refs *refs)
{
	if (!route || !claim || !reservation || !refs || !address ||
	    claim->slot >= SE_POOL_B || reservation->held)
		return SE_POOL_CORRUPT;
	refs->route = 0;
	__u32 account = claim->slot, zero = 0;
	refs->bitmap = bpf_map_lookup_elem(&se_pool_bitmaps, &account);
	struct se_pool_sequence *sequence =
		bpf_map_lookup_elem(&se_pool_sequence, &zero);
	__u32 bucket = se_pool_bucket(address);
	refs->directory = bpf_map_lookup_elem(&se_pool_directory, &bucket);
	if (!refs->bitmap || !sequence || !refs->directory)
		return SE_POOL_CORRUPT;
#ifdef __clang__
#pragma unroll
#endif
	for (int attempt = 0; attempt < 8; attempt++) {
		*reservation = (struct se_pool_reservation){};
		int result = se_pool_task_select(route, claim, refs->bitmap,
						 address, reservation);
		if (result != SE_POOL_OK)
			return result;
		__u32 slot = reservation->pool_slot;
		refs->charge = bpf_map_lookup_elem(&se_pool_charges, &slot);
		refs->meta = bpf_map_lookup_elem(&se_pool_task_meta, &slot);
		refs->payload =
			bpf_map_lookup_elem(&se_pool_task_payload, &slot);
		if (!refs->charge || !refs->meta || !refs->payload)
			return SE_POOL_CORRUPT; /* no charge yet */
		result = se_pool_next_cookie(sequence, reservation);
		if (result != SE_POOL_OK)
			return result;
		result = se_pool_task_charge(route, claim, refs->bitmap,
					     refs->charge, reservation);
		if (result == SE_POOL_CONTENDED)
			continue;
		if (result != SE_POOL_OK)
			return result;
		refs->route =
			route; /* exact fixed account proven by successful charge */
		result = se_pool_task_initialize(refs->meta, reservation);
		if (result != SE_POOL_OK) {
			/* Metadata contradiction is retained as FAULT_HELD, never refunded. */
			se_pool_task_complete(route, refs->bitmap, refs->charge,
					      refs->meta, reservation);
			return SE_POOL_CORRUPT;
		}
		return SE_POOL_OK;
	}
	return SE_POOL_CONTENDED;
}

#endif
