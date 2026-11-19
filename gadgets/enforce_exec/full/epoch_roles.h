/* SPDX-License-Identifier: GPL-2.0 */
#ifndef FULL_EPOCH_ROLES_H
#define FULL_EPOCH_ROLES_H

/* Work-copy scalar-role merge only: no task storage, pending grants, lineage
 * discovery or activation owner. ER_ACCEPTED_EPOCH(uid) must read a COMPLETE,
 * immutable successful-activation catalogue, including removed policies.
 * Zero means proven never activated, NOT missing/unknown evidence. The owner
 * must supply ER_UNKNOWN for an unavailable catalogue/failed lookup. Epochs
 * cannot equal ER_UNKNOWN. Candidate and catalogue snapshots must remain fixed
 * throughout a merge and their version must be checked at publication. */
#ifndef ER_ACCEPTED_EPOCH
#error "define ER_ACCEPTED_EPOCH(uid) using trusted successful history"
#endif
#define ER_SLOTS 16
#define ER_ACTIVE 8
#define ER_UNKNOWN (~(__u64)0)
#define ER_INVALID (-1)
#define ER_CAPACITY (-2)
#define ER_LINEAGE (-3)
#define ER_STALE (-4)
#ifndef ER_INLINE
#define ER_INLINE static __inline __attribute__((always_inline))
#endif

struct er_row {
	__u64 uid, epoch, role;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	__u32 knowledge, reserved;
#endif
};
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
enum { ER_ROLE_EMPTY = 0, ER_ROLE_KNOWN = 1, ER_ROLE_UNKNOWN = 2 };
_Static_assert(sizeof(struct er_row) == 32, "development role ABI");
#else
_Static_assert(sizeof(struct er_row) == 24, "ABI2 role ABI");
#endif
ER_INLINE struct er_row er_known_row(__u64 uid, __u64 epoch, __u64 role)
{
	struct er_row row = { .uid = uid, .epoch = epoch, .role = role };
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	row.knowledge = ER_ROLE_KNOWN;
#endif
	return row;
}
ER_INLINE int er_role_known(const struct er_row *row)
{
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	return row->knowledge == ER_ROLE_KNOWN && row->reserved == 0;
#else
	return row->role != 0;
#endif
}
struct er_authority {
	__u64 uid, epoch, root;
	__u32 new_uid, reserved;
};
struct er_candidate {
	__u32 count, reserved;
	struct er_authority active[ER_ACTIVE];
};
struct er_state {
	__u64 version;
	struct er_row rows[ER_SLOTS];
};
struct er_work {
	__u64 base_version, authority_version;
	int error;
	__u32 prepared;
	struct er_row rows[ER_SLOTS];
};

/* Snapshot under the state lock. authority_version is a nonzero, never-reused
 * owner version covering BOTH candidate and successful history. Do not call
 * any merge/lookup function under the state lock. */
ER_INLINE void er_snapshot(struct er_work *w, const struct er_state *state,
			   __u64 authority_version)
{
	w->base_version = state->version;
	w->authority_version = authority_version;
	w->error = authority_version ? 0 : ER_INVALID;
	w->prepared = 0;
	for (int i = 0; i < ER_SLOTS; i++)
		w->rows[i] = state->rows[i];
}
ER_INLINE int er_fail(struct er_work *w, int error)
{
	if (!w->error)
		w->error = error;
	return w->error;
}
ER_INLINE int er_candidate_valid(const struct er_candidate *c)
{
	if (c->count > ER_ACTIVE || c->reserved)
		return ER_INVALID;
		/* Keep this fixed eight-row validator out of the surrounding loop SCC.
     * The pinned verifier otherwise carries its scalar induction register into
     * the following rows loop after LLVM reuses it for a map-value pointer. */
#ifdef __BPF__
#pragma clang loop unroll(full)
#endif
	for (int i = 0; i < ER_ACTIVE; i++) {
		const struct er_authority *a = &c->active[i];
		if ((__u32)i >= c->count) {
			if (a->uid || a->epoch || a->root || a->new_uid ||
			    a->reserved)
				return ER_INVALID;
			continue;
		}
		if (!a->uid || !a->epoch || a->epoch == ER_UNKNOWN ||
		    !a->root || a->new_uid > 1 || a->reserved)
			return ER_INVALID;
		for (int j = 0; j < ER_ACTIVE; j++)
			if (j < i && c->active[j].uid == a->uid)
				return ER_INVALID;
		__u64 er_accepted = ER_ACCEPTED_EPOCH(a->uid);
		if (er_accepted == ER_UNKNOWN ||
		    (a->new_uid ? er_accepted != 0 : er_accepted != a->epoch))
			return ER_INVALID;
	}
	return 0;
}
/* 1 accepted, 2 current staged root, 0 proven stale never-activated row.
 * A mismatched accepted epoch is corruption, never a reason to re-root. */
ER_INLINE int er_row_kind(const struct er_row *r, const struct er_candidate *c)
{
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	if (!r->uid)
		return (r->epoch || r->role || r->knowledge || r->reserved) ?
			       ER_INVALID :
			       0;
	if (r->reserved ||
	    (r->knowledge != ER_ROLE_KNOWN && r->knowledge != ER_ROLE_UNKNOWN))
		return ER_INVALID;
#else
	if (!r->uid)
		return (r->epoch || r->role) ? ER_INVALID : 0;
#endif
	if (!r->epoch || r->epoch == ER_UNKNOWN || !r->role)
		return ER_INVALID;
	__u64 er_accepted = ER_ACCEPTED_EPOCH(r->uid);
	if (er_accepted == ER_UNKNOWN)
		return ER_INVALID;
	if (er_accepted)
		return er_accepted == r->epoch ? 1 : ER_INVALID;
	for (int i = 0; i < ER_ACTIVE; i++) {
		if ((__u32)i >= c->count)
			break;
		const struct er_authority *a = &c->active[i];
		if (a->uid == r->uid && a->epoch == r->epoch)
			return a->new_uid && a->root == r->role &&
					       er_role_known(r) ?
				       2 :
				       ER_INVALID;
	}
	return 0;
}
ER_INLINE int er_rows_valid(const struct er_row *rows,
			    const struct er_candidate *c)
{
	for (int i = 0; i < ER_SLOTS; i++) {
		if (er_row_kind(&rows[i], c) < 0)
			return ER_INVALID;
		if (!rows[i].uid)
			continue;
		for (int j = 0; j < ER_SLOTS; j++)
			if (j < i && rows[j].uid == rows[i].uid)
				return ER_INVALID;
	}
	return 0;
}
ER_INLINE int er_prepare(struct er_work *w, const struct er_candidate *c)
{
	if (w->error)
		return w->error;
	if (er_candidate_valid(c) || er_rows_valid(w->rows, c))
		return er_fail(w, ER_INVALID);
	for (int i = 0; i < ER_SLOTS; i++) {
		if (er_row_kind(&w->rows[i], c) == 0)
			w->rows[i] = (struct er_row){};
	}
	w->prepared = 1;
	return 0;
}
ER_INLINE int er_insert(struct er_work *w, struct er_row row)
{
	int vacant = -1;
	for (int i = 0; i < ER_SLOTS; i++) {
		if (w->rows[i].uid == row.uid) {
			/* Existing accepted role wins; incoming state never overwrites it. */
			return w->rows[i].epoch == row.epoch ?
				       0 :
				       er_fail(w, ER_INVALID);
		}
		if (!w->rows[i].uid && vacant < 0)
			vacant = i;
	}
	if (vacant < 0 || vacant >= ER_SLOTS)
		return er_fail(w, ER_CAPACITY);
	w->rows[vacant] = row;
	return 0;
}
/* lineage_verified must be the caller's explicit kernel-verified decision,
 * never cgroup membership, absent state or a userspace seed assertion.
 * Only new UIDs receive roots. Accepted UIDs missing a row remain missing. */
ER_INLINE int er_stage_roots(struct er_work *w, const struct er_candidate *c,
			     int lineage_verified)
{
	if (w->error)
		return w->error;
	if (lineage_verified != 1)
		return er_fail(w, ER_LINEAGE);
	if (er_prepare(w, c))
		return w->error;
	for (int i = 0; i < ER_ACTIVE; i++) {
		if ((__u32)i >= c->count)
			break;
		const struct er_authority *a = &c->active[i];
		if (a->new_uid &&
		    er_insert(w, er_known_row(a->uid, a->epoch, a->root)))
			return w->error;
	}
	return 0;
}
/* source must be a coherent committed/staged-root snapshot, never pending exec
 * grants. Current-new staged roots are inherited only while exactly authorized
 * by the same immutable candidate. Caller must validate creator lineage. */
ER_INLINE int er_inherit(struct er_work *w, const struct er_candidate *c,
			 const struct er_row source[ER_SLOTS])
{
	if (w->error)
		return w->error;
	if (er_prepare(w, c) || er_rows_valid(source, c))
		return er_fail(w, ER_INVALID);
	for (int i = 0; i < ER_SLOTS; i++) {
		int kind = er_row_kind(&source[i], c);
		if (kind > 0 && er_insert(w, source[i]))
			return w->error;
	}
	return 0;
}
/* Publish ONLY under the destination state lock, after owner authority/version
 * synchronization. No map lookups, helper calls, allocation or nested locks.
 * Every other writer MUST increment state.version; no wrap or version reuse.
 * A failed/partial work copy is never published. Snapshot/merge/publish callers
 * must not mutate work.rows except through this API; this is not a hostile-input
 * validator. It cannot by itself establish source lineage or catalogue trust. */
ER_INLINE int er_publish(struct er_state *state, const struct er_work *w,
			 __u64 authority_version)
{
	if (w->error)
		return w->error;
	if (!w->prepared || !authority_version ||
	    w->authority_version != authority_version ||
	    w->base_version != state->version || state->version == ER_UNKNOWN)
		return ER_STALE;
	for (int i = 0; i < ER_SLOTS; i++)
		state->rows[i] = w->rows[i];
	state->version++;
	return 0;
}
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
/* Canonical-ledger primitives, not yet wired into owner storage. er_state is
 * the sole persistent 16-cell ledger; these records are bounded scratch only.
 * Caller holds a stable COMPLETE catalogue/descriptor authority claim from
 * snapshot through final use, and exclusive candidate ownership for staging.
 * Snapshot/store run under the task lock; classification/preparation run outside
 * it. Caller rechecks physical task cookie, session, generation, eligibility and
 * transaction ownership before either publisher. These helpers do not establish
 * those properties, inventory coverage, or a candidate pass receipt.
 * Prepared scratch is API-owned, not an untrusted command representation. */
struct er_canonical_view {
	struct er_work work;
	__u32 accepted_mask;
};
struct er_fact_change {
	struct er_row before, after;
	__u32 index;
};
struct er_fact_patch {
	__u64 base_version, authority_version;
	__u32 count, prepared;
	struct er_fact_change changes[ER_ACTIVE];
};
/* Preserve physical indices. Catalogue-proven unaccepted cells are omitted
 * only from scratch; they must never be erased by publishing this projection. */
ER_INLINE int er_canonical_classify(struct er_canonical_view *view)
{
	struct er_work *w = &view->work;
	const struct er_candidate none = {};
	view->accepted_mask = 0;
	if (w->error || !w->authority_version || er_rows_valid(w->rows, &none))
		return er_fail(w, ER_INVALID);
	for (int i = 0; i < ER_SLOTS; i++)
		if (er_row_kind(&w->rows[i], &none) == 1)
			view->accepted_mask |= 1U << i;
	w->prepared = 1;
	return 0;
}
/* Caller snapshots with er_snapshot before classification. Only this projection
 * may be inherited into a fresh RESERVED child; never overwrite a live child. */
ER_INLINE int er_canonical_project(const struct er_canonical_view *view,
				   struct er_work *projection)
{
	if (view->work.error || !view->work.prepared)
		return ER_INVALID;
	*projection = view->work;
	for (int i = 0; i < ER_SLOTS; i++)
		if (!(view->accepted_mask & (1U << i)))
			projection->rows[i] = (struct er_row){};
	return 0;
}
ER_INLINE int er_canonical_patch_prepare(const struct er_canonical_view *view,
					 const struct er_row *desired,
					 __u32 count,
					 struct er_fact_patch *patch)
{
	patch->prepared = patch->count = 0;
	if (view->work.error || !view->work.prepared || count > ER_ACTIVE)
		return ER_INVALID;
	patch->base_version = view->work.base_version;
	patch->authority_version = view->work.authority_version;
	const struct er_candidate none = {};
	for (__u32 n = 0; n < ER_ACTIVE; n++) {
		if (n >= count)
			break;
		if (er_row_kind(&desired[n], &none) != 1)
			return ER_INVALID;
		for (__u32 j = 0; j < n; j++)
			if (desired[j].uid == desired[n].uid)
				return ER_INVALID;
		int found = -1;
		for (int i = 0; i < ER_SLOTS; i++)
			if ((view->accepted_mask & (1U << i)) &&
			    view->work.rows[i].uid == desired[n].uid &&
			    view->work.rows[i].epoch == desired[n].epoch)
				found = i;
		if (found < 0)
			return ER_INVALID;
		patch->changes[n] =
			(struct er_fact_change){ .before =
							 view->work.rows[found],
						 .after = desired[n],
						 .index = (__u32)found };
	}
	patch->count = count;
	patch->prepared = 1;
	return 0;
}
/* No catalogue/helper calls below. Validate ALL targets before the first store.
 * Candidate-only writes cannot conflict: they neither move accepted cells nor
 * change fact_version. Unchanged/empty patches do not consume a fact version. */
ER_INLINE int er_canonical_patch_publish(struct er_state *state,
					 const struct er_fact_patch *patch,
					 __u64 authority)
{
	if (!patch->prepared || patch->count > ER_ACTIVE || !authority ||
	    authority != patch->authority_version ||
	    state->version != patch->base_version)
		return ER_STALE;
	int changed = 0;
	for (__u32 n = 0; n < ER_ACTIVE; n++) {
		if (n >= patch->count)
			break;
		const struct er_fact_change *change = &patch->changes[n];
		if (change->index >= ER_SLOTS)
			return ER_INVALID;
		const struct er_row *row = &state->rows[change->index];
		if (row->uid != change->before.uid ||
		    row->epoch != change->before.epoch ||
		    row->role != change->before.role ||
		    row->knowledge != change->before.knowledge ||
		    row->reserved != change->before.reserved)
			return ER_STALE;
		if (change->after.uid != row->uid ||
		    change->after.epoch != row->epoch || !change->after.role ||
		    change->after.reserved ||
		    (change->after.knowledge != ER_ROLE_KNOWN &&
		     change->after.knowledge != ER_ROLE_UNKNOWN))
			return ER_INVALID;
		changed |= row->role != change->after.role ||
			   row->knowledge != change->after.knowledge;
	}
	if (changed && state->version >= ER_UNKNOWN - 1)
		return ER_STALE;
	for (__u32 n = 0; n < ER_ACTIVE; n++) {
		if (n >= patch->count)
			break;
		const struct er_fact_change *change = &patch->changes[n];
		/* Every index was rejected unless < ER_SLOTS before ANY store.
		 * Exclusive owned scratch cannot change between passes. Constrain
		 * this reload for the verifier without a fallible partial publisher. */
		__u32 index = change->index & (ER_SLOTS - 1);
		state->rows[index].role = change->after.role;
		state->rows[index].knowledge = change->after.knowledge;
	}
	if (changed)
		state->version++;
	return 0;
}
/* Reuse existing bounded root planning in scratch. It preserves all accepted
 * cells at their immutable indices. No accepted missing row acquires a root. */
ER_INLINE int er_canonical_stage_prepare(struct er_canonical_view *view,
					 const struct er_candidate *candidate,
					 int lineage_verified)
{
	if (er_canonical_classify(view))
		return view->work.error;
	return er_stage_roots(&view->work, candidate, lineage_verified);
}
ER_INLINE int er_canonical_stage_publish(struct er_state *state,
					 const struct er_canonical_view *view,
					 __u64 authority)
{
	const struct er_work *w = &view->work;
	if (w->error)
		return w->error;
	if (!w->prepared || !authority || authority != w->authority_version ||
	    state->version != w->base_version)
		return ER_STALE;
	for (int i = 0; i < ER_SLOTS; i++) {
		if (!(view->accepted_mask & (1U << i)))
			continue;
		const struct er_row *a = &state->rows[i], *b = &w->rows[i];
		if (a->uid != b->uid || a->epoch != b->epoch ||
		    a->role != b->role || a->knowledge != b->knowledge ||
		    a->reserved != b->reserved)
			return ER_STALE;
	}
	/* Held catalogue authority and exclusive staging make every other index
  * still unaccepted. Never copy accepted cells or increment factual version. */
	for (int i = 0; i < ER_SLOTS; i++)
		if (!(view->accepted_mask & (1U << i)))
			state->rows[i] = w->rows[i];
	return 0;
}
#endif
#endif
