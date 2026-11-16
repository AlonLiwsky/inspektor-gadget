/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_CATALOGUE_PURE_H
#define ENFORCE_EXEC_SHARED_POOL_CATALOGUE_PURE_H
#ifndef ENFORCE_EXEC_ABI3_DEVELOPMENT
#error "scoped catalogue classifier requires development role ABI"
#endif
#include "shared_pool_epoch_cache_wire.h"

/* Exact unsigned inequality without a data-dependent BPF branch. The empty
 * asm keeps the two's-complement arithmetic from being folded back into an
 * equality jump by the compiler; on BPF this is XOR, NEG, OR, SHR. */
static __attribute__((always_inline)) inline __u32
se_pool_catalogue_ne64(__u64 a, __u64 b)
{
	__u64 difference = a ^ b, negative = difference;
	asm volatile("" : "+r"(negative));
	negative = -negative;
	return (__u32)((difference | negative) >> 63);
}

/* One bounded row check. The optional noinline boundary lets legacy verifiers
 * finish each row before examining the next; no row result is published until
 * the caller has validated all positions. Return -1 for invalid, 0 for a
 * proven never-accepted row, and 1 for an accepted row. */
#ifdef SE_POOL_CATALOGUE_ROW_NOINLINE
static __attribute__((noinline)) int se_pool_catalogue_classify_row(
#else
static __attribute__((always_inline)) inline int se_pool_catalogue_classify_row(
#endif
	const struct er_work *snapshot, const struct se_pool_epoch_cache *cache,
	__u32 i)
{
	if (i >= 16)
		return -1;
	const struct er_row *row = &snapshot->rows[i];
	__u64 accepted = cache->rows[i].accepted_epoch;
	__u32 present = se_pool_catalogue_ne64(row->uid, 0);
	__u32 accepted_bit = se_pool_catalogue_ne64(accepted, 0);
	__u32 invalid = se_pool_catalogue_ne64(cache->rows[i].uid, row->uid) |
			(1U ^ se_pool_catalogue_ne64(accepted, ER_UNKNOWN));
	invalid |= (1U ^ present) &
		   (accepted_bit | se_pool_catalogue_ne64(row->epoch, 0) |
		    se_pool_catalogue_ne64(row->role, 0) |
		    se_pool_catalogue_ne64(row->knowledge, 0) |
		    se_pool_catalogue_ne64(row->reserved, 0));
	invalid |=
		present &
		((1U ^ se_pool_catalogue_ne64(row->epoch, 0)) |
		 (1U ^ se_pool_catalogue_ne64(row->epoch, ER_UNKNOWN)) |
		 (1U ^ se_pool_catalogue_ne64(row->role, 0)) |
		 se_pool_catalogue_ne64(row->reserved, 0) |
		 (se_pool_catalogue_ne64(row->knowledge, ER_ROLE_KNOWN) &
		  se_pool_catalogue_ne64(row->knowledge, ER_ROLE_UNKNOWN)) |
		 (accepted_bit & se_pool_catalogue_ne64(accepted, row->epoch)));
	for (__u32 j = 0; j < i; j++)
		invalid |= present &
			   (1U ^ se_pool_catalogue_ne64(snapshot->rows[j].uid,
							row->uid));
	return invalid ? -1 : (int)accepted_bit;
}

/* Pure, fixed-position equivalent of er_canonical_classify for the empty
 * candidate. The cache binds each position's UID to the exact accepted epoch
 * observed under the held scope claim, not to current-task HASH lookup. */
/* Scope/generation are trusted only after the caller validates a live route
 * claim or an exact persistent reader on a lexical TASK/WORK owner. Do not
 * call this scalar core from a copied token or current-cgroup observation. */
static __attribute__((always_inline)) inline int
se_pool_catalogue_classify_after_authority(
	struct er_canonical_view *view, const struct se_pool_epoch_cache *cache,
	__u64 scope, __u64 generation)
{
	if (!view)
		return ER_INVALID;
	view->accepted_mask = 0;
	if (!cache || !scope || !generation || cache->scope != scope ||
	    cache->generation != generation)
		return er_fail(&view->work, ER_INVALID);
	struct er_work *snapshot = &view->work;
	if (snapshot->error || !snapshot->authority_version ||
	    snapshot->authority_version != generation)
		return er_fail(snapshot, ER_INVALID);
	__u32 accepted_mask = 0;
	for (__u32 i = 0; i < 16; i++) {
		int accepted =
			se_pool_catalogue_classify_row(snapshot, cache, i);
		if (accepted < 0)
			return er_fail(snapshot, ER_INVALID);
		accepted_mask |= ((__u32)accepted) << i;
	}
	view->accepted_mask = accepted_mask;
	snapshot->prepared = 1;
	return 0;
}
static __attribute__((always_inline)) inline int
se_pool_catalogue_classify(struct er_canonical_view *view,
			   const struct se_pool_epoch_cache *cache,
			   const struct se_route_claim *claim)
{
	if (!view)
		return ER_INVALID;
	if (!claim || !claim->owned || claim->reserved) {
		view->accepted_mask = 0;
		return er_fail(&view->work, ER_INVALID);
	}
	return se_pool_catalogue_classify_after_authority(
		view, cache, claim->scope, claim->generation);
}

/* Final-store preflight: require the exact cache used for this WORK snapshot,
 * and the fixed-position projection it authorized. No helper or map lookup is
 * permitted here, so the result can be checked before taking the parent lock. */
#ifdef SE_POOL_CATALOGUE_PROJECTION_GLOBAL_DIAGNOSTIC
#define SE_POOL_PROJECTION_ATTR __attribute__((noinline))
#define SE_POOL_PROJECTION_LINKAGE
#elif defined(SE_POOL_CATALOGUE_PROJECTION_NOINLINE_DIAGNOSTIC)
#define SE_POOL_PROJECTION_ATTR __attribute__((noinline))
#define SE_POOL_PROJECTION_LINKAGE static
#else
#define SE_POOL_PROJECTION_ATTR __attribute__((always_inline)) inline
#define SE_POOL_PROJECTION_LINKAGE static
#endif
SE_POOL_PROJECTION_LINKAGE SE_POOL_PROJECTION_ATTR int
se_pool_catalogue_projection_matches(const struct er_canonical_view *view,
				     const struct er_work *projected,
				     const struct se_pool_epoch_cache *cache,
				     const struct se_route_claim *claim)
{
	if (!view || !projected || !cache || !claim || !claim->owned ||
	    claim->reserved || !claim->scope || !claim->generation ||
	    cache->scope != claim->scope ||
	    cache->generation != claim->generation || view->work.error ||
	    !view->work.prepared ||
	    view->work.authority_version != claim->generation ||
	    projected->error || !projected->prepared ||
	    projected->base_version != view->work.base_version ||
	    projected->authority_version != view->work.authority_version)
		return 0;
	for (__u32 i = 0; i < 16; i++) {
		const struct er_row *source = &view->work.rows[i];
		const struct er_row *output = &projected->rows[i];
		__u64 accepted = cache->rows[i].accepted_epoch;
		int keep = !!(view->accepted_mask & (1U << i));
		if (cache->rows[i].uid != source->uid ||
		    accepted == ER_UNKNOWN || !!accepted != keep ||
		    (accepted && (!source->uid || source->epoch != accepted)))
			return 0;
		if (keep) {
			if (output->uid != source->uid ||
			    output->epoch != source->epoch ||
			    output->role != source->role ||
			    output->knowledge != source->knowledge ||
			    output->reserved != source->reserved)
				return 0;
		} else if (output->uid || output->epoch || output->role ||
			   output->knowledge || output->reserved) {
			return 0;
		}
	}
	return 1;
}
#undef SE_POOL_PROJECTION_ATTR
#undef SE_POOL_PROJECTION_LINKAGE
#endif
