/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef ENFORCE_EXEC_SHARED_POLICY_LOOKUP_H
#define ENFORCE_EXEC_SHARED_POLICY_LOOKUP_H
#if defined(ENFORCE_EXEC_FULLPOLICY_EVALUATOR_H) || \
	defined(ENFORCE_EXEC_FULLPOLICY_MATCHER_H)
#error "include shared_policy_lookup.h before evaluator.h and matcher.h"
#endif

/* Include before evaluator.h. One private view belongs to one retained snapshot
 * for the whole invocation (including matcher refetches). It must not be shared
 * across tasks, sleepable invocations, or nested evaluator calls. The adapter
 * owns scope/snapshot claims and immutable slot pins until the LAST access.
 * Inputs must come from whole-union native compiler admission and the exact
 * retained scope snapshot; this adapter does not replace policy-set admission
 * or authenticate root epochs. No map helper may run under a spin lock.
 *
 * Only RULE lookup selects an object. Header/policy/container lookups NEVER
 * change that selection. Data references are local: data begins at 9+rules,
 * not 265, and may collide with every synthetic global rule/container key.
 * Therefore structural access uses typed evaluator seams, never key tagging.
 */
struct se_policy_view;
struct fm_blob;
struct fe_header;
struct fe_policy;
struct fe_rule;
struct fe_string;
static inline const struct fe_header *se_policy_header(struct se_policy_view *);
static inline const struct fe_policy *se_policy_policy(struct se_policy_view *,
						       unsigned int);
static inline const struct fe_rule *se_policy_rule(struct se_policy_view *,
						   unsigned int);
static inline const struct fe_string *
se_policy_container(struct se_policy_view *);
static inline const struct fm_blob *se_policy_data(struct se_policy_view *,
						   unsigned int);
#ifndef SE_POLICY_VIEW
#define SE_POLICY_VIEW(ctx) ((struct se_policy_view *)(ctx))
#endif
#define FE_HEADER_LOOKUP(ctx) se_policy_header(SE_POLICY_VIEW(ctx))
#define FE_POLICY_LOOKUP(ctx, index) \
	se_policy_policy(SE_POLICY_VIEW(ctx), index)
#define FE_RULE_LOOKUP(ctx, index) se_policy_rule(SE_POLICY_VIEW(ctx), index)
#define FE_CONTAINER_LOOKUP(ctx) se_policy_container(SE_POLICY_VIEW(ctx))
#define FM_BLOB_LOOKUP(ctx, key) se_policy_data(SE_POLICY_VIEW(ctx), key)
#ifndef SE_POLICY_EVALUATOR_HEADER
#define SE_POLICY_EVALUATOR_HEADER "evaluator.h"
#endif
#include SE_POLICY_EVALUATOR_HEADER

struct se_policy_ref {
	fm_u64 generation, root_epoch;
	fm_u32 slot, entries;
};
struct se_policy_view {
	/* Host fixture context only. BPF invocation map scratch MUST keep this
	 * NULL: never persist a kernel/map pointer in a map value. The production
	 * physical callback resolves fixed maps from scalar slot/generation. */
	void *physical_context;
	fm_u64 scope_cookie;
	struct se_policy_ref refs[8];
	struct fe_header header;
	struct fe_policy policies[8];
	struct fe_string container;
	struct fe_rule rule;
	fm_u32 rule_counts[8], selected, ready;
};

/* The production adapter must resolve the exact RETAINED slot+generation,
 * reject stale/recycled identity, and bound keys by that slot's validated
 * immutable length. Ref.entries is that same retained descriptor length, not
 * policy input. A returned pointer stays immutable/live across nested lookups.
 * This callback is not an unlocked slot lookup followed by unchecked arena read.
 */
static inline const struct fm_blob *
se_policy_physical(void *context, fm_u32 slot, fm_u64 generation, fm_u32 key);

static __attribute__((always_inline)) inline int
se_policy_prepare(struct se_policy_view *v, void *physical, fm_u64 scope,
		  fm_u64 generation, const struct fe_string *container,
		  const struct se_policy_ref *refs, fm_u32 count)
{
	if (!v)
		return -1;
	v->ready = 0;
	v->selected = 8;
	if (!scope || scope == ~0ULL || !generation || generation == ~0ULL ||
	    !container || !container->length || container->length > 255 ||
	    !refs || !count || count > 8)
		return -1;
	v->physical_context = physical;
	v->scope_cookie = scope;
	v->header = (struct fe_header){ .generation = generation,
					.policies = count,
					.rule_base = 9 };
	v->container = *container;
	for (fm_u32 i = 0; i < 8; i++) {
		if (i >= count)
			break;
		struct se_policy_ref ref = refs[i];
		if (!ref.generation || ref.generation == ~0ULL ||
		    !ref.root_epoch || ref.root_epoch > generation ||
		    ref.entries < 10 || ref.entries > FM_MAX_ENTRIES)
			return -1;
		const struct fe_header *h = (const void *)se_policy_physical(
			physical, ref.slot, ref.generation, 0);
		if (!h || h->generation || h->container || h->policies != 1 ||
		    h->rule_base != 9 || h->rules > 256 ||
		    h->rules > ref.entries - 10 ||
		    h->rules > 256 - v->header.rules)
			return -1;
		v->rule_counts[i] = h->rules;
		v->header.rules += h->rules;
		const struct fe_policy *p = (const void *)se_policy_physical(
			physical, ref.slot, ref.generation, 1);
		if (!p || !p->uid || !p->root_role || p->root_epoch ||
		    p->mode < 1 || p->mode > 2 || p->fallback > 2)
			return -1;
		for (fm_u32 j = 0; j < 8; j++) {
			if (j >= i)
				break;
			if (v->policies[j].uid == p->uid)
				return -1;
		}
		v->policies[i] = *p;
		v->policies[i].root_epoch = ref.root_epoch;
		v->refs[i] = ref;
	}
	v->ready = 1;
	return 0;
}
static inline const struct fe_header *se_policy_header(struct se_policy_view *v)
{
	return v && v->ready ? &v->header : 0;
}
static inline const struct fe_policy *se_policy_policy(struct se_policy_view *v,
						       fm_u32 index)
{
	return v && v->ready && index < 8 && index < v->header.policies ?
		       &v->policies[index] :
		       0;
}
static inline const struct fe_string *
se_policy_container(struct se_policy_view *v)
{
	return v && v->ready ? &v->container : 0;
}
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
#define SE_STAGE_POLICY_INLINE __attribute__((always_inline))
#else
#define SE_STAGE_POLICY_INLINE
#endif
static SE_STAGE_POLICY_INLINE inline const struct fe_rule *
se_policy_rule(struct se_policy_view *v, fm_u32 index)
{
	if (!v || !v->ready)
		return 0;
	v->selected = 8;
	if (index >= v->header.rules || index >= 256)
		return 0;
	fm_u32 local = index;
	for (fm_u32 i = 0; i < 8; i++) {
		if (i >= v->header.policies)
			break;
		if (local >= v->rule_counts[i]) {
			local -= v->rule_counts[i];
			continue;
		}
		const struct se_policy_ref *ref = &v->refs[i];
		const struct fe_rule *r = (const void *)se_policy_physical(
			v->physical_context, ref->slot, ref->generation,
			9 + local);
		if (!r || r->policy != 0)
			return 0;
		v->rule = *r;
		v->rule.policy =
			i; /* ONLY this field changes; references stay local. */
		v->selected = i;
		return &v->rule;
	}
	return 0;
}
static SE_STAGE_POLICY_INLINE inline const struct fm_blob *
se_policy_data(struct se_policy_view *v, fm_u32 key)
{
	if (!v || !v->ready || v->selected >= 8 ||
	    v->selected >= v->header.policies)
		return 0;
	const struct se_policy_ref *ref = &v->refs[v->selected];
	if (key < 9 + v->rule_counts[v->selected] || key >= ref->entries)
		return 0;
	return se_policy_physical(v->physical_context, ref->slot,
				  ref->generation, key);
}
#undef SE_STAGE_POLICY_INLINE
#endif
