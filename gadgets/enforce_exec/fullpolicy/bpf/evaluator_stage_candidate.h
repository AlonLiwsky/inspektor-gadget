/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 The Inspektor Gadget authors */
#ifndef ENFORCE_EXEC_FULLPOLICY_EVALUATOR_STAGE_CANDIDATE_H
#define ENFORCE_EXEC_FULLPOLICY_EVALUATOR_STAGE_CANDIDATE_H
#include "evaluator.h"

/* Scalar-only continuation state. The caller must retain an immutable
 * program read lease and separately authenticate its WORK at every stage;
 * this cursor is not a policy pin or a task capability. An isolated fixture
 * loads and TEST_RUNs on Rocky 4.18; no selected exec image uses it yet. */
#ifndef FE_STAGE_RULES
#define FE_STAGE_RULES 16U
#endif
enum { FE_STAGE_EMPTY, FE_STAGE_ACTIVE, FE_STAGE_READY, FE_STAGE_FINISHED };
struct fe_stage_cursor {
	fm_u64 generation;
	fm_u32 policies, rules, next_rule, state;
	fm_u32 matched, allow_mode, deny_mode, uncertain_deny;
	fm_u32 enforced_grants, role_conflicts;
#ifdef FE_AUDIT_ISOLATION
	fm_u32 uncertain_allow;
#endif
};

FE_INLINE int fe_stage_begin(void *blob_context, const struct fe_facts *f,
			     struct fe_scratch *s,
			     struct fe_stage_cursor *cursor)
{
	if (!s || !cursor || cursor->state != FE_STAGE_EMPTY || !f)
		return -1;
	s->decision.deny = 0;
	s->decision.mode = 1;
	s->decision.error = 0;
	s->decision.audit_unknown = 0;
#ifdef FE_AUDIT_ISOLATION
	s->decision.enforced_writes = 0;
	s->decision.role_conflicts = 0;
	for (fm_u32 i = 0; i < 8; i++)
		s->decision.known_role_witnesses[i] = 0;
#endif
	for (fm_u32 i = 0; i < 4; i++)
		s->decision.matched_rules[i] = 0;
	for (fm_u32 i = 0; i < 8; i++)
		s->decision.proposed_roles[i] = 0;
	const struct fe_header *h = FE_HEADER_LOOKUP(blob_context);
	if (!h || !h->policies || h->policies > 8 || h->rules > 256 ||
	    h->rule_base != 9 || h->container >= FM_MAX_ENTRIES ||
	    f->ancestor_count > 16 || f->role_count > 8 ||
	    !fe_path_valid(&f->actor_path) || !fe_path_valid(&f->target_path)) {
		s->decision.error = FE_INVALID;
		return -1;
	}
	struct fe_paths_check paths = { f, 0 };
	if (FE_LOOP(16, fe_ancestor_valid, &paths) < 0 || paths.error) {
		s->decision.error = FE_INVALID;
		return -1;
	}
	*cursor = (struct fe_stage_cursor){
		.generation = h->generation,
		.policies = h->policies,
		.rules = h->rules,
		.state = h->rules ? FE_STAGE_ACTIVE : FE_STAGE_READY,
		.allow_mode = 1,
		.deny_mode = 1,
	};
	return 0;
}

/* One bounded rule window. Reconstruct all pointers from the caller's
 * freshly authenticated WORK/program; only scalar accumulators persist. */
FE_INLINE int fe_stage_advance(void *blob_context, const struct fe_facts *f,
			       struct fe_scratch *s,
			       struct fe_stage_cursor *cursor
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
			       ,
			       struct fe_alt_request *alt_request
#endif
)
{
	if (!f || !s || !cursor || cursor->state != FE_STAGE_ACTIVE ||
	    cursor->next_rule >= cursor->rules || cursor->rules > 256)
		return -1;
	const struct fe_header *h = FE_HEADER_LOOKUP(blob_context);
	if (!h || h->generation != cursor->generation ||
	    h->rules != cursor->rules || h->policies != cursor->policies ||
	    h->rule_base != 9) {
		s->decision.error = FE_INVALID;
		for (fm_u32 i = 0; i < 8; i++)
			s->decision.proposed_roles[i] = 0;
		cursor->state = FE_STAGE_READY;
		return -1;
	}
	struct fe_eval_context e = {
		.blob_context = blob_context,
		.facts = f,
		.scratch = s,
#ifdef FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC
		.alt_request = alt_request,
#endif
#ifndef FE_STAGE_RELOOKUP_HEADER_CANDIDATE
		.header = h,
#endif
		.matched = cursor->matched,
		.allow_mode = cursor->allow_mode,
		.deny_mode = cursor->deny_mode,
		.uncertain_deny = cursor->uncertain_deny,
		.enforced_grants = cursor->enforced_grants,
		.role_conflicts = cursor->role_conflicts,
#ifdef FE_AUDIT_ISOLATION
		.uncertain_allow = cursor->uncertain_allow,
#endif
	};
#if defined(__bpf__) && defined(FE_BOUNDED_LOOP_CANDIDATE)
#pragma unroll
#endif
	for (fm_u32 i = 0; i < FE_STAGE_RULES; i++) {
		if (cursor->next_rule >= cursor->rules)
			break;
		int stop = fe_rule_step(cursor->next_rule, &e);
		cursor->next_rule++;
		if (stop) {
			cursor->state = FE_STAGE_READY;
			break;
		}
	}
	cursor->matched = e.matched;
	cursor->allow_mode = e.allow_mode;
	cursor->deny_mode = e.deny_mode;
	cursor->uncertain_deny = e.uncertain_deny;
	cursor->enforced_grants = e.enforced_grants;
	cursor->role_conflicts = e.role_conflicts;
#ifdef FE_AUDIT_ISOLATION
	cursor->uncertain_allow = e.uncertain_allow;
#endif
	if (cursor->next_rule == cursor->rules)
		cursor->state = FE_STAGE_READY;
	return 0;
}

FE_INLINE int fe_stage_finish(void *blob_context, struct fe_scratch *s,
			      struct fe_stage_cursor *cursor)
{
	if (!s || !cursor || cursor->state != FE_STAGE_READY)
		return -1;
	cursor->state = FE_STAGE_FINISHED;
	if (cursor->next_rule < cursor->rules && !s->decision.error)
		s->decision.error = FE_INVALID;
	const struct fe_header *h = FE_HEADER_LOOKUP(blob_context);
	if (!h || h->generation != cursor->generation ||
	    h->rules != cursor->rules || h->policies != cursor->policies ||
	    h->rule_base != 9)
		s->decision.error = FE_INVALID;
#ifdef FE_AUDIT_ISOLATION
	if (s->decision.error && s->decision.error != FE_UNKNOWN &&
	    s->decision.error != FE_AUDIT_UNKNOWN) {
#else
	if (s->decision.error) {
#endif
		for (fm_u32 i = 0; i < 8; i++)
			s->decision.proposed_roles[i] = 0;
		return -1;
	}
	if (!cursor->matched) {
		for (fm_u32 i = 0; i < 8; i++) {
			if (i >= cursor->policies)
				break;
			const struct fe_policy *p =
				FE_POLICY_LOOKUP(blob_context, i);
			if (!p || p->fallback > 2 || p->mode < 1 ||
			    p->mode > 2) {
				s->decision.error = FE_INVALID;
				return -1;
			}
			if (p->fallback == 2) {
				s->decision.deny = 1;
				if (p->mode > cursor->deny_mode)
					cursor->deny_mode = p->mode;
			} else if (p->fallback == 1 &&
				   p->mode > cursor->allow_mode)
				cursor->allow_mode = p->mode;
		}
	}
#ifdef FE_AUDIT_ISOLATION
	if (!cursor->matched && cursor->uncertain_allow && s->decision.deny &&
	    cursor->deny_mode == 1) {
		cursor->uncertain_deny = 1;
		s->decision.audit_unknown |= FE_AUDIT_UNCERTAIN_FALLBACK |
					     FE_AUDIT_GLOBAL_SUPPRESS;
	}
#endif
	s->decision.mode = s->decision.deny ? cursor->deny_mode :
					      cursor->allow_mode;
	for (fm_u32 i = 0; i < 8; i++) {
		if (s->decision.deny || cursor->uncertain_deny ||
		    s->decision.error == FE_UNKNOWN ||
		    (FE_ROLE_UNCERTAIN(s->decision.audit_unknown) & (1U << i)))
			s->decision.proposed_roles[i] = 0;
	}
	return s->decision.error && s->decision.error != FE_AUDIT_UNKNOWN ? -1 :
									    0;
}
#endif
