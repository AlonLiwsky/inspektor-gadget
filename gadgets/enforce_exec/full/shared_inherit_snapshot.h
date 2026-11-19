/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_INHERIT_SNAPSHOT_H
#define ENFORCE_EXEC_SHARED_INHERIT_SNAPSHOT_H

#ifdef ENFORCE_EXEC_POOL_OPAQUE_SNAPSHOT_BRANCHLESS_DIAGNOSTIC
static __always_inline __u32 se_inherit_ne64(__u64 a, __u64 b)
{
	__u64 difference = a ^ b, negative = difference;
	asm volatile("" : "+r"(negative));
	negative = -negative;
	return (__u32)((difference | negative) >> 63);
}
#endif

/* Pure preflight shared by the legacy and eventual typed-pool child birth
 * paths. Include after shared_control.h and shared_exec.h. The caller holds
 * the early route claim across this check and final commit; this function
 * acquires no lock and invokes no map helper. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SNAPSHOT_MATCH_NOINLINE_DIAGNOSTIC
#define SE_INHERIT_MATCH_ATTR __attribute__((noinline))
#else
#define SE_INHERIT_MATCH_ATTR __always_inline
#endif
static SE_INHERIT_MATCH_ATTR int
se_inherit_snapshot_matches(const struct se_route_claim *claim,
			    const struct se_snapshot *snapshot,
			    const struct er_work *projected)
{
	if (!claim || !snapshot || !projected ||
	    snapshot->scope != claim->scope ||
	    snapshot->serial != claim->serial ||
	    snapshot->generation != claim->generation ||
	    !se_snapshot_metadata_valid(&snapshot->metadata, snapshot->count,
					claim->generation))
		return 0;
	for (__u32 i = 0; i < 8; i++) {
		if (i >= snapshot->count)
			break;
		int found = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_SNAPSHOT_BRANCHLESS_DIAGNOSTIC
		int unknown = 0;
#ifdef __clang__
#pragma clang loop unroll(disable)
#endif
		for (__u32 j = 0; j < 16; j++) {
			const struct er_row *row = &projected->rows[j];
			int match =
				(1U ^
				 se_inherit_ne64(
					 row->uid,
					 snapshot->metadata.policy_uids[i])) &
				(1U ^
				 se_inherit_ne64(
					 row->epoch,
					 snapshot->metadata.root_epochs[i]));
			found += match;
			unknown |= match & !er_role_known(row);
		}
		if (found != 1 ||
		    (claim->execution_class == 2 &&
		     (snapshot->metadata.required_known & (1U << i)) &&
		     unknown))
			return 0;
#else
		for (__u32 j = 0; j < 16; j++) {
			const struct er_row *row = &projected->rows[j];
			if (row->uid != snapshot->metadata.policy_uids[i] ||
			    row->epoch != snapshot->metadata.root_epochs[i])
				continue;
			found++;
			if (claim->execution_class == 2 &&
			    (snapshot->metadata.required_known & (1U << i)) &&
			    !er_role_known(row))
				return 0;
		}
		if (found != 1)
			return 0;
#endif
	}
	return 1;
}
#undef SE_INHERIT_MATCH_ATTR

/* Final inheritance mutation, with no lookup or helper. The caller holds
 * the exact parent TASK semantic lock and its original route claim; child
 * belongs exclusively to this unpublished task_alloc constructor. An opaque
 * TASK path must supply both lexical handles instead of relooking up an
 * address-keyed row. No parent/child lock nesting is required. */
#define SE_INHERIT_COMMIT_STALE (-1)
#define SE_INHERIT_COMMIT_PUBLISH_FAULT (-2)
static __always_inline int se_inherit_child_commit_locked(
	const struct se_task_state *parent, struct se_task_state *child,
	const struct se_route_claim *claim, const struct se_exec_work *history,
	const struct er_work *inherited)
{
	if (!parent || !child || !claim || !history || !inherited ||
	    parent->physical_cookie != history->physical_cookie ||
	    parent->scope_cookie != claim->scope ||
	    parent->flags != history->flags ||
	    parent->eligibility_version != history->eligibility_version ||
	    parent->committed.version != history->view.work.base_version ||
	    child->scope_cookie != claim->scope ||
	    child->scope_slot != claim->slot || child->flags != SE_TASK_LIVE ||
	    child->committed.version || child->exec.owned ||
	    child->reader.owned || child->next_invocation)
		return SE_INHERIT_COMMIT_STALE;
	if (se_child_roles_publish(&child->committed, inherited))
		return SE_INHERIT_COMMIT_PUBLISH_FAULT;
	/* task_alloc precedes final parent/cgroup publication. This copy is not
	 * eligibility: a successful-birth hook and held fork claim validate it. */
	child->flags = SE_TASK_LIVE;
	return 0;
}
#endif
