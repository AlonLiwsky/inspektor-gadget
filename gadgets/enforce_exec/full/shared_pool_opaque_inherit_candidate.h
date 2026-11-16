/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_INHERIT_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_INHERIT_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE)
#error "opaque parent inheritance requires exact TASK and WORK semantics"
#endif
#include "shared_pool_opaque_work_semantic_candidate.h"
#include "shared_pool_opaque_birth_candidate.h"

/* Snapshot the physically opened parent, not an address-keyed relookup or a
 * cgroup tuple. The caller holds the original route claim, lexical parent
 * TASK lease and ACTIVE WORK semantic ticket through this call and later
 * classification/projection. WORK bytes are stable until semantic_done. No
 * helper runs while the TASK metadata lock is held. This copies provenance;
 * it does not classify epochs, authenticate the snapshot or commit a child. */
static __attribute__((noinline)) int
se_op_parent_snapshot_held(struct se_ol_payload_handle *owner,
			   const struct se_owk_semantic_handle *semantic,
			   struct se_invocation *work,
			   const struct se_route_claim *claim)
{
	if (!owner || !semantic || semantic->held != 1 ||
	    semantic->owner != owner || !semantic->ticket ||
	    !semantic->payload || work != &semantic->payload->semantic ||
	    !claim || !claim->owned || claim->reserved || !claim->scope ||
	    !claim->generation || !owner->lease.cookie ||
	    semantic->ticket->held != 1 || semantic->ticket->stage != 3 ||
	    semantic->ticket->scope != claim->scope ||
	    semantic->ticket->account_slot != claim->slot ||
	    semantic->ticket->owner_locator != owner->lease.locator ||
	    semantic->ticket->owner_cookie != owner->lease.cookie ||
	    semantic->ticket->owner_slot != owner->lease.slot ||
	    work->scope != claim->scope ||
	    work->cookie != semantic->ticket->cookie ||
	    work->sequence != semantic->ticket->invocation_sequence)
		return SE_OL_CORRUPT;
	struct se_task_state *parent = 0;
	int result = se_op_task_semantic_begin(owner, &parent);
	if (result != SE_OL_OK)
		return result;
	int exact = parent->physical_cookie == owner->lease.cookie &&
		    parent->scope_cookie == claim->scope &&
		    parent->scope_slot == claim->slot &&
		    parent->flags == SE_TASK_QUALIFIED &&
		    parent->committed.version != 0;
	if (exact)
		se_exec_snapshot_locked(parent, claim->generation,
					&work->history);
	se_op_task_semantic_end(owner, &parent);
	return exact ? SE_OL_OK : SE_OL_STALE;
}

#ifdef SE_OWK_CATALOGUE_EPOCH
#include "shared_pool_opaque_work_catalogue_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PARENT_PROJECT_SPLIT_DIAGNOSTIC
/* Keep cache acquisition/classification out of the later canonical
 * projection's BPF frame. The caller retains its lexical WORK and route. */
static __attribute__((noinline)) int
se_op_parent_fill_cache_held(struct se_owk_semantic_handle *semantic,
			     const struct se_route_claim *claim)
{
	return se_owk_catalogue_fill(semantic, claim);
}
static __attribute__((noinline)) int
se_op_parent_classify_held(struct se_owk_semantic_handle *semantic,
			   struct se_invocation *work,
			   const struct se_route_claim *claim)
{
	if (se_op_parent_fill_cache_held(semantic, claim) != SE_OL_OK ||
	    se_pool_catalogue_classify(&work->history.view,
				       &semantic->payload->catalogue, claim))
		return SE_OL_CORRUPT;
	return SE_OL_OK;
}
#endif
/* The same held WORK ticket carries the parent snapshot, fixed-position
 * COMPLETE catalogue cache and projected child rows. The original claim
 * remains owned through the last cache read and later child publication.
 * Unknown history is a fault, never an inferred empty parent role set. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PARENT_PROJECT_INLINE_DIAGNOSTIC
#define SE_OP_PARENT_PROJECT_ATTR __attribute__((always_inline)) inline
#else
#define SE_OP_PARENT_PROJECT_ATTR __attribute__((noinline))
#endif
static SE_OP_PARENT_PROJECT_ATTR int
se_op_parent_project_held(struct se_owk_semantic_handle *semantic,
			  struct se_invocation *work,
			  const struct se_route_claim *claim)
{
	if (!semantic || semantic->held != 1 || !semantic->owner ||
	    !semantic->ticket || !semantic->payload ||
	    work != &semantic->payload->semantic || !claim || !claim->owned ||
	    claim->reserved ||
	    work->history.physical_cookie != semantic->owner->lease.cookie ||
	    work->history.scope_cookie != claim->scope ||
	    work->history.flags != SE_TASK_QUALIFIED ||
	    work->history.view.work.error ||
	    work->history.view.work.authority_version != claim->generation)
		return SE_OL_CORRUPT;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PARENT_PROJECT_SPLIT_DIAGNOSTIC
	if (se_op_parent_classify_held(semantic, work, claim) != SE_OL_OK)
		return SE_OL_CORRUPT;
	if (er_canonical_project(&work->history.view, &work->inherited) ||
	    !se_pool_catalogue_projection_matches(
		    &work->history.view, &work->inherited,
		    &semantic->payload->catalogue, claim))
		return SE_OL_CORRUPT;
#else
	if (se_owk_catalogue_fill(semantic, claim) != SE_OL_OK ||
	    se_pool_catalogue_classify(&work->history.view,
				       &semantic->payload->catalogue, claim) ||
	    er_canonical_project(&work->history.view, &work->inherited) ||
	    !se_pool_catalogue_projection_matches(
		    &work->history.view, &work->inherited,
		    &semantic->payload->catalogue, claim))
		return SE_OL_CORRUPT;
#endif
	return SE_OL_OK;
}
#undef SE_OP_PARENT_PROJECT_ATTR

/* Recheck the source TASK before publishing its child's projected roles.
 * task_alloc runs on that very parent task, so the parent cannot execute a
 * second callback or task_free between this lexical check and child commit.
 * Never replace this with a borrowed address-keyed row or a copied tuple. */
static __attribute__((noinline)) int
se_op_parent_revalidate_held(struct se_ol_payload_handle *owner,
			     const struct se_owk_semantic_handle *semantic,
			     const struct se_invocation *work,
			     const struct se_route_claim *claim)
{
	if (!owner || !semantic || semantic->held != 1 ||
	    semantic->owner != owner || !semantic->ticket ||
	    !semantic->payload || work != &semantic->payload->semantic ||
	    !claim || !claim->owned || claim->reserved ||
	    semantic->ticket->held != 1 || semantic->ticket->stage != 3 ||
	    semantic->ticket->scope != claim->scope ||
	    semantic->ticket->account_slot != claim->slot ||
	    semantic->ticket->owner_locator != owner->lease.locator ||
	    semantic->ticket->owner_cookie != owner->lease.cookie ||
	    semantic->ticket->owner_slot != owner->lease.slot ||
	    work->scope != semantic->ticket->scope ||
	    work->cookie != semantic->ticket->cookie ||
	    work->sequence != semantic->ticket->invocation_sequence)
		return SE_OL_CORRUPT;
	struct se_task_state *parent = 0;
	int status = se_op_task_semantic_begin(owner, &parent);
	if (status != SE_OL_OK)
		return status;
	const struct se_exec_work *history = &work->history;
	int exact =
		parent->physical_cookie == owner->lease.cookie &&
		parent->physical_cookie == history->physical_cookie &&
		parent->scope_cookie == claim->scope &&
		parent->scope_cookie == history->scope_cookie &&
		parent->scope_slot == claim->slot &&
		parent->flags == SE_TASK_QUALIFIED &&
		parent->flags == history->flags &&
		parent->eligibility_version == history->eligibility_version &&
		parent->committed.version == history->view.work.base_version;
	se_op_task_semantic_end(owner, &parent);
	return exact ? SE_OL_OK : SE_OL_STALE;
}

/* Last-use handoff: the accepted cache and projected rows must still belong
 * to the exact parent WORK under the same route claim. On refusal, abort the
 * charged unpublished child; on success, child roles and directory publish
 * before WORK or route release. The caller owns those later releases. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_TAILCALL_DIAGNOSTIC
#define SE_OP_PUBLISH_CHILD_ATTR __attribute__((always_inline)) inline
#else
#define SE_OP_PUBLISH_CHILD_ATTR __attribute__((noinline))
#endif
static SE_OP_PUBLISH_CHILD_ATTR int
se_op_publish_child_from_parent_work_after_projection(
	struct se_owk_semantic_handle *semantic,
	const struct se_route_claim *claim, const struct se_snapshot *snapshot,
	const void *child_key, struct se_oc_reservation *child)
{
	if (!child)
		return SE_OL_CORRUPT;
	struct se_ol_payload_handle *owner = semantic ? semantic->owner : 0;
	struct se_invocation *work = semantic && semantic->payload ?
					     &semantic->payload->semantic :
					     0;
	int status = se_op_parent_revalidate_held(owner, semantic, work, claim);
	if (status != SE_OL_OK) {
		(void)se_op_abort_semantic_birth(child);
		return status;
	}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_HANDOFF_STOP_AFTER_REVALIDATE
#ifndef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_HANDOFF_DIAGNOSTIC
#error "stop-after-revalidate is verifier-isolation-only"
#endif
	(void)se_op_abort_semantic_birth(child);
	return SE_OL_CORRUPT;
#endif
	return se_op_publish_charged_child_after_snapshot(
		claim, snapshot, &work->inherited, child_key, child);
}
#undef SE_OP_PUBLISH_CHILD_ATTR

/* Direct callers must still validate the cache at final use. The charged
 * constructor below is the only caller allowed to precheck it before charge
 * while retaining the same lexical WORK lease and route claim. */
static __attribute__((noinline)) int se_op_publish_child_from_parent_work(
	struct se_owk_semantic_handle *semantic,
	const struct se_route_claim *claim, const struct se_snapshot *snapshot,
	const void *child_key, struct se_oc_reservation *child)
{
	if (!child)
		return SE_OL_CORRUPT;
	struct se_invocation *work = semantic && semantic->payload ?
					     &semantic->payload->semantic :
					     0;
	if (!work ||
	    !se_pool_catalogue_projection_matches(
		    &work->history.view, &work->inherited,
		    &semantic->payload->catalogue, claim) ||
	    !se_inherit_snapshot_matches(claim, snapshot, &work->inherited)) {
		(void)se_op_abort_semantic_birth(child);
		return SE_OL_CORRUPT;
	}
	return se_op_publish_child_from_parent_work_after_projection(
		semantic, claim, snapshot, child_key, child);
}

/* Preflight immutable WORK and snapshot evidence before the charged child
 * reservation. It is a separate verifier frame in the diagnostic layout;
 * the exact parent TASK check still occurs after charge. */
static __attribute__((noinline)) int
se_op_preflight_child_from_parent_work(struct se_owk_semantic_handle *semantic,
				       const struct se_route_claim *claim,
				       const struct se_snapshot *snapshot,
				       const void *child_key)
{
	/* Validate immutable WORK cache/projection and snapshot before child
	 * reservation, while the lexical WORK lease and route claim remain owned.
	 * The physical parent TASK is revalidated after charge, immediately
	 * before publish. No other writer can mutate this WORK or claim here. */
	if (!semantic || semantic->held != 1 || !semantic->payload ||
	    !semantic->ticket || !claim || !claim->owned || claim->reserved ||
	    !snapshot)
		return SE_OL_CORRUPT;
	const struct se_invocation *work = &semantic->payload->semantic;
	if (!se_pool_catalogue_projection_matches(
		    &work->history.view, &work->inherited,
		    &semantic->payload->catalogue, claim) ||
	    !se_inherit_snapshot_matches(claim, snapshot, &work->inherited))
		return SE_OL_CORRUPT;
	return child_key ? SE_OL_OK : SE_OL_CORRUPT;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_TAILCALL_DIAGNOSTIC
/* The diagnostic's route-claim frame split permits inlining this constructor
 * to save one older-kernel BPF call quantum without merging route pointers. */
#define SE_OP_CONSTRUCT_CHILD_ATTR __attribute__((always_inline)) inline
#else
#define SE_OP_CONSTRUCT_CHILD_ATTR __attribute__((noinline))
#endif
static SE_OP_CONSTRUCT_CHILD_ATTR int
se_op_construct_child_from_parent_work(struct se_owk_semantic_handle *semantic,
				       const struct se_route_claim *claim,
				       const struct se_snapshot *snapshot,
				       const void *child_key)
{
	if (se_op_preflight_child_from_parent_work(semantic, claim, snapshot,
						   child_key) != SE_OL_OK)
		return SE_OL_CORRUPT;
	struct se_oc_reservation child = {};
	int status = se_op_prepare_charged_child(claim, &child);
	if (status != SE_OL_OK)
		return status;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_HANDOFF_STOP_AFTER_PREPARE
#ifndef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_HANDOFF_DIAGNOSTIC
#error "stop-after-prepare is verifier-isolation-only"
#endif
	(void)se_op_abort_semantic_birth(&child);
	return SE_OL_CORRUPT; /* verifier isolation only; no child publication */
#endif
	return se_op_publish_child_from_parent_work_after_projection(
		semantic, claim, snapshot, child_key, &child);
}
#endif
#endif
