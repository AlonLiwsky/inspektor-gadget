/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_BIRTH_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_BIRTH_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE)
#error "opaque birth requires exact route and semantic TASK candidates"
#endif
#include "shared_inherit_snapshot.h"

/* One already-owned original-route claim pins its account until commit/abort.
 * The caller retains and releases that claim on every branch. Keep prepare
 * separate from directory publication: a selected task_alloc must project and
 * validate parent roles, then write them to the unpublished child under its
 * exact constructor lease before calling publish. The isolated fixture has no
 * authenticated parent and exercises only the raw lifecycle transaction. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_TAILCALL_DIAGNOSTIC
#define SE_OP_PREPARE_CHILD_ATTR __attribute__((always_inline)) inline
#define SE_OP_PUBLISH_SNAPSHOT_ATTR __attribute__((always_inline)) inline
#else
#define SE_OP_PREPARE_CHILD_ATTR __attribute__((noinline))
#define SE_OP_PUBLISH_SNAPSHOT_ATTR __attribute__((noinline))
#endif
static SE_OP_PREPARE_CHILD_ATTR int
se_op_prepare_charged_child(const struct se_route_claim *claim,
			    struct se_oc_reservation *reservation)
{
	if (!claim || !reservation)
		return SE_OL_CORRUPT;
	int status = se_oc_reserve_route_claim(claim, reservation);
	if (status != SE_OL_OK)
		return status;
	status = se_oc_begin_charged(reservation);
	if (status != SE_OL_OK)
		return status; /* charge stays retained/faulted; no invented refund */
	status = se_op_initialize_task_semantic(reservation);
	if (status == SE_OL_OK)
		return SE_OL_OK;
	return se_op_abort_semantic_birth(reservation) == SE_OL_OK ?
		       status :
		       SE_OL_CORRUPT;
}

/* The child-role lexical lock has no lifetime across archive or directory
 * publication. Isolate its handle frame so the full callback does not keep
 * that stack quantum while finishing the charged TASK transaction. */
static __attribute__((noinline)) int
se_op_store_charged_child_roles(struct se_oc_reservation *reservation,
				const struct er_work *projected)
{
	struct se_op_child_roles_handle child_roles = {};
	struct er_state *roles = 0;
	int status = se_op_child_roles_begin(reservation, &child_roles, &roles);
	if (status != SE_OL_OK)
		return status;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_HANDOFF_STOP_AFTER_CHILD_ROLE_OPEN
#ifndef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_HANDOFF_DIAGNOSTIC
#error "stop-after-child-role-open is verifier-isolation-only"
#endif
	se_op_child_roles_end(&child_roles, &roles);
	return SE_OL_CORRUPT;
#endif
	int published = se_child_roles_publish(roles, projected);
	se_op_child_roles_end(&child_roles, &roles);
	return published ? SE_OL_CORRUPT : SE_OL_OK;
}

/* A dead predecessor may still own the same original-key HASH cell until
 * its exact reaper runs. A new task_alloc must not mistake that EEXIST for a
 * full TASK/WORK account or overwrite the predecessor by address alone.
 * The replacement primitives take an independently revalidated old hold,
 * transfer exclusive ownership by scalar CAS, and give the old charge its
 * DIR_DONE receipt before the new child becomes LIVE. */
#define SE_OP_INSERT_RETRY 1
static __attribute__((noinline)) int
se_op_replace_charged_child(struct se_oc_reservation *reservation,
			    const void *opaque_key, const void *archive)
{
	struct se_ol_observation predecessor = {};
	int status = se_ol_observe(opaque_key, &predecessor);
	if (status != SE_OL_OK) {
		/* The predecessor's key was deleted after our EEXIST. Nothing was
		 * held or written: return the intact constructor (NO_ENTRY, one
		 * lease) for exactly one fresh insertion by the caller. Part of the
		 * physical-reuse fix in every build, never a witness option. */
		if (status == SE_OL_STALE)
			return -1;
#ifdef SE_OP_REPLACE_FAILURE
		SE_OP_REPLACE_FAILURE(0); /* test-only: observation refused */
#endif
		goto abort;
	}
	status = se_ol_read_observation(&predecessor);
	if (status != SE_OL_OK) {
#ifdef SE_OP_REPLACE_FAILURE
		SE_OP_REPLACE_FAILURE(1); /* test-only: zero/withdrawn value */
#endif
		goto abort;
	}
	status = se_ow_hold_replacement(&predecessor);
	if (status != SE_OL_OK) {
#ifdef SE_OP_REPLACE_FAILURE
		SE_OP_REPLACE_FAILURE(2); /* test-only: predecessor claimed */
#endif
		goto abort;
	}
	status = se_ow_claim_replacement(reservation->meta, reservation->cookie,
					 &predecessor, archive);
	if (status != SE_OL_OK) {
#ifdef SE_OP_REPLACE_FAILURE
		SE_OP_REPLACE_FAILURE(3); /* test-only: claim lost */
#endif
		if (predecessor.stage == SE_OL_HELD)
			goto fault; /* contradictory old hold: never invent release */
		goto abort;
	}
	status = se_ow_publish_replacement(
		reservation->meta, reservation->cookie, &predecessor, archive);
	if (status != SE_OL_OK) {
		if (predecessor.stage == SE_OL_EXCLUSIVE &&
		    se_ow_cancel_replacement_claim(
			    &predecessor, reservation->locator) == SE_OL_OK)
			goto abort;
		/* CAS_ATTEMPTED may have changed the directory. Keep both
		 * charges pinned instead of aborting a possibly published child. */
		goto fault;
	}
	status = se_op_finish_semantic_birth(reservation);
	if (status == SE_OL_OK)
		return SE_OL_OK;
abort:
	return se_op_abort_semantic_birth(reservation) == SE_OL_OK ?
		       status :
		       SE_OL_CORRUPT;
fault:
	if (reservation->account_slot >= SE_OC_ACCOUNTS ||
	    reservation->task_slot >= SE_OL_TASKS ||
	    reservation->task_slot / SE_OC_QUOTA != reservation->account_slot)
		return SE_OL_CORRUPT;
	__u32 local = reservation->task_slot -
		      reservation->account_slot * SE_OC_QUOTA;
	if (local >= SE_OC_QUOTA)
		return SE_OL_CORRUPT;
	(void)se_oc_fault_exact(reservation->account, reservation->charge,
				local, reservation->cookie);
	return SE_OL_CORRUPT;
}

/* The child-role lock is closed before archive/directory publication. Keep
 * these later fallible transitions in their own frame; every failure still
 * aborts the exact charged, unpublished constructor. */
static __attribute__((noinline)) int
se_op_finish_charged_child_publication(struct se_oc_reservation *reservation,
				       const void *opaque_key)
{
	int status = se_ow_archive(reservation->meta, reservation->task_slot,
				   reservation->cookie, opaque_key);
	if (status != SE_OL_OK)
		goto abort;
	const __u64 *archive = archive_lookup(reservation->task_slot);
	if (!archive) {
		status = SE_OL_CORRUPT;
		goto abort;
	}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_HANDOFF_STOP_AFTER_ARCHIVE
#ifndef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_HANDOFF_DIAGNOSTIC
#error "stop-after-archive is verifier-isolation-only"
#endif
	status = SE_OL_CORRUPT;
	goto abort;
#endif
	status = se_ow_insert_zero(reservation->meta, reservation->cookie,
				   archive);
	/* Verifier-cost isolation only. This deliberately denies a contended
	 * constructor after exact abort; it must never be used for policy. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_HANDOFF_STOP_BEFORE_REPLACEMENT
#ifndef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_HANDOFF_DIAGNOSTIC
#error "stop-before-replacement is verifier-isolation-only"
#endif
	if (status == SE_OL_CONTENDED)
		goto abort;
#endif
	/* -1: the colliding key vanished before replacement observed it. Retry
	 * the insertion once; a second collision or failure aborts exactly. */
	if (status == SE_OL_CONTENDED) {
		status = se_op_replace_charged_child(reservation, opaque_key,
						     archive);
		if (status != -1)
			return status;
		status = se_ow_insert_zero(reservation->meta,
					   reservation->cookie, archive);
	}
	if (status != SE_OL_OK)
		goto abort;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_HANDOFF_STOP_AFTER_INSERT_ZERO
#ifndef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_HANDOFF_DIAGNOSTIC
#error "stop-after-insert-zero is verifier-isolation-only"
#endif
	status = SE_OL_CORRUPT;
	goto abort;
#endif
	status = se_ow_publish_zero(reservation->meta, reservation->cookie,
				    archive);
	if (status != SE_OL_OK)
		goto abort;
#ifdef SE_OP_ABORT_AFTER_PUBLISH_ZERO
	/* Diagnostic fault edge: a denied task_alloc cannot rely on task_free. */
	if (SE_OP_ABORT_AFTER_PUBLISH_ZERO()) {
		status = SE_OL_CORRUPT;
		goto abort;
	}
#endif
	status = se_op_finish_semantic_birth(reservation);
	if (status == SE_OL_OK)
		return SE_OL_OK;
abort:
	return se_op_abort_semantic_birth(reservation) == SE_OL_OK ?
		       status :
		       SE_OL_CORRUPT;
}

/* Caller must still own the same claim and charged constructor. The caller
 * supplies a parent-derived canonical projection and the held immutable
 * snapshot. This helper checks charge/claim identity, but cannot establish
 * the parent TASK/WORK lineage or snapshot membership that produced the
 * projection; the parent-WORK path checks those before charge. It writes
 * roles before opaque-key directory publication. Any failure after
 * charge attempts exact abort, never a synthetic refund. */
static SE_OP_PUBLISH_SNAPSHOT_ATTR int
se_op_publish_charged_child_after_snapshot(
	const struct se_route_claim *claim, const struct se_snapshot *snapshot,
	const struct er_work *projected, const void *opaque_key,
	struct se_oc_reservation *reservation)
{
	if (!reservation)
		return SE_OL_CORRUPT;
	int status = SE_OL_CORRUPT;
	if (!claim || !claim->owned || claim->reserved || !snapshot ||
	    !projected || projected->error || !projected->prepared ||
	    !projected->authority_version || !opaque_key ||
	    claim->scope != reservation->scope ||
	    claim->incarnation != reservation->incarnation ||
	    claim->slot != reservation->account_slot)
		goto abort;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_HANDOFF_STOP_AFTER_SNAPSHOT_MATCH
#ifndef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_HANDOFF_DIAGNOSTIC
#error "stop-after-snapshot-match is verifier-isolation-only"
#endif
	status = SE_OL_CORRUPT;
	goto abort;
#endif
	status = se_op_store_charged_child_roles(reservation, projected);
	if (status != SE_OL_OK)
		goto abort;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_HANDOFF_STOP_AFTER_CHILD_ROLES
#ifndef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_HANDOFF_DIAGNOSTIC
#error "stop-after-child-roles is verifier-isolation-only"
#endif
	status = SE_OL_CORRUPT;
	goto abort;
#endif
	return se_op_finish_charged_child_publication(reservation, opaque_key);
abort:
	return se_op_abort_semantic_birth(reservation) == SE_OL_OK ?
		       status :
		       SE_OL_CORRUPT;
}

/* Standalone charged births keep the full snapshot check at final use.
 * Parent-WORK births may move this same check before child charge only while
 * retaining one lexical WORK lease and the same route claim and snapshot
 * through publication; see se_op_construct_child_from_parent_work. */
static __attribute__((noinline)) int se_op_publish_charged_child(
	const struct se_route_claim *claim, const struct se_snapshot *snapshot,
	const struct er_work *projected, const void *opaque_key,
	struct se_oc_reservation *reservation)
{
	if (!reservation)
		return SE_OL_CORRUPT;
	if (!se_inherit_snapshot_matches(claim, snapshot, projected)) {
		(void)se_op_abort_semantic_birth(reservation);
		return SE_OL_CORRUPT;
	}
	return se_op_publish_charged_child_after_snapshot(
		claim, snapshot, projected, opaque_key, reservation);
}
#endif
