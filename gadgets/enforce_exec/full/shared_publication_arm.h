/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_PUBLICATION_ARM_H
#define ENFORCE_EXEC_SHARED_PUBLICATION_ARM_H
#include "shared_route.h"
#include "shared_arm_abi.h"
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#include "shared_catalogue_wire.h"

/* Not a se_operation. se_command must never publish these. Only the
 * authenticated cgroup_kn_lock_live fexit may call the locked producer, and
 * only while that barrier holds cgroup_mutex. A syscall receipt is not commit
 * or withdrawal. This is not native Ready or kernel qualification. */
/* The fexit result is the cgroup whose kernfs file was locked. On the pinned
 * amd64 source, cgroup_id(cgrp) is cgrp->kn->id. Never arm a binding from an
 * A-side lock on another cgroup, even if it uses drain_offline=true. */
static __always_inline int
se_arm_target_cgroup_matches(__u64 observed,
			     const struct se_route_anchor *route)
{
	return observed && route && route->cgroup_identity == observed;
}

/* Fallible. i is a constant slot. Empty cells may receive identity; an
 * occupied cell must already be this scope and UID, with epoch zero or the
 * same immutable value. */
static __always_inline int se_arm_cell_ready(const struct se_route_anchor *a,
					     const struct se_snapshot *s,
					     const struct se_arm_request *req,
					     struct se_epoch_cell *cell,
					     __u32 i)
{
	if (!cell || !a->scope || req->scope != a->scope || !req->epochs[i] ||
	    req->epochs[i] != s->metadata.root_epochs[i] ||
	    !s->metadata.policy_uids[i])
		return -1;
	__u64 have_scope = cell->scope, have_uid = cell->uid,
	      have_epoch = cell->epoch;
	int empty = !have_scope && !have_uid && !have_epoch;
	int same = have_scope == a->scope &&
		   have_uid == s->metadata.policy_uids[i] &&
		   (have_epoch == 0 || have_epoch == req->epochs[i]);
	return !empty && !same ? -1 : 0;
}

/* Distinct policies must not alias one cell. Slot indexes are constant. */
static __always_inline int se_arm_epochs_ready(
	const struct se_route_anchor *a, const struct se_binding_snapshots *b,
	const struct se_snapshot *s, const struct se_arm_request *req,
	struct se_epoch_cell *cells[8])
{
	if (!a->scope || a->scope != b->scope || !cells ||
	    s->count != req->count)
		return -1;
	if (req->count > 0 && se_arm_cell_ready(a, s, req, cells[0], 0))
		return -1;
	if (req->count > 1 &&
	    (cells[1] == cells[0] || se_arm_cell_ready(a, s, req, cells[1], 1)))
		return -1;
	if (req->count > 2 && (cells[2] == cells[0] || cells[2] == cells[1] ||
			       se_arm_cell_ready(a, s, req, cells[2], 2)))
		return -1;
	if (req->count > 3 &&
	    (cells[3] == cells[0] || cells[3] == cells[1] ||
	     cells[3] == cells[2] || se_arm_cell_ready(a, s, req, cells[3], 3)))
		return -1;
	if (req->count > 4 && (cells[4] == cells[0] || cells[4] == cells[1] ||
			       cells[4] == cells[2] || cells[4] == cells[3] ||
			       se_arm_cell_ready(a, s, req, cells[4], 4)))
		return -1;
	if (req->count > 5 &&
	    (cells[5] == cells[0] || cells[5] == cells[1] ||
	     cells[5] == cells[2] || cells[5] == cells[3] ||
	     cells[5] == cells[4] || se_arm_cell_ready(a, s, req, cells[5], 5)))
		return -1;
	if (req->count > 6 && (cells[6] == cells[0] || cells[6] == cells[1] ||
			       cells[6] == cells[2] || cells[6] == cells[3] ||
			       cells[6] == cells[4] || cells[6] == cells[5] ||
			       se_arm_cell_ready(a, s, req, cells[6], 6)))
		return -1;
	if (req->count > 7 &&
	    (cells[7] == cells[0] || cells[7] == cells[1] ||
	     cells[7] == cells[2] || cells[7] == cells[3] ||
	     cells[7] == cells[4] || cells[7] == cells[5] ||
	     cells[7] == cells[6] || se_arm_cell_ready(a, s, req, cells[7], 7)))
		return -1;
	return 0;
}

/* Infallible continuation. Only prevalidated slots are written. No lookup,
 * lock, helper or failure path belongs here. */
static __always_inline void se_arm_store_slot(struct se_epoch_cell *cell,
					      const struct se_route_anchor *a,
					      const struct se_snapshot *s,
					      const struct se_arm_request *req,
					      __u32 i)
{
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	/* se_arm_epochs_ready proved every slot below count non-NULL, but the
	 * product's larger commit preflight (G019 gap 3) makes clang reload
	 * req->count here, so the verifier no longer correlates the two and
	 * walks a count > i path with cells[i] NULL. Re-proving it is free and
	 * changes nothing (never NULL on a path that reaches here). */
	if (!cell)
		return;
#endif
	cell->scope = a->scope;
	cell->uid = s->metadata.policy_uids[i];
	cell->epoch = req->epochs[i];
	cell->reserved0 = 0;
	cell->reserved1 = 0;
}
/* 0 = index already names this bank. 1 = insert. -1 = refuse. An index is not
 * authority until the cell itself carries this scope, UID and epoch. */
static __always_inline int
se_arm_index_decision(const __u32 *have, __u32 bank,
		      const struct se_epoch_cell *cell, __u64 scope, __u64 uid)
{
	int empty, same;

	if (!scope || !uid || uid == ~0ULL || !cell)
		return -1;
	if (have)
		return *have == bank ? 0 : -1;
	empty = !cell->scope && !cell->uid && !cell->epoch &&
		!cell->reserved0 && !cell->reserved1;
	same = cell->scope == scope && cell->uid == uid && cell->epoch &&
	       cell->epoch != ~0ULL && !cell->reserved0 && !cell->reserved1;
	return empty || same ? 1 : -1;
}
static __always_inline int se_arm_uids_match(const struct se_snapshot *s,
					     const struct se_arm_request *req,
					     const __u64 uid[8])
{
	if (!s || !req)
		return -1;
	if (req->count > 0 && s->metadata.policy_uids[0] != uid[0])
		return -1;
	if (req->count > 1 && s->metadata.policy_uids[1] != uid[1])
		return -1;
	if (req->count > 2 && s->metadata.policy_uids[2] != uid[2])
		return -1;
	if (req->count > 3 && s->metadata.policy_uids[3] != uid[3])
		return -1;
	if (req->count > 4 && s->metadata.policy_uids[4] != uid[4])
		return -1;
	if (req->count > 5 && s->metadata.policy_uids[5] != uid[5])
		return -1;
	if (req->count > 6 && s->metadata.policy_uids[6] != uid[6])
		return -1;
	if (req->count > 7 && s->metadata.policy_uids[7] != uid[7])
		return -1;
	return 0;
}

static __always_inline void se_arm_store_epochs(
	struct se_epoch_cell *cells[8], const struct se_route_anchor *a,
	const struct se_snapshot *s, const struct se_arm_request *req)
{
	if (req->count > 0)
		se_arm_store_slot(cells[0], a, s, req, 0);
	if (req->count > 1)
		se_arm_store_slot(cells[1], a, s, req, 1);
	if (req->count > 2)
		se_arm_store_slot(cells[2], a, s, req, 2);
	if (req->count > 3)
		se_arm_store_slot(cells[3], a, s, req, 3);
	if (req->count > 4)
		se_arm_store_slot(cells[4], a, s, req, 4);
	if (req->count > 5)
		se_arm_store_slot(cells[5], a, s, req, 5);
	if (req->count > 6)
		se_arm_store_slot(cells[6], a, s, req, 6);
	if (req->count > 7)
		se_arm_store_slot(cells[7], a, s, req, 7);
}

static __always_inline int
se_arm_commit_locked(int from_barrier, struct se_route_anchor *a,
		     struct se_binding_snapshots *b,
		     const struct se_arm_request *req,
		     struct se_epoch_cell *cells[8])
{
	if (!from_barrier || !a || !b || !req || !cells || req->reserved ||
	    req->operation != SE_ARM_COMMIT || !req->scope ||
	    req->scope != a->scope || req->record >= 2 || !req->count ||
	    req->count > 8 || req->expected_generation != b->generation ||
	    req->qualification != a->admission_serial)
		return -1;
	/* Every production snapshot reader is acquired through a route claim,
	 * but a lexical route claim can be released without becoming a reader.
	 * Therefore the route serial dominates, rather than equals, the binding
	 * serial. Both are checked under the same lock: the route qualification
	 * proves no new admission, while binding preflight uses its current serial. */
	__u32 record = req->record & 1;
	struct se_snapshot *s = &b->records[record];
	if (!se_snapshot_metadata_valid(&s->metadata, req->count,
					b->generation + 1) ||
	    se_arm_epochs_ready(a, b, s, req, cells) ||
	    se_route_commit_preflight_locked(a, b, record, req->serial,
					     req->qualification))
		return -1;
	se_arm_store_epochs(cells, a, s, req);
	se_route_commit_publish_locked(a, b, record);
	return 0;
}

static __always_inline int
se_arm_withdraw_locked(int from_barrier, struct se_route_anchor *a,
		       struct se_binding_snapshots *b,
		       const struct se_arm_request *req)
{
	if (!from_barrier || !a || !b || !req || req->reserved ||
	    req->operation != SE_ARM_WITHDRAW || !req->scope ||
	    req->scope != a->scope ||
	    req->expected_generation != b->generation ||
	    req->qualification != a->admission_serial)
		return -1;
	__u64 generation = b->generation;
	if (se_route_withdraw_locked(a, b) || b->generation != generation ||
	    b->active_serial)
		return -1;
	return 0;
}

#ifndef SE_PUBLICATION_ARM_TEST
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_WRONLY);
	__type(key, __u32);
	__type(value, struct se_arm_request);
} se_arm_requests SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_arm_receipt);
} se_arm_receipts SEC(".maps");
#include "shared_catalogue_kernel.h"
/* Scalar request copy only. Cell pointers stay in registers/stack; a map
 * cannot carry them back to the verifier. Not an epoch authority. */
struct se_arm_frame {
	struct se_arm_request req;
};
_Static_assert(sizeof(struct se_arm_frame) == 176, "arm frame wire");
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_arm_frame);
} se_arm_frame SEC(".maps");
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRCTL_ARM_CANDIDATE
/* Candidate-only stage: publish the cgroup locator while the route is still
 * PREPARING. A reader seeing it early cannot claim the route. Commit must
 * revalidate this exact locator before changing the locked phase to ACTIVE. */
#define SE_ARM_ROUTE_STAGE_CANDIDATE 4
static __always_inline int se_arm_route_stage_candidate(
	struct se_route_anchor *route, struct se_shared_binding *binding,
	const struct se_arm_request *req, __u32 slot, __u64 observed_cgroup)
{
	if (req->record >= 2 || !req->scope || !req->serial)
		return -1;
	__u64 cgroup = 0, locator = 0;
	bpf_spin_lock(&route->lock);
	const struct se_snapshot *snapshot =
		&binding->state.records[req->record & 1];
	if (route->phase == SE_ROUTE_PREPARING && route->incarnation &&
	    route->cgroup_identity == observed_cgroup &&
	    route->scope == req->scope && route->payload_slot == slot &&
	    route->admission_serial == req->qualification &&
	    binding->state.scope == req->scope &&
	    binding->state.generation == req->expected_generation &&
	    binding->state.admission_serial == req->qualification &&
	    snapshot->scope == req->scope && snapshot->serial == req->serial &&
	    snapshot->phase == SE_SNAPSHOT_PREPARED) {
		cgroup = route->cgroup_identity;
		locator = se_route_locator(slot, route->incarnation);
	}
	bpf_spin_unlock(&route->lock);
	if (!cgroup || !locator)
		return -1;
	const __u64 *have = bpf_map_lookup_elem(&se_route_index, &cgroup);
	if (have) {
		if (*have != locator)
			return -1;
	} else if (bpf_map_update_elem(&se_route_index, &cgroup, &locator,
				       BPF_NOEXIST)) {
		have = bpf_map_lookup_elem(&se_route_index, &cgroup);
		if (!have || *have != locator)
			return -1;
	}
	/* A changed route after the fallible map update is not a success receipt.
	 * Its stale locator still cannot admit a nonmatching route incarnation. */
	bpf_spin_lock(&route->lock);
	int valid = route->phase == SE_ROUTE_PREPARING &&
		    route->cgroup_identity == cgroup &&
		    se_route_locator(slot, route->incarnation) == locator &&
		    route->scope == req->scope &&
		    binding->state.scope == req->scope;
	bpf_spin_unlock(&route->lock);
	return valid ? 0 : -1;
}
#endif
static __always_inline int se_arm_bind_one(__u64 scope, __u64 uid, __u32 bank,
					   struct se_epoch_cell *cell,
					   __u32 *created)
{
	struct se_epoch_key key = { scope, uid };
	const __u32 *have;
	int decision;

	if (bank >= SE_PROFILE_ACCEPTED_UIDS)
		return -1;
	have = bpf_map_lookup_elem(&se_epoch_index, &key);
	decision = se_arm_index_decision(have, bank, cell, scope, uid);

	if (decision < 0)
		return -1;
	if (!decision)
		return 0;
	if (bpf_map_update_elem(&se_epoch_index, &key, &bank, BPF_NOEXIST)) {
		have = bpf_map_lookup_elem(&se_epoch_index, &key);
		return !have || *have != bank ? -1 : 0;
	}
	*created = 1;
	return 0;
}
static __always_inline void
se_arm_rollback_one(__u64 scope, __u64 uid, __u32 created,
		    const struct se_epoch_cell *cell)
{
	struct se_epoch_key key = { scope, uid };
	int empty, foreign;

	if (!created || !cell)
		return;
	empty = !cell->scope && !cell->uid && !cell->epoch;
	foreign = cell->scope != scope || cell->uid != uid;
	if (!empty && !foreign)
		return;
	bpf_map_delete_elem(&se_epoch_index, &key);
}
static __always_inline void
se_arm_rollback_bound(__u64 scope, const __u64 uid[8], const __u32 created[8],
		      struct se_epoch_cell *cells[8])
{
	if (created[0])
		se_arm_rollback_one(scope, uid[0], created[0], cells[0]);
	if (created[1])
		se_arm_rollback_one(scope, uid[1], created[1], cells[1]);
	if (created[2])
		se_arm_rollback_one(scope, uid[2], created[2], cells[2]);
	if (created[3])
		se_arm_rollback_one(scope, uid[3], created[3], cells[3]);
	if (created[4])
		se_arm_rollback_one(scope, uid[4], created[4], cells[4]);
	if (created[5])
		se_arm_rollback_one(scope, uid[5], created[5], cells[5]);
	if (created[6])
		se_arm_rollback_one(scope, uid[6], created[6], cells[6]);
	if (created[7])
		se_arm_rollback_one(scope, uid[7], created[7], cells[7]);
}
/* Fallible, and only before the route lock. Record is a constant 0 or 1 so
 * the verifier keeps the binding pointer. A spilled snapshot pointer does not. */
static __always_inline void se_arm_take_uids(const struct se_snapshot *s,
					     __u32 count, __u64 uid[8])
{
	if (count > 0)
		uid[0] = s->metadata.policy_uids[0];
	if (count > 1)
		uid[1] = s->metadata.policy_uids[1];
	if (count > 2)
		uid[2] = s->metadata.policy_uids[2];
	if (count > 3)
		uid[3] = s->metadata.policy_uids[3];
	if (count > 4)
		uid[4] = s->metadata.policy_uids[4];
	if (count > 5)
		uid[5] = s->metadata.policy_uids[5];
	if (count > 6)
		uid[6] = s->metadata.policy_uids[6];
	if (count > 7)
		uid[7] = s->metadata.policy_uids[7];
}
static __always_inline int se_arm_bind_loaded(struct se_binding_snapshots *b,
					      const struct se_arm_request *req,
					      struct se_epoch_cell *cells[8],
					      __u64 uid[8], __u32 created[8])
{
	if (!b || !req || req->record >= 2)
		return -1;
	if ((req->record & 1) == 0)
		se_arm_take_uids(&b->records[0], req->count, uid);
	else
		se_arm_take_uids(&b->records[1], req->count, uid);
	if (req->count > 0 &&
	    se_arm_bind_one(req->scope, uid[0], req->bank_index[0], cells[0],
			    &created[0]))
		return -1;
	if (req->count > 1 &&
	    se_arm_bind_one(req->scope, uid[1], req->bank_index[1], cells[1],
			    &created[1])) {
		se_arm_rollback_bound(req->scope, uid, created, cells);
		return -1;
	}
	if (req->count > 2 &&
	    se_arm_bind_one(req->scope, uid[2], req->bank_index[2], cells[2],
			    &created[2])) {
		se_arm_rollback_bound(req->scope, uid, created, cells);
		return -1;
	}
	if (req->count > 3 &&
	    se_arm_bind_one(req->scope, uid[3], req->bank_index[3], cells[3],
			    &created[3])) {
		se_arm_rollback_bound(req->scope, uid, created, cells);
		return -1;
	}
	if (req->count > 4 &&
	    se_arm_bind_one(req->scope, uid[4], req->bank_index[4], cells[4],
			    &created[4])) {
		se_arm_rollback_bound(req->scope, uid, created, cells);
		return -1;
	}
	if (req->count > 5 &&
	    se_arm_bind_one(req->scope, uid[5], req->bank_index[5], cells[5],
			    &created[5])) {
		se_arm_rollback_bound(req->scope, uid, created, cells);
		return -1;
	}
	if (req->count > 6 &&
	    se_arm_bind_one(req->scope, uid[6], req->bank_index[6], cells[6],
			    &created[6])) {
		se_arm_rollback_bound(req->scope, uid, created, cells);
		return -1;
	}
	if (req->count > 7 &&
	    se_arm_bind_one(req->scope, uid[7], req->bank_index[7], cells[7],
			    &created[7])) {
		se_arm_rollback_bound(req->scope, uid, created, cells);
		return -1;
	}
	return 0;
}
/* Commit does not insert. A missing index is a separate bind barrier so the
 * verifier does not explore map updates inside the publication preflight. */
static __always_inline int se_arm_require_one(__u64 scope, __u64 uid,
					      __u32 bank,
					      struct se_epoch_cell *cell)
{
	struct se_epoch_key key = { scope, uid };
	const __u32 *have = bpf_map_lookup_elem(&se_epoch_index, &key);

	return se_arm_index_decision(have, bank, cell, scope, uid) ? -1 : 0;
}
static __always_inline int
se_arm_require_loaded(struct se_binding_snapshots *b,
		      const struct se_arm_request *req,
		      struct se_epoch_cell *cells[8], __u64 uid[8])
{
	if (!b || !req || req->record >= 2)
		return -1;
	if ((req->record & 1) == 0)
		se_arm_take_uids(&b->records[0], req->count, uid);
	else
		se_arm_take_uids(&b->records[1], req->count, uid);
	if (req->count > 0 && se_arm_require_one(req->scope, uid[0],
						 req->bank_index[0], cells[0]))
		return -1;
	if (req->count > 1 && se_arm_require_one(req->scope, uid[1],
						 req->bank_index[1], cells[1]))
		return -1;
	if (req->count > 2 && se_arm_require_one(req->scope, uid[2],
						 req->bank_index[2], cells[2]))
		return -1;
	if (req->count > 3 && se_arm_require_one(req->scope, uid[3],
						 req->bank_index[3], cells[3]))
		return -1;
	if (req->count > 4 && se_arm_require_one(req->scope, uid[4],
						 req->bank_index[4], cells[4]))
		return -1;
	if (req->count > 5 && se_arm_require_one(req->scope, uid[5],
						 req->bank_index[5], cells[5]))
		return -1;
	if (req->count > 6 && se_arm_require_one(req->scope, uid[6],
						 req->bank_index[6], cells[6]))
		return -1;
	if (req->count > 7 && se_arm_require_one(req->scope, uid[7],
						 req->bank_index[7], cells[7]))
		return -1;
	return 0;
}

static __always_inline int se_arm_load_cells(const struct se_arm_request *req,
					     struct se_epoch_cell *cells[8])
{
	if (!req->count || req->count > 8)
		return -1;
	if (req->count > 0) {
		__u32 index = req->bank_index[0];
		cells[0] = SE_EPOCH_BANK_LOOKUP(&index);
		if (!cells[0])
			return -1;
	}
	if (req->count > 1) {
		__u32 index = req->bank_index[1];
		cells[1] = SE_EPOCH_BANK_LOOKUP(&index);
		if (!cells[1])
			return -1;
	}
	if (req->count > 2) {
		__u32 index = req->bank_index[2];
		cells[2] = SE_EPOCH_BANK_LOOKUP(&index);
		if (!cells[2])
			return -1;
	}
	if (req->count > 3) {
		__u32 index = req->bank_index[3];
		cells[3] = SE_EPOCH_BANK_LOOKUP(&index);
		if (!cells[3])
			return -1;
	}
	if (req->count > 4) {
		__u32 index = req->bank_index[4];
		cells[4] = SE_EPOCH_BANK_LOOKUP(&index);
		if (!cells[4])
			return -1;
	}
	if (req->count > 5) {
		__u32 index = req->bank_index[5];
		cells[5] = SE_EPOCH_BANK_LOOKUP(&index);
		if (!cells[5])
			return -1;
	}
	if (req->count > 6) {
		__u32 index = req->bank_index[6];
		cells[6] = SE_EPOCH_BANK_LOOKUP(&index);
		if (!cells[6])
			return -1;
	}
	if (req->count > 7) {
		__u32 index = req->bank_index[7];
		cells[7] = SE_EPOCH_BANK_LOOKUP(&index);
		if (!cells[7])
			return -1;
	}
	return 0;
}

/* Unselected older-kernel experiment: a committed physical admin temporarily
 * resident in the target cgroup may trigger a non-sleepable LSM callback.
 * This does NOT by itself replace the cgroup_mutex publication contract;
 * lifetime, migration, v1 hierarchy and rollback still need qualification. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRCTL_ARM_CANDIDATE
#if !defined(ENFORCE_EXEC_SHARED_RECOVERY) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE)
#error "prctl arm candidate requires recovered physical admin"
#endif
SEC("lsm/task_prctl")
int BPF_PROG(se_publication_arm, int option, unsigned long arg2,
	     unsigned long arg3, unsigned long arg4, unsigned long arg5,
	     int prior)
{
	(void)arg2;
	(void)arg3;
	(void)arg4;
	(void)arg5;
	/* PR_SET_NAME is a diagnostic trigger, never authority. */
	if (prior || option != 15)
		return prior;
	__u64 observed_cgroup = bpf_get_current_cgroup_id();
#else
/* Successful cgroup_kn_lock_live only. A missing or stale request is not a
 * failure receipt: this fexit also runs for unrelated cgroup locks. */
SEC("fexit/cgroup_kn_lock_live")
int BPF_PROG(se_publication_arm, struct kernfs_node *kn, bool drain,
	     struct cgroup *result)
{
	(void)kn;
	if (!result || (__u64)result >= ~4095ULL)
		return 0;
#ifdef ENFORCE_EXEC_SHARED_RECOVERY
	/* Recovery A deliberately writes a nonempty whitespace payload to
	 * cgroup.subtree_control.  Its no-mask-change path calls this helper with
	 * drain_offline=true; do not consume a staged request on other cgroup
	 * operations which use drain_offline=false.  This is only defense in
	 * depth: A must not perform any unrelated true-drain operation while S
	 * has a request staged. */
	if (!drain)
		return 0;
#else
	(void)drain;
#endif
#endif
	__u32 zero = 0;
	const struct se_node_config *config = SE_CONFIG_LOOKUP(&zero);
	const struct se_arm_request *input =
		bpf_map_lookup_elem(&se_arm_requests, &zero);
#ifdef ENFORCE_EXEC_SHARED_RECOVERY
	int administrator = input && config &&
			    se_rm_command_authorized(config->node_cookie);
#else
	const __u64 *admin = SE_ADMIN_LOOKUP();
#endif
	struct se_arm_receipt *receipt =
		bpf_map_lookup_elem(&se_arm_receipts, &zero);
#ifdef ENFORCE_EXEC_SHARED_RECOVERY
	if (!se_profile_matches(config) || !input || !administrator ||
	    !receipt || input->node_cookie != config->node_cookie ||
	    input->reserved || !input->sequence || input->sequence == ~0ULL ||
	    (receipt->node_cookie &&
	     receipt->node_cookie != config->node_cookie) ||
	    input->sequence <= receipt->sequence)
		return 0;
#else
	if (!se_profile_matches(config) || !input || !admin || !receipt ||
	    *admin != config->nonce || input->nonce != config->nonce ||
	    input->node_cookie != config->node_cookie || input->reserved ||
	    !input->sequence || input->sequence == ~0ULL ||
	    (receipt->node_cookie &&
	     receipt->node_cookie != config->node_cookie) ||
	    input->sequence <= receipt->sequence)
		return 0;
#endif
	struct se_arm_frame *frame = bpf_map_lookup_elem(&se_arm_frame, &zero);
	if (!frame) {
		*receipt =
			(struct se_arm_receipt){ .node_cookie =
							 config->node_cookie,
						 .sequence = input->sequence,
						 .operation = input->operation,
						 .status = 1 };
		return 0;
	}
	__builtin_memcpy(&frame->req, input, sizeof(frame->req));
	struct se_arm_request *reqp = &frame->req;
	__u32 key = reqp->binding;
	struct se_shared_binding *binding = SE_BINDING_LOOKUP(&key);
	struct se_route_anchor *route = SE_ROUTE_LOOKUP(&key);
	if (!binding || !route || key >= config->bindings) {
		*receipt =
			(struct se_arm_receipt){ .node_cookie =
							 config->node_cookie,
						 .sequence = reqp->sequence,
						 .operation = reqp->operation,
						 .status = 1 };
		return 0;
	}
#ifdef ENFORCE_EXEC_SHARED_RECOVERY
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRCTL_ARM_CANDIDATE
	if (!se_arm_target_cgroup_matches(observed_cgroup, route))
#else
	if (!se_arm_target_cgroup_matches(BPF_CORE_READ(result, kn, id), route))
#endif
		return 0;
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRCTL_ARM_CANDIDATE
	if (reqp->operation == SE_ARM_ROUTE_STAGE_CANDIDATE) {
		int staged = se_arm_route_stage_candidate(route, binding, reqp,
							  key, observed_cgroup);
		*receipt = (struct se_arm_receipt){
			.node_cookie = config->node_cookie,
			.sequence = reqp->sequence,
			.operation = SE_ARM_ROUTE_STAGE_CANDIDATE,
			.status = staged ? 1 : 0,
			.value = route->phase
		};
		return 0;
	}
#endif
	const struct se_snapshot *snap =
		reqp->record < 2 ? &binding->state.records[reqp->record & 1] :
				   0;
	struct se_epoch_cell *cells[8] = {};
	__u64 bound_uid[8] = {};
	__u32 created[8] = {};
	if (reqp->operation == SE_ARM_BIND) {
		int bound = !snap || se_arm_load_cells(reqp, cells) ||
			    se_arm_bind_loaded(&binding->state, reqp, cells,
					       bound_uid, created);
		if (bound)
			se_arm_rollback_bound(reqp->scope, bound_uid, created,
					      cells);
		*receipt = (struct se_arm_receipt){ .node_cookie =
							    config->node_cookie,
						    .sequence = reqp->sequence,
						    .operation = SE_ARM_BIND,
						    .status = bound ? 1 : 0,
						    .value = route->phase };
		return 0;
	}
	int loaded = reqp->operation == SE_ARM_COMMIT && snap &&
				     !se_arm_load_cells(reqp, cells) ?
			     0 :
			     -1;
	int indexed = loaded || se_arm_require_loaded(&binding->state, reqp,
						      cells, bound_uid) ?
			      -1 :
			      0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRCTL_ARM_CANDIDATE
	__u64 route_cgroup = route->cgroup_identity;
	__u32 route_incarnation = route->incarnation;
	__u64 expected_locator = se_route_locator(key, route_incarnation);
	const __u64 *route_locator =
		bpf_map_lookup_elem(&se_route_index, &route_cgroup);
	int route_indexed = route_cgroup && route_incarnation &&
			    route_locator && *route_locator == expected_locator;
#endif
	bpf_spin_lock(&route->lock);
	int uid_match = (reqp->record & 1) == 0 ?
				se_arm_uids_match(&binding->state.records[0],
						  reqp, bound_uid) :
				se_arm_uids_match(&binding->state.records[1],
						  reqp, bound_uid);
	int result_code = -1;
	if (reqp->operation == SE_ARM_COMMIT && !loaded && !indexed &&
	    !uid_match
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRCTL_ARM_CANDIDATE
	    && route_indexed && route_cgroup == observed_cgroup &&
	    route->cgroup_identity == route_cgroup &&
	    route->incarnation == route_incarnation
#endif
	)
		result_code = se_arm_commit_locked(1, route, &binding->state,
						   reqp, cells);
	else if (reqp->operation == SE_ARM_WITHDRAW
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRCTL_ARM_CANDIDATE
		 && route->cgroup_identity == observed_cgroup
#endif
	)
		result_code =
			se_arm_withdraw_locked(1, route, &binding->state, reqp);
	__u64 generation = binding->state.generation;
	__u64 serial = binding->state.active_serial;
	__u32 phase = route->phase;
	bpf_spin_unlock(&route->lock);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRCTL_ARM_CANDIDATE
	/* Tombstone the route first. A stale locator cannot admit once phase is
	 * WITHDRAWN; report cleanup failure rather than pretending it vanished. */
	if (reqp->operation == SE_ARM_WITHDRAW && !result_code) {
		const __u64 *have =
			bpf_map_lookup_elem(&se_route_index, &route_cgroup);
		if (!have || *have != expected_locator ||
		    bpf_map_delete_elem(&se_route_index, &route_cgroup))
			result_code = -1;
	}
#endif
	*receipt = (struct se_arm_receipt){ .node_cookie = config->node_cookie,
					    .sequence = reqp->sequence,
					    .generation = result_code ?
								  0 :
								  generation,
					    .serial = result_code ? 0 : serial,
					    .operation = reqp->operation,
					    .status = result_code ? 1 : 0,
					    .value = phase };
	return 0;
}
#endif
#endif
