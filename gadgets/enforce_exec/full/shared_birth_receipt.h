/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_BIRTH_RECEIPT_H
#define ENFORCE_EXEC_SHARED_BIRTH_RECEIPT_H

/* G019 gap 2 (cross-generation first-exec qualification): may a child born
 * under the receipt's route claim qualify under the current claim of the
 * same route? Pure: scalars in, a verdict out, no map or helper access (the
 * host contract testdata/birth_receipt_admits_contract.c drives its truth
 * table).
 *
 * The route identity (scope, slot, incarnation, execution class) must be
 * equal: a withdrawn and republished route, another slot or a class change
 * is never this child's route. Within it:
 *   - the same generation must be the exact claim the child was born under
 *     (serial and record equal): 1;
 *   - an older receipt generation is a revision committed after the birth:
 *     the child is admitted under the current generation: 2;
 *   - a receipt generation newer than the current route's cannot happen
 *     (generations only grow while the route keeps its incarnation): -1, an
 *     invariant fault (the caller counts QUALIFY);
 *   - anything else: 0, not admitted (the child stays unqualified).
 * The execution class is 1 (Audit) or 2 (Strict); any other value in the
 * receipt is never admitted. */
static __attribute__((always_inline)) inline int
se_birth_receipt_admits(__u64 r_scope, __u64 r_generation, __u64 r_serial,
			__u32 r_slot, __u32 r_incarnation, __u32 r_record,
			__u32 r_class, __u64 c_scope, __u64 c_generation,
			__u64 c_serial, __u32 c_slot, __u32 c_incarnation,
			__u32 c_record, __u32 c_class)
{
	if (r_class < 1 || r_class > 2 || !r_scope || !r_generation ||
	    r_scope != c_scope || r_slot != c_slot ||
	    r_incarnation != c_incarnation || r_class != c_class)
		return 0;
	if (r_generation > c_generation)
		return -1;
	if (r_generation == c_generation)
		return r_serial == c_serial && r_record == c_record ? 1 : 0;
	return 2;
}

#ifdef SE_BIRTH_PARK_LOOKUP
/* G019 gap 1 (birth park): the fork source hands its route claim to the
 * constructor target instead of releasing it and letting the target
 * re-admit the cgroup. The target used to re-admit, so a revision committed
 * between the two task_alloc programs left the child unconstructed
 * (CONSTRUCT). A parked claim keeps the route's early claim on its record
 * (ACTIVE, or RETIRING once a revision commits past it: G019 gap 3), which
 * blocks only the withdrawal and the reuse of that record until the target
 * takes and releases it: the child is built under exactly the generation
 * its source admitted. One park
 * per forking task (the target runs in the same task_alloc call); only that
 * task touches it, and its task_free releases a park no target took.
 *
 * Adapter (the verdict object's per-task storage; the host contract's
 * stand-ins):
 *   SE_BIRTH_PARK_LOOKUP(create)  the current task's park (create: allocate)
 *   SE_BIRTH_PARK_COUNT(index)    the witness, SE_BIRTH_PARK_* below
 *   SE_BIRTH_CLAIM_RELEASE(claim) release a route claim (0 released)
 *   SE_BIRTH_ROUTE_LOOKUP(slot)   the route anchor of a slot */
struct se_birth_park {
	struct se_route_claim claim;
	__u64 child, parent_cookie;
	__u32 owned, reserved;
};
_Static_assert(sizeof(struct se_birth_park) == 80, "birth park value");
/* Witness cells: [0] parked, [1] taken by the target, [2] abandoned (the
 * target never ran or failed before construction; released), [3] a stale
 * park released (a later fork's put or task_free), [4] put failed (no
 * storage; the birth takes the missing-target path), [5] a park's release
 * failed, or the target's own parked claim no longer validated (its route is
 * latched: unresolved_sources), [6] the target found no valid park for its
 * child (CONSTRUCT), [7] a cross-generation first-exec qualification
 * accepted (gap 2). */
#define SE_BIRTH_PARK_PARKED 0
#define SE_BIRTH_PARK_TAKEN 1
#define SE_BIRTH_PARK_ABANDONED 2
#define SE_BIRTH_PARK_STALE 3
#define SE_BIRTH_PARK_PUT_FAILED 4
#define SE_BIRTH_PARK_LATCHED 5
#define SE_BIRTH_PARK_TAKE_FAILED 6
#define SE_BIRTH_PARK_CROSS_GENERATION 7
#define SE_BIRTH_PARK_CELLS 8

/* Release an owned park's claim (counted as counted). A claim that cannot
 * be released keeps its early claim on the route forever: latch the route
 * (unresolved_sources, as se_route_source_latch_locked does) so it is
 * reported and never published or withdrawn again before teardown. */
static __attribute__((noinline)) void
se_birth_park_drop(struct se_birth_park *park, __u32 counted)
{
	if (!park || !park->owned)
		return;
	park->owned = 0;
	if (!SE_BIRTH_CLAIM_RELEASE(&park->claim)) {
		SE_BIRTH_PARK_COUNT(counted);
		return;
	}
	struct se_route_anchor *route = SE_BIRTH_ROUTE_LOOKUP(park->claim.slot);
	if (route) {
		bpf_spin_lock(&route->lock);
		route->unresolved_sources = 1;
		bpf_spin_unlock(&route->lock);
	}
	SE_BIRTH_PARK_COUNT(SE_BIRTH_PARK_LATCHED);
}
/* Source: park the claim for child (0), or refuse (-1: the caller still
 * owns the claim). A park still owned is a stale birth whose target never
 * ran: it is released first. The early claim moves with the claim. */
static __attribute__((noinline)) int
se_birth_park_put(struct se_route_claim *claim, __u64 child,
		  __u64 parent_cookie)
{
	struct se_birth_park *park = SE_BIRTH_PARK_LOOKUP(1);
	if (!park) {
		SE_BIRTH_PARK_COUNT(SE_BIRTH_PARK_PUT_FAILED);
		return -1;
	}
	se_birth_park_drop(park, SE_BIRTH_PARK_STALE);
	park->claim = *claim;
	park->child = child;
	park->parent_cookie = parent_cookie;
	park->owned = 1;
	claim->owned = 0;
	SE_BIRTH_PARK_COUNT(SE_BIRTH_PARK_PARKED);
	return 0;
}
/* Source or target failure before construction: release this task's park,
 * if any (a Strict park makes the fail-closed mode 2: deny). */
static __attribute__((noinline)) void se_birth_park_abandon(__u32 *mode_out)
{
	struct se_birth_park *park = SE_BIRTH_PARK_LOOKUP(0);
	if (!park || !park->owned)
		return;
	if (park->claim.execution_class == 2)
		*mode_out = 2;
	se_birth_park_drop(park, SE_BIRTH_PARK_ABANDONED);
}
/* Target: take the park the source left for exactly this child and re-check
 * it under the route lock (SE_ROUTE_OWNED, claim filled). Anything else is
 * SE_ROUTE_UNSELECTED for the caller (CONSTRUCT), with a Strict park's mode
 * 2; a park for another child is left to its owner. This child's parked
 * claim that no longer validates is never released (it is not ours) but
 * still holds its early claim: its route is latched like a failed release in
 * se_birth_park_drop (LATCHED, and TAKE_FAILED for the CONSTRUCT). */
static __attribute__((noinline)) int
se_birth_park_take(__u64 child, struct se_route_claim *claim, __u32 *mode_out)
{
	struct se_birth_park *park = SE_BIRTH_PARK_LOOKUP(0);
	int valid = 0;
	if (park && park->owned) {
		if (park->claim.execution_class == 2)
			*mode_out = 2;
		if (park->child == child) {
			*claim = park->claim;
			park->owned = 0;
			struct se_route_anchor *route =
				SE_BIRTH_ROUTE_LOOKUP(claim->slot);
			if (route) {
				bpf_spin_lock(&route->lock);
				valid = se_route_claim_valid(route, claim);
				if (!valid)
					route->unresolved_sources = 1;
				bpf_spin_unlock(&route->lock);
			}
			/* Never release an invalid claim (it is not ours). */
			if (!valid) {
				claim->owned = 0;
				SE_BIRTH_PARK_COUNT(SE_BIRTH_PARK_LATCHED);
			}
		}
	}
	SE_BIRTH_PARK_COUNT(valid ? SE_BIRTH_PARK_TAKEN :
				    SE_BIRTH_PARK_TAKE_FAILED);
	return valid ? SE_ROUTE_OWNED : SE_ROUTE_UNSELECTED;
}
#endif

#endif
