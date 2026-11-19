// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Never attach. This isolated verifier object uses synthetic account/cookie
 * values and has no authenticated source cleanup authority. It tests only
 * the compiled candidate shapes, not product enforcement. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#if defined(ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE) &&                \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE))
#error "staged observation overlay requires typed TASK/WORK continuation"
#endif

#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#define ER_ACCEPTED_EPOCH(uid) ((__u64)0)
#include "epoch_roles.h"

#define ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE 1
/* Match the selected development profile's exact B2/T128 task partition.
 * Still a never-attached verifier fixture, not a selected product ABI. */
#define SE_OL_TASKS 128
#define SE_OC_ACCOUNTS 2
#define SE_OC_QUOTA 64
#define SE_OWK_ACCOUNTS SE_OC_ACCOUNTS
#define SE_OWK_QUOTA 32
#define SE_OWK_WORKS (SE_OWK_ACCOUNTS * SE_OWK_QUOTA)
#include "shared_pool_opaque_core_candidate.h"
/* Synthetic route for a separate never-attached composition verifier path;
 * this is not a selected route index or policy authority. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_OC_ACCOUNTS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_route_anchor);
} writer_probe_route SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_OC_ACCOUNTS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_binding_snapshots);
} writer_probe_snapshots SEC(".maps");
/* Defaults to zero. The load-only test never arms this map or attaches a
 * program; an accidental attachment is inert unless explicitly armed. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} writer_probe_gate SEC(".maps");
static int gate_armed(void)
{
	__u32 zero = 0;
	const __u32 *armed = bpf_map_lookup_elem(&writer_probe_gate, &zero);
	return armed && *armed == 1;
}

static struct se_route_anchor *route_lookup(__u32 slot)
{
	return bpf_map_lookup_elem(&writer_probe_route, &slot);
}
static struct se_binding_snapshots *snapshot_lookup(__u32 slot)
{
	return bpf_map_lookup_elem(&writer_probe_snapshots, &slot);
}
#include "shared_pool_opaque_accessors_candidate.h"

SEC("lsm/task_alloc")
int BPF_PROG(opaque_locator_writer_alloc_probe, struct task_struct *child,
	     unsigned long clone_flags, int prior)
{
	(void)clone_flags;
	if (prior || !gate_armed())
		return prior;
	__u32 slot = 0;
	struct se_ol_meta *meta = meta_lookup(slot);
	__u64 locator = 0;
	if (se_ow_begin(meta, slot, 1, &locator) != SE_OL_OK)
		return -1;
	if (se_ow_archive(meta, slot, 1, &child) != SE_OL_OK) {
		se_ow_abort_constructor(meta, 1);
		return -1;
	}
	__u64 *archive = bpf_map_lookup_elem(&se_opaque_archive, &slot);
	if (!archive || se_ow_insert_zero(meta, 1, archive) != SE_OL_OK) {
		se_ow_abort_constructor(meta, 1);
		return -1;
	}
	if (se_ow_publish_zero(meta, 1, archive) != SE_OL_OK) {
		se_ow_abort_constructor(meta, 1);
		return -1;
	}
	if (se_ow_finish_birth(meta, 1) != SE_OL_OK)
		return -1;
	return -1; /* no source cleanup if this probe is wrongly attached */
}

/* A second, never-attached LSM program makes the same-key replacement path
 * verifier-reachable without pretending this synthetic cookie is a charge.
 * All ordinary refusals return denial only in this isolated probe. */
SEC("lsm/task_alloc")
int BPF_PROG(opaque_locator_replace_alloc_probe, struct task_struct *child,
	     unsigned long clone_flags, int prior)
{
	(void)clone_flags;
	if (prior || !gate_armed())
		return prior;
	__u32 slot = 1;
	struct se_ol_meta *next = meta_lookup(slot);
	__u64 locator = 0;
	if (se_ow_begin(next, slot, 2, &locator) != SE_OL_OK)
		return -1;
	if (se_ow_archive(next, slot, 2, &child) != SE_OL_OK) {
		se_ow_abort_constructor(next, 2);
		return -1;
	}
	__u64 *archive = bpf_map_lookup_elem(&se_opaque_archive, &slot);
	struct se_ol_observation observation = {};
	if (!archive || se_ol_observe(&child, &observation) != SE_OL_OK ||
	    se_ol_read_observation(&observation) != SE_OL_OK ||
	    se_ow_hold_replacement(&observation) != SE_OL_OK) {
		se_ow_abort_constructor(next, 2);
		return -1;
	}
	if (se_ow_claim_replacement(next, 2, &observation, archive) !=
	    SE_OL_OK) {
		if (observation.stage == SE_OL_HELD)
			se_ol_cancel_observation(&observation);
		se_ow_abort_constructor(next, 2);
		return -1;
	}
	if (se_ow_publish_replacement(next, 2, &observation, archive) !=
	    SE_OL_OK)
		return -1; /* exact old/new charges stay fault-held */
	(void)se_ow_finish_birth(next, 2);
	return -1; /* synthetic replacement is never an admitted child */
}

/* Actual typed hook argument, but still load-only: no program is attached,
 * and the synthetic maps/charge cannot authorize a real lifetime. */
SEC("lsm/task_free")
int BPF_PROG(opaque_locator_final_free_probe, struct task_struct *dying)
{
	if (!gate_armed())
		return 0;
	struct se_of_lease lease = {};
	if (se_of_record_death(dying, &lease) == SE_OL_OK)
		se_of_release(&lease, dying);
	return 0;
}

/* Charged semantic-constructor verifier shape. It still has synthetic
 * account values and no reaper/NotReady owner; ambiguous insertion is
 * fault-held. The default-zero gate is never armed or attached. */
SEC("lsm/task_alloc")
int BPF_PROG(opaque_locator_charge_alloc_probe, struct task_struct *child,
	     unsigned long clone_flags, int prior)
{
	(void)clone_flags;
	if (prior || !gate_armed())
		return prior;
	struct se_oc_reservation reservation = {};
	/* Verifier reachability only: 10/1 is NOT a route claim. */
	if (se_oc_bind_account(0, 10, 1) != SE_OL_OK)
		return -1;
	if (se_oc_reserve_any(0, 10, 1, &reservation) != SE_OL_OK)
		return -1;
	if (se_oc_begin_charged(&reservation) != SE_OL_OK)
		return -1;
	if (se_op_initialize_task_semantic(&reservation) != SE_OL_OK)
		goto abort;
	struct se_op_child_roles_handle child_roles = {};
	struct er_state *roles = 0;
	if (se_op_child_roles_begin(&reservation, &child_roles, &roles) !=
	    SE_OL_OK)
		goto abort;
	int empty_roles = roles->version == 0;
	se_op_child_roles_end(&child_roles, &roles);
	if (!empty_roles)
		goto abort;
	struct task_struct *opaque_key = child;
	if (se_ow_archive(reservation.meta, reservation.task_slot,
			  reservation.cookie, &opaque_key) != SE_OL_OK)
		goto abort;
	const __u64 *archive = archive_lookup(reservation.task_slot);
	if (!archive ||
	    se_ow_insert_zero(reservation.meta, reservation.cookie, archive) !=
		    SE_OL_OK ||
	    se_ow_publish_zero(reservation.meta, reservation.cookie, archive) !=
		    SE_OL_OK)
		goto abort;
	if (se_op_finish_semantic_birth(&reservation) != SE_OL_OK)
		goto abort;
	/* Synthetic constructor has no source-owned cleanup: never admit. */
	return -1;
abort:
	/* INSERT_INTENT or a raced structural contradiction is intentionally
	 * fault-held; neither this probe nor a future hook may refund it. */
	se_op_abort_semantic_birth(&reservation);
	return -1;
}

SEC("lsm/task_alloc")
int BPF_PROG(opaque_locator_route_claim_probe, struct task_struct *child,
	     unsigned long clone_flags, int prior)
{
	(void)child;
	(void)clone_flags;
	if (prior || !gate_armed())
		return prior;
	__u32 slot = 0;
	struct se_route_anchor *route = route_lookup(slot);
	if (!route)
		return -1;
	struct se_route_claim claim = {};
	bpf_spin_lock(&route->lock);
	/* Test-only synthetic owner: no policy/route-index publication. */
	if (route->phase == SE_ROUTE_FREE) {
		route->incarnation = 1;
		route->cgroup_identity = 1;
		route->scope = 10;
		route->payload_slot = 0;
		route->payload_generation = 1;
		route->active_serial = 1;
		route->execution_class = 2;
		route->phase = SE_ROUTE_ACTIVE;
	}
	int admitted =
		se_route_claim_locked(route, se_route_locator(0, 1), 1, &claim);
	bpf_spin_unlock(&route->lock);
	if (admitted != SE_ROUTE_OWNED)
		return -1;
	struct se_oc_reservation reservation = {};
	int result = se_oc_reserve_route_claim(&claim, &reservation);
	bpf_spin_lock(&route->lock);
	int released = se_route_release_locked(route, &claim);
	bpf_spin_unlock(&route->lock);
	/* This synthetic probe has no source cleanup. Even if someone wrongly
	 * arms and attaches it, never admit a child with a retained charge. */
	(void)result;
	(void)released;
	return -1;
}

/* Never attached: exercise the account-authoritative withdrawn-route
 * recycle verifier shape with a fixed synthetic snapshot map. */
SEC("tc")
int opaque_locator_route_recycle_probe(struct __sk_buff *skb)
{
	(void)skb;
	if (!gate_armed())
		return -1;
	__u32 slot = 0;
	struct se_binding_snapshots *snapshots = snapshot_lookup(slot);
	if (!snapshots)
		return -1;
	(void)se_owk_route_recycle(slot, snapshots);
	return -1;
}

/* A typed hook argument is only the opaque HASH key. The exact locator
 * lease is transferred to a lexical fixed-payload handle; this unarmed
 * probe does not claim semantic identity or policy authority. */
SEC("lsm/task_alloc")
int BPF_PROG(opaque_locator_payload_handle_probe, struct task_struct *child,
	     unsigned long clone_flags, int prior)
{
	(void)clone_flags;
	if (prior || !gate_armed())
		return prior;
	struct task_struct *opaque_key = child;
	struct se_ol_payload_handle handle = {};
	if (se_ol_task_open(&opaque_key, &handle) != SE_OL_OK)
		return -1;
	void *payload = 0;
	if (se_ol_payload_begin(&handle, &payload) != SE_OL_OK) {
		se_ol_payload_close(&handle);
		return -1;
	}
	((struct se_pool_task_wire *)payload)->bytes[0] = 1;
	/* begin established this exact lexical bracket. A fallible end leaves a
	 * verifier-visible return while the spinlock is held; release directly. */
	payload = 0;
	handle.locked = 0;
	bpf_spin_unlock(&handle.lease.meta->lock);
	(void)se_ol_payload_close(&handle);
	return -1; /* never admit from an observation-only fixture */
}

/* WORK BUILDING reservation from the exact original-key TASK handle. This
 * synthetic program always denies if wrongly attached: it has no WORK
 * attach, completion, or refund authority. */
SEC("lsm/task_alloc")
int BPF_PROG(opaque_locator_work_credit_probe, struct task_struct *child,
	     unsigned long clone_flags, int prior)
{
	(void)clone_flags;
	if (prior || !gate_armed())
		return prior;
	struct task_struct *opaque_key = child;
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&opaque_key, &owner) != SE_OL_OK)
		return -1;
	__u32 work_slot = 0;
	struct se_owk_ticket ticket = {};
	if (se_owk_bind_owner(&owner) == SE_OL_OK &&
	    se_owk_choose(&owner, &work_slot) == SE_OL_OK) {
		int begun = se_owk_begin(&owner, work_slot, &ticket);
		if (begun == SE_OL_OK) {
			if (se_owk_attach_owner(&owner, &ticket) == SE_OL_OK) {
				if (se_owk_initialize_payload(
					    &owner, &ticket) == SE_OL_OK &&
				    se_owk_commit(&owner, &ticket) == SE_OL_OK)
					(void)se_owk_done(&owner, &ticket);
				else
					(void)se_owk_abort(&owner, &ticket);
			} else {
				(void)se_owk_abort_building(&owner, &ticket);
			}
		} else if (ticket.held) {
			(void)se_owk_abort_building(&owner, &ticket);
		}
	}
	(void)se_ol_payload_close(&owner);
	return -1;
}

SEC("tc")
int opaque_locator_writer_reaper_probe(struct __sk_buff *skb)
{
	(void)skb;
	if (!gate_armed())
		return 0;
	__u32 slot = 0;
	struct se_ol_meta *meta = meta_lookup(slot);
	__u64 *archive = bpf_map_lookup_elem(&se_opaque_archive, &slot);
	if (!meta || !archive)
		return 0;
	/* The test has no real task_free/death proof. Every stage is guarded by
	 * its own metadata preconditions; these calls only make the code
	 * verifier-reachable in this never-attached ELF. */
	se_ow_reconcile_publish_intent(meta, 1, archive);
	se_ow_mark_absent_deleted(meta, 1);
	se_ow_claim_aborted_zero(meta, 1);
	se_ow_claim_withdraw(meta, 1);
	se_ow_advance_withdraw(meta, 1, archive);
	se_ow_delete_withdrawn_zero(meta, 1, archive);
	se_ow_zero_archive(meta, 1);
	return 0;
}

/* Checks are verifier-reachable; no source cleanup receipt is fabricated.
 * Default-zero gate and never-attached object prohibit runtime operation. */
SEC("tc")
int opaque_locator_refund_probe(struct __sk_buff *skb)
{
	(void)skb;
	if (!gate_armed())
		return 0;
	return se_oc_refund_step(0, 1) == SE_OC_RETURNED ? 1 : 0;
}

SEC("tc")
int opaque_locator_payload_zero_probe(struct __sk_buff *skb)
{
	(void)skb;
	if (!gate_armed())
		return 0;
	return se_op_zero_payload(0, 1) == SE_OC_PROGRESS ? 1 : 0;
}

/* Never attached: source-owned WORK completion is absent in this synthetic
 * object, so this verifier path cannot grant a real owner or refund. */
SEC("tc")
int opaque_locator_work_reap_probe(struct __sk_buff *skb)
{
	(void)skb;
	if (!gate_armed())
		return 0;
	return se_owk_reap_step(0, 1) == SE_OWK_RETURNED ? 1 : 0;
}

char LICENSE[] SEC("license") = "GPL";
