// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
/* Isolated test-only actual task_alloc/task_free/reaper fixture. Load-only
 * verifier probes leave the gate at zero. The opt-in attached test sets one
 * isolated cgroup and freezes the gate before attaching lifecycle LSM entries.
 * Its synthetic exec/WORK source is not a product policy or a substitute for
 * selected-hook migration. Native and reader obligations remain empty. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_CONTROL_CANDIDATE
#error "synthetic lifecycle fixture cannot claim real control authority"
#endif
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
#define FM_STAGE_INLINE_INSTRUCTION_WINDOW 1
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_EVAL_CANDIDATE) ||       \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_TAILCALL_FIXTURE) || \
	!defined(FE_BOUNDED_LOOP_CANDIDATE)
#error "staged fixture requires evaluator resolver, tail-call and bounded loops"
#endif
struct fm_blob;
struct fm_global_token;
struct se_policy_view;
static __attribute__((always_inline)) inline struct se_policy_view *
se_stage_view_from_token(const struct fm_global_token *);
static __attribute__((always_inline)) inline const struct fm_blob *
se_stage_blob_from_token(unsigned int, unsigned long long, unsigned int);
#define SE_POLICY_VIEW(ctx) \
	se_stage_view_from_token((const struct fm_global_token *)(ctx))
#define FM_GLOBAL_SCALAR_BLOB_LOOKUP(slot, cookie, key) \
	se_stage_blob_from_token((slot), (cookie), (key))
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_CATALOGUE_CANDIDATE)
#error "reader catalogue fixture requires the opaque WORK catalogue"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_HANDOFF_DIAGNOSTIC) &&    \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_PARENT_SNAPSHOT_DIAGNOSTIC) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_CATALOGUE_CANDIDATE))
#error "child WORK handoff diagnostic requires parent snapshot and catalogue"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_TAILCALL_DIAGNOSTIC) &&      \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_HANDOFF_DIAGNOSTIC) || \
	 !defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE))
#error "child WORK tail-call diagnostic requires handoff and continuation"
#endif
#include "opaque_locator_writer_probe.bpf.c"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_TAILCALL_DIAGNOSTIC
static __attribute__((noinline)) int
opaque_lifecycle_abort_after_publish_zero(void);
#define SE_OP_ABORT_AFTER_PUBLISH_ZERO() \
	opaque_lifecycle_abort_after_publish_zero()
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE
#include "shared_pool_opaque_birth_candidate.h"
/* Synthetic empty projection for lifecycle-only tests. This is not a
 * parent-derived canonical projection or a product inheritance authority. */
static const struct er_work opaque_lifecycle_projected = {
	.authority_version = 1,
	.prepared = 1,
	.rows = { { .uid = 1,
		    .epoch = 1,
		    .role = 1,
		    .knowledge = ER_ROLE_KNOWN } },
};
static const struct se_snapshot opaque_lifecycle_inherit_snapshot = {
	.scope = 10, .serial = 1, .generation = 1, .count = 1,
	.metadata = {
		.root_epochs = { 1 }, .policy_uids = { 1 },
		.container_length = 1, .container = "/",
	},
};
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_DEATH_FIXTURE) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE)
#error "death fixture requires explicit WORK continuation candidate"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_TAILCALL_FIXTURE) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_DEATH_FIXTURE)
#error "tail-call fixture requires suspended-WORK death fallback"
#endif
#include "shared_pool_opaque_final_semantic_candidate.h"
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_EVAL_CANDIDATE
#ifndef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
#error "evaluator resolver fixture requires typed opaque WORK"
#endif
#include "shared_pool_opaque_work_eval_candidate.h"
#ifdef ENFORCE_EXEC_SUSPENDED_WORK_READ_CANDIDATE
#define SE_OWK_CURRENT_TASK() bpf_get_current_task_btf()
#include "shared_pool_opaque_work_suspended_read_candidate.h"
#endif
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
static __attribute__((always_inline)) inline struct se_policy_view *
se_stage_view_from_token(const struct fm_global_token *token)
{
#if defined(ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC) && \
	!defined(ENFORCE_EXEC_STAGE2_SOURCE_OBJECT)
	return token && !token->reserved ?
		       se_owk_suspended_view_from_token(token->slot,
							token->cookie) :
		       0;
#else
	return token && !token->reserved ?
		       se_owk_view_from_lexical_token(token->slot,
						      token->cookie) :
		       0;
#endif
}
static __attribute__((always_inline)) inline const struct fm_blob *
se_stage_blob_from_token(unsigned int slot, unsigned long long cookie,
			 unsigned int key)
{
	struct fm_global_token token = { .slot = slot, .cookie = cookie };
	return se_policy_data(se_stage_view_from_token(&token), key);
}
#define OPAQUE_LIFECYCLE_POLICY_ENTRIES 11
#else
#define OPAQUE_LIFECYCLE_POLICY_ENTRIES 10
#endif
/* Synthetic blobs and snapshot for real view preparation inside the retained
 * WORK bracket. The guarded object variant is BPF-initialized and userspace
 * read-only; neither variant is a product snapshot/pin catalogue. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, OPAQUE_LIFECYCLE_POLICY_ENTRIES);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct fm_blob);
} opaque_lifecycle_policy_blobs SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	/* Product-shaped trust experiment: userspace cannot write the object;
	 * an isolated, gated BPF seeder writes it before the exec links attach.
	 * Legacy fixture builds still use a Go-filled, frozen synthetic object. */
#ifdef ENFORCE_EXEC_PRODUCT_OBJECT_TRUST_DIAGNOSTIC
	__uint(map_flags, BPF_F_RDONLY);
#else
	__uint(map_flags, 0);
#endif
	__type(key, __u32);
	__type(value, struct se_shared_object);
} opaque_lifecycle_policy_object SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct se_snapshot);
} opaque_lifecycle_policy_snapshot SEC(".maps");
#define SE_OBJECT_LOOKUP(key) \
	bpf_map_lookup_elem(&opaque_lifecycle_policy_object, (key))
#include "shared_policy_prepare.h"
static __attribute__((always_inline)) inline const struct fm_blob *
se_policy_physical(void *context, fm_u32 slot, fm_u64 generation, fm_u32 key)
{
	__u32 zero = 0;
	const struct se_shared_object *object =
		bpf_map_lookup_elem(&opaque_lifecycle_policy_object, &zero);
	return !context && !slot && object &&
			       object->state.phase == SE_OBJECT_READY &&
			       object->state.generation == generation &&
			       object->state.pins &&
			       key < object->state.length &&
			       key < OPAQUE_LIFECYCLE_POLICY_ENTRIES ?
		       bpf_map_lookup_elem(&opaque_lifecycle_policy_blobs,
					   &key) :
		       0;
}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CATALOGUE_CANDIDATE
#ifndef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
#error "catalogue fixture requires the typed opaque WORK"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_CATALOGUE_CANDIDATE) && \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE)
#error "map-backed catalogue diagnostic requires the retained reader path"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE
static struct se_binding_snapshots *opaque_lifecycle_binding_lookup(__u32 slot)
{
	return bpf_map_lookup_elem(&writer_probe_snapshots, &slot);
}
#define SE_OWK_BINDING_LOOKUP(slot) opaque_lifecycle_binding_lookup(slot)
#endif
/* The map-backed diagnostic emits the real non-evicting index/bank reader.
 * No ARM publisher or source-authenticated snapshot exists in this fixture;
 * do not attach it as product enforcement. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_REAL_CATALOGUE_CANDIDATE
#define SE_PROFILE_ACCEPTED_UIDS 32
#include "shared_catalogue_kernel.h"
#define SE_OWK_CATALOGUE_EPOCH(scope, uid) se_catalogue_epoch((scope), (uid))
#else
/* Synthetic COMPLETE history for this isolated scope/UID only. This is NOT
 * a product successful-activation catalogue or selected policy authority. */
#define SE_OWK_CATALOGUE_EPOCH(scope, uid) \
	((scope) == 10 && (uid) == 1 ? 1ULL : ER_UNKNOWN)
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CATALOGUE_CLASSIFY_CANDIDATE
#define SE_POOL_CATALOGUE_ROW_NOINLINE 1
#endif
#include "shared_pool_opaque_work_catalogue_candidate.h"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PARENT_SNAPSHOT_DIAGNOSTIC
#ifndef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
#error "parent snapshot diagnostic requires an exact WORK semantic ticket"
#endif
#include "shared_pool_opaque_inherit_candidate.h"
#endif

struct opaque_lifecycle_gate {
	__u64 cgroup_id;
	__u64 scope;
	__u32 incarnation, enabled;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_lifecycle_gate);
} opaque_lifecycle_gate SEC(".maps");
#ifdef ENFORCE_EXEC_POOL_OPAQUE_CHILD_TAILCALL_PRIMITIVE_DIAGNOSTIC
/* Primitive feasibility only. No TASK/WORK/route authority crosses this
 * edge and neither program is a policy or an approved source/target. */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} opaque_lifecycle_child_tail_targets SEC(".maps");
struct opaque_lifecycle_child_tail_counts {
	__u64 source, target, fallback;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct opaque_lifecycle_child_tail_counts);
} opaque_lifecycle_child_tail_counts SEC(".maps");
SEC("lsm/task_alloc")
int BPF_PROG(opaque_lifecycle_child_tail_source_probe,
	     struct task_struct *child, unsigned long clone_flags, int prior)
{
	(void)child;
	(void)clone_flags;
	if (prior)
		return prior;
	__u32 zero = 0;
	const struct opaque_lifecycle_gate *gate =
		bpf_map_lookup_elem(&opaque_lifecycle_gate, &zero);
	if (!gate || gate->enabled != 1 || !gate->cgroup_id ||
	    bpf_get_current_cgroup_id() != gate->cgroup_id)
		return 0;
	struct opaque_lifecycle_child_tail_counts *counts =
		bpf_map_lookup_elem(&opaque_lifecycle_child_tail_counts, &zero);
	if (counts)
		__sync_fetch_and_add(&counts->source, 1);
	bpf_tail_call(ctx, &opaque_lifecycle_child_tail_targets, 0);
	if (counts)
		__sync_fetch_and_add(&counts->fallback, 1);
	return -1; /* missing target must not accept an enforcement callback */
}
SEC("lsm/task_alloc")
int BPF_PROG(opaque_lifecycle_child_tail_target_probe,
	     struct task_struct *child, unsigned long clone_flags, int prior)
{
	(void)child;
	(void)clone_flags;
	__u32 zero = 0;
	struct opaque_lifecycle_child_tail_counts *counts =
		bpf_map_lookup_elem(&opaque_lifecycle_child_tail_counts, &zero);
	if (counts)
		__sync_fetch_and_add(&counts->target, 1);
	return prior ? prior : -1; /* no policy authority: always deny */
}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_TAILCALL_DIAGNOSTIC
/* The target is never attached independently. This map is populated only by
 * a verifier probe; a missing target must fall back to exact WORK cleanup. */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} opaque_lifecycle_child_work_targets SEC(".maps");
struct opaque_lifecycle_child_work_counts {
	__u64 source, target, accepted, fallback;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct opaque_lifecycle_child_work_counts);
} opaque_lifecycle_child_work_counts SEC(".maps");
/* Test-only forced route loss occurs after source claim release and before
 * the tail call. This is not the selected binding withdrawal protocol. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, __u32);
} opaque_lifecycle_child_work_fault SEC(".maps");
static __attribute__((noinline)) int
opaque_lifecycle_abort_after_publish_zero(void)
{
	__u32 zero = 0;
	const __u32 *fault =
		bpf_map_lookup_elem(&opaque_lifecycle_child_work_fault, &zero);
	struct opaque_lifecycle_child_work_counts *counts =
		bpf_map_lookup_elem(&opaque_lifecycle_child_work_counts, &zero);
	/* The seed constructor precedes the counted charged source. */
	return fault && *fault == 2 && counts && counts->source == 1;
}
/* Synthetic test qualification only. The child born by the existing
 * lifecycle constructor must execute once before it forks as a parent.
 * This is not an identity/eligibility producer for selected enforcement. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_lifecycle_child_work_qualify_probe,
	     struct linux_binprm *bprm, int prior)
{
	(void)bprm;
	if (prior)
		return prior;
	__u32 zero = 0;
	const struct opaque_lifecycle_gate *gate =
		bpf_map_lookup_elem(&opaque_lifecycle_gate, &zero);
	if (!gate || gate->enabled != 1 || !gate->cgroup_id ||
	    bpf_get_current_cgroup_id() != gate->cgroup_id)
		return 0;
	struct task_struct *key = bpf_get_current_task_btf();
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&key, &owner) != SE_OL_OK)
		return 0; /* untracked test launcher has no TASK to qualify */
	struct se_task_state *task = 0;
	int opened = se_op_task_semantic_begin(&owner, &task);
	if (opened == SE_OL_OK) {
		if (task->physical_cookie == owner.lease.cookie &&
		    task->scope_cookie == gate->scope &&
		    task->flags == SE_TASK_LIVE && task->committed.version != 0)
			task->flags = SE_TASK_QUALIFIED;
		se_op_task_semantic_end(&owner, &task);
	}
	(void)se_ol_payload_close(&owner);
	return 0;
}
#endif
#ifdef ENFORCE_EXEC_PRODUCT_OBJECT_TRUST_DIAGNOSTIC
/* Only the disposable test controller may attach this seeder, before the
 * lifecycle links. It proves the BPF_F_RDONLY object can be initialized by
 * BPF code, not the selected authenticated command/publication protocol. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_lifecycle_seed_policy_object, struct linux_binprm *bprm,
	     int prior)
{
	(void)bprm;
	if (prior)
		return prior;
	__u32 zero = 0;
	const struct opaque_lifecycle_gate *gate =
		bpf_map_lookup_elem(&opaque_lifecycle_gate, &zero);
	if (!gate || gate->enabled != 1 || !gate->scope ||
	    bpf_get_current_cgroup_id() != gate->cgroup_id)
		return 0;
	struct se_shared_object *object =
		bpf_map_lookup_elem(&opaque_lifecycle_policy_object, &zero);
	if (!object)
		return -1;
	bpf_spin_lock(&object->lock);
	int empty = object->state.phase == SE_OBJECT_FREE &&
		    !object->state.generation && !object->state.pins &&
		    !object->state.length;
	if (empty) {
		object->state.generation = 1;
		object->state.phase = SE_OBJECT_READY;
		object->state.length = OPAQUE_LIFECYCLE_POLICY_ENTRIES;
		object->state.pins = 1;
	}
	bpf_spin_unlock(&object->lock);
	return empty ? 0 : -1;
}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_TAILCALL_FIXTURE
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	/* Populate exact stage ID and freeze before any link is attached. */
	__uint(map_flags, 0);
	__type(key, __u32);
	__type(value, __u32);
} opaque_lifecycle_tail_targets SEC(".maps");
#endif
#ifdef ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} opaque_lifecycle_suspended_diag_target SEC(".maps");
#endif
struct opaque_lifecycle_request {
	__u64 cookie;
	__u32 slot, reserved;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_lifecycle_request);
} opaque_lifecycle_request SEC(".maps");
struct opaque_lifecycle_counters {
	__u64 births, deaths, denied, reaper_calls;
	__u64 last_cookie, last_reap_result;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE
	__u64 exec_reserved, exec_aborted, exec_faults;
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
	__u64 work_done, work_faults, work_reaper_calls;
	__u64 last_work_reap_result;
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_DEATH_FIXTURE
	__u64 work_suspended, work_death_closed;
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_TAILCALL_FIXTURE
	__u64 tail_entry, tail_stage, tail_fallback, tail_done;
#endif
#ifdef ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC
	__u64 diag_eval, diag_stage2, diag_fallback;
#endif
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct opaque_lifecycle_counters);
} opaque_lifecycle_counters SEC(".maps");

static __always_inline struct opaque_lifecycle_counters *
lifecycle_counters(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&opaque_lifecycle_counters, &zero);
}

/* The first synthetically qualified parent has no predecessor by design.
 * Keep its exact normal-publication checks separate from the replacement
 * target's verifier graph; this is not a selectable product constructor. */
static __attribute__((noinline)) int
opaque_lifecycle_publish_seed_parent(const struct se_route_claim *claim,
				     struct se_oc_reservation *reservation,
				     const void *opaque_key)
{
	int status = SE_OL_CORRUPT;
	if (!claim || !claim->owned || claim->reserved || !reservation ||
	    !opaque_key || claim->scope != reservation->scope ||
	    claim->incarnation != reservation->incarnation ||
	    claim->slot != reservation->account_slot ||
	    !se_inherit_snapshot_matches(claim,
					 &opaque_lifecycle_inherit_snapshot,
					 &opaque_lifecycle_projected))
		goto abort;
	status = se_op_store_charged_child_roles(reservation,
						 &opaque_lifecycle_projected);
	if (status != SE_OL_OK)
		goto abort;
	status = se_ow_archive(reservation->meta, reservation->task_slot,
			       reservation->cookie, opaque_key);
	if (status != SE_OL_OK)
		goto abort;
	const __u64 *archive = archive_lookup(reservation->task_slot);
	if (!archive) {
		status = SE_OL_CORRUPT;
		goto abort;
	}
	status = se_ow_insert_zero(reservation->meta, reservation->cookie,
				   archive);
	if (status != SE_OL_OK)
		goto abort;
	status = se_ow_publish_zero(reservation->meta, reservation->cookie,
				    archive);
	if (status != SE_OL_OK)
		goto abort;
	status = se_op_finish_semantic_birth(reservation);
	if (status == SE_OL_OK)
		return SE_OL_OK;
abort:
	return se_op_abort_semantic_birth(reservation) == SE_OL_OK ?
		       status :
		       SE_OL_CORRUPT;
}

SEC("lsm/task_alloc")
int BPF_PROG(opaque_lifecycle_task_alloc, struct task_struct *child,
	     unsigned long clone_flags, int prior)
{
	(void)clone_flags;
	if (prior)
		return prior;
	__u32 zero = 0;
	const struct opaque_lifecycle_gate *gate =
		bpf_map_lookup_elem(&opaque_lifecycle_gate, &zero);
	if (!gate || gate->enabled != 1 || !gate->cgroup_id || !gate->scope ||
	    !gate->incarnation ||
	    bpf_get_current_cgroup_id() != gate->cgroup_id)
		return 0;
	/* This remains a synthetic fixture route, but the charged constructor
	 * now consumes the same held route-claim adapter required by the selected
	 * owner. Keep the claim until the birth commits or aborts; otherwise a
	 * withdrawn route could recycle its account between bind and reserve. */
	struct se_route_anchor *route = route_lookup(0);
	if (!route)
		goto denied;
	struct se_route_claim claim = {};
	bpf_spin_lock(&route->lock);
	if (route->phase == SE_ROUTE_FREE) {
		route->incarnation = gate->incarnation;
		route->cgroup_identity = gate->cgroup_id;
		route->scope = gate->scope;
		route->payload_slot = 0;
		route->payload_generation = 1;
		route->active_serial = 1;
		route->execution_class = 2;
		route->phase = SE_ROUTE_ACTIVE;
	}
	int admitted = se_route_claim_locked(
		route, se_route_locator(0, gate->incarnation), gate->cgroup_id,
		&claim);
	bpf_spin_unlock(&route->lock);
	if (admitted != SE_ROUTE_OWNED)
		goto denied;
	struct se_oc_reservation reservation = {};
	struct task_struct *opaque_key = child;
	if (se_op_prepare_charged_child(&claim, &reservation) != SE_OL_OK)
		goto release_denied;
	/* The selected hook must derive and snapshot-check a real parent
	 * projection here. This fixture supplies only its synthetic empty one. */
	if (opaque_lifecycle_publish_seed_parent(&claim, &reservation,
						 &opaque_key) != SE_OL_OK)
		goto release_denied;
	bpf_spin_lock(&route->lock);
	int released = se_route_release_locked(route, &claim);
	bpf_spin_unlock(&route->lock);
	if (released)
		goto denied;
	struct opaque_lifecycle_counters *counters = lifecycle_counters();
	if (counters) {
		__sync_fetch_and_add(&counters->births, 1);
		counters->last_cookie = reservation.cookie;
	}
	return 0;
release_denied:
	bpf_spin_lock(&route->lock);
	(void)se_route_release_locked(route, &claim);
	bpf_spin_unlock(&route->lock);
denied: {
	struct opaque_lifecycle_counters *counters = lifecycle_counters();
	if (counters)
		__sync_fetch_and_add(&counters->denied, 1);
}
	return -1;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_EVAL_CANDIDATE
static __attribute__((noinline)) int
opaque_lifecycle_policy_prepare(struct se_invocation *work, __u64 scope)
{
	__u32 zero = 0;
	const struct se_snapshot *snapshot =
		bpf_map_lookup_elem(&opaque_lifecycle_policy_snapshot, &zero);
	return se_prepare_policy_view(&work->view, scope, snapshot, 1);
}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CATALOGUE_CLASSIFY_CANDIDATE
static __attribute__((noinline)) int
opaque_lifecycle_catalogue_classify(struct er_canonical_view *view,
				    const struct se_pool_epoch_cache *cache,
				    const struct se_route_claim *claim)
{
	return se_pool_catalogue_classify(view, cache, claim);
}
#endif
/* One actual bprm callback owns the exact TASK lease and a stack WORK ticket.
 * The synthetic semantic write proves the typed pointer is usable only while
 * the ticket remains ACTIVE; it is not a policy decision. */
static __attribute__((noinline)) int
opaque_lifecycle_work_roundtrip(struct se_ol_payload_handle *owner, __u64 scope)
{
	struct se_owk_ticket ticket = {};
	__u32 slot = 0;
	if (se_owk_bind_owner(owner) != SE_OL_OK ||
	    se_owk_choose(owner, &slot) != SE_OL_OK ||
	    se_owk_begin(owner, slot, &ticket) != SE_OL_OK)
		goto fail;
	if (se_owk_attach_owner(owner, &ticket) != SE_OL_OK ||
	    se_owk_initialize_payload(owner, &ticket) != SE_OL_OK ||
	    se_owk_commit(owner, &ticket) != SE_OL_OK)
		goto fail;
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	if (se_owk_semantic_open(owner, &ticket, &semantic, &work) != SE_OL_OK)
		goto fail;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PARENT_SNAPSHOT_DIAGNOSTIC
	/* Verifier-only: the fixture's route was synthetically seeded at birth.
	 * Exercise lexical parent TASK + retained WORK pointer provenance, but
	 * never treat this as an authenticated parent or product reader. */
	struct se_route_anchor *diagnostic_route = route_lookup(0);
	if (diagnostic_route) {
		struct se_route_claim diagnostic_claim = {};
		__u64 diagnostic_cgroup = bpf_get_current_cgroup_id();
		bpf_spin_lock(&diagnostic_route->lock);
		int admission = se_route_claim_locked(
			diagnostic_route,
			se_route_locator(0, diagnostic_route->incarnation),
			diagnostic_cgroup, &diagnostic_claim);
		bpf_spin_unlock(&diagnostic_route->lock);
		if (admission == SE_ROUTE_OWNED) {
			int snapped = se_op_parent_snapshot_held(
				owner, &semantic, work, &diagnostic_claim);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CATALOGUE_CANDIDATE
			if (snapped == SE_OL_OK)
				(void)se_op_parent_project_held(
					&semantic, work, &diagnostic_claim);
#else
			(void)snapped;
#endif
			bpf_spin_lock(&diagnostic_route->lock);
			(void)se_route_release_locked(diagnostic_route,
						      &diagnostic_claim);
			bpf_spin_unlock(&diagnostic_route->lock);
		}
	}
#endif
	work->view.scope_cookie = scope;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_EVAL_CANDIDATE
	if (opaque_lifecycle_policy_prepare(work, scope))
		goto fail;
	struct fm_global_token token = {};
	if (se_owk_evaluator_token(&semantic, &token) != SE_OL_OK ||
	    token.slot != ticket.work_slot || token.cookie != ticket.cookie ||
	    se_owk_view_from_identity(token.slot, token.cookie) != &work->view)
		goto fail;
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
	/* Fact capture has ended. The raw argv copy buffer is dead and must not
	 * be interpreted as cursor state. The WORK lease protects this storage. */
	__builtin_memset(&work->observation.stage_cursor, 0,
			 sizeof(work->observation.stage_cursor));
	if (fe_stage_begin(&token, &work->observation.facts,
			   &work->observation.evaluator,
			   &work->observation.stage_cursor) != 0 ||
	    work->observation.stage_cursor.state != FE_STAGE_ACTIVE)
		goto fail;
#ifdef ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC
	/* Source-issued while the lexical ACTIVE ticket still owns WORK. The
	 * successor only reads this scalar pair after current-task proof. */
	work->observation.stage_workspace.token = token;
#endif
#endif
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CATALOGUE_CANDIDATE
	work->history.scope_cookie = scope;
	work->history.view.work.authority_version = 1;
	work->history.view.work.rows[0] = er_known_row(1, 1, 3);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE
	/* No reader producer exists in this fixture. Keep the reader adapter
	 * verifier-reachable without treating the synthetic claim below as a
	 * substitute for a retained TASK/invocation reader. */
	int reader_status = se_owk_catalogue_fill_reader(&semantic);
	if (reader_status == SE_OL_OK &&
	    se_owk_catalogue_classify_reader(&semantic) != SE_OL_OK)
		goto fail;
#endif
	struct se_route_claim claim = {
		.scope = scope,
		.generation = 1,
		.owned = 1,
	};
	if (se_owk_catalogue_fill(&semantic, &claim) != SE_OL_OK)
		goto fail;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CATALOGUE_CLASSIFY_CANDIDATE
	if (opaque_lifecycle_catalogue_classify(&work->history.view,
						&semantic.payload->catalogue,
						&claim) != 0 ||
	    work->history.view.accepted_mask != 1)
		goto fail;
#endif
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_DEATH_FIXTURE
	/* Deliberately retain one charged WORK after this bprm callback. The
	 * actual task_free callback below, not a synthetic reaper request, must
	 * supply the death lease that closes this suspended transaction. */
	work = 0;
	semantic = (struct se_owk_semantic_handle){};
	if (se_owk_suspend(owner, &ticket, 1) != SE_OL_OK)
		goto fail;
	struct opaque_lifecycle_counters *suspended = lifecycle_counters();
	if (suspended)
		__sync_fetch_and_add(&suspended->work_suspended, 1);
	return SE_OL_OK;
#endif
	if (se_owk_semantic_done(&semantic, &work) != SE_OL_OK)
		goto fail;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_EVAL_CANDIDATE
	if (se_owk_evaluator_token(&semantic, &token) != SE_OL_CORRUPT ||
	    token.slot || token.cookie ||
	    se_owk_view_from_identity(ticket.work_slot, ticket.cookie))
		goto fail;
#endif
	return SE_OL_OK;
fail:
	/* A source failure never drops a charged WORK credit. Abort only through
	 * the ticket's exact stage; a contradiction remains fault-held. */
	if (ticket.held) {
		int result = SE_OL_CORRUPT;
		if (ticket.stage == 0)
			result = se_owk_abort_building(owner, &ticket);
		else if (ticket.stage == 1 || ticket.stage == 2)
			result = se_owk_abort(owner, &ticket);
		else if (ticket.stage == 3)
			result = se_owk_done(owner, &ticket);
		if (result != SE_OL_OK)
			se_owk_fault_ticket(&ticket);
	}
	return SE_OL_CORRUPT;
}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_HANDOFF_DIAGNOSTIC
/* Never attach as policy. The route and snapshot below are synthetic; this
 * separate program exists only to make the full TASK/WORK/child call chain
 * verifier-reachable with a default-zero isolated gate. */
#ifdef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_TAILCALL_DIAGNOSTIC
static __attribute__((noinline)) int
opaque_lifecycle_prepare_child_work(__u64 cgroup_id)
#else
SEC("lsm/task_alloc")
int BPF_PROG(opaque_lifecycle_child_work_handoff_probe,
	     struct task_struct *child, unsigned long clone_flags, int prior)
#endif
{
#ifndef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_TAILCALL_DIAGNOSTIC
	if (prior)
		return prior;
	__u32 zero = 0;
	const struct opaque_lifecycle_gate *gate =
		bpf_map_lookup_elem(&opaque_lifecycle_gate, &zero);
	if (!gate || gate->enabled != 1 || !gate->cgroup_id ||
	    bpf_get_current_cgroup_id() != gate->cgroup_id)
		return 0;
	if (clone_flags & (1ULL << 33))
		return -1;
#endif
	struct se_route_anchor *route = route_lookup(0);
	if (!route)
		return -1;
	struct se_route_claim claim = {};
	bpf_spin_lock(&route->lock);
	int admitted = se_route_claim_locked(
		route, se_route_locator(0, route->incarnation),
#ifdef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_TAILCALL_DIAGNOSTIC
		cgroup_id,
#else
		gate->cgroup_id,
#endif
		&claim);
	bpf_spin_unlock(&route->lock);
	if (admitted != SE_ROUTE_OWNED)
		return -1;
	struct task_struct *parent_key = bpf_get_current_task_btf();
	struct se_ol_payload_handle parent = {};
	if (se_ol_task_open(&parent_key, &parent) != SE_OL_OK)
		goto release_claim;
	struct se_owk_ticket ticket = {};
	__u32 slot = 0;
	if (se_owk_bind_owner(&parent) != SE_OL_OK ||
	    se_owk_choose(&parent, &slot) != SE_OL_OK ||
	    se_owk_begin(&parent, slot, &ticket) != SE_OL_OK)
		goto work_failure;
	if (se_owk_attach_owner(&parent, &ticket) != SE_OL_OK ||
	    se_owk_initialize_payload(&parent, &ticket) != SE_OL_OK ||
	    se_owk_commit(&parent, &ticket) != SE_OL_OK)
		goto work_failure;
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	if (se_owk_semantic_open(&parent, &ticket, &semantic, &work) !=
	    SE_OL_OK)
		goto work_failure;
	if (se_op_parent_snapshot_held(&parent, &semantic, work, &claim) !=
		    SE_OL_OK ||
	    se_op_parent_project_held(&semantic, work, &claim) != SE_OL_OK)
		goto active_failure;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_TAILCALL_DIAGNOSTIC
	/* No pointer or stack claim crosses the edge. The successor must reopen
	 * the same physical TASK and independently reclaim/revalidate the route.
	 * The WORK charge retains the lineage and cache through suspension. */
	work = 0;
	semantic = (struct se_owk_semantic_handle){};
	if (se_owk_suspend(&parent, &ticket, 1) != SE_OL_OK)
		goto work_failure;
	if (se_ol_payload_close(&parent) != SE_OL_OK)
		goto release_claim;
	bpf_spin_lock(&route->lock);
	int claim_released = se_route_release_locked(route, &claim);
	bpf_spin_unlock(&route->lock);
	if (claim_released)
		return -1; /* fault-held WORK; no unowned claim reconstruction */
	return 0;
#else
	struct task_struct *child_key = child;
	int committed = se_op_construct_child_from_parent_work(
				&semantic, &claim,
				&opaque_lifecycle_inherit_snapshot,
				&child_key) == SE_OL_OK;
	/* Once published, denial cannot assume a later task_free; retain the
	 * child even if WORK/claim cleanup faults. This is diagnostic only. */
	(void)se_owk_semantic_done(&semantic, &work);
	(void)se_ol_payload_close(&parent);
	bpf_spin_lock(&route->lock);
	(void)se_route_release_locked(route, &claim);
	bpf_spin_unlock(&route->lock);
	return committed ? 0 : -1;
#endif
active_failure:
	se_owk_fault_ticket(&ticket);
	(void)se_owk_semantic_done(&semantic, &work);
	goto close_parent;
work_failure:
	if (ticket.held) {
		if (ticket.stage == 0)
			(void)se_owk_abort_building(&parent, &ticket);
		else if (ticket.stage == 1 || ticket.stage == 2)
			(void)se_owk_abort(&parent, &ticket);
		else if (ticket.stage == 3)
			(void)se_owk_done(&parent, &ticket);
	}
close_parent:
	(void)se_ol_payload_close(&parent);
release_claim:
	bpf_spin_lock(&route->lock);
	(void)se_route_release_locked(route, &claim);
	bpf_spin_unlock(&route->lock);
	return -1;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_CHILD_WORK_TAILCALL_DIAGNOSTIC
static __attribute__((noinline)) int
opaque_lifecycle_child_work_missing_target(void)
{
	struct task_struct *parent_key = bpf_get_current_task_btf();
	struct se_ol_payload_handle parent = {};
	struct se_owk_ticket ticket = {};
	if (se_ol_task_open(&parent_key, &parent) == SE_OL_OK) {
		if (se_owk_resume(&parent, 1, &ticket) == SE_OL_OK)
			(void)se_owk_done(&parent, &ticket);
		(void)se_ol_payload_close(&parent);
	}
	return -1;
}
static __attribute__((noinline)) int opaque_lifecycle_force_route_loss(void)
{
	struct se_route_anchor *route = route_lookup(0);
	if (!route)
		return 0;
	bpf_spin_lock(&route->lock);
	int exact = route->phase == SE_ROUTE_ACTIVE && !route->early_claims &&
		    !route->reserved &&
		    route->scope == opaque_lifecycle_inherit_snapshot.scope &&
		    route->active_serial ==
			    opaque_lifecycle_inherit_snapshot.serial &&
		    route->payload_generation ==
			    opaque_lifecycle_inherit_snapshot.generation;
	if (exact) {
		route->phase = SE_ROUTE_WITHDRAWN;
		route->admission_serial++;
	}
	bpf_spin_unlock(&route->lock);
	return exact;
}
/* Returning from prepare destroys every lexical pointer and stack claim. */
SEC("lsm/task_alloc")
int BPF_PROG(opaque_lifecycle_child_work_handoff_probe,
	     struct task_struct *child, unsigned long clone_flags, int prior)
{
	(void)child;
	if (prior)
		return prior;
	__u32 zero = 0;
	const struct opaque_lifecycle_gate *gate =
		bpf_map_lookup_elem(&opaque_lifecycle_gate, &zero);
	if (!gate || gate->enabled != 1 || !gate->cgroup_id ||
	    bpf_get_current_cgroup_id() != gate->cgroup_id)
		return 0;
	if ((clone_flags & (1ULL << 33)) ||
	    opaque_lifecycle_prepare_child_work(gate->cgroup_id) != 0)
		return -1;
	struct opaque_lifecycle_child_work_counts *counts =
		bpf_map_lookup_elem(&opaque_lifecycle_child_work_counts, &zero);
	if (counts)
		__sync_fetch_and_add(&counts->source, 1);
	const __u32 *fault =
		bpf_map_lookup_elem(&opaque_lifecycle_child_work_fault, &zero);
	if (fault && *fault == 1 && !opaque_lifecycle_force_route_loss())
		return opaque_lifecycle_child_work_missing_target();
	bpf_tail_call(ctx, &opaque_lifecycle_child_work_targets, 0);
	/* Missing target: exact suspended WORK is reclaimed or fault-held. */
	if (counts)
		__sync_fetch_and_add(&counts->fallback, 1);
	return opaque_lifecycle_child_work_missing_target();
}
/* Scalar claim bytes can cross a BPF-to-BPF call; the route map pointer and
 * lock cannot. Reopen the fixed route element for each exact transition. */
static __attribute__((noinline)) int
opaque_lifecycle_claim_child_route(__u64 cgroup_id,
				   struct se_route_claim *claim)
{
	struct se_route_anchor *route = route_lookup(0);
	if (!route)
		return 0;
	bpf_spin_lock(&route->lock);
	int admitted = se_route_claim_locked(
		route, se_route_locator(0, route->incarnation), cgroup_id,
		claim);
	bpf_spin_unlock(&route->lock);
	return admitted == SE_ROUTE_OWNED;
}
static __attribute__((noinline)) int
opaque_lifecycle_release_child_route(struct se_route_claim *claim)
{
	struct se_route_anchor *route = route_lookup(0);
	if (!route)
		return 0;
	bpf_spin_lock(&route->lock);
	int released = se_route_release_locked(route, claim);
	bpf_spin_unlock(&route->lock);
	return released == 0;
}
/* Keep the route claim outside the target's TASK/WORK handle frame. The
 * caller still owns the ACTIVE semantic lease across this synchronous call. */
static __attribute__((noinline)) int opaque_lifecycle_claimed_child_from_work(
	struct se_owk_semantic_handle *semantic, struct task_struct *child,
	__u64 cgroup_id)
{
	struct se_route_claim claim = {};
	if (!opaque_lifecycle_claim_child_route(cgroup_id, &claim))
		return 0;
	int committed = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_CHILD_TAIL_EARLY_SNAPSHOT_DIAGNOSTIC
	/* Isolate the matcher before charge; this branch always denies. */
	struct se_invocation *work = &semantic->payload->semantic;
	int matched = se_inherit_snapshot_matches(
		&claim, &opaque_lifecycle_inherit_snapshot, &work->inherited);
	struct opaque_lifecycle_counters *counts = lifecycle_counters();
	if (matched && counts)
		__sync_fetch_and_add(&counts->births, 1);
#else
	struct task_struct *child_key = child;
	committed = se_op_construct_child_from_parent_work(
			    semantic, &claim,
			    &opaque_lifecycle_inherit_snapshot,
			    &child_key) == SE_OL_OK;
#endif
	return opaque_lifecycle_release_child_route(&claim) && committed;
}
/* Counter/gate state stays in the tiny LSM wrapper, not in the live TASK
 * and WORK handle frame that later invokes charged child publication. */
static __attribute__((noinline)) int
opaque_lifecycle_finish_child_work(struct task_struct *child, __u64 cgroup_id)
{
	struct task_struct *parent_key = bpf_get_current_task_btf();
	struct se_ol_payload_handle parent = {};
	struct se_owk_ticket ticket = {};
	int committed = 0;
	if (se_ol_task_open(&parent_key, &parent) != SE_OL_OK)
		return 0;
	if (se_owk_resume(&parent, 1, &ticket) != SE_OL_OK)
		goto close_parent;
	struct se_owk_semantic_handle semantic = {};
	struct se_invocation *work = 0;
	if (se_owk_semantic_open(&parent, &ticket, &semantic, &work) !=
	    SE_OL_OK) {
		(void)se_owk_done(&parent, &ticket);
		goto close_parent;
	}
	committed = opaque_lifecycle_claimed_child_from_work(&semantic, child,
							     cgroup_id);
	if (se_owk_semantic_done(&semantic, &work) != SE_OL_OK)
		committed = 0;
close_parent:
	if (se_ol_payload_close(&parent) != SE_OL_OK)
		committed = 0;
	return committed;
}
SEC("lsm/task_alloc")
int BPF_PROG(opaque_lifecycle_child_work_target_probe,
	     struct task_struct *child, unsigned long clone_flags, int prior)
{
	if (prior)
		return prior;
	__u32 zero = 0;
	const struct opaque_lifecycle_gate *gate =
		bpf_map_lookup_elem(&opaque_lifecycle_gate, &zero);
	if (!gate || gate->enabled != 1 || !gate->cgroup_id ||
	    bpf_get_current_cgroup_id() != gate->cgroup_id ||
	    (clone_flags & (1ULL << 33)))
		return -1;
	struct opaque_lifecycle_child_work_counts *counts =
		bpf_map_lookup_elem(&opaque_lifecycle_child_work_counts, &zero);
	if (counts)
		__sync_fetch_and_add(&counts->target, 1);
	int committed =
		opaque_lifecycle_finish_child_work(child, gate->cgroup_id);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_CHILD_TAIL_EARLY_SNAPSHOT_DIAGNOSTIC
	return -1;
#else
	if (committed && counts)
		__sync_fetch_and_add(&counts->accepted, 1);
	return committed ? 0 : -1;
#endif
}
#endif
#endif
/* Test-only source owner: a real bprm callback reserves one transaction on
 * the exact current physical TASK. The synthetic policy metadata exercises
 * transaction ownership, not policy selection or an enforcement verdict. An
 * untracked task (including the shell moved into the test cgroup after its
 * birth) remains nonblocking. No helper runs under the TASK metadata lock. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_lifecycle_exec, struct linux_binprm *bprm, int prior)
{
	__u32 zero = 0;
	const struct opaque_lifecycle_gate *gate =
		bpf_map_lookup_elem(&opaque_lifecycle_gate, &zero);
	if (!gate || gate->enabled != 1 || !gate->scope ||
	    bpf_get_current_cgroup_id() != gate->cgroup_id)
		return prior;
	struct task_struct *physical = bpf_get_current_task_btf();
	struct task_struct *opaque_key = physical;
	struct se_ol_payload_handle handle = {};
	if (prior) {
		/* The test producer preserves an earlier LSM errno while recording
		 * the same exact TASK semantic mutation as the selected callback. */
		if (se_ol_task_open(&opaque_key, &handle) == SE_OL_OK) {
			(void)se_op_task_note_prior_deny(&handle, (__u64)bprm);
			(void)se_ol_payload_close(&handle);
		}
		return prior;
	}
	if (se_ol_task_open(&opaque_key, &handle) != SE_OL_OK)
		return 0;
	struct se_task_state *task = 0;
	int reserved = 0, fault = 0;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
	int work_done = 0, work_fault = 0;
#endif
	if (se_op_task_semantic_begin(&handle, &task) != SE_OL_OK) {
		fault = 1;
		goto close;
	}
	struct se_exec_source source = {
		.scope = gate->scope,
		.generation = 1,
		.bprm = (__u64)bprm,
		.execution_class = 1,
		.count = 1,
		.policies = { { .uid = 1, .epoch = 1 } },
	};
	int result = se_exec_reserve_locked(task, handle.lease.cookie, &source);
	if (result == 0)
		reserved = 1;
	else if (result < 0)
		fault = 1;
	se_op_task_semantic_end(&handle, &task);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
	if (result >= 0) {
		if (opaque_lifecycle_work_roundtrip(&handle, gate->scope) ==
		    SE_OL_OK)
			work_done = 1;
		else
			work_fault = 1;
	}
#endif
close:
	if (se_ol_payload_close(&handle) != SE_OL_OK)
		fault = 1;
	struct opaque_lifecycle_counters *counters = lifecycle_counters();
	if (counters) {
		if (reserved)
			__sync_fetch_and_add(&counters->exec_reserved, 1);
		if (fault)
			__sync_fetch_and_add(&counters->exec_faults, 1);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
		if (work_done)
			__sync_fetch_and_add(&counters->work_done, 1);
		if (work_fault)
			__sync_fetch_and_add(&counters->work_faults, 1);
#endif
	}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_TAILCALL_FIXTURE
	if (work_fault)
		return -1;
	if (work_done) {
		if (counters)
			__sync_fetch_and_add(&counters->tail_entry, 1);
		bpf_tail_call(ctx, &opaque_lifecycle_tail_targets, 0);
		/* Missing/replaced stage: this callback remains the source owner.
		 * Reopen the original key, consume the suspended WORK, and deny. */
		if (counters)
			__sync_fetch_and_add(&counters->tail_fallback, 1);
		handle = (struct se_ol_payload_handle){};
		struct se_owk_ticket closing = {};
		if (se_ol_task_open(&opaque_key, &handle) == SE_OL_OK) {
			if (se_owk_resume(&handle, 1, &closing) == SE_OL_OK)
				(void)se_owk_done(&handle, &closing);
			(void)se_ol_payload_close(&handle);
		}
		return -1;
	}
#endif
	return 0;
}
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_TAILCALL_FIXTURE
/* Not independently attached. Only the frozen program-array edge can reach
 * this successor; it must reopen the same original physical TASK key. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_lifecycle_exec_stage, struct linux_binprm *bprm, int prior)
{
	(void)bprm;
	if (prior)
		return prior;
	__u32 zero = 0;
	const struct opaque_lifecycle_gate *gate =
		bpf_map_lookup_elem(&opaque_lifecycle_gate, &zero);
	if (!gate || gate->enabled != 1 || !gate->scope ||
	    bpf_get_current_cgroup_id() != gate->cgroup_id)
		return -1;
	struct opaque_lifecycle_counters *counters = lifecycle_counters();
	if (counters)
		__sync_fetch_and_add(&counters->tail_stage, 1);
	struct task_struct *opaque_key = bpf_get_current_task_btf();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	if (se_ol_task_open(&opaque_key, &owner) != SE_OL_OK)
		return -1;
	int ok = se_owk_resume(&owner, 1, &ticket) == SE_OL_OK;
	if (ok) {
		struct se_owk_semantic_handle semantic = {};
		struct se_invocation *work = 0;
		ok = se_owk_semantic_open(&owner, &ticket, &semantic, &work) ==
		     SE_OL_OK;
#ifdef ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE
		if (ok) {
			struct fm_global_token *token =
				&work->observation.stage_workspace.token;
			__builtin_memset(token, 0, sizeof(*token));
			/* Diagnostic-only split: measure the combined source/begin path
			 * before loading the full matcher/evaluator successor graph. */
#ifdef ENFORCE_EXEC_STAGE_BEGIN_ONLY_DIAGNOSTIC
			ok = se_owk_evaluator_token(&semantic, token) ==
				     SE_OL_OK &&
			     work->observation.stage_cursor.state ==
				     FE_STAGE_ACTIVE;
#elif defined(ENFORCE_EXEC_STAGE_ADVANCE_ONLY_DIAGNOSTIC)
			ok = se_owk_evaluator_token(&semantic, token) ==
				     SE_OL_OK &&
			     work->observation.stage_cursor.state ==
				     FE_STAGE_ACTIVE &&
			     fe_stage_advance(
				     token, &work->observation.facts,
				     &work->observation.evaluator,
				     &work->observation.stage_cursor) == 0 &&
			     work->observation.stage_cursor.state ==
				     FE_STAGE_READY;
#else
			ok = se_owk_evaluator_token(&semantic, token) ==
				     SE_OL_OK &&
			     token->slot == ticket.work_slot &&
			     token->cookie == ticket.cookie &&
			     work->observation.stage_cursor.state ==
				     FE_STAGE_ACTIVE &&
			     fe_stage_advance(
				     token, &work->observation.facts,
				     &work->observation.evaluator,
				     &work->observation.stage_cursor) == 0 &&
			     work->observation.stage_cursor.state ==
				     FE_STAGE_READY &&
			     fe_stage_finish(token,
					     &work->observation.evaluator,
					     &work->observation.stage_cursor) ==
				     0 &&
			     work->observation.stage_cursor.state ==
				     FE_STAGE_FINISHED &&
			     work->observation.evaluator.decision.mode == 2 &&
			     !work->observation.evaluator.decision.deny &&
			     !work->observation.evaluator.decision.error;
#endif
		}
#endif
		if (ok)
			ok = work->view.scope_cookie == gate->scope &&
			     se_owk_semantic_done(&semantic, &work) == SE_OL_OK;
		if (!ok && ticket.held)
			(void)se_owk_done(&owner, &ticket);
	}
	if (se_ol_payload_close(&owner) != SE_OL_OK)
		ok = 0;
	if (ok && counters)
		__sync_fetch_and_add(&counters->tail_done, 1);
	return ok ? 0 : -1;
}
#endif
#endif

#ifdef ENFORCE_EXEC_SUSPENDED_WORK_READ_CANDIDATE
/* Unarmed load-only current-task reader probe. It always denies and is not a
 * tail-call target or policy decision. The counter makes the validated read
 * verifier-reachable without attaching it to any workload. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_lifecycle_suspended_current_probe,
	     struct linux_binprm *bprm, int prior)
{
	(void)bprm;
	if (prior)
		return prior;
	__u32 zero = 0;
	const struct opaque_lifecycle_gate *gate =
		bpf_map_lookup_elem(&opaque_lifecycle_gate, &zero);
	if (!gate || gate->enabled != 1 || !gate->scope ||
	    bpf_get_current_cgroup_id() != gate->cgroup_id)
		return -1;
	struct se_owk_payload *payload =
		se_owk_suspended_current(gate->scope, 1, 0);
	if (payload) {
		struct opaque_lifecycle_counters *counters =
			lifecycle_counters();
		if (counters)
			__sync_fetch_and_add(&counters->tail_stage, 1);
	}
	return -1;
}
#endif

#ifdef ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC
/* Both the tail-call destination and its missing-target fallback use this
 * same exact current-TASK stage-2 closer. Its return is always a deny; no
 * evaluator result is trusted as a verdict by this diagnostic. */
static __attribute__((noinline)) int
opaque_lifecycle_close_suspended_stage(__u32 stage)
{
	struct task_struct *physical = bpf_get_current_task_btf();
	struct se_ol_payload_handle owner = {};
	struct se_owk_ticket ticket = {};
	if (se_ol_task_open(&physical, &owner) != SE_OL_OK)
		return -1;
	if (se_owk_resume(&owner, stage, &ticket) == SE_OL_OK)
		(void)se_owk_done(&owner, &ticket);
	if (ticket.held)
		(void)se_owk_done(&owner, &ticket);
	(void)se_ol_payload_close(&owner);
	return -1;
}

SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_lifecycle_suspended_stage2_diagnostic,
	     struct linux_binprm *bprm, int prior)
{
	(void)bprm;
	if (prior)
		return prior;
	__u32 zero = 0;
	const struct opaque_lifecycle_gate *gate =
		bpf_map_lookup_elem(&opaque_lifecycle_gate, &zero);
	if (!gate || gate->enabled != 1 || !gate->scope ||
	    bpf_get_current_cgroup_id() != gate->cgroup_id)
		return -1;
	struct opaque_lifecycle_counters *counters = lifecycle_counters();
	if (counters)
		__sync_fetch_and_add(&counters->diag_stage2, 1);
	return opaque_lifecycle_close_suspended_stage(2);
}

/* Program-only verifier compartment. The authenticated reader, stage claim,
 * evaluator and stage-2 commit share a stack; successful commit tail-calls
 * the stage-2 closer or uses a direct missing-target fallback. No policy is
 * applied. Never attach this diagnostic or use it as a selected target. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_lifecycle_suspended_eval_reader_diagnostic,
	     struct linux_binprm *bprm, int prior)
{
	(void)bprm;
	if (prior)
		return prior;
	__u32 zero = 0;
	const struct opaque_lifecycle_gate *gate =
		bpf_map_lookup_elem(&opaque_lifecycle_gate, &zero);
	if (!gate || gate->enabled != 1 || !gate->scope ||
	    bpf_get_current_cgroup_id() != gate->cgroup_id)
		return -1;
	struct se_owk_payload *payload =
		se_owk_suspended_current(gate->scope, 1, 1);
	if (!payload)
		return -1;
	struct se_invocation *work = &payload->semantic;
	struct fm_global_token *token =
		&work->observation.stage_workspace.token;
	{
		struct opaque_lifecycle_counters *counters =
			lifecycle_counters();
		if (counters)
			__sync_fetch_and_add(&counters->diag_eval, 1);
	}
	if (token->slot == work->slot && token->cookie == work->cookie &&
	    !token->reserved &&
	    se_owk_suspended_view_from_token(token->slot, token->cookie) ==
		    &work->view)
		(void)fe_stage_advance(token, &work->observation.facts,
				       &work->observation.evaluator,
				       &work->observation.stage_cursor);
#ifdef ENFORCE_EXEC_STAGE_COMMIT_FAILURE_DIAGNOSTIC
#define SE_OWK_DIAG_COMMIT_SCOPE(work) ((work)->scope + 1)
#else
#define SE_OWK_DIAG_COMMIT_SCOPE(work) ((work)->scope)
#endif
	if (se_owk_commit_suspended_stage(
		    payload, SE_OWK_DIAG_COMMIT_SCOPE(work), 1) != SE_OL_OK) {
		/* A failed commit cannot abandon a reserved WORK. Release only
		 * through the same physical TASK/account authentication, then
		 * resume stage 1 and close. If commit already advanced stage 2,
		 * the stage-2 closer handles that exact state instead. Structural
		 * contradiction remains fail-closed for death/fault handling. */
		if (se_owk_suspended_current(work->scope, 1, 2) == payload)
			return opaque_lifecycle_close_suspended_stage(1);
		return opaque_lifecycle_close_suspended_stage(2);
	}
#undef SE_OWK_DIAG_COMMIT_SCOPE
	bpf_tail_call(ctx, &opaque_lifecycle_suspended_diag_target, 0);
	struct opaque_lifecycle_counters *counters = lifecycle_counters();
	if (counters)
		__sync_fetch_and_add(&counters->diag_fallback, 1);
	return opaque_lifecycle_close_suspended_stage(2);
}
#endif

#if defined(ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE) && \
	defined(ENFORCE_EXEC_SUSPENDED_EVAL_STACK_PROBE)
/* Never attach or select this diagnostic. It deliberately lacks WORK/TASK
 * authority and always denies; only its compiled evaluator stack is useful.
 * A real suspended reader must be added and proved before this can run. */
SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_lifecycle_suspended_eval_stack_probe,
	     struct linux_binprm *bprm, int prior)
{
	(void)bprm;
	if (prior)
		return prior;
	__u32 zero = 0;
	struct se_owk_payload *payload = SE_OWK_PAYLOAD_LOOKUP(zero);
	if (!payload)
		return -1;
	struct se_invocation *work = &payload->semantic;
	struct fm_global_token *token =
		&work->observation.stage_workspace.token;
	if (fe_stage_advance(token, &work->observation.facts,
			     &work->observation.evaluator,
			     &work->observation.stage_cursor))
		return -1;
	return -1;
}
#endif

SEC("lsm/task_free")
int BPF_PROG(opaque_lifecycle_task_free, struct task_struct *physical)
{
	struct se_of_lease lease = {};
	if (se_of_record_death(physical, &lease) != SE_OL_OK)
		return 0;
	/* The fixture's actual task_free owns exec abort; native and reader
	 * obligations are empty. WORK_DONE is source-issued at death only when
	 * there is no WORK ref; otherwise the WORK-first reaper issues it. */
	struct se_of_semantic_handle semantic = {};
	struct se_pool_task_wire *payload = 0;
	if (se_of_semantic_begin(&lease, physical, &semantic, &payload) ==
	    SE_OL_OK) {
		struct se_ol_meta *meta = lease.meta;
		int exec_clear = 1;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE
		int exec_aborted = 0;
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE
		/* There is no reader producer. The real bprm transaction is cleared
		 * under the exact post-DEAD owner lock before EXEC_DONE is issued. */
		struct se_task_state *task = &payload->semantic;
		if (task->exec.owned) {
			exec_clear = task->exec.bprm && task->exec.sequence &&
				     !se_exec_abort_locked(task, lease.cookie,
							   task->exec.bprm,
							   task->exec.sequence);
			exec_aborted = exec_clear;
		}
		if (!exec_clear)
			meta->cleanup_error = 1;
#endif
		if (meta->phase == SE_OL_DEAD && !meta->native_refs &&
		    !meta->cleanup_error && exec_clear)
			meta->cleanup_done |= SE_OL_EXEC_DONE |
					      SE_OL_NATIVE_DONE;
		(void)se_of_semantic_end(&semantic, &payload);
#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_DEATH_FIXTURE
		int work_death = se_owk_finish_suspended_death(&lease);
		if (work_death == SE_OL_OK) {
			struct opaque_lifecycle_counters *death_counters =
				lifecycle_counters();
			if (death_counters)
				__sync_fetch_and_add(
					&death_counters->work_death_closed, 1);
		}
		if (work_death == SE_OL_CORRUPT) {
			bpf_spin_lock(&meta->lock);
			meta->cleanup_error = 1;
			bpf_spin_unlock(&meta->lock);
		}
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE
		struct opaque_lifecycle_counters *exec_counters =
			lifecycle_counters();
		if (exec_counters && exec_aborted)
			__sync_fetch_and_add(&exec_counters->exec_aborted, 1);
#endif
	}
	(void)se_of_release(&lease, physical);
	struct opaque_lifecycle_counters *counters = lifecycle_counters();
	if (counters)
		__sync_fetch_and_add(&counters->deaths, 1);
	return 0;
}

/* The userspace controller serializes exact slot/cookie requests. One
 * invocation performs at most one durable stage and cannot invent a death
 * or source completion receipt. A mismatched request leaves the charge. */
SEC("tc")
int opaque_lifecycle_reap(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const struct opaque_lifecycle_request *request =
		bpf_map_lookup_elem(&opaque_lifecycle_request, &zero);
	if (!request || !request->cookie || request->reserved ||
	    request->slot >= SE_OL_TASKS)
		return 0;
	struct se_ol_meta *meta = meta_lookup(request->slot);
	struct opaque_lifecycle_counters *counters = lifecycle_counters();
	if (!meta || !counters)
		return 0;
	__u64 cookie = request->cookie;
	__u32 phase, directory;
	bpf_spin_lock(&meta->lock);
	int exact = meta->cookie == cookie &&
		    (meta->phase == SE_OL_DEAD ||
		     meta->phase == SE_OL_ABORTED ||
		     meta->phase == SE_OL_CLEANING ||
		     meta->phase == SE_OL_ARCHIVE_ZEROED ||
		     meta->phase == SE_OL_REFUND_PENDING);
	phase = meta->phase;
	directory = meta->directory_state;
	bpf_spin_unlock(&meta->lock);
	/* The refund tail first resets metadata to FREE (cookie zero), while
	 * the exact RETURN_READY charge still owns the account bit. The final
	 * account-locked return must remain reachable from that state; the
	 * refund helper itself rechecks the charge, bit, last cookie and FREE
	 * metadata before touching credit. */
	if (!exact && phase == SE_OL_FREE) {
		struct se_oc_charge *charge = charge_lookup(request->slot);
		if (charge && charge->state == SE_OC_RETURN_READY &&
		    charge->cookie == cookie)
			exact = 1;
	}
	if (!exact)
		return 0;
	const __u64 *archive = archive_lookup(request->slot);
	int result = SE_OL_CORRUPT;
	if (phase == SE_OL_ARCHIVE_ZEROED || phase == SE_OL_REFUND_PENDING ||
	    phase == SE_OL_FREE) {
		if (phase == SE_OL_ARCHIVE_ZEROED)
			(void)se_op_zero_payload(request->slot, cookie);
		result = se_oc_refund_step(request->slot, cookie);
	} else if (directory == SE_OL_PUBLISHED) {
		result = se_ow_claim_withdraw(meta, cookie);
	} else if (directory == SE_OL_WITHDRAW_CLAIM && archive) {
		result = se_ow_advance_withdraw(meta, cookie, archive);
	} else if (directory == SE_OL_WITHDRAWN_ZERO && archive) {
		result = se_ow_delete_withdrawn_zero(meta, cookie, archive);
	} else if (directory == SE_OL_NO_ENTRY) {
		result = se_ow_mark_absent_deleted(meta, cookie);
	} else if (directory == SE_OL_ZERO_OWNED) {
		result = se_ow_claim_aborted_zero(meta, cookie);
	} else if (directory == SE_OL_DELETED) {
		result = se_ow_zero_archive(meta, cookie);
	}
	__sync_fetch_and_add(&counters->reaper_calls, 1);
	counters->last_reap_result = result;
	return 0;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE
/* Test-run only: the userspace controller supplies an exact WORK slot/cookie
 * and serializes one source-authorized reaper stage before TASK refund. */
SEC("tc")
int opaque_lifecycle_work_reap(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const struct opaque_lifecycle_request *request =
		bpf_map_lookup_elem(&opaque_lifecycle_request, &zero);
	if (!request || !request->cookie || request->reserved ||
	    request->slot >= SE_OWK_WORKS)
		return 0;
	int result = se_owk_reap_step(request->slot, request->cookie);
	struct opaque_lifecycle_counters *counters = lifecycle_counters();
	if (counters) {
		__sync_fetch_and_add(&counters->work_reaper_calls, 1);
		counters->last_work_reap_result = result;
	}
	return 0;
}
#endif
