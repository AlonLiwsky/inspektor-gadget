// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
#ifndef IG_OPAQUE_REAL_OWNER_LIVE_BOOTSTRAP_DIAGNOSTIC_H
#define IG_OPAQUE_REAL_OWNER_LIVE_BOOTSTRAP_DIAGNOSTIC_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC
#error "test-only bootstrap must be explicitly selected"
#endif
#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE
#error "test-only live bootstrap requires the complete reaper composition"
#endif

/* Never product authority. The controller chooses one disposable cgroup and
 * freezes this gate before any link. The TC initializer is run once before
 * the seed hook attaches; it deliberately bypasses authenticated commands,
 * object pins and native ARM. Only actual opaque TASK/WORK maps are shared
 * with the callback under test. */
struct opaque_real_live_bootstrap_gate {
	__u64 cgroup, scope;
	/* Zero is the earlier Audit fixture default; 2 opts into strict only
	 * for the isolated exhaustion test. Never product configuration. */
	__u32 enabled, execution_class;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_real_live_bootstrap_gate);
} opaque_real_live_bootstrap_gate SEC(".maps");

static __always_inline const struct opaque_real_live_bootstrap_gate *
opaque_real_live_gate(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&opaque_real_live_bootstrap_gate, &zero);
}

/* The synthetic policy has one UID with a known parent role. It cannot
 * authorize a product verdict; the real reader and WORK path must still
 * authenticate their own physical TASK, route and accepted-history cells. */
static const struct er_work opaque_real_live_parent_roles = {
	.authority_version = 1,
	.prepared = 1,
	.rows = { { .uid = 1,
		    .epoch = 1,
		    .role = 1,
		    .knowledge = ER_ROLE_KNOWN } },
};
static const struct se_snapshot opaque_real_live_seed_snapshot = {
	.scope = 10, .serial = 1, .generation = 1, .count = 1,
	.metadata = {
		.root_epochs = { 1 }, .policy_uids = { 1 },
		.container_length = 1, .container = "/",
	},
};

SEC("tc")
int opaque_real_live_bootstrap_control(struct __sk_buff *skb)
{
	(void)skb;
	const struct opaque_real_live_bootstrap_gate *gate =
		opaque_real_live_gate();
	if (!gate || gate->enabled != 1 || gate->execution_class > 2 ||
	    !gate->cgroup || gate->scope != 10)
		return -1;
	__u32 execution_class = gate->execution_class == 2 ? 2 : 1;
	__u32 zero = 0;
	struct se_route_anchor *route = bpf_map_lookup_elem(&se_routes, &zero);
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &zero);
	struct se_epoch_cell *cell = bpf_map_lookup_elem(&se_epoch_bank, &zero);
	if (!route || !binding || !cell || route->phase ||
	    binding->state.scope || cell->scope)
		return -1;
	struct se_binding_snapshots *state = &binding->state;
	state->scope = gate->scope;
	state->generation = 1;
	state->active_serial = 1;
	state->active_record = 0;
	state->records[0].scope = gate->scope;
	state->records[0].serial = 1;
	state->records[0].generation = 1;
	state->records[0].phase = SE_SNAPSHOT_ACTIVE;
	state->records[0].count = 1;
	state->records[0].execution_class = execution_class;
	state->records[0].metadata.root_epochs[0] = 1;
	state->records[0].metadata.policy_uids[0] = 1;
	state->records[0].metadata.container_length = 1;
	state->records[0].metadata.container[0] = '/';
	cell->scope = gate->scope;
	cell->uid = 1;
	cell->epoch = 1;
	struct se_epoch_key epoch_key = { .scope = gate->scope, .uid = 1 };
	if (bpf_map_update_elem(&se_epoch_index, &epoch_key, &zero,
				BPF_NOEXIST))
		return -1;
	bpf_spin_lock(&route->lock);
	route->incarnation = 1;
	route->cgroup_identity = gate->cgroup;
	route->scope = gate->scope;
	route->payload_slot = 0;
	route->payload_generation = 1;
	route->active_serial = 1;
	route->active_record = 0;
	route->execution_class = execution_class;
	route->phase = SE_ROUTE_ACTIVE;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	route->rec[0] = (struct se_route_rec){ .serial = 1,
					       .generation = 1,
					       .phase = SE_SNAPSHOT_ACTIVE };
#endif
	bpf_spin_unlock(&route->lock);
	__u64 locator = se_route_locator(0, 1);
	return bpf_map_update_elem(&se_route_index, &gate->cgroup, &locator,
				   BPF_NOEXIST) ?
		       -1 :
		       0;
}

#ifdef ENFORCE_EXEC_POOL_OPAQUE_ROUTE_MIGRATION_DIAGNOSTIC
/* G025 step 7, test-only: a second route (route/binding/epoch slot 1, scope
 * 11) on a second disposable cgroup with the OPPOSITE class, seeded exactly
 * like the first and run once before any hook attaches. Births never happen
 * there (the seeded parent stays on the first cgroup); it only receives
 * migrated children. Never product authority. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_real_live_bootstrap_gate);
} opaque_real_live_second_route_gate SEC(".maps");

SEC("tc")
int opaque_real_live_bootstrap_second_route(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0, one = 1;
	const struct opaque_real_live_bootstrap_gate *first =
		opaque_real_live_gate();
	const struct opaque_real_live_bootstrap_gate *gate =
		bpf_map_lookup_elem(&opaque_real_live_second_route_gate, &zero);
	if (!first || !gate || first->enabled != 1 || gate->enabled != 1 ||
	    first->execution_class < 1 || first->execution_class > 2 ||
	    gate->execution_class != 3 - first->execution_class ||
	    !gate->cgroup || gate->cgroup == first->cgroup ||
	    first->scope != 10 || gate->scope != 11)
		return -1;
	__u32 execution_class = gate->execution_class == 2 ? 2 : 1;
	struct se_route_anchor *route = bpf_map_lookup_elem(&se_routes, &one);
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &one);
	struct se_epoch_cell *cell = bpf_map_lookup_elem(&se_epoch_bank, &one);
	if (!route || !binding || !cell || route->phase ||
	    binding->state.scope || cell->scope)
		return -1;
	struct se_binding_snapshots *state = &binding->state;
	state->scope = gate->scope;
	state->generation = 1;
	state->active_serial = 1;
	state->active_record = 0;
	state->records[0].scope = gate->scope;
	state->records[0].serial = 1;
	state->records[0].generation = 1;
	state->records[0].phase = SE_SNAPSHOT_ACTIVE;
	state->records[0].count = 1;
	state->records[0].execution_class = execution_class;
	state->records[0].metadata.root_epochs[0] = 1;
	state->records[0].metadata.policy_uids[0] = 1;
	state->records[0].metadata.container_length = 1;
	state->records[0].metadata.container[0] = '/';
	cell->scope = gate->scope;
	cell->uid = 1;
	cell->epoch = 1;
	struct se_epoch_key epoch_key = { .scope = gate->scope, .uid = 1 };
	if (bpf_map_update_elem(&se_epoch_index, &epoch_key, &one, BPF_NOEXIST))
		return -1;
	bpf_spin_lock(&route->lock);
	route->incarnation = 1;
	route->cgroup_identity = gate->cgroup;
	route->scope = gate->scope;
	route->payload_slot = 1;
	route->payload_generation = 1;
	route->active_serial = 1;
	route->active_record = 0;
	route->execution_class = execution_class;
	route->phase = SE_ROUTE_ACTIVE;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	route->rec[0] = (struct se_route_rec){ .serial = 1,
					       .generation = 1,
					       .phase = SE_SNAPSHOT_ACTIVE };
#endif
	bpf_spin_unlock(&route->lock);
	__u64 locator = se_route_locator(1, 1);
	return bpf_map_update_elem(&se_route_index, &gate->cgroup, &locator,
				   BPF_NOEXIST) ?
		       -1 :
		       0;
}
#endif

#ifdef ENFORCE_EXEC_POOL_OPAQUE_RELOAD_DIAGNOSTIC
/* G025 step 8, test-only generation advance of the first route. Today the
 * bootstrap fixes generation 1; this entrypoint publishes the next one with
 * the PRODUCT route/binding commit pair (se_route_commit_preflight_locked +
 * se_route_commit_publish_locked) under the original route lock. Only the
 * snapshot staging and object pin bookkeeping are direct test stores, as in
 * the bootstrap seed (no authenticated PIN command, no native ARM). Record r
 * always tickets fixed object r: object 0 is the seeded policy, object 1 the
 * test-only second policy. The preflight refuses while any early claim,
 * source pin, unresolved source, binding inflight count or old-record reader
 * exists, so an in-flight exec can never observe a generation change.
 * Codes: 0 published; 1 refused by that preflight (candidate rolled back,
 * last-good kept); 2 injected mid-publication fault after the candidate was
 * PREPARED and pinned (rolled back, last-good kept); -1 invariant. */
struct opaque_real_live_advance_request {
	__u32 fault, enabled;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_real_live_advance_request);
} opaque_real_live_advance_request SEC(".maps");

SEC("tc")
int opaque_real_live_bootstrap_advance(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0, one = 1;
	const struct opaque_real_live_bootstrap_gate *gate =
		opaque_real_live_gate();
	const struct opaque_real_live_advance_request *request =
		bpf_map_lookup_elem(&opaque_real_live_advance_request, &zero);
	struct se_route_anchor *route = bpf_map_lookup_elem(&se_routes, &zero);
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &zero);
	struct se_shared_object *object0 =
		bpf_map_lookup_elem(&se_objects, &zero);
	struct se_shared_object *object1 =
		bpf_map_lookup_elem(&se_objects, &one);
	if (!gate || gate->enabled != 1 || gate->scope != 10 || !request ||
	    request->enabled != 1 || request->fault > 1 || !route || !binding ||
	    !object0 || !object1)
		return -1;
	__u32 fault = request->fault;
	int code = -1;
	struct se_binding_snapshots *b = &binding->state;
	bpf_spin_lock(&route->lock);
	__u32 active = b->active_record & 1;
	__u32 record = active ^ 1;
	struct se_snapshot *s = &b->records[record];
	const struct se_snapshot *old = &b->records[active];
	struct se_object *target = record ? &object1->state : &object0->state;
	__u32 execution_class = old->execution_class;
	if (route->phase != SE_ROUTE_ACTIVE || route->payload_slot != 0 ||
	    b->scope != gate->scope || !b->active_serial ||
	    old->phase != SE_SNAPSHOT_ACTIVE || execution_class < 1 ||
	    execution_class > 2 || target->phase != SE_OBJECT_READY ||
	    target->slot != record ||
	    target->execution_class != execution_class)
		goto out;
	/* The previous retiring record has no reader (its commit required
	 * zero claims and new readers only acquire the active record). */
	if (s->phase == SE_SNAPSHOT_RETIRING) {
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
		/* G019 gap 3: the retiring record may still have holders (its
		 * commit no longer required none): busy, retried (code 1). */
		if (s->claims || se_route_rec_held(route, record)) {
			code = 1;
			goto out;
		}
#endif
		if (s->count != 1 || s->claims || s->commands ||
		    s->tickets[0].phase != SE_TICKET_HELD ||
		    s->tickets[0].object_slot != record || !target->pins)
			goto out;
		target->pins--;
		s->tickets[0].phase = SE_TICKET_RELEASED;
		if (se_snapshot_reclaim_locked(s))
			goto out;
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
		route->rec[se_route_rec_index(record)] =
			(struct se_route_rec){};
#endif
	}
	if (target->pins == (__u32)~0U)
		goto out;
	/* The bootstrap seeded serial 1 without advancing next_serial; never
	 * reissue an active serial. */
	if (b->next_serial < b->active_serial)
		b->next_serial = b->active_serial;
	struct se_pin_ticket handle = {
		.object_generation = target->generation,
		.object_slot = record,
	};
	if (se_snapshot_prepare_locked(b, record, &handle, 1, execution_class))
		goto out;
	s->metadata.root_epochs[0] = 1;
	s->metadata.policy_uids[0] = 1;
	s->metadata.container_length = 1;
	s->metadata.container[0] = '/';
	target->pins++;
	s->tickets[0].phase = SE_TICKET_HELD;
	if (se_snapshot_prepared_locked(s) ||
	    !se_snapshot_metadata_valid(&s->metadata, 1, b->generation + 1)) {
		code = -1;
		goto rollback;
	}
	if (fault) {
		code = 2;
		goto rollback;
	}
	if (se_route_commit_preflight_locked(route, b, record, s->serial,
					     route->admission_serial)) {
		code = 1;
		goto rollback;
	}
	se_route_commit_publish_locked(route, b, record);
	code = 0;
	goto out;
rollback:
	/* Abort only the uncommitted candidate; the ACTIVE record, generation
	 * and route tuple are untouched. */
	if (se_snapshot_retire_locked(s) || !target->pins) {
		code = -1;
		goto out;
	}
	target->pins--;
	s->tickets[0].phase = SE_TICKET_RELEASED;
	if (se_snapshot_reclaim_locked(s))
		code = -1;
out:
	bpf_spin_unlock(&route->lock);
	return code;
}
#endif

static __attribute__((noinline)) int
opaque_real_live_seed_child(struct task_struct *child)
{
	struct se_route_claim claim = {};
	if (se_route_admit(bpf_get_current_cgroup_id(), &claim) !=
	    SE_ROUTE_OWNED)
		return -1;
	struct se_oc_reservation reservation = {};
	int prepared = se_op_prepare_charged_child(&claim, &reservation);
	int published = 0;
	if (prepared == SE_OL_OK) {
		struct task_struct *key = child;
		published = se_op_publish_charged_child(
				    &claim, &opaque_real_live_seed_snapshot,
				    &opaque_real_live_parent_roles, &key,
				    &reservation) == SE_OL_OK;
	}
	struct se_route_anchor *route = route_lookup(claim.slot);
	if (route) {
		bpf_spin_lock(&route->lock);
		(void)se_route_release_locked(route, &claim);
		bpf_spin_unlock(&route->lock);
	}
	/* A published child must not be denied after its charge became live. */
	return published ? 0 : -1;
}

SEC("lsm/task_alloc")
int BPF_PROG(opaque_real_live_bootstrap_birth, struct task_struct *child,
	     unsigned long clone_flags, int prior)
{
	(void)clone_flags;
	if (prior)
		return prior;
	const struct opaque_real_live_bootstrap_gate *gate =
		opaque_real_live_gate();
	if (!gate || gate->enabled != 1 ||
	    bpf_get_current_cgroup_id() != gate->cgroup)
		return 0;
	return opaque_real_live_seed_child(child);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(opaque_real_live_bootstrap_qualify, struct linux_binprm *bprm,
	     int prior)
{
	(void)bprm;
	if (prior)
		return prior;
	const struct opaque_real_live_bootstrap_gate *gate =
		opaque_real_live_gate();
	if (!gate || gate->enabled != 1 ||
	    bpf_get_current_cgroup_id() != gate->cgroup)
		return 0;
	__u64 key = (__u64)bpf_get_current_task_btf();
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&key, &owner) != SE_OL_OK)
		return 0;
	struct se_task_state *task = 0;
	if (se_op_task_semantic_begin(&owner, &task) == SE_OL_OK) {
		if (task->physical_cookie == owner.lease.cookie &&
		    task->scope_cookie == gate->scope &&
		    task->flags == SE_TASK_LIVE && task->committed.version)
			task->flags = SE_TASK_QUALIFIED;
		se_op_task_semantic_end(&owner, &task);
	}
	(void)se_ol_payload_close(&owner);
	return 0;
}

/* A test-only transport to the real one-step WORK reaper. It cannot create
 * source cleanup receipts; the attached completion must first do that. */
struct opaque_real_live_work_reap_request {
	__u64 cookie;
	__u32 slot, enabled;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_real_live_work_reap_request);
} opaque_real_live_work_reap_request SEC(".maps");
SEC("tc")
int opaque_real_live_reap_work(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const struct opaque_real_live_bootstrap_gate *gate =
		opaque_real_live_gate();
	const struct opaque_real_live_work_reap_request *request =
		bpf_map_lookup_elem(&opaque_real_live_work_reap_request, &zero);
	if (!gate || gate->enabled != 1 || !request || request->enabled != 1 ||
	    !request->cookie)
		return SE_OWK_STALE;
	/* The visit claim when the object returns WORK synchronously (G019
	 * option C): this test reaper and BPF's own return never step one WORK
	 * at once. */
	return SE_OWK_REAP_CLAIMED(request->slot, request->cookie);
}

struct opaque_real_live_task_reap_request {
	__u64 cookie;
	__u32 slot, enabled;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_real_live_task_reap_request);
} opaque_real_live_task_reap_request SEC(".maps");
SEC("tc")
int opaque_real_live_reap_task(struct __sk_buff *skb)
{
	(void)skb;
	__u32 zero = 0;
	const struct opaque_real_live_bootstrap_gate *gate =
		opaque_real_live_gate();
	const struct opaque_real_live_task_reap_request *request =
		bpf_map_lookup_elem(&opaque_real_live_task_reap_request, &zero);
	if (!gate || gate->enabled != 1 || !request || request->enabled != 1 ||
	    !request->cookie || request->slot >= SE_OL_TASKS)
		return SE_OR_FAULT;
	struct se_oc_charge *charge = charge_lookup(request->slot);
	if (!charge || charge->cookie != request->cookie)
		return SE_OR_FAULT;
	return se_or_task_visit(request->slot);
}
#endif
