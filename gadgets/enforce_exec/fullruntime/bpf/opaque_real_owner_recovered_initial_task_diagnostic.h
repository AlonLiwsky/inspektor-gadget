// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
#ifndef IG_OPAQUE_REAL_OWNER_RECOVERED_INITIAL_TASK_DIAGNOSTIC_H
#define IG_OPAQUE_REAL_OWNER_RECOVERED_INITIAL_TASK_DIAGNOSTIC_H
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_RECOVERED_INITIAL_TASK_DIAGNOSTIC) || \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_RECOVERY_CANDIDATE) ||       \
	!defined(ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC)
#error "recovered initial TASK diagnostic requires recovered admin and disposable bootstrap"
#endif
#ifdef ENFORCE_EXEC_POOL_OPAQUE_NATIVE_CONFIG_GATE_CANDIDATE
#error "diagnostic initial TASK enrollment cannot be selected as product authority"
#endif

/* Test-only request. The tuple is a selector, NOT authority: the current
 * physical task must be the COMMITTED recovered admin, and the target must
 * come from a held proc FD's signal-0 task_kill callback. The fixture routes
 * its proc FD through physical-pin preparation, but its BindingLease is not
 * a trusted runtime lease and cannot authorize product enrollment. The
 * synthetic snapshot/roles below are not product policy or Ready proof. */
struct opaque_recovered_initial_request {
	__u64 node_cookie, admin_generation, cgroup, scope;
	__u32 target_tgid, enabled;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_recovered_initial_request);
} opaque_recovered_initial_request SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u32);
} opaque_recovered_initial_consumed SEC(".maps");
/* Stage is diagnostic only; it cannot grant a TASK, recovery, or cleanup. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u32);
} opaque_recovered_initial_stage SEC(".maps");
/* BPF-owned, UAPI-read-only witness. A first authenticated signal-0 captures
 * the physical TASK while the runtime fixture holds its proc/namespace pins;
 * a second invocation may enroll only that same TASK. task_free tombstones
 * the witness before that address can be reused, closing pointer ABA. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u64);
} opaque_recovered_initial_physical SEC(".maps");

static __always_inline void
opaque_recovered_initial_retire_physical(struct task_struct *physical)
{
	__u32 zero = 0;
	__u64 *witness =
		bpf_map_lookup_elem(&opaque_recovered_initial_physical, &zero);
	if (witness)
		(void)__sync_val_compare_and_swap(witness, (__u64)physical, 1);
}

/* The constructor and semantic handle need disjoint BPF call frames. */
static __attribute__((noinline)) int
opaque_recovered_initial_charge(struct task_struct *target, __u64 cgroup,
				__u64 scope)
{
	struct se_route_claim claim = {};
	if (se_route_admit(cgroup, &claim) != SE_ROUTE_OWNED)
		return -1;
	if (claim.scope != scope) {
		(void)real_owner_child_release_claim(&claim);
		return -1;
	}
	struct se_oc_reservation initial = {};
	int status = se_op_prepare_charged_child(&claim, &initial);
	if (status == SE_OL_OK) {
		struct task_struct *key = target;
		status = se_op_publish_charged_child(
			&claim, &opaque_real_live_seed_snapshot,
			&opaque_real_live_parent_roles, &key, &initial);
	}
	int released = real_owner_child_release_claim(&claim);
	return status == SE_OL_OK && !released ? 0 : -1;
}

static __attribute__((noinline)) int
opaque_recovered_initial_qualify(struct task_struct *target, __u64 scope)
{
	__u64 key = (__u64)target;
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&key, &owner) != SE_OL_OK)
		return -1;
	struct se_task_state *task = 0;
	int qualified = 0;
	if (se_op_task_semantic_begin(&owner, &task) == SE_OL_OK) {
		if (task->physical_cookie == owner.lease.cookie &&
		    task->scope_cookie == scope &&
		    task->flags == SE_TASK_LIVE && task->committed.version) {
			task->flags = SE_TASK_QUALIFIED;
			qualified = 1;
		}
		se_op_task_semantic_end(&owner, &task);
	}
	if (se_ol_payload_close(&owner) != SE_OL_OK)
		qualified = 0;
	return qualified ? 0 : -1;
}

SEC("lsm/task_kill")
int BPF_PROG(opaque_real_owner_recovered_initial_task_diagnostic,
	     struct task_struct *target, struct kernel_siginfo *info,
	     int signal, const struct cred *cred, int prior)
{
	(void)info;
	(void)cred;
	if (prior || signal || !target || !real_owner_image_configured())
		return prior;
	__u32 zero = 0;
	const struct opaque_recovered_initial_request *request =
		bpf_map_lookup_elem(&opaque_recovered_initial_request, &zero);
	__u32 *consumed =
		bpf_map_lookup_elem(&opaque_recovered_initial_consumed, &zero);
	__u32 *stage =
		bpf_map_lookup_elem(&opaque_recovered_initial_stage, &zero);
	__u64 *witness =
		bpf_map_lookup_elem(&opaque_recovered_initial_physical, &zero);
	const struct opaque_real_live_bootstrap_gate *gate =
		opaque_real_live_gate();
	if (!request || !consumed || !stage || !witness || !gate ||
	    request->enabled != 1 || gate->enabled != 1 ||
	    !request->node_cookie || !request->admin_generation ||
	    !request->target_tgid || !request->cgroup ||
	    request->cgroup != gate->cgroup || request->scope != gate->scope ||
	    !se_rm_reap_authorized(request->node_cookie,
				   request->admin_generation))
		return 0;
	__u32 tid = 0, tgid = 0;
	__u64 cgroup = 0;
	if (BPF_CORE_READ_INTO(&tid, target, pid) ||
	    BPF_CORE_READ_INTO(&tgid, target, tgid) ||
	    BPF_CORE_READ_INTO(&cgroup, target, cgroups, dfl_cgrp, kn, id) ||
	    tid != tgid || tgid != request->target_tgid ||
	    cgroup != request->cgroup)
		return 0;
	__u64 physical = (__u64)target;
	__u64 observed = __sync_val_compare_and_swap(witness, 0, physical);
	if (observed == 0) {
		(void)__sync_val_compare_and_swap(stage, 0, 1);
		return 0; /* capture is never enrollment */
	}
	if (observed != physical)
		return -1; /* moved/replaced physical TASK, including tombstone */
	if (__sync_val_compare_and_swap(consumed, 0, 1) != 0)
		return 0;
	*stage = 2;
	if (opaque_recovered_initial_charge(target, request->cgroup,
					    request->scope))
		return -1;
	*stage = 3;
	if (opaque_recovered_initial_qualify(target, request->scope))
		return -1;
	*stage = 4;
	return 0;
}
#endif
