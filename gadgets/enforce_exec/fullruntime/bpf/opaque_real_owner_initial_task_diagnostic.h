// SPDX-License-Identifier: GPL-2.0
// Copyright 2026 The Inspektor Gadget authors
#ifndef IG_OPAQUE_REAL_OWNER_INITIAL_TASK_DIAGNOSTIC_H
#define IG_OPAQUE_REAL_OWNER_INITIAL_TASK_DIAGNOSTIC_H
#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC
#error "initial TASK fixture requires disposable bootstrap"
#endif
#ifndef ENFORCE_EXEC_POOL_OPAQUE_INITIAL_TASK_DIAGNOSTIC
#error "initial TASK fixture is opt-in only"
#endif

/* Test-only stand-in for the missing native exact-init witness. A PID and
 * cgroup are NOT production authority: the live test must hold the helper
 * while staging this request, and the selected image must exclude this map.
 * This fixture also reuses task_alloc's CONSTRUCTION_DONE transaction on the
 * current, live prctl task. That succeeds in the narrow test but is NOT a
 * source-certified initial-task completion protocol for product adoption. */
struct opaque_initial_request {
	__u64 cgroup, scope;
	__u32 tid, enabled;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct opaque_initial_request);
} opaque_initial_request SEC(".maps");

/* The kernel callback consumes one request before charging. A failed attempt
 * cannot be retried with the same scalar tuple; no second root is inferred. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, __u32);
} opaque_initial_consumed SEC(".maps");

SEC("lsm/task_prctl")
int BPF_PROG(opaque_real_owner_initial_task_diagnostic, int option,
	     unsigned long arg2, unsigned long arg3, unsigned long arg4,
	     unsigned long arg5, int prior)
{
	(void)arg2;
	(void)arg3;
	(void)arg4;
	(void)arg5;
	if (prior || option != 15 || !real_owner_image_configured())
		return prior;
	__u32 zero = 0;
	const struct opaque_initial_request *request =
		bpf_map_lookup_elem(&opaque_initial_request, &zero);
	__u32 *consumed = bpf_map_lookup_elem(&opaque_initial_consumed, &zero);
	const struct opaque_real_live_bootstrap_gate *gate =
		opaque_real_live_gate();
	if (!request || !consumed || !gate || request->enabled != 1 ||
	    gate->enabled != 1 || request->scope != gate->scope ||
	    request->cgroup != gate->cgroup ||
	    request->cgroup != bpf_get_current_cgroup_id() ||
	    request->tid != (__u32)bpf_get_current_pid_tgid())
		return 0;
	if (__sync_val_compare_and_swap(consumed, 0, 1) != 0)
		return -1;
	struct task_struct *current = bpf_get_current_task_btf();
	if (!current)
		return -1;
	struct se_route_claim claim = {};
	if (se_route_admit(request->cgroup, &claim) != SE_ROUTE_OWNED)
		return -1;
	struct se_oc_reservation initial = {};
	int status = se_op_prepare_charged_child(&claim, &initial);
	if (status == SE_OL_OK) {
		struct task_struct *key = current;
		status = se_op_publish_charged_child(
			&claim, &opaque_real_live_seed_snapshot,
			&opaque_real_live_parent_roles, &key, &initial);
	}
	int released = real_owner_child_release_claim(&claim);
	if (status != SE_OL_OK || released)
		return -1;
	__u64 key = (__u64)current;
	struct se_ol_payload_handle owner = {};
	if (se_ol_task_open(&key, &owner) != SE_OL_OK)
		return -1;
	struct se_task_state *task = 0;
	int qualified = 0;
	if (se_op_task_semantic_begin(&owner, &task) == SE_OL_OK) {
		if (task->physical_cookie == owner.lease.cookie &&
		    task->scope_cookie == request->scope &&
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
#endif
