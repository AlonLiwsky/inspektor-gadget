/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_REAPER_TRANSPORT_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_REAPER_TRANSPORT_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_REAPER_CANDIDATE) ||              \
	!defined(ENFORCE_EXEC_SHARED_RECOVERY) ||                \
	!(defined(ENFORCE_EXEC_POOL_DEVELOPMENT) &&              \
	  defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY) &&       \
	  defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE)) && \
		!defined(ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE)
#error "reaper transport requires a recovered typed or opaque pool candidate"
#endif

/* BPF_PROG_TEST_RUN is the command transport on admitted older kernels. The
 * host must load these TC programs but never attach them. Only the physical
 * recovered admin can begin a step. The single-flight BUSY reservation owns
 * this BPF-writable, userspace-readonly stage across same-invocation tail
 * calls; no userspace ticket or previous receipt grants authority. */
struct se_pool_reap_stage {
	__u64 physical_task;
	struct se_pool_request accepted;
	__u32 task_start, work_start, active, reserved;
	struct se_pool_reap_progress progress;
};
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_pool_reap_stage);
} se_pool_reap_stage SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} se_pool_reap_chain SEC(".maps");

SEC("tc") int se_pool_reaper_entry(struct __sk_buff *skb)
{
	__u32 zero = 0;
	const struct se_pool_request *request =
		bpf_map_lookup_elem(&se_pool_reap_request, &zero);
	struct se_pool_control *control =
		bpf_map_lookup_elem(&se_pool_reap_control, &zero);
	struct se_pool_receipt *receipt =
		bpf_map_lookup_elem(&se_pool_reap_receipt, &zero);
	struct se_pool_reap_stage *stage =
		bpf_map_lookup_elem(&se_pool_reap_stage, &zero);
	if (!request || !control || !receipt || !stage)
		return 0;
	struct se_pool_request accepted = {};
	if (se_pool_reap_begin(request, control, &accepted) !=
	    SE_POOL_REAP_ACCEPT)
		return 0;
	__u64 task = bpf_get_current_task();
	bpf_spin_lock(&control->lock);
	__u32 task_start = control->task_cursor;
	__u32 work_start = control->work_cursor;
	bpf_spin_unlock(&control->lock);
	*stage = (struct se_pool_reap_stage){
		.physical_task = task,
		.accepted = accepted,
		.task_start = task_start,
		.work_start = work_start,
		.active = 1,
		.progress = {
			.task_cursor = task_start,
			.work_cursor = work_start,
		},
	};
	bpf_tail_call(skb, &se_pool_reap_chain, 0);
	(void)se_pool_reap_abort(control, receipt, &accepted, &stage->progress);
	stage->active = 0;
	return 0;
}

SEC("tc") int se_pool_reaper_chunk(struct __sk_buff *skb)
{
	__u32 zero = 0;
	struct se_pool_control *control =
		bpf_map_lookup_elem(&se_pool_reap_control, &zero);
	struct se_pool_receipt *receipt =
		bpf_map_lookup_elem(&se_pool_reap_receipt, &zero);
	struct se_pool_reap_stage *stage =
		bpf_map_lookup_elem(&se_pool_reap_stage, &zero);
	if (!control || !receipt || !stage || stage->active != 1 ||
	    stage->physical_task != bpf_get_current_task())
		return 0;
	bpf_spin_lock(&control->lock);
	int held =
		control->flags == SE_POOL_REAP_BUSY &&
		control->node_incarnation == stage->accepted.node_incarnation &&
		control->last_admin_generation ==
			stage->accepted.admin_generation &&
		control->last_reap_sequence == stage->accepted.reap_sequence &&
		control->scan_epoch == stage->accepted.expected_epoch &&
		control->task_cursor == stage->task_start &&
		control->work_cursor == stage->work_start;
	bpf_spin_unlock(&control->lock);
	if (!held)
		return 0; /* Structural fault retains BUSY; never invent completion. */
	if (se_pool_reap_chunk4(&stage->accepted, stage->task_start,
				stage->work_start,
				&stage->progress) != SE_POOL_REAP_ACCEPT) {
		(void)se_pool_reap_abort(control, receipt, &stage->accepted,
					 &stage->progress);
		stage->active = 0;
		return 0;
	}
	if (stage->progress.task_examined == stage->accepted.task_budget &&
	    stage->progress.work_examined == stage->accepted.work_budget) {
		(void)se_pool_reap_finish(control, receipt, &stage->accepted,
					  &stage->progress);
		stage->active = 0;
		return 0;
	}
	bpf_tail_call(skb, &se_pool_reap_chain, 0);
	(void)se_pool_reap_abort(control, receipt, &stage->accepted,
				 &stage->progress);
	stage->active = 0;
	return 0;
}
#endif
