/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_REAPER_CONTROL_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_REAPER_CONTROL_CANDIDATE_H
#if !defined(ENFORCE_EXEC_SHARED_RECOVERY) ||               \
	!(defined(ENFORCE_EXEC_POOL_DEVELOPMENT) &&         \
	  defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY)) && \
		!defined(ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE)
#error "reaper control requires a recovered typed or opaque pool candidate"
#endif
#if !defined(SE_POOL_T) || !defined(SE_POOL_W)
#error "reaper control requires explicit fixed TASK and WORK capacities"
#endif

/* This protocol is deliberately not an entrypoint. Its caller must execute
 * begin, the exact 32/32 visits, and finish in ONE BPF invocation. A future
 * tail-call driver must clear BUSY in its missing-tail-call fallback; a
 * separate invocation is never permitted to finish or reset an accepted step.
 * The recovery predicate samples the real physical caller under its own lock
 * before this function takes the independent pool-control lock. */
enum {
	SE_POOL_REAP_ABI = 1,
	SE_POOL_REAP_STEP = 1,
	SE_POOL_REAP_BUSY = 1,
	SE_POOL_REAP_RECEIPT_VALID = 1,
	/* Stage/zero-byte telemetry is not wired to the current visitors. */
	SE_POOL_REAP_RECEIPT_METRICS_INCOMPLETE = 2,
};
enum se_pool_reap_admission {
	SE_POOL_REAP_ACCEPT = 0,
	SE_POOL_REAP_REFUSE = 1,
	SE_POOL_REAP_IN_FLIGHT = 2,
	SE_POOL_REAP_FAULT = 3,
};

struct se_pool_reap_progress {
	__u32 task_cursor, work_cursor;
	__u32 task_examined, work_examined;
	__u32 task_reclaimed, work_reclaimed;
	__u32 task_pending, work_pending;
	__u32 task_faults, work_faults;
	__u64 bytes_zeroed, stages;
};

/* Copy once before authentication, then validate only the copied request.
 * A rejection must preserve the previous accepted receipt and control. */
static __attribute__((always_inline)) inline int
se_pool_reap_begin(const struct se_pool_request *wire,
		   struct se_pool_control *control,
		   struct se_pool_request *accepted)
{
	if (!wire || !control || !accepted)
		return SE_POOL_REAP_REFUSE;
	struct se_pool_request q = *wire;
	if (q.abi != SE_POOL_REAP_ABI || q.operation != SE_POOL_REAP_STEP ||
	    !q.node_incarnation || !q.admin_generation || !q.reap_sequence ||
	    q.reap_sequence == ~(__u64)0 || q.reserved0 || q.reserved1 ||
	    q.task_budget != (SE_POOL_T < 32u ? SE_POOL_T : 32u) ||
	    q.work_budget != (SE_POOL_W < 32u ? SE_POOL_W : 32u))
		return SE_POOL_REAP_REFUSE;
	if (!se_rm_reap_authorized(q.node_incarnation, q.admin_generation))
		return SE_POOL_REAP_REFUSE;

	int result = SE_POOL_REAP_REFUSE;
	bpf_spin_lock(&control->lock);
	if (control->flags == SE_POOL_REAP_BUSY) {
		result = SE_POOL_REAP_IN_FLIGHT;
	} else if (control->flags ||
		   (control->node_incarnation &&
		    control->node_incarnation != q.node_incarnation) ||
		   control->task_cursor >= SE_POOL_T ||
		   control->work_cursor >= SE_POOL_W ||
		   control->scan_epoch == ~(__u64)0 ||
		   control->last_reap_sequence >= ~(__u64)0 - 1 ||
		   control->task_visits > ~(__u64)0 - q.task_budget ||
		   control->work_visits > ~(__u64)0 - q.work_budget) {
		result = SE_POOL_REAP_FAULT;
	} else if (q.expected_epoch == control->scan_epoch &&
		   q.reap_sequence == control->last_reap_sequence + 1 &&
		   q.admin_generation >= control->last_admin_generation) {
		control->flags = SE_POOL_REAP_BUSY;
		control->node_incarnation = q.node_incarnation;
		control->last_admin_generation = q.admin_generation;
		control->last_reap_sequence = q.reap_sequence;
		result = SE_POOL_REAP_ACCEPT;
	}
	bpf_spin_unlock(&control->lock);
	if (result == SE_POOL_REAP_ACCEPT)
		*accepted = q;
	return result;
}

/* Both terminal paths accept only progress from real visits in this BPF
 * invocation. An incomplete path (for example a failed tail call) publishes a
 * fault receipt, advances only actual visits, consumes the epoch/sequence and
 * releases BUSY. It must never be mistaken for a successful 32/32 scan. A
 * malformed frame or changed control retains BUSY as an invariant fault. */
static __attribute__((always_inline)) inline int se_pool_reap_epilogue(
	struct se_pool_control *control, struct se_pool_receipt *receipt,
	const struct se_pool_request *accepted,
	const struct se_pool_reap_progress *progress, int incomplete)
{
	if (!control || !receipt || !accepted || !progress)
		return SE_POOL_REAP_FAULT;
	int result = SE_POOL_REAP_FAULT;
	bpf_spin_lock(&control->lock);
	const __u32 next_task = (__u32)(((__u64)control->task_cursor +
					 progress->task_examined) %
					SE_POOL_T);
	const __u32 next_work = (__u32)(((__u64)control->work_cursor +
					 progress->work_examined) %
					SE_POOL_W);
	const int full = progress->task_examined == accepted->task_budget &&
			 progress->work_examined == accepted->work_budget;
	if (accepted->abi == SE_POOL_REAP_ABI &&
	    accepted->operation == SE_POOL_REAP_STEP && !accepted->reserved0 &&
	    !accepted->reserved1 &&
	    accepted->task_budget == (SE_POOL_T < 32u ? SE_POOL_T : 32u) &&
	    accepted->work_budget == (SE_POOL_W < 32u ? SE_POOL_W : 32u) &&
	    control->flags == SE_POOL_REAP_BUSY &&
	    control->node_incarnation == accepted->node_incarnation &&
	    control->last_admin_generation == accepted->admin_generation &&
	    control->last_reap_sequence == accepted->reap_sequence &&
	    control->scan_epoch == accepted->expected_epoch &&
	    progress->task_examined <= accepted->task_budget &&
	    progress->work_examined <= accepted->work_budget &&
	    (incomplete ? !full : full) && progress->task_cursor == next_task &&
	    progress->work_cursor == next_work &&
	    (__u64)progress->task_reclaimed + progress->task_pending +
			    progress->task_faults <=
		    progress->task_examined &&
	    (__u64)progress->work_reclaimed + progress->work_pending +
			    progress->work_faults <=
		    progress->work_examined) {
		*receipt = (struct se_pool_receipt){
			.abi = SE_POOL_REAP_ABI,
			.status = incomplete ? SE_POOL_REAP_FAULT :
					       SE_POOL_REAP_ACCEPT,
			.node_incarnation = accepted->node_incarnation,
			.admin_generation = accepted->admin_generation,
			.reap_sequence = accepted->reap_sequence,
			.epoch_before = control->scan_epoch,
			.epoch_after = control->scan_epoch + 1,
			.task_before = control->task_cursor,
			.task_after = next_task,
			.work_before = control->work_cursor,
			.work_after = next_work,
			.task_examined = progress->task_examined,
			.work_examined = progress->work_examined,
			.task_reclaimed = progress->task_reclaimed,
			.work_reclaimed = progress->work_reclaimed,
			.task_pending = progress->task_pending,
			.work_pending = progress->work_pending,
			.task_faults = progress->task_faults,
			.work_faults = progress->work_faults,
			.bytes_zeroed = progress->bytes_zeroed,
			.stages = progress->stages,
			.flags = SE_POOL_REAP_RECEIPT_VALID |
				 SE_POOL_REAP_RECEIPT_METRICS_INCOMPLETE,
		};
		control->task_cursor = next_task;
		control->work_cursor = next_work;
		control->task_visits += progress->task_examined;
		control->work_visits += progress->work_examined;
		control->scan_epoch++;
		control->flags = 0;
		result = incomplete ? SE_POOL_REAP_FAULT : SE_POOL_REAP_ACCEPT;
	}
	bpf_spin_unlock(&control->lock);
	return result;
}

static __attribute__((always_inline)) inline int
se_pool_reap_finish(struct se_pool_control *control,
		    struct se_pool_receipt *receipt,
		    const struct se_pool_request *accepted,
		    const struct se_pool_reap_progress *progress)
{
	return se_pool_reap_epilogue(control, receipt, accepted, progress, 0);
}

static __attribute__((always_inline)) inline int
se_pool_reap_abort(struct se_pool_control *control,
		   struct se_pool_receipt *receipt,
		   const struct se_pool_request *accepted,
		   const struct se_pool_reap_progress *progress)
{
	return se_pool_reap_epilogue(control, receipt, accepted, progress, 1);
}
#endif
