/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_REAPER_CHUNK_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_REAPER_CHUNK_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE) || \
	!defined(ENFORCE_EXEC_SHARED_RECOVERY)
#error "opaque reaper chunk requires the recovered candidate"
#endif

/* Work-first fixed-slot scan. Every count is the result of an actual visit;
 * the copied request and cursor are merely bounds, never cleanup authority.
 * Eight tail-called chunks cover a 32/32 step without one verifier-sized
 * monolith. The common transport aborts on a missing continuation. */
static __attribute__((noinline)) int
se_pool_reap_chunk4(const struct se_pool_request *accepted, __u32 task_start,
		    __u32 work_start, struct se_pool_reap_progress *progress)
{
	if (!accepted || !progress ||
	    accepted->task_budget != (SE_POOL_T < 32u ? SE_POOL_T : 32u) ||
	    accepted->work_budget != (SE_POOL_W < 32u ? SE_POOL_W : 32u) ||
	    task_start >= SE_POOL_T || work_start >= SE_POOL_W ||
	    progress->task_examined > accepted->task_budget ||
	    progress->work_examined > accepted->work_budget ||
	    progress->task_cursor !=
		    (__u32)(((__u64)task_start + progress->task_examined) %
			    SE_POOL_T) ||
	    progress->work_cursor !=
		    (__u32)(((__u64)work_start + progress->work_examined) %
			    SE_POOL_W) ||
	    (__u64)progress->task_reclaimed + progress->task_pending +
			    progress->task_faults >
		    progress->task_examined ||
	    (__u64)progress->work_reclaimed + progress->work_pending +
			    progress->work_faults >
		    progress->work_examined)
		return SE_POOL_REAP_FAULT;
	if (progress->task_examined == accepted->task_budget &&
	    progress->work_examined == accepted->work_budget)
		return SE_POOL_REAP_REFUSE;

#ifdef __clang__
#pragma unroll
#endif
	for (__u32 i = 0; i < 4; i++) {
		if (progress->work_examined >= accepted->work_budget)
			break;
		int result = se_or_work_visit(progress->work_cursor);
		if (result == SE_OR_RETURNED)
			progress->work_reclaimed++;
		else if (result == SE_OR_PENDING || result == SE_OR_PROGRESS)
			progress->work_pending++;
		else if (result == SE_OR_FAULT)
			progress->work_faults++;
		progress->work_examined++;
		progress->work_cursor = progress->work_cursor + 1 == SE_POOL_W ?
						0 :
						progress->work_cursor + 1;
	}
#ifdef __clang__
#pragma unroll
#endif
	for (__u32 i = 0; i < 4; i++) {
		if (progress->task_examined >= accepted->task_budget)
			break;
		int result = se_or_task_visit(progress->task_cursor);
		if (result == SE_OR_RETURNED)
			progress->task_reclaimed++;
		else if (result == SE_OR_PENDING || result == SE_OR_PROGRESS)
			progress->task_pending++;
		else if (result == SE_OR_FAULT)
			progress->task_faults++;
		progress->task_examined++;
		progress->task_cursor = progress->task_cursor + 1 == SE_POOL_T ?
						0 :
						progress->task_cursor + 1;
	}
	return SE_POOL_REAP_ACCEPT;
}
#endif
