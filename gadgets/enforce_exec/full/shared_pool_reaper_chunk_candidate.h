/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_REAPER_CHUNK_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_REAPER_CHUNK_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_DEVELOPMENT) ||                 \
	!defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY) ||      \
	!defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE) || \
	!defined(ENFORCE_EXEC_SHARED_RECOVERY)
#error "reaper chunk requires the typed pool and recovery development image"
#endif

/* One bounded work-first chunk. The accepted request and progress are
 * internal same-invocation state, never wire authority. A future tail-call
 * driver must preserve this state across chunks, invoke eight chunks for a
 * 32/32 profile, and take a mandatory success/inconclusive epilogue. This
 * helper does not itself reserve BUSY, authenticate a caller, or publish a
 * receipt. All slot counters below are outcomes of real visitor calls. */
SE_POOL_INLINE int se_pool_reap_chunk4(const struct se_pool_request *accepted,
				       __u32 task_start, __u32 work_start,
				       struct se_pool_reap_progress *progress)
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
		int status =
			se_pool_reap_work_visit_slot(progress->work_cursor);
		if (status == SE_PW_RETURNED)
			progress->work_reclaimed++;
		else if (status == SE_PW_FREE)
			; /* No charge existed or it was already returned. */
		else if (status == SE_PW_PENDING || status == SE_PW_BUSY ||
			 status == SE_PW_CONTENDED || status == SE_PW_ALREADY)
			progress->work_pending++;
		else
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
		int status =
			se_pool_reap_task_visit_slot(progress->task_cursor);
		if (status == SE_POOL_OK)
			progress->task_reclaimed++;
		else if (status == SE_POOL_ALREADY_RETURNED)
			; /* No current charge. */
		else if (status == SE_POOL_PENDING_CLEANUP ||
			 status == SE_POOL_NOT_ELIGIBLE ||
			 status == SE_POOL_CONTENDED || status == SE_POOL_STALE)
			progress->task_pending++;
		else
			progress->task_faults++;
		progress->task_examined++;
		progress->task_cursor = progress->task_cursor + 1 == SE_POOL_T ?
						0 :
						progress->task_cursor + 1;
	}
	return SE_POOL_REAP_ACCEPT;
}
#endif
