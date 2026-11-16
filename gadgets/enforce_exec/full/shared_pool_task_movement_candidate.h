/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_TASK_MOVEMENT_CANDIDATE_H
#define ENFORCE_EXEC_SHARED_POOL_TASK_MOVEMENT_CANDIDATE_H
#if !defined(ENFORCE_EXEC_POOL_DEVELOPMENT) ||            \
	!defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY) || \
	!defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE)
#error "typed task movement is candidate-only"
#endif

/* The exact TASK handle owns the original account throughout this observation.
 * A current-cgroup mismatch invalidates eligibility, but never transfers the
 * original charge or invents admission in the destination. No map helper or
 * route lock is held under the TASK metadata lock. The second begin rechecks
 * the lexical token after the route observation before mutating semantics. */
SE_POOL_INLINE int
se_pool_observe_task_movement(struct se_pool_task_semantic_handle *handle,
			      __u64 cgroup)
{
	if (!handle || !cgroup || handle->locked || handle->lease.held != 1 ||
	    !handle->meta || !handle->payload)
		return SE_POOL_CORRUPT;
	int status = se_pool_task_semantic_begin(handle);
	if (status != SE_POOL_OK)
		return status;
	const struct se_task_state *task = &handle->payload->semantic;
	__u64 cookie = task->physical_cookie;
	__u64 scope = task->scope_cookie;
	__u32 account = task->scope_slot;
	int ended = se_pool_task_semantic_end(handle);
	if (ended != SE_POOL_OK)
		return ended;
	if (cookie != handle->lease.token.cookie || !scope ||
	    account >= SE_POOL_B)
		return SE_POOL_CORRUPT;
	struct se_route_anchor *route = se_route_anchor_lookup(&account);
	if (!route)
		return SE_POOL_CORRUPT;
	bpf_spin_lock(&route->lock);
	int moved = route->scope != scope || route->payload_slot != account ||
		    route->cgroup_identity != cgroup;
	bpf_spin_unlock(&route->lock);
	if (!moved)
		return SE_POOL_OK;
	status = se_pool_task_semantic_begin(handle);
	if (status != SE_POOL_OK)
		return status;
	struct se_task_state *current = &handle->payload->semantic;
	if (current->physical_cookie != cookie ||
	    current->scope_cookie != scope || current->scope_slot != account) {
		status = SE_POOL_CORRUPT;
	} else if (!(current->flags & SE_TASK_QUARANTINED)) {
		current->flags |= SE_TASK_QUARANTINED;
		if (current->eligibility_version < ~0ULL - 1)
			current->eligibility_version++;
	}
	if (status == SE_POOL_OK && current->exec.owned)
		se_exec_fault_locked(&current->exec);
	ended = se_pool_task_semantic_end(handle);
	return ended == SE_POOL_OK ? status : ended;
}
#endif
