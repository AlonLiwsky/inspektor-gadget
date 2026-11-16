/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_KERNEL_H
#define ENFORCE_EXEC_SHARED_KERNEL_H
#ifdef ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE
#error "legacy TASK/WORK maps cannot coexist with opaque owner"
#endif
#ifndef SE_PROFILE_TASKS
#error "shared task/scratch/catalogue capacities must be explicit"
#endif
static __always_inline __u64 se_shared_accepted_epoch(__u64 uid);
#define ER_ACCEPTED_EPOCH(uid) se_shared_accepted_epoch(uid)
#include "epoch_roles.h"
#include "shared_exec.h"
#include "shared_inherit_snapshot.h"
#include "shared_policy_prepare.h"
#include "shared_invocation_wire.h"
/* TASK pool declarations must precede the actual shared hooks so a selected
 * hook can own a lexical TASK handle rather than rediscovering se_tasks by
 * address. The work/reaper candidates remain after this header until their
 * selected callbacks are migrated. Ordinary shared images emit none of this. */
#ifdef ENFORCE_EXEC_POOL_DEVELOPMENT
#include "shared_pool_abi_candidate.h"
#include "shared_pool_task_core.h"
#ifdef ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE
#include "shared_pool_task_semantic_candidate.h"
#include "shared_pool_task_movement_candidate.h"
#include "shared_pool_exec_fault_candidate.h"
#endif
#endif
struct se_zero_task {
	unsigned char bytes[sizeof(struct se_task_state)];
};
struct se_zero_invocation {
	unsigned char bytes[sizeof(struct se_invocation)];
};
struct se_sequence {
	struct bpf_spin_lock lock;
	__u32 reserved;
	__u64 next;
};
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_PROFILE_TASKS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct se_task_state);
} se_tasks SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct se_zero_task);
} se_zero_tasks SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_PROFILE_SCRATCH);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u64);
	__type(value, struct se_invocation);
} se_invocations SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY_PROG);
	__type(key, __u32);
	__type(value, struct se_zero_invocation);
} se_zero_invocations SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_PROFILE_ACCEPTED_UIDS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, struct se_epoch_key);
	__type(value, __u64);
} se_accepted_epochs SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_sequence);
} se_task_sequences SEC(".maps");
static __always_inline struct se_invocation *se_current_invocation(void)
{
	__u64 key = (__u64)bpf_get_current_task_btf();
	return bpf_map_lookup_elem(&se_invocations, &key);
}
#ifdef ENFORCE_EXEC_SHARED_SCALAR_EVAL_CANDIDATE
/* Intermediate legacy-storage adapter: an explicit scalar token travels
 * through nested evaluator lookups, but the backing WORK is still found by
 * current-task address. This does NOT authenticate an opaque WORK ticket or
 * permit selection of an opaque image. The callback keeps its WORK alive. */
static inline struct se_policy_view *
se_shared_view_from_token(const struct fm_global_token *token)
{
	if (!token || token->reserved || !token->cookie ||
	    token->slot >= SE_PROFILE_BINDINGS)
		return 0;
	struct se_invocation *w = se_current_invocation();
	return w && w->slot == token->slot && w->cookie == token->cookie &&
			       w->scope && w->view.ready &&
			       w->view.scope_cookie == w->scope ?
		       &w->view :
		       0;
}
static inline const struct fm_blob *
se_shared_blob_from_token(unsigned int slot, unsigned long long cookie,
			  unsigned int key)
{
	struct fm_global_token token = { .slot = slot, .cookie = cookie };
	return se_policy_data(se_shared_view_from_token(&token), key);
}
#endif
static inline struct se_policy_view *full_shared_view(void)
{
	struct se_invocation *w = se_current_invocation();
	return w ? &w->view : 0;
}
static __always_inline __u64 se_shared_accepted_epoch(__u64 uid)
{
	struct se_invocation *w = se_current_invocation();
	if (!w || !w->scope)
		return ER_UNKNOWN;
#ifdef SE_CATALOGUE_FROM_BANK
	/* The hash cannot be updated under the route lock. The bank cell written
	 * in that lock is the catalogue; the index only finds it. */
	return se_catalogue_epoch(w->scope, uid);
#else
	struct se_epoch_key key = { w->scope, uid };
	const __u64 *epoch = bpf_map_lookup_elem(&se_accepted_epochs, &key);
	/* Catalogue is non-evicting and scope authority is retained. Missing means
  * never accepted, not an instruction to bootstrap a retained UID. */
	return epoch ? *epoch : 0;
#endif
}
#include "shared_policy_physical_kernel.h"
static __always_inline int se_task_reserve(__u32 slot, __u64 scope,
					   __u64 *cookie)
{
	__u32 zero = 0;
	struct se_sequence *sequence =
		bpf_map_lookup_elem(&se_task_sequences, &zero);
	struct se_route_anchor *route = bpf_map_lookup_elem(&se_routes, &slot);
	if (!sequence || !route || slot >= SE_PROFILE_BINDINGS)
		return -1;
	bpf_spin_lock(&sequence->lock);
	__u64 next = sequence->next;
	if (next < ~0ULL - 1)
		sequence->next = ++next;
	else
		next = 0;
	bpf_spin_unlock(&sequence->lock);
	if (!next)
		return -1;
	bpf_spin_lock(&route->lock);
	int invalid = route->scope != scope ||
		      route->tasks_used >= SE_PROFILE_TASK_QUOTA;
	if (!invalid)
		route->tasks_used++;
	bpf_spin_unlock(&route->lock);
	if (invalid)
		return -1;
	*cookie = next;
	return 0;
}
static __always_inline void se_task_refund(__u32 slot, __u64 scope,
					   __u64 cookie)
{
	/* Fixed ARRAY + owned charge pin this account through refund. No current
  * cgroup lookup, allocation, or recyclable HASH account is involved. */
	struct se_route_anchor *route = bpf_map_lookup_elem(&se_routes, &slot);
	if (!route)
		return;
	bpf_spin_lock(&route->lock);
	if (route->scope == scope && cookie && route->tasks_used)
		route->tasks_used--;
	else
		route->reserved =
			1; /* structural invariant, not ordinary capacity pressure */
	bpf_spin_unlock(&route->lock);
}
static __always_inline const void *se_task_zero(void)
{
	__u32 zero = 0;
	return bpf_map_lookup_elem(&se_zero_tasks, &zero);
}
#define SE_TASK_ZERO_TEMPLATE() se_task_zero()
#define SE_TASK_RESERVE(slot, scope, cookie) \
	se_task_reserve(slot, scope, cookie)
#define SE_TASK_REFUND(slot, scope, cookie) se_task_refund(slot, scope, cookie)
#include "shared_task_identity.h"
static __always_inline struct se_invocation *
se_work_acquire(__u64 address, struct se_route_anchor *route, __u32 slot,
		__u64 scope)
{
	__u32 zero = 0;
	const void *empty = bpf_map_lookup_elem(&se_zero_invocations, &zero);
	if (!empty)
		return 0;
	bpf_spin_lock(&route->lock);
	int invalid = route->scope != scope ||
		      route->scratch_used >= SE_PROFILE_SCRATCH_QUOTA;
	if (!invalid)
		route->scratch_used++;
	bpf_spin_unlock(&route->lock);
	if (invalid)
		return 0;
	if (bpf_map_update_elem(&se_invocations, &address, empty,
				BPF_NOEXIST)) {
		bpf_spin_lock(&route->lock);
		route->scratch_used--;
		bpf_spin_unlock(&route->lock);
		return 0;
	}
	struct se_invocation *w =
		bpf_map_lookup_elem(&se_invocations, &address);
	if (!w)
		return 0; /* private successful insert invariant: retain charge */
	w->scope = scope;
	w->slot = slot;
	return w;
}
static __always_inline void se_work_release(__u64 address,
					    struct se_route_anchor *route)
{
	if (bpf_map_delete_elem(&se_invocations, &address))
		return; /* retains charge */
	bpf_spin_lock(&route->lock);
	if (route->scratch_used)
		route->scratch_used--;
	else
		route->reserved = 1;
	bpf_spin_unlock(&route->lock);
}
static __always_inline int se_prepare_view(struct se_invocation *w,
					   const struct se_snapshot *snapshot,
					   __u64 generation)
{
	return se_prepare_policy_view(&w->view, w->scope, snapshot, generation);
}
static inline const __u64 *se_route_index_lookup(const __u64 *key)
{
	return bpf_map_lookup_elem(&se_route_index, key);
}
static inline struct se_route_anchor *se_route_anchor_lookup(const __u32 *key)
{
	return bpf_map_lookup_elem(&se_routes, key);
}
static __always_inline long se_shared_fault(__u32 mode, int prior)
{
	return prior ? fe_lsm_result(prior) : (mode == 2 ? -1 : 0);
}
static __always_inline void se_early_release(struct se_route_claim *claim)
{
	if (!claim->owned)
		return;
	struct se_route_anchor *route =
		bpf_map_lookup_elem(&se_routes, &claim->slot);
	if (!route)
		return;
	bpf_spin_lock(&route->lock);
	se_route_release_locked(route, claim);
	bpf_spin_unlock(&route->lock);
}
/* Legacy map wrapper; the semantic body also serves an exact opaque TASK
 * bracket once the selected hooks migrate. */
static __always_inline void se_owned_fault(struct se_task_state *task,
					   __u64 bprm)
{
	if (!task)
		return;
	bpf_spin_lock(&task->lock);
	se_exec_owned_fault_locked(task, bprm);
	bpf_spin_unlock(&task->lock);
}
/* The caller holds the exact TASK owner lock; a route observation alone never
 * grants authority to fault another physical generation. */
static __always_inline void
se_task_movement_fault_locked(struct se_task_state *task, __u64 cookie,
			      __u64 scope, __u32 slot)
{
	if (task->physical_cookie == cookie && task->scope_cookie == scope &&
	    task->scope_slot == slot) {
		if (!(task->flags & SE_TASK_QUARANTINED)) {
			task->flags |= SE_TASK_QUARANTINED;
			if (task->eligibility_version < ~0ULL - 1)
				task->eligibility_version++;
		}
		if (task->exec.owned)
			se_exec_fault_locked(&task->exec);
	}
}
/* Identity-only movement observation, not admission or policy authority.
 * A live task charge pins its original fixed route account. No transaction is
 * required to invalidate eligibility, and no current-route claim is borrowed. */
/* The route/identity check has its own frame so it cannot inflate the
 * already bounded bprm ingress frame. */
static __attribute__((noinline)) void
se_observe_task_movement(struct se_task_state *task, __u64 cgroup)
{
	if (!task)
		return;
	__u64 cookie, scope;
	__u32 slot;
	bpf_spin_lock(&task->lock);
	/* The snapshot is not authority after unlock; it only selects the
	 * original route to compare. The second lock rechecks the identity. */
	cookie = task->physical_cookie;
	scope = task->scope_cookie;
	slot = task->scope_slot;
	int live = (task->flags & SE_TASK_LIVE) && !task->identity_reserved;
	bpf_spin_unlock(&task->lock);
	if (!live || !cookie || !scope)
		return;
	struct se_route_anchor *original =
		bpf_map_lookup_elem(&se_routes, &slot);
	int moved = 1;
	if (original) {
		bpf_spin_lock(&original->lock);
		moved = original->scope != scope ||
			original->payload_slot != slot ||
			original->cgroup_identity != cgroup;
		bpf_spin_unlock(&original->lock);
	}
	if (!moved)
		return;
	bpf_spin_lock(&task->lock);
	se_task_movement_fault_locked(task, cookie, scope, slot);
	bpf_spin_unlock(&task->lock);
}
/* Policy evaluation consumes an already-owned TASK and WORK. The caller
 * retains and closes both lifetimes; this body must not rediscover either
 * owner by physical address. The legacy callback below still supplies its
 * existing maps. An opaque successor must supply exact lexical handles and
 * keep them through the final policy lookup; the current evaluator's global
 * blob/view resolver still reads se_invocations and must be rebound before
 * this body can be used by the replacement image. */
struct se_shared_eval_args {
	struct linux_binprm *bprm;
	struct se_task_state *task;
	struct se_invocation *work;
	const struct se_snapshot *snapshot;
	__u64 generation, cookie, sequence;
	__u32 mode;
	int prior, ingress_strict;
};
/* The caller retains TASK/WORK and the snapshot through this return; none of
 * these pointers escape. BPF subprograms accept at most five arguments. */
static __attribute__((noinline)) long
se_shared_evaluate_owned_work(const struct se_shared_eval_args *args)
{
	struct linux_binprm *bprm = args->bprm;
	struct se_task_state *task = args->task;
	struct se_invocation *w = args->work;
	const struct se_snapshot *snapshot = args->snapshot;
	__u64 generation = args->generation, cookie = args->cookie;
	__u64 sequence = args->sequence;
	__u32 mode = args->mode;
	int prior = args->prior, ingress_strict = args->ingress_strict;
	if (se_prepare_view(w, snapshot, generation)) {
		se_owned_fault(task, (__u64)bprm);
		return se_shared_fault(ingress_strict ? 2 : mode, 0);
	}
	w->cookie = cookie;
	w->sequence = sequence;
	struct observation *o = &w->observation;
	full_observe(bprm, o);
	bpf_spin_lock(&task->lock);
	se_exec_snapshot_locked(task, generation, &w->history);
	bpf_spin_unlock(&task->lock);
	int error = se_exec_fill_roles(&w->history, &o->facts);
	if (!error) {
#ifdef ENFORCE_EXEC_SHARED_SCALAR_EVAL_CANDIDATE
		struct fm_global_token token = {
			.slot = w->slot,
			.cookie = w->cookie,
		};
		error = fe_evaluate(&token, &o->facts, &o->evaluator);
#else
		error = fe_evaluate(0, &o->facts, &o->evaluator);
#endif
	}
	bpf_spin_lock(&task->lock);
	if (!task->exec.owned || task->exec.bprm != (__u64)bprm ||
	    task->exec.sequence != sequence ||
	    task->eligibility_version != w->history.eligibility_version)
		error = 1;
	if (error)
		se_exec_fault_locked(&task->exec);
	else
		error = se_exec_propose_locked(&task->exec,
					       &o->evaluator.decision);
	bpf_spin_unlock(&task->lock);
	long result =
		fe_lsm_verdict(mode, prior, error, &o->evaluator.decision);
	return ingress_strict ? -1 : result;
}
/* Actual bprm entry. Current-route admission precedes fallible task/scratch
 * lookups. An existing original-scope reader is recovered only as authority,
 * never by treating a copied current-cgroup tuple as an observation lease. */
static __always_inline long se_shared_check(struct linux_binprm *bprm,
					    int prior)
{
	__u64 address = (__u64)bpf_get_current_task_btf();
	if (prior) {
		struct se_task_state *task =
			bpf_map_lookup_elem(&se_tasks, &address);
		if (task) {
			se_observe_task_movement(task,
						 bpf_get_current_cgroup_id());
			bpf_spin_lock(&task->lock);
			se_exec_note_prior_deny_locked(task, (__u64)bprm);
			bpf_spin_unlock(&task->lock);
		}
		return fe_lsm_result(prior);
	}
	__u64 cgroup = bpf_get_current_cgroup_id();
	struct se_route_claim early = {};
	int admission = se_route_admit(cgroup, &early);
	int current_strict =
		admission == SE_ROUTE_STRICT_FAULT ||
		(admission == SE_ROUTE_OWNED && early.execution_class == 2);
	int ingress_strict = 0;
	struct se_task_state *task = bpf_map_lookup_elem(&se_tasks, &address);
	se_observe_task_movement(task, cgroup);
	/* Invalid locator/anchor invariants are not a validated current-scope
	 * class. Recovery of an Audit reader cannot make this admitted-map
	 * invariant violation safe; reject without inventing B authority. */
	if (admission == SE_ROUTE_INVARIANT_FAULT) {
		se_owned_fault(task, (__u64)bprm);
		return -1;
	}
	__u32 slot = early.slot, mode = early.execution_class,
	      record = early.record;
	__u64 scope = early.scope, generation = early.generation,
	      serial = early.serial, sequence = 0, cookie = 0;
	int continuing = 0;
	__u64 original_generation = 0;
	__u32 original_class = 0;
	if (task) {
		bpf_spin_lock(&task->lock);
		if ((task->flags & SE_TASK_LIVE) && !task->identity_reserved &&
		    task->exec.owned && task->exec.bprm == (__u64)bprm) {
			continuing = 1;
			slot = task->scope_slot;
			scope = task->scope_cookie;
			sequence = task->exec.sequence;
			cookie = task->physical_cookie;
			original_generation = task->exec.generation;
			original_class = task->exec.execution_class;
		}
		bpf_spin_unlock(&task->lock);
	}
	struct se_route_anchor *route = 0;
	if (continuing) {
		route = bpf_map_lookup_elem(&se_routes, &slot);
		struct se_shared_binding *reader_binding =
			bpf_map_lookup_elem(&se_bindings, &slot);
		if (!route || !reader_binding) {
			se_early_release(&early);
			return -1;
		}
		bpf_spin_lock(&route->lock);
		int moved = route->cgroup_identity != cgroup;
		int owned = se_exec_reader_authority_locked(
			route, &reader_binding->state, task, slot, scope,
			original_generation, cookie, sequence, original_class);
		if (owned) {
			mode = route->execution_class;
			generation = route->payload_generation;
			serial = route->active_serial;
			record = route->active_record;
		}
		bpf_spin_unlock(&route->lock);
		se_early_release(&early);
		if (!owned)
			return -1; /* retained-reader structural invariant */
		if (moved) {
			ingress_strict = current_strict;
			bpf_spin_lock(&task->lock);
			if (!(task->flags & SE_TASK_QUARANTINED)) {
				task->flags |= SE_TASK_QUARANTINED;
				if (task->eligibility_version < ~0ULL - 1)
					task->eligibility_version++;
			}
			se_exec_fault_locked(&task->exec);
			bpf_spin_unlock(&task->lock);
		}
	} else {
		/* Selected Audit admission failed before a transaction could
		 * record causal writers. Do not export old qualified history
		 * after the unobserved execution. UNSELECTED withdrawal is not
		 * this fault and preserves same-scope eligibility. */
		if (admission == SE_ROUTE_AUDIT_FAULT)
			se_owned_fault(task, (__u64)bprm);
		if (admission != SE_ROUTE_OWNED)
			return (admission == SE_ROUTE_STRICT_FAULT ||
				admission == SE_ROUTE_INVARIANT_FAULT) ?
				       -1 :
				       0;
		route = bpf_map_lookup_elem(&se_routes, &slot);
		if (!route || !task) {
			se_early_release(&early);
			return se_shared_fault(ingress_strict ? 2 : mode, 0);
		}
	}
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &slot);
	if (!binding || record >= 2) {
		se_owned_fault(task, (__u64)bprm);
		se_early_release(&early);
		return se_shared_fault(ingress_strict ? 2 : mode, 0);
	}
	const struct se_snapshot *snapshot = &binding->state.records[record];
	int error = snapshot->scope != scope || snapshot->serial != serial ||
		    snapshot->generation != generation ||
		    snapshot->phase != SE_SNAPSHOT_ACTIVE ||
		    !se_snapshot_metadata_valid(&snapshot->metadata,
						snapshot->count, generation);
	if (!error && !continuing) {
		bpf_spin_lock(&task->lock);
		cookie = task->physical_cookie;
		error = se_exec_begin_snapshot_locked(task, cookie, (__u64)bprm,
						      snapshot);
		sequence = task->exec.sequence;
		bpf_spin_unlock(&task->lock);
		if (!error) {
			bpf_spin_lock(&route->lock);
			error = se_exec_reader_attach_locked(route,
							     &binding->state,
							     task, &early,
							     cookie, sequence);
			bpf_spin_unlock(&route->lock);
			if (error) {
				bpf_spin_lock(&task->lock);
				se_exec_abort_locked(task, cookie, (__u64)bprm,
						     sequence);
				task->flags |= SE_TASK_QUARANTINED;
				bpf_spin_unlock(&task->lock);
			}
		}
	}
	se_early_release(&early);
	if (error) {
		se_owned_fault(task, (__u64)bprm);
		return se_shared_fault(ingress_strict ? 2 : mode, 0);
	}
	/* Persistent descriptor/possible writers exist before scratch can fail. */
	struct se_invocation *w = se_work_acquire(address, route, slot, scope);
	if (!w) {
		se_owned_fault(task, (__u64)bprm);
		return se_shared_fault(ingress_strict ? 2 : mode, 0);
	}
	struct se_shared_eval_args args = {
		.bprm = bprm,
		.task = task,
		.work = w,
		.snapshot = snapshot,
		.generation = generation,
		.cookie = cookie,
		.sequence = sequence,
		.mode = mode,
		.prior = prior,
		.ingress_strict = ingress_strict,
	};
	long result = se_shared_evaluate_owned_work(&args);
	se_work_release(address, route);
	return result;
}
static __always_inline int se_shared_finish(struct task_struct *physical,
					    struct linux_binprm *bprm,
					    int success)
{
	__u64 address = (__u64)physical;
	struct se_task_state *task = bpf_map_lookup_elem(&se_tasks, &address);
	if (!task)
		return 0;
	__u64 sequence = 0, cookie = 0, scope = 0, generation = 0;
	__u32 slot = 0;
	bpf_spin_lock(&task->lock);
	if (task->exec.owned && task->exec.bprm == (__u64)bprm) {
		sequence = task->exec.sequence;
		cookie = task->physical_cookie;
		scope = task->scope_cookie;
		slot = task->scope_slot;
		generation = task->exec.generation;
	}
	bpf_spin_unlock(&task->lock);
	if (!sequence)
		return 0;
	struct se_route_anchor *route = bpf_map_lookup_elem(&se_routes, &slot);
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &slot);
	if (!route || !binding)
		return 0;
	struct se_invocation *w = se_work_acquire(address, route, slot, scope);
	int completed = 0;
	if (w) {
		bpf_spin_lock(&task->lock);
		se_exec_snapshot_locked(task, generation, &w->history);
		bpf_spin_unlock(&task->lock);
		if (!se_exec_completion_prepare(&w->history, success)) {
			bpf_spin_lock(&task->lock);
			completed = !se_exec_complete_locked(task, &w->history,
							     generation);
			bpf_spin_unlock(&task->lock);
		}
		se_work_release(address, route);
	}
	if (!completed) {
		bpf_spin_lock(&task->lock);
		completed = se_exec_finish_bounded_locked(task, cookie,
							  (__u64)bprm, sequence,
							  success) >= 0;
		bpf_spin_unlock(&task->lock);
	}
	if (completed) {
		bpf_spin_lock(&route->lock);
		se_exec_reader_release_locked(&binding->state, task, cookie,
					      sequence);
		bpf_spin_unlock(&route->lock);
	}
	return 0;
}
SEC("tp_btf/sched_process_exec")
int BPF_PROG(se_sched_exec, struct task_struct *task, int old_pid,
	     struct linux_binprm *bprm)
{
	(void)old_pid;
	return se_shared_finish(task, bprm, 1);
}
SEC("fexit/bprm_execve")
int BPF_PROG(se_bprm_exit, struct linux_binprm *bprm, int ret)
{
	(void)ret;
	return se_shared_finish(bpf_get_current_task_btf(), bprm, 0);
}
/* task_alloc child is unpublished and cannot escape this callback. Parent is
 * the live current task. Early scope ownership excludes catalogue publication;
 * no map helper or child lock is taken in final parent-locked validation/store. */
static __always_inline int se_inherit_child(__u64 parent_address,
					    __u64 child_address,
					    struct se_route_claim *claim,
					    unsigned long clone_flags)
{
	if (clone_flags & (1ULL << 33))
		return -1; /* target-cgroup ingress not qualified */
	struct se_task_state *parent =
		bpf_map_lookup_elem(&se_tasks, &parent_address);
	struct se_task_state *child =
		bpf_map_lookup_elem(&se_tasks, &child_address);
	struct se_route_anchor *route =
		bpf_map_lookup_elem(&se_routes, &claim->slot);
	struct se_shared_binding *binding =
		bpf_map_lookup_elem(&se_bindings, &claim->slot);
	__u32 record = claim->record;
	if (!parent || !child || !route || !binding || record >= 2)
		return -1;
	struct se_invocation *w = se_work_acquire(parent_address, route,
						  claim->slot, claim->scope);
	if (!w)
		return -1;
	bpf_spin_lock(&parent->lock);
	se_exec_snapshot_locked(parent, claim->generation, &w->history);
	bpf_spin_unlock(&parent->lock);
	int invalid = w->history.scope_cookie != claim->scope ||
		      w->history.flags != SE_TASK_QUALIFIED ||
		      er_canonical_classify(&w->history.view) ||
		      er_canonical_project(&w->history.view, &w->inherited);
	const struct se_snapshot *snapshot = &binding->state.records[record];
	if (!invalid &&
	    !se_inherit_snapshot_matches(claim, snapshot, &w->inherited))
		invalid = 1;
	if (!invalid) {
		bpf_spin_lock(&parent->lock);
		invalid = se_inherit_child_commit_locked(
			parent, child, claim, &w->history, &w->inherited);
		bpf_spin_unlock(&parent->lock);
	}
	se_work_release(parent_address, route);
	return invalid ? -1 : 0;
}
SEC("lsm/task_alloc")
int BPF_PROG(se_task_alloc, struct task_struct *child,
	     unsigned long clone_flags, int ret)
{
	if (ret)
		return ret;
#ifdef ENFORCE_EXEC_SHARED_RECOVERY
	int recovery_ret = se_rm_capture(child, clone_flags, ret);
	if (recovery_ret)
		return recovery_ret;
#endif
	struct se_route_claim claim = {};
	int admitted = se_route_admit(bpf_get_current_cgroup_id(), &claim);
	if (admitted != SE_ROUTE_OWNED)
		return (admitted == SE_ROUTE_STRICT_FAULT ||
			admitted == SE_ROUTE_INVARIANT_FAULT) ?
			       -1 :
			       0;
	int error = se_task_birth((__u64)child, claim.slot, claim.scope);
	if (!error)
		error = se_inherit_child((__u64)bpf_get_current_task_btf(),
					 (__u64)child, &claim, clone_flags);
	__u32 mode = claim.execution_class;
	se_early_release(&claim);
	return error && mode == 2 ? -1 : 0;
}
SEC("lsm/task_free")
int BPF_PROG(se_task_free, struct task_struct *physical)
{
	/* No dereference/acquire of this untrusted dying task argument. */
#ifdef ENFORCE_EXEC_SHARED_RECOVERY
	se_rm_close(physical);
#endif
	__u64 address = (__u64)physical;
	struct se_task_state *task = bpf_map_lookup_elem(&se_tasks, &address);
	if (task) {
		__u64 sequence = 0, cookie = 0, bprm = 0;
		__u32 slot = 0;
		bpf_spin_lock(&task->lock);
		sequence = task->exec.sequence;
		cookie = task->physical_cookie;
		bprm = task->exec.bprm;
		slot = task->scope_slot;
		if (task->exec.owned)
			se_exec_abort_locked(task, cookie, bprm, sequence);
		bpf_spin_unlock(&task->lock);
		struct se_route_anchor *route =
			bpf_map_lookup_elem(&se_routes, &slot);
		struct se_shared_binding *binding =
			bpf_map_lookup_elem(&se_bindings, &slot);
		if (route && binding) {
			bpf_spin_lock(&route->lock);
			if (task->reader.owned)
				se_exec_reader_release_locked(&binding->state,
							      task, cookie,
							      sequence);
			bpf_spin_unlock(&route->lock);
		}
	}
	se_task_death(address);
	return 0;
}
#endif
