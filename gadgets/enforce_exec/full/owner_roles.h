/* SPDX-License-Identifier: GPL-2.0 */
#ifndef FULL_OWNER_ROLES_H
#define FULL_OWNER_ROLES_H
/* Persistent-owner role lifecycle. Include evaluator.h then owner_types.h.
 * No native activation/Ready claim: authoritative catalogue, gate ownership,
 * immutable map publication and physical inventory remain owner contracts. */
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
/* EO_TASK_STAGE_BEGIN */
/* The qualified candidate writer holds its dispatch ownership until this final
 * store. Caller holds only task.lock here; catalogue/merge validation completed
 * outside the lock. This helper cannot select an active descriptor or certify. */
static __always_inline int eo_stage_task_locked(struct eo_task *task,
						const struct eo_work *work,
						__u64 cookie, __u64 attempt,
						__u32 reserved, __u64 authority,
						__u32 required_known)
{
	const struct eo_stage_stamp *stamp = &work->stage_request;
	if (!cookie || task->cookie != cookie || reserved ||
	    work->source_descriptor.history_reserved || !attempt ||
	    attempt == ER_UNKNOWN ||
	    attempt <= work->source_descriptor.generation || !authority ||
	    authority == ER_UNKNOWN || authority != work->authority ||
	    !work->reader.owned || work->reader.kind != EO_READER_CANDIDATE ||
	    work->reader.descriptor.generation != attempt ||
	    stamp->attempt != attempt || !stamp->pass_id ||
	    stamp->pass_id == ER_UNKNOWN || !stamp->pass_start_serial ||
	    stamp->pass_start_serial == ER_UNKNOWN ||
	    stamp->task_cookie != cookie ||
	    stamp->fact_version != task->committed.version ||
	    stamp->prior_generation != work->source_descriptor.generation ||
	    stamp->reserved || stamp->required_known_mask != required_known ||
	    stamp->eligibility_flags != task->flags ||
	    task->flags != work->source_flags || !(task->flags & EO_VERIFIED) ||
	    (task->flags & (EO_QUARANTINED | EO_PENDING_BIRTH)) ||
	    !work->candidate.count || work->candidate.count > 8 ||
	    required_known >> work->candidate.count)
		return -1;
	__u32 newmask = 0;
	for (__u32 i = 0; i < 8; i++) {
		if (i >= work->candidate.count)
			break;
		const struct er_authority *policy = &work->candidate.active[i];
		int found = 0;
		if (policy->new_uid)
			newmask |= 1U << i;
		for (int row = 0; row < ER_SLOTS; row++) {
			const struct er_row *value = &work->view.work.rows[row];
			if (value->uid == policy->uid &&
			    value->epoch == policy->epoch &&
			    (!(required_known & (1U << i)) ||
			     er_role_known(value)))
				found++;
		}
		if (found != 1)
			return -1;
	}
	if (stamp->staged_new_uid_mask != newmask)
		return -1;
	int duplicate = task->staged.attempt == attempt &&
			task->staged.pass_id == stamp->pass_id;
	if (er_canonical_stage_publish(&task->committed, &work->view,
				       authority))
		return -1;
	task->staged = *stamp;
	return duplicate ?
		       1 :
		       0; /* Duplicate restaging does not add inventory credit. */
}
/* EO_TASK_STAGE_END */
#endif
static __always_inline __u64 *eo_gate(__u32 slot)
{
	if (slot >= 65536)
		return 0;
	return bpf_map_lookup_elem(&eo_gates, &slot);
}
static __always_inline int eo_load_candidate(struct eo_work *w, __u32 slot,
					     __u32 newmask)
{
	struct eo_health *h = eo_status();
	struct eo_phase *phase = eo_phase_state();
	if (!phase || phase->state == EO_PUBLISHING ||
	    phase->state == EO_STOPPED)
		return -1;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	const struct fe_header *head = (const void *)eo_current_blob(0);
#else
	const struct fe_header *head = (const void *)eo_blob(slot, 0);
#endif
	if (!h || !h->authority_version || h->retired || !head ||
	    !head->generation || head->generation == ER_UNKNOWN ||
	    !head->policies || head->policies > ER_ACTIVE ||
	    head->rule_base != 9 || head->rules > 256 ||
	    newmask >> head->policies)
		return -1;
	w->authority = h->authority_version;
	w->a_epoch = head->generation;
	w->candidate.count = head->policies;
	w->candidate.reserved = 0;
	for (int i = 0; i < ER_ACTIVE; i++) {
		w->candidate.active[i] = (struct er_authority){};
		if ((__u32)i >= head->policies)
			continue;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
		const struct fe_policy *p =
			(const void *)eo_current_blob(1 + i);
#else
		const struct fe_policy *p = (const void *)eo_blob(slot, 1 + i);
#endif
		if (!p || !p->uid || !p->root_role || !p->root_epoch ||
		    p->root_epoch == ER_UNKNOWN ||
		    p->root_epoch > head->generation)
			return -1;
		__u64 accepted = eo_accepted_epoch(p->uid);
		if (accepted == ER_UNKNOWN)
			return -1;
		__u32 fresh = 0;
		if (accepted) {
			if (accepted != p->root_epoch)
				return -1;
		} else {
			if (!(newmask & (1U << i)))
				return -1;
			fresh = 1;
		}
		w->candidate.active[i] =
			(struct er_authority){ p->uid, p->root_epoch,
					       p->root_role, fresh, 0 };
	}
	return er_candidate_valid(&w->candidate) ||
			       h->authority_version != w->authority ?
		       -1 :
		       0;
}
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
/* A separately verified pure predicate keeps physical-inventory iterations
 * from multiplying the eight-by-sixteen role-state branch space. */
__noinline int eo_rows_present(struct eo_work *w)
{
	if (!w || w->candidate.count > ER_ACTIVE)
		return -1;
	for (int i = 0; i < ER_ACTIVE; i++) {
		if ((__u32)i >= w->candidate.count)
			break;
		struct er_authority *a = &w->candidate.active[i];
		int found = 0;
		// Fixed offsets avoid LLVM's split-search induction escaping its bound in
		// the pinned verifier. Duplicate matches still refuse, never truncate.
#ifdef __BPF__
#pragma clang loop unroll(full)
#endif
		for (int j = 0; j < ER_SLOTS; j++) {
			struct er_row *r = &w->merge.rows[j];
			if (r->uid == a->uid && r->epoch == a->epoch &&
			    r->role) {
				if (found)
					return -1;
				found = 1;
			}
		}
		if (!found)
			return -1;
	}
	return 0;
}
#endif
/* A separately verified pure predicate keeps physical-inventory iterations
 * from multiplying the eight-by-sixteen role-state branch space. */
__noinline int eo_rows_complete(struct eo_work *w)
{
	if (!w || w->candidate.count > ER_ACTIVE)
		return -1;
	for (int i = 0; i < ER_ACTIVE; i++) {
		if ((__u32)i >= w->candidate.count)
			break;
		struct er_authority *a = &w->candidate.active[i];
		int found = 0;
		// Fixed offsets avoid LLVM's split-search induction escaping its bound in
		// the pinned verifier. Duplicate matches still refuse, never truncate.
#ifdef __BPF__
#pragma clang loop unroll(full)
#endif
		for (int j = 0; j < ER_SLOTS; j++) {
			struct er_row *r = &w->merge.rows[j];
			if (r->uid == a->uid && r->epoch == a->epoch &&
			    r->role && er_role_known(r)) {
				if (found)
					return -1;
				found = 1;
			}
		}
		if (!found)
			return -1;
	}
	return 0;
}
static __noinline int
eo_validate_task_impl(struct eo_task *s, struct eo_work *w, int require_known)
{
	struct eo_health *h = eo_status();
	if (!h || h->authority_version != w->authority)
		return -1;
	__u32 flags;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	struct eo_config *config = eo_config();
	if (!config)
		return -1;
	int admin = w->busy && w == eo_borrow_work() && w->reader.owned == 1 &&
		    w->reader.session_cookie == config->cookie &&
		    (w->reader.kind == EO_READER_CANDIDATE ||
		     w->reader.kind == EO_READER_AUTHORITY) &&
		    eo_current_admin(config->cookie);
#endif
	bpf_spin_lock(&s->lock);
	flags = s->flags;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	int owned = admin ||
		    (s->exec.owned && s->exec.reader.owned == 1 &&
		     s->exec.reader.kind == EO_READER_EXEC &&
		     s->exec.reader.session_cookie == config->cookie &&
		     s->exec.reader.descriptor.generation == w->a_epoch);
	if (!owned) {
		bpf_spin_unlock(&s->lock);
		return -1;
	}
	w->source_flags = flags;
	w->source_descriptor = admin ? w->reader.descriptor :
				       s->exec.reader.descriptor;
	er_snapshot(&w->view.work, &s->committed, w->authority);
#else
	er_snapshot(&w->merge, &s->committed, w->authority);
#endif
	bpf_spin_unlock(&s->lock);
	if (!(flags & EO_VERIFIED) || (flags & EO_QUARANTINED))
		return -1;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	if (er_canonical_classify(&w->view) ||
	    er_canonical_project(&w->view, &w->merge) ||
	    er_candidate_valid(&w->candidate))
		return -1;
#else
	if (er_prepare(&w->merge, &w->candidate))
		return -1;
#endif
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	if (require_known ? eo_rows_complete(w) : eo_rows_present(w))
		return -1;
#else
	(void)require_known;
	if (eo_rows_complete(w))
		return -1;
#endif
	return h->authority_version == w->authority ? 0 : -1;
}
static __noinline int eo_stage_task_impl(struct task_struct *task,
					 struct eo_task *s, struct eo_work *w,
					 __u32 newmask)
{
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	(void)task;
	(void)s;
	(void)w;
	(void)newmask;
	return -1;
#else
	struct eo_config *c = eo_config();
	struct eo_health *h = eo_status();
	if (!c || !h || h->authority_version != w->authority)
		return -1;
	__u64 *gate = eo_gate(c->gate_slot);
	if (!gate || fg_read(gate) != FG_CLOSED)
		return -1;
	for (int i = 0; i < ER_ACTIVE; i++)
		if ((__u32)i < w->candidate.count &&
		    w->candidate.active[i].new_uid && !(newmask & (1U << i)))
			return -1;
	if (!eo_lineage(task, s))
		return -1;
	bpf_spin_lock(&s->lock);
	er_snapshot(&w->merge, &s->committed, w->authority);
	bpf_spin_unlock(&s->lock);
	if (er_stage_roots(&w->merge, &w->candidate, 1) || eo_rows_complete(w))
		return -1;
	int result = -1;
	bpf_spin_lock(&s->lock);
	if (!(s->flags & EO_QUARANTINED) &&
	    h->authority_version == w->authority)
		result = er_publish(&s->committed, &w->merge, w->authority);
	bpf_spin_unlock(&s->lock);
	return result ? -1 : 0;
#endif
}
static __always_inline int eo_validate_task(struct eo_task *s,
					    struct eo_work *w)
{
	return eo_validate_task_impl(s, w, 1);
}
/* Exec may observe retained UNKNOWN; readiness still requires eo_validate_task. */
static __always_inline int eo_validate_exec_task(struct eo_task *s,
						 struct eo_work *w)
{
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	return eo_validate_task_impl(s, w, 0);
#else
	return eo_validate_task(s, w);
#endif
}
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
/* EO_TASK_STAGE_WRAPPER_BEGIN */
static __always_inline int eo_stage_work_valid(struct eo_work *work)
{
	struct eo_dispatch *dispatch = eo_dispatch_state();
	struct eo_config *config = eo_config();
	if (!dispatch || !config || !work->busy || work != eo_borrow_work() ||
	    !eo_current_admin(config->cookie) ||
	    work->reader.session_cookie != config->cookie)
		return -1;
	bpf_spin_lock(&dispatch->lock);
	int invalid =
		!eo_candidate_owned(dispatch, config->cookie,
				    work->reader.descriptor.generation) ||
		dispatch->candidate.state != EO_CANDIDATE_STAGING ||
		dispatch->candidate.writers != 1 ||
		work->reader.sequence != dispatch->candidate.write_sequence ||
		!work->reader.owned ||
		work->reader.kind != EO_READER_CANDIDATE ||
		work->reader.descriptor.program_bank !=
			dispatch->candidate.program_bank ||
		work->stage_request.pass_id != dispatch->candidate.pass_id ||
		work->stage_request.pass_start_serial !=
			dispatch->candidate.pass_start_serial ||
		dispatch->candidate.receipt_serial != dispatch->serial ||
		!eo_dispatch_same(&work->source_descriptor, &dispatch->active);
	bpf_spin_unlock(&dispatch->lock);
	return invalid ? -1 : 0;
}

static __always_inline int eo_stage_candidate_task(struct task_struct *task,
						   struct eo_task *state,
						   struct eo_work *work,
						   __u32 required_known)
{
	(void)task; /* Qualification is READ ONLY; staging may never adopt lineage. */
	struct eo_health *health = eo_status();
	if (eo_stage_work_valid(work) || !health ||
	    !health->authority_version || health->retired ||
	    !work->reader.owned || work->reader.kind != EO_READER_CANDIDATE ||
	    work->source_descriptor.history_reserved ||
	    work->reader.descriptor.history_reserved)
		return -1;
	bpf_spin_lock(&state->lock);
	work->source_flags = state->flags;
	work->stage_request.task_cookie = state->cookie;
	work->stage_request.fact_version = state->committed.version;
	work->stage_request.eligibility_flags = state->flags;
	er_snapshot(&work->view.work, &state->committed, work->authority);
	bpf_spin_unlock(&state->lock);
	if (!(work->source_flags & EO_VERIFIED) ||
	    (work->source_flags & (EO_QUARANTINED | EO_PENDING_BIRTH)) ||
	    er_canonical_stage_prepare(&work->view, &work->candidate, 1))
		return -1;
	work->stage_request.attempt = work->reader.descriptor.generation;
	work->stage_request.prior_generation =
		work->source_descriptor.generation;
	work->stage_request.required_known_mask = required_known;
	work->stage_request.staged_new_uid_mask = 0;
	for (int i = 0; i < ER_ACTIVE; i++)
		if ((__u32)i < work->candidate.count &&
		    work->candidate.active[i].new_uid)
			work->stage_request.staged_new_uid_mask |= 1U << i;
	__u64 authority = health->authority_version;
	if (eo_stage_work_valid(work))
		return -1;
	bpf_spin_lock(&state->lock);
	int result = eo_stage_task_locked(state, work,
					  work->stage_request.task_cookie,
					  work->reader.descriptor.generation, 0,
					  authority, required_known);
	bpf_spin_unlock(&state->lock);
	if (result == 0) {
		struct eo_dispatch *dispatch = eo_dispatch_state();
		if (!dispatch)
			return -1;
		bpf_spin_lock(&dispatch->lock);
		if (dispatch->candidate.pass_id !=
			    work->stage_request.pass_id ||
		    dispatch->candidate.attempt !=
			    work->stage_request.attempt ||
		    dispatch->candidate.receipt_serial != dispatch->serial ||
		    dispatch->candidate.writers != 1 ||
		    dispatch->candidate.write_sequence !=
			    work->reader.sequence ||
		    dispatch->candidate.inventory_count >= 4096)
			result = -1;
		else
			dispatch->candidate.inventory_count++;
		bpf_spin_unlock(&dispatch->lock);
	}
	return result;
}
/* EO_TASK_STAGE_WRAPPER_END */
#endif
static __always_inline int eo_stage_task(struct task_struct *task,
					 struct eo_task *s, struct eo_work *w,
					 __u32 newmask)
{
	return eo_stage_task_impl(task, s, w, newmask);
}
static __always_inline void eo_clear_pending(struct eo_exec_tx *tx)
{
	for (int i = 0; i < ER_ACTIVE; i++)
		tx->pending[i] = (struct er_row){};
}
static __always_inline void eo_exec_suppress(void)
{
	struct eo_task *s = eo_lookup_task(bpf_get_current_task_btf());
	if (!s)
		return;
	bpf_spin_lock(&s->lock);
	if (s->exec.owned) {
		s->exec.suppress = 1;
		eo_clear_pending(&s->exec);
	}
	bpf_spin_unlock(&s->lock);
}
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
static __always_inline __u32 eo_exec_class(void)
{
	struct eo_task *s = eo_lookup_task(bpf_get_current_task_btf());
	if (!s)
		return 2;
	__u32 execution_class;
	bpf_spin_lock(&s->lock);
	execution_class = s->exec.owned ? s->exec.execution_class : 2;
	bpf_spin_unlock(&s->lock);
	return execution_class == 1 ? 1 : 2;
}
/* Shared observation failure cannot certify a missed role transition. Only
 * possible authored role writers are affected; unchanged UID histories survive. */
/* EO_EXEC_OBSERVATION_FAULT_BEGIN */
static __always_inline void eo_exec_observation_fault(__u64 generation,
						      __u64 bit)
{
	eo_data_fault(generation, bit);
	struct eo_dispatch *dispatch = eo_dispatch_state();
	if (dispatch) {
		bpf_spin_lock(&dispatch->lock);
		dispatch->coverage_unknown = 1;
		bpf_spin_unlock(&dispatch->lock);
	}
	struct eo_task *s = eo_lookup_task(bpf_get_current_task_btf());
	if (!s)
		return;
	bpf_spin_lock(&s->lock);
	if (s->exec.owned && s->exec.generation == generation) {
		const struct eo_dispatch_descriptor *descriptor =
			&s->exec.reader.descriptor;
		// This sealed mask survives an unreadable header, scratch or observer.
		__u32 writes = descriptor->role_writer_mask;
		if (!descriptor->policy_count || descriptor->policy_count > 8 ||
		    descriptor->policy_count != s->exec.policy_count ||
		    (writes >> descriptor->policy_count))
			writes =
				0xffU; /* Broken admitted descriptor is an integrity failure. */
		s->exec.role_write_mask |= writes;
		s->exec.role_uncertain_mask |= writes;
		s->exec.suppress = 1;
		eo_clear_pending(&s->exec);
	}
	bpf_spin_unlock(&s->lock);
}
/* EO_EXEC_OBSERVATION_FAULT_END */

#endif
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
/* EO_EXEC_ADMISSION_BEGIN */
static __always_inline void
eo_release_exec_reader(struct eo_reader_claim *local)
{
	if (!local->owned)
		return;
	struct eo_dispatch *dispatch = eo_dispatch_state();
	if (!dispatch)
		return; /* Impossible for admitted program-retained ARRAY0. */
	bpf_spin_lock(&dispatch->lock);
	if (eo_dispatch_claim_end_locked(dispatch, local))
		dispatch->integrity_fault |= 1;
	bpf_spin_unlock(&dispatch->lock);
}
static __always_inline int eo_exec_begin_development(struct linux_binprm *bprm,
						     __u64 *generation,
						     __u32 *execution_class)
{
	*generation = 0;
	*execution_class =
		2; /* Unclassified lifetime-invariant failure, not audit evidence. */
	struct eo_config *c = eo_config();
	if (!c || !c->cookie || c->abi != EO_ABI)
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	struct eo_task *s = 0;
	if (bpf_get_current_cgroup_id() != c->cgroup) {
		s = eo_lookup_task(task);
		if (!s)
			return 0;
		__u32 owned;
		bpf_spin_lock(&s->lock);
		owned = s->exec.owned && s->exec.owner_cookie == c->cookie;
		bpf_spin_unlock(&s->lock);
		if (!owned)
			return 0;
	}
	struct eo_dispatch *dispatch = eo_dispatch_state();
	if (!dispatch)
		return -1;
	struct eo_reader_claim local = {};
	bpf_spin_lock(&dispatch->lock);
	if (dispatch->scope_state == EO_SCOPE_UNINITIALIZED) {
		bpf_spin_unlock(&dispatch->lock);
		return 0; // Explicit preactivation state, never advertised as protected.
	}
	if (dispatch->scope_state == EO_SCOPE_INACTIVE) {
		int matching = dispatch->session_cookie == c->cookie &&
			       dispatch->cgroup == c->cgroup;
		bpf_spin_unlock(&dispatch->lock);
		return matching ? 0 : -1;
	}
	int refused = dispatch->session_cookie != c->cookie ||
		      dispatch->cgroup != c->cgroup ||
		      eo_dispatch_claim_begin_locked(dispatch, &local, 1,
						     EO_READER_EXEC);
	if (local.descriptor.execution_class)
		*execution_class = local.descriptor.execution_class;
	bpf_spin_unlock(&dispatch->lock);
	*generation = local.descriptor.generation;
	if (refused) {
		if (*generation)
			eo_exec_observation_fault(*generation, 2);
		return -1;
	}
	if (!s)
		s = eo_lookup_task(task);
	if (!s)
		s = eo_get_task(task);
	if (!s)
		goto observer_fault;
	__u32 policies = local.descriptor.policy_count;
	int invalid = 0;
	bpf_spin_lock(&s->lock);
	if (s->exec.owned) {
		if (s->exec.bprm != (__u64)bprm ||
		    s->exec.owner_cookie != c->cookie ||
		    s->exec.reader.owned != 1 ||
		    !eo_dispatch_same(&s->exec.reader.descriptor,
				      &local.descriptor) ||
		    s->exec.policy_count != policies || s->exec.checks >= 64)
			invalid = 1;
		else
			s->exec.checks++;
	} else if (!s->cookie || s->invocation_sequence >= ~0ULL - 1)
		invalid = 1;
	else {
		__builtin_memset(&s->exec, 0, sizeof(s->exec));
		s->invocation_sequence++;
		local.sequence = s->invocation_sequence;
		s->exec.reader = local;
		local.owned =
			0; /* Counter ownership transferred; no release/reacquire gap. */
		s->exec.bprm = (__u64)bprm;
		s->exec.cgroup = c->cgroup;
		s->exec.owner_cookie = c->cookie;
		s->exec.generation = *generation;
		s->exec.execution_class = *execution_class;
		s->exec.policy_count = policies;
		s->exec.slot = c->gate_slot;
		s->exec.owned = 1;
		s->exec.checks = 1;
	}
	bpf_spin_unlock(&s->lock);
	eo_release_exec_reader(&local);
	if (invalid) {
		eo_exec_observation_fault(*generation, 2);
		return -1;
	}
	struct eo_health *h = eo_status();
	const struct fe_header *header = (const void *)eo_program_blob(
		local.descriptor.program_bank, 0, *generation);
	if (!h || h->retired || h->faults || !header ||
	    header->generation != *generation || header->policies != policies)
		goto observer_fault;
	struct eo_work *w = eo_get_work();
	if (!w) {
		eo_exec_observation_fault(*generation, 2);
		return -1;
	}
	invalid = eo_load_candidate(w, 0, 0) || w->a_epoch != *generation ||
		  eo_validate_exec_task(s, w);
	eo_put_work(w);
	if (invalid) {
		eo_exec_observation_fault(*generation, 2);
		return -1;
	}
	return 1;
observer_fault:
	eo_exec_observation_fault(*generation, 2);
	bpf_spin_lock(&dispatch->lock);
	dispatch->coverage_unknown = 1;
	bpf_spin_unlock(&dispatch->lock);
	eo_release_exec_reader(&local);
	return -1;
}
/* EO_EXEC_ADMISSION_END */
#endif
#ifndef ENFORCE_EXEC_ABI3_DEVELOPMENT
static __always_inline int eo_exec_begin(struct linux_binprm *bprm,
					 __u64 *generation)
{
	*generation = 0;
	struct eo_config *c = eo_config();
	struct eo_health *h = eo_status();
	if (!c || !h || !c->cookie || c->abi != EO_ABI || h->retired)
		return 0;
	struct task_struct *task = bpf_get_current_task_btf();
	struct eo_task *s = eo_lookup_task(task);
	__u32 owned = 0;
	if (s) {
		bpf_spin_lock(&s->lock);
		owned = s->exec.owned;
		*generation = s->exec.generation;
		bpf_spin_unlock(&s->lock);
	}
	if (!owned && bpf_get_current_cgroup_id() != c->cgroup)
		return 0;
	if (h->faults) {
		eo_exec_suppress();
		return -1;
	}
	if (!owned) {
		__u64 *gate = eo_gate(c->gate_slot);
		if (!gate)
			return -1;
		if (fg_enter(gate)) {
			__sync_fetch_and_add(&h->gate_denials, 1);
			return -1;
		}
		s = eo_get_task(task);
		if (!s) {
			eo_fault(EO_FAULT_STORAGE);
			fg_leave_owned(gate, 1, &h->faults);
			return -1;
		}
		const struct fe_header *head = (const void *)eo_blob(0, 0);
		__u64 gen = head ? head->generation : 0;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
		__u32 policies = 0, role_writers = 0;
		int execution_class =
			fe_execution_class(0, gen, &policies, &role_writers);
		if (execution_class < 1) {
			fg_leave_owned(gate, 1, &h->faults);
			eo_fault(EO_FAULT_STATE);
			return -1;
		}
#endif
		int collision = 0;
		bpf_spin_lock(&s->lock);
		if (s->exec.owned)
			collision = 1;
		else {
			s->exec.bprm = (__u64)bprm;
			s->exec.cgroup = c->cgroup;
			s->exec.generation = gen;
			s->exec.owner_cookie = c->cookie;
			s->exec.slot = c->gate_slot;
			s->exec.owned = 1;
			s->exec.checks = 0;
			s->exec.suppress = 0;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
			s->exec.execution_class = execution_class;
			s->exec.policy_count = policies;
			s->exec.role_uncertain_mask = s->exec.role_write_mask =
				0;
			s->exec.global_deny_unknown = s->exec.known_deny_seen =
				0;
#endif
			eo_clear_pending(&s->exec);
		}
		bpf_spin_unlock(&s->lock);
		if (collision) {
			eo_fault(EO_FAULT_STATE);
			fg_leave_owned(gate, 1, &h->faults);
			return -1;
		}
		*generation = gen;
	}
	int invalid = 0;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	__u32 policies = 0, role_writers = 0;
	int execution_class =
		fe_execution_class(0, *generation, &policies, &role_writers);
#endif
	bpf_spin_lock(&s->lock);
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	if (execution_class < 1 ||
	    s->exec.execution_class != (__u32)execution_class ||
	    s->exec.policy_count != policies)
		invalid = 1;
#endif
	if (s->exec.bprm != (__u64)bprm || s->exec.owner_cookie != c->cookie ||
	    s->exec.cgroup != c->cgroup || s->exec.slot != c->gate_slot ||
	    !s->exec.generation || s->exec.generation == ER_UNKNOWN ||
	    s->exec.checks >= 64)
		invalid = 1;
	else
		s->exec.checks++;
	bpf_spin_unlock(&s->lock);
	struct eo_work *w = eo_get_work();
	if (!w)
		invalid = 1;
	else {
		if (eo_load_candidate(w, 0, 0) || w->a_epoch != *generation ||
		    eo_validate_exec_task(s, w))
			invalid = 1;
		eo_put_work(w);
	}
	if (invalid) {
		eo_exec_suppress();
		eo_quarantine(s);
		return -1;
	}
	return 1;
}
#endif
static __always_inline int eo_fill_roles(struct fe_facts *f)
{
	f->role_count = 0;
	for (int i = 0; i < ER_ACTIVE; i++)
		f->roles[i] = (struct fe_role){};
	struct eo_task *s = eo_lookup_task(bpf_get_current_task_btf());
	if (!s)
		return -1;
	struct eo_work *w = eo_get_work();
	if (!w)
		return -1;
	__u64 generation;
	__u32 owned;
	bpf_spin_lock(&s->lock);
	generation = s->exec.generation;
	owned = s->exec.owned;
	bpf_spin_unlock(&s->lock);
	int result = -1;
	if (!owned || eo_load_candidate(w, 0, 0) || w->a_epoch != generation ||
	    eo_validate_exec_task(s, w))
		goto out;
	for (int i = 0; i < ER_ACTIVE; i++) {
		if ((__u32)i >= w->candidate.count)
			break;
		struct er_authority *a = &w->candidate.active[i];
		for (int j = 0; j < ER_SLOTS; j++)
			if (w->merge.rows[j].uid == a->uid &&
			    w->merge.rows[j].epoch == a->epoch &&
			    er_role_known(&w->merge.rows[j])) {
				__u32 index = f->role_count;
				if (index >= ER_ACTIVE)
					goto out;
				f->roles[index].policy_uid = a->uid;
				f->roles[index].role = w->merge.rows[j].role;
				f->role_count++;
			}
	}
	result = 0;
out:
	eo_put_work(w);
	return result;
}
static __always_inline int eo_exec_propose(struct linux_binprm *bprm,
					   const struct fe_decision *d)
{
	struct eo_task *s = eo_lookup_task(bpf_get_current_task_btf());
	if (!s)
		return -1;
	struct eo_config *c = eo_config();
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	const struct fe_header *head = (const void *)eo_current_blob(0);
#else
	const struct fe_header *head = (const void *)eo_blob(0, 0);
#endif
	__u64 generation;
	int invalid;
	bpf_spin_lock(&s->lock);
	generation = s->exec.generation;
	invalid = !c || !head || !s->exec.owned ||
		  s->exec.bprm != (__u64)bprm ||
		  s->exec.owner_cookie != c->cookie ||
		  s->exec.cgroup != c->cgroup || s->exec.slot != c->gate_slot ||
		  !generation || generation == ER_UNKNOWN ||
		  generation != head->generation;
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	invalid = invalid || !head || !head->policies ||
		  head->policies > ER_ACTIVE ||
		  s->exec.policy_count != head->policies ||
		  (d->audit_unknown & ~FE_UNCERTAINTY_VALID_MASK);
	if ((d->audit_unknown & FE_AUDIT_UNCERTAIN_FALLBACK) &&
	    (d->deny != 1 || d->mode != 1 ||
	     !(d->audit_unknown & FE_AUDIT_GLOBAL_SUPPRESS)))
		invalid = 1;
#endif
	bpf_spin_unlock(&s->lock);
	if (invalid) {
		eo_exec_suppress();
		eo_quarantine(s);
		eo_fault(EO_FAULT_STATE);
		return -1;
	}
	/* Observation failures and authored transition conflicts poison this attempt,
  * not previously trusted lineage/committed roles. A repaired generation can
  * therefore recover without re-rooting or clearing accepted task state. */
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
	int known_deny = d->deny &&
			 !(d->audit_unknown & FE_AUDIT_UNCERTAIN_FALLBACK);
	if (known_deny) {
		bpf_spin_lock(&s->lock);
		s->exec.known_deny_seen = 1;
		bpf_spin_unlock(&s->lock);
	}
	if (known_deny || (d->error && d->error != FE_AUDIT_UNKNOWN)) {
#else
	if (d->deny || d->error) {
#endif
		eo_exec_suppress();
		if (d->error
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
		    && d->error != FE_AUDIT_UNKNOWN
#endif
		) {
			eo_data_fault(generation,
				      1ULL << (d->error <= FE_ROLE_CONFLICT ?
						       d->error :
						       FE_INVALID));
			return -1;
		}
		return 0;
	}
	struct eo_work *w = eo_get_work();
	if (!w) {
		eo_exec_suppress();
		return -1;
	}
	invalid = eo_load_candidate(w, 0, 0);
	int conflict = 0;
	if (!invalid)
		invalid = eo_validate_exec_task(s, w);
	if (!invalid) {
		bpf_spin_lock(&s->lock);
		if (!s->exec.owned || s->exec.bprm != (__u64)bprm ||
		    s->exec.generation != w->a_epoch ||
		    s->committed.version != w->merge.base_version)
			invalid = 1;
		else {
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
			__u32 writes = FE_ROLE_WRITES(d->audit_unknown);
			for (int i = 0; i < ER_ACTIVE; i++)
				if (d->proposed_roles[i])
					writes |= 1U << i;
			__u32 uncertain = FE_ROLE_UNCERTAIN(d->audit_unknown);
			if ((writes | uncertain | (d->audit_unknown & 0xffU)) >>
			    s->exec.policy_count)
				invalid = 1;
			s->exec.role_write_mask |= writes;
			s->exec.enforced_write_mask |= d->enforced_writes;
			s->exec.role_conflict_mask |= d->role_conflicts;
			if ((d->enforced_writes | d->role_conflicts) >>
			    s->exec.policy_count)
				invalid = 1;
			if (s->exec.enforced_write_mask &
			    s->exec.role_conflict_mask)
				conflict = 1;
			s->exec.role_uncertain_mask |= uncertain;
			if (d->audit_unknown & FE_AUDIT_GLOBAL_SUPPRESS) {
				s->exec.global_deny_unknown = 1;
				s->exec.suppress = 1;
			}
			if (s->exec.global_deny_unknown)
				s->exec.role_uncertain_mask |=
					s->exec.role_write_mask;
			for (int i = 0; i < ER_ACTIVE; i++) {
				if (s->exec.role_uncertain_mask & (1U << i)) {
					if (s->exec.pending[i].uid)
						s->exec.pending[i].knowledge =
							ER_ROLE_UNKNOWN;
				} else if (s->exec.suppress) {
					s->exec.pending[i] = (struct er_row){};
				}
			}
#endif
			for (int i = 0; i < ER_ACTIVE; i++) {
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
				if (s->exec.known_deny_seen)
					continue;
				__u64 role =
					d->known_role_witnesses[i] ?
						d->known_role_witnesses[i] :
						d->proposed_roles[i];
#else
				if (s->exec.suppress)
					continue;
				__u64 role = d->proposed_roles[i];
#endif
				if (!role)
					continue;
				if ((__u32)i >= w->candidate.count) {
					invalid = 1;
					continue;
				}
				struct er_authority *a =
					&w->candidate.active[i];
				struct er_row *p = &s->exec.pending[i];
				if (p->uid && (p->uid != a->uid ||
					       p->epoch != a->epoch)) {
					invalid = 1;
					continue;
				}
				if (p->uid && p->role != role) {
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
					s->exec.role_conflict_mask |= 1U << i;
					s->exec.role_uncertain_mask |= 1U << i;
					p->knowledge = ER_ROLE_UNKNOWN;
					if (s->exec.enforced_write_mask &
					    (1U << i))
						conflict = 1;
#else
					conflict = 1;
#endif
					continue;
				}
				if (!p->uid)
					*p = er_known_row(a->uid, a->epoch,
							  role);
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
				if (s->exec.suppress ||
				    (s->exec.role_uncertain_mask & (1U << i)))
					p->knowledge = ER_ROLE_UNKNOWN;
#endif
			}
		}
		if (invalid || conflict) {
			s->exec.suppress = 1;
			eo_clear_pending(&s->exec);
		}
		bpf_spin_unlock(&s->lock);
	}
	eo_put_work(w);
	if (invalid) {
		eo_exec_suppress();
		eo_quarantine(s);
		eo_fault(EO_FAULT_STATE);
		return -1;
	}
	if (conflict) {
		eo_data_fault(generation, 1ULL << FE_ROLE_CONFLICT);
		return -1;
	}
	return 0;
}
/* Completion always clears owned state before the final shared count release.
 * Fexit is mandatory: kernel_execve failure does not guarantee sys_exit. */
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
struct eo_completion_merge {
	struct eo_work *work;
	__u32 policy_count, uncertain, suppress, invalid, changed;
};
/* Typed memory and scalar return let the verifier prove this bounded merge
 * once, independently of callback context and the caller's pending paths. */
__noinline int eo_completion_merge_policy(struct eo_work *w, __u32 i,
					  __u32 uncertain, __u32 suppress)
{
	if (!w || i >= ER_ACTIVE || w->candidate.count > ER_ACTIVE ||
	    i >= w->candidate.count)
		return -1;
	const struct er_authority *a = &w->candidate.active[i];
	const struct er_row *pending = &w->source.rows[i];
	int unknown = !!(uncertain & (1U << i));
	if (!unknown && (suppress || !pending->uid))
		return 0;
	if (!unknown && (pending->uid != a->uid || pending->epoch != a->epoch ||
			 !pending->role || !er_role_known(pending))) {
		return -1;
	}
	int found = 0;
	for (int j = 0; j < ER_SLOTS; j++) {
		struct er_row *row = &w->merge.rows[j];
		if (row->uid != a->uid || row->epoch != a->epoch)
			continue;
		found++;
		if (unknown)
			row->knowledge = ER_ROLE_UNKNOWN;
		else {
			row->role = pending->role;
			row->knowledge = ER_ROLE_KNOWN;
		}
	}
	return found == 1 ? 1 : -1;
}
static long eo_completion_policy_step(__u32 i, void *opaque)
{
	struct eo_completion_merge *context = opaque;
	if (i >= ER_ACTIVE || i >= context->policy_count) {
		context->invalid = 1;
		return 1;
	}
	int result = eo_completion_merge_policy(
		context->work, i, context->uncertain, context->suppress);
	if (result < 0)
		context->invalid = 1;
	else if (result)
		context->changed = 1;
	return 0;
}
static __always_inline int eo_prepare_fact_patch(struct eo_work *w)
{
	w->patch.prepared = w->patch.count = 0;
	w->patch.base_version = w->view.work.base_version;
	w->patch.authority_version = w->view.work.authority_version;
	if (w->view.work.error || !w->view.work.prepared || w->merge.error)
		return -1;
	for (int i = 0; i < ER_SLOTS; i++) {
		const struct er_row *before = &w->view.work.rows[i],
				    *after = &w->merge.rows[i];
		if (!(w->view.accepted_mask & (1U << i))) {
			if (after->uid)
				return -1;
			continue;
		}
		if (before->uid != after->uid || before->epoch != after->epoch)
			return -1;
		if (before->role == after->role &&
		    before->knowledge == after->knowledge)
			continue;
		if (w->patch.count >= ER_ACTIVE)
			return -1;
		w->patch.changes[w->patch.count++] = (struct er_fact_change){
			.before = *before, .after = *after, .index = (__u32)i
		};
	}
	w->patch.prepared = 1;
	return 0;
}
static __always_inline int
eo_finish_exec(struct task_struct *task, struct linux_binprm *bprm, int success)
{
	struct eo_task *s = eo_lookup_task(task);
	struct eo_health *h = eo_status();
	struct eo_config *c = eo_config();
	if (!s || !h || !c)
		return 0;
	/* Snapshot the explicit scalar prefix; pending rows use owned work storage,
     * rather than placing a complete 384-byte transaction on the BPF stack. */
	struct {
		__u64 bprm, cgroup, generation, owner_cookie;
		__u32 owned, slot, suppress, checks;
		__u32 execution_class, role_uncertain_mask, role_write_mask;
		__u32 global_deny_unknown, known_deny_seen, policy_count;
		__u32 enforced_write_mask, role_conflict_mask;
	} tx = {};
	_Static_assert(sizeof(tx) ==
			       __builtin_offsetof(struct eo_exec_tx, pending),
		       "exec snapshot prefix");
	struct eo_reader_claim reader = {};
	__u64 reader_sequence, task_cookie;
	bpf_spin_lock(&s->lock);
	reader_sequence = s->exec.reader.sequence;
	task_cookie = s->cookie;
	__builtin_memcpy(&tx, &s->exec, sizeof(tx));
	bpf_spin_unlock(&s->lock);
	if (!tx.owned)
		return 0;
	if ((bprm && tx.bprm != (__u64)bprm) || tx.owner_cookie != c->cookie ||
	    tx.cgroup != c->cgroup || tx.slot != c->gate_slot) {
		eo_quarantine(s);
		return 0;
	}
	int invalid = 0, changed = 0;
	struct eo_work *w = 0;
	/* A known semantic deny cancels changes deterministically, even when audit
     * let exec succeed. Failure also preserves the entire committed vector. */
	if (success && !tx.known_deny_seen) {
		w = eo_get_work();
		if (!w)
			invalid = 1;
		else {
			if (eo_load_candidate(w, 0, 0) ||
			    w->a_epoch != tx.generation ||
			    w->candidate.count != tx.policy_count ||
			    eo_validate_exec_task(s, w))
				invalid = 1;
			if (!invalid) {
				bpf_spin_lock(&s->lock);
				if (__builtin_memcmp(&tx, &s->exec, sizeof(tx)))
					invalid = 1;
				for (int i = 0; i < ER_ACTIVE; i++)
					w->source.rows[i] = s->exec.pending[i];
				bpf_spin_unlock(&s->lock);
				__u32 uncertain = tx.role_uncertain_mask |
						  (tx.global_deny_unknown ?
							   tx.role_write_mask :
							   0);
				if ((uncertain | tx.role_write_mask) >>
				    tx.policy_count)
					invalid = 1;
				struct eo_completion_merge merge = {
					.work = w,
					.policy_count = tx.policy_count,
					.uncertain = uncertain,
					.suppress = tx.suppress
				};
				if (tx.policy_count > ER_ACTIVE ||
				    FE_LOOP(tx.policy_count,
					    eo_completion_policy_step,
					    &merge) != tx.policy_count ||
				    merge.invalid)
					invalid = 1;
				changed = merge.changed;
				if (!invalid && changed &&
				    eo_prepare_fact_patch(w))
					invalid = 1;
			}
		}
	}
	__u32 claimed = 0;
	bpf_spin_lock(&s->lock);
	if (s->exec.owned && s->exec.bprm == tx.bprm &&
	    s->exec.owner_cookie == tx.owner_cookie &&
	    s->exec.generation == tx.generation) {
		if (__builtin_memcmp(&tx, &s->exec, sizeof(tx)))
			invalid = 1;
		if (s->exec.reader.owned != 1 ||
		    s->exec.reader.sequence != reader_sequence ||
		    s->cookie != task_cookie)
			invalid = 1;
		if (w && !invalid) {
			for (int i = 0; i < ER_ACTIVE; i++)
				if (__builtin_memcmp(&s->exec.pending[i],
						     &w->source.rows[i],
						     sizeof(struct er_row)))
					invalid = 1;
		}
		if (success && !tx.known_deny_seen && changed && !invalid &&
		    w) {
			if (s->flags != w->source_flags ||
			    (s->flags & EO_QUARANTINED) ||
			    !eo_dispatch_same(&s->exec.reader.descriptor,
					      &w->source_descriptor) ||
			    h->authority_version != w->authority ||
			    er_canonical_patch_publish(&s->committed, &w->patch,
						       w->authority))
				invalid = 1;
		}
		eo_clear_pending(&s->exec);
		s->exec.owned = s->exec.suppress = s->exec.checks = 0;
		s->exec.bprm = 0;
		s->exec.execution_class = s->exec.policy_count = 0;
		s->exec.role_uncertain_mask = s->exec.role_write_mask = 0;
		s->exec.global_deny_unknown = s->exec.known_deny_seen = 0;
		s->exec.enforced_write_mask = s->exec.role_conflict_mask = 0;
		if (eo_reader_take_locked(&s->exec.reader, s->cookie,
					  task_cookie, reader_sequence,
					  &reader))
			invalid = 1;
		else
			claimed = 1;
	}
	bpf_spin_unlock(&s->lock);
	if (w)
		eo_put_work(w);
	if (invalid) {
		eo_quarantine(s);
		eo_fault(EO_FAULT_STATE);
	}
	if (claimed)
		eo_release_exec_reader(&reader);
	return 0;
}
#else
static __always_inline int
eo_finish_exec(struct task_struct *task, struct linux_binprm *bprm, int success)
{
	struct eo_task *s = eo_lookup_task(task);
	struct eo_health *h = eo_status();
	struct eo_config *c = eo_config();
	if (!s || !h || !c)
		return 0;
	__u32 owned, slot, suppress;
	__u64 identity, owner, generation, original;
	bpf_spin_lock(&s->lock);
	owned = s->exec.owned;
	slot = s->exec.slot;
	identity = s->exec.bprm;
	owner = s->exec.owner_cookie;
	generation = s->exec.generation;
	suppress = s->exec.suppress;
	original = s->exec.cgroup;
	bpf_spin_unlock(&s->lock);
	if (!owned)
		return 0;
	if ((bprm && identity != (__u64)bprm) || owner != c->cookie ||
	    original != c->cgroup || slot != c->gate_slot) {
		eo_quarantine(s);
		return 0;
	}
	__u64 *gate = eo_gate(slot);
	if (!gate) {
		eo_fault(EO_FAULT_GATE);
		return 0;
	}
	int invalid = 0;
	struct eo_work *w = 0;
	if (success && !suppress) {
		w = eo_get_work();
		if (!w)
			invalid = 1;
		else {
			if (eo_load_candidate(w, 0, 0) ||
			    w->a_epoch != generation ||
			    eo_validate_exec_task(s, w))
				invalid = 1;
			if (!invalid) {
				bpf_spin_lock(&s->lock);
				for (int i = 0; i < ER_ACTIVE; i++)
					w->source.rows[i] = s->exec.pending[i];
				bpf_spin_unlock(&s->lock);
				for (int i = 0; i < ER_ACTIVE; i++) {
					struct er_row *p = &w->source.rows[i];
					if (!p->uid)
						continue;
					int found = 0;
					for (int j = 0; j < ER_SLOTS; j++)
						if (w->merge.rows[j].uid ==
							    p->uid &&
						    w->merge.rows[j].epoch ==
							    p->epoch) {
							w->merge.rows[j].role =
								p->role;
							found++;
						}
					if (found != 1 || !p->role)
						invalid = 1;
				}
			}
		}
	}
	__u32 claimed = 0;
	bpf_spin_lock(&s->lock);
	if (s->exec.owned && s->exec.bprm == identity &&
	    s->exec.owner_cookie == owner) {
		if (success && !s->exec.suppress && !invalid && w) {
			if ((s->flags & EO_QUARANTINED) ||
			    h->authority_version != w->authority ||
			    er_publish(&s->committed, &w->merge, w->authority))
				invalid = 1;
		}
		eo_clear_pending(&s->exec);
		s->exec.bprm = 0;
		s->exec.owned = 0;
		s->exec.suppress = 0;
		s->exec.checks = 0;
		claimed = 1;
	}
	bpf_spin_unlock(&s->lock);
	if (w)
		eo_put_work(w);
	if (invalid) {
		eo_quarantine(s);
		eo_fault(EO_FAULT_STATE);
	}
	fg_leave_owned(gate, claimed, &h->faults);
	return 0;
}
#endif
static __always_inline __u64 eo_task_cgroup(struct task_struct *task)
{
	__u64 id = 0;
	if (BPF_CORE_READ_INTO(&id, task, cgroups, dfl_cgrp, kn, id))
		return 0;
	return id;
}
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
/* EO_CANONICAL_FORK_BEGIN */
/* Read only from the fork's retained physical policy bank. The authority claim
 * excludes catalogue/descriptor publication until inheritance or failure.
 * Missing/UNKNOWN active facts are distinct from structural corruption: audit
 * may inherit the factual projection, while strict must refuse the fork. */
static __always_inline int
eo_fork_active_known(const struct eo_work *work,
		     const struct eo_dispatch_descriptor *descriptor)
{
	if (!descriptor->generation || descriptor->history_reserved ||
	    descriptor->reserved || descriptor->program_bank > 1 ||
	    !descriptor->policy_count || descriptor->policy_count > ER_ACTIVE)
		return -1;
	const struct fe_header *head = (const void *)eo_program_blob(
		descriptor->program_bank, 0, descriptor->generation);
	if (!head || head->generation != descriptor->generation ||
	    head->policies != descriptor->policy_count)
		return -1;
	int missing = 0;
	for (__u32 i = 0; i < ER_ACTIVE; i++) {
		if (i >= descriptor->policy_count)
			break;
		const struct fe_policy *policy = (const void *)eo_program_blob(
			descriptor->program_bank, 1 + i,
			descriptor->generation);
		if (!policy || !policy->uid || !policy->root_epoch ||
		    policy->root_epoch == ER_UNKNOWN ||
		    eo_accepted_epoch(policy->uid) != policy->root_epoch)
			return -1;
		int found = 0;
		for (int j = 0; j < ER_SLOTS; j++) {
			const struct er_row *row = &work->view.work.rows[j];
			if ((work->view.accepted_mask & (1U << j)) &&
			    row->uid == policy->uid &&
			    row->epoch == policy->root_epoch &&
			    er_role_known(row))
				found++;
		}
		if (found != 1)
			missing = 1;
	}
	return missing;
}

static __always_inline int
eo_initialize_child_locked(struct eo_task *child, const struct eo_work *work,
			   __u64 cookie)
{
	if (!cookie || child->cookie != cookie || child->flags ||
	    child->invocation_sequence || child->exec.owned ||
	    child->fork.owned || child->staged.attempt ||
	    child->staged.pass_id || child->committed.version ||
	    !work->merge.prepared || work->merge.error)
		return -1;
	for (int i = 0; i < ER_SLOTS; i++) {
		const struct er_row *row = &child->committed.rows[i];
		if (row->uid || row->epoch || row->role || row->knowledge ||
		    row->reserved)
			return -1;
	}
	for (int i = 0; i < ER_SLOTS; i++)
		child->committed.rows[i] = work->merge.rows[i];
	child->committed.version = 1;
	child->flags = EO_VERIFIED;
	return 0;
}
static __always_inline int
eo_release_fork(struct eo_task *parent, struct task_struct *child, int failed)
{
	struct eo_config *config = eo_config();
	if (!parent || !config)
		return 0;
	struct eo_reader_claim local = {};
	int invalid = 0;
	bpf_spin_lock(&parent->lock);
	if (parent->fork.owned) {
		if (parent->fork.owner_cookie != config->cookie ||
		    parent->fork.cgroup != config->cgroup ||
		    (!failed && parent->fork.child != (__u64)child) ||
		    parent->fork.reader.kind != EO_READER_FORK ||
		    eo_reader_take_locked(&parent->fork.reader, parent->cookie,
					  parent->cookie,
					  parent->fork.reader.sequence, &local))
			invalid = 1;
		else {
			parent->fork.owned = 0;
			parent->fork.child = 0;
		}
	}
	bpf_spin_unlock(&parent->lock);
	if (invalid)
		eo_quarantine(parent);
	if (local.owned)
		eo_release_exec_reader(&local);
	return 0;
}
static __always_inline int eo_fork_begin(struct task_struct *child,
					 __u64 clone_flags, int ret)
{
	if (ret)
		return ret;
	struct eo_config *config = eo_config();
	if (!config || config->abi != EO_ABI || !config->cookie ||
	    bpf_get_current_cgroup_id() != config->cgroup)
		return 0;
	struct eo_dispatch *dispatch = eo_dispatch_state();
	if (!dispatch)
		return -1;
	struct eo_reader_claim claim = {};
	bpf_spin_lock(&dispatch->lock);
	if (dispatch->scope_state == EO_SCOPE_UNINITIALIZED ||
	    dispatch->scope_state == EO_SCOPE_INACTIVE) {
		bpf_spin_unlock(&dispatch->lock);
		return 0;
	}
	int invalid = eo_dispatch_claim_begin_locked(dispatch, &claim, 1,
						     EO_READER_FORK);
	bpf_spin_unlock(&dispatch->lock);
	__u32 execution_class = claim.descriptor.execution_class;
	if (invalid)
		return execution_class == 1 ? 0 : -1;
	struct eo_task *parent = eo_get_task(bpf_get_current_task_btf());
	if (!parent) {
		eo_release_exec_reader(&claim);
		return execution_class == 1 ? 0 : -1;
	}
	bpf_spin_lock(&parent->lock);
	invalid = parent->fork.owned ||
		  parent->invocation_sequence >= ER_UNKNOWN - 1;
	if (!invalid) {
		claim.sequence = ++parent->invocation_sequence;
		parent->fork =
			(struct eo_fork_tx){ .child = (__u64)child,
					     .cgroup = config->cgroup,
					     .owner_cookie = config->cookie,
					     .owned = 1,
					     .slot = config->gate_slot,
					     .reader = claim };
		claim.owned = 0;
	}
	bpf_spin_unlock(&parent->lock);
	if (claim.owned)
		eo_release_exec_reader(&claim);
	if (invalid)
		return execution_class == 1 ? 0 : -1;
	if (clone_flags & (1ULL << 33)) {
		eo_quarantine(parent);
		return execution_class == 1 ? 0 : -1;
	}
	struct eo_work *work = eo_get_work();
	struct eo_health *health = eo_status();
	invalid = !work || !health || health->faults || health->retired;
	if (!invalid) {
		work->authority = health->authority_version;
		bpf_spin_lock(&parent->lock);
		invalid =
			!(parent->flags & EO_VERIFIED) ||
			(parent->flags & (EO_QUARANTINED | EO_PENDING_BIRTH)) ||
			!parent->fork.owned || !parent->fork.reader.owned;
		er_snapshot(&work->view.work, &parent->committed,
			    work->authority);
		bpf_spin_unlock(&parent->lock);
		if (!invalid)
			invalid = er_canonical_classify(&work->view);
		if (!invalid) {
			int knowledge =
				eo_fork_active_known(work, &claim.descriptor);
			invalid = knowledge < 0 ||
				  (execution_class == 2 && knowledge != 0);
		}
	}
	if (work)
		eo_put_work(work);
	if (invalid) {
		eo_quarantine(parent);
		return execution_class == 1 ? 0 : -1;
	}
	return 0;
}
static __always_inline int eo_fork_complete(struct task_struct *child,
					    __u64 clone_flags)
{
	struct eo_config *config = eo_config();
	struct eo_health *health = eo_status();
	if (!config || !health || !config->cookie || config->abi != EO_ABI)
		return 0;
	struct task_struct *physical_parent = bpf_get_current_task_btf();
	struct eo_task *parent = eo_lookup_task(physical_parent);
	struct eo_reader_claim reader = {};
	__u64 expected_child = 0, parent_cookie = 0;
	if (parent) {
		bpf_spin_lock(&parent->lock);
		if (parent->fork.owned) {
			reader = parent->fork.reader;
			expected_child = parent->fork.child;
			parent_cookie = parent->cookie;
		}
		bpf_spin_unlock(&parent->lock);
	}
	if (!reader.owned && eo_task_cgroup(child) != config->cgroup &&
	    bpf_get_current_cgroup_id() != config->cgroup)
		return 0;
	struct eo_reader_claim mutation = {};
	if (!reader.owned && eo_mutation_begin(&mutation))
		return 0;
	struct eo_task *state = eo_get_task(child);
	if (!state) {
		eo_fault(EO_FAULT_STORAGE);
		goto done;
	}
	if (!reader.owned) {
		/* Only explicit preactivation observation may record an unqualified birth. */
		if (mutation.descriptor.generation ||
		    clone_flags & (1ULL << 33) ||
		    eo_task_cgroup(child) != config->cgroup ||
		    bpf_get_current_cgroup_id() != config->cgroup) {
			eo_quarantine(state);
			goto done;
		}
		__u64 creator = eo_group(physical_parent);
		if (!creator ||
		    bpf_map_update_elem(&eo_birth_groups, &state->cookie,
					&creator, BPF_NOEXIST)) {
			eo_quarantine(state);
			goto done;
		}
		bpf_spin_lock(&state->lock);
		if (!state->flags && !state->committed.version) {
			state->flags = EO_PENDING_BIRTH;
			state->committed.version = 1;
		}
		bpf_spin_unlock(&state->lock);
		goto done;
	}
	if (!parent || expected_child != (__u64)child ||
	    reader.kind != EO_READER_FORK ||
	    reader.session_cookie != config->cookie ||
	    clone_flags & (1ULL << 33) ||
	    eo_task_cgroup(child) != config->cgroup ||
	    bpf_get_current_cgroup_id() != config->cgroup) {
		eo_quarantine(state);
		goto done;
	}
	struct eo_work *work = eo_get_work();
	if (!work) {
		eo_quarantine(state);
		goto done;
	}
	work->authority = health->authority_version;
	bpf_spin_lock(&parent->lock);
	int invalid = parent->cookie != parent_cookie || !parent->fork.owned ||
		      parent->fork.child != expected_child ||
		      !parent->fork.reader.owned ||
		      parent->fork.reader.sequence != reader.sequence ||
		      !(parent->flags & EO_VERIFIED) ||
		      (parent->flags & (EO_QUARANTINED | EO_PENDING_BIRTH));
	work->source_flags = parent->flags;
	er_snapshot(&work->view.work, &parent->committed, work->authority);
	bpf_spin_unlock(&parent->lock);
	if (!invalid)
		invalid = er_canonical_classify(&work->view) ||
			  er_canonical_project(&work->view, &work->merge);
	if (!invalid) {
		int knowledge = eo_fork_active_known(work, &reader.descriptor);
		invalid = knowledge < 0 ||
			  (reader.descriptor.execution_class == 2 &&
			   knowledge != 0);
	}
	/* This final parent-locked check is the inheritance linearization point.
  * A later mutation is ordered after this accepted snapshot; child publication
  * needs only its own lock, never a nested parent/child lock pair. */
	if (!invalid) {
		bpf_spin_lock(&parent->lock);
		invalid =
			parent->cookie != parent_cookie ||
			parent->committed.version !=
				work->view.work.base_version ||
			parent->flags != work->source_flags ||
			!(parent->flags & EO_VERIFIED) ||
			(parent->flags & (EO_QUARANTINED | EO_PENDING_BIRTH)) ||
			!parent->fork.owned ||
			parent->fork.child != expected_child ||
			!parent->fork.reader.owned ||
			parent->fork.reader.sequence != reader.sequence ||
			!eo_dispatch_same(&parent->fork.reader.descriptor,
					  &reader.descriptor);
		bpf_spin_unlock(&parent->lock);
	}
	if (!invalid) {
		bpf_spin_lock(&state->lock);
		invalid =
			health->authority_version != work->authority ||
			eo_initialize_child_locked(state, work, state->cookie);
		bpf_spin_unlock(&state->lock);
	}
	eo_put_work(work);
	if (invalid)
		eo_quarantine(state);
done:
	if (mutation.owned)
		eo_mutation_end(&mutation);
	return eo_release_fork(parent, child, 0);
}
/* EO_CANONICAL_FORK_END */
SEC("lsm.s/task_alloc")
int BPF_PROG(eo_task_alloc, struct task_struct *child, __u64 clone_flags,
	     int ret)
{
	return eo_fork_begin(child, clone_flags, ret);
}
SEC("tp_btf/task_newtask")
int BPF_PROG(eo_task_newtask, struct task_struct *child, __u64 clone_flags)
{
	return eo_fork_complete(child, clone_flags);
}
#else
/* No lookup/write follows a counted fork's final release. The owner identity
 * and gate slot are the original admission's, never the completion's cgroup. */
static __always_inline int
eo_release_fork(struct eo_task *p, struct task_struct *child, int failed)
{
	struct eo_config *c = eo_config();
	struct eo_health *h = eo_status();
	if (!c || !h || !p)
		return 0;
	__u32 slot, owned;
	__u64 owner, identity, original;
	bpf_spin_lock(&p->lock);
	slot = p->fork.slot;
	owned = p->fork.owned;
	owner = p->fork.owner_cookie;
	identity = p->fork.child;
	original = p->fork.cgroup;
	bpf_spin_unlock(&p->lock);
	if (!owned)
		return 0;
	if (owner != c->cookie || original != c->cgroup ||
	    slot != c->gate_slot || (!failed && identity != (__u64)child)) {
		eo_quarantine(p);
		return 0;
	}
	__u64 *gate = eo_gate(slot);
	if (!gate) {
		eo_fault(EO_FAULT_GATE);
		return 0;
	}
	__u32 claimed = 0;
	bpf_spin_lock(&p->lock);
	if (p->fork.owned && p->fork.owner_cookie == owner &&
	    p->fork.child == identity) {
		p->fork.owned = 0;
		p->fork.child = 0;
		claimed = 1;
	}
	bpf_spin_unlock(&p->lock);
	fg_leave_owned(gate, claimed, &h->faults);
	return 0;
}
SEC("lsm.s/task_alloc")
int BPF_PROG(eo_task_alloc, struct task_struct *child, __u64 clone_flags,
	     int ret)
{
	if (ret)
		return ret;
	struct eo_config *c = eo_config();
	struct eo_health *h = eo_status();
	if (!c || !h || !c->cookie || c->abi != EO_ABI || h->retired ||
	    bpf_get_current_cgroup_id() != c->cgroup)
		return 0;
	if (h->faults)
		return -1;
	__u64 *gate = eo_gate(c->gate_slot);
	if (!gate)
		return -1;
	if (fg_enter(gate)) {
		__sync_fetch_and_add(&h->gate_denials, 1);
		return -11;
	}
	struct task_struct *parent = bpf_get_current_task_btf();
	struct eo_task *p = eo_get_task(parent);
	if (!p) {
		eo_fault(EO_FAULT_STORAGE);
		fg_leave_owned(gate, 1, &h->faults);
		return -1;
	}
	int collision = 0;
	bpf_spin_lock(&p->lock);
	if (p->fork.owned)
		collision = 1;
	else
		p->fork = (struct eo_fork_tx){ (__u64)child, c->cgroup,
					       c->cookie, 1, c->gate_slot };
	bpf_spin_unlock(&p->lock);
	if (collision) {
		eo_fault(EO_FAULT_STATE);
		fg_leave_owned(gate, 1, &h->faults);
		return -1;
	}
	/* Accepted state is required after activation; lack of a role never roots it.
  * Initial observation before root authorization records births only. */
	if (clone_flags & (1ULL << 33)) {
		__sync_fetch_and_add(&h->gate_denials, 1);
		return -1;
	}
	if (h->active_generation) {
		struct eo_work *w = eo_get_work();
		int invalid = !w;
		if (w) {
			invalid = eo_load_candidate(w, 0, 0) ||
				  eo_validate_task(p, w);
			eo_put_work(w);
		}
		if (invalid) {
			eo_quarantine(p);
			return -1;
		}
	}
	return 0;
}
SEC("tp_btf/task_newtask")
int BPF_PROG(eo_task_newtask, struct task_struct *child, __u64 clone_flags)
{
	struct eo_config *c = eo_config();
	struct eo_health *h = eo_status();
	if (!c || !h || !c->cookie || c->abi != EO_ABI || h->retired)
		return 0;
	struct task_struct *parent = bpf_get_current_task_btf();
	struct eo_task *p = eo_lookup_task(parent);
	__u32 owned = 0;
	__u64 original = 0, owner = 0, identity = 0;
	if (p) {
		bpf_spin_lock(&p->lock);
		owned = p->fork.owned;
		original = p->fork.cgroup;
		owner = p->fork.owner_cookie;
		identity = p->fork.child;
		bpf_spin_unlock(&p->lock);
	}
	__u64 target = eo_task_cgroup(child),
	      current = bpf_get_current_cgroup_id();
	if (!owned && target != c->cgroup && current != c->cgroup)
		return 0;
	if (owned && (owner != c->cookie || original != c->cgroup ||
		      identity != (__u64)child)) {
		eo_quarantine(p);
		return 0;
	}
	__u32 observing = eo_credit(&h->pending_births, EO_TASKS) != 0;
	if (!observing) {
		eo_fault(EO_FAULT_CAPACITY);
		return eo_release_fork(p, child, 0);
	}
	struct eo_task *s = eo_get_task(child);
	if (!s) {
		eo_fault(EO_FAULT_STORAGE);
		goto release;
	}
	if (!p)
		p = eo_get_task(parent);
	if (!p) {
		eo_quarantine(s);
		goto release;
	}
	if (target != c->cgroup || current != c->cgroup ||
	    (clone_flags & (1ULL << 33))) {
		eo_quarantine(s);
		goto release;
	}
	/* A post-activation uncounted success is unknown ingress, never a late root. */
	if (!owned && h->active_generation) {
		eo_quarantine(s);
		goto release;
	}
	struct eo_phase *phase = eo_phase_state();
	if (!phase || phase->state == EO_PUBLISHING ||
	    phase->state == EO_STOPPED) {
		eo_quarantine(s);
		goto release;
	}
	__u64 creator = eo_group(parent);
	struct eo_anchor *anchor = eo_root();
	if (!anchor || !anchor->group) {
		if (!creator ||
		    bpf_map_update_elem(&eo_birth_groups, &s->cookie, &creator,
					BPF_NOEXIST)) {
			eo_quarantine(s);
			goto release;
		}
		int overflow = 0;
		bpf_spin_lock(&s->lock);
		if (!(s->flags & EO_PENDING_BIRTH)) {
			if (s->committed.version >= ER_UNKNOWN - 1)
				overflow = 1;
			else {
				s->flags |= EO_PENDING_BIRTH;
				s->committed.version++;
			}
		}
		bpf_spin_unlock(&s->lock);
		if (overflow) {
			eo_fault(EO_FAULT_VERSION);
			eo_quarantine(s);
		}
		goto release;
	}
	if (!eo_lineage(parent, p)) {
		eo_quarantine(s);
		goto release;
	}
	struct eo_work *w = eo_get_work();
	if (!w) {
		eo_quarantine(s);
		goto release;
	}
	__u32 slot = 0, mask = 0;
	if (!h->active_generation) {
		if ((phase->state != EO_STAGING &&
		     phase->state != EO_VALIDATED) ||
		    !phase->candidate_generation || !phase->new_uid_mask) {
			eo_put_work(w);
			eo_quarantine(s);
			goto release;
		}
		slot = 1;
		mask = phase->new_uid_mask;
	}
	int invalid = eo_load_candidate(w, slot, mask);
	if (!invalid && slot == 1 && w->a_epoch != phase->candidate_generation)
		invalid = 1;
	if (!invalid) {
		bpf_spin_lock(&p->lock);
		w->source = p->committed;
		w->source_flags = p->flags;
		bpf_spin_unlock(&p->lock);
		if (!(w->source_flags & EO_VERIFIED) ||
		    (w->source_flags & EO_QUARANTINED))
			invalid = 1;
	}
	if (!invalid) {
		bpf_spin_lock(&s->lock);
		er_snapshot(&w->merge, &s->committed, w->authority);
		bpf_spin_unlock(&s->lock);
		invalid = er_inherit(&w->merge, &w->candidate, w->source.rows);
		if (!invalid &&
		    (h->active_generation || h->a_complete == w->a_epoch)) {
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
			invalid = h->active_generation ? eo_rows_present(w) :
							 eo_rows_complete(w);
#else
			invalid = eo_rows_complete(w);
#endif
		}
	}
	if (!invalid) {
		bpf_spin_lock(&s->lock);
		if ((s->flags & EO_QUARANTINED) ||
		    h->authority_version != w->authority ||
		    er_publish(&s->committed, &w->merge, w->authority))
			invalid = 1;
		else {
			s->flags |= EO_VERIFIED;
			s->flags &= ~EO_PENDING_BIRTH;
		}
		bpf_spin_unlock(&s->lock);
	}
	eo_put_work(w);
	if (invalid)
		eo_quarantine(s);
release:
	if (observing)
		__sync_fetch_and_sub(&h->pending_births, 1);
	return eo_release_fork(p, child, 0);
}
#endif
SEC("fexit/copy_process")
int BPF_PROG(eo_copy_process_exit, struct pid *pid, int trace, int node,
	     struct kernel_clone_args *args, struct task_struct *result)
{
	if ((__u64)result < ~4094ULL)
		return 0;
	struct eo_task *p = eo_lookup_task(bpf_get_current_task_btf());
	return eo_release_fork(p, 0, 1);
}
SEC("tp_btf/sched_process_exec")
int BPF_PROG(eo_sched_exec, struct task_struct *task, int old_pid,
	     struct linux_binprm *bprm)
{
	return eo_finish_exec(task, bprm, 1);
}
SEC("fexit/bprm_execve")
int BPF_PROG(eo_bprm_exit, struct linux_binprm *bprm, int ret)
{
	return eo_finish_exec(bpf_get_current_task_btf(), bprm, 0);
}
SEC("tp_btf/sched_process_exit")
int BPF_PROG(eo_task_exit, struct task_struct *task)
{
	/* Fork cleanup precedes exec cleanup. A task cannot be running exec while
  * copy_process is still active; both fallbacks nevertheless remain bounded. */
	struct eo_task *s = eo_lookup_task(task);
	eo_release_fork(s, 0, 1);
	return eo_finish_exec(task, 0, 0);
}
#endif
