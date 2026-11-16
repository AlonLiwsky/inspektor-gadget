/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_EXEC_H
#define ENFORCE_EXEC_SHARED_EXEC_H
#if defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE) && \
	(!defined(ENFORCE_EXEC_POOL_DEVELOPMENT) ||       \
	 !defined(ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY))
#error "typed pool semantic view is candidate-only"
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE) && \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_LOCATOR_CANDIDATE) || \
	 defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE))
#error "typed opaque TASK semantic view requires its exclusive locator candidate"
#endif
/* Include after the shared policy view and canonical ledger. The adapter owns
 * a retained scope/snapshot claim and COMPLETE scoped catalogue until last use.
 * No helper here allocates a task, invents identity, or initializes a root. */
#define SE_TASK_VERIFIED 1U
#define SE_TASK_QUARANTINED 2U
#define SE_TASK_LIVE 4U
#define SE_TASK_QUALIFIED (SE_TASK_VERIFIED | SE_TASK_LIVE)
struct se_exec_policy {
	__u64 uid, epoch;
};
struct se_exec_transaction {
	__u64 bprm, sequence, generation, eligibility_version;
	__u32 owned, execution_class, policy_count, potential_writers;
	__u32 writes, uncertain, enforced_writes, conflicts;
	__u32 global_unknown, known_deny, grants, hard_fault;
	struct se_exec_policy policies[8];
	__u64 witnesses[8];
};
struct se_task_stage {
	__u64 attempt, pass_id, physical_cookie, fact_version, generation,
		start_serial;
	__u32 eligibility_flags, new_uid_mask, required_known_mask, reserved;
};
/* scope_cookie is immutable for the whole physical record lifetime. Movement
 * quarantines this record and preserves its ledger; it cannot relabel A as B. */
struct se_task_state {
#if defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE) || \
	defined(ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE)
	/* Selected pool semantics cannot carry a second BTF spinlock. The
	 * fixed metadata value owns synchronization; the prefix is typed data. */
	__u32 reserved_lock;
#else
	struct bpf_spin_lock lock;
#endif
	__u32 flags;
	__u64 physical_cookie, scope_cookie, eligibility_version,
		next_invocation;
	__u32 scope_slot, identity_reserved;
	struct er_state committed;
	struct se_task_stage staged;
	/* Only the route anchor lock owns reader. Role/transaction fields use task
  * lock; no caller may hold both. Physical invocation owns the handoff. */
	struct se_reader_owner reader;
	__u64 reader_invocation;
	struct se_exec_transaction exec;
};
_Static_assert(sizeof(struct se_task_state) == 960, "shared task state wire");
_Static_assert(sizeof(struct se_task_stage) == 64, "shared stage stamp wire");
struct se_exec_work {
	__u64 physical_cookie, scope_cookie, eligibility_version;
	__u32 flags, reserved;
	struct se_exec_transaction transaction;
	struct er_canonical_view view;
	struct er_fact_patch patch;
	struct er_row desired[8];
};
#include "shared_inherit_roles.h"
/* Called under task lock after early route ownership, before route transfer.
 * A failed transfer MUST clear this exact reserved transaction before returning.
 * An existing interpreter transaction retains its original snapshot/owner. */
struct se_exec_source {
	__u64 scope, generation, bprm;
	__u32 execution_class, count, writers, reserved;
	struct se_exec_policy policies[8];
};
/* Clamp a policy count to the 8-entry arrays behind a compiler barrier.
 * Without it LLVM folds "i < 8 && i < count" into "i < count", and the exact
 * AL2023 6.12 verifier then walks past the arrays (g005b-verdict-load-
 * 20261109). Semantics are identical to breaking at min(count, 8). */
static __attribute__((always_inline)) inline __u32 se_policy_bound(__u32 count)
{
	if (count > 8)
		count = 8;
	asm volatile("" : "+r"(count));
	return count;
}
/* This helper is invoked with the TASK value lock held. BPF-to-BPF calls
 * under that lock are rejected by the verifier, so inlining is mandatory. */
static __attribute__((always_inline)) inline int
se_exec_reserve_locked(struct se_task_state *task, __u64 cookie,
		       const struct se_exec_source *source)
{
	if (!(task->flags & SE_TASK_LIVE) || !cookie ||
	    cookie != task->physical_cookie || !source->bprm ||
	    task->scope_cookie != source->scope || !source->generation ||
	    source->generation == ~0ULL || !task->eligibility_version ||
	    source->reserved || source->execution_class < 1 ||
	    source->execution_class > 2 || !source->count ||
	    source->count > 8 || (source->writers >> source->count))
		return -1;
	if (source->execution_class == 2 && task->flags != SE_TASK_QUALIFIED)
		return -1;
	for (__u32 i = 0; i < 8; i++) {
		if (i >= source->count)
			break;
		if (!source->policies[i].uid || !source->policies[i].epoch ||
		    source->policies[i].epoch > source->generation)
			return -1;
		for (__u32 j = 0; j < i; j++)
			if (source->policies[j].uid == source->policies[i].uid)
				return -1;
	}
	if (task->exec.owned) {
		if (task->exec.bprm != source->bprm ||
		    task->exec.generation != source->generation ||
		    task->exec.execution_class != source->execution_class ||
		    task->exec.policy_count != source->count)
			return -1;
		for (__u32 i = 0; i < 8; i++) {
			if (i >= source->count)
				break;
			if (task->exec.policies[i].uid !=
				    source->policies[i].uid ||
			    task->exec.policies[i].epoch !=
				    source->policies[i].epoch)
				return -1;
		}
		return 1;
	}
	if (task->next_invocation >= ~0ULL - 1)
		return -1;
	task->exec = (struct se_exec_transaction){
		.bprm = source->bprm,
		.sequence = ++task->next_invocation,
		.generation = source->generation,
		.eligibility_version = task->eligibility_version,
		.owned = 1,
		.execution_class = source->execution_class,
		.policy_count = source->count,
		.potential_writers = source->writers
	};
	for (__u32 i = 0; i < 8; i++) {
		if (i >= source->count)
			break;
		/* Keep the BPF copy scalar: Clang may lower a struct assignment to
		 * unsupported memcpy inside the bounded policy loop. */
		task->exec.policies[i].uid = source->policies[i].uid;
		task->exec.policies[i].epoch = source->policies[i].epoch;
	}
	return 0;
}
static __attribute__((always_inline)) inline int
se_exec_begin_locked(struct se_task_state *task, __u64 cookie, __u64 bprm,
		     const struct se_policy_view *view, __u32 mode,
		     __u32 writers)
{
	if (!view || !view->ready)
		return -1;
	struct se_exec_source source = { .scope = view->scope_cookie,
					 .generation = view->header.generation,
					 .bprm = bprm,
					 .execution_class = mode,
					 .count = view->header.policies,
					 .writers = writers };
	for (__u32 i = 0; i < 8; i++) {
		if (i >= source.count)
			break;
		source.policies[i] =
			(struct se_exec_policy){ view->policies[i].uid,
						 view->policies[i].root_epoch };
	}
	return se_exec_reserve_locked(task, cookie, &source);
}
/* Retained immutable snapshot metadata permits reservation BEFORE scratch or
 * object lookup. Compiler metadata is authenticated at Commit, not inferred. */
static __attribute__((always_inline)) inline int
se_exec_begin_snapshot_locked(struct se_task_state *task, __u64 cookie,
			      __u64 bprm, const struct se_snapshot *snapshot)
{
	if (!se_snapshot_metadata_valid(&snapshot->metadata, snapshot->count,
					snapshot->generation))
		return -1;
	struct se_exec_source source = {
		.scope = snapshot->scope,
		.generation = snapshot->generation,
		.bprm = bprm,
		.execution_class = snapshot->execution_class,
		.count = snapshot->count,
		.writers = snapshot->metadata.role_writers
	};
	for (__u32 i = 0; i < 8; i++) {
		if (i >= source.count)
			break;
		source.policies[i] = (struct se_exec_policy){
			snapshot->metadata.policy_uids[i],
			snapshot->metadata.root_epochs[i]
		};
	}
	return se_exec_reserve_locked(task, cookie, &source);
}
/* Anchor lock only, after task-locked reservation. The adapter retains the
 * physical task reference and sole invocation through this handoff. It never
 * reads task-locked transaction fields here: identities are reservation outputs.
 */
static __attribute__((always_inline)) inline int se_exec_reader_attach_locked(
	struct se_route_anchor *anchor, struct se_binding_snapshots *binding,
	struct se_task_state *task, struct se_route_claim *claim, __u64 cookie,
	__u64 invocation)
{
	if (!invocation || task->reader_invocation || task->reader.owned)
		return -1;
	struct se_reader_token token = {};
	if (se_route_transfer_locked(anchor, binding, claim, cookie,
				     &task->reader, &token))
		return -1;
	task->reader_invocation = invocation;
	return 0;
}
/* Exact persistent claim consumption; a duplicate finish cannot refund a new
 * invocation even when it reuses this same physical task and scope. */
static __attribute__((always_inline)) inline int
se_exec_reader_release_locked(struct se_binding_snapshots *binding,
			      struct se_task_state *task, __u64 cookie,
			      __u64 invocation)
{
	if (!invocation || task->reader_invocation != invocation ||
	    task->reader.token.task_cookie != cookie)
		return -1;
	struct se_reader_token token = task->reader.token;
	if (se_reader_release_locked(binding, &task->reader, &token))
		return -1;
	task->reader_invocation = 0;
	return 0;
}
/* Called under the original route/binding lock with a source-owned physical
 * TASK, never with a copied token as the sole authority. A live reader claim
 * prevents withdrawal. In the product publisher (G019 gap 3) it no longer
 * prevents a same-route commit: the reader keeps reading its own record,
 * ACTIVE or RETIRING. The accepted catalogue it evaluates against is still
 * stable, because within a binding's lifetime the product catalogue is
 * write-once per (scope, UID):
 *   - a revision keeps the policy UID, class and root epoch
 *     (real_owner_publish_revision refuses any change up front);
 *   - the (scope, UID) -> bank index entry is inserted BPF_NOEXIST and only
 *     an existing entry of the same bank is accepted (real_owner_epoch_bind,
 *     se_arm_index_decision);
 *   - the commit preflight accepts the bank's epoch cell only empty, or of
 *     the same scope/UID with epoch 0 or equal (real_owner_epoch_cell_ready),
 *     so the commit's epoch store writes the identical bytes;
 *   - the cells and index entries of a scope are cleared only by
 *     real_owner_recycle_clean, with both records FREE (no reader left).
 * The per-WORK epoch cache is tagged with the reader's own generation, and
 * any scope/generation/epoch mismatch fails closed (CORRUPT, never allow).
 * The caller must keep the exact TASK/invocation owner live through its last
 * catalogue lookup; this predicate does not create another lease. */
static __attribute__((always_inline)) inline int
se_exec_reader_authority_locked(const struct se_route_anchor *route,
				const struct se_binding_snapshots *binding,
				const struct se_task_state *task, __u32 slot,
				__u64 scope, __u64 generation, __u64 cookie,
				__u64 invocation, __u32 execution_class)
{
#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE
	/* G019 gap 3: the reader's own record, ACTIVE or RETIRING (a revision
	 * may commit while it is held; it keeps reading its record). */
	if (!route || !binding || !task || !scope || !generation || !cookie ||
	    !invocation || execution_class < 1 || execution_class > 2 ||
	    route->reserved || !route->incarnation || !route->cgroup_identity ||
	    route->phase != SE_ROUTE_ACTIVE || route->payload_slot != slot ||
	    route->scope != scope ||
	    route->execution_class != execution_class ||
	    binding->scope != scope || !(task->flags & SE_TASK_LIVE) ||
	    task->identity_reserved || task->physical_cookie != cookie ||
	    task->scope_cookie != scope || task->scope_slot != slot ||
	    task->reader_invocation != invocation || !task->reader.owned ||
	    task->reader.reserved || task->reader.token.record >= 2)
		return 0;
	{
		const struct se_reader_token *token = &task->reader.token;
		const struct se_snapshot *snapshot =
			&binding->records[se_route_rec_index(token->record)];
		return token->scope == scope && token->sequence &&
		       token->task_cookie == cookie &&
		       token->execution_class == execution_class &&
		       snapshot->scope == scope &&
		       snapshot->serial == token->serial &&
		       snapshot->generation == generation &&
		       (snapshot->phase == SE_SNAPSHOT_ACTIVE ||
			snapshot->phase == SE_SNAPSHOT_RETIRING) &&
		       snapshot->claims &&
		       snapshot->execution_class == execution_class;
	}
#endif
	if (!route || !binding || !task || !scope || !generation || !cookie ||
	    !invocation || execution_class < 1 || execution_class > 2 ||
	    route->reserved || !route->incarnation || !route->cgroup_identity ||
	    route->phase != SE_ROUTE_ACTIVE || route->payload_slot != slot ||
	    route->scope != scope || route->payload_generation != generation ||
	    route->execution_class != execution_class ||
	    route->active_record >= 2 || !route->active_serial ||
	    binding->scope != scope || binding->generation != generation ||
	    binding->active_record != route->active_record ||
	    binding->active_serial != route->active_serial ||
	    !(task->flags & SE_TASK_LIVE) || task->identity_reserved ||
	    task->physical_cookie != cookie || task->scope_cookie != scope ||
	    task->scope_slot != slot || task->reader_invocation != invocation ||
	    !task->reader.owned || task->reader.reserved)
		return 0;
	const struct se_reader_token *token = &task->reader.token;
	const struct se_snapshot *snapshot =
		&binding->records[route->active_record];
	return token->scope == scope && token->serial == route->active_serial &&
	       token->sequence && token->task_cookie == cookie &&
	       token->record == route->active_record &&
	       token->execution_class == execution_class &&
	       snapshot->scope == scope && snapshot->serial == token->serial &&
	       snapshot->generation == generation &&
	       snapshot->phase == SE_SNAPSHOT_ACTIVE && snapshot->claims &&
	       snapshot->execution_class == execution_class;
}
/* Failed setup/exec cleanup is task-locked and exact; caller subsequently
 * refunds the matching reader (if attached) under the anchor lock. */
static __attribute__((always_inline)) inline int
se_exec_abort_locked(struct se_task_state *task, __u64 cookie, __u64 bprm,
		     __u64 invocation)
{
	if (task->physical_cookie != cookie || !task->exec.owned ||
	    task->exec.bprm != bprm || task->exec.sequence != invocation)
		return -1;
	task->exec.owned = 0;
	return 0;
}
/* Tracking failures are causal for possible role writers only. The caller
 * returns by immutable class; this state update itself never decides LSM errno. */
static inline void se_exec_fault_locked(struct se_exec_transaction *tx)
{
	tx->hard_fault = 1;
	tx->uncertain |= tx->potential_writers | tx->writes;
	tx->grants = 0;
}
/* Pure TASK-locked mutations shared by the legacy value lock and the exact
 * opaque metadata-lock bracket. Neither helper acquires a map reference,
 * chooses a verdict, or treats a task pointer as identity authority. */
static __attribute__((always_inline)) inline void
se_exec_owned_fault_locked(struct se_task_state *task, __u64 bprm)
{
	if (task->exec.owned && task->exec.bprm == bprm)
		se_exec_fault_locked(&task->exec);
	else if (!task->exec.owned) {
		task->flags |= SE_TASK_QUARANTINED;
		if (task->eligibility_version < ~0ULL - 1)
			task->eligibility_version++;
	}
}
static __attribute__((always_inline)) inline void
se_exec_note_prior_deny_locked(struct se_task_state *task, __u64 bprm)
{
	if (task->exec.owned && task->exec.bprm == bprm) {
		task->exec.known_deny = 1;
		task->exec.grants = 0;
	}
}
static inline int se_exec_propose_locked(struct se_exec_transaction *tx,
					 const struct fe_decision *d)
{
	if (!tx->owned || !tx->policy_count || tx->policy_count > 8)
		return -1;
	__u32 valid = (1U << tx->policy_count) - 1;
	__u32 writes = FE_ROLE_WRITES(d->audit_unknown);
	__u32 uncertain = FE_ROLE_UNCERTAIN(d->audit_unknown);
	if ((d->audit_unknown & ~FE_UNCERTAINTY_VALID_MASK) ||
	    ((writes | uncertain | (d->audit_unknown & 255U) |
	      d->enforced_writes | d->role_conflicts) &
	     ~valid) ||
	    ((d->audit_unknown & FE_AUDIT_UNCERTAIN_FALLBACK) &&
	     (!d->deny || d->mode != 1))) {
		se_exec_fault_locked(tx);
		return -1;
	}
	if (d->deny && !(d->audit_unknown & FE_AUDIT_UNCERTAIN_FALLBACK)) {
		tx->known_deny = 1;
		tx->grants = 0;
		return 0;
	}
	if (d->error && d->error != FE_AUDIT_UNKNOWN) {
		se_exec_fault_locked(tx);
		return -1;
	}
	tx->writes |= writes;
	tx->uncertain |= uncertain;
	tx->enforced_writes |= d->enforced_writes;
	tx->conflicts |= d->role_conflicts;
	if (d->audit_unknown &
	    (FE_AUDIT_GLOBAL_SUPPRESS | FE_AUDIT_UNCERTAIN_FALLBACK))
		tx->global_unknown = 1;
	for (__u32 i = 0, bound = se_policy_bound(tx->policy_count);
	     i < bound && i < 8; i++) {
		__u64 role = d->known_role_witnesses[i] ?
				     d->known_role_witnesses[i] :
				     d->proposed_roles[i];
		if (d->proposed_roles[i]) {
			tx->writes |= 1U << i;
			tx->grants |= 1U << i;
		}
		if (!role)
			continue;
		if (tx->witnesses[i] && tx->witnesses[i] != role) {
			tx->conflicts |= 1U << i;
			tx->uncertain |= 1U << i;
		} else
			tx->witnesses[i] = role;
	}
	if (tx->global_unknown)
		tx->uncertain |= tx->writes;
	tx->grants &= ~tx->uncertain;
	if (tx->enforced_writes & tx->conflicts) {
		se_exec_fault_locked(tx);
		return -1;
	}
	return 0;
}
/* Snapshot under task lock. Catalogue classification and desired patch planning
 * occur outside it, under the retained scope authority, then ALL identities and
 * transaction bytes are rechecked before the accepted-only patch publisher. */
/* Older admitted kernels reject BPF-to-BPF calls under a spinlock. Keep the
 * entire snapshot copy in the caller's lock-held instruction frame. */
static __attribute__((always_inline)) inline void
se_exec_snapshot_locked(const struct se_task_state *task, __u64 authority,
			struct se_exec_work *work)
{
	work->physical_cookie = task->physical_cookie;
	work->scope_cookie = task->scope_cookie;
	work->eligibility_version = task->eligibility_version;
	work->flags = task->flags;
	work->transaction = task->exec;
	work->reserved = 0;
	er_snapshot(&work->view.work, &task->committed, authority);
}
/* One flattened (policy-major, row-minor) step of the role fill, shared by
 * the host loop and the BPF bpf_loop driver so both run identical logic.
 * error 1: a policy has != 1 accepted row (roles cleared); 2: overflow. */
struct se_exec_role_fill {
	struct se_exec_work *work;
	struct fe_facts *facts;
	__u32 present, done;
	int error;
};
static __attribute__((always_inline)) inline int
se_exec_role_fill_step(__u32 idx, struct se_exec_role_fill *c)
{
	struct se_exec_work *work = c->work;
	struct fe_facts *facts = c->facts;
	__u32 i = idx >> 4, j = idx & 15;
	if (!work || !facts) {
		c->error = 2;
		return 1;
	}
	if (i >= 8 || i >= work->transaction.policy_count) {
		c->done = 1;
		return 1;
	}
	const struct se_exec_policy *p = &work->transaction.policies[i];
	if (j == 0)
		c->present = 0;
	const struct er_row *r = &work->view.work.rows[j];
	if ((work->view.accepted_mask & (1U << j)) && r->uid == p->uid &&
	    r->epoch == p->epoch) {
		c->present++;
		if (er_role_known(r)) {
			__u32 n = facts->role_count;
			if (n >= 8) {
				c->error = 2;
				return 1;
			}
			facts->roles[n & 7] =
				(struct fe_role){ r->uid, r->role };
			facts->role_count = n + 1;
		}
	}
	if (j == 15 && c->present != 1) {
		c->error = 1;
		return 1;
	}
	return 0;
}
#if defined(__bpf__) && defined(SE_EXEC_ROLE_FILL_BPF_LOOP)
/* The nested 8x16 open-coded fill exceeded 1M processed instructions in the
 * verdict prepare program on exact AL2023 6.18; the callback is verified once. */
static int se_exec_role_fill_cb(__u32 idx, void *raw)
{
	return se_exec_role_fill_step(idx, raw);
}
#endif
/* Consume only a view already classified under a retained, complete catalogue
 * claim. The typed pool path supplies its explicit-scope classifier; the
 * legacy wrapper below preserves the selected current-invocation behavior. */
static inline int se_exec_fill_roles_preclassified(struct se_exec_work *work,
						   struct fe_facts *facts)
{
	facts->role_count = 0;
	if (work->transaction.eligibility_version !=
		    work->eligibility_version ||
	    work->view.work.error || !work->view.work.prepared)
		return -1;
	if (work->flags != SE_TASK_QUALIFIED)
		return 0;
	struct se_exec_role_fill c = { .work = work, .facts = facts };
#if defined(__bpf__) && defined(SE_EXEC_ROLE_FILL_BPF_LOOP)
	/* A loop that neither ran every step nor reached the policy bound
	 * must never look like "no roles, success". */
	long steps = bpf_loop(128, se_exec_role_fill_cb, &c, 0);
	if (steps != 128 && !c.done && !c.error)
		c.error = 2;
#else
	for (__u32 idx = 0; idx < 128; idx++)
		if (se_exec_role_fill_step(idx, &c))
			break;
#endif
	if (c.error == 1)
		facts->role_count = 0;
	return c.error ? -1 : 0;
}
static inline int se_exec_fill_roles(struct se_exec_work *work,
				     struct fe_facts *facts)
{
	facts->role_count = 0;
	if (work->transaction.eligibility_version !=
		    work->eligibility_version ||
	    er_canonical_classify(&work->view))
		return -1;
	return se_exec_fill_roles_preclassified(work, facts);
}
static inline int
se_exec_completion_prepare_preclassified(struct se_exec_work *work, int success)
{
	struct se_exec_transaction *tx = &work->transaction;
	if (!tx->owned ||
	    tx->eligibility_version != work->eligibility_version ||
	    tx->policy_count > 8 || work->view.work.error ||
	    !work->view.work.prepared)
		return -1;
	__u32 count = 0;
	if (success && !tx->known_deny) {
		for (__u32 i = 0, bound = se_policy_bound(tx->policy_count);
		     i < bound && i < 8; i++) {
			int unknown = !!(tx->uncertain & (1U << i));
			if (!unknown && !(tx->grants & (1U << i)))
				continue;
			const struct se_exec_policy *p = &tx->policies[i];
			int found = 0;
			for (__u32 j = 0; j < 16; j++) {
				const struct er_row *r =
					&work->view.work.rows[j];
				if (!(work->view.accepted_mask & (1U << j)) ||
				    r->uid != p->uid || r->epoch != p->epoch)
					continue;
				struct er_row next = *r;
				if (unknown)
					next.knowledge = ER_ROLE_UNKNOWN;
				else {
					if (!tx->witnesses[i])
						return -1;
					next.role = tx->witnesses[i];
					next.knowledge = ER_ROLE_KNOWN;
				}
				if (count >= 8)
					return -1;
				work->desired[count++] = next;
				found++;
			}
			if (found != 1)
				return -1; /* never bootstrap missing accepted history */
		}
	}
	return er_canonical_patch_prepare(&work->view, work->desired, count,
					  &work->patch);
}
static inline int se_exec_completion_prepare(struct se_exec_work *work,
					     int success)
{
	struct se_exec_transaction *tx = &work->transaction;
	if (!tx->owned ||
	    tx->eligibility_version != work->eligibility_version ||
	    tx->policy_count > 8 || er_canonical_classify(&work->view))
		return -1;
	return se_exec_completion_prepare_preclassified(work, success);
}
static inline int se_exec_complete_locked(struct se_task_state *task,
					  const struct se_exec_work *work,
					  __u64 authority)
{
	if (task->physical_cookie != work->physical_cookie ||
	    task->scope_cookie != work->scope_cookie ||
	    task->eligibility_version != work->eligibility_version ||
	    task->flags != work->flags || !task->exec.owned ||
	    __builtin_memcmp(&task->exec, &work->transaction,
			     sizeof(task->exec)))
		return -1;
	if (er_canonical_patch_publish(&task->committed, &work->patch,
				       authority))
		return -1;
	/* Reader ownership remains until the adapter takes/releases its exact token
  * under the route lock AFTER this final task/snapshot use. Duplicate finish
  * sees owned=0 and cannot consume another invocation's reader. */
	task->exec.owned = 0;
	return 0;
}
/* Allocation-independent completion for an invocation whose work buffer is
 * unavailable. The retained snapshot is authority for these exact accepted
 * UID/epoch pairs. No catalogue lookup or root insertion occurs under lock.
 * Two passes validate ALL causal targets/version before the first row store.
 * Known proposals lose precision to UNKNOWN; nonwriters/provisional cells stay.
 * Return -1 for stale ownership, otherwise ownership is consumed (1=quarantine).
 */
static __attribute__((always_inline)) inline int
se_exec_finish_bounded_locked(struct se_task_state *task, __u64 cookie,
			      __u64 bprm, __u64 invocation, int success)
{
	struct se_exec_transaction *tx = &task->exec;
	if (task->physical_cookie != cookie || !tx->owned || tx->bprm != bprm ||
	    tx->sequence != invocation)
		return -1;
	__u32 mask = tx->uncertain | tx->writes;
	int invalid = tx->policy_count > 8 || !tx->policy_count ||
		      tx->eligibility_version != task->eligibility_version;
	if (!invalid && (mask >> tx->policy_count))
		invalid = 1;
	int changed = 0;
	__u32 targets = 0;
	if (success && !tx->known_deny && !invalid) {
		for (__u32 i = 0, bound = se_policy_bound(tx->policy_count);
		     i < bound && i < 8; i++) {
			if (!(mask & (1U << i)))
				continue;
			const struct se_exec_policy *p = &tx->policies[i];
			int found = 0;
			/* Fixed row offsets avoid a carried pointer across duplicate-search latches. */
#ifdef __clang__
#pragma clang loop unroll(full)
#endif
			for (__u32 j = 0; j < 16; j++) {
				const struct er_row *r =
					&task->committed.rows[j];
				if (r->uid != p->uid || r->epoch != p->epoch)
					continue;
				/* A second match already guarantees refusal; do not enumerate
				 * further duplicate subsets or change any factual row. */
				if (found) {
					invalid = 1;
					goto finish;
				}
				found = 1;
				targets |= 1U << j;
				if (!r->role || r->reserved ||
				    (r->knowledge != ER_ROLE_KNOWN &&
				     r->knowledge != ER_ROLE_UNKNOWN)) {
					invalid = 1;
					goto finish;
				}
				changed |= r->knowledge != ER_ROLE_UNKNOWN;
			}
			if (found != 1) {
				invalid = 1;
				goto finish;
			}
		}
		if (changed && task->committed.version >= ER_UNKNOWN - 1)
			invalid = 1;
		if (!invalid) {
			/* The task lock keeps the validated target positions stable.
			 * Publish exactly those cells, without a second UID cross-product. */
			for (__u32 j = 0; j < 16; j++) {
				if (targets & (1U << j))
					task->committed.rows[j].knowledge =
						ER_ROLE_UNKNOWN;
			}
			if (changed)
				task->committed.version++;
		}
	}
finish:
	if (invalid) {
		task->flags |= SE_TASK_QUARANTINED;
		if (task->eligibility_version < ~0ULL - 1)
			task->eligibility_version++;
	}
	tx->owned = 0;
	return invalid ? 1 : 0;
}
#endif
