/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef uint8_t __u8;
struct bpf_spin_lock {
	int held;
};
static void bpf_spin_lock(struct bpf_spin_lock *l)
{
	assert(!l->held);
	l->held = 1;
}
static void bpf_spin_unlock(struct bpf_spin_lock *l)
{
	assert(l->held);
	l->held = 0;
}
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#include "shared_route.h"
#include "shared_policy_lookup.h"
static struct fm_blob cells[12];
static const struct fm_blob *se_policy_physical(void *ctx, fm_u32 slot,
						fm_u64 generation, fm_u32 key)
{
	(void)ctx;
	return !slot && generation == 1 && key < 12 ? &cells[key] : 0;
}
static __u64 current_scope;
static __u64 forced_accepted_epoch;
static __u64 accepted(__u64 uid)
{
	return uid == 1 ? (forced_accepted_epoch ?
				   forced_accepted_epoch :
				   (current_scope == 11 ? 13 : 4)) :
			  0;
}
#define ER_ACCEPTED_EPOCH(uid) accepted(uid)
#include "epoch_roles.h"
#include "shared_exec.h"
#if defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE) || \
	defined(ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE)
#include "shared_pool_task_wire.h"
static void typed_task_wire_overlay(void)
{
	struct se_pool_task_wire payload = {};
	payload.semantic.physical_cookie = 41;
	payload.semantic.scope_cookie = 43;
	payload.semantic.flags = SE_TASK_LIVE;
	payload.semantic.committed.version = 7;
	assert(payload.identity.physical_cookie == 41 &&
	       payload.identity.scope_cookie == 43 &&
	       payload.identity.flags == SE_TASK_LIVE);
	assert(payload.bytes[0] == 7);
	payload.semantic.exec = (struct se_exec_transaction){
		.bprm = 71,
		.sequence = 73,
		.owned = 1,
	};
	assert(!se_exec_abort_locked(&payload.semantic, 41, 71, 73));
	assert(!payload.semantic.exec.owned &&
	       payload.identity.physical_cookie == 41);
}
#endif
#if defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE) || \
	defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE)
struct observation {
	struct fe_facts facts;
	struct fe_scratch evaluator;
	char argument[4097];
};
#include "shared_invocation_wire.h"
#include "shared_pool_opaque_work_wire.h"
#if defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE)
#include "shared_pool_catalogue_pure.h"
static void typed_work_catalogue_parity(void)
{
	assert(!se_pool_catalogue_ne64(0, 0));
	assert(!se_pool_catalogue_ne64(~(__u64)0, ~(__u64)0));
	assert(se_pool_catalogue_ne64(0, 1));
	assert(se_pool_catalogue_ne64(1ULL << 63, 0));
	assert(se_pool_catalogue_ne64(0, ~(__u64)0));
	current_scope = 11;
	for (int scenario = 0; scenario < 7; scenario++) {
		forced_accepted_epoch = scenario == 4 ? ER_UNKNOWN : 0;
		struct er_state state = { .version = 7 };
		if (scenario != 0)
			state.rows[0] = er_known_row(1, 13, 3);
		if (scenario == 2)
			state.rows[0].knowledge = ER_ROLE_UNKNOWN;
		if (scenario == 3)
			state.rows[0].epoch = 14;
		if (scenario == 5)
			state.rows[15] = state.rows[0];
		if (scenario == 6)
			state.rows[0].reserved = 1;
		struct er_canonical_view legacy = {}, typed = {}, scoped = {};
		er_snapshot(&legacy.work, &state, 1);
		typed = legacy;
		scoped = legacy;
		struct se_owk_payload payload = {};
		struct se_pool_epoch_cache *cache = &payload.catalogue;
		cache->scope = 11;
		cache->generation = 1;
		for (unsigned i = 0; i < ER_SLOTS; i++) {
			cache->rows[i].uid = typed.work.rows[i].uid;
			cache->rows[i].accepted_epoch =
				cache->rows[i].uid ?
					accepted(cache->rows[i].uid) :
					0;
		}
		struct se_route_claim claim = {
			.scope = 11,
			.generation = 1,
			.owned = 1,
		};
		int old = er_canonical_classify(&legacy);
		int now = se_pool_catalogue_classify(&typed, cache, &claim);
		int via_reader = se_pool_catalogue_classify_after_authority(
			&scoped, cache, 11, 1);
		assert(old == now && now == via_reader &&
		       legacy.work.error == typed.work.error &&
		       legacy.accepted_mask == typed.accepted_mask &&
		       legacy.work.prepared == typed.work.prepared &&
		       !memcmp(&typed, &scoped, sizeof(typed)));
		if (!old) {
			struct er_work old_projection = {},
				       typed_projection = {};
			assert(!er_canonical_project(&legacy, &old_projection));
			assert(!er_canonical_project(&typed,
						     &typed_projection));
			assert(!memcmp(&old_projection, &typed_projection,
				       sizeof(old_projection)));
			assert(se_pool_catalogue_projection_matches(
				&typed, &typed_projection, cache, &claim));
		}
	}
	/* Deterministic differential sweep locks the arithmetic row check to
	 * the existing canonical result across malformed and provisional cells. */
	__u64 seed = 0x5eed;
	for (unsigned trial = 0; trial < 2048; trial++) {
		forced_accepted_epoch = trial % 19 == 0 ? ER_UNKNOWN : 0;
		struct er_state state = { .version = 7 };
		for (unsigned i = 0; i < ER_SLOTS; i++) {
			seed = seed * 6364136223846793005ULL + 1;
			if ((seed >> 32) % 5 == 0)
				continue;
			struct er_row *row = &state.rows[i];
			row->uid = 1 + ((seed >> 37) % 3);
			row->epoch = (seed >> 41) % 17;
			row->role = (seed >> 46) % 5;
			row->knowledge = (seed >> 51) % 4;
			row->reserved = (seed >> 55) % 7 == 0;
		}
		struct er_canonical_view legacy = {}, typed = {};
		er_snapshot(&legacy.work, &state, 1);
		typed = legacy;
		struct se_pool_epoch_cache cache = {
			.scope = 11,
			.generation = 1,
		};
		for (unsigned i = 0; i < ER_SLOTS; i++) {
			cache.rows[i].uid = state.rows[i].uid;
			cache.rows[i].accepted_epoch =
				state.rows[i].uid ?
					accepted(state.rows[i].uid) :
					0;
		}
		struct se_route_claim claim = {
			.scope = 11,
			.generation = 1,
			.owned = 1,
		};
		int old = er_canonical_classify(&legacy);
		int now = se_pool_catalogue_classify(&typed, &cache, &claim);
		assert(old == now && legacy.work.error == typed.work.error &&
		       legacy.accepted_mask == typed.accepted_mask &&
		       legacy.work.prepared == typed.work.prepared);
	}
	forced_accepted_epoch = 0;
}
#endif
static void typed_work_wire_overlay(void)
{
	struct se_owk_payload payload = {};
	payload.semantic.scope = 47;
	payload.semantic.cookie = 53;
	payload.semantic.sequence = 59;
	payload.semantic.slot = 7;
	payload.semantic.view.scope_cookie = 11;
	payload.semantic.observation.argument[0] = 'x';
	payload.catalogue.scope = 11;
	payload.catalogue.generation = 1;
	payload.catalogue.rows[0].uid = 1;
	payload.catalogue.rows[0].accepted_epoch = 13;
	assert(payload.scope == 47 && payload.cookie == 53 &&
	       payload.sequence == 59 && payload.slot == 7);
	assert(payload.bytes[8] == 11);
	assert(payload.bytes[3176 - 32 +
			     __builtin_offsetof(struct observation, argument)] ==
	       'x');
	assert(payload.catalogue.scope == 11 &&
	       payload.catalogue.rows[0].accepted_epoch == 13);
}
#endif
static struct se_policy_view view;
static struct se_exec_work work;
static struct fe_facts facts;
static struct fe_scratch scratch;
static void configure(__u64 scope)
{
	current_scope = scope;
	struct fe_header h = { .policies = 1, .rule_base = 9, .rules = 1 };
	struct fe_policy p = {
		.uid = 1, .root_role = 3, .fallback = 1, .mode = 1
	};
	struct fe_rule r = { .mode = 1,
			     .actor_image = -1,
			     .target_image = -1,
			     .stdin_pipe = -1,
			     .set_role = 7 };
	memcpy(&cells[0], &h, sizeof(h));
	memcpy(&cells[1], &p, sizeof(p));
	memcpy(&cells[9], &r, sizeof(r));
	struct se_policy_ref ref = { .generation = 1,
				     .root_epoch = accepted(1),
				     .entries = 12 };
	struct fe_string container = { .length = 1, .bytes = { 'c' } };
	assert(!se_policy_prepare(&view, 0, scope, 20, &container, &ref, 1));
}
static void propose(struct se_task_state *task)
{
	se_exec_snapshot_locked(task, 1, &work);
	memset(&facts, 0, sizeof(facts));
	assert(!se_exec_fill_roles(&work, &facts));
	assert(!fe_evaluate(&view, &facts, &scratch));
	assert(!se_exec_propose_locked(&task->exec, &scratch.decision));
}
static void finish(struct se_task_state *task, int success)
{
	se_exec_snapshot_locked(task, 1, &work);
	assert(!se_exec_completion_prepare(&work, success));
	assert(!se_exec_complete_locked(task, &work, 1));
	assert(se_exec_complete_locked(task, &work, 1));
}
static void preclassified_exec_equivalence(void)
{
	configure(11);
	struct se_task_state task = { .flags = SE_TASK_QUALIFIED,
				      .physical_cookie = 99,
				      .scope_cookie = 11,
				      .eligibility_version = 1 };
	task.committed.version = 7;
	task.committed.rows[0] = er_known_row(1, 13, 3);
	task.exec = (struct se_exec_transaction){ .owned = 1,
						  .eligibility_version = 1,
						  .policy_count = 1,
						  .grants = 1,
						  .witnesses = { 9 },
						  .policies = { { 1, 13 } } };
	struct se_exec_work legacy = {}, classified = {};
	struct fe_facts old_facts = {}, new_facts = {};
	se_exec_snapshot_locked(&task, 20, &legacy);
	classified = legacy;
	assert(se_exec_fill_roles_preclassified(&classified, &new_facts));
	assert(!new_facts.role_count && !classified.view.work.prepared);
	assert(!se_exec_fill_roles(&legacy, &old_facts));
	assert(!er_canonical_classify(&classified.view));
	assert(!se_exec_fill_roles_preclassified(&classified, &new_facts));
	assert(old_facts.role_count == 1 &&
	       old_facts.role_count == new_facts.role_count &&
	       !memcmp(old_facts.roles, new_facts.roles,
		       sizeof(old_facts.roles)));

	legacy = (struct se_exec_work){};
	classified = (struct se_exec_work){};
	se_exec_snapshot_locked(&task, 20, &legacy);
	classified = legacy;
	assert(se_exec_completion_prepare_preclassified(&classified, 1));
	assert(!se_exec_completion_prepare(&legacy, 1));
	assert(!er_canonical_classify(&classified.view));
	assert(!se_exec_completion_prepare_preclassified(&classified, 1));
	assert(legacy.patch.prepared && legacy.patch.count == 1 &&
	       !memcmp(&legacy.patch, &classified.patch, sizeof(legacy.patch)));
	assert(legacy.patch.changes[0].after.role == 9);

	legacy = (struct se_exec_work){};
	classified = (struct se_exec_work){};
	se_exec_snapshot_locked(&task, 20, &legacy);
	classified = legacy;
	assert(!se_exec_completion_prepare(&legacy, 0));
	assert(!er_canonical_classify(&classified.view));
	assert(!se_exec_completion_prepare_preclassified(&classified, 0));
	assert(!legacy.patch.count && !classified.patch.count);
}
/* All sixteen cells populated: causal accepted targets occupy the high half;
 * the low half models unrelated/provisional facts that MUST remain byte exact. */
static void bounded_completion_targets(void)
{
	struct se_task_state base = { .physical_cookie = 99,
				      .eligibility_version = 1,
				      .flags = SE_TASK_QUALIFIED };
	base.exec = (struct se_exec_transaction){ .owned = 1,
						  .bprm = 100,
						  .sequence = 1,
						  .eligibility_version = 1,
						  .policy_count = 8,
						  .writes = 255 };
	base.committed.version = 7;
	for (__u32 i = 0; i < 16; i++)
		base.committed.rows[i] = er_known_row(i + 1, 3, i + 100);
	for (__u32 i = 0; i < 8; i++)
		base.exec.policies[i] = (struct se_exec_policy){ i + 9, 3 };
	for (int fault = 0; fault < 6; fault++) {
		struct se_task_state task = base;
		if (fault == 1)
			task.committed.rows[15].epoch++;
		if (fault == 2)
			task.committed.rows[15].reserved = 1;
		if (fault == 3)
			task.committed.rows[0] = task.committed.rows[15];
		if (fault == 4)
			task.committed.version = ER_UNKNOWN - 1;
		/* Duplicate first target early; the later valid targets must not publish. */
		if (fault == 5) {
			task.committed.rows[0] = task.committed.rows[8];
			task.committed.rows[1] = task.committed.rows[8];
			task.committed.rows[8] = er_known_row(99, 3, 108);
		}
		struct er_state before = task.committed;
		assert(se_exec_finish_bounded_locked(&task, 99, 100, 1, 1) ==
		       !!fault);
		assert(!task.exec.owned);
		if (fault) {
			assert(!memcmp(&before, &task.committed,
				       sizeof(before)));
			assert(task.flags & SE_TASK_QUARANTINED);
			assert(task.eligibility_version == 2);
		} else {
			assert(!memcmp(before.rows, task.committed.rows,
				       8 * sizeof(struct er_row)));
			for (__u32 i = 8; i < 16; i++) {
				before.rows[i].knowledge = ER_ROLE_UNKNOWN;
				assert(!memcmp(&before.rows[i],
					       &task.committed.rows[i],
					       sizeof(struct er_row)));
			}
			assert(task.committed.version == 8);
		}
	}
	for (int deny = 0; deny < 2; deny++) {
		struct se_task_state task = base;
		task.exec.known_deny = deny;
		assert(!se_exec_finish_bounded_locked(&task, 99, 100, 1, deny));
		assert(!memcmp(&base.committed, &task.committed,
			       sizeof(base.committed)));
	}
}
/* The caller supplies a retained, committed scope-11 snapshot whose two
 * UID/epoch pairs are accepted for that scope. This fixture does NOT authenticate
 * that premise: the global accepted() callback above is not used by fallback,
 * and neither it nor these initialized descriptors prove scoped kernel authority.
 * The production begin helper must copy the exact descriptor before faulting. */
static void bounded_completion_unknown_controls(void)
{
	const struct se_snapshot snapshot = { .scope = 11,
					      .serial = 1,
					      .generation = 20,
					      .phase = SE_SNAPSHOT_ACTIVE,
					      .count = 2,
					      .execution_class = 1,
					      .metadata = {
						      .root_epochs = { 13, 14 },
						      .policy_uids = { 1, 2 },
						      .role_writers = 3,
						      .container_length = 1,
						      .container = { 'c' } } };
	for (int control = 0; control < 5; control++) {
		struct se_task_state task = { .flags = SE_TASK_QUALIFIED,
					      .physical_cookie = 99,
					      .scope_cookie = 11,
					      .eligibility_version = 1 };
		task.committed.version = control >= 3 ? ER_UNKNOWN - 1 : 7;
		task.committed.rows[0] = er_known_row(1, 13, 3);
		task.committed.rows[1] = er_known_row(2, 14, 7);
		task.committed.rows[2] = er_known_row(3, 15, 9); /* nonwriter */
		task.committed.rows[3] =
			er_known_row(1, 19, 8); /* provisional */
		if (control)
			task.committed.rows[0].knowledge = ER_ROLE_UNKNOWN;
		if (control == 1 || control == 3)
			task.committed.rows[1].knowledge = ER_ROLE_UNKNOWN;
		assert(!se_exec_begin_snapshot_locked(&task, 99, 100,
						      &snapshot));
		assert(task.exec.policy_count == 2 &&
		       task.exec.potential_writers == 3);
		assert(task.exec.policies[0].uid == 1 &&
		       task.exec.policies[0].epoch == 13);
		assert(task.exec.policies[1].uid == 2 &&
		       task.exec.policies[1].epoch == 14);
		se_exec_fault_locked(&task.exec);
		struct er_state expected = task.committed;
		int invalid = control ==
			      4; /* mixed Known/UNKNOWN at version ceiling */
		if (!invalid) {
			expected.rows[0].knowledge = ER_ROLE_UNKNOWN;
			expected.rows[1].knowledge = ER_ROLE_UNKNOWN;
			if (control == 0 || control == 2)
				expected.version++;
		}
		assert(se_exec_finish_bounded_locked(&task, 99, 100,
						     task.exec.sequence,
						     1) == invalid);
		/* Full-state comparison covers roles, nonwriters, provisional cells,
		 * all unused slots and a single (or no-op) version increment. */
		assert(!memcmp(&expected, &task.committed, sizeof(expected)));
		assert(!task.exec.owned);
		assert(!!(task.flags & SE_TASK_QUARANTINED) == invalid);
		assert(task.eligibility_version == (invalid ? 2U : 1U));
		struct se_task_state completed = task;
		assert(se_exec_finish_bounded_locked(
			       &task, 99, 100, task.exec.sequence, 1) == -1);
		assert(!memcmp(&completed, &task, sizeof(task)));
	}
}
/* Both legacy and opaque lexical locks must invoke these same pure semantic
 * mutations; neither helper may choose a verdict or borrow a route claim. */
static void common_exec_mutations(void)
{
	struct se_task_state task = {
		.flags = SE_TASK_LIVE,
		.eligibility_version = 7,
	};
	se_exec_owned_fault_locked(&task, 0x10);
	assert(task.flags == (SE_TASK_LIVE | SE_TASK_QUARANTINED) &&
	       task.eligibility_version == 8);
	task.exec = (struct se_exec_transaction){
		.owned = 1,
		.bprm = 0x20,
		.grants = 3,
	};
	se_exec_owned_fault_locked(&task, 0x10);
	assert(!task.exec.hard_fault && task.exec.grants == 3 &&
	       task.eligibility_version == 8);
	se_exec_note_prior_deny_locked(&task, 0x10);
	assert(!task.exec.known_deny && task.exec.grants == 3);
	se_exec_note_prior_deny_locked(&task, 0x20);
	assert(task.exec.known_deny && !task.exec.grants);
	task.exec.grants = 3;
	se_exec_owned_fault_locked(&task, 0x20);
	assert(task.exec.hard_fault && !task.exec.grants &&
	       task.eligibility_version == 8);
}
/* Differential check of the flattened role-fill step against the original
 * nested 8x16 loop (reference copied verbatim from before G005-B). */
static int reference_fill_roles(struct se_exec_work *work,
				struct fe_facts *facts)
{
	facts->role_count = 0;
	if (work->transaction.eligibility_version !=
		    work->eligibility_version ||
	    work->view.work.error || !work->view.work.prepared)
		return -1;
	if (work->flags != SE_TASK_QUALIFIED)
		return 0;
	for (__u32 i = 0; i < 8; i++) {
		if (i >= work->transaction.policy_count)
			break;
		const struct se_exec_policy *p = &work->transaction.policies[i];
		int present = 0;
		for (__u32 j = 0; j < 16; j++) {
			const struct er_row *r = &work->view.work.rows[j];
			if ((work->view.accepted_mask & (1U << j)) &&
			    r->uid == p->uid && r->epoch == p->epoch) {
				present++;
				if (!er_role_known(r))
					continue;
				if (facts->role_count >= 8)
					return -1;
				facts->roles[facts->role_count++] =
					(struct fe_role){ r->uid, r->role };
			}
		}
		if (present != 1) {
			facts->role_count = 0;
			return -1;
		}
	}
	return 0;
}

static void flattened_role_fill_differential(void)
{
	unsigned seed = 12345;
	unsigned cases[4] = { 0 };
	for (int round = 0; round < 200000; round++) {
		struct se_exec_work work = {};
		seed = seed * 1103515245u + 12345u;
		work.eligibility_version =
			work.transaction.eligibility_version = 1;
		work.view.work.prepared = 1;
		work.flags = (seed >> 7) % 17 ? SE_TASK_QUALIFIED : 0;
		work.transaction.policy_count =
			(seed >> 11) % 10; /* includes >8 */
		for (int i = 0; i < 8; i++) {
			seed = seed * 1103515245u + 12345u;
			work.transaction.policies[i].uid = 1 + (seed >> 9) % 4;
			work.transaction.policies[i].epoch =
				1 + (seed >> 13) % 2;
		}
		for (int j = 0; j < 16; j++) {
			seed = seed * 1103515245u + 12345u;
			work.view.work.rows[j].uid = 1 + (seed >> 9) % 4;
			work.view.work.rows[j].epoch = 1 + (seed >> 13) % 2;
			work.view.work.rows[j].role = (seed >> 17) % 5;
			work.view.work.rows[j].knowledge = (seed >> 21) % 3;
			if ((seed >> 24) % 3)
				work.view.accepted_mask |= 1U << j;
		}
		struct fe_facts a = { .role_count = 77 },
				b = { .role_count = 77 };
		struct se_exec_work wa = work, wb = work;
		int ra = reference_fill_roles(&wa, &a);
		int rb = se_exec_fill_roles_preclassified(&wb, &b);
		assert(ra == rb && a.role_count == b.role_count);
		for (__u32 k = 0; k < a.role_count && k < 8; k++)
			assert(a.roles[k].policy_uid == b.roles[k].policy_uid &&
			       a.roles[k].role == b.roles[k].role);
		cases[ra ? (a.role_count ? 2 : 1) : (a.role_count ? 3 : 0)]++;
	}
	/* Both error kinds (cleared and overflow-with-roles) and both success
	 * kinds were exercised. */
	assert(cases[0] && cases[1] && cases[3]);
	printf("flattened role fill differential: ok %u/%u/%u/%u\n", cases[0],
	       cases[1], cases[2], cases[3]);
}

int main(void)
{
	flattened_role_fill_differential();
	common_exec_mutations();
#if defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE) || \
	defined(ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE)
	typed_task_wire_overlay();
#endif
#if defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE) || \
	defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE)
	typed_work_wire_overlay();
#endif
#if defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE)
	typed_work_catalogue_parity();
#endif
	preclassified_exec_equivalence();
	bounded_completion_targets();
	bounded_completion_unknown_controls();
	configure(11);
	struct se_task_state task = { .flags = SE_TASK_QUALIFIED,
				      .physical_cookie = 99,
				      .scope_cookie = 11,
				      .eligibility_version = 1 };
	task.committed.rows[0] = er_known_row(1, 13, 3);
	struct se_route_anchor anchor = { .incarnation = 1,
					  .scope = 11,
					  .cgroup_identity = 7,
					  .payload_generation = 20,
					  .active_serial = 1,
					  .execution_class = 1,
					  .phase = SE_ROUTE_ACTIVE };
	struct se_binding_snapshots binding = { .scope = 11,
						.generation = 20,
						.active_serial = 1 };
	binding.records[0] = (struct se_snapshot){ .scope = 11,
						   .serial = 1,
						   .generation = 20,
						   .phase = SE_SNAPSHOT_ACTIVE,
						   .execution_class = 1 };
	struct se_route_claim early = {};
	assert(se_route_claim_locked(&anchor, se_route_locator(0, 1), 7,
				     &early) == SE_ROUTE_OWNED);
	assert(!se_exec_begin_locked(&task, 99, 101, &view, 1, 1));
	__u64 invocation = task.exec.sequence;
	assert(!se_exec_reader_attach_locked(&anchor, &binding, &task, &early,
					     99, invocation));
	assert(!anchor.early_claims && binding.records[0].claims == 1);
	assert(se_exec_reader_authority_locked(&anchor, &binding, &task, 0, 11,
					       20, 99, invocation, 1));
	assert(!se_exec_reader_authority_locked(&anchor, &binding, &task, 0, 11,
						20, 99, invocation + 1, 1));
	assert(!se_exec_reader_authority_locked(&anchor, &binding, &task, 0, 11,
						20, 98, invocation, 1));
	struct se_binding_snapshots unpinned = binding;
	unpinned.records[0].claims = 0;
	assert(!se_exec_reader_authority_locked(&anchor, &unpinned, &task, 0,
						11, 20, 99, invocation, 1));
	struct se_route_anchor replaced = anchor;
	replaced.incarnation = 0;
	assert(!se_exec_reader_authority_locked(&replaced, &binding, &task, 0,
						11, 20, 99, invocation, 1));
	propose(&task);
	/* Interpreter re-entry retains the complete original transaction and claim,
	 * including nonzero proposals; a distinct bprm cannot replace either. */
	struct se_task_state interpreter_before = task;
	struct se_binding_snapshots binding_before = binding;
	struct se_route_anchor anchor_before = anchor;
	assert(task.exec.writes && task.exec.witnesses[0] == 7);
	assert(se_exec_begin_locked(&task, 99, 101, &view, 1, 0) == 1);
	assert(!memcmp(&task, &interpreter_before, sizeof(task)));
	assert(se_exec_begin_locked(&task, 99, 999, &view, 1, 1) < 0);
	assert(!memcmp(&task, &interpreter_before, sizeof(task)));
	assert(!memcmp(&binding, &binding_before, sizeof(binding)));
	assert(!memcmp(&anchor, &anchor_before, sizeof(anchor)));
	se_exec_snapshot_locked(&task, 1, &work);
	assert(!se_exec_completion_prepare(&work, 1));
	struct se_exec_work old_completion = work;
	/* Candidate-only staging after completion snapshot must survive publication. */
	task.committed.rows[1] = er_known_row(2, 21, 9);
	assert(!se_exec_complete_locked(&task, &work, 1));
	assert(!se_exec_reader_release_locked(&binding, &task, 99, invocation));
	assert(!se_exec_reader_authority_locked(&anchor, &binding, &task, 0, 11,
						20, 99, invocation, 1));
	assert(se_exec_reader_release_locked(&binding, &task, 99, invocation));
	assert(!binding.records[0].claims);
	assert(task.committed.rows[0].role == 7 &&
	       task.committed.rows[1].uid == 2);
	assert(!se_exec_begin_locked(&task, 99, 102, &view, 1, 1));
	__u64 new_invocation = task.exec.sequence;
	assert(new_invocation != invocation);
	assert(se_route_claim_locked(&anchor, se_route_locator(0, 1), 7,
				     &early) == SE_ROUTE_OWNED);
	assert(anchor.early_claims == 1 && !binding.records[0].claims);
	assert(!se_exec_reader_attach_locked(&anchor, &binding, &task, &early,
					     99, new_invocation));
	assert(!anchor.early_claims && binding.records[0].claims == 1);
	propose(&task);
	/* Replayed completion/release must not publish or refund the NEW owner. */
	struct se_task_state replacement_before = task;
	binding_before = binding;
	anchor_before = anchor;
	assert(se_exec_complete_locked(&task, &old_completion, 1));
	assert(se_exec_reader_release_locked(&binding, &task, 99, invocation));
	assert(!memcmp(&task, &replacement_before, sizeof(task)));
	assert(!memcmp(&binding, &binding_before, sizeof(binding)));
	assert(!memcmp(&anchor, &anchor_before, sizeof(anchor)));
	assert(task.reader_invocation == new_invocation && task.reader.owned &&
	       binding.records[0].claims == 1 && !anchor.early_claims);
	se_exec_fault_locked(&task.exec);
	finish(&task, 1);
	assert(!se_exec_reader_release_locked(&binding, &task, 99,
					      new_invocation));
	assert(!task.reader.owned && !task.reader_invocation &&
	       !binding.records[0].claims && !anchor.early_claims);
	assert(se_exec_reader_release_locked(&binding, &task, 99,
					     new_invocation));
	assert(task.committed.rows[0].knowledge == ER_ROLE_UNKNOWN &&
	       task.committed.rows[0].role == 7);
	assert(!se_exec_begin_locked(&task, 99, 103, &view, 1, 1));
	se_exec_snapshot_locked(&task, 1, &work);
	assert(!se_exec_fill_roles(&work, &facts));
	assert(!facts.role_count);
	propose(&task);
	finish(&task, 1);
	assert(er_role_known(&task.committed.rows[0]));
	struct er_state before = task.committed;
	assert(!se_exec_begin_locked(&task, 99, 104, &view, 1, 1));
	propose(&task);
	se_exec_fault_locked(&task.exec);
	finish(&task, 0);
	assert(!memcmp(&before, &task.committed, sizeof(before)));
	assert(!se_exec_begin_locked(&task, 99, 105, &view, 1, 1));
	propose(&task);
	struct fe_decision deny = { .deny = 1, .mode = 1 };
	assert(!se_exec_propose_locked(&task.exec, &deny));
	finish(&task, 1);
	assert(!memcmp(&before, &task.committed, sizeof(before)));
	/* Foreign scope cannot consume this physical task's history. */
	configure(12);
	view.policies[0].root_epoch =
		13; /* even equal UID/epoch cannot cross scope */
	assert(se_exec_begin_locked(&task, 99, 106, &view, 1, 1));
	configure(12);
	struct se_task_state neighbor = { .flags = SE_TASK_QUALIFIED,
					  .physical_cookie = 100,
					  .scope_cookie = 12,
					  .eligibility_version = 1 };
	neighbor.committed.rows[0] = er_known_row(1, 4, 3);
	assert(!se_exec_begin_locked(&neighbor, 100, 106, &view, 1, 1));
	propose(&neighbor);
	finish(&neighbor, 1);
	assert(neighbor.committed.rows[0].epoch == 4 &&
	       task.committed.rows[0].epoch == 13);
	configure(11);
	assert(!se_exec_begin_locked(&task, 99, 107, &view, 1, 1));
	propose(&task);
	se_exec_snapshot_locked(&task, 1, &work);
	assert(!se_exec_completion_prepare(&work, 1));
	task.eligibility_version++;
	assert(se_exec_complete_locked(&task, &work, 1));
	assert(!memcmp(&before, &task.committed, sizeof(before)));
	task.exec.owned = 0;
	assert(!se_exec_begin_locked(&task, 99, 109, &view, 1, 1));
	propose(&task);
	task.eligibility_version++;
	se_exec_snapshot_locked(&task, 1, &work);
	assert(se_exec_completion_prepare(&work, 1));
	assert(!se_exec_abort_locked(&task, 99, 109, task.exec.sequence));
	task.flags = SE_TASK_QUARANTINED | SE_TASK_LIVE;
	assert(se_exec_begin_locked(&task, 99, 108, &view, 2, 1));
	assert(!se_exec_begin_locked(&task, 99, 108, &view, 1, 1));
	se_exec_snapshot_locked(&task, 1, &work);
	assert(!se_exec_fill_roles(&work, &facts));
	assert(!facts.role_count);
	/* Returning A after quarantine cannot regain role authority. */
	assert(!se_exec_abort_locked(&task, 99, 108, task.exec.sequence));
	assert(se_exec_begin_locked(&task, 99, 110, &view, 2, 1));
	struct se_task_state missing = { .flags = SE_TASK_QUALIFIED,
					 .physical_cookie = 101,
					 .scope_cookie = 11,
					 .eligibility_version = 1 };
	assert(!se_exec_begin_locked(&missing, 101, 111, &view, 2, 1));
	se_exec_snapshot_locked(&missing, 1, &work);
	assert(se_exec_fill_roles(&work, &facts));
	/* Immutable class governs real failures and never replaces prior denials. */
	struct fe_decision empty = {};
	assert(fe_lsm_verdict(1, -13, 1, &empty) == -13);
	assert(fe_lsm_verdict(1, 0, 1, &empty) == 0);
	assert(fe_lsm_verdict(2, 0, 1, &empty) < 0);
	return 0;
}
