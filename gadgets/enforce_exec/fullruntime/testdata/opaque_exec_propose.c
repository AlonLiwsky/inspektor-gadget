/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Reuse the real candidate ownership fixture, not replacement handle stubs.
 * Policy/receipt inputs below are synthetic host evidence, not admission. */
#define ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE 1
#define ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE 1
#define main opaque_locator_fixture_main
#include "../../full/test/host/opaque_locator_candidate.c"
#undef main
#include "shared_pool_opaque_exec_propose_candidate.h"
#include "shared_pool_opaque_exec_prepare_candidate.h"

struct proposal_fixture {
	__u64 key;
	struct se_ol_payload_handle owner;
	struct se_owk_ticket ticket;
	struct se_owk_semantic_handle handle;
	struct se_invocation *work;
	struct se_exec_terminal_receipt receipt;
};

static void proposal_setup(struct proposal_fixture *f)
{
	*f = (struct proposal_fixture){};
	f->key = seed_live_opaque_task_for_open();
	assert(se_ol_task_open(&f->key, &f->owner) == SE_OL_OK);
	routes[0] = (struct se_route_anchor){
		.incarnation = 1,
		.cgroup_identity = 7,
		.scope = 10,
		.payload_slot = 0,
		.payload_generation = 13,
		.active_serial = 1,
		.execution_class = 1,
		.phase = SE_ROUTE_ACTIVE,
	};
	bindings[0] = (struct se_binding_snapshots){
		.scope = 10,
		.generation = 13,
		.active_serial = 1,
		.records = { { .scope = 10,
			       .serial = 1,
			       .generation = 13,
			       .phase = SE_SNAPSHOT_ACTIVE,
			       .count = 1,
			       .execution_class = 1,
			       .metadata = { .root_epochs = { 13 },
					     .policy_uids = { 1 },
					     .role_writers = 1,
					     .container_length = 1,
					     .container = "/" } } },
	};
	struct se_task_state *task = &payloads[0].semantic;
	task->committed.version = 7;
	task->committed.rows[0] = er_known_row(1, 13, 3);
	/* WORK and exec sequences are different domains; do not conflate them. */
	metas[0].next_work_sequence = 40;
	struct se_route_claim claim = {};
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &claim) == SE_ROUTE_OWNED);
	bpf_spin_unlock(&routes[0].lock);
	__u64 invocation = 0;
	assert(se_op_exec_reader_begin(&f->owner, &claim, &bindings[0], 0x1234,
				       &invocation) == SE_OL_OK);
	f->receipt = (struct se_exec_terminal_receipt){
		.physical = f->key,
		.bprm = 0x1234,
		.cookie = f->owner.lease.cookie,
		.locator = f->owner.lease.locator,
		.invocation = invocation,
		.scope = 10,
		.generation = 13,
		.phase = SE_EXEC_TERMINAL_REGISTERED,
	};
	__u32 slot = 0;
	assert(se_owk_bind_owner(&f->owner) == SE_OL_OK);
	assert(se_owk_choose(&f->owner, &slot) == SE_OL_OK);
	assert(se_owk_begin(&f->owner, slot, &f->ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&f->owner, &f->ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&f->owner, &f->ticket) == SE_OL_OK);
	assert(se_owk_commit(&f->owner, &f->ticket) == SE_OL_OK);
	assert(se_owk_semantic_open(&f->owner, &f->ticket, &f->handle,
				    &f->work) == SE_OL_OK);
	assert(f->work->sequence == 41 && invocation == 1);
	struct se_task_state *locked = 0;
	assert(se_op_task_semantic_begin(&f->owner, &locked) == SE_OL_OK);
	se_exec_snapshot_locked(locked, 13, &f->work->history);
	se_op_task_semantic_end(&f->owner, &locked);
	f->work->view = (struct se_policy_view){
		.scope_cookie = 10,
		.ready = 1,
		.header = { .generation = 13, .policies = 1, .rule_base = 9 },
		.policies = { { .uid = 1,
				.root_epoch = 13,
				.root_role = 3,
				.mode = 1,
				.fallback = 1 } },
	};
	struct observation *o = &f->work->observation;
	assert(!fe_stage_begin(&f->work->view, &o->facts, &o->evaluator,
			       &o->stage_cursor));
	assert(!fe_stage_finish(&f->work->view, &o->evaluator,
				&o->stage_cursor));
}

static void proposal_close(struct proposal_fixture *f)
{
	assert(f->owner.lease.held && f->ticket.held && f->handle.held);
	assert(!held && !lock_errors);
	assert(se_owk_semantic_done(&f->handle, &f->work) == SE_OL_OK);
	assert(se_ol_payload_close(&f->owner) == SE_OL_OK);
}

static int propose(struct proposal_fixture *f, int prior)
{
	return se_owk_exec_propose_reader(&f->handle, &f->receipt, f->key,
					  prior);
}

static void success_and_replay(void)
{
	struct proposal_fixture f;
	proposal_setup(&f);
	f.work->observation.evaluator.decision.proposed_roles[0] = 9;
	assert(propose(&f, 0) == SE_OL_OK);
	assert(payloads[0].semantic.exec.grants == 1 &&
	       payloads[0].semantic.exec.witnesses[0] == 9);
	struct se_exec_transaction after = payloads[0].semantic.exec;
	assert(propose(&f, 0) == SE_OL_CORRUPT);
	assert(!memcmp(&after, &payloads[0].semantic.exec, sizeof(after)));
	assert(payloads[0].semantic.committed.rows[0].role == 3);
	proposal_close(&f);
}

static void stale_inputs_do_not_mutate(void)
{
	for (unsigned which = 0; which < 13; which++) {
		struct proposal_fixture f;
		proposal_setup(&f);
		switch (which) {
		case 0:
			f.receipt.cookie++;
			break;
		case 1:
			f.receipt.locator++;
			break;
		case 2:
			f.receipt.invocation++;
			break;
		case 3:
			f.receipt.generation++;
			break;
		case 4:
			f.receipt.bprm++;
			break;
		case 5:
			f.receipt.scope++;
			break;
		case 6:
			f.receipt.physical++;
			break;
		case 7:
			f.work->observation.stage_cursor.state = FE_STAGE_READY;
			break;
		case 8:
			f.work->observation.stage_cursor.generation++;
			break;
		case 9:
			f.work->view.policies[0].uid++;
			break;
		case 10:
			payloads[0].semantic.eligibility_version++;
			break;
		case 11:
			payloads[0].semantic.committed.version++;
			break;
		case 12:
			f.work->history.transaction.sequence++;
			break;
		}
		struct se_task_state before = payloads[0].semantic;
		assert(propose(&f, 0) != SE_OL_OK);
		assert(!memcmp(&before, &payloads[0].semantic, sizeof(before)));
		proposal_close(&f);
	}
}

static void uncertainty_prior_and_failed_proposal(void)
{
	struct proposal_fixture f;
	proposal_setup(&f);
	struct fe_decision *d = &f.work->observation.evaluator.decision;
	d->proposed_roles[0] = 9;
	d->audit_unknown = 1U << FE_ROLE_UNCERTAIN_SHIFT;
	assert(propose(&f, 0) == SE_OL_OK);
	assert(!payloads[0].semantic.exec.grants &&
	       (payloads[0].semantic.exec.uncertain & 1));
	proposal_close(&f);
	proposal_setup(&f);
	f.work->observation.evaluator.decision.proposed_roles[0] = 9;
	assert(propose(&f, -13) == SE_OL_OK);
	assert(payloads[0].semantic.exec.known_deny &&
	       !payloads[0].semantic.exec.grants);
	proposal_close(&f);
	proposal_setup(&f);
	f.work->observation.evaluator.decision.audit_unknown = 1U << 29;
	assert(propose(&f, 0) == SE_OL_CORRUPT);
	assert(payloads[0].semantic.exec.hard_fault &&
	       payloads[0].semantic.exec.owned &&
	       payloads[0].semantic.reader.owned);
	assert(f.work->observation.stage_cursor.state ==
	       SE_OWK_PROPOSAL_CONSUMED);
	proposal_close(&f);
}

static void stale_work_lease_preserves_cleanup(void)
{
	struct proposal_fixture f;
	proposal_setup(&f);
	struct se_exec_transaction before = payloads[0].semantic.exec;
	f.ticket.cookie++;
	assert(propose(&f, 0) == SE_OL_CORRUPT);
	f.ticket.cookie--;
	f.ticket.owner_locator++;
	assert(propose(&f, 0) == SE_OL_CORRUPT);
	f.ticket.owner_locator--;
	work_metas[0].phase = SE_OWK_DONE;
	assert(propose(&f, 0) == SE_OL_CORRUPT);
	work_metas[0].phase = SE_OWK_ACTIVE;
	assert(!memcmp(&before, &payloads[0].semantic.exec, sizeof(before)));
	assert(f.work->observation.stage_cursor.state == FE_STAGE_FINISHED);
	proposal_close(&f);
}

static void incomplete_finished_audit_unknown_is_rejected(void)
{
	struct proposal_fixture f;
	proposal_setup(&f);
	f.work->view.header.rules = 1;
	f.work->observation.stage_cursor.rules = 1;
	f.work->observation.evaluator.decision.error = FE_AUDIT_UNKNOWN;
	struct se_task_state before = payloads[0].semantic;
	assert(propose(&f, 0) == SE_OL_CORRUPT);
	assert(!memcmp(&before, &payloads[0].semantic, sizeof(before)));
	assert(f.work->observation.stage_cursor.state == FE_STAGE_FINISHED);
	proposal_close(&f);
}

static void repeated_interpreter_work_rechecks_snapshot(void)
{
	for (int prior_between = 0; prior_between < 2; prior_between++) {
		struct proposal_fixture f;
		proposal_setup(&f);
		struct se_exec_work stale = f.work->history;
		struct se_policy_view view = f.work->view;
		f.work->observation.evaluator.decision.proposed_roles[0] = 9;
		assert(propose(&f, 0) == SE_OL_OK);
		assert(se_owk_semantic_done(&f.handle, &f.work) == SE_OL_OK);
		/* Another interpreter check keeps the exec/reader, but owns a new
		 * WORK and must snapshot the already accumulated transaction. */
		f.ticket = (struct se_owk_ticket){};
		__u32 slot = 0;
		assert(se_owk_choose(&f.owner, &slot) == SE_OL_OK && slot == 1);
		assert(se_owk_begin(&f.owner, slot, &f.ticket) == SE_OL_OK);
		assert(se_owk_attach_owner(&f.owner, &f.ticket) == SE_OL_OK);
		assert(se_owk_initialize_payload(&f.owner, &f.ticket) ==
		       SE_OL_OK);
		assert(se_owk_commit(&f.owner, &f.ticket) == SE_OL_OK);
		assert(se_owk_semantic_open(&f.owner, &f.ticket, &f.handle,
					    &f.work) == SE_OL_OK);
		assert(f.work->sequence == 42 && f.receipt.invocation == 1);
		f.work->view = view;
		struct observation *o = &f.work->observation;
		assert(!fe_stage_begin(&f.work->view, &o->facts, &o->evaluator,
				       &o->stage_cursor));
		assert(!fe_stage_finish(&f.work->view, &o->evaluator,
					&o->stage_cursor));
		f.work->history = stale;
		struct se_exec_transaction before = payloads[0].semantic.exec;
		assert(propose(&f, 0) == SE_OL_STALE);
		assert(!memcmp(&before, &payloads[0].semantic.exec,
			       sizeof(before)));
		struct se_task_state *task = 0;
		assert(se_op_task_semantic_begin(&f.owner, &task) == SE_OL_OK);
		se_exec_snapshot_locked(task, 13, &f.work->history);
		se_op_task_semantic_end(&f.owner, &task);
		if (prior_between) {
			assert(se_op_task_note_prior_deny(
				       &f.owner, f.receipt.bprm) == SE_OL_OK);
			assert(propose(&f, -13) == SE_OL_STALE);
			assert(payloads[0].semantic.exec.known_deny &&
			       !payloads[0].semantic.exec.grants);
			assert(se_op_task_semantic_begin(&f.owner, &task) ==
			       SE_OL_OK);
			se_exec_snapshot_locked(task, 13, &f.work->history);
			se_op_task_semantic_end(&f.owner, &task);
		}
		o->evaluator.decision.proposed_roles[0] = 9;
		assert(propose(&f, prior_between ? -13 : 0) == SE_OL_OK);
		assert(payloads[0].semantic.exec.known_deny ==
		       (__u32)prior_between);
		assert(payloads[0].semantic.exec.grants ==
		       (prior_between ? 0U : 1U));
		before = payloads[0].semantic.exec;
		assert(propose(&f, 0) == SE_OL_CORRUPT);
		assert(!memcmp(&before, &payloads[0].semantic.exec,
			       sizeof(before)));
		assert(payloads[0].semantic.committed.rows[0].role == 3);
		proposal_close(&f);
	}
}

static void preparation_inputs(struct proposal_fixture *f)
{
	proposal_setup(f);
	/* Birth alone is live but not role-qualified. This positive fixture
	 * explicitly supplies qualification; preparation must never infer it. */
	payloads[0].semantic.flags = SE_TASK_QUALIFIED;
	f->work->history = (struct se_exec_work){};
	f->work->observation = (struct observation){};
	opaque_catalogue_epoch = 13;
}

static void reader_work_preparation(void)
{
	struct proposal_fixture f;
	preparation_inputs(&f);
	struct se_task_state before = payloads[0].semantic;
	assert(se_owk_exec_prepare_reader(&f.handle, &f.receipt, f.key) ==
	       SE_OL_OK);
	assert(f.work->observation.facts.role_count == 1);
	assert(f.work->observation.facts.roles[0].policy_uid == 1 &&
	       f.work->observation.facts.roles[0].role == 3);
	assert(f.work->history.transaction.sequence == f.receipt.invocation);
	assert(!memcmp(&before, &payloads[0].semantic, sizeof(before)));
	assert(se_owk_exec_prepare_reader(&f.handle, &f.receipt, f.key) !=
	       SE_OL_OK);
	proposal_close(&f);
	preparation_inputs(&f);
	payloads[0].semantic.flags = SE_TASK_LIVE;
	before = payloads[0].semantic;
	assert(se_owk_exec_prepare_reader(&f.handle, &f.receipt, f.key) ==
	       SE_OL_OK);
	assert(!f.work->observation.facts.role_count);
	assert(!memcmp(&before, &payloads[0].semantic, sizeof(before)));
	proposal_close(&f);
	for (unsigned which = 0; which < 12; which++) {
		preparation_inputs(&f);
		switch (which) {
		case 0:
			f.receipt.cookie++;
			break;
		case 1:
			f.receipt.locator++;
			break;
		case 2:
			f.receipt.physical++;
			break;
		case 3:
			f.receipt.bprm++;
			break;
		case 4:
			f.receipt.invocation++;
			break;
		case 5:
			f.receipt.generation++;
			break;
		case 6:
			f.receipt.phase = SE_EXEC_TERMINAL_SUCCESS;
			break;
		case 7:
			f.work->view.policies[0].uid++;
			break;
		case 8:
			opaque_catalogue_epoch = ER_UNKNOWN;
			break;
		case 9:
			bindings[0].records[0].claims = 0;
			break;
		case 10:
			f.ticket.cookie++;
			break;
		case 11:
			f.work->observation.stage_cursor.state =
				FE_STAGE_ACTIVE;
			break;
		}
		before = payloads[0].semantic;
		assert(se_owk_exec_prepare_reader(&f.handle, &f.receipt,
						  f.key) != SE_OL_OK);
		assert(!f.work->observation.facts.role_count);
		assert(!memcmp(&before, &payloads[0].semantic, sizeof(before)));
		if (which == 10)
			f.ticket.cookie--;
		proposal_close(&f);
	}
	opaque_catalogue_epoch = 13;
}

int main(void)
{
	reader_work_preparation();
	success_and_replay();
	stale_inputs_do_not_mutate();
	uncertainty_prior_and_failed_proposal();
	stale_work_lease_preserves_cleanup();
	incomplete_finished_audit_unknown_is_rejected();
	repeated_interpreter_work_rechecks_snapshot();
	puts("opaque exec proposal adapter: PASS");
	return 0;
}
