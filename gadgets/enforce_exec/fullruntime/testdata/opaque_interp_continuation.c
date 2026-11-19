/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* G019 gap 4 (review H1) host contract: the same-bprm interpreter
 * continuation's stage classes, reader classification relaxation, pending
 * receipt classification, failure-frame and WORK identity predicates, and
 * accumulated proposals, on the real candidate ownership fixture.
 * TestOpaqueInterpContinuationHostContract compiles it at -O0/-O2, with
 * ASan/UBSan, and against source mutations that must each fail it. */
#define ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_CONTINUATION_CANDIDATE 1
#define ENFORCE_EXEC_STAGED_EVALUATOR_CANDIDATE 1
#define ENFORCE_EXEC_SUSPENDED_WORK_READ_CANDIDATE 1
#define ENFORCE_EXEC_SUSPENDED_EVAL_READER_DIAGNOSTIC 1
#define SE_OWK_STAGE_CLASSES 1
/* The verdict object's evaluation view stage: any pass's 3p+2. */
#define SE_OWK_EVAL_VIEW_STAGE SE_OWK_STAGE_CLASS(2, 5)
#define main opaque_locator_fixture_main
#include "../../full/test/host/opaque_locator_candidate.c"
#undef main
#include "shared_pool_opaque_exec_propose_candidate.h"
#include "shared_pool_opaque_exec_prepare_candidate.h"
/* The failure-frame types of the verdict object (same members). */
struct se_failure_outer_frame {
	__u64 physical, bprm, cookie, locator, invocation, scope, generation;
	__u32 depth, uncertain;
};
struct se_failure_handler_frame {
	__u64 bprm;
	__u32 depth, uncertain;
};
#include "shared_exec_interp_continuation.h"

#define PREPARE SE_OWK_STAGE_CLASS(1, 5)
#define EVAL SE_OWK_STAGE_CLASS(2, 5)
#define TERMINAL SE_OWK_STAGE_CLASS(0, 5)

static __u64 key;
static struct se_ol_payload_handle owner;

static void open_owner(void)
{
	owner = (struct se_ol_payload_handle){};
	assert(se_ol_task_open(&key, &owner) == SE_OL_OK);
}
static void close_owner(void)
{
	assert(se_ol_payload_close(&owner) == SE_OL_OK);
	owner = (struct se_ol_payload_handle){};
	assert(!held && !lock_errors);
}
static void start_work(struct se_owk_ticket *ticket)
{
	*ticket = (struct se_owk_ticket){};
	assert(se_owk_bind_owner(&owner) == SE_OL_OK);
	assert(se_owk_begin(&owner, 0, ticket) == SE_OL_OK);
	assert(se_owk_attach_owner(&owner, ticket) == SE_OL_OK);
	assert(se_owk_initialize_payload(&owner, ticket) == SE_OL_OK);
	assert(se_owk_commit(&owner, ticket) == SE_OL_OK);
}
/* A fresh TASK whose only WORK is suspended at exactly `target`, reached by
 * the monotone +1 chain through exact single-stage resumes. */
static void walk_to(__u32 target)
{
	key = seed_live_opaque_task_for_open();
	struct se_owk_ticket ticket;
	open_owner();
	start_work(&ticket);
	assert(se_owk_suspend(&owner, &ticket, 1) == SE_OL_OK);
	close_owner();
	for (__u32 stage = 1; stage < target; stage++) {
		open_owner();
		ticket = (struct se_owk_ticket){};
		assert(se_owk_resume(&owner, stage, &ticket) == SE_OL_OK &&
		       ticket.continuation_stage == stage);
		assert(se_owk_suspend(&owner, &ticket, stage + 1) == SE_OL_OK);
		close_owner();
	}
	assert(work_metas[0].phase == SE_OWK_SUSPENDED &&
	       work_metas[0].continuation_stage == target);
}
static void assert_untouched(__u32 stage)
{
	assert(work_metas[0].phase == SE_OWK_SUSPENDED &&
	       !work_metas[0].active_leases &&
	       work_metas[0].continuation_stage == stage &&
	       !work_metas[0].continuation_reserved &&
	       !work_accounts[0].fault && !held && !lock_errors);
}

/* Pass p: prepare 3p+1, evaluation 3p+2, terminal 3p+3, p = 0..5. */
static void stage_arithmetic(void)
{
	for (__u32 p = 0; p < SE_OWK_EXEC_PASSES; p++) {
		for (__u32 r = 0; r < 3; r++) {
			__u32 stage = 3 * p + (r ? r : 3);
			for (__u32 q = 0; q < 3; q++)
				assert(se_owk_stage_matches(
					       stage,
					       SE_OWK_STAGE_CLASS(q, 5)) ==
				       (q == r));
			/* A lower pass bound excludes the later passes only. */
			assert(se_owk_stage_matches(stage,
						    SE_OWK_STAGE_CLASS(r, p)));
			if (p)
				assert(!se_owk_stage_matches(
					stage, SE_OWK_STAGE_CLASS(r, p - 1)));
			assert(se_owk_stage_matches(stage, stage) &&
			       !se_owk_stage_matches(stage, stage + 1));
		}
	}
	assert(se_owk_stage_class_last(PREPARE) == 16 &&
	       se_owk_stage_class_last(EVAL) == 17 &&
	       se_owk_stage_class_last(TERMINAL) == 18);
	for (__u32 stage = 19; stage <= SE_OWK_CONTINUATION_MAX; stage++)
		for (__u32 r = 0; r < 3; r++)
			assert(!se_owk_stage_matches(stage,
						     SE_OWK_STAGE_CLASS(r, 5)));
	for (__u32 r = 0; r < 3; r++)
		assert(!se_owk_stage_matches(0, SE_OWK_STAGE_CLASS(r, 5)));
	/* Only a bounded class or a plain 1..MAX stage is a valid input. */
	for (__u32 r = 0; r < 3; r++)
		assert(se_owk_stage_expected_valid(SE_OWK_STAGE_CLASS(r, 5)) &&
		       !se_owk_stage_expected_valid(SE_OWK_STAGE_CLASS(r, 6)));
	assert(!se_owk_stage_expected_valid(SE_OWK_STAGE_CLASS(3, 1)) &&
	       !se_owk_stage_expected_valid(SE_OWK_STAGE_CLASS(1, 5) |
					    0x200U) &&
	       !se_owk_stage_expected_valid(0) &&
	       se_owk_stage_expected_valid(1) &&
	       se_owk_stage_expected_valid(SE_OWK_CONTINUATION_MAX) &&
	       !se_owk_stage_expected_valid(SE_OWK_CONTINUATION_MAX + 1));
	/* A continuation resumes its predecessor's terminal stage 3p and runs
	 * pass p; pass 6 would be exec_binprm depth 6, which is -ELOOP. */
	for (__u32 p = 1; p < SE_OWK_EXEC_PASSES; p++)
		assert(se_exec_continue_pass(3 * p, SE_OWK_EXEC_PASSES) == p);
	assert(!se_exec_continue_pass(18, SE_OWK_EXEC_PASSES) &&
	       !se_exec_continue_pass(21, SE_OWK_EXEC_PASSES) &&
	       !se_exec_continue_pass(0, SE_OWK_EXEC_PASSES) &&
	       !se_exec_continue_pass(4, SE_OWK_EXEC_PASSES) &&
	       !se_exec_continue_pass(5, SE_OWK_EXEC_PASSES) &&
	       !se_exec_continue_pass(3, 1));
	assert(SE_OWK_STAGE_CLASS(0, 5) != SE_OWK_STAGE_CLASS(1, 5));
}

/* Every stage 1..18 resumes under exactly its own class and replays any
 * other class as a non-mutating STALE; the resumed ticket carries the
 * actual stage, so the successor suspends to exactly stage + 1. The
 * failure cleanup cascade (evaluation, prepare, terminal class) consumes
 * exactly one WORK at any stage. */
static void every_stage_resumes_its_class_only(void)
{
	const __u32 tokens[3] = { TERMINAL, PREPARE, EVAL };
	for (__u32 stage = 1; stage <= 18; stage++) {
		walk_to(stage);
		open_owner();
		for (__u32 r = 0; r < 3; r++) {
			if (r == stage % 3)
				continue;
			struct se_owk_ticket wrong = {};
			assert(se_owk_resume(&owner, tokens[r], &wrong) ==
				       SE_OL_STALE &&
			       !wrong.held && !wrong.cookie);
			assert_untouched(stage);
		}
		struct se_owk_ticket ticket = {};
		int resumed = 0;
		const __u32 cascade[3] = { EVAL, PREPARE, TERMINAL };
		for (__u32 i = 0; i < 3; i++) {
			if (resumed)
				break;
			ticket = (struct se_owk_ticket){};
			resumed = se_owk_resume(&owner, cascade[i], &ticket) ==
				  SE_OL_OK;
			assert(resumed == (cascade[i] == tokens[stage % 3]));
		}
		assert(resumed && ticket.held &&
		       ticket.continuation_stage == stage &&
		       work_metas[0].phase == SE_OWK_ACTIVE);
		struct se_owk_ticket replay = {};
		assert(se_owk_resume(&owner, tokens[stage % 3], &replay) ==
			       SE_OL_STALE &&
		       !replay.held && !work_accounts[0].fault);
		/* The class never relaxes the monotone +1 suspension. */
		assert(se_owk_suspend(&owner, &ticket, stage + 2) ==
			       SE_OL_CORRUPT &&
		       ticket.held == 1 && !work_accounts[0].fault);
		assert(se_owk_suspend(&owner, &ticket, stage) ==
			       SE_OL_CORRUPT &&
		       ticket.held == 1 && !work_accounts[0].fault);
		assert(se_owk_done(&owner, &ticket) == SE_OL_OK);
		assert(work_metas[0].phase == SE_OWK_DONE &&
		       !work_metas[0].continuation_stage &&
		       !work_accounts[0].fault);
		close_owner();
	}
}

/* Six passes of the same exec, then the depth bound. */
static void six_passes_then_depth_refusal(void)
{
	walk_to(1);
	for (__u32 p = 0; p < SE_OWK_EXEC_PASSES; p++) {
		const __u32 order[3] = { PREPARE, EVAL, TERMINAL };
		for (__u32 i = 0; i < 3; i++) {
			open_owner();
			struct se_owk_ticket ticket = {};
			assert(se_owk_resume(&owner, order[i], &ticket) ==
				       SE_OL_OK &&
			       ticket.continuation_stage == 3 * p + 1 + i);
			if (i < 2 || p + 1 < SE_OWK_EXEC_PASSES) {
				if (i == 2) {
					/* The continuation's own resume. */
					assert(se_exec_continue_pass(
						       ticket.continuation_stage,
						       SE_OWK_EXEC_PASSES) ==
					       p + 1);
				}
				assert(se_owk_suspend(
					       &owner, &ticket,
					       ticket.continuation_stage + 1) ==
				       SE_OL_OK);
			} else {
				/* Pass 6 does not exist: the continuation
				 * refuses at the depth bound and finishes. */
				assert(ticket.continuation_stage == 18 &&
				       !se_exec_continue_pass(
					       18, SE_OWK_EXEC_PASSES));
				assert(se_owk_done(&owner, &ticket) ==
				       SE_OL_OK);
			}
			close_owner();
			if (i < 2 || p + 1 < SE_OWK_EXEC_PASSES)
				assert_untouched(3 * p + 2 + i);
		}
	}
	assert(work_metas[0].phase == SE_OWK_DONE);
	/* A class bound below the stage replays without mutation. */
	walk_to(18);
	open_owner();
	struct se_owk_ticket ticket = {};
	assert(se_owk_resume(&owner, SE_OWK_STAGE_CLASS(0, 4), &ticket) ==
		       SE_OL_STALE &&
	       !ticket.held);
	assert_untouched(18);
	assert(se_owk_resume(&owner, SE_OWK_STAGE_CLASS(1, 6), &ticket) ==
		       SE_OL_CORRUPT &&
	       !ticket.held);
	assert_untouched(18);
	assert(se_owk_resume(&owner, TERMINAL, &ticket) == SE_OL_OK &&
	       ticket.continuation_stage == 18);
	assert(se_owk_done(&owner, &ticket) == SE_OL_OK);
	close_owner();
}

/* The stage and rule programs' suspended claim and the evaluator's view
 * relookup accept any pass's evaluation stage, and only it. */
static void suspended_evaluation_claim_every_pass(void)
{
	for (__u32 p = 0; p < SE_OWK_EXEC_PASSES; p++) {
		__u32 stage = 3 * p + 2;
		walk_to(stage - 1);
		open_owner();
		struct se_owk_ticket ticket = {};
		assert(se_owk_resume(&owner, PREPARE, &ticket) == SE_OL_OK);
		struct se_owk_semantic_handle semantic = {};
		struct se_invocation *work = 0;
		assert(se_owk_semantic_open(&owner, &ticket, &semantic,
					    &work) == SE_OL_OK);
		memset(opaque_policy_blobs, 0, sizeof(opaque_policy_blobs));
		const struct fe_header header = { .policies = 1,
						  .rule_base = 9 };
		const struct fe_policy policy = { .uid = 1,
						  .root_role = 1,
						  .mode = 2 };
		memcpy(&opaque_policy_blobs[0], &header, sizeof(header));
		memcpy(&opaque_policy_blobs[1], &policy, sizeof(policy));
		const struct fe_string container = { .length = 1,
						     .bytes = { '/' } };
		const struct se_policy_ref ref = { .slot = 0,
						   .generation = 1,
						   .root_epoch = 1,
						   .entries = 10 };
		assert(!se_policy_prepare(&work->view, 0, ticket.scope, 1,
					  &container, &ref, 1));
		assert(se_owk_semantic_suspend(&semantic, &work, stage) ==
		       SE_OL_OK);
		close_owner();
		suspended_current_task_key = key;
		struct se_owk_payload *expected = &work_payloads[0];
		assert(!se_owk_suspended_current(10, PREPARE, 1) &&
		       !se_owk_suspended_current(10, TERMINAL, 1));
		if (p)
			assert(!se_owk_suspended_current(
				10, SE_OWK_STAGE_CLASS(2, p - 1), 1));
		assert(!work_metas[0].continuation_reserved);
		assert(se_owk_suspended_current(10, EVAL, 1) == expected &&
		       work_metas[0].continuation_reserved == 1);
		assert(se_owk_suspended_current(10, EVAL, 3) == expected);
		assert(se_owk_suspended_view_from_token(
			       0, expected->semantic.cookie) ==
		       &expected->semantic.view);
		/* A stage outside the class is refused under the claim too. */
		work_metas[0].continuation_stage = stage + 1;
		assert(!se_owk_suspended_current(10, EVAL, 2) &&
		       work_metas[0].continuation_reserved == 1);
		work_metas[0].continuation_stage = stage;
		assert(se_owk_suspended_current(10, EVAL, 2) == expected &&
		       !work_metas[0].continuation_reserved);
		assert(!se_owk_suspended_view_from_token(
			expected->semantic.cookie, 0));
		open_owner();
		ticket = (struct se_owk_ticket){};
		assert(se_owk_resume(&owner, EVAL, &ticket) == SE_OL_OK &&
		       ticket.continuation_stage == stage);
		assert(se_owk_done(&owner, &ticket) == SE_OL_OK);
		close_owner();
		suspended_current_task_key = 0;
	}
}

static void classify_fixture(struct se_exec_terminal_receipt *receipt)
{
	key = seed_live_opaque_task_for_open();
	open_owner();
	routes[0] = (struct se_route_anchor){ .incarnation = 1,
					      .cgroup_identity = 7,
					      .scope = 10,
					      .payload_slot = 0,
					      .payload_generation = 13,
					      .active_serial = 1,
					      .execution_class = 1,
					      .phase = SE_ROUTE_ACTIVE };
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
					     .container = "/" } } }
	};
	struct se_route_claim claim = {};
	bpf_spin_lock(&routes[0].lock);
	assert(se_route_claim_locked(&routes[0], se_route_locator(0, 1), 7,
				     &claim) == SE_ROUTE_OWNED);
	bpf_spin_unlock(&routes[0].lock);
	__u64 invocation = 0;
	assert(se_op_exec_reader_begin(&owner, &claim, &bindings[0], 0x1234,
				       &invocation) == SE_OL_OK);
	*receipt = (struct se_exec_terminal_receipt){
		.physical = key,
		.bprm = 0x1234,
		.cookie = owner.lease.cookie,
		.locator = owner.lease.locator,
		.invocation = invocation,
		.scope = 10,
		.generation = 13,
		.phase = SE_EXEC_TERMINAL_REGISTERED,
	};
}

/* The current-WORK premise is relaxed for CONTINUE only, and only in the
 * continuation's mode; every other identity check is unchanged. */
static void classify_continue_relaxation(void)
{
	struct se_exec_terminal_receipt receipt;
	key = seed_live_opaque_task_for_open();
	open_owner();
	routes[0] = (struct se_route_anchor){ .incarnation = 1,
					      .scope = 10,
					      .phase = SE_ROUTE_ACTIVE };
	bindings[0] = (struct se_binding_snapshots){ .scope = 10 };
	/* Never NEW in continuation mode. */
	assert(se_op_exec_reader_classify(&owner, &bindings[0], 0, key,
					  0x1234) == SE_EXEC_READER_NEW);
	assert(se_op_exec_reader_classify_continue(&owner, &bindings[0], 0, key,
						   0x1234) ==
	       SE_EXEC_READER_RETAIN);
	close_owner();
	classify_fixture(&receipt);
	struct se_task_state before = payloads[0].semantic;
	assert(se_op_exec_reader_classify(&owner, &bindings[0], &receipt, key,
					  0x1234) == SE_EXEC_READER_CONTINUE);
	assert(se_op_exec_reader_classify_continue(&owner, &bindings[0],
						   &receipt, key, 0x1234) ==
	       SE_EXEC_READER_CONTINUE);
	metas[0].current_work_owned = 1;
	assert(se_op_exec_reader_classify(&owner, &bindings[0], &receipt, key,
					  0x1234) == SE_EXEC_READER_RETAIN);
	assert(se_op_exec_reader_classify_continue(&owner, &bindings[0],
						   &receipt, key, 0x1234) ==
	       SE_EXEC_READER_CONTINUE);
	/* Every other identity premise still holds in continuation mode. */
	struct se_exec_terminal_receipt good = receipt;
	for (unsigned field = 0; field < 11; field++) {
		receipt = good;
		__u64 bprm = 0x1234;
		switch (field) {
		case 0:
			receipt.physical++;
			break;
		case 1:
			receipt.cookie++;
			break;
		case 2:
			receipt.locator++;
			break;
		case 3:
			receipt.bprm++;
			break;
		case 4:
			receipt.invocation++;
			break;
		case 5:
			receipt.scope++;
			break;
		case 6:
			receipt.generation++;
			break;
		case 7:
			receipt.reserved = 1;
			break;
		case 8:
			receipt.phase = SE_EXEC_TERMINAL_SUCCESS;
			break;
		case 9:
			receipt.phase = SE_EXEC_TERMINAL_FAILURE;
			break;
		case 10:
			bprm = 0x5678;
			break;
		}
		assert(se_op_exec_reader_classify_continue(
			       &owner, &bindings[0], &receipt, key, bprm) ==
		       SE_EXEC_READER_RETAIN);
	}
	receipt = good;
	routes[0].incarnation++;
	assert(se_op_exec_reader_classify_continue(&owner, &bindings[0],
						   &receipt, key, 0x1234) ==
	       SE_EXEC_READER_RETAIN);
	routes[0].incarnation--;
	payloads[0].semantic.reader_invocation++;
	assert(se_op_exec_reader_classify_continue(&owner, &bindings[0],
						   &receipt, key, 0x1234) ==
	       SE_EXEC_READER_RETAIN);
	payloads[0].semantic.reader_invocation--;
	/* A terminal receipt is not reclassified while a WORK is owned. */
	metas[0].current_work_owned = 0;
	receipt.phase = SE_EXEC_TERMINAL_FAILURE;
	assert(se_op_exec_reader_classify(&owner, &bindings[0], &receipt, key,
					  0) == SE_EXEC_READER_TERMINAL);
	assert(se_op_exec_reader_classify_continue(&owner, &bindings[0],
						   &receipt, key,
						   0) == SE_EXEC_READER_RETAIN);
	assert(!memcmp(&before, &payloads[0].semantic, sizeof(before)));
	close_owner();
}

/* A REGISTERED receipt is a continuation candidate only at a later
 * admission of the same exec; a stale same-bprm receipt at a first
 * admission stays pending. */
static void pending_receipt_classes(void)
{
	const struct se_exec_terminal_receipt good = {
		.physical = 0xa1,
		.bprm = 0x1234,
		.cookie = 5,
		.locator = 6,
		.invocation = 7,
		.scope = 10,
		.generation = 13,
		.phase = SE_EXEC_TERMINAL_REGISTERED,
	};
	assert(se_exec_receipt_pending_class(0, 0xa1, 0x1234, 1) ==
	       SE_EXEC_PENDING_NONE);
	assert(se_exec_receipt_pending_class(0, 0xa1, 0x1234, 0) ==
	       SE_EXEC_PENDING_NONE);
	assert(se_exec_receipt_pending_class(&good, 0xa1, 0x1234, 1) ==
	       SE_EXEC_PENDING_CONTINUE);
	assert(se_exec_receipt_pending_class(&good, 0xa1, 0x1234, 0) ==
	       SE_EXEC_PENDING_RECEIPT);
	assert(se_exec_receipt_pending_class(&good, 0xa1, 0x1234, 0x100U) ==
	       SE_EXEC_PENDING_CONTINUE);
	for (unsigned field = 0; field < 14; field++) {
		struct se_exec_terminal_receipt r = good;
		__u64 physical = 0xa1, bprm = 0x1234;
		switch (field) {
		case 0:
			r.physical++;
			break;
		case 1:
			r.bprm++;
			break;
		case 2:
			r.cookie = 0;
			break;
		case 3:
			r.locator = 0;
			break;
		case 4:
			r.invocation = 0;
			break;
		case 5:
			r.scope = 0;
			break;
		case 6:
			r.generation = 0;
			break;
		case 7:
			r.reserved = 1;
			break;
		case 8:
			r.phase = SE_EXEC_TERMINAL_SUCCESS;
			break;
		case 9:
			r.phase = SE_EXEC_TERMINAL_FAILURE;
			break;
		case 10:
			r.phase = 0;
			break;
		case 11:
			bprm = 0x5678;
			break;
		case 12:
			physical = 0;
			r.physical = 0;
			break;
		case 13:
			bprm = 0;
			r.bprm = 0;
			break;
		}
		assert(se_exec_receipt_pending_class(&r, physical, bprm, 1) ==
		       SE_EXEC_PENDING_RECEIPT);
	}
}

/* The later pass's failure frames: the outer frame bound by pass 0 to the
 * receipt, and this pass's own handler frame for the same bprm. */
static void continuation_frames(void)
{
	const struct se_exec_terminal_receipt receipt = {
		.physical = 0xa1,
		.bprm = 0x1234,
		.cookie = 5,
		.locator = 6,
		.invocation = 7,
		.scope = 10,
		.generation = 13,
		.phase = SE_EXEC_TERMINAL_REGISTERED,
	};
	const struct se_failure_outer_frame outer_good = {
		.physical = 0xa1,
		.bprm = 0x1234,
		.cookie = 5,
		.locator = 6,
		.invocation = 7,
		.scope = 10,
		.generation = 13,
		.depth = 1,
	};
	const struct se_failure_handler_frame handler_good = { .bprm = 0x1234,
							       .depth = 1 };
	const struct se_exec_terminal_receipt *r = &receipt;
	const struct se_failure_outer_frame *o = &outer_good;
	const struct se_failure_handler_frame *h = &handler_good;
	assert(SE_EXEC_CONTINUE_FRAMES_EXACT(r, o, h, 0xa1ULL, 0x1234ULL));
	assert(!SE_EXEC_CONTINUE_FRAMES_EXACT(r, o, h, 0xa2ULL, 0x1234ULL));
	assert(!SE_EXEC_CONTINUE_FRAMES_EXACT(r, o, h, 0xa1ULL, 0x1235ULL));
	const struct se_failure_outer_frame *no_outer = 0;
	const struct se_failure_handler_frame *no_handler = 0;
	assert(!SE_EXEC_CONTINUE_FRAMES_EXACT(r, no_outer, h, 0xa1ULL,
					      0x1234ULL));
	assert(!SE_EXEC_CONTINUE_FRAMES_EXACT(r, o, no_handler, 0xa1ULL,
					      0x1234ULL));
	for (unsigned field = 0; field < 13; field++) {
		struct se_failure_outer_frame outer = outer_good;
		struct se_failure_handler_frame handler = handler_good;
		switch (field) {
		case 0:
			outer.physical++;
			break;
		case 1:
			outer.bprm++;
			break;
		case 2:
			outer.cookie++;
			break;
		case 3:
			outer.locator++;
			break;
		case 4:
			outer.invocation++;
			break;
		case 5:
			outer.scope++;
			break;
		case 6:
			outer.generation++;
			break;
		case 7:
			outer.depth = 2;
			break;
		case 8:
			outer.uncertain = 1;
			break;
		case 9:
			handler.bprm++;
			break;
		case 10:
			handler.depth = 2;
			break;
		case 11:
			handler.uncertain = 1;
			break;
		case 12:
			/* An unbound outer frame (pass 0 never bound it). */
			outer.cookie = outer.locator = outer.invocation = 0;
			outer.scope = outer.generation = 0;
			break;
		}
		o = &outer;
		h = &handler;
		assert(!SE_EXEC_CONTINUE_FRAMES_EXACT(r, o, h, 0xa1ULL,
						      0x1234ULL));
	}
}

struct proposal_fixture {
	struct se_owk_ticket ticket;
	struct se_owk_semantic_handle handle;
	struct se_invocation *work;
	struct se_exec_terminal_receipt receipt;
	struct se_policy_view view;
};
/* One pass's evaluation on the current ACTIVE WORK: snapshot the TASK's
 * (accumulated) transaction, evaluate, propose. */
static int evaluate_and_propose(struct proposal_fixture *f, __u64 role,
				int deny)
{
	struct se_task_state *task = 0;
	assert(se_op_task_semantic_begin(&owner, &task) == SE_OL_OK);
	se_exec_snapshot_locked(task, 13, &f->work->history);
	se_op_task_semantic_end(&owner, &task);
	f->work->view = f->view;
	struct observation *o = &f->work->observation;
	assert(!fe_stage_begin(&f->work->view, &o->facts, &o->evaluator,
			       &o->stage_cursor));
	assert(!fe_stage_finish(&f->work->view, &o->evaluator,
				&o->stage_cursor));
	o->evaluator.decision.proposed_roles[0] = role;
	o->evaluator.decision.deny = deny;
	return se_owk_exec_propose_reader(&f->handle, &f->receipt, key, 0);
}
/* Pass 0 up to its proposal, suspended at the terminal stage 3. */
static void pass_zero(struct proposal_fixture *f)
{
	*f = (struct proposal_fixture){};
	classify_fixture(&f->receipt);
	payloads[0].semantic.committed.version = 7;
	payloads[0].semantic.committed.rows[0] = er_known_row(1, 13, 3);
	start_work(&f->ticket);
	assert(se_owk_semantic_open(&owner, &f->ticket, &f->handle, &f->work) ==
	       SE_OL_OK);
	f->view = (struct se_policy_view){
		.scope_cookie = 10,
		.ready = 1,
		.header = { .generation = 13, .policies = 1, .rule_base = 9 },
		.policies = { { .uid = 1,
				.root_epoch = 13,
				.root_role = 3,
				.mode = 1,
				.fallback = 1 } },
	};
	assert(evaluate_and_propose(f, 9, 0) == SE_OL_OK);
	/* Pass 0 runs at 1 (prepare) and 2 (evaluation); here the WORK
	 * jumps there by the same +1 chain. */
	for (__u32 stage = 1; stage <= 3; stage++) {
		assert(se_owk_semantic_suspend(&f->handle, &f->work, stage) ==
		       SE_OL_OK);
		close_owner();
		open_owner();
		f->ticket = (struct se_owk_ticket){};
		f->handle = (struct se_owk_semantic_handle){};
		if (stage == 3)
			break;
		assert(se_owk_resume(&owner, stage, &f->ticket) == SE_OL_OK);
		assert(se_owk_semantic_open(&owner, &f->ticket, &f->handle,
					    &f->work) == SE_OL_OK);
	}
}
/* The continuation's resume and WORK identity proof, then the payload
 * reset that leaves the WORK exactly as fresh for the prepare program. */
static void continue_pass(struct proposal_fixture *f, __u32 pass)
{
	assert(metas[0].current_work_owned == 1);
	assert(se_op_exec_reader_classify(&owner, &bindings[0], &f->receipt,
					  key,
					  0x1234) == SE_EXEC_READER_RETAIN);
	assert(se_op_exec_reader_classify_continue(&owner, &bindings[0],
						   &f->receipt, key, 0x1234) ==
	       SE_EXEC_READER_CONTINUE);
	f->ticket = (struct se_owk_ticket){};
	assert(se_owk_resume(&owner, TERMINAL, &f->ticket) == SE_OL_OK);
	assert(se_exec_continue_pass(f->ticket.continuation_stage,
				     SE_OWK_EXEC_PASSES) == pass);
	assert(se_owk_semantic_open(&owner, &f->ticket, &f->handle, &f->work) ==
	       SE_OL_OK);
	assert(se_exec_continue_work_exact(f->work, &f->receipt, 1));
	struct se_owk_payload *payload = f->handle.payload;
	memset(&payload->semantic.history, 0,
	       sizeof(*payload) - __builtin_offsetof(struct se_owk_payload,
						     semantic.history));
	assert(!se_exec_continue_work_exact(f->work, &f->receipt, 1));
}

/* Each pass's role proposal accumulates into the one exec transaction; a
 * deny at a later pass is sticky; the identity proof rejects any WORK that
 * is not the receipt's proposed terminal WORK of the frozen class. */
static void accumulated_proposals_and_work_identity(void)
{
	struct proposal_fixture f;
	pass_zero(&f);
	assert(payloads[0].semantic.exec.grants == 1 &&
	       payloads[0].semantic.exec.witnesses[0] == 9);
	f.ticket = (struct se_owk_ticket){};
	assert(se_owk_resume(&owner, TERMINAL, &f.ticket) == SE_OL_OK &&
	       f.ticket.continuation_stage == 3);
	assert(se_owk_semantic_open(&owner, &f.ticket, &f.handle, &f.work) ==
	       SE_OL_OK);
	assert(se_exec_continue_work_exact(f.work, &f.receipt, 1));
	assert(!se_exec_continue_work_exact(f.work, &f.receipt, 2) &&
	       !se_exec_continue_work_exact(f.work, &f.receipt, 0) &&
	       !se_exec_continue_work_exact(0, &f.receipt, 1) &&
	       !se_exec_continue_work_exact(f.work, 0, 1));
	struct se_exec_terminal_receipt good = f.receipt;
	for (unsigned field = 0; field < 5; field++) {
		f.receipt = good;
		switch (field) {
		case 0:
			f.receipt.cookie++;
			break;
		case 1:
			f.receipt.scope++;
			break;
		case 2:
			f.receipt.bprm++;
			break;
		case 3:
			f.receipt.invocation++;
			break;
		case 4:
			f.receipt.generation++;
			break;
		}
		assert(!se_exec_continue_work_exact(f.work, &f.receipt, 1));
	}
	f.receipt = good;
	struct observation *o = &f.work->observation;
	o->stage_cursor.state = FE_STAGE_FINISHED;
	assert(!se_exec_continue_work_exact(f.work, &f.receipt, 1));
	o->stage_cursor.state = SE_OWK_PROPOSAL_CONSUMED;
	f.work->history.transaction.execution_class = 2;
	assert(!se_exec_continue_work_exact(f.work, &f.receipt, 1));
	f.work->history.transaction.execution_class = 1;
	f.work->history.reserved = 1;
	assert(!se_exec_continue_work_exact(f.work, &f.receipt, 1));
	f.work->history.reserved = 0;
	f.work->history.transaction.owned = 0;
	assert(!se_exec_continue_work_exact(f.work, &f.receipt, 1));
	f.work->history.transaction.owned = 1;
	assert(se_exec_continue_work_exact(f.work, &f.receipt, 1));
	assert(se_owk_semantic_done(&f.handle, &f.work) == SE_OL_OK);
	close_owner();

	pass_zero(&f);
	/* Pass roles: the same witness, a conflicting witness (uncertain), a
	 * deny (sticky), then allowed passes that cannot clear the deny. */
	const __u64 roles[SE_OWK_EXEC_PASSES] = { 9, 9, 10, 0, 9, 9 };
	for (__u32 pass = 1; pass < SE_OWK_EXEC_PASSES; pass++) {
		continue_pass(&f, pass);
		assert(evaluate_and_propose(&f, roles[pass], pass == 3) ==
		       SE_OL_OK);
		const struct se_exec_transaction *tx =
			&payloads[0].semantic.exec;
		assert(tx->owned && !tx->hard_fault && tx->sequence == 1 &&
		       tx->bprm == 0x1234);
		assert(tx->known_deny == (pass >= 3 ? 1U : 0U));
		if (pass == 1)
			assert(tx->grants == 1 && tx->witnesses[0] == 9 &&
			       !tx->conflicts && !tx->uncertain);
		if (pass >= 2)
			assert((tx->conflicts & 1) && (tx->uncertain & 1) &&
			       !tx->grants);
		/* prepare 3p+1, evaluation 3p+2, terminal 3p+3 */
		for (__u32 stage = 3 * pass + 1; stage <= 3 * pass + 3;
		     stage++) {
			assert(se_owk_semantic_suspend(&f.handle, &f.work,
						       stage) == SE_OL_OK);
			close_owner();
			open_owner();
			f.ticket = (struct se_owk_ticket){};
			f.handle = (struct se_owk_semantic_handle){};
			if (stage == 3 * pass + 3)
				break;
			assert(se_owk_resume(&owner,
					     stage % 3 == 1 ? PREPARE : EVAL,
					     &f.ticket) == SE_OL_OK);
			assert(se_owk_semantic_open(&owner, &f.ticket,
						    &f.handle,
						    &f.work) == SE_OL_OK);
		}
	}
	/* After pass 5 a seventh continuation is refused at the depth bound;
	 * the terminal still resumes and completes exactly once. */
	f.ticket = (struct se_owk_ticket){};
	assert(se_owk_resume(&owner, TERMINAL, &f.ticket) == SE_OL_OK &&
	       f.ticket.continuation_stage == 18 &&
	       !se_exec_continue_pass(18, SE_OWK_EXEC_PASSES));
	assert(se_owk_done(&owner, &f.ticket) == SE_OL_OK);
	close_owner();
	assert(work_accounts[0].used == 1 && !work_accounts[0].fault);
}

/* A stale reader proposal (history not refreshed after a previous pass's
 * proposal) is STALE and does not mutate the transaction. */
static void unreset_continuation_cannot_propose(void)
{
	struct proposal_fixture f;
	pass_zero(&f);
	f.ticket = (struct se_owk_ticket){};
	assert(se_owk_resume(&owner, TERMINAL, &f.ticket) == SE_OL_OK);
	assert(se_owk_semantic_open(&owner, &f.ticket, &f.handle, &f.work) ==
	       SE_OL_OK);
	struct se_exec_transaction before = payloads[0].semantic.exec;
	/* PROPOSAL_CONSUMED is not FINISHED: the old evaluation cannot be
	 * proposed a second time. */
	assert(se_owk_exec_propose_reader(&f.handle, &f.receipt, key, 0) ==
	       SE_OL_CORRUPT);
	assert(!memcmp(&before, &payloads[0].semantic.exec, sizeof(before)));
	assert(se_owk_semantic_done(&f.handle, &f.work) == SE_OL_OK);
	close_owner();
}

/* The stale-resume injector's shape: at a continuation the WORK sits at the
 * previous pass's terminal stage 3p; resuming it with the prepare class is
 * a STALE replay that changes nothing (no fault, no claim, no stage move),
 * so the refusal's cleanup cascade (evaluation, prepare, terminal class)
 * still consumes it exactly once and the receipt identity is untouched. */
static void stale_resume_refusal_is_non_mutating(void)
{
	struct proposal_fixture f;
	for (__u32 p = 1; p < SE_OWK_EXEC_PASSES; p++) {
		pass_zero(&f);
		for (__u32 q = 1; q < p; q++) {
			continue_pass(&f, q);
			assert(evaluate_and_propose(&f, 9, 0) == SE_OL_OK);
			for (__u32 stage = 3 * q + 1; stage <= 3 * q + 3;
			     stage++) {
				assert(se_owk_semantic_suspend(
					       &f.handle, &f.work, stage) ==
				       SE_OL_OK);
				close_owner();
				open_owner();
				f.ticket = (struct se_owk_ticket){};
				f.handle = (struct se_owk_semantic_handle){};
				if (stage == 3 * q + 3)
					break;
				assert(se_owk_resume(&owner,
						     stage % 3 == 1 ? PREPARE :
								      EVAL,
						     &f.ticket) == SE_OL_OK);
				assert(se_owk_semantic_open(
					       &owner, &f.ticket, &f.handle,
					       &f.work) == SE_OL_OK);
			}
		}
		struct se_task_state before = payloads[0].semantic;
		struct se_owk_ticket stale = {};
		assert(se_owk_resume(&owner, PREPARE, &stale) == SE_OL_STALE &&
		       !stale.held && !stale.cookie);
		assert_untouched(3 * p);
		assert(!memcmp(&before, &payloads[0].semantic, sizeof(before)));
		assert(se_op_exec_reader_classify_continue(
			       &owner, &bindings[0], &f.receipt, key, 0x1234) ==
		       SE_EXEC_READER_CONTINUE);
		const __u32 cascade[3] = { EVAL, PREPARE, TERMINAL };
		int consumed = 0;
		for (__u32 i = 0; i < 3; i++) {
			struct se_owk_ticket t = {};
			int ok = se_owk_resume(&owner, cascade[i], &t) ==
				 SE_OL_OK;
			assert(ok == (i == 2));
			if (ok) {
				assert(t.continuation_stage == 3 * p);
				assert(se_owk_done(&owner, &t) == SE_OL_OK);
				consumed++;
			}
		}
		assert(consumed == 1 && work_metas[0].phase == SE_OWK_DONE &&
		       !work_accounts[0].fault);
		close_owner();
	}
}

int main(void)
{
	stage_arithmetic();
	every_stage_resumes_its_class_only();
	six_passes_then_depth_refusal();
	suspended_evaluation_claim_every_pass();
	classify_continue_relaxation();
	pending_receipt_classes();
	continuation_frames();
	accumulated_proposals_and_work_identity();
	unreset_continuation_cannot_propose();
	stale_resume_refusal_is_non_mutating();
	printf("opaque interpreter continuation contract: PASS\n");
	return 0;
}
