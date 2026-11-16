/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#define ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE 1
#define ENFORCE_EXEC_POOL_OPAQUE_WORK_READER_CATALOGUE_CANDIDATE 1
#define main opaque_locator_fixture_main
#include "../../full/test/host/opaque_locator_candidate.c"
#undef main

struct receipt_fixture {
	__u64 key;
	struct se_ol_payload_handle owner;
	struct se_exec_terminal_receipt receipt;
};
static void setup(struct receipt_fixture *f)
{
	*f = (struct receipt_fixture){};
	f->key = seed_live_opaque_task_for_open();
	assert(se_ol_task_open(&f->key, &f->owner) == SE_OL_OK);
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
}
static int classify(struct receipt_fixture *f,
		    const struct se_exec_terminal_receipt *receipt, __u64 bprm)
{
	return se_op_exec_reader_classify(&f->owner, &bindings[0], receipt,
					  f->key, bprm);
}
static void begin(struct receipt_fixture *f)
{
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
		.phase = SE_EXEC_TERMINAL_REGISTERED
	};
}
int main(void)
{
	struct receipt_fixture f;
	setup(&f);
	assert(classify(&f, 0, 0x1234) == SE_EXEC_READER_NEW);
	assert(classify(&f, 0, 0) == SE_EXEC_READER_RETAIN);
	begin(&f);
	assert(classify(&f, 0, 0x1234) == SE_EXEC_READER_RETAIN);
	assert(classify(&f, &f.receipt, 0x1234) == SE_EXEC_READER_CONTINUE);
	assert(classify(&f, &f.receipt, 0x5678) == SE_EXEC_READER_RETAIN);
	assert(se_op_task_note_prior_deny(&f.owner, 0x1234) == SE_OL_OK);
	struct se_task_state before = payloads[0].semantic;
	struct se_exec_terminal_receipt good = f.receipt;
	for (unsigned int field = 0; field < 10; field++) {
		f.receipt = good;
		switch (field) {
		case 0:
			f.receipt.physical++;
			break;
		case 1:
			f.receipt.cookie++;
			break;
		case 2:
			f.receipt.locator++;
			break;
		case 3:
			f.receipt.bprm++;
			break;
		case 4:
			f.receipt.invocation++;
			break;
		case 5:
			f.receipt.scope++;
			break;
		case 6:
			f.receipt.generation++;
			break;
		case 7:
			f.receipt.reserved = 1;
			break;
		case 8:
			f.receipt.phase = 0;
			break;
		case 9:
			f.receipt.phase = 99;
			break;
		}
		assert(classify(&f, &f.receipt, 0x1234) ==
		       SE_EXEC_READER_RETAIN);
		assert(!memcmp(&before, &payloads[0].semantic, sizeof(before)));
	}
	f.receipt = good;
	for (unsigned int phase = SE_EXEC_TERMINAL_SUCCESS;
	     phase <= SE_EXEC_TERMINAL_FAILURE; phase++) {
		f.receipt.phase = phase;
		assert(classify(&f, &f.receipt, 0x5678) ==
		       SE_EXEC_READER_TERMINAL);
		assert(classify(&f, &f.receipt, 0) == SE_EXEC_READER_TERMINAL);
	}
	assert(!memcmp(&before, &payloads[0].semantic, sizeof(before)));
	f.receipt = good;
	routes[0].incarnation++;
	assert(classify(&f, &f.receipt, 0x1234) == SE_EXEC_READER_RETAIN);
	routes[0].incarnation--;
	assert(classify(&f, &f.receipt, 0x1234) == SE_EXEC_READER_CONTINUE);
	assert(payloads[0].semantic.exec.known_deny && f.owner.lease.held);
	metas[0].current_work_owned = 1;
	assert(classify(&f, &f.receipt, 0x1234) == SE_EXEC_READER_RETAIN);
	metas[0].current_work_owned = 0;
	__u64 reader_invocation = payloads[0].semantic.reader_invocation;
	payloads[0].semantic.reader_invocation++;
	assert(classify(&f, &f.receipt, 0x1234) == SE_EXEC_READER_RETAIN);
	payloads[0].semantic.reader_invocation = reader_invocation;
	f.owner.lease.cookie++;
	assert(classify(&f, &f.receipt, 0x1234) == SE_EXEC_READER_RETAIN);
	f.owner.lease.cookie--;
	assert(classify(&f, &f.receipt, 0x1234) == SE_EXEC_READER_CONTINUE);
	f.receipt.phase = SE_EXEC_TERMINAL_FAILURE;
	assert(se_op_exec_reader_finish_bounded(
		       &f.owner, &bindings[0], f.receipt.bprm,
		       f.receipt.invocation, 0) == SE_OL_OK);
	assert(!payloads[0].semantic.exec.owned &&
	       !payloads[0].semantic.reader.owned);
	before = payloads[0].semantic;
	/* Even already-settled terminal evidence must be retired by its owner,
	 * not mistaken for a clean new begin or another interpreter iteration. */
	assert(classify(&f, &f.receipt, 0x1234) == SE_EXEC_READER_TERMINAL);
	assert(!memcmp(&before, &payloads[0].semantic, sizeof(before)));
	assert(classify(&f, 0, 0x5678) == SE_EXEC_READER_NEW);
	payloads[0].semantic.reader_invocation = reader_invocation;
	assert(classify(&f, 0, 0x5678) == SE_EXEC_READER_RETAIN);
	payloads[0].semantic.reader_invocation = 0;
	assert(!held && !lock_errors);
	assert(se_ol_payload_close(&f.owner) == SE_OL_OK);
	puts("opaque exec receipt classification: PASS");
	return 0;
}
