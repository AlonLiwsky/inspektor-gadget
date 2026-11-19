/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <string.h>
#include "shared-arm-transaction.h"

struct fixture {
	struct se_arm_request written;
	struct se_arm_request *source;
	int journal[3], writes, triggers, proofs;
	int fail_journal, fail_write, fail_trigger, fail_proof;
};

static int journal(void *opaque, enum se_arm_journal_phase phase,
		   const struct se_arm_request *request,
		   const struct se_arm_receipt *receipt)
{
	struct fixture *f = opaque;
	assert(request->node_cookie == 4 && request->sequence == 8);
	assert((phase == SE_ARM_J_RESOLVED) == (receipt != 0));
	f->journal[phase]++;
	if (phase == SE_ARM_J_PREPARED && f->source)
		f->source->scope = 999;
	return f->fail_journal == (int)phase + 1 ? -1 : 0;
}

static int write_request(void *opaque, const struct se_arm_request *request)
{
	struct fixture *f = opaque;
	f->writes++;
	f->written = *request;
	return f->fail_write ? -1 : 0;
}

static int trigger_a(void *opaque, __u64 sequence)
{
	struct fixture *f = opaque;
	assert(sequence == f->written.sequence);
	f->triggers++;
	return f->fail_trigger ? -1 : 0;
}

static int state_proof(void *opaque, const struct se_arm_request *request,
		       const struct se_arm_receipt *receipt)
{
	struct fixture *f = opaque;
	assert(!memcmp(request, &f->written, sizeof(*request)));
	assert(receipt->sequence == request->sequence);
	f->proofs++;
	return f->fail_proof ? -1 : 0;
}

static struct se_arm_tx_ops ops(struct fixture *f)
{
	return (struct se_arm_tx_ops){ .ctx = f,
				       .journal = journal,
				       .write_request = write_request,
				       .trigger_a = trigger_a,
				       .state_proof = state_proof };
}

static struct se_arm_request request(void)
{
	return (struct se_arm_request){ .node_cookie = 4,
					.sequence = 8,
					.scope = 9,
					.serial = 3,
					.expected_generation = 2,
					.operation = SE_ARM_COMMIT,
					.count = 1 };
}

static struct se_arm_receipt receipt(void)
{
	return (struct se_arm_receipt){ .node_cookie = 4,
					.sequence = 8,
					.generation = 3,
					.serial = 3,
					.operation = SE_ARM_COMMIT };
}

static void happy_and_ambiguous(void)
{
	struct fixture f = {};
	struct se_arm_transaction tx = {};
	struct se_arm_tx_ops op = ops(&f);
	struct se_arm_request req = request();
	struct se_arm_receipt got = receipt();
	tx.last_sequence = 7;
	assert(se_arm_tx_init(&tx, 4)); /* cannot reset a retained sequence */
	tx.last_sequence = 0;
	f.source = &req;
	assert(!se_arm_tx_init(&tx, 4));
	assert(se_arm_tx_init(&tx, 4));
	assert(!se_arm_tx_stage(&tx, &req, &op));
	assert(tx.phase == SE_ARM_TX_WRITTEN && f.writes == 1 &&
	       f.journal[SE_ARM_J_PREPARED] == 1 &&
	       f.journal[SE_ARM_J_WRITTEN] == 1);
	assert(req.scope == 999); /* mutated inside the PREPARED callback */
	assert(tx.request.scope == 9 && f.written.scope == 9);
	assert(se_arm_tx_stage(&tx, &req, &op));
	f.fail_trigger = 1;
	assert(se_arm_tx_permit(&tx, &op));
	assert(tx.phase == SE_ARM_TX_PERMITTED && f.triggers == 1);
	assert(se_arm_tx_permit(&tx, &op)); /* never rerun on ambiguous error */
	got.sequence = 7;
	assert(se_arm_tx_reconcile(&tx, &got, &op));
	assert(tx.phase == SE_ARM_TX_PERMITTED && !f.proofs);
	got = receipt();
	f.fail_proof = 1;
	assert(se_arm_tx_reconcile(&tx, &got, &op));
	assert(tx.phase == SE_ARM_TX_PERMITTED);
	f.fail_proof = 0;
	got.generation = 4;
	assert(se_arm_tx_reconcile(&tx, &got, &op));
	got = receipt();
	f.fail_journal = SE_ARM_J_RESOLVED + 1;
	assert(se_arm_tx_reconcile(&tx, &got, &op));
	assert(tx.phase == SE_ARM_TX_PERMITTED);
	f.fail_journal = 0;
	assert(!se_arm_tx_reconcile(&tx, &got, &op));
	assert(tx.phase == SE_ARM_TX_EMPTY && tx.last_sequence == 8 &&
	       f.triggers == 1 && !tx.request.sequence);
	req = request();
	assert(se_arm_tx_stage(&tx, &req, &op)); /* no replay */
}

static void prepermit_failures(void)
{
	struct se_arm_request req = request();
	struct fixture f = { .fail_journal = SE_ARM_J_PREPARED + 1 };
	struct se_arm_transaction tx = {};
	struct se_arm_tx_ops op = ops(&f);
	assert(!se_arm_tx_init(&tx, 4));
	assert(se_arm_tx_stage(&tx, &req, &op));
	assert(tx.phase == SE_ARM_TX_PREPARED && !f.writes);
	assert(se_arm_tx_permit(&tx, &op) && !f.triggers);
	f = (struct fixture){ .fail_write = 1 };
	tx = (struct se_arm_transaction){};
	assert(!se_arm_tx_init(&tx, 4));
	assert(se_arm_tx_stage(&tx, &req, &op));
	assert(tx.phase == SE_ARM_TX_PREPARED && f.writes == 1 && !f.triggers);
	f = (struct fixture){ .fail_journal = SE_ARM_J_WRITTEN + 1 };
	tx = (struct se_arm_transaction){};
	assert(!se_arm_tx_init(&tx, 4));
	assert(se_arm_tx_stage(&tx, &req, &op));
	assert(tx.phase == SE_ARM_TX_PREPARED && f.writes == 1 && !f.triggers);
	assert(se_arm_tx_permit(&tx, &op) && !f.triggers);
}

static void malformed_input_and_refusal(void)
{
	struct fixture f = {};
	struct se_arm_transaction tx = {};
	struct se_arm_tx_ops op = ops(&f);
	struct se_arm_request req = request();
	struct se_arm_receipt got = receipt();
	assert(!se_arm_tx_init(&tx, 4));
	req.reserved = 1;
	assert(se_arm_tx_stage(&tx, &req, &op) && tx.phase == SE_ARM_TX_EMPTY);
	req = request();
	req.sequence = 0;
	assert(se_arm_tx_stage(&tx, &req, &op) && tx.phase == SE_ARM_TX_EMPTY);
	req = request();
	assert(!se_arm_tx_stage(&tx, &req, &op));
	assert(!se_arm_tx_permit(&tx, &op));
	got.status = 1;
	assert(se_arm_tx_reconcile(&tx, &got, &op));
	got.generation = got.serial = 0;
	assert(!se_arm_tx_reconcile(&tx, &got, &op));
	assert(tx.last_sequence == 8 && tx.phase == SE_ARM_TX_EMPTY);
}

int main(void)
{
	happy_and_ambiguous();
	prepermit_failures();
	malformed_input_and_refusal();
	return 0;
}
