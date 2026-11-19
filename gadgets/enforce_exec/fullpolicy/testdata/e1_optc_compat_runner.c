/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* E1 (option C) host parity runner: the evaluator compiled with the EXACT
 * knob set of the option C compat object (fullruntime/selfqual/optcengine/
 * bpf/optc.bpf.c), driven the way that object drives it: fe_stage_begin, one
 * rule per fe_stage_advance (16 advances per window, at most 16 windows),
 * fe_stage_finish, through the scalar-token global lookup. It prints the
 * staged decision in evaluator_runner.c's format, so runEvaluatorParity
 * compares it with the Go reference evaluator. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#define FE_BOUNDED_LOOP_CANDIDATE 1
#define FE_RULE_STEP_INLINE_DIAGNOSTIC 1
#define FE_STAGE_RELOOKUP_HEADER_CANDIDATE 1
#define FE_STAGE_RULES 1U
#define FE_STAGED_OLD_KERNEL_RULE_WINDOW_DIAGNOSTIC 1
#define FM_WORK_RUN_STATE_DIAGNOSTIC 1
#define FM_STAGE_INLINE_INSTRUCTION_WINDOW 1
#define OC_ADVANCES 16
#define OC_WINDOWS 16
struct fm_blob;
static const struct fm_blob *lookup_scalar(unsigned int, unsigned long long,
					   unsigned int);
#define FM_GLOBAL_SCALAR_BLOB_LOOKUP(slot, cookie, key) \
	lookup_scalar((slot), (cookie), (key))
#define FM_BLOB_LOOKUP(context, key)                                       \
	lookup_scalar(((const struct fm_global_token *)(context))->slot,   \
		      ((const struct fm_global_token *)(context))->cookie, \
		      (key))
#include "../bpf/evaluator_stage_candidate.h"

static struct fm_blob *entries;
static unsigned int count;
static const struct fm_blob *lookup_scalar(unsigned int slot,
					   unsigned long long cookie,
					   unsigned int key)
{
	return slot == 0 && cookie == 7 && key < count ? &entries[key] : 0;
}

int main(int argc, char **argv)
{
	if (argc != 3)
		return 2;
	FILE *program = fopen(argv[1], "rb"), *facts = fopen(argv[2], "rb");
	if (!program || !facts || fseek(program, 0, SEEK_END))
		return 2;
	long size = ftell(program);
	if (size <= 0 || size % 288 || size / 288 > FM_MAX_ENTRIES ||
	    fseek(program, 0, SEEK_SET))
		return 2;
	count = size / 288;
	entries = calloc(count, 288);
	struct fe_facts *f = calloc(1, sizeof(*f));
	struct fe_scratch *s = calloc(1, sizeof(*s));
	struct fe_alt_request *alt = calloc(1, sizeof(*alt));
	if (!entries || !f || !s || !alt ||
	    fread(entries, 288, count, program) != count ||
	    fread(f, sizeof(*f), 1, facts) != 1)
		return 2;
	memset(s, 0xa5, sizeof(*s));
	struct fm_global_token tok = { .slot = 0, .cookie = 7 };
	struct fe_stage_cursor cursor = {};
	int result = fe_stage_begin(&tok, f, s, &cursor);
	if (result == 0) {
		/* The engine: OC_WINDOWS invocations of OC_ADVANCES advances;
		 * rules left over at the cap are a fault (never a prefix). */
		for (int w = 0; w < OC_WINDOWS && cursor.state == FE_STAGE_ACTIVE; w++)
			for (int k = 0; k < OC_ADVANCES && cursor.state == FE_STAGE_ACTIVE; k++)
				if (fe_stage_advance(&tok, f, s, &cursor, alt))
					return 5;
		if (cursor.state == FE_STAGE_ACTIVE)
			return 7;
		result = fe_stage_finish(&tok, s, &cursor);
	}
	struct fe_decision d = s->decision;
	printf("%d %u %u %u", result, d.deny, d.mode, d.error);
	for (unsigned int i = 0; i < 4; i++)
		printf(" %llu", d.matched_rules[i]);
	for (unsigned int i = 0; i < 8; i++)
		printf(" %llu", d.proposed_roles[i]);
	fm_u32 policies = 0, writers = 0;
	const struct fe_header *head = (const void *)entries;
	int execution_class =
		fe_execution_class(&tok, head->generation, &policies, &writers);
	printf(" %u %u %u %u %u\n", d.audit_unknown, (unsigned int)execution_class,
	       writers, d.enforced_writes, d.role_conflicts);
	return 0;
}
