/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
/* Two immutable synthetic policy slots. The explicit WORK scalar token must
 * survive rule, list, argument-string and nested evaluator callbacks. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
struct fm_blob;
static const struct fm_blob *lookup_scalar(unsigned int, unsigned long long,
					   unsigned int);
#define FM_GLOBAL_SCALAR_BLOB_LOOKUP(slot, cookie, key) \
	lookup_scalar((slot), (cookie), (key))
#define FM_BLOB_LOOKUP(context, key)                                       \
	lookup_scalar(((const struct fm_global_token *)(context))->slot,   \
		      ((const struct fm_global_token *)(context))->cookie, \
		      (key))
#include "../bpf/evaluator.h"

static struct fm_blob cells[2][16];
static const struct fm_blob *lookup_scalar(fm_u32 slot, fm_u64 cookie,
					   fm_u32 key)
{
	return slot < 2 && cookie == 101 + slot && key < 16 ?
		       &cells[slot][key] :
		       0;
}
static void seed_slot(fm_u32 slot, fm_u32 uid)
{
	struct fe_header header = {
		.generation = 1,
		.policies = 1,
		.rule_base = 9,
		.rules = 1,
	};
	struct fe_policy policy = {
		.uid = 1,
		.root_role = 3,
		.mode = 2,
	};
	struct fe_rule rule = {
		.policy = 0,
		.mode = 2,
		.deny = 1,
		.actor_image = -1,
		.target_image = -1,
		.stdin_pipe = -1,
		.actor_path = { .base = 12, .count = 1 },
		.uid = { .base = 10, .count = 1 },
		.arg_contains = { .base = 11, .count = 1 },
	};
	struct fe_string argument = { .length = 3, .bytes = { 'f', 'o', 'o' } };
	memcpy(&cells[slot][0], &header, sizeof(header));
	memcpy(&cells[slot][1], &policy, sizeof(policy));
	memcpy(&cells[slot][9], &rule, sizeof(rule));
	cells[slot][10].words[0] = uid;
	memcpy(&cells[slot][11], &argument, sizeof(argument));
	struct fm_pattern *pattern = (void *)&cells[slot][12];
	struct fm_instruction *consume = (void *)&cells[slot][13];
	struct fm_instruction *match = (void *)&cells[slot][14];
	*pattern =
		(struct fm_pattern){ .code_base = 13, .start = 0, .count = 2 };
	*consume = (struct fm_instruction){ .op = FM_RUNE,
					    .out = 1,
					    .count = 1,
					    .ranges = { slot ? 'b' : 'a',
							slot ? 'b' : 'a' } };
	*match = (struct fm_instruction){ .op = FM_MATCH };
}
static void run(struct fm_global_token token, fm_u32 uid, char actor, int deny)
{
	struct fe_facts facts = {
		.actor_image = -1,
		.target_image = -1,
		.stdin_pipe = -1,
		.effective_uid = uid,
		.uid_known = 1,
		.argc = 1,
		.argv_bytes = 4,
		.argv_complete = 1,
	};
	facts.actor_path.length = 1;
	facts.actor_path.bytes[0] = actor;
	memcpy(facts.argv, "foo", 4);
	struct fe_scratch scratch = {};
	int result = fe_evaluate(&token, &facts, &scratch);
	if (deny >= 0) {
		assert(result == 0 && !scratch.decision.error);
		assert((int)scratch.decision.deny == deny);
	} else {
		assert(result != 0 && scratch.decision.error);
	}
}
int main(void)
{
	seed_slot(0, 100);
	seed_slot(1, 200);
	run((struct fm_global_token){ .slot = 0, .cookie = 101 }, 100, 'a', 1);
	run((struct fm_global_token){ .slot = 0, .cookie = 101 }, 100, 'b', 0);
	run((struct fm_global_token){ .slot = 1, .cookie = 102 }, 100, 'b', 0);
	run((struct fm_global_token){ .slot = 1, .cookie = 102 }, 200, 'b', 1);
	run((struct fm_global_token){ .slot = 1, .cookie = 102 }, 200, 'a', 0);
	run((struct fm_global_token){ .slot = 0, .cookie = 102 }, 100, 'a', -1);
	puts("scalar evaluator context: PASS");
}
