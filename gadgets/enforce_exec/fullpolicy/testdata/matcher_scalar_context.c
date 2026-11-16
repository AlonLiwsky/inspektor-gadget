/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <assert.h>
#include <stdio.h>

struct fm_blob;
static const struct fm_blob *
lookup_scalar(unsigned slot, unsigned long long cookie, unsigned key);
#define FM_GLOBAL_SCALAR_BLOB_LOOKUP(slot, cookie, key) \
	lookup_scalar((slot), (cookie), (key))
#define FM_BLOB_LOOKUP(context, key)                                       \
	lookup_scalar(((const struct fm_global_token *)(context))->slot,   \
		      ((const struct fm_global_token *)(context))->cookie, \
		      (key))
#include "../bpf/evaluator.h"

static struct fm_blob programs[2][4];
static unsigned instruction_lookups;
static const struct fm_blob *
lookup_scalar(unsigned slot, unsigned long long cookie, unsigned key)
{
	if (slot >= 2 || cookie != 101 + slot || key >= 4)
		return NULL;
	if (key >= 2)
		instruction_lookups++;
	return &programs[slot][key];
}
static void program(unsigned slot, unsigned char rune)
{
	struct fm_pattern *pattern = (void *)&programs[slot][1];
	struct fm_instruction *consume = (void *)&programs[slot][2];
	struct fm_instruction *match = (void *)&programs[slot][3];
	*pattern =
		(struct fm_pattern){ .code_base = 2, .start = 0, .count = 2 };
	*consume = (struct fm_instruction){
		.op = FM_RUNE, .out = 1, .count = 1, .ranges = { rune, rune }
	};
	*match = (struct fm_instruction){ .op = FM_MATCH };
}
int main(void)
{
	program(0, 'a');
	program(1, 'b');
	struct fm_scratch scratch = {};
	const fm_u8 a[256] = { 'a' }, b[256] = { 'b' };
	struct fm_global_token first = { .slot = 0, .cookie = 101 };
	struct fm_global_token second = { .slot = 1, .cookie = 102 };
	assert(fe_blob(&first, 1) == &programs[0][1]);
	assert(fe_blob(&second, 1) == &programs[1][1]);
	assert(fm_match_key(&first, 1, a, 1, &scratch) == 1);
	assert(fm_match_key(&first, 1, b, 1, &scratch) == 0);
	assert(fm_match_key(&second, 1, b, 1, &scratch) == 1);
	assert(fm_match_key(&second, 1, a, 1, &scratch) == 0);
	assert(instruction_lookups >= 4);
	first.cookie = 102;
	assert(fe_blob(&first, 1) == NULL);
	assert(fm_match_key(&first, 1, a, 1, &scratch) == -1);
	first.cookie = 101;
	first.reserved = 1;
	assert(fm_match_key(&first, 1, a, 1, &scratch) == -1);
	puts("scalar matcher context PASS");
	return 0;
}
