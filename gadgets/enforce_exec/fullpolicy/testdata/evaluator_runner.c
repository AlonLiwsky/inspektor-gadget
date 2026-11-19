/* SPDX-License-Identifier: Apache-2.0 */
/* Native harness for the same header used by BPF; allocation is harness-only. */
#ifdef __bpf__
struct fm_blob;
#ifdef FE_SCALAR_TEST
static inline const struct fm_blob *
lookup_scalar(unsigned int, unsigned long long, unsigned int);
#define FM_GLOBAL_SCALAR_BLOB_LOOKUP(slot, cookie, key) \
	lookup_scalar((slot), (cookie), (key))
#define FM_BLOB_LOOKUP(context, key)                                       \
	lookup_scalar(((const struct fm_global_token *)(context))->slot,   \
		      ((const struct fm_global_token *)(context))->cookie, \
		      (key))
#else
static inline const struct fm_blob *lookup_global(unsigned int);
#define FM_GLOBAL_BLOB_LOOKUP(key) lookup_global(key)
#define FM_BLOB_LOOKUP(context, key) lookup_global(key)
#endif
#include "../bpf/evaluator.h"
#define SEC(name) __attribute__((section(name), used))
#define MAP_UINT(name, value) int(*name)[value]
#define MAP_TYPE(name, value) value *name
struct {
	MAP_UINT(type, 1);
	MAP_UINT(max_entries, FM_MAX_ENTRIES);
	MAP_UINT(map_flags,
		 1U << 7); /* BPF_F_RDONLY_PROG, matching production */
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fm_blob);
} blobs SEC(".maps");
struct {
	MAP_UINT(type, 2);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fe_facts);
} input_map SEC(".maps");
struct {
	MAP_UINT(type, 2);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fe_scratch);
} scratch_map SEC(".maps");
static void *(*map_lookup)(void *, const void *) = (void *)1;
#ifdef FE_SCALAR_TEST
static inline const struct fm_blob *
lookup_scalar(unsigned int slot, unsigned long long cookie, unsigned int key)
{
	return slot == 0 && cookie == 101 ? map_lookup(&blobs, &key) : 0;
}
#else
static inline const struct fm_blob *lookup_global(unsigned int key)
{
	return map_lookup(&blobs, &key);
}
#endif
/* Program.Test only. Shared test maps are not a concurrent runtime scratch
 * design. This filter is never attached to a socket or exec hook. */
SEC("socket") int evaluator(void *unused)
{
	(void)unused;
	fm_u32 zero = 0;
	const struct fe_facts *facts = map_lookup(&input_map, &zero);
	struct fe_scratch *scratch = map_lookup(&scratch_map, &zero);
	if (!facts || !scratch)
		return 0;
#ifdef FE_SCALAR_TEST
	struct fm_global_token token = { .slot = 0, .cookie = 101 };
	return fe_evaluate(&token, facts, scratch) + 1;
#else
	return fe_evaluate(&blobs, facts, scratch) + 1;
#endif
}
char LICENSE[] SEC("license") = "GPL";
#else
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
struct fm_blob;
struct fixture {
	struct fm_blob *entries;
	unsigned int count;
};
#ifdef FE_FIXED_MAP_TEST
static struct fixture *active_fixture;
static const struct fm_blob *lookup_global(unsigned int);
#define FM_GLOBAL_BLOB_LOOKUP(key) lookup_global(key)
#endif
static const struct fm_blob *lookup(void *, unsigned int);
#define FM_BLOB_LOOKUP(context, key) lookup(context, key)
#include "../bpf/evaluator.h"
#ifdef FE_STAGE_CANDIDATE
#include "../bpf/evaluator_stage_candidate.h"
#endif
static const struct fm_blob *lookup(void *ctx, unsigned int key)
{
	struct fixture *f = ctx;
	return key < f->count ? &f->entries[key] : NULL;
}
#ifdef FE_FIXED_MAP_TEST
static const struct fm_blob *lookup_global(unsigned int key)
{
	return lookup(active_fixture, key);
}
#endif
int main(int argc, char **argv)
{
	if (argc == 7 && !strcmp(argv[1], "verdict")) {
		struct fe_decision d = { .deny = (unsigned int)atoi(argv[5]),
					 .mode = (unsigned int)atoi(argv[6]) };
		printf("%ld\n",
		       fe_lsm_verdict((unsigned int)atoi(argv[2]),
				      atoi(argv[3]), atoi(argv[4]), &d));
		return 0;
	}
	if (argc == 2) {
		printf("%ld\n", fe_lsm_result((int)strtol(argv[1], NULL, 10)));
		return 0;
	}
	if (argc != 3)
		return 2;
	FILE *program = fopen(argv[1], "rb"), *facts = fopen(argv[2], "rb");
	if (!program || !facts || fseek(program, 0, SEEK_END))
		return 2;
	long size = ftell(program);
	if (size <= 0 || size % 288 || size / 288 > FM_MAX_ENTRIES ||
	    fseek(program, 0, SEEK_SET))
		return 2;
	struct fixture fixture = { .count = size / 288 };
	fixture.entries = calloc(fixture.count, 288);
	struct fe_facts *f = calloc(1, sizeof(*f));
	struct fe_scratch *s = calloc(1, sizeof(*s));
	if (!fixture.entries || !f || !s ||
	    fread(fixture.entries, 288, fixture.count, program) !=
		    fixture.count ||
	    fread(f, sizeof(*f), 1, facts) != 1)
		return 2;
#ifdef FE_FIXED_MAP_TEST
	active_fixture = &fixture;
#endif
	memset(s, 0xa5, sizeof(*s));
	int result = fe_evaluate(&fixture, f, s);
	struct fe_decision first = s->decision;
	int again = fe_evaluate(&fixture, f, s);
	if (result != again || memcmp(&first, &s->decision, sizeof(first)))
		return 3;
#ifdef FE_STAGE_CANDIDATE
	struct fe_scratch *staged = calloc(1, sizeof(*staged));
	struct fe_stage_cursor cursor = {};
	if (!staged)
		return 4;
	memset(staged, 0xa5, sizeof(*staged));
	int staged_result = fe_stage_begin(&fixture, f, staged, &cursor);
	unsigned int passes = 0;
	if (staged_result == 0) {
		for (unsigned int pass = 0;
		     pass < 17 && cursor.state == FE_STAGE_ACTIVE;
		     pass++, passes++)
			staged_result =
				fe_stage_advance(&fixture, f, staged, &cursor);
		if (cursor.state != FE_STAGE_READY)
			return 5;
		staged_result = fe_stage_finish(&fixture, staged, &cursor);
	}
	if (((const struct fe_header *)fixture.entries)->rules == 256 &&
	    (passes != 16 || cursor.next_rule != 256))
		return 7;
	if (staged_result != result ||
	    memcmp(&first, &staged->decision, sizeof(first))) {
		fprintf(stderr,
			"staged evaluator differs: original=%d staged=%d rule=%u state=%u\n",
			result, staged_result, cursor.next_rule, cursor.state);
		return 6;
	}
	struct fe_decision final = staged->decision;
	if (cursor.state == FE_STAGE_FINISHED &&
	    (fe_stage_finish(&fixture, staged, &cursor) != -1 ||
	     fe_stage_advance(&fixture, f, staged, &cursor) != -1 ||
	     memcmp(&final, &staged->decision, sizeof(final))))
		return 8;
	struct fe_scratch *tampered = calloc(1, sizeof(*tampered));
	struct fe_stage_cursor bad = {};
	if (!tampered)
		return 9;
	if (fe_stage_begin(&fixture, f, tampered, &bad) == 0 &&
	    bad.state == FE_STAGE_ACTIVE) {
		bad.generation++;
		if (fe_stage_advance(&fixture, f, tampered, &bad) != -1 ||
		    tampered->decision.error != FE_INVALID ||
		    fe_stage_finish(&fixture, tampered, &bad) != -1)
			return 10;
	}
	free(tampered);
	free(staged);
#endif
	printf("%d %u %u %u", result, first.deny, first.mode, first.error);
	for (unsigned int i = 0; i < 4; i++)
		printf(" %llu", first.matched_rules[i]);
	for (unsigned int i = 0; i < 8; i++)
		printf(" %llu", first.proposed_roles[i]);
	fm_u32 policies = 0, writers = 0;
	const struct fe_header *head = (const void *)fixture.entries;
	int execution_class = fe_execution_class(&fixture, head->generation,
						 &policies, &writers);
	printf(" %u %u %u %u %u\n", first.audit_unknown,
	       (unsigned int)execution_class, writers, first.enforced_writes,
	       first.role_conflicts);
	fclose(program);
	fclose(facts);
	free(fixture.entries);
	free(f);
	free(s);
	return 0;
}

#endif
