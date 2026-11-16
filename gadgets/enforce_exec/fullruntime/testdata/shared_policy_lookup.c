// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fm_blob;
#ifdef SE_LOOKUP_ORACLE
static const struct fm_blob *legacy_lookup(void *, unsigned int);
#define FM_BLOB_LOOKUP(ctx, key) legacy_lookup(ctx, key)
#include "evaluator.h"
#else
#ifdef SE_LOOKUP_GLOBAL
struct se_policy_view;
extern struct se_policy_view global_view;
#define SE_POLICY_VIEW(ctx) ((void)(ctx), &global_view)
#define FM_GLOBAL_BLOB_LOOKUP(key) se_policy_data(&global_view, key)
#endif
#include "shared_policy_lookup.h"
struct se_policy_view global_view;
#endif

struct loaded {
	struct fm_blob *entries, *original;
	unsigned count;
	unsigned long long generation;
};
static struct loaded objects[8], legacy;
static unsigned object_count, scenario;
static int inject_fault;
#ifndef SE_LOOKUP_ORACLE
static inline const struct fm_blob *
se_policy_physical(void *context, fm_u32 slot, fm_u64 generation, fm_u32 key)
{
	(void)context;
	if (slot >= object_count || generation != objects[slot].generation ||
	    key >= objects[slot].count)
		return 0;
	if (inject_fault && slot == 1 && key >= 10)
		return 0;
	return &objects[slot].entries[key];
}
#else
static const struct fm_blob *legacy_lookup(void *context, unsigned key)
{
	(void)context;
	if (inject_fault && key >= 11)
		return 0;
	return key < legacy.count ? &legacy.entries[key] : 0;
}
#endif
static unsigned read_u32(FILE *f)
{
	uint32_t value;
	assert(fread(&value, sizeof(value), 1, f) == 1);
	return value;
}
static void load(FILE *f, struct loaded *out)
{
	out->count = read_u32(f);
	assert(out->count >= 9 && out->count <= FM_MAX_ENTRIES);
	out->entries = calloc(out->count, sizeof(*out->entries));
	assert(out->entries && fread(out->entries, sizeof(*out->entries),
				     out->count, f) == out->count);
	out->original = malloc(out->count * sizeof(*out->entries));
	assert(out->original);
	memcpy(out->original, out->entries, out->count * sizeof(*out->entries));
}
static void path(struct fe_path *p, const char *text)
{
	p->length = strlen(text);
	assert(p->length <= 255);
	memcpy(p->bytes, text, p->length);
}
#ifndef SE_LOOKUP_ORACLE
static void check_lookup_identity_and_stability(struct se_policy_view *v)
{
	assert(!se_policy_data(v, 10)); /* no selected rule yet */
	unsigned global = 0;
	for (unsigned i = 0; i < object_count; i++) {
		assert(se_policy_policy(v, i)->root_epoch == i + 2);
		for (unsigned local = 0; local < v->rule_counts[i];
		     local++, global++) {
			const struct fe_rule *rule = se_policy_rule(v, global);
			assert(rule && rule->policy == i);
			struct fe_rule expected =
				*(const struct fe_rule *)&objects[i]
					 .entries[9 + local];
			expected.policy = i;
			assert(!memcmp(rule, &expected, sizeof(expected)));
			const struct fe_header *header = se_policy_header(v);
			const struct fe_policy *other =
				se_policy_policy(v, (i + 1) % object_count);
			const struct fe_string *container =
				se_policy_container(v);
			assert(header && other && container &&
			       v->selected == i);
			unsigned key = 9 + v->rule_counts[i];
			assert(se_policy_data(v, key) ==
			       &objects[i].entries[key]);
			assert(!memcmp(rule, &expected, sizeof(expected)));
			/* The same local integer can be a synthetic global rule key;
			 * data lookup must never select another object or rewrite scratch. */
			assert(!se_policy_data(v, 1));
			assert(!se_policy_data(v, objects[i].count));
			unsigned long long saved = objects[i].generation;
			objects[i].generation++;
			assert(!se_policy_data(v, key));
			assert(!se_policy_rule(v, global));
			objects[i].generation = saved;
			assert(se_policy_rule(v, global));
		}
	}
	assert(!se_policy_rule(v, v->header.rules));
	assert(!se_policy_data(v, 10));
}
#endif
int main(int argc, char **argv)
{
	assert(argc == 2);
#ifndef SE_LOOKUP_ORACLE
	if (!strcmp(argv[1], "--layout")) {
		printf("view=%zu ref=%zu header=%zu policy=%zu rule=%zu container=%zu\n",
		       sizeof(struct se_policy_view),
		       sizeof(struct se_policy_ref), sizeof(struct fe_header),
		       sizeof(struct fe_policy), sizeof(struct fe_rule),
		       sizeof(struct fe_string));
		return 0;
	}
#endif
	FILE *f = fopen(argv[1], "rb");
	assert(f);
	object_count = read_u32(f);
	scenario = read_u32(f);
	assert(object_count && object_count <= 8);
	for (unsigned i = 0; i < object_count; i++) {
		load(f, &objects[i]);
		objects[i].generation = 100 + i;
	}
	load(f, &legacy);
	assert(!fclose(f));
	struct fe_facts facts = {};
	struct fe_scratch scratch = {};
	path(&facts.actor_path, "/actor");
	path(&facts.target_path, "/allowed");
	facts.actor_image = facts.target_image = 1;
	facts.effective_uid = scenario & 8 ? 99 : 1000;
	facts.uid_known = 1;
	facts.fs_mask = facts.fs_known = FE_MEMFD;
	facts.ancestors_complete = 1;
	facts.argc = 1;
	facts.argv_bytes = 4;
	facts.argv_complete = 1;
	memcpy(facts.argv, "arg", 4);
	facts.stdin_pipe = 1;
	if (scenario & 4)
		facts.actor_path.length = 0;
	if (scenario & 16)
		facts.target_image = -1;
	const struct fe_header *h = (const void *)&legacy.entries[0];
	if (!(scenario & 1)) {
		facts.role_count = object_count;
		for (unsigned i = 0; i < object_count; i++) {
			const struct fe_policy *p =
				(const void *)&legacy.entries[1 + i];
			facts.roles[i] =
				(struct fe_role){ p->uid, p->root_role };
		}
	}
	int error;
#ifdef SE_LOOKUP_ORACLE
	(void)h;
	inject_fault = scenario & 32;
	error = fe_evaluate(0, &facts, &scratch);
#else
	struct se_policy_ref refs[8] = {};
	for (unsigned i = 0; i < object_count; i++)
		refs[i] = (struct se_policy_ref){ .slot = i,
						  .generation =
							  objects[i].generation,
						  .root_epoch = i + 2,
						  .entries = objects[i].count };
	const struct fe_string *container =
		(const void *)&legacy.entries[h->container];
	struct se_policy_view *v = &global_view;
	assert(!se_policy_prepare(v, 0, 77, 9, container, refs, object_count));
	check_lookup_identity_and_stability(v);
	for (unsigned i = 0; i < object_count; i++)
		refs[i].root_epoch = 1;
	assert(!se_policy_prepare(v, 0, 88, 10, container, refs, object_count));
	assert(v->scope_cookie == 88 && se_policy_header(v)->generation == 10);
	for (unsigned i = 0; i < object_count; i++) {
		assert(se_policy_policy(v, i)->root_epoch == 1);
		refs[i].root_epoch = i + 2;
	}

	unsigned long long saved = refs[0].generation;
	refs[0].generation++;
	assert(se_policy_prepare(v, 0, 77, 9, container, refs, object_count) <
	       0);
	assert(!se_policy_header(v) && !se_policy_rule(v, 0) &&
	       !se_policy_data(v, 10));
	refs[0].generation = saved;
	assert(!se_policy_prepare(v, 0, 77, 9, container, refs, object_count));
	unsigned policies, writers;
	assert(fe_execution_class(v, 9, &policies, &writers) >= 1 &&
	       policies == object_count);
	inject_fault = scenario & 32;
	error = fe_evaluate(v, &facts, &scratch);
#endif
	struct fe_decision *d = &scratch.decision;
#ifndef FE_AUDIT_ISOLATION
#error "parity fixture requires development decision fields"
#endif
	/* Assert that the new parity columns exercise real semantic state, not just
  * two matching zero-filled outputs. The existing evaluator is the oracle. */
	if (scenario & 64) {
		assert(d->enforced_writes == 1 && d->known_role_witnesses[0]);
		assert(d->proposed_roles[0] == d->known_role_witnesses[0]);
	}
	if (scenario & 128) {
		assert(d->error == FE_ROLE_CONFLICT && d->role_conflicts == 1);
		assert(d->enforced_writes == 1 && d->known_role_witnesses[0]);
		assert(!d->proposed_roles[0]);
	}
	if (scenario & 256) {
		assert(d->error == FE_AUDIT_UNKNOWN &&
		       (d->audit_unknown & FE_AUDIT_GLOBAL_SUPPRESS));
		assert(d->enforced_writes == 1 && d->known_role_witnesses[0]);
		assert(!d->proposed_roles[0]);
	}
	if (scenario & 512) {
		assert(d->error == FE_AUDIT_UNKNOWN && d->role_conflicts == 1);
		assert(!d->enforced_writes && d->known_role_witnesses[0]);
		assert((FE_ROLE_UNCERTAIN(d->audit_unknown) & 1) &&
		       !d->proposed_roles[0]);
	}
	if (scenario & 1024) {
		assert(d->error == FE_UNKNOWN && d->enforced_writes == 1);
		assert(d->known_role_witnesses[0] && !d->proposed_roles[0]);
	}
	if (scenario & 2048) {
		assert(d->error == FE_AUDIT_UNKNOWN && d->enforced_writes == 1);
		assert((FE_ROLE_UNCERTAIN(d->audit_unknown) & 2) &&
		       (FE_ROLE_WRITES(d->audit_unknown) & 2));
		assert(d->known_role_witnesses[0] &&
		       !d->known_role_witnesses[1]);
		assert(d->proposed_roles[0] && !d->proposed_roles[1]);
	}
	printf("%d %u %u %u %u", error, d->deny, d->mode, d->error,
	       d->audit_unknown);
	for (unsigned i = 0; i < 4; i++)
		printf(" %llu", d->matched_rules[i]);
	for (unsigned i = 0; i < 8; i++)
		printf(" %llu", d->proposed_roles[i]);
	printf(" %u %u", d->enforced_writes, d->role_conflicts);
	for (unsigned i = 0; i < 8; i++)
		printf(" %llu", d->known_role_witnesses[i]);
	puts("");
	for (unsigned i = 0; i < object_count; i++) {
		assert(!memcmp(objects[i].entries, objects[i].original,
			       objects[i].count * sizeof(struct fm_blob)));
		free(objects[i].entries);
		free(objects[i].original);
	}
	free(legacy.entries);
	free(legacy.original);
}
