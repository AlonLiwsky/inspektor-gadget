// SPDX-License-Identifier: GPL-2.0
// Load-only verifier probe for full 4,096-byte argv validation. Never attach.
#define FE_BOUNDED_LOOP_CANDIDATE 1
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#define BPF_MAP_TYPE_ARRAY 2
struct fm_blob;
static inline const struct fm_blob *unused_blob(void *ctx, unsigned int key)
{
	(void)ctx;
	(void)key;
	return 0;
}
#define FM_BLOB_LOOKUP(ctx, key) unused_blob(ctx, key)
#include "../bpf/evaluator.h"
#define SEC(name) __attribute__((section(name), used))
#define MAP_UINT(name, value) int(*name)[value]
#define MAP_TYPE(name, value) value *name
struct {
	MAP_UINT(type, BPF_MAP_TYPE_ARRAY);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fe_facts);
} argv_facts SEC(".maps");
struct {
	MAP_UINT(type, BPF_MAP_TYPE_ARRAY);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fe_scratch);
} argv_scratch SEC(".maps");
static void *(*map_lookup)(void *, const void *) = (void *)1;
SEC("socket") int evaluator_argv_probe(void *unused)
{
	(void)unused;
	fm_u32 zero = 0;
	const struct fe_facts *facts = map_lookup(&argv_facts, &zero);
	struct fe_scratch *scratch = map_lookup(&argv_scratch, &zero);
	return fe_argv_valid(facts, scratch);
}
char LICENSE[] SEC("license") = "GPL";
