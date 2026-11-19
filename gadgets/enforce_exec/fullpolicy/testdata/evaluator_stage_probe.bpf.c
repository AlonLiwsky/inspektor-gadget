// SPDX-License-Identifier: GPL-2.0
// Unattached verifier and TEST_RUN probe for one candidate rule window.
#define FE_BOUNDED_LOOP_CANDIDATE 1
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_F_RDONLY_PROG (1U << 7)
struct fm_blob;
static inline const struct fm_blob *stage_blob(unsigned int key);
#define FM_GLOBAL_BLOB_LOOKUP(key) stage_blob(key)
#define FM_BLOB_LOOKUP(context, key) stage_blob(key)
#include "../bpf/evaluator_stage_candidate.h"
#define SEC(name) __attribute__((section(name), used))
#define MAP_UINT(name, value) int(*name)[value]
#define MAP_TYPE(name, value) value *name
struct {
	MAP_UINT(type, BPF_MAP_TYPE_ARRAY);
	MAP_UINT(max_entries, FM_MAX_ENTRIES);
	MAP_UINT(map_flags, BPF_F_RDONLY_PROG);
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fm_blob);
} stage_blobs SEC(".maps");
struct {
	MAP_UINT(type, BPF_MAP_TYPE_ARRAY);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fe_facts);
} stage_facts SEC(".maps");
struct {
	MAP_UINT(type, BPF_MAP_TYPE_ARRAY);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fe_scratch);
} stage_scratch SEC(".maps");
struct {
	MAP_UINT(type, BPF_MAP_TYPE_ARRAY);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fe_stage_cursor);
} stage_cursor SEC(".maps");
static void *(*map_lookup)(void *, const void *) = (void *)1;
static inline const struct fm_blob *stage_blob(unsigned int key)
{
	return map_lookup(&stage_blobs, &key);
}
SEC("socket") int evaluator_stage_probe(void *unused)
{
	(void)unused;
	fm_u32 zero = 0;
	const struct fe_facts *facts = map_lookup(&stage_facts, &zero);
	struct fe_scratch *scratch = map_lookup(&stage_scratch, &zero);
	struct fe_stage_cursor *cursor = map_lookup(&stage_cursor, &zero);
	if (!facts || !scratch || !cursor)
		return 0;
	return fe_stage_advance(&stage_blobs, facts, scratch, cursor) + 1;
}
char LICENSE[] SEC("license") = "GPL";
