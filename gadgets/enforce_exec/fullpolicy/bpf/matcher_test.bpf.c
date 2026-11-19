/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 The Inspektor Gadget authors */
/* Test-run-only socket filter. It is never attached to a socket or hook. */
struct fm_blob;
static inline const struct fm_blob *lookup_global(unsigned int);
#define FM_GLOBAL_BLOB_LOOKUP(key) lookup_global(key)
#define FM_BLOB_LOOKUP(context, key) lookup_global(key)
#include "matcher.h"

#define SEC(name) __attribute__((section(name), used))
#define MAP_UINT(name, value) int(*name)[value]
#define MAP_TYPE(name, value) value *name
struct {
	MAP_UINT(type, 1); /* BPF_MAP_TYPE_HASH */
	MAP_UINT(max_entries, FM_MAX_ENTRIES);
	MAP_UINT(map_flags,
		 1U << 7); /* BPF_F_RDONLY_PROG, matching production */
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fm_blob);
} blobs SEC(".maps");
struct {
	MAP_UINT(type, 2); /* BPF_MAP_TYPE_ARRAY */
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fm_scratch);
} scratch_map SEC(".maps");
struct matcher_input {
	fm_u32 pattern_key, length;
	fm_u8 bytes[256];
};
struct {
	MAP_UINT(type, 2);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct matcher_input);
} input_map SEC(".maps");
static void *(*map_lookup)(void *, const void *) = (void *)1;
static inline const struct fm_blob *lookup_global(unsigned int key)
{
	return map_lookup(&blobs, &key);
}
SEC("socket") int matcher(void *unused)
{
	(void)unused;
	fm_u32 zero = 0;
	struct matcher_input *input = map_lookup(&input_map, &zero);
	struct fm_scratch *scratch = map_lookup(&scratch_map, &zero);
	if (!input || !scratch)
		return 0;
	fm_u32 key = input->pattern_key;
	const struct fm_blob *pattern = map_lookup(&blobs, &key);
	if (!pattern)
		return 0;
	/* Program.Test reports an unsigned result; offset the tri-state result. */
	int result =
		fm_match_key(&blobs, key, input->bytes, input->length, scratch);
	return result + 1;
}
char LICENSE[] SEC("license") = "GPL";
