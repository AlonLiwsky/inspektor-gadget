/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright 2026 The Inspektor Gadget authors */
/* TEST_RUN-only scalar-context verifier fixture; never attached. */
struct fm_blob;
static inline const struct fm_blob *
lookup_scalar(unsigned int, unsigned long long, unsigned int);
#define FM_GLOBAL_SCALAR_BLOB_LOOKUP(slot, cookie, key) \
	lookup_scalar((slot), (cookie), (key))
#define FM_BLOB_LOOKUP(context, key)                                       \
	lookup_scalar(((const struct fm_global_token *)(context))->slot,   \
		      ((const struct fm_global_token *)(context))->cookie, \
		      (key))
#include "matcher.h"

#define SEC(name) __attribute__((section(name), used))
#define MAP_UINT(name, value) int(*name)[value]
#define MAP_TYPE(name, value) value *name
struct {
	MAP_UINT(type, 1); /* BPF_MAP_TYPE_HASH */
	MAP_UINT(max_entries, 2 * FM_MAX_ENTRIES);
	MAP_UINT(map_flags, 1U << 7); /* BPF_F_RDONLY_PROG */
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fm_blob);
} blobs SEC(".maps");
struct {
	MAP_UINT(type, 2);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct fm_scratch);
} scratch_map SEC(".maps");
struct matcher_scalar_input {
	fm_u32 pattern_key, length, slot, reserved;
	fm_u64 cookie;
	fm_u8 bytes[256];
};
struct {
	MAP_UINT(type, 2);
	MAP_UINT(max_entries, 1);
	MAP_TYPE(key, fm_u32);
	MAP_TYPE(value, struct matcher_scalar_input);
} input_map SEC(".maps");
static void *(*map_lookup)(void *, const void *) = (void *)1;
static inline const struct fm_blob *lookup_scalar(fm_u32 slot, fm_u64 cookie,
						  fm_u32 key)
{
	if (slot >= 2 || cookie != 101 + slot || key >= FM_MAX_ENTRIES)
		return 0;
	fm_u32 actual = slot * FM_MAX_ENTRIES + key;
	return map_lookup(&blobs, &actual);
}
SEC("socket") int matcher_scalar(void *unused)
{
	(void)unused;
	fm_u32 zero = 0;
	struct matcher_scalar_input *input = map_lookup(&input_map, &zero);
	struct fm_scratch *scratch = map_lookup(&scratch_map, &zero);
	if (!input || !scratch)
		return 0;
	struct fm_global_token token = {
		.slot = input->slot,
		.reserved = input->reserved,
		.cookie = input->cookie,
	};
	return fm_match_key(&token, input->pattern_key, input->bytes,
			    input->length, scratch) +
	       1;
}
char LICENSE[] SEC("license") = "GPL";
