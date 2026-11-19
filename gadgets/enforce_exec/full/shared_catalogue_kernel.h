/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_CATALOGUE_KERNEL_H
#define ENFORCE_EXEC_SHARED_CATALOGUE_KERNEL_H
#include "shared_route.h"
#include "shared_catalogue_wire.h"
#ifndef SE_PROFILE_ACCEPTED_UIDS
#error "successful-history catalogue requires explicit accepted UID capacity"
#endif
/* Kernel-owned, non-evicting successful-activation history. A present index
 * is never proof by itself: the cell must match the exact scope and UID. */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, SE_PROFILE_ACCEPTED_UIDS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, __u32);
	__type(value, struct se_epoch_cell);
} se_epoch_bank SEC(".maps");
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, SE_PROFILE_ACCEPTED_UIDS);
	__uint(map_flags, BPF_F_RDONLY);
	__type(key, struct se_epoch_key);
	__type(value, __u32);
} se_epoch_index SEC(".maps");
#ifndef SE_EPOCH_BANK_LOOKUP
#define SE_EPOCH_BANK_LOOKUP(key) bpf_map_lookup_elem(&se_epoch_bank, key)
#endif
static __always_inline __u64 se_catalogue_epoch(__u64 scope, __u64 uid)
{
	struct se_epoch_key key = { scope, uid };
	const __u32 *index = bpf_map_lookup_elem(&se_epoch_index, &key);
	__u32 bank;
	const struct se_epoch_cell *cell;

	if (!index)
		return 0;
	bank = *index;
	cell = SE_EPOCH_BANK_LOOKUP(&bank);
	return se_catalogue_indexed_read(1, cell, scope, uid);
}
#endif
