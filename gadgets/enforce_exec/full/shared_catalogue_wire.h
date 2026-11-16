/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_CATALOGUE_WIRE_H
#define ENFORCE_EXEC_SHARED_CATALOGUE_WIRE_H
/* Requires __u32, __u64 and __always_inline from the including BPF or host
 * source. Publication and retained opaque WORK readers share this exact wire
 * and absent-index versus invalid-present-cell interpretation. */
struct se_epoch_cell {
	__u64 scope, uid, epoch;
	__u32 reserved0, reserved1;
};
_Static_assert(sizeof(struct se_epoch_cell) == 32, "epoch cell wire");

/* A present index must resolve to its exact, committed cell. A foreign,
 * missing or malformed cell is unavailable history (ER_UNKNOWN), never proof
 * that the UID was not activated. Only an absent index in the complete,
 * non-evicting catalogue proves never accepted. */
static __always_inline __u64 se_catalogue_read(const struct se_epoch_cell *cell,
					       __u64 scope, __u64 uid)
{
	if (!scope || !uid || uid == ~0ULL || !cell || cell->scope != scope ||
	    cell->uid != uid || !cell->epoch || cell->epoch == ~0ULL ||
	    cell->reserved0 || cell->reserved1)
		return ~0ULL;
	return cell->epoch;
}
/* Keep the absent-index/invalid-present-cell distinction explicit for every
 * reader, including the lexical opaque WORK catalogue cache. */
static __always_inline __u64 se_catalogue_indexed_read(
	int indexed, const struct se_epoch_cell *cell, __u64 scope, __u64 uid)
{
	return indexed ? se_catalogue_read(cell, scope, uid) : 0;
}
#endif
