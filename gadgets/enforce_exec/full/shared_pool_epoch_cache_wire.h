/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_EPOCH_CACHE_WIRE_H
#define ENFORCE_EXEC_SHARED_POOL_EPOCH_CACHE_WIRE_H

/* Exact WORK extension shared by the flat and opaque semantic candidates.
 * A scoped, retained catalogue claim must fill it; the wire alone grants no
 * UID-history authority. Zero is valid only when the COMPLETE catalogue
 * proves a UID was never accepted, never when lookup merely failed. */
struct se_pool_epoch_cache_row {
	__u64 uid, accepted_epoch;
};
struct se_pool_epoch_cache {
	__u64 scope, generation;
	struct se_pool_epoch_cache_row rows[16];
};
_Static_assert(sizeof(struct se_pool_epoch_cache) == 272,
	       "selected WORK catalogue cache wire size");
#endif
