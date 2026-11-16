/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_INHERIT_ROLES_H
#define ENFORCE_EXEC_SHARED_INHERIT_ROLES_H

/* Requires epoch_roles.h. The child is physically unpublished; caller owns
 * the parent lock, has revalidated its snapshot, and owns child birth (HASH
 * physical-key exclusion or pool constructor lease). Preflight every fixed
 * row before the first write and publish version last. HASH and pool
 * adapters share role-copy semantics; this helper grants no ownership. */
static inline __attribute__((always_inline)) int
se_child_roles_publish(struct er_state *child, const struct er_work *projected)
{
	if (!child || !projected || child->version)
		return -1;
#ifdef __clang__
#pragma clang loop unroll(full)
#endif
	for (__u32 j = 0; j < 16; j++)
		if (child->rows[j].uid || child->rows[j].epoch ||
		    child->rows[j].role
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
		    || child->rows[j].knowledge || child->rows[j].reserved
#endif
		)
			return -1;
	for (__u32 j = 0; j < 16; j++)
		child->rows[j] = projected->rows[j];
	child->version = 1;
	return 0;
}
#endif
