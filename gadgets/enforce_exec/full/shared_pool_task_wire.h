/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_TASK_WIRE_H
#define ENFORCE_EXEC_SHARED_POOL_TASK_WIRE_H

/* One TASK payload wire shape for the typed pool and opaque-key candidates.
 * The identity prefix is checked before any semantic byte is exposed. The
 * remainder is not authority until a typed lexical handle owns the payload. */
struct se_ol_task_identity {
	__u32 reserved_lock, flags;
	__u64 physical_cookie, scope_cookie, eligibility_version,
		next_invocation;
	__u32 scope_slot, identity_reserved;
};
struct se_pool_task_wire {
#if defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE) || \
	defined(ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE)
	union {
		struct {
			struct se_ol_task_identity identity;
			__u8 bytes[1280 - sizeof(struct se_ol_task_identity)];
		};
		struct {
			struct se_task_state semantic;
			__u8 semantic_extension[1280 -
						sizeof(struct se_task_state)];
		};
	};
#else
	struct se_ol_task_identity identity;
	__u8 bytes[1280 - sizeof(struct se_ol_task_identity)];
#endif
};
_Static_assert(sizeof(struct se_ol_task_identity) == 48,
	       "selected TASK semantic identity prefix");
_Static_assert(sizeof(struct se_pool_task_wire) == 1280,
	       "selected TASK payload wire size");
_Static_assert(__builtin_offsetof(struct se_pool_task_wire, identity) == 0 &&
		       __builtin_offsetof(struct se_pool_task_wire, bytes) ==
			       48,
	       "selected TASK payload identity offset");
#if defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE) || \
	defined(ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE)
_Static_assert(
	sizeof(struct se_task_state) == 960 &&
		__builtin_offsetof(struct se_pool_task_wire, semantic) == 0 &&
		__builtin_offsetof(struct se_pool_task_wire,
				   semantic_extension) == 960 &&
		__builtin_offsetof(struct se_pool_task_wire,
				   semantic.committed) ==
			__builtin_offsetof(struct se_pool_task_wire, bytes) &&
		__builtin_offsetof(struct se_pool_task_wire,
				   semantic.physical_cookie) ==
			__builtin_offsetof(struct se_pool_task_wire,
					   identity.physical_cookie) &&
		__builtin_offsetof(struct se_pool_task_wire,
				   semantic.scope_cookie) ==
			__builtin_offsetof(struct se_pool_task_wire,
					   identity.scope_cookie) &&
		__builtin_offsetof(struct se_pool_task_wire, semantic.flags) ==
			__builtin_offsetof(struct se_pool_task_wire,
					   identity.flags),
	"typed TASK semantic must overlay the opaque identity wire");
#endif
#endif
