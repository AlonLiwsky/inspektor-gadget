/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_WIRE_H
#define ENFORCE_EXEC_SHARED_POOL_OPAQUE_WORK_WIRE_H
#if defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE) &&       \
	(!defined(ENFORCE_EXEC_POOL_OPAQUE_TASK_SEMANTIC_CANDIDATE) || \
	 defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE))
#error "typed opaque WORK requires its exclusive typed TASK owner"
#endif
#if defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE) || \
	defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE)
#include "shared_pool_epoch_cache_wire.h"
#endif

/* The first 32 bytes are the opaque WORK identity; the candidate semantic
 * view overlays the real invocation type only when that type is available. */
struct se_owk_payload {
#if defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE) || \
	defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE)
	union {
		struct {
			__u64 scope, cookie, sequence;
			__u32 slot, reserved;
			__u8 bytes[19456 - 32];
		};
		struct {
			struct se_invocation semantic;
			struct se_pool_epoch_cache catalogue;
		};
	};
#else
	__u64 scope, cookie, sequence;
	__u32 slot, reserved;
	__u8 bytes[19456 - 32];
#endif
};
_Static_assert(sizeof(struct se_owk_payload) == 19456 &&
		       __builtin_offsetof(struct se_owk_payload, bytes) == 32,
	       "opaque WORK semantic wire geometry");
#if defined(ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE) || \
	defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SEMANTIC_CANDIDATE)
_Static_assert(
	sizeof(struct se_invocation) == 19184 &&
		__builtin_offsetof(struct se_owk_payload, semantic) == 0 &&
		__builtin_offsetof(struct se_owk_payload, catalogue) == 19184 &&
		__builtin_offsetof(struct se_owk_payload, semantic.view) ==
			__builtin_offsetof(struct se_owk_payload, bytes) &&
		__builtin_offsetof(struct se_owk_payload, semantic.history) ==
			936 &&
		__builtin_offsetof(struct se_owk_payload, semantic.inherited) ==
			2640 &&
		__builtin_offsetof(struct se_owk_payload,
				   semantic.observation) == 3176 &&
		__builtin_offsetof(struct se_owk_payload, semantic.scope) ==
			__builtin_offsetof(struct se_owk_payload, scope) &&
		__builtin_offsetof(struct se_owk_payload, semantic.cookie) ==
			__builtin_offsetof(struct se_owk_payload, cookie) &&
		__builtin_offsetof(struct se_owk_payload, semantic.sequence) ==
			__builtin_offsetof(struct se_owk_payload, sequence) &&
		__builtin_offsetof(struct se_owk_payload, semantic.slot) ==
			__builtin_offsetof(struct se_owk_payload, slot) &&
		__builtin_offsetof(struct se_owk_payload, semantic.reserved) ==
			__builtin_offsetof(struct se_owk_payload, reserved),
	"typed WORK semantic must overlay the opaque identity wire");
#endif
#endif
