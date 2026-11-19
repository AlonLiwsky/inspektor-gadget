/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_INVOCATION_WIRE_H
#define ENFORCE_EXEC_SHARED_INVOCATION_WIRE_H

/* Include after shared_exec.h, shared_inherit_snapshot.h and the policy
 * view. This is the one selected WORK semantic type, not a second owner. */
struct se_invocation {
	__u64 scope, cookie, sequence;
	__u32 slot, reserved;
	struct se_policy_view view;
	struct se_exec_work history;
	struct er_work inherited;
	struct observation observation;
};
_Static_assert(sizeof(struct se_invocation) == 19184,
	       "shared invocation semantic wire size");
#endif
