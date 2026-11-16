/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <linux/bpf.h>
#include <stddef.h>
#include <stdio.h>

#define __uint(name, value) int(*name)[value]
#define __type(name, value) value *name
#define SEC(name)
#define ENFORCE_EXEC_ABI3_DEVELOPMENT 1
#define ENFORCE_EXEC_SHARED_NODE 1
#define ENFORCE_EXEC_POOL_ABI_CANDIDATE_ONLY 1
#define ENFORCE_EXEC_POOL_DEVELOPMENT 1
#define ENFORCE_EXEC_POOL_SEMANTIC_VIEW_CANDIDATE 1
#define SE_PROFILE_TASKS 128
#define SE_PROFILE_SCRATCH 32
#define SE_PROFILE_BINDINGS 2
#define SE_PROFILE_TASK_QUOTA 64
#define SE_PROFILE_SCRATCH_QUOTA 16

/* The production semantic types have these fixed prefix sizes and offsets.
 * This fixture tests the candidate ABI's typed embedding, not production
 * helper invocation or BPF verifier acceptance. */
struct er_state {
	_Alignas(8) unsigned char bytes[520];
};
struct se_task_stage {
	_Alignas(8) unsigned char bytes[64];
};
struct se_reader_owner {
	_Alignas(8) unsigned char bytes[48];
};
struct se_exec_transaction {
	_Alignas(8) unsigned char bytes[272];
};
struct se_policy_view {
	_Alignas(8) unsigned char bytes[904];
};
struct se_exec_work {
	_Alignas(8) unsigned char bytes[1704];
};
struct er_work {
	_Alignas(8) unsigned char bytes[536];
};
struct observation {
	_Alignas(8) unsigned char bytes[16008];
};
struct se_task_state {
	__u32 reserved_lock, flags;
	__u64 physical_cookie, scope_cookie, eligibility_version,
		next_invocation;
	__u32 scope_slot, identity_reserved;
	struct er_state committed;
	struct se_task_stage staged;
	struct se_reader_owner reader;
	__u64 reader_invocation;
	struct se_exec_transaction exec;
};
struct se_invocation {
	__u64 scope, cookie, sequence;
	__u32 slot, reserved;
	struct se_policy_view view;
	struct se_exec_work history;
	struct er_work inherited;
	struct observation observation;
};
#include "shared_pool_abi_candidate.h"

_Static_assert(sizeof(struct se_task_state) == 960, "TASK semantic prefix");
_Static_assert(sizeof(struct se_invocation) == 19184, "WORK semantic prefix");
_Static_assert(offsetof(struct se_pool_task_payload, semantic) == 0,
	       "TASK semantic member starts at zero");
_Static_assert(offsetof(struct se_pool_task_payload, semantic.flags) == 4,
	       "TASK flags preserve wire offset");
_Static_assert(offsetof(struct se_pool_work_payload, semantic) == 0,
	       "WORK semantic member starts at zero");

int main(void)
{
	puts("typed pool semantic prefix candidate OK");
	return 0;
}
