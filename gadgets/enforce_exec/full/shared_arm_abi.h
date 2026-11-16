/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_ARM_ABI_H
#define ENFORCE_EXEC_SHARED_ARM_ABI_H

/* Include after Linux __u32/__u64 definitions, in BPF or native C. These
 * operations belong to the fexit publication barrier, not se_command. */
#define SE_ARM_COMMIT 1
#define SE_ARM_WITHDRAW 2
#define SE_ARM_BIND 3

struct se_arm_request {
	__u64 node_cookie, nonce, sequence;
	__u64 scope, serial, expected_generation, qualification;
	__u32 operation, binding, record, count, reserved;
	__u32 bank_index[8];
	__u64 epochs[8];
};
struct se_arm_receipt {
	__u64 node_cookie, sequence, generation, serial;
	__u32 operation, status, value, reserved;
};
_Static_assert(sizeof(struct se_arm_request) == 176, "arm request wire");
_Static_assert(sizeof(struct se_arm_receipt) == 48, "arm receipt wire");

#endif
