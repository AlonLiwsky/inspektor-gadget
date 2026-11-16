/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <linux/types.h>
#include <stddef.h>
#include "shared_arm_abi.h"

_Static_assert(SE_ARM_COMMIT == 1 && SE_ARM_WITHDRAW == 2 && SE_ARM_BIND == 3,
	       "arm operation domain");
_Static_assert(offsetof(struct se_arm_request, node_cookie) == 0,
	       "node cookie");
_Static_assert(offsetof(struct se_arm_request, sequence) == 16, "sequence");
_Static_assert(offsetof(struct se_arm_request, qualification) == 48,
	       "qualification");
_Static_assert(offsetof(struct se_arm_request, operation) == 56, "operation");
_Static_assert(offsetof(struct se_arm_request, reserved) == 72, "reserved");
_Static_assert(offsetof(struct se_arm_request, bank_index) == 76,
	       "bank indexes");
_Static_assert(offsetof(struct se_arm_request, epochs) == 112, "epochs");
_Static_assert(offsetof(struct se_arm_receipt, generation) == 16, "generation");
_Static_assert(offsetof(struct se_arm_receipt, operation) == 32,
	       "receipt operation");
_Static_assert(offsetof(struct se_arm_receipt, reserved) == 44,
	       "receipt reserved");
int main(void)
{
	return 0;
}
