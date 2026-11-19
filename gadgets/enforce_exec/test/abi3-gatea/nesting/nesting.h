// SPDX-License-Identifier: GPL-2.0
#ifndef IG_NESTING_H
#define IG_NESTING_H
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif
struct nest_config {
	__u64 pid_tgid, nonce, seed;
	__u32 fd, strict;
};
struct nest_key {
	__u64 cookie, sequence;
};
struct nest_state {
	__u32 lock, initialized;
	__u64 task, inode, cookie, sequence, active, outer_sequence;
	__u64 outer_hits, inner_hits, inner_sequence, acquired, released,
		failures;
	__u64 outer_intact, inner_clean, uncertain, errors;
	__s64 helper_result, insertion_error;
	__u64 order, op_fault;
};
/* Audit never changes the incoming result; strict uncertainty affects this op. */
static inline int nest_result(int prior, int strict, int uncertain)
{
	return prior ? prior : (strict && uncertain ? -13 : 0);
}
#endif
