/* SPDX-License-Identifier: GPL-2.0 */
#ifndef ABI3_GATEA_FIXTURE_H
#define ABI3_GATEA_FIXTURE_H
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif
#define GA_LIMIT 64
#define GA_AUDIT 0
#define GA_STRICT 1
#define GA_SEED 1
#define GA_INVENTORY 2
#define GA_STAGE 3
#define GA_ARM 4
#define GA_HOLD_SCRATCH 5
#define GA_FREE_SCRATCH 6
#define GA_RELEASE_TASK 7
#define GA_ITERATOR_ERROR 8
struct ga_config {
	__u32 admin_pid, strict, reject_later, hold_child;
};
struct ga_command {
	__u32 operation, pad;
	__u64 attempt;
};
struct ga_bank {
	__u64 generation, uid, epoch, role;
};
/* Lock is first in BPF-only records; userspace reads the identical layout. */
struct ga_stats {
	__u32 lock, seeded;
	__u64 serial, next_cookie, inflight, retained, births, frees;
	__u64 refused, failures, faults, taint, scratch_collisions;
	__u64 last_key, last_cookie, last_free_cookie;
	__u64 active_attempt, active_bank, active_program, receipt_serial,
		receipt_attempt;
	__u64 ready, inventory, held, armed;
	struct ga_bank catalogue[2];
};
#endif
