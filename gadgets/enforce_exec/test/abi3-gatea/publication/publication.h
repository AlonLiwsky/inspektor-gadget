/* SPDX-License-Identifier: GPL-2.0 */
#ifndef GATEA_PUBLICATION_H
#define GATEA_PUBLICATION_H
#ifndef __VMLINUX_H__
#include <linux/types.h>
#endif
#define PC_TASKS 3
#define PC_UIDS 32
#define PC_ADDITIONS 8
#define PC_ALL_TASKS ((1U << PC_TASKS) - 1)
#define PC_AUDIT 0
#define PC_STRICT 1
#define PC_NONE 0
#define PC_LOADING 1
#define PC_SEALING 2
#define PC_SEALED 3
#define PC_STAGING 4
#define PC_CERTIFIED 5
#define PC_COMMITTED 6
#define PC_ABORTED 7
enum pc_operation {
	PC_PIN = 1,
	PC_REGISTER,
	PC_BEGIN,
	PC_WRITE_BEGIN,
	PC_WRITE_END,
	PC_SEAL,
	PC_SNAPSHOT,
	PC_STAGE,
	PC_CERTIFY,
	PC_ARM,
	PC_ABORT,
	PC_READ_BEGIN,
	PC_READ_END,
	PC_EVAL,
	PC_QUERY
};
struct pc_config {
	__u64 nonce;
	__u32 tgid, admin_tid, control_fd, pad;
};
struct pc_command {
	__u64 nonce, attempt, uid0, uid1, extra_uids[6];
	__u32 op, bank, mode, slot, arg0, arg1, deny_bits, bad_stamp,
		unknown_mask;
};
struct pc_rule {
	__u64 uid, epoch;
	__u32 role, arg, deny, pad;
};
struct pc_epoch {
	__u64 uid, epoch;
};
struct pc_program {
	__u64 stamp;
	__u32 count, mode;
	struct pc_rule rules[2];
	struct pc_epoch additions[PC_ADDITIONS];
};
struct pc_role {
	__u64 uid, epoch, version;
	__u32 role, known;
};
struct pc_history {
	__u64 stamp, cookie;
	struct pc_role roles[2];
};
struct pc_catalogue {
	__u64 uid, accepted_epoch;
};
/* Mirror the locked state for BPF_F_LOCK diagnostic reads. */
#define PC_STATE_FIELDS                                                  \
	__u32 pinned;                                                    \
	__u64 admin_task, control_kn, serial, next_cookie, last_attempt; \
	__u64 active_attempt, active_bank, active_mode;                  \
	__u64 attempt, bank, mode, phase, uid0, uid1, expected_active;   \
	__u64 receipt_serial, receipt_attempt, staged_mask;              \
	__u64 readers, writers, registrations, registered_mask;          \
	__u64 max_readers, reserved, accepted, refused, incoherent;      \
	__u64 evals, denials, audit_denials, arms, arm_refused;          \
	__s64 arm_result;                                                \
	__u64 query0, query1, query_attempt, query_bank, query_mode
struct pc_stats {
	__u32 lock;
	PC_STATE_FIELDS;
};
#endif
