/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_ARM_JOURNAL_H
#define ENFORCE_EXEC_SHARED_ARM_JOURNAL_H

#include <sys/types.h>
#include "shared-arm-transaction.h"

/* S-owned append-only journal. The caller must zero-initialize this struct
 * before open. A verified scan is crash evidence, not kernel authority:
 * native restart must still reconcile exact maps and task roles. */
struct se_arm_journal {
	struct se_arm_request pending;
	__u64 node_cookie, last_sequence;
	dev_t device;
	ino_t inode;
	off_t size;
	int fd, dir_fd, initialized, poisoned;
	enum se_arm_tx_phase phase;
};

/* First incarnation bootstrap must explicitly create with O_EXCL; restart
 * must call open_at, which refuses a missing journal instead of resetting
 * sequence history. The external incarnation/pin ledger decides which path
 * is legal; this component does not establish bootstrap authority itself. */
int se_arm_journal_create_at(int trusted_dir_fd, __u64 node_cookie,
			     struct se_arm_journal *journal);
int se_arm_journal_open_at(int trusted_dir_fd, __u64 node_cookie,
			   struct se_arm_journal *journal);
int se_arm_journal_append(void *ctx, enum se_arm_journal_phase phase,
			  const struct se_arm_request *request,
			  const struct se_arm_receipt *receipt);
/* Reconstruct sequence ownership after a verified scan. An unresolved
 * PREPARED/WRITTEN tail becomes PERMITTED/HOLD: A must never be retriggered
 * from a journal alone. Only exact receipt plus locked state proof can clear
 * it. S must not call this for a poisoned or unverified journal. */
int se_arm_journal_restore_hold(const struct se_arm_journal *journal,
				struct se_arm_transaction *tx);
int se_arm_journal_close(struct se_arm_journal *journal);

#endif
