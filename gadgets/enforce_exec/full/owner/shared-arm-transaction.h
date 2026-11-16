/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#ifndef ENFORCE_EXEC_SHARED_ARM_TRANSACTION_H
#define ENFORCE_EXEC_SHARED_ARM_TRANSACTION_H

#include <linux/types.h>
#include "../shared_arm_abi.h"

/* Source-only S-side component. tx must be zero-initialized once; restart
 * reconstruction from a durable journal is NOT implemented here. S is a
 * separate, single-threaded native process, not a Go-thread capability or a
 * product activation path.
 * Every callback belongs to the trusted S process and must use exact FDs. */
enum se_arm_tx_phase {
	SE_ARM_TX_EMPTY,
	SE_ARM_TX_PREPARED,
	SE_ARM_TX_WRITTEN,
	SE_ARM_TX_PERMITTED,
};
enum se_arm_journal_phase {
	SE_ARM_J_PREPARED,
	SE_ARM_J_WRITTEN,
	SE_ARM_J_RESOLVED,
};
struct se_arm_transaction {
	struct se_arm_request request;
	__u64 node_cookie, last_sequence;
	enum se_arm_tx_phase phase;
};
struct se_arm_tx_ops {
	void *ctx;
	/* Must durably fsync before returning success; no permit on failure. */
	int (*journal)(void *, enum se_arm_journal_phase,
		       const struct se_arm_request *,
		       const struct se_arm_receipt *);
	/* S's exclusive writer FD; no other writer may change this map value. */
	int (*write_request)(void *, const struct se_arm_request *);
	/* Exactly one explicit token to the committed physical A. An error or
	 * interrupted write is ambiguous, never an invitation to rerun. */
	int (*trigger_a)(void *, __u64);
	/* Coherent locked state proof after exact receipt; return nonzero if
	 * commit/withdraw/bind or rejection cannot be established. */
	int (*state_proof)(void *, const struct se_arm_request *,
			   const struct se_arm_receipt *);
};

int se_arm_tx_init(struct se_arm_transaction *, __u64 node_cookie);
int se_arm_tx_stage(struct se_arm_transaction *, const struct se_arm_request *,
		    const struct se_arm_tx_ops *);
int se_arm_tx_permit(struct se_arm_transaction *, const struct se_arm_tx_ops *);
int se_arm_tx_reconcile(struct se_arm_transaction *,
			const struct se_arm_receipt *,
			const struct se_arm_tx_ops *);
/* Exact wire receipt predicate, shared with durable journal replay. This
 * does not replace the separate locked descendant-state proof. */
int se_arm_tx_receipt_matches(const struct se_arm_request *,
			      const struct se_arm_receipt *);

#endif
