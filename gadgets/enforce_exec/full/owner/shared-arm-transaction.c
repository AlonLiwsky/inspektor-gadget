/* Copyright 2026 The Inspektor Gadget authors
 * SPDX-License-Identifier: Apache-2.0 */
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include "shared-arm-transaction.h"

static int se_arm_request_padding_zero(const struct se_arm_request *request)
{
	const unsigned char *bytes = (const unsigned char *)request;
	for (size_t i = offsetof(struct se_arm_request, bank_index) +
			sizeof(request->bank_index);
	     i < offsetof(struct se_arm_request, epochs); i++)
		if (bytes[i])
			return 0;
	return 1;
}

int se_arm_tx_init(struct se_arm_transaction *tx, __u64 node_cookie)
{
	if (!tx || !node_cookie || tx->node_cookie || tx->phase ||
	    tx->last_sequence || tx->request.sequence)
		return -1;
	tx->node_cookie = node_cookie;
	return 0;
}

int se_arm_tx_stage(struct se_arm_transaction *tx,
		    const struct se_arm_request *request,
		    const struct se_arm_tx_ops *ops)
{
	if (!tx || !request || !ops || !ops->journal || !ops->write_request ||
	    tx->phase != SE_ARM_TX_EMPTY || !tx->node_cookie ||
	    request->node_cookie != tx->node_cookie || request->reserved ||
	    !se_arm_request_padding_zero(request) || !request->sequence ||
	    request->sequence == ULLONG_MAX ||
	    request->sequence <= tx->last_sequence ||
	    (request->operation != SE_ARM_BIND &&
	     request->operation != SE_ARM_COMMIT &&
	     request->operation != SE_ARM_WITHDRAW))
		return -1;

	/* Retain the full 176 bytes before invoking any callback. A caller may
	 * alter its source buffer after stage; S never reads it again. */
	memcpy(&tx->request, request, sizeof(tx->request));
	tx->phase = SE_ARM_TX_PREPARED;
	if (ops->journal(ops->ctx, SE_ARM_J_PREPARED, &tx->request, 0))
		return -1;
	if (ops->write_request(ops->ctx, &tx->request))
		return -1;
	if (ops->journal(ops->ctx, SE_ARM_J_WRITTEN, &tx->request, 0))
		return -1;
	tx->phase = SE_ARM_TX_WRITTEN;
	return 0;
}

int se_arm_tx_permit(struct se_arm_transaction *tx,
		     const struct se_arm_tx_ops *ops)
{
	if (!tx || !ops || !ops->trigger_a || tx->phase != SE_ARM_TX_WRITTEN)
		return -1;
	/* Set before IPC: a failed/short/interrupt result can still mean A ran. */
	tx->phase = SE_ARM_TX_PERMITTED;
	return ops->trigger_a(ops->ctx, tx->request.sequence);
}

int se_arm_tx_receipt_matches(const struct se_arm_request *request,
			      const struct se_arm_receipt *receipt)
{
	if (!receipt || receipt->node_cookie != request->node_cookie ||
	    receipt->sequence != request->sequence ||
	    receipt->operation != request->operation || receipt->reserved ||
	    receipt->status > 1)
		return 0;
	if (receipt->status)
		return !receipt->generation && !receipt->serial;
	switch (request->operation) {
	case SE_ARM_COMMIT:
		return request->expected_generation < ULLONG_MAX - 1 &&
		       request->serial &&
		       receipt->generation ==
			       request->expected_generation + 1 &&
		       receipt->serial == request->serial;
	case SE_ARM_WITHDRAW:
		return receipt->generation == request->expected_generation &&
		       !receipt->serial;
	case SE_ARM_BIND:
		return !receipt->generation && !receipt->serial;
	default:
		return 0;
	}
}

int se_arm_tx_reconcile(struct se_arm_transaction *tx,
			const struct se_arm_receipt *receipt,
			const struct se_arm_tx_ops *ops)
{
	if (!tx || !ops || !ops->journal || !ops->state_proof ||
	    tx->phase != SE_ARM_TX_PERMITTED ||
	    !se_arm_tx_receipt_matches(&tx->request, receipt) ||
	    ops->state_proof(ops->ctx, &tx->request, receipt) ||
	    ops->journal(ops->ctx, SE_ARM_J_RESOLVED, &tx->request, receipt))
		return -1;
	tx->last_sequence = tx->request.sequence;
	memset(&tx->request, 0, sizeof(tx->request));
	tx->phase = SE_ARM_TX_EMPTY;
	return 0;
}
