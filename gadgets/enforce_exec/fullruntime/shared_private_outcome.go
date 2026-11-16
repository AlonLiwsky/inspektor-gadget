// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import "context"

// These outcomes are private by-value command results, NOT error values or a
// qualified worker API. In particular, they neither model provider allocations
// nor enumerate snapshot/discard/accounting primary+cleanup diagnostics.
type sharedOutcomeCode uint8

const (
	sharedOutcomeOK sharedOutcomeCode = iota
	sharedOutcomeCanceledAdmission
	sharedOutcomeClosed
	sharedOutcomePanic
	sharedOutcomeUnavailable
	sharedOutcomePendingConflict
	sharedOutcomeUnsupported
	sharedOutcomeSequenceExhausted
	sharedOutcomeWriteFailed
	sharedOutcomeRunFailed
	sharedOutcomeReadFailed
	sharedOutcomeContradictory
	sharedOutcomeRefused
	sharedOutcomeObjectPoisoned
	sharedOutcomeObjectPendingConflict
)

type sharedReceiptClass uint8

const (
	sharedReceiptNone sharedReceiptClass = iota
	sharedReceiptCompleted
	sharedReceiptRefused
	sharedReceiptUnresolved
	sharedReceiptIncompatible
)

type sharedOutcomeIdentities uint8

const (
	sharedIdentityCanceled sharedOutcomeIdentities = 1 << iota
	sharedIdentityDeadline
	sharedIdentityClosed
	sharedIdentityUnavailable
)

// code describes the command/control stage; receipt separately describes the
// coordinator result. sharedOutcomeOK with sharedReceiptIncompatible is NOT
// success. Callers must inspect both before deciding cleanup or reuse.
type sharedCommandOutcome struct {
	code       sharedOutcomeCode
	receipt    sharedReceiptClass
	identities sharedOutcomeIdentities
}

// Only source-bound sentinel equality is inspected. Never call foreign error
// methods, including errors.Is/As: arbitrary adapter chains are not this compact
// contract. These scalar results intentionally do not implement error.
func sharedDirectIdentities(err error) sharedOutcomeIdentities {
	switch err { //nolint:errorlint // Direct trusted leaf identity only; invoking foreign Is/Unwrap is forbidden.
	case context.Canceled:
		return sharedIdentityCanceled
	case context.DeadlineExceeded:
		return sharedIdentityDeadline
	case ErrControlClosed:
		return sharedIdentityClosed
	case ErrSharedNativeUnavailable:
		return sharedIdentityUnavailable
	default:
		return 0
	}
}

func (o sharedCommandOutcome) hasIdentity(target error) bool {
	identity := sharedDirectIdentities(target)
	return identity != 0 && o.identities&identity != 0
}

// The same joined control job and receipt state machine serve rich and private
// calls. Only error presentation differs. A selected transport may itself
// allocate/format errors; projecting here does not qualify those allocations.
func (c *sharedControl) callPrivate(ctx context.Context, command sharedCommandWire, transport sharedCommandTransport) (sharedReceiptWire, sharedCommandOutcome) {
	if c == nil || c.thread == nil {
		return sharedReceiptWire{}, sharedCommandOutcome{code: sharedOutcomeUnavailable, identities: sharedIdentityUnavailable}
	}
	if transport == nil {
		transport = c.resources
	}
	var receipt sharedReceiptWire
	var outcome sharedCommandOutcome
	err, canceled, _ := c.thread.doJoined(ctx, func() error {
		result := c.commandResult(command, transport)
		receipt = result.receipt
		outcome = sharedCommandOutcome{code: result.code, identities: sharedDirectIdentities(result.err)}
		switch {
		case receipt.Sequence != 0 && receipt.Status != 0:
			outcome.receipt = sharedReceiptRefused
		case receipt.Sequence != 0:
			outcome.receipt = sharedReceiptCompleted
		case c.pending != nil:
			outcome.receipt = sharedReceiptUnresolved
		}
		return nil
	}, true)
	// Capture cancellation before any outer operation finish/cleanup can cancel
	// its own context. Never replace a completed receipt with cancellation.
	outcome.identities |= sharedDirectIdentities(err) | sharedDirectIdentities(canceled)
	if err != nil {
		switch err { //nolint:errorlint // Direct trusted leaf identity only; invoking foreign Is/Unwrap is forbidden.
		case errPrivateControlPanic: //nolint:errorlint // Exact static private terminal identity; never inspect foreign chains.
			outcome.code = sharedOutcomePanic
			outcome.receipt = sharedReceiptUnresolved
		case context.Canceled, context.DeadlineExceeded:
			outcome.code = sharedOutcomeCanceledAdmission
		default:
			outcome.code = sharedOutcomeClosed
		}
	}
	return receipt, outcome
}

func (n *NodeEnforcer) runSharedObjectCommandPrivate(ctx context.Context, slot *sharedObjectSlot, command sharedCommandWire, transport sharedCommandTransport) sharedCommandOutcome {
	if code := prepareSharedObjectCommand(slot, command); code != sharedOutcomeOK {
		class := sharedReceiptUnresolved
		if code == sharedOutcomeObjectPoisoned {
			class = sharedReceiptIncompatible
		}
		return sharedCommandOutcome{code: code, receipt: class}
	}
	receipt, outcome := n.host.control.callPrivate(ctx, command, transport)
	outcome.receipt = classifySharedObjectReceipt(slot, command, receipt)
	return outcome
}
