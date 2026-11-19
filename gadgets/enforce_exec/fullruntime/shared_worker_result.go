// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
)

type workerSite uint8

const (
	workerSiteNone workerSite = iota
	workerObjectCount
	workerBegin
	workerBinding
	workerPins
	workerRecord
	workerPolicy
	workerCompile
	workerOwnedSize
	workerRetainedLimit
	workerReserve
	workerAcquire
	workerObjectBegin
	workerEntry
	workerObjectCell
	workerClass
	workerObjectSeal
	workerSnapshotInput
	workerSnapshotCandidate
	workerSnapshotUnused
	workerSnapshotAccount
	workerSnapshotScope
	workerSnapshotSummary
	workerSnapshotMetadata
	workerSnapshotAuthored
	workerSnapshotReady
	workerSnapshotPrepare
	workerSnapshotPin
	workerSnapshotSeal
	workerDiscardInput
	workerDiscardRecord
	workerSnapshotState
	workerSnapshotReconcile
	workerSnapshotInspect
	workerSnapshotAbort
	workerSnapshotRelease
	workerSnapshotReclaim
	workerSnapshotEmpty
	workerAuthoredUnassociated
	workerAuthoredShared
	workerObjectReconcile
	workerObjectPoison
	workerObjectAbort
	workerObjectRetire
	workerObjectReclaim
	workerObjectEmpty
	workerSlotSource
	workerAuthoredFinal
)

type workerReason uint8

const (
	workerNone workerReason = iota
	workerOpaque
	workerCommand
	workerCompiler
	workerUnavailable
	workerInvalidCount
	workerCandidateCapacity
	workerRetainedLimitFailure
	workerRetainedCapacity
	workerSlotCapacity
	workerForeignSnapshot
	workerStaleProvenance
	workerAlreadyAttempted
	workerScopeMismatch
	workerMetadataInvalid
	workerAuthoredLost
	workerUploadUnavailable
	workerMissingCandidate
	workerForeignCandidate
	workerStaleCandidate
	workerObjectUncertain
	workerObjectNotReclaimed
	workerRetainedOwnership
	workerSnapshotPoisoned
	workerSnapshotPending
	workerSnapshotUnresolved
	workerSnapshotRefusalIncompatible
	workerSnapshotRefused
	workerSnapshotOperationInvalid
	workerSnapshotReceiptIncompatible
	workerSnapshotTicketPhase
	workerSnapshotNotReclaimed
)

// Private by-value diagnostics only: no error implementation or output owner.
type workerDiagnostic struct {
	site    workerSite
	reason  workerReason
	command sharedCommandOutcome
}

func (d workerDiagnostic) failed() bool { return d.reason != workerNone }

type workerResult struct {
	primary, cleanup workerDiagnostic
	cleanupAttempted bool
}

func (r workerResult) failed() bool { return r.primary.failed() || r.cleanup.failed() }

// The transient rich presentation slot is always nil in private mode. Compiler
// errors never enter it: preparation has a separate direct static-error return.
type workerStep struct {
	diagnostic workerDiagnostic
	err        error
}

func (s workerStep) failed() bool { return s.diagnostic.failed() }

type workerMode bool

const (
	workerRich    workerMode = false
	workerPrivate workerMode = true
)

func (m workerMode) failure(site workerSite, reason workerReason, err error) workerStep {
	d := workerDiagnostic{site: site, reason: reason, command: sharedCommandOutcome{identities: sharedDirectIdentities(err)}}
	switch reason {
	case workerSnapshotPoisoned, workerObjectUncertain:
		d.command.receipt = sharedReceiptIncompatible
	case workerSnapshotPending:
		d.command.receipt = sharedReceiptUnresolved
	}
	if m == workerPrivate {
		return workerStep{diagnostic: d}
	}
	if err == nil {
		err = errors.New(reason.message())
	}
	return workerStep{diagnostic: d, err: err}
}

func (r workerReason) message() string {
	switch r {
	case workerInvalidCount:
		return "invalid shared object count"
	case workerCandidateCapacity:
		return "shared candidate records exhausted"
	case workerRetainedLimitFailure:
		return "shared authored object storage exceeds reserved bytes"
	case workerRetainedCapacity:
		return "shared retained source budget exhausted"
	case workerSlotCapacity:
		return "shared object slots/attempts exhausted"
	case workerForeignSnapshot:
		return "foreign snapshot candidate"
	case workerStaleProvenance:
		return "stale snapshot candidate provenance"
	case workerAlreadyAttempted:
		return "snapshot candidate already attempted"
	case workerScopeMismatch:
		return "snapshot proposal scope/generation differs from retained provenance"
	case workerMetadataInvalid:
		return "invalid compiled snapshot metadata"
	case workerAuthoredLost:
		return "snapshot lost original authored provenance or object lease"
	case workerUploadUnavailable:
		return "snapshot object upload provenance unavailable"
	case workerMissingCandidate:
		return "missing shared candidate"
	case workerForeignCandidate:
		return "foreign shared candidate record"
	case workerStaleCandidate:
		return "stale shared candidate record"
	case workerObjectUncertain:
		return "shared object ownership remains uncertain"
	case workerObjectNotReclaimed:
		return "shared object not reclaimed"
	case workerRetainedOwnership:
		return "shared retained storage ownership mismatch"
	case workerSnapshotPoisoned:
		return "snapshot outcome incompatible"
	case workerSnapshotPending:
		return "snapshot command unresolved"
	case workerSnapshotUnresolved:
		return "snapshot outcome unresolved"
	case workerSnapshotRefusalIncompatible:
		return "incompatible snapshot refusal receipt"
	case workerSnapshotRefused:
		return "snapshot command refused"
	case workerSnapshotOperationInvalid:
		return "unsupported snapshot operation"
	case workerSnapshotReceiptIncompatible:
		return "incompatible snapshot command receipt"
	case workerSnapshotTicketPhase:
		return "ticket receipt incompatible with candidate phase"
	case workerSnapshotNotReclaimed:
		return "snapshot has not been reclaimed"
	default:
		return "shared worker failure"
	}
}

func (m workerMode) objectCommand(ctx context.Context, n *NodeEnforcer, slot *sharedObjectSlot, command sharedCommandWire, transport sharedCommandTransport, site workerSite) workerStep {
	if m == workerRich {
		if err := n.runSharedObjectCommand(ctx, slot, command, transport); err != nil {
			return m.failure(site, workerCommand, err)
		}
		return workerStep{}
	}
	outcome := n.runSharedObjectCommandPrivate(ctx, slot, command, transport)
	return privateCommandStep(site, outcome)
}

func privateCommandStep(site workerSite, outcome sharedCommandOutcome) workerStep {
	if outcome.code == sharedOutcomeOK && outcome.identities == 0 && outcome.receipt == sharedReceiptCompleted {
		return workerStep{}
	}
	return workerStep{diagnostic: workerDiagnostic{site: site, reason: workerCommand, command: outcome}}
}

func singleWorkerResult(step workerStep) (workerResult, error) {
	return workerResult{primary: step.diagnostic}, step.err
}
