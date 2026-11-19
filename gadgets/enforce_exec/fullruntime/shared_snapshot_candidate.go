// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// The private cohesive worker constructs operation-local intents only for a
// checked fresh scope. Its production applicability remains unavailable.
// Neither this proposal nor PREPARED authenticates accepted epochs/images or
// grants Ready. Existing rich fixtures may still inject explicit proposals.
type sharedSnapshotIntent struct {
	candidate sharedObjectCandidate
	account   *sharedPhysicalScope
	proposal  fullpolicy.SharedSnapshot
}

// The only producer of generation zero is successful BINDING_OPEN. This worker
// has no Commit opcode and must not advance accepted generation. Only
// se_publication_arm may do that, from cgroup_kn_lock_live. A syscall receipt
// is not commit or withdrawal. Only a validated PREPARE receipt advances
// nextSerial; reclaim never rewinds it.
type (
	sharedSnapshotScopeState     struct{ generation, nextSerial uint64 }
	sharedSnapshotCandidateState struct {
		account                         *sharedPhysicalScope
		scope, targetGeneration, serial uint64
		phase                           uint32
		pending, poisoned               bool
		tickets                         [fullpolicy.MaxPolicies]uint8
		inspect                         [fullpolicy.MaxPolicies]bool
		command                         sharedCommandWire
	}
)

func (c sharedObjectCandidate) prepareSnapshotUsing(ctx context.Context, intent *sharedSnapshotIntent, transport sharedCommandTransport) error {
	_, err := c.prepareSnapshotResult(ctx, intent, transport, workerRich)
	return err
}

func (c sharedObjectCandidate) prepareSnapshotPrivate(ctx context.Context, intent *sharedSnapshotIntent, transport sharedCommandTransport) workerResult {
	result, _ := c.prepareSnapshotResult(ctx, intent, transport, workerPrivate)
	return result
}

func (c sharedObjectCandidate) prepareSnapshotResult(ctx context.Context, intent *sharedSnapshotIntent, transport sharedCommandTransport, mode workerMode) (workerResult, error) {
	if c.node == nil || intent == nil {
		return singleWorkerResult(mode.failure(workerSnapshotInput, workerUnavailable, ErrSharedNativeUnavailable))
	}
	n := c.node
	ctx, finish, err := n.beginSharedObjectOperation(ctx)
	if err != nil {
		return singleWorkerResult(mode.failure(workerBegin, workerOpaque, err))
	}
	defer finish()
	if int(c.record) >= len(n.objects.records) {
		return singleWorkerResult(mode.failure(workerSnapshotCandidate, workerForeignSnapshot, nil))
	}
	record := &n.objects.records[c.record]
	if !record.live || !record.complete || record.token != c.token || intent.candidate != c || record.count == 0 || record.count > fullpolicy.MaxPolicies {
		return singleWorkerResult(mode.failure(workerSnapshotCandidate, workerStaleProvenance, nil))
	}
	if record.snapshot.account != nil || record.snapshot.pending || record.snapshot.phase != 0 {
		return singleWorkerResult(mode.failure(workerSnapshotUnused, workerAlreadyAttempted, nil))
	}
	binding := c.record / 2
	n.mu.Lock()
	account := n.host.scopeSlots[binding]
	n.mu.Unlock()
	if account == nil || account != intent.account {
		return singleWorkerResult(mode.failure(workerSnapshotAccount, workerUnavailable, ErrSharedNativeUnavailable))
	}
	account.mu.Lock()
	defer account.mu.Unlock()
	return c.prepareSnapshotLocked(ctx, intent, transport, mode)
}

// Caller owns the registered operation and exact account lock.
func (c sharedObjectCandidate) prepareSnapshotLocked(ctx context.Context, intent *sharedSnapshotIntent, transport sharedCommandTransport, mode workerMode) (workerResult, error) {
	n := c.node
	var err error
	if int(c.record) >= len(n.objects.records) {
		return singleWorkerResult(mode.failure(workerSnapshotCandidate, workerForeignSnapshot, nil))
	}
	record := &n.objects.records[c.record]
	if !record.live || !record.complete || record.token != c.token || intent.candidate != c || record.count == 0 || record.count > fullpolicy.MaxPolicies {
		return singleWorkerResult(mode.failure(workerSnapshotCandidate, workerStaleProvenance, nil))
	}
	if record.snapshot.account != nil || record.snapshot.pending || record.snapshot.phase != 0 {
		return singleWorkerResult(mode.failure(workerSnapshotUnused, workerAlreadyAttempted, nil))
	}
	binding := c.record / 2
	n.mu.Lock()
	account := n.host.scopeSlots[binding]
	n.mu.Unlock()
	if account == nil || account != intent.account {
		return singleWorkerResult(mode.failure(workerSnapshotAccount, workerUnavailable, ErrSharedNativeUnavailable))
	}
	if account.registration.Sequence == 0 || account.registration.Operation != sharedBindingOpen || account.registration.Status != 0 || account.registration.NodeCookie != n.host.control.config.NodeCookie || !account.native.reserved || account.native.slot != binding {
		return singleWorkerResult(mode.failure(workerSnapshotAccount, workerUnavailable, ErrSharedNativeUnavailable))
	}
	if err = account.pins.Check(ctx); err != nil {
		return singleWorkerResult(mode.failure(workerPins, workerOpaque, err))
	}
	proposal := intent.proposal
	scope := &n.objects.scopes[binding]
	if scope.generation >= math.MaxUint64-1 || scope.nextSerial >= math.MaxUint64-1 || proposal.ScopeCookie != account.registration.Sequence || proposal.Generation != scope.generation+1 || len(proposal.Policies) != int(record.count) {
		return singleWorkerResult(mode.failure(workerSnapshotScope, workerScopeMismatch, nil))
	}
	summary, err := proposal.ExecutionMetadata()
	if err != nil {
		return singleWorkerResult(mode.failure(workerSnapshotSummary, workerOpaque, err))
	}
	if summary.PolicyCount != record.count || summary.ExecutionClass < 1 || summary.ExecutionClass > 2 || len(proposal.Container) == 0 || len(proposal.Container) > fullpolicy.MaxStringBytes || !utf8.ValidString(proposal.Container) || strings.IndexByte(proposal.Container, 0) >= 0 {
		return singleWorkerResult(mode.failure(workerSnapshotMetadata, workerMetadataInvalid, nil))
	}
	command := sharedCommandWire{Operation: 8, Binding: binding, Record: c.record % 2, Scope: proposal.ScopeCookie, Generation: scope.generation, Serial: scope.nextSerial, Count: record.count, ExecutionClass: summary.ExecutionClass}
	command.Metadata.RoleWriters = summary.RoleWriters
	command.Metadata.RequiredKnown = summary.RequiredKnown
	command.Metadata.ContainerLength = uint32(len(proposal.Container))
	copy(command.Metadata.Container[:], proposal.Container)
	for i, ref := range proposal.Policies {
		if ref.Object != record.source[i] || ref.RootEpoch == 0 || ref.RootEpoch > proposal.Generation || !record.associated[i] || !record.held[i] {
			return singleWorkerResult(mode.failure(workerSnapshotAuthored, workerAuthoredLost, nil))
		}
		slot := &n.objects.slots[record.slots[i]]
		if slot.object == nil || slot.phase != 2 || slot.refs == 0 || slot.pending || slot.poisoned || slot.retiring || !slot.object.Equal(ref.Object) {
			return singleWorkerResult(mode.failure(workerSnapshotReady, workerUploadUnavailable, nil))
		}
		command.Handles[i] = sharedPinWire{ObjectGeneration: slot.generation, ObjectSlot: record.slots[i]}
		command.Metadata.RootEpochs[i] = ref.RootEpoch
		command.Metadata.PolicyUIDs[i] = ref.Object.UID()
	}
	record.snapshot = sharedSnapshotCandidateState{account: account, scope: proposal.ScopeCookie, targetGeneration: proposal.Generation}
	primary := n.runSharedSnapshotResult(ctx, record, command, transport, mode, workerSnapshotPrepare)
	if !primary.failed() {
		for i := uint32(0); i < record.count; i++ {
			primary = n.runSharedSnapshotResult(ctx, record, n.sharedSnapshotCommand(c, record, 9, i), transport, mode, workerSnapshotPin)
			if primary.failed() {
				break
			}
		}
	}
	if !primary.failed() {
		primary = n.runSharedSnapshotResult(ctx, record, n.sharedSnapshotCommand(c, record, 10, 0), transport, mode, workerSnapshotSeal)
	}
	if primary.failed() {
		// Snapshot the primary before uncanceled cleanup and before finish. A
		// completed canceled PIN still owns its ticket and must be released.
		cleanup := n.discardSharedObjectRecordResult(context.WithoutCancel(ctx), c, transport, mode)
		result := workerResult{primary: primary.diagnostic, cleanup: cleanup.diagnostic, cleanupAttempted: true}
		if mode == workerRich {
			return result, errors.Join(primary.err, cleanup.err)
		}
		return result, nil
	}
	return workerResult{}, nil
}

func (n *NodeEnforcer) sharedSnapshotCommand(c sharedObjectCandidate, record *sharedObjectRecord, operation, index uint32) sharedCommandWire {
	command := sharedCommandWire{Operation: operation, Binding: c.record / 2, Record: c.record % 2, Scope: record.snapshot.scope, Serial: record.snapshot.serial}
	if operation == 9 || operation == 12 || operation == 15 {
		command.Index = index
		command.Object = record.slots[index]
	}
	return command
}

// Exact command-specific outcomes; no nonzero error is interpreted as proof
// that the command did not execute. A failed ticket command requires authenticated
// ticket INSPECT, never an assumed EMPTY/RELEASED state or object-content proof.
func (n *NodeEnforcer) runSharedSnapshotCommand(ctx context.Context, record *sharedObjectRecord, command sharedCommandWire, transport sharedCommandTransport) error {
	return n.runSharedSnapshotResult(ctx, record, command, transport, workerRich, workerSnapshotPrepare).err
}

func (n *NodeEnforcer) runSharedSnapshotResult(ctx context.Context, record *sharedObjectRecord, command sharedCommandWire, transport sharedCommandTransport, mode workerMode, site workerSite) workerStep {
	s := &record.snapshot
	if s.poisoned {
		return mode.failure(site, workerSnapshotPoisoned, nil)
	}
	if s.pending && s.command != command {
		return mode.failure(site, workerSnapshotPending, nil)
	}
	s.pending = true
	s.command = command
	var receipt sharedReceiptWire
	var err error
	var outcome sharedCommandOutcome
	if mode == workerPrivate {
		receipt, outcome = n.host.control.callPrivate(ctx, command, transport)
	} else if transport == nil {
		receipt, err = n.host.control.call(ctx, command)
	} else {
		receipt, err = n.host.control.callWithTransport(ctx, command, transport)
	}
	reason := n.classifySharedSnapshotReceipt(record, command, receipt)
	if mode == workerRich {
		if reason == workerNone {
			if err != nil {
				return mode.failure(site, workerCommand, err)
			}
			return workerStep{}
		}
		step := mode.failure(site, reason, nil)
		// Preserve these two existing DIRECT rich exceptions, not a new Join.
		if reason != workerSnapshotOperationInvalid && reason != workerSnapshotTicketPhase {
			step.err = errors.Join(err, step.err)
		}
		return step
	}
	if reason == workerNone {
		return privateCommandStep(site, outcome)
	}
	switch reason {
	case workerSnapshotUnresolved:
		outcome.receipt = sharedReceiptUnresolved
	case workerSnapshotRefused:
		outcome.receipt = sharedReceiptRefused
	default:
		outcome.receipt = sharedReceiptIncompatible
	}
	return workerStep{diagnostic: workerDiagnostic{site: site, reason: reason, command: outcome}}
}

func (n *NodeEnforcer) classifySharedSnapshotReceipt(record *sharedObjectRecord, command sharedCommandWire, receipt sharedReceiptWire) workerReason {
	s := &record.snapshot
	if receipt.Sequence == 0 {
		return workerSnapshotUnresolved
	}
	// The validated refusal consumes its command sequence, but does not authorize
	// advancing snapshot serial or assuming a ticket mutation did not happen.
	if receipt.Status != 0 {
		if receipt.Generation != 0 || receipt.Serial != 0 || receipt.Value != 0 {
			s.poisoned = true
			return workerSnapshotRefusalIncompatible
		}
		s.pending = false
		s.command = sharedCommandWire{}
		switch command.Operation {
		case 8, 10: // C guards precede all state mutation for PREPARE and SEAL.
		case 9, 12:
			s.inspect[command.Index] = true
		default:
			s.poisoned = true
		}
		return workerSnapshotRefused
	}
	serial, value := uint64(0), uint32(0)
	switch command.Operation {
	case 8:
		serial = command.Serial + 1
		value = 1
	case 9:
		value = 1
	case 10:
		serial = s.serial
		value = 2
	case 11:
		serial = s.serial
		value = 4
	case 12:
		value = 2
	case 13: // RECLAIM clears the native record, including its serial.
	case 15:
		value = receipt.Value
	default:
		s.poisoned = true
		return workerSnapshotOperationInvalid
	}
	if receipt.Generation != 0 || receipt.Serial != serial || receipt.Value != value || value > 4 || (command.Operation == 15 && value > 2) {
		s.poisoned = true
		return workerSnapshotReceiptIncompatible
	}
	s.pending = false
	s.command = sharedCommandWire{}
	switch command.Operation {
	case 8:
		s.serial = serial
		s.phase = 1
		n.objects.scopes[command.Binding].nextSerial = serial
	case 9:
		s.tickets[command.Index] = 1
	case 10:
		s.phase = 2
	case 11:
		s.phase = 4
	case 12:
		s.tickets[command.Index] = 2
	case 13:
		s.phase = 0
		s.serial = 0
	case 15:
		if (s.phase != 4 && value == 2) || (s.phase == 4 && value == 0) {
			s.poisoned = true
			return workerSnapshotTicketPhase
		}
		s.tickets[command.Index] = uint8(value)
		s.inspect[command.Index] = false
	}
	return workerNone
}

// Must complete before ANY native object lease/source reference is dropped.
// Active/unknown/poisoned records are retained, never implicitly withdrawn.
func (n *NodeEnforcer) discardSharedSnapshot(ctx context.Context, c sharedObjectCandidate, record *sharedObjectRecord, transport sharedCommandTransport) error {
	return n.discardSharedSnapshotResult(ctx, c, record, transport, workerRich).err
}

func (n *NodeEnforcer) discardSharedSnapshotResult(ctx context.Context, c sharedObjectCandidate, record *sharedObjectRecord, transport sharedCommandTransport, mode workerMode) workerStep {
	s := &record.snapshot
	if s.account == nil {
		return workerStep{}
	}
	if s.poisoned || s.phase == 3 {
		return mode.failure(workerSnapshotState, workerUnavailable, ErrSharedNativeUnavailable)
	}
	if s.pending {
		if step := n.runSharedSnapshotResult(ctx, record, s.command, transport, mode, workerSnapshotReconcile); step.failed() {
			return step
		}
	}
	for i := uint32(0); i < record.count; i++ {
		if s.inspect[i] {
			if step := n.runSharedSnapshotResult(ctx, record, n.sharedSnapshotCommand(c, record, 15, i), transport, mode, workerSnapshotInspect); step.failed() {
				return step
			}
		}
	}
	if s.phase == 1 || s.phase == 2 {
		if step := n.runSharedSnapshotResult(ctx, record, n.sharedSnapshotCommand(c, record, 11, 0), transport, mode, workerSnapshotAbort); step.failed() {
			return step
		}
	}
	if s.phase == 4 {
		for i := uint32(0); i < record.count; i++ {
			if s.tickets[i] == 1 {
				if step := n.runSharedSnapshotResult(ctx, record, n.sharedSnapshotCommand(c, record, 12, i), transport, mode, workerSnapshotRelease); step.failed() {
					return step
				}
			}
		}
		if step := n.runSharedSnapshotResult(ctx, record, n.sharedSnapshotCommand(c, record, 13, 0), transport, mode, workerSnapshotReclaim); step.failed() {
			return step
		}
	}
	if s.phase != 0 {
		return mode.failure(workerSnapshotEmpty, workerSnapshotNotReclaimed, nil)
	}
	return workerStep{}
}
