// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"math"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// One node-wide registry, never a collection per binding. Fixed records retain
// ORIGINAL authored objects independently of physical digest/Equal reuse.
// Protocol jobs are deliberately single-flight, with rejection rather than an
// unbounded queue. This also bounds retained command/cancellation ownership.
type sharedObjectRegistry struct {
	scopes        []sharedSnapshotScopeState
	slots         []sharedObjectSlot
	records       []sharedObjectRecord
	operation     sharedStartupOperation
	nextAttempt   uint64
	retainedBytes uint64
	destroyed     bool
}
type sharedObjectSlot struct {
	sourceBytes                 uint64
	object                      *fullpolicy.SharedPolicy
	generation, attempt         uint64
	capacity, phase, refs       uint32
	retiring, poisoned, pending bool
	command                     sharedCommandWire
}
type sharedObjectRecord struct {
	snapshot    sharedSnapshotCandidateState
	sourceBytes [fullpolicy.MaxPolicies]uint64
	token       uint64
	live        bool
	complete    bool
	count       uint32
	source      [fullpolicy.MaxPolicies]*fullpolicy.SharedPolicy
	slots       [fullpolicy.MaxPolicies]uint32
	held        [fullpolicy.MaxPolicies]bool
	associated  [fullpolicy.MaxPolicies]bool
}

// Internal ABA-checked record capability, not a naked kernel object handle.
type sharedObjectCandidate struct {
	node   *NodeEnforcer
	record uint32
	token  uint64
}

// Called ONLY after profile/resource admission. Slot ordinal is the prefix sum
// of slot counts, never the arena CELL offset returned by ObjectRange.
func newSharedObjectRegistry(p SharedProfile) *sharedObjectRegistry {
	var count uint64
	for _, n := range p.PolicySlots {
		count += n
	}
	r := &sharedObjectRegistry{slots: make([]sharedObjectSlot, count), records: make([]sharedObjectRecord, 2*p.Bindings), scopes: make([]sharedSnapshotScopeState, p.Bindings)}
	ordinal := 0
	for class, n := range p.PolicySlots {
		for range n {
			r.slots[ordinal].capacity = [4]uint32{256, 1024, 4096, 16384}[class]
			ordinal++
		}
	}
	return r
}

func (n *NodeEnforcer) beginSharedObjectOperation(ctx context.Context) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.beginSharedObjectOperationLocked(ctx)
}

// Caller holds node.mu; admission and registration are one critical section.
func (n *NodeEnforcer) beginSharedObjectOperationLocked(ctx context.Context) (context.Context, func(), error) {
	if n.objects == nil || n.host == nil || n.host.protocol == nil || !n.host.handshakeComplete || n.closing || n.closed || n.objects.operation.done != nil {
		return nil, nil, ErrSharedNativeUnavailable
	}
	deadline, hasDeadline := ctx.Deadline()
	op := &sharedOperationContext{
		node: n, values: context.WithoutCancel(ctx), caller: ctx,
		callerDone: ctx.Done(), deadline: deadline, hasDeadline: hasDeadline,
		cancelled: make(chan struct{}), relayJoined: make(chan struct{}), operationDone: make(chan struct{}),
	}
	n.objects.operation = sharedStartupOperation{cancel: op.stop, done: op.operationDone}
	go op.relay()
	return op, op.finish, nil
}

// This private preparation uploads compiler-owned content only; it grants no
// snapshot/root/image qualification and exposes no public candidate interface.
func (s *BindingSession) prepareSharedObjectsUsing(ctx context.Context, policies []fullpolicy.Policy, transport sharedCommandTransport) (sharedObjectCandidate, error) {
	candidate, step, compilerOnly := s.prepareSharedObjectsResult(ctx, policies, transport, workerRich)
	if compilerOnly != nil {
		return candidate, compilerOnly
	}
	return candidate, step.err
}

// compilerOnly is returned directly from the controlled compact compiler call,
// never from provider/transport/runtime errors. No compiler diagnostic is copied,
// inspected or reconstructed, and preparation never automatically discards.
func (s *BindingSession) prepareSharedObjectsPrivate(ctx context.Context, policies []fullpolicy.Policy, transport sharedCommandTransport) (sharedObjectCandidate, workerResult, error) {
	candidate, step, compilerOnly := s.prepareSharedObjectsResult(ctx, policies, transport, workerPrivate)
	return candidate, workerResult{primary: step.diagnostic}, compilerOnly
}

func (s *BindingSession) prepareSharedObjectsResult(ctx context.Context, policies []fullpolicy.Policy, transport sharedCommandTransport, mode workerMode) (sharedObjectCandidate, workerStep, error) {
	var candidate sharedObjectCandidate
	if len(policies) == 0 || len(policies) > fullpolicy.MaxPolicies {
		return candidate, mode.failure(workerObjectCount, workerInvalidCount, nil), nil
	}
	n := s.node
	ctx, finish, err := n.beginSharedObjectOperation(ctx)
	if err != nil {
		return candidate, mode.failure(workerBegin, workerOpaque, err), nil
	}
	defer finish()
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.account
	a.mu.Lock()
	defer a.mu.Unlock()
	return s.prepareSharedObjectsLocked(ctx, policies, transport, mode, nil)
}

// Session and account locks and the registered operation are held by the caller.
func (s *BindingSession) prepareSharedObjectsLocked(ctx context.Context, policies []fullpolicy.Policy, transport sharedCommandTransport, mode workerMode, budget *sharedWorkerBudget) (sharedObjectCandidate, workerStep, error) {
	var candidate sharedObjectCandidate
	n, a := s.node, s.account
	var err error
	if s.removed || a.registration.Sequence == 0 || !a.native.reserved {
		return candidate, mode.failure(workerBinding, workerUnavailable, ErrSharedNativeUnavailable), nil
	}
	if err = a.pins.Check(ctx); err != nil {
		return candidate, mode.failure(workerPins, workerOpaque, err), nil
	}
	registry := n.objects
	first := int(a.native.slot) * 2
	var record *sharedObjectRecord
	for i := first; i < first+2; i++ {
		if !registry.records[i].live && registry.records[i].token < math.MaxUint64-1 {
			record = &registry.records[i]
			record.token++
			record.live = true
			candidate = sharedObjectCandidate{node: n, record: uint32(i), token: record.token}
			break
		}
	}
	if record == nil {
		return candidate, mode.failure(workerRecord, workerCandidateCapacity, nil), nil
	}
	// The fixed record and compile-worker allowance are reserved BEFORE any
	// compiler work. The single accepted worker uses one declared CompileBytes
	// allowance. A compiler-owned preflight covering transient work is still
	// required before exposing this preparation as budget-qualified: checking
	// retained output below does NOT prove the CompileBytes workspace bound.
	for i, policy := range policies {
		if err = ctx.Err(); err != nil {
			return candidate, mode.failure(workerPolicy, workerOpaque, err), nil
		}
		var object *fullpolicy.SharedPolicy
		var e error
		if budget == nil {
			object, e = fullpolicy.CompileSharedPolicyCompact(policy)
		} else {
			var debit uint64
			object, debit, e = fullpolicy.CompileSharedPolicyLimited(policy, budget.remaining)
			if !budget.consume(debit) {
				return candidate, mode.failure(workerCompile, workerRetainedOwnership, nil), nil
			}
		}
		if e != nil {
			return candidate, workerStep{diagnostic: workerDiagnostic{site: workerCompile, reason: workerCompiler}}, e
		}
		bytes, e := object.RetainedBytes()
		if e != nil {
			return candidate, mode.failure(workerOwnedSize, workerOpaque, e), nil
		}
		if budget == nil && bytes > n.config.Profile.CompileBytes {
			return candidate, mode.failure(workerRetainedLimit, workerRetainedLimitFailure, nil), nil
		}
		if step := n.reserveSharedRetainedResult(bytes, mode); step.failed() {
			return candidate, step, nil
		}
		record.sourceBytes[i] = bytes
		record.source[i] = object
		record.count = uint32(i + 1)
		if step := n.acquireSharedObjectResult(ctx, record, uint32(i), object, uint32(len(policy.Rules)), transport, mode); step.failed() {
			return candidate, step, nil
		}
	}
	record.complete = true
	return candidate, workerStep{}, nil
}

func (n *NodeEnforcer) acquireSharedObjectResult(ctx context.Context, record *sharedObjectRecord, position uint32, object *fullpolicy.SharedPolicy, rules uint32, transport sharedCommandTransport, mode workerMode) workerStep {
	registry := n.objects
	for i := range registry.slots {
		slot := &registry.slots[i]
		if slot.object != nil && slot.phase == 2 && !slot.retiring && !slot.poisoned && !slot.pending && slot.object.Digest() == object.Digest() && slot.object.Equal(object) {
			slot.refs++
			record.slots[position] = uint32(i)
			record.held[position] = true
			record.associated[position] = true
			return workerStep{}
		}
	}
	index := -1
	for i := range registry.slots {
		slot := &registry.slots[i]
		if slot.object == nil && slot.phase == 0 && slot.generation < math.MaxUint64-1 && slot.capacity >= object.EntryCount() {
			index = i
			break
		}
	}
	if index < 0 || registry.nextAttempt >= math.MaxUint64-1 {
		return mode.failure(workerAcquire, workerSlotCapacity, nil)
	}
	registry.nextAttempt++
	slot := &registry.slots[index]
	slot.object = object
	// The representative aliases this exact authored allocation. Transfer its
	// existing charge to the slot; other independently compiled source objects
	// remain charged separately even when their physical cells deduplicate.
	slot.sourceBytes = record.sourceBytes[position]
	record.sourceBytes[position] = 0
	slot.attempt = registry.nextAttempt
	slot.refs = 1
	record.slots[position] = uint32(index)
	record.held[position] = true
	record.associated[position] = true
	if step := mode.objectCommand(ctx, n, slot, sharedCommandWire{Operation: 1, Object: uint32(index), Generation: slot.generation, Attempt: slot.attempt, Count: object.EntryCount()}, transport, workerObjectBegin); step.failed() {
		return step
	}
	for i := uint32(0); i < object.EntryCount(); i++ {
		cell, err := object.Entry(i)
		if err != nil {
			return mode.failure(workerEntry, workerOpaque, err)
		}
		if step := mode.objectCommand(ctx, n, slot, sharedCommandWire{Operation: 2, Object: uint32(index), Generation: slot.generation, Attempt: slot.attempt, Index: i, Value: cell}, transport, workerObjectCell); step.failed() {
			return step
		}
	}
	class, err := object.ExecutionClass()
	if err != nil {
		return mode.failure(workerClass, workerOpaque, err)
	}
	return mode.objectCommand(ctx, n, slot, sharedCommandWire{Operation: 3, Object: uint32(index), Generation: slot.generation, Attempt: slot.attempt, Count: rules, ExecutionClass: class}, transport, workerObjectSeal)
}

// Preserve the exact pending request, even on errors/cancellation. A validated
// receipt is classified before its accompanying error. No INSPECT proves bytes.
func (n *NodeEnforcer) runSharedObjectCommand(ctx context.Context, slot *sharedObjectSlot, command sharedCommandWire, transport sharedCommandTransport) error {
	switch prepareSharedObjectCommand(slot, command) {
	case sharedOutcomeObjectPoisoned:
		return fmt.Errorf("shared object outcome incompatible")
	case sharedOutcomeObjectPendingConflict:
		return fmt.Errorf("shared object has unresolved command")
	}
	var receipt sharedReceiptWire
	var err error
	if transport == nil {
		receipt, err = n.host.control.call(ctx, command)
	} else {
		receipt, err = n.host.control.callWithTransport(ctx, command, transport)
	}
	switch classifySharedObjectReceipt(slot, command, receipt) {
	case sharedReceiptUnresolved:
		return errors.Join(err, fmt.Errorf("shared object command unresolved"))
	case sharedReceiptIncompatible:
		return errors.Join(err, fmt.Errorf("shared object command refused or incompatible"))
	}
	return err
}

func prepareSharedObjectCommand(slot *sharedObjectSlot, command sharedCommandWire) sharedOutcomeCode {
	if slot.poisoned {
		return sharedOutcomeObjectPoisoned
	}
	if slot.pending && slot.command != command {
		return sharedOutcomeObjectPendingConflict
	}
	slot.command = command
	slot.pending = true
	return sharedOutcomeOK
}

// Receipt classification and ownership mutation precede error presentation on
// both paths. Cancellation never erases a validated completed receipt.
func classifySharedObjectReceipt(slot *sharedObjectSlot, command sharedCommandWire, receipt sharedReceiptWire) sharedReceiptClass {
	if receipt.Sequence == 0 {
		return sharedReceiptUnresolved
	}
	generation, phase := command.Generation, uint32(0)
	switch command.Operation {
	case 1:
		generation++
		phase = 1
	case 2:
		generation = 0
	case 3:
		phase = 2
	case 5:
		phase = 3
	}
	if receipt.Status != 0 || receipt.Generation != generation || receipt.Serial != 0 || receipt.Value != phase {
		slot.poisoned = true
		return sharedReceiptIncompatible
	}
	slot.pending = false
	slot.command = sharedCommandWire{}
	if command.Operation != 2 {
		slot.generation = generation
		slot.phase = phase
	}
	return sharedReceiptCompleted
}

func (c sharedObjectCandidate) discard(ctx context.Context, transport sharedCommandTransport) error {
	return c.discardResult(ctx, transport, workerRich).err
}

func (c sharedObjectCandidate) discardPrivate(ctx context.Context, transport sharedCommandTransport) workerResult {
	return workerResult{primary: c.discardResult(ctx, transport, workerPrivate).diagnostic}
}

func (n *NodeEnforcer) discardSharedObjectRecord(ctx context.Context, c sharedObjectCandidate, transport sharedCommandTransport) error {
	return n.discardSharedObjectRecordResult(ctx, c, transport, workerRich).err
}

func (c sharedObjectCandidate) discardResult(ctx context.Context, transport sharedCommandTransport, mode workerMode) workerStep {
	if c.node == nil {
		return mode.failure(workerDiscardInput, workerMissingCandidate, nil)
	}
	n := c.node
	ctx, finish, err := n.beginSharedObjectOperation(ctx)
	if err != nil {
		return mode.failure(workerBegin, workerOpaque, err)
	}
	defer finish()
	return n.discardSharedObjectRecordResult(ctx, c, transport, mode)
}

// Called either by its admitted native operation or joined whole-node cleanup.
func (n *NodeEnforcer) discardSharedObjectRecordResult(ctx context.Context, c sharedObjectCandidate, transport sharedCommandTransport, mode workerMode) workerStep {
	registry := n.objects
	if int(c.record) >= len(registry.records) {
		return mode.failure(workerDiscardRecord, workerForeignCandidate, nil)
	}
	record := &registry.records[c.record]
	if c.node != n || !record.live || record.token != c.token {
		return mode.failure(workerDiscardRecord, workerStaleCandidate, nil)
	}
	if step := n.discardSharedSnapshotResult(ctx, c, record, transport, mode); step.failed() {
		return step
	}
	for i := uint32(0); i < record.count; i++ {
		if !record.associated[i] {
			if step := n.releaseSharedAuthoredResult(record, i, mode, workerAuthoredUnassociated); step.failed() {
				return step
			}
			continue
		}
		index := record.slots[i]
		slot := &registry.slots[index]
		if record.held[i] {
			slot.refs--
			record.held[i] = false
		}
		if slot.refs != 0 {
			record.associated[i] = false
			if step := n.releaseSharedAuthoredResult(record, i, mode, workerAuthoredShared); step.failed() {
				return step
			}
			continue
		}
		slot.retiring = true // Remove from lookup BEFORE retirement intent.
		if slot.pending {
			if step := mode.objectCommand(ctx, n, slot, slot.command, transport, workerObjectReconcile); step.failed() {
				return step
			}
		}
		if slot.poisoned {
			return mode.failure(workerObjectPoison, workerObjectUncertain, nil)
		}
		if slot.phase == 1 {
			if step := mode.objectCommand(ctx, n, slot, sharedCommandWire{Operation: 4, Object: index, Generation: slot.generation, Attempt: slot.attempt}, transport, workerObjectAbort); step.failed() {
				return step
			}
		}
		if slot.phase == 2 {
			if step := mode.objectCommand(ctx, n, slot, sharedCommandWire{Operation: 5, Object: index, Generation: slot.generation}, transport, workerObjectRetire); step.failed() {
				return step
			}
		}
		if slot.phase == 3 {
			if step := mode.objectCommand(ctx, n, slot, sharedCommandWire{Operation: 6, Object: index, Generation: slot.generation}, transport, workerObjectReclaim); step.failed() {
				return step
			}
		}
		if slot.phase != 0 {
			return mode.failure(workerObjectEmpty, workerObjectNotReclaimed, nil)
		}
		if step := n.releaseSharedRetainedResult(slot.sourceBytes, mode, workerSlotSource); step.failed() {
			return step
		}
		*slot = sharedObjectSlot{generation: slot.generation, capacity: slot.capacity}
		record.associated[i] = false
		if step := n.releaseSharedAuthoredResult(record, i, mode, workerAuthoredFinal); step.failed() {
			return step
		}
	}
	*record = sharedObjectRecord{token: record.token}
	return workerStep{}
}

func (n *NodeEnforcer) settleSharedObjects(ctx context.Context, transport sharedCommandTransport) error {
	if n.objects == nil {
		return nil
	}
	var result error
	for i := range n.objects.records {
		r := &n.objects.records[i]
		if r.live {
			result = errors.Join(result, n.discardSharedObjectRecord(ctx, sharedObjectCandidate{node: n, record: uint32(i), token: r.token}, transport))
		}
	}
	return result
}

// Fixed registry/table and one extra cancellation-snapshot record. Retained
// compiler allocations use the checked global CandidateBytes ledger. Neither
// object class nor binding record imposes an invented per-owner byte limit.
func sharedObjectRegistryBytes(profile SharedProfile) (uint64, error) {
	admission, err := profile.Validate()
	if err != nil {
		return 0, err
	}
	slots, err := checkedSharedProduct(admission.PolicyObjects, uint64(unsafe.Sizeof(sharedObjectSlot{})))
	if err != nil {
		return 0, err
	}
	records, err := checkedSharedProduct(admission.Snapshots, uint64(unsafe.Sizeof(sharedObjectRecord{})))
	if err != nil {
		return 0, err
	}
	scopes, err := checkedSharedProduct(profile.Bindings, uint64(unsafe.Sizeof(sharedSnapshotScopeState{})))
	if err != nil {
		return 0, err
	}
	return checkedSharedResourceSum(scopes, uint64(unsafe.Sizeof(sharedObjectRegistry{})), uint64(unsafe.Sizeof((*sharedObjectRegistry)(nil))), slots, records, uint64(unsafe.Sizeof(sharedStartupOperation{})))
}

// Called only by the single admitted native operation, which retains its
// compile-worker reservation across measurement and this ownership transfer.
func (n *NodeEnforcer) reserveSharedRetainedBytes(bytes uint64) error {
	return n.reserveSharedRetainedResult(bytes, workerRich).err
}

func (n *NodeEnforcer) reserveSharedRetainedResult(bytes uint64, mode workerMode) workerStep {
	r := n.objects
	if bytes > math.MaxUint64-r.retainedBytes || r.retainedBytes+bytes > n.config.Profile.CandidateBytes {
		return mode.failure(workerReserve, workerRetainedCapacity, nil)
	}
	r.retainedBytes += bytes
	return workerStep{}
}

func (n *NodeEnforcer) releaseSharedAuthoredSource(record *sharedObjectRecord, index uint32) error {
	return n.releaseSharedAuthoredResult(record, index, workerRich, workerAuthoredFinal).err
}

func (n *NodeEnforcer) releaseSharedAuthoredResult(record *sharedObjectRecord, index uint32, mode workerMode, site workerSite) workerStep {
	if step := n.releaseSharedRetainedResult(record.sourceBytes[index], mode, site); step.failed() {
		return step
	}
	record.sourceBytes[index] = 0
	record.source[index] = nil
	return workerStep{}
}

func (n *NodeEnforcer) releaseSharedRetainedBytes(bytes uint64) error {
	return n.releaseSharedRetainedResult(bytes, workerRich, workerSlotSource).err
}

func (n *NodeEnforcer) releaseSharedRetainedResult(bytes uint64, mode workerMode, site workerSite) workerStep {
	if bytes > n.objects.retainedBytes {
		return mode.failure(site, workerRetainedOwnership, nil)
	}
	n.objects.retainedBytes -= bytes
	return workerStep{}
}
