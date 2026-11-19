// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sort"
	"sync"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// ProgramMapSpec is the fixed frozen-inner ABI. The outer slot must never be
// independently written; the persistent owner holds admission through bootstrap
// and publication. NO_PREALLOC avoids reserving maximum payload for tiny plans.
func ProgramMapSpec() *ebpf.MapSpec {
	return &ebpf.MapSpec{Name: "exec_program", Type: ebpf.Hash, KeySize: 4, ValueSize: fullpolicy.KernelBlobSize, MaxEntries: fullpolicy.MaxKernelEntries, Flags: unix.BPF_F_NO_PREALLOC | unix.BPF_F_RDONLY_PROG}
}

// ProgramSlotsSpec describes the program FD-array map, which rejects RDONLY_PROG flags.
// The verifier intrinsically permits
// BPF lookup only for map-of-maps; native userspace alone changes these slots.
func ProgramSlotsSpec() *ebpf.MapSpec {
	return &ebpf.MapSpec{Name: "exec_programs", Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 2, InnerMap: ProgramMapSpec()}
}

func AcceptedEpochsSpec() *ebpf.MapSpec {
	return &ebpf.MapSpec{Name: "exec_epochs", Type: ebpf.Hash, KeySize: 8, ValueSize: 8, MaxEntries: fullpolicy.MaxRoleEpochHistory, Flags: unix.BPF_F_NO_PREALLOC | unix.BPF_F_RDONLY_PROG}
}

type (
	slotResource interface{ Close() error }
	slotWriter   interface {
		Put(interface{}, interface{}) error
		Delete(interface{}) error
	}
)
type slotFactory func(*fullpolicy.KernelProgram) (slotResource, error)

// freezeProgram returns an owned FD. Close consumes the native FD even when
// Linux reports a close error; no ambiguous retry of a recycled FD is allowed.
func freezeProgram(p *fullpolicy.KernelProgram) (slotResource, error) {
	m, err := ebpf.NewMap(ProgramMapSpec())
	if err != nil {
		return nil, err
	}
	for i, entry := range p.Entries {
		if err = m.Put(uint32(i), entry); err != nil {
			return nil, errors.Join(err, m.Close())
		}
	}
	if err = m.Freeze(); err != nil {
		return nil, errors.Join(err, m.Close())
	}
	return m, nil
}

// ProgramSlot owns inner-map FDs, successful UID epochs and historical names for
// ONE persistent binding. It borrows the outer/history maps and gate. It does not
// attach hooks, authorize lineage, activate membership or supply aggregate memory
// budgets. Those prerequisites belong to the native binding owner. The caller
// must not independently write the borrowed slots/history or publish this gate.
//
// Stage (slot1) is prepared under a drained gate. Native bootstrap must complete
// against it before Commit. Commit atomically swaps active slot0 and records UID
// epochs; it deliberately DOES NOT reopen admission. Finish follows successful
// native phase cleanup. An error after Commit must never be treated as rollback.
type ProgramSlot struct {
	mu                    sync.Mutex
	gate                  *Gate
	slots, accepted       slotWriter
	create                slotFactory
	history               IdentityRegistry
	epochs                map[string]uint64
	generation, attempted uint64
	active                slotResource
	update                *programUpdate
	staging               bool
	garbage               []slotResource
	broken                error
	closed                bool
	retiring              bool
}
type programUpdate struct {
	owner           *ProgramSlot
	lease           *UpdateLease
	image           slotResource
	previous        slotResource
	generation      uint64
	next            map[string]uint64
	additions       []epochAddition
	flushed         int
	newMask         uint32
	committed, done bool
}
type epochAddition struct{ uid, epoch uint64 }

// ProgramUpdate is a handle, not duplicated authority: value copies share the
// same private state. Always Finish after Commit, or Abort before Commit. Retain
// an unfinished handle on native phase-cleanup failure; do not accidentally
// reopen admission while bootstrap is still active.
type (
	ProgramUpdate struct{ state *programUpdate }
	ProgramCommit struct {
		Committed  bool
		Generation uint64
	}
)

func NewProgramSlot(gate *Gate, slots, accepted *ebpf.Map) (*ProgramSlot, error) {
	if gate == nil || slots == nil || accepted == nil {
		return nil, fmt.Errorf("gate, program slots and successful epochs required")
	}
	if slots.Type() != ebpf.ArrayOfMaps || slots.KeySize() != 4 || slots.ValueSize() != 4 || slots.MaxEntries() != 2 || slots.Flags() != 0 {
		return nil, fmt.Errorf("invalid program slots ABI")
	}
	spec := AcceptedEpochsSpec()
	if accepted.Type() != spec.Type || accepted.KeySize() != spec.KeySize || accepted.ValueSize() != spec.ValueSize || accepted.MaxEntries() != spec.MaxEntries || accepted.Flags() != spec.Flags {
		return nil, fmt.Errorf("invalid successful epochs ABI")
	}
	var key uint64
	if err := accepted.NextKey(nil, &key); err == nil {
		return nil, fmt.Errorf("successful epoch map is not empty")
	} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil, fmt.Errorf("checking successful epoch map: %w", err)
	}
	for i := uint32(0); i < 2; i++ {
		var id uint32
		if err := slots.Lookup(i, &id); err == nil {
			return nil, fmt.Errorf("program slots are not empty")
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("checking program slots: %w", err)
		}
	}
	return newProgramSlot(gate, slots, accepted, freezeProgram)
}

func newProgramSlot(gate *Gate, slots, accepted slotWriter, create slotFactory) (*ProgramSlot, error) {
	closed, count, err := gate.State()
	if err != nil {
		return nil, err
	}
	if closed || count != 0 {
		return nil, fmt.Errorf("program owner requires fresh open drained gate")
	}
	return &ProgramSlot{gate: gate, slots: slots, accepted: accepted, create: create, epochs: map[string]uint64{}}, nil
}

func snapshotProgram(p *fullpolicy.KernelProgram) *fullpolicy.KernelProgram {
	if p == nil {
		return nil
	}
	c := *p
	c.Entries = append([]fullpolicy.Blob(nil), p.Entries...)
	c.Rules = append([]fullpolicy.RuleMetadata(nil), p.Rules...)
	c.Identities = maps.Clone(p.Identities)
	return &c
}

func (p *ProgramSlot) Epochs() map[string]uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return maps.Clone(p.epochs)
}
func (p *ProgramSlot) Generation() uint64 { p.mu.Lock(); defer p.mu.Unlock(); return p.generation }

// cleanup retries only the staging reference and owned retired FDs. Successful
// epoch rows are append-only and are NEVER deleted, including on errors.
func (p *ProgramSlot) cleanup() error {
	var errs []error
	if p.staging {
		if err := p.slots.Delete(uint32(1)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			errs = append(errs, err)
		} else {
			p.staging = false
		}
	}
	if !p.staging {
		for _, r := range p.garbage {
			errs = append(errs, r.Close())
		}
		p.garbage = nil
	}
	return errors.Join(errs...)
}

// Cleanup may be used by same-revision health retries, without restarting maps
// or changing roles. Native bootstrap must no longer use staging at this point.
func (p *ProgramSlot) Cleanup() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	if p.update != nil {
		return ErrGateBusy
	}
	return errors.Join(p.broken, p.cleanup())
}

func (p *ProgramSlot) Begin(ctx context.Context, program *fullpolicy.KernelProgram) (*ProgramUpdate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.retiring {
		return nil, fmt.Errorf("program owner closed")
	}
	if p.broken != nil {
		return nil, p.broken
	}
	if p.update != nil {
		return nil, ErrGateBusy
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := p.cleanup(); err != nil {
		return nil, err
	}
	candidate := snapshotProgram(program)
	if err := fullpolicy.ValidateKernelProgram(candidate); err != nil {
		return nil, err
	}
	h, _ := fullpolicy.Decode[fullpolicy.KernelHeader](candidate.Entries[0])
	if h.Generation <= p.attempted {
		return nil, fmt.Errorf("program generation reused or nonmonotonic")
	}
	p.attempted = h.Generation
	next := maps.Clone(p.epochs)
	var additions []epochAddition
	var mask uint32
	for i := uint32(0); i < h.PolicyCount; i++ {
		row, _ := fullpolicy.Decode[fullpolicy.KernelPolicy](candidate.Entries[fullpolicy.KernelPolicyBase+i])
		id := candidate.Identities[row.UID]
		if epoch, ok := p.epochs[id]; ok {
			if epoch != row.RootEpoch {
				return nil, fmt.Errorf("successful UID epoch changed")
			}
		} else {
			if row.RootEpoch != h.Generation {
				return nil, fmt.Errorf("new UID must use this attempt epoch")
			}
			next[id] = row.RootEpoch
			additions = append(additions, epochAddition{row.UID, row.RootEpoch})
			mask |= 1 << i
		}
	}
	if len(next) > fullpolicy.MaxRoleEpochHistory {
		return nil, fmt.Errorf("successful UID capacity exceeded")
	}
	if err := p.history.Reserve(candidate); err != nil {
		return nil, err
	}
	image, err := p.create(candidate)
	if err != nil {
		return nil, err
	}
	lease, err := p.gate.BeginUpdate(ctx)
	if err != nil {
		return nil, errors.Join(err, image.Close())
	}
	if err = p.slots.Put(uint32(1), image); err != nil {
		reopen := lease.Reopen()
		if reopen != nil {
			p.broken = reopen
		}
		return nil, errors.Join(err, reopen, image.Close())
	}
	p.staging = true
	sort.Slice(additions, func(i, j int) bool { return additions[i].uid < additions[j].uid })
	u := &programUpdate{owner: p, lease: lease, image: image, previous: p.active, generation: h.Generation, next: next, additions: additions, newMask: mask}
	p.update = u
	return &ProgramUpdate{state: u}, nil
}

func (u *ProgramUpdate) NewUIDMask() uint32 {
	if u == nil || u.state == nil {
		return 0
	}
	return u.state.newMask
}

// Map is borrowed until Finish/Abort. Never close or independently publish it.
func (u *ProgramUpdate) Map() (*ebpf.Map, error) {
	if u == nil || u.state == nil {
		return nil, ErrStaleLease
	}
	s := u.state
	p := s.owner
	p.mu.Lock()
	defer p.mu.Unlock()
	if s.done || p.update != s {
		return nil, ErrStaleLease
	}
	m, ok := s.image.(*ebpf.Map)
	if !ok {
		return nil, fmt.Errorf("not a native map")
	}
	return m, nil
}

func (u *ProgramUpdate) Commit() (ProgramCommit, error) {
	if u == nil || u.state == nil {
		return ProgramCommit{}, ErrStaleLease
	}
	s := u.state
	p := s.owner
	p.mu.Lock()
	defer p.mu.Unlock()
	result := ProgramCommit{Generation: p.generation}
	if s.done || p.update != s {
		return result, ErrStaleLease
	}
	if !s.committed {
		// One atomic slot replacement is the semantic commit boundary. There are
		// no provisional successful epochs, so precommit failures need no catalogue
		// rollback and can safely retain the healthy previous program.
		if err := p.slots.Put(uint32(0), s.image); err != nil {
			return result, err
		}
		p.active = s.image
		p.epochs = s.next
		p.generation = s.generation
		s.committed = true
	}
	result = ProgramCommit{true, s.generation}
	// Kernel history catches up WHILE admission and publication phase stay
	// closed. Even a partial write is already a SUCCESSFUL activation, never a
	// row to roll back. Repeated Commit resumes idempotently; Finish cannot open
	// the gate until every row is present.
	for s.flushed < len(s.additions) {
		a := s.additions[s.flushed]
		if err := p.accepted.Put(a.uid, a.epoch); err != nil {
			return result, err
		}
		s.flushed++
	}
	return result, nil
}

// Finish follows native bootstrap-phase cleanup, not merely a successful map
// swap. Even when reopening/cleanup fails, committed epochs remain committed.
func (u *ProgramUpdate) Finish() error {
	if u == nil || u.state == nil {
		return ErrStaleLease
	}
	s := u.state
	p := s.owner
	p.mu.Lock()
	defer p.mu.Unlock()
	if s.done || p.update != s {
		return ErrStaleLease
	}
	if !s.committed {
		return fmt.Errorf("uncommitted update requires Abort")
	}
	if s.flushed != len(s.additions) {
		return fmt.Errorf("committed epoch publication is incomplete")
	}
	err := s.lease.Reopen()
	if err != nil {
		p.broken = err
	}
	s.done = true
	p.update = nil
	cleanup := p.cleanup()
	if s.previous != nil {
		cleanup = errors.Join(cleanup, s.previous.Close())
		s.previous = nil
	}
	return errors.Join(err, cleanup)
}

// Abort follows native bootstrap-phase cleanup. Copies are idempotent after an
// abort; a committed update can never be rolled back by an old handle.
func (u *ProgramUpdate) Abort() error {
	if u == nil || u.state == nil {
		return ErrStaleLease
	}
	s := u.state
	p := s.owner
	p.mu.Lock()
	defer p.mu.Unlock()
	if s.done {
		return nil
	}
	if p.update != s {
		return ErrStaleLease
	}
	if s.committed {
		return fmt.Errorf("committed update requires Finish")
	}
	p.garbage = append(p.garbage, s.image)
	err := s.lease.Reopen()
	if err != nil {
		p.broken = err
	}
	s.done = true
	p.update = nil
	return errors.Join(err, p.cleanup())
}

// Retire is the before-StopGadget barrier. It closes/drains normal admission,
// or consumes this owner's already-drained pending update lease without ever
// reopening a half-finalized revision. It does NOT detach hooks or release pins.
// No further publication is permitted; CloseAfterDetach performs final cleanup.
func (p *ProgramSlot) Retire(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed || p.retiring {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if s := p.update; s != nil {
		if err := s.lease.Retire(); err != nil {
			return err
		}
		s.done = true
		p.retiring = true
		return nil
	}
	if p.broken != nil {
		// Reopen consumes its lease even on failure. Only this exclusive publisher
		// can retire its own leftover CLOSED+0 word; never adopt a foreign closure.
		if !p.gate.publisher.TryLock() {
			return ErrGateBusy
		}
		defer p.gate.publisher.Unlock()
		closed, count, err := p.gate.State()
		if err != nil {
			return err
		}
		if !closed || count != 0 {
			return ErrGateCorrupt
		}
		if p.gate.retired.CompareAndSwap(false, true) && p.gate.onRetire != nil {
			p.gate.onRetire()
		}
		p.retiring = true
		return nil
	}
	lease, err := p.gate.BeginUpdate(ctx)
	if err != nil {
		return err
	}
	if err = lease.Retire(); err != nil {
		return err
	}
	p.retiring = true
	return nil
}

// CloseAfterDetach consumes this owner's FDs only AFTER the native runtime has
// confirmed all its hooks/commands stopped. It is not a replacement for draining
// before StopGadget. Outer/history maps and mmap lifetime remain caller-owned.
// An abandoned/failed lease is completed by Retire only if still owned/drained.
func (p *ProgramSlot) CloseAfterDetach() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	var errs []error
	if s := p.update; s != nil {
		if !p.retiring {
			errs = append(errs, s.lease.Retire())
		}
		if !s.committed {
			errs = append(errs, s.image.Close())
		}
		if s.previous != nil && s.previous != p.active {
			errs = append(errs, s.previous.Close())
		}
		s.done = true
		p.update = nil
	}
	if p.active != nil {
		errs = append(errs, p.active.Close())
		p.active = nil
	}
	for _, r := range p.garbage {
		errs = append(errs, r.Close())
	}
	p.garbage = nil
	return errors.Join(errs...)
}
