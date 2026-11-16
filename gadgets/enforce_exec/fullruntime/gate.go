// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Package fullruntime owns persistent exec admission, publication and native
// lifecycle for the matching experimental enforce_exec owner image.
package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

const (
	GateClosed            uint64 = 1 << 63
	GateCountMask                = GateClosed - 1
	MaxAdmittedExecs             = 4096
	MaxLifetimeSlots             = 65536
	MaxConcurrentBindings        = 1024
	GateCASAttempts              = 64
)

var (
	ErrGateBusy      = errors.New("gate admission or publisher is closed")
	ErrGateCapacity  = errors.New("gate admission capacity exhausted")
	ErrGateCorrupt   = errors.New("invalid gate count")
	ErrGateUnderflow = errors.New("gate admission underflow")
	ErrGateRetired   = errors.New("gate slot permanently retired")
	ErrGateClosed    = errors.New("gate memory unmapped")
	ErrStaleLease    = errors.New("update lease already completed")
	ErrSlotCapacity  = errors.New("gate slot capacity exhausted")
)

type gateMemory struct {
	mu     sync.RWMutex
	mapped []byte
	closed bool
}

// Gate has one Go publisher owner and a word shared with BPF atomic operations.
// Never construct multiple Gate owners for the same word. Do not copy a Gate.
// Ordinary stores and bpf_map_update_elem writes to a live word are forbidden.
type Gate struct {
	memory    *gateMemory
	word      *uint64
	publisher sync.Mutex
	retired   atomic.Bool
	onRetire  func()
}

// NewGateWord wraps one caller-owned aligned word (useful for protocol tests).
// The caller must keep the word alive, and must not unmap it independently.
func NewGateWord(word *uint64) (*Gate, error) {
	if word == nil || uintptr(unsafe.Pointer(word))%8 != 0 {
		return nil, fmt.Errorf("gate requires a non-nil 8-byte-aligned word")
	}
	if atomic.LoadUint64(word)&GateCountMask > MaxAdmittedExecs {
		return nil, ErrGateCorrupt
	}
	return &Gate{word: word, memory: &gateMemory{}}, nil
}

func (g *Gate) load() (uint64, error) {
	g.memory.mu.RLock()
	defer g.memory.mu.RUnlock()
	if g.memory.closed {
		return 0, ErrGateClosed
	}
	return atomic.LoadUint64(g.word), nil
}

func (g *Gate) cas(old, next uint64) (bool, error) {
	g.memory.mu.RLock()
	defer g.memory.mu.RUnlock()
	if g.memory.closed {
		return false, ErrGateClosed
	}
	return atomic.CompareAndSwapUint64(g.word, old, next), nil
}

// State observes one atomic word. Closed alone does not identify a publisher.
func (g *Gate) State() (closed bool, count uint64, err error) {
	v, err := g.load()
	if err != nil {
		return false, 0, err
	}
	if v&GateCountMask > MaxAdmittedExecs {
		return v&GateClosed != 0, v & GateCountMask, ErrGateCorrupt
	}
	return v&GateClosed != 0, v & GateCountMask, nil
}

// Enter mirrors the BPF bounded-CAS admission primitive. A successful caller owns
// exactly one subsequent Leave, even if its current cgroup or PID later changes.
func (g *Gate) Enter() error {
	if g.retired.Load() {
		return ErrGateRetired
	}
	for range GateCASAttempts {
		v, err := g.load()
		if err != nil {
			return err
		}
		count := v & GateCountMask
		if count > MaxAdmittedExecs {
			return ErrGateCorrupt
		}
		if v&GateClosed != 0 {
			return ErrGateBusy
		}
		if count == MaxAdmittedExecs {
			return ErrGateCapacity
		}
		ok, err := g.cas(v, v+1)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return ErrGateBusy
}

// Leave must follow all role commits and pending-state cleanup. It does not
// validate per-task ownership: the caller must prevent duplicate completion.
// Contention exhaustion leaves the count retained and returns an explicit error;
// callers must retain release ownership and retry, never pretend it succeeded.
func (g *Gate) Leave() error {
	for range GateCASAttempts {
		v, err := g.load()
		if err != nil {
			return err
		}
		count := v & GateCountMask
		if count > MaxAdmittedExecs {
			return ErrGateCorrupt
		}
		if count == 0 {
			return ErrGateUnderflow
		}
		ok, err := g.cas(v, v-1)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
	return ErrGateBusy
}

// BeginUpdate closes admission and waits for all admitted transactions to finish.
// Only the returned lease may publish then reopen/retire this gate. A timeout
// reopens this owner's closure preserving the outstanding count and old policy.
// Concurrent publishers return ErrGateBusy rather than taking over a closed bit.
func (g *Gate) BeginUpdate(ctx context.Context) (*UpdateLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if g.retired.Load() {
		return nil, ErrGateRetired
	}
	if !g.publisher.TryLock() {
		return nil, ErrGateBusy
	}
	unlock := true
	defer func() {
		if unlock {
			g.publisher.Unlock()
		}
	}()
	closed := false
	for range GateCASAttempts {
		v, err := g.load()
		if err != nil {
			return nil, err
		}
		if v&GateCountMask > MaxAdmittedExecs {
			return nil, ErrGateCorrupt
		}
		if v&GateClosed != 0 {
			return nil, ErrGateBusy
		}
		ok, err := g.cas(v, v|GateClosed)
		if err != nil {
			return nil, err
		}
		if ok {
			closed = true
			break
		}
	}
	if !closed {
		return nil, ErrGateBusy
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		// Cancellation wins over drain when both become visible together.
		if err := ctx.Err(); err != nil {
			return nil, errors.Join(err, g.reopen())
		}
		v, err := g.load()
		if err != nil {
			return nil, err
		}
		if v&GateClosed == 0 || v&GateCountMask > MaxAdmittedExecs {
			return nil, ErrGateCorrupt
		}
		if v&GateCountMask == 0 {
			unlock = false
			return &UpdateLease{gate: g, done: new(atomic.Bool)}, nil
		}
		select {
		case <-ctx.Done():
		case <-ticker.C:
		}
	}
}

// reopen is called only by the publisher holding g.publisher. It never discards
// an outstanding count. Admissions can only start after its successful CAS.
func (g *Gate) reopen() error {
	for {
		v, err := g.load()
		if err != nil {
			return err
		}
		if v&GateClosed == 0 || v&GateCountMask > MaxAdmittedExecs {
			return ErrGateCorrupt
		}
		ok, err := g.cas(v, v&GateCountMask)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
	}
}

type UpdateLease struct {
	gate *Gate
	// Shared across value copies: copying a handle must not duplicate the right
	// to unlock/reopen a later publisher's gate.
	done *atomic.Bool
}

// Reopen follows completed map publication (or an unchanged old configuration).
// A copied/stale lease must never be used to reopen another publisher's gate.
func (l *UpdateLease) Reopen() error {
	if l == nil || l.gate == nil || l.done == nil || !l.done.CompareAndSwap(false, true) {
		return ErrStaleLease
	}
	g := l.gate
	defer g.publisher.Unlock()
	_, count, err := g.State()
	if err != nil {
		return err
	}
	if count != 0 {
		return ErrGateCorrupt
	}
	return g.reopen()
}

// Retire permanently closes a drained slot. Slots are never recycled, preventing
// a delayed pre-admission BPF reader from admitting against a different binding.
func (l *UpdateLease) Retire() error {
	if l == nil || l.gate == nil || l.done == nil || !l.done.CompareAndSwap(false, true) {
		return ErrStaleLease
	}
	g := l.gate
	defer g.publisher.Unlock()
	closed, count, err := g.State()
	if err != nil {
		return err
	}
	if !closed || count != 0 {
		return ErrGateCorrupt
	}
	g.retired.Store(true)
	if g.onRetire != nil {
		g.onRetire()
	}
	return nil
}

// GateMap owns one writable mmap view and monotonic slot allocation. It borrows
// the map FD, but its mmap remains valid independently until Close. Do not make
// another allocator for the same map. The supplied map must be new/zero-filled.
type GateMap struct {
	mu           sync.Mutex
	memory       *gateMemory
	words        []uint64
	next, active uint32
}

func NewGateMap(m *ebpf.Map) (*GateMap, error) {
	if m == nil {
		return nil, fmt.Errorf("gate map is required")
	}
	if m.Type() != ebpf.Array || m.KeySize() != 4 || m.ValueSize() != 8 || m.MaxEntries() != MaxLifetimeSlots || m.Flags()&unix.BPF_F_MMAPABLE == 0 || m.Flags()&(unix.BPF_F_RDONLY|unix.BPF_F_RDONLY_PROG|unix.BPF_F_WRONLY|unix.BPF_F_WRONLY_PROG) != 0 {
		return nil, fmt.Errorf("gate map requires a writable mmap-able ARRAY with key4/value8/65536 entries")
	}
	mapped, err := unix.Mmap(m.FD(), 0, MaxLifetimeSlots*8, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
	if err != nil {
		return nil, fmt.Errorf("mmap gate map: %w", err)
	}
	words := unsafe.Slice((*uint64)(unsafe.Pointer(&mapped[0])), MaxLifetimeSlots)
	for i := range words {
		if atomic.LoadUint64(&words[i]) != 0 {
			_ = unix.Munmap(mapped)
			return nil, fmt.Errorf("gate map is not a fresh zero-filled map")
		}
	}
	return &GateMap{memory: &gateMemory{mapped: mapped}, words: words}, nil
}

func (m *GateMap) Allocate() (uint32, *Gate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.memory.mu.RLock()
	defer m.memory.mu.RUnlock()
	if m.memory.closed {
		return 0, nil, ErrGateClosed
	}
	if m.next >= MaxLifetimeSlots || m.active >= MaxConcurrentBindings {
		return 0, nil, ErrSlotCapacity
	}
	slot := m.next
	m.next++
	m.active++
	g := &Gate{memory: m.memory, word: &m.words[slot]}
	g.onRetire = func() { m.mu.Lock(); m.active--; m.mu.Unlock() }
	return slot, g, nil
}

// Close requires every allocated slot to have been explicitly retired. This
// refuses unmapping while a publisher lease or admitted transaction can use it.
func (m *GateMap) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.memory.mu.Lock()
	defer m.memory.mu.Unlock()
	if m.memory.closed {
		return nil
	}
	if m.active != 0 {
		return ErrGateBusy
	}
	if len(m.memory.mapped) > 0 {
		if err := unix.Munmap(m.memory.mapped); err != nil {
			return err
		}
	}
	m.memory.closed = true
	m.words = nil
	m.memory.mapped = nil
	return nil
}
