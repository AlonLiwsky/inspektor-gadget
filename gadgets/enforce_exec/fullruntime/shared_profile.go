// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"math"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

const SharedProfileVersion uint32 = 1

// SharedQuota reserves each binding's capacity, including during candidate
// preparation. Images counts reserved image-origin KEY CELLS across active,
// candidate and retiring evidence together, not evidence sets or snapshot handles.
// A reused immutable evidence set is charged once until its last reference retires.
// It does not certify ingress, kernel support or physical memory.
type SharedQuota struct{ Tasks, Scratch, InodeFacts, AcceptedUIDs, Images uint64 }

// SharedProfile has no inferred defaults. PolicySlots is indexed by the fixed
// cell classes 256,1024,4096,16384, globally, NOT once per binding.
// Images is the global image-origin key-cell pool, not a per-input validation
// limit. Image-set metadata remains bounded by the two snapshot records per
// binding; reserving key cells does not authorize complete image evidence.
type SharedProfile struct {
	Version                                                        uint32
	Bindings                                                       uint64
	PolicySlots                                                    [4]uint64
	Tasks, Scratch, InodeFacts, AcceptedUIDs, Images               uint64
	CompileBytes, CompileConcurrency, TelemetryBytes, RolloutBytes uint64
	CandidateBytes                                                 uint64
	PossibleCPUs                                                   uint32
	PerBinding                                                     SharedQuota
	// ExitTombstones is the node-wide credit-at-exit tombstone table
	// (se_exit_tombstones max_entries, SE_PROFILE_EXIT_TOMBSTONES), sized
	// for the exit burst (exit-to-free latency x exit rate), NOT by TASK
	// count; each binding owns an equal share. Zero selects the legacy
	// 32 x Tasks, kept only so pre-existing qualification objects stay
	// byte-identical; product profiles set it explicitly.
	ExitTombstones uint64
	// VerdictRing is the byte size of the node-wide verdict event ring
	// (opaque_real_verdict_events max_entries, SE_PROFILE_VERDICT_RING;
	// G020): a power of two from 4 KiB to 256 MiB. Zero selects the
	// default, max(1 MiB, Bindings x 256 KiB) rounded up to a power of two
	// (the object's default for its SE_PROFILE_BINDINGS).
	VerdictRing uint64
}

// Verdict ring bounds (the BPF static assert on SE_PROFILE_VERDICT_RING).
const (
	sharedVerdictRingMin        = 4096
	sharedVerdictRingMax        = 1 << 28
	sharedVerdictRingDefaultMin = 1 << 20
	sharedVerdictRingPerBinding = 256 << 10
)

// verdictRing is the effective verdict ring size (see VerdictRing); 0 when
// the default exceeds sharedVerdictRingMax.
func (p SharedProfile) verdictRing() uint64 {
	if p.VerdictRing != 0 {
		return p.VerdictRing
	}
	if p.Bindings > sharedVerdictRingMax/sharedVerdictRingPerBinding {
		return 0
	}
	ring := uint64(sharedVerdictRingDefaultMin)
	for ring < p.Bindings*sharedVerdictRingPerBinding {
		ring <<= 1
	}
	return ring
}

// sharedMaxExitTombstones mirrors the BPF static assert on
// SE_PROFILE_EXIT_TOMBSTONES.
const sharedMaxExitTombstones = 1 << 20

// exitTombstones is the effective tombstone table size (see ExitTombstones).
func (p SharedProfile) exitTombstones() uint64 {
	if p.ExitTombstones == 0 {
		return 32 * p.Tasks
	}
	return p.ExitTombstones
}

// SharedAdmission describes logical capacity only. Complete map/wire/native and
// physical allocation accounting remains required at collection creation.
type SharedAdmission struct{ ArenaCells, ArenaBytes, PolicyObjects, Snapshots, PinTickets uint64 }

func checkedSharedProduct(a, b uint64) (uint64, error) {
	if b != 0 && a > math.MaxUint64/b {
		return 0, fmt.Errorf("shared capacity product overflow")
	}
	return a * b, nil
}

func (p SharedProfile) Validate() (SharedAdmission, error) {
	var a SharedAdmission
	if p.Version != SharedProfileVersion || p.Bindings == 0 || p.PossibleCPUs == 0 || p.PossibleCPUs > 64 || p.CompileBytes == 0 || p.CompileConcurrency == 0 || p.TelemetryBytes == 0 || p.RolloutBytes == 0 || p.CandidateBytes == 0 {
		return a, fmt.Errorf("complete versioned shared profile required")
	}
	for _, count := range []uint64{p.Bindings, p.Tasks, p.Scratch, p.InodeFacts, p.AcceptedUIDs, p.Images} {
		if count == 0 || count > math.MaxUint32 {
			return a, fmt.Errorf("shared map count outside u32 domain")
		}
	}
	for _, pair := range [][2]uint64{{p.PerBinding.Tasks, p.Tasks}, {p.PerBinding.Scratch, p.Scratch}, {p.PerBinding.InodeFacts, p.InodeFacts}, {p.PerBinding.AcceptedUIDs, p.AcceptedUIDs}, {p.PerBinding.Images, p.Images}} {
		reserved, err := checkedSharedProduct(p.Bindings, pair[0])
		if err != nil {
			return a, err
		}
		if pair[0] == 0 || reserved > pair[1] {
			return a, fmt.Errorf("shared binding reservation exceeds pool")
		}
	}
	for i, size := range [4]uint64{256, 1024, 4096, 16384} {
		cells, err := checkedSharedProduct(p.PolicySlots[i], size)
		if err != nil {
			return a, err
		}
		if cells > math.MaxUint64-a.ArenaCells || p.PolicySlots[i] > math.MaxUint64-a.PolicyObjects {
			return a, fmt.Errorf("shared arena sum overflow")
		}
		a.ArenaCells += cells
		a.PolicyObjects += p.PolicySlots[i]
	}
	if a.ArenaCells > math.MaxUint32 {
		return a, fmt.Errorf("shared arena index exceeds u32 domain")
	}
	if a.PolicyObjects == 0 {
		return a, fmt.Errorf("empty shared arena")
	}
	var err error
	a.ArenaBytes, err = checkedSharedProduct(a.ArenaCells, fullpolicy.KernelBlobSize)
	if err != nil {
		return SharedAdmission{}, err
	}
	a.Snapshots, err = checkedSharedProduct(p.Bindings, 2)
	if err != nil {
		return SharedAdmission{}, err
	}
	a.PinTickets, err = checkedSharedProduct(p.Bindings, 16)
	if err != nil {
		return SharedAdmission{}, err
	}
	if _, err = checkedSharedProduct(p.CompileBytes, p.CompileConcurrency); err != nil {
		return SharedAdmission{}, err
	}
	if a.Snapshots > math.MaxUint32 || a.PinTickets > math.MaxUint32 {
		return SharedAdmission{}, fmt.Errorf("shared snapshot/ticket count exceeds u32 domain")
	}
	if p.Tasks > math.MaxUint64/32 {
		return SharedAdmission{}, fmt.Errorf("shared exit tombstones overflow")
	}
	if t := p.exitTombstones(); t == 0 || t > sharedMaxExitTombstones || t%p.Bindings != 0 {
		return SharedAdmission{}, fmt.Errorf("shared exit tombstones %d must be a nonzero multiple of %d bindings, at most %d", t, p.Bindings, sharedMaxExitTombstones)
	}
	if r := p.verdictRing(); r < sharedVerdictRingMin || r > sharedVerdictRingMax || r&(r-1) != 0 {
		return SharedAdmission{}, fmt.Errorf("shared verdict ring %d (%d bindings) must be a power of two from %d to %d bytes", r, p.Bindings, sharedVerdictRingMin, sharedVerdictRingMax)
	}
	return a, nil
}

// ObjectRange derives the only allowed global arena range from class and slot.
// There is no caller-selected base and no per-binding payload allocation.
func (p SharedProfile) ObjectRange(class uint32, slot uint64) (base, cells uint64, err error) {
	if _, err = p.Validate(); err != nil {
		return 0, 0, err
	}
	if class >= 4 || slot >= p.PolicySlots[class] {
		return 0, 0, fmt.Errorf("invalid shared object slot")
	}
	sizes := [4]uint64{256, 1024, 4096, 16384}
	for i := uint32(0); i < class; i++ {
		base += p.PolicySlots[i] * sizes[i]
	}
	return base + slot*sizes[class], sizes[class], nil
}
