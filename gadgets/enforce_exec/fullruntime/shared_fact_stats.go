// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Per-pass exec facts (G020, full/shared_pass_facts.h): every product
// object collects the target and actor paths, the target's fs class, the
// stdin pipe and up to 16 ancestors on each evaluated bprm_check pass. A fact
// the pass cannot collect is UNKNOWN to the evaluator (Strict denies a rule
// that consults it, Audit records the unknown); FactStatsMap counts each
// reason (one u64 per cell, RDONLY).
const (
	FactStatsMap = "opaque_real_fact_stats"
	FactStats    = 17

	// sharedFactWitnessMap is the test-only per-pass witness ring
	// (ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_WITNESS): a product object never
	// carries it (#error in the source, sharedProductForbiddenMaps).
	sharedFactWitnessMap = "opaque_real_fact_witness"
)

// Cells of FactStatsMap (SE_PF_* in full/shared_pass_facts.h).
const (
	FactPasses            = iota // passes collected (one per evaluated pass)
	FactTargetMissing            // no exec file
	FactTargetPath               // d_path failed or not absolute, or the root walk was unknown
	FactTargetTooLong            // longer than 255 bytes (never truncated)
	FactTargetOutsideRoot        // D5: not reachable from the binding root (binfmt_misc F)
	FactActorMissing             // no exe file
	FactActorPath                // d_path failed or too long, or the root walk was unknown
	FactActorOutsideRoot         // the actor's exe is not reachable from its root
	FactFSUnknown                // at least one fs class unknown
	FactStdinUnknown             // stdin not observable (shared files table)
	FactAncestorUnknown          // the ancestor walk failed: ancestor facts UNKNOWN
	FactAncestorBoundary         // the chain ended at the binding's init or the workload's edge (complete)
	FactAncestorTruncated        // more than 16 ancestors (known prefix, incomplete)
	FactRootMismatch             // H1: the task's root is not the binding's anchored root (chroot): every path UNKNOWN
	FactTargetMemfd              // the target is on a kernel-internal mount (memfd)
	FactPathUTF8                 // a target or actor path is not valid UTF-8
	FactActorDeleted             // the actor's executable is deleted
)

// SharedFactHealth is the per-pass fact witness of the window from node
// start to the latest health check. Unknown counts are policy outcomes, not
// infrastructure faults: each pass was evaluated, a rule consulting an
// unknown fact was decided UNKNOWN (Strict deny, Audit unknown).
type SharedFactHealth struct {
	Passes, TargetMissing, TargetPath, TargetTooLong, TargetOutsideRoot,
	ActorMissing, ActorPath, ActorOutsideRoot, FSUnknown, StdinUnknown,
	AncestorUnknown, AncestorBoundary, AncestorTruncated,
	RootMismatch, TargetMemfd, PathUTF8, ActorDeleted uint64
}

type sharedFactStatsRead func() ([FactStats]uint64, error)

// sharedFactStats is the witness map's admitted shape.
var sharedFactStats = operators.NativeMapResource{
	Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8, MaxEntries: FactStats, Flags: unix.BPF_F_RDONLY,
}

func hasSharedFactStats(admitted *operators.NativeResources) bool {
	if admitted == nil {
		return false
	}
	_, ok := admitted.Maps[FactStatsMap]
	return ok
}

// borrowSharedFactStats reads the witness through the map handle the eBPF
// operator published (operators.MapPrefix); the operator owns it.
func borrowSharedFactStats(gc operators.GadgetContext) (sharedFactStatsRead, error) {
	value, _ := gc.GetVar(operators.MapPrefix + FactStatsMap)
	m, _ := value.(*ebpf.Map)
	if m == nil {
		return nil, fmt.Errorf("shared candidate map %s was not published", FactStatsMap)
	}
	return func() ([FactStats]uint64, error) {
		var out [FactStats]uint64
		for i := range out {
			raw, err := m.LookupBytes(uint32(i))
			if err != nil || len(raw) != 8 {
				return out, fmt.Errorf("%s[%d]: %d bytes: %w", FactStatsMap, i, len(raw), err)
			}
			out[i] = binary.LittleEndian.Uint64(raw)
		}
		return out, nil
	}, nil
}

// sharedLiveFactStats is node health over the fact witness. The unknown
// counts are reported only, never Degraded and never a fail-closed class:
// they are policy-UNKNOWN decisions about facts the kernel cannot see (a
// path longer than 255 bytes, an interpreter outside the task's root), which
// any workload can produce at will, so gating node health on them would let
// one tenant degrade the node; the fail-closed rate counts execs refused
// WITHOUT an evaluation. An unreadable or backwards witness is a sticky
// fault (the facts can no longer be accounted).
type sharedLiveFactStats struct {
	read     sharedFactStatsRead
	baseline [FactStats]uint64
	previous [FactStats]uint64 // the latest reading: counters only grow
	mu       sync.Mutex
	last     SharedFactHealth
	fault    error // sticky
	closed   bool
}

func (f *sharedLiveFactStats) check() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fault != nil || f.closed {
		return f.fault
	}
	now, err := f.read()
	if err != nil {
		f.fault = fmt.Errorf("shared candidate fact witness unknown, node degraded: %w", err)
		return f.fault
	}
	var d [FactStats]uint64
	for i := range now {
		if now[i] < f.previous[i] {
			f.fault = fmt.Errorf("shared candidate fact witness unknown, node degraded: counter %d moved backwards (%d -> %d)", i, f.previous[i], now[i])
			return f.fault
		}
		d[i] = now[i] - f.baseline[i]
	}
	f.previous = now
	f.last = SharedFactHealth{
		Passes: d[FactPasses], TargetMissing: d[FactTargetMissing], TargetPath: d[FactTargetPath],
		TargetTooLong: d[FactTargetTooLong], TargetOutsideRoot: d[FactTargetOutsideRoot],
		ActorMissing: d[FactActorMissing], ActorPath: d[FactActorPath], ActorOutsideRoot: d[FactActorOutsideRoot],
		FSUnknown: d[FactFSUnknown], StdinUnknown: d[FactStdinUnknown], AncestorUnknown: d[FactAncestorUnknown],
		AncestorBoundary: d[FactAncestorBoundary], AncestorTruncated: d[FactAncestorTruncated],
		RootMismatch: d[FactRootMismatch], TargetMemfd: d[FactTargetMemfd], PathUTF8: d[FactPathUTF8], ActorDeleted: d[FactActorDeleted],
	}
	return nil
}

func (f *sharedLiveFactStats) report() (SharedFactHealth, error) {
	err := f.check()
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.last, err
}

func (f *sharedLiveFactStats) close() {
	_ = f.check()
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
}

// newLiveFactStats opens the fact window of an admitted object (nil, nil
// for an object without the per-pass facts).
func (n *NodeEnforcer) newLiveFactStats(gc operators.GadgetContext, admitted *operators.NativeResources) (*sharedLiveFactStats, error) {
	if !hasSharedFactStats(admitted) {
		return nil, nil
	}
	if m := admitted.Maps[FactStatsMap]; m != sharedFactStats {
		return nil, fmt.Errorf("shared candidate fact witness %s malformed: %+v", FactStatsMap, m)
	}
	borrow := n.host.factStats
	if borrow == nil {
		borrow = borrowSharedFactStats
	}
	read, err := borrow(gc)
	if err != nil || read == nil {
		return nil, fmt.Errorf("shared candidate fact witness unavailable: %w", err)
	}
	baseline, err := read()
	if err != nil {
		return nil, fmt.Errorf("shared candidate fact witness unreadable: %w", err)
	}
	return &sharedLiveFactStats{read: read, baseline: baseline, previous: baseline}, nil
}

// FactHealth reports the per-pass fact witness of the live node since its
// start (G020): the passes collected and, per reason, the facts that were
// UNKNOWN to the evaluator. The counts never degrade the node; an
// unreadable witness is a sticky fault, also carried by Ready and Inspect.
// ErrSharedNativeUnavailable without a live object carrying the facts.
func (n *NodeEnforcer) FactHealth() (SharedFactHealth, error) {
	n.mu.Lock()
	var facts *sharedLiveFactStats
	if n.host != nil && n.host.live != nil {
		facts = n.host.live.facts
	}
	n.mu.Unlock()
	if facts == nil {
		return SharedFactHealth{}, ErrSharedNativeUnavailable
	}
	return facts.report()
}
