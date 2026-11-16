// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Birth park (G019 gap 1, product objects only): the fork source hands its
// route claim to the constructor target through per-task storage
// (se_birth_parks, struct se_birth_park) instead of releasing it and letting
// the target re-admit the cgroup, so a revision can never commit between the
// two task_alloc programs. BirthParkStatsMap is its witness (one u64 per
// cell, RDONLY), cell 7 also counting the cross-generation first-exec
// qualifications (G019 gap 2).
const (
	BirthParkStatsMap = "opaque_real_birth_park"
	BirthParkStats    = 8

	sharedBirthParkMap   = "se_birth_parks"
	sharedBirthParkBytes = 80 // struct se_birth_park
)

// Cells of BirthParkStatsMap (REAL_OWNER_PARK_* in the verdict source).
const (
	BirthParkParked          = iota // the source parked its claim
	BirthParkTaken                  // the target took it
	BirthParkAbandoned              // released after a failure before construction
	BirthParkStale                  // a park its target never took, released late
	BirthParkPutFailed              // no storage: the birth took the missing-target path
	BirthParkLatched                // a park's release failed, or the target's parked claim no longer validated: its route is latched
	BirthParkTakeFailed             // the target found no valid park (CONSTRUCT)
	BirthParkCrossGeneration        // a cross-generation first-exec qualification
)

// SharedBirthParkHealth is the birth-park witness of the window from node
// start to the latest health check.
type SharedBirthParkHealth struct {
	Parked, Taken, Abandoned, Stale, PutFailed, Latched, TakeFailed, CrossGeneration uint64
}

type sharedBirthParkStatsRead func() ([BirthParkStats]uint64, error)

// sharedBirthParkStats is the witness map's admitted shape.
var sharedBirthParkStats = operators.NativeMapResource{
	Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8, MaxEntries: BirthParkStats, Flags: unix.BPF_F_RDONLY,
}

// hasSharedBirthPark reports whether the admitted object carries the birth
// park (product objects; validateSharedProductControl requires both maps).
func hasSharedBirthPark(admitted *operators.NativeResources) bool {
	if admitted == nil {
		return false
	}
	_, ok := admitted.Maps[BirthParkStatsMap]
	return ok
}

// borrowSharedBirthParkStats reads the witness through the map handle the
// eBPF operator published (operators.MapPrefix); the operator owns it.
func borrowSharedBirthParkStats(gc operators.GadgetContext) (sharedBirthParkStatsRead, error) {
	value, _ := gc.GetVar(operators.MapPrefix + BirthParkStatsMap)
	m, _ := value.(*ebpf.Map)
	if m == nil {
		return nil, fmt.Errorf("shared candidate map %s was not published", BirthParkStatsMap)
	}
	return func() ([BirthParkStats]uint64, error) {
		var out [BirthParkStats]uint64
		for i := range out {
			raw, err := m.LookupBytes(uint32(i))
			if err != nil || len(raw) != 8 {
				return out, fmt.Errorf("%s[%d]: %d bytes: %w", BirthParkStatsMap, i, len(raw), err)
			}
			out[i] = binary.LittleEndian.Uint64(raw)
		}
		return out, nil
	}, nil
}

// sharedLiveBirthPark is node health over the birth-park witness:
//   - a latched park (its claim could not be released, or the target found
//     its own parked claim no longer valid, so its route is latched until
//     teardown) is a sticky Degraded fault, like an unreadable or backwards
//     witness (Unknown);
//   - a stale park (released late: its target neither took nor abandoned
//     it, so the route's early claim held its record, blocking that
//     record's withdrawal and reuse meanwhile) or a failed take (the child
//     was not constructed, CONSTRUCT) is Degraded while one was observed
//     within the last FailClosedRateDegradedWindow (the fail-closed
//     witness's Degraded rule), then clears.
//
// Parked, taken, abandoned and cross-generation counts are reported only;
// a failed put is already a counted MISSING_TARGET refusal.
type sharedLiveBirthPark struct {
	read     sharedBirthParkStatsRead
	baseline [BirthParkStats]uint64
	clock    func() time.Time // nil: time.Now
	mu       sync.Mutex
	last     SharedBirthParkHealth
	fault    error // sticky
	closed   bool
	// degradedAt is when Stale or TakeFailed last grew (zero: never).
	degradedAt time.Time
}

func (b *sharedLiveBirthPark) now() time.Time {
	if b.clock != nil {
		return b.clock()
	}
	return time.Now()
}

// check reads the witness (unless closed or faulted) and returns the sticky
// fault or the Degraded window.
func (b *sharedLiveBirthPark) check() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.fault != nil || b.closed {
		return b.fault
	}
	now, err := b.read()
	if err != nil {
		b.fault = fmt.Errorf("shared candidate birth-park witness unknown, node degraded: %w", err)
		return b.fault
	}
	var d [BirthParkStats]uint64
	for i := range now {
		if now[i] < b.baseline[i] {
			b.fault = fmt.Errorf("shared candidate birth-park witness unknown, node degraded: counter %d moved backwards (%d -> %d)", i, b.baseline[i], now[i])
			return b.fault
		}
		d[i] = now[i] - b.baseline[i]
	}
	previous := b.last
	b.last = SharedBirthParkHealth{
		Parked: d[BirthParkParked], Taken: d[BirthParkTaken], Abandoned: d[BirthParkAbandoned], Stale: d[BirthParkStale],
		PutFailed: d[BirthParkPutFailed], Latched: d[BirthParkLatched], TakeFailed: d[BirthParkTakeFailed],
		CrossGeneration: d[BirthParkCrossGeneration],
	}
	if b.last.Latched > 0 {
		b.fault = fmt.Errorf("shared candidate birth-park latched=%d (a parked route claim could not be released; its route is latched until teardown), node degraded", b.last.Latched)
		return b.fault
	}
	at := b.now()
	if b.last.Stale > previous.Stale || b.last.TakeFailed > previous.TakeFailed {
		b.degradedAt = at
	}
	if !b.degradedAt.IsZero() && at.Sub(b.degradedAt) < FailClosedRateDegradedWindow {
		return fmt.Errorf("shared candidate birth-park stale=%d take-failed=%d within %s, node degraded",
			b.last.Stale, b.last.TakeFailed, FailClosedRateDegradedWindow)
	}
	return nil
}

// report refreshes the window and returns its counters with the fault.
func (b *sharedLiveBirthPark) report() (SharedBirthParkHealth, error) {
	err := b.check()
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.last, err
}

// close takes the final reading before the collection closes.
func (b *sharedLiveBirthPark) close() {
	_ = b.check()
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
}

// newLiveBirthPark opens the birth-park window of an admitted product
// object (nil, nil for an object without the birth park).
func (n *NodeEnforcer) newLiveBirthPark(gc operators.GadgetContext, admitted *operators.NativeResources) (*sharedLiveBirthPark, error) {
	if !hasSharedBirthPark(admitted) {
		return nil, nil
	}
	if m := admitted.Maps[BirthParkStatsMap]; m != sharedBirthParkStats {
		return nil, fmt.Errorf("shared candidate birth-park witness %s malformed: %+v", BirthParkStatsMap, m)
	}
	borrow := n.host.birthParkStats
	if borrow == nil {
		borrow = borrowSharedBirthParkStats
	}
	read, err := borrow(gc)
	if err != nil || read == nil {
		return nil, fmt.Errorf("shared candidate birth-park witness unavailable: %w", err)
	}
	baseline, err := read()
	if err != nil {
		return nil, fmt.Errorf("shared candidate birth-park witness unreadable: %w", err)
	}
	return &sharedLiveBirthPark{read: read, baseline: baseline}, nil
}

// BirthParkHealth reports the birth-park witness of the live node since its
// start (G019 gaps 1 and 2): a latched park is a sticky Degraded fault; a
// stale park or a failed take is Degraded within the last
// FailClosedRateDegradedWindow; both are also carried by Ready and Inspect.
// ErrSharedNativeUnavailable without a live product object.
func (n *NodeEnforcer) BirthParkHealth() (SharedBirthParkHealth, error) {
	n.mu.Lock()
	var park *sharedLiveBirthPark
	if n.host != nil && n.host.live != nil {
		park = n.host.live.birthPark
	}
	n.mu.Unlock()
	if park == nil {
		return SharedBirthParkHealth{}, ErrSharedNativeUnavailable
	}
	return park.report()
}
