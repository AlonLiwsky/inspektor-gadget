// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"encoding/binary"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Exec-capsule store witness (se_exec_capsule_stats: one ARRAY entry of
// SharedCapsuleCounters u64, SE_CAP_STAT_* in full/shared_exec_capsule.h).
const (
	SharedCapsuleCounters = 15
	// SharedCapsuleReleaseFault (SE_CAP_STAT_RELEASE_FAULT) counts a capsule
	// whose original-route pin could not be released: that route stays
	// pinned (fail-closed) and the node is unhealthy.
	SharedCapsuleReleaseFault = 12
	// SharedCapsuleFault (SE_CAP_STAT_FAULT) counts a degraded admission
	// (Strict denied, Audit allowed and counted ADMISSION by the fail-closed
	// witness). Reported, never a node fault on its own.
	SharedCapsuleFault = 13
	// SharedCapsuleDeathRetired (SE_CAP_STAT_DEATH_RETIRED) counts a capsule
	// whose terminal was missed and that task_free retired. Any growth
	// within the last FailClosedRateDegradedWindow is Degraded (not sticky;
	// see sharedLiveCapsule).
	SharedCapsuleDeathRetired = 14
)

const sharedCapsuleStatsMap = "se_exec_capsule_stats"

// SharedCapsuleHealth is the exec-capsule witness of the window from node
// start to the latest health check.
type SharedCapsuleHealth struct {
	ReleaseFaults, Faults, DeathRetired uint64
}

type sharedCapsuleStatsRead func() ([SharedCapsuleCounters]uint64, error)

// sharedCapsuleStatsShape checks the admitted witness shape.
func sharedCapsuleStatsShape(resources *operators.NativeResources) error {
	m, ok := resources.Maps[sharedCapsuleStatsMap]
	if !ok || m.Type != uint32(ebpf.Array) || m.KeySize != 4 || m.ValueSize != 8*SharedCapsuleCounters || m.MaxEntries != 1 {
		return fmt.Errorf("shared candidate exec-capsule witness %s missing or malformed: %+v", sharedCapsuleStatsMap, m)
	}
	return nil
}

// borrowSharedCapsuleStats reads se_exec_capsule_stats through the map handle
// the eBPF operator published (operators.MapPrefix); the operator owns it.
func borrowSharedCapsuleStats(gc operators.GadgetContext) (sharedCapsuleStatsRead, error) {
	value, _ := gc.GetVar(operators.MapPrefix + sharedCapsuleStatsMap)
	m, _ := value.(*ebpf.Map)
	if m == nil {
		return nil, fmt.Errorf("shared candidate map %s was not published", sharedCapsuleStatsMap)
	}
	return func() ([SharedCapsuleCounters]uint64, error) {
		var out [SharedCapsuleCounters]uint64
		raw, err := m.LookupBytes(uint32(0))
		if err != nil || len(raw) != 8*SharedCapsuleCounters {
			return out, fmt.Errorf("%s[0]: %d bytes: %w", sharedCapsuleStatsMap, len(raw), err)
		}
		for i := range out {
			out[i] = binary.LittleEndian.Uint64(raw[8*i:])
		}
		return out, nil
	}, nil
}

// sharedLiveCapsule is node health over the exec-capsule witness, like
// sharedLiveExitCredit: a release fault (Degraded) or an unreadable or
// backwards witness (Unknown) is a sticky fault until node teardown.
//
// A death retire (review L2) is Degraded while one was observed within the
// last FailClosedRateDegradedWindow, the fail-closed witness's Degraded rule
// (threshold 0 over 60 s), and clears after a quiet window. It is never
// benign: the attach order (death retire, terminal, entry, begin) and the
// final reading before detach (Stop) leave no attach/detach boundary inside
// the window, and every exec returns through bprm_execve's fexit, so a
// missed terminal means the terminal program itself did not run (a
// trampoline recursion miss). It is not sticky: the retire released the
// capsule's original-route pin (a release that failed is a sticky release
// fault) and the exec's admission was evaluated, so no route stays pinned
// and no exec went unevaluated.
type sharedLiveCapsule struct {
	read     sharedCapsuleStatsRead
	baseline [SharedCapsuleCounters]uint64
	clock    func() time.Time // nil: time.Now
	mu       sync.Mutex
	last     SharedCapsuleHealth
	fault    error // sticky, the first unhealthy window
	closed   bool  // the collection is closing: never read again
	// retiredAt is when DeathRetired last grew (zero: never).
	retiredAt time.Time
}

func (c *sharedLiveCapsule) now() time.Time {
	if c.clock != nil {
		return c.clock()
	}
	return time.Now()
}

// check reads the witness (unless closed or faulted) and returns the sticky
// fault, or the death-retire Degraded window.
func (c *sharedLiveCapsule) check() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fault != nil || c.closed {
		return c.fault
	}
	now, err := c.read()
	if err != nil {
		c.fault = fmt.Errorf("shared candidate exec-capsule witness unknown, node degraded: %w", err)
		return c.fault
	}
	for i := range now {
		if now[i] < c.baseline[i] {
			c.fault = fmt.Errorf("shared candidate exec-capsule witness unknown, node degraded: counter %d moved backwards (%d -> %d)", i, c.baseline[i], now[i])
			return c.fault
		}
	}
	previous := c.last.DeathRetired
	c.last = SharedCapsuleHealth{
		ReleaseFaults: now[SharedCapsuleReleaseFault] - c.baseline[SharedCapsuleReleaseFault],
		Faults:        now[SharedCapsuleFault] - c.baseline[SharedCapsuleFault],
		DeathRetired:  now[SharedCapsuleDeathRetired] - c.baseline[SharedCapsuleDeathRetired],
	}
	if c.last.ReleaseFaults > 0 {
		c.fault = fmt.Errorf("shared candidate exec-capsule release-fault=%d (fault=%d death-retired=%d), node degraded",
			c.last.ReleaseFaults, c.last.Faults, c.last.DeathRetired)
		return c.fault
	}
	at := c.now()
	if c.last.DeathRetired > previous {
		c.retiredAt = at
	}
	if !c.retiredAt.IsZero() && at.Sub(c.retiredAt) < FailClosedRateDegradedWindow {
		return fmt.Errorf("shared candidate exec-capsule death-retired=%d (a missed exec terminal) within %s, node degraded",
			c.last.DeathRetired, FailClosedRateDegradedWindow)
	}
	return nil
}

// report refreshes the window and returns its counters with the sticky fault.
func (c *sharedLiveCapsule) report() (SharedCapsuleHealth, error) {
	err := c.check()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last, err
}

// close takes the final reading before the collection closes.
func (c *sharedLiveCapsule) close() {
	_ = c.check() // sticky in c.fault, reported by liveHealthFault
	c.mu.Lock()
	c.closed = true
	c.mu.Unlock()
}

// CapsuleHealth reports the exec-capsule witness of the live node since its
// start: release faults (any is a sticky Degraded fault, also carried by
// Ready and Inspect), degraded admissions and death retires (Degraded, also
// carried by Ready and Inspect, while one is within the last
// FailClosedRateDegradedWindow).
func (n *NodeEnforcer) CapsuleHealth() (SharedCapsuleHealth, error) {
	n.mu.Lock()
	var capsule *sharedLiveCapsule
	if n.host != nil && n.host.live != nil {
		capsule = n.host.live.capsule
	}
	n.mu.Unlock()
	if capsule == nil {
		return SharedCapsuleHealth{}, ErrSharedNativeUnavailable
	}
	return capsule.report()
}
