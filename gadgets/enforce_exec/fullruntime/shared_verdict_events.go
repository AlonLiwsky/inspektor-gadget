// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Verdict events (G020): one legacy-compatible verdict event per evaluated
// pass, emitted by the product object's global emitter. Its counters map has
// the shape of the persistent owner's verdict counters (owner.go
// validateCounterMap): a PERCPU_ARRAY of three u64 cells.
const (
	SharedVerdictCountersMap = "opaque_real_verdict_counters"
	// SharedVerdictRingMap is the node-wide ring buffer of the "verdict"
	// datasource (GADGET_TRACER), sized by SharedProfile.VerdictRing.
	SharedVerdictRingMap = "opaque_real_verdict_events"
	// SharedVerdictDataSource is the datasource of the verdict events.
	SharedVerdictDataSource = "verdict"

	// Cells of SharedVerdictCountersMap, KernelEventCounters' fields.
	SharedVerdictSubmitted         = 0 // events submitted to the ring buffer
	SharedVerdictLost              = 1 // failed ring-buffer reservations
	SharedVerdictObservationErrors = 2 // passes whose event could not be built
	SharedVerdictCounters          = 3

	// SharedEventABIAnnotation is the image annotation naming the verdict
	// event ABI the object emits; SharedEventABIVersion is the one this
	// package decodes.
	SharedEventABIAnnotation = "enforce-exec-shared-event-abi"
	SharedEventABIVersion    = "1"
)

// Bits of a verdict event's facts_unknown field (full/shared_verdict_event.h
// SE_VERDICT_UNKNOWN_*): the facts of the evaluated pass that were UNKNOWN.
// A fault event carries every bit.
const (
	SharedVerdictUnknownTargetPath uint32 = 1 << iota
	SharedVerdictUnknownUID
	SharedVerdictUnknownAncestors
	SharedVerdictUnknownFS
	SharedVerdictUnknownArgv
	SharedVerdictUnknownStdin
	SharedVerdictUnknownActorPath
	SharedVerdictUnknownImage
	SharedVerdictUnknownAll uint32 = 1<<iota - 1
)

// SharedVerdictPassUnknown is the pass field of a fault event.
const SharedVerdictPassUnknown = ^uint32(0)

// sharedVerdictEmitterLanded is the single switch of the verdict event ABI:
// false while no product object carries the emitter, so an object without
// SharedVerdictCountersMap or SharedEventABIAnnotation is admitted (one that
// carries either must match); true once the BPF emitter lands, so both are
// required. Admission (validateSharedVerdictCounters, admitSharedEventABI)
// and BuildSharedCandidateImage read only this. Landed (G020): every
// product-publisher object carries se_verdict_emit, its ring
// (SharedVerdictRingMap, pinned by sharedProductMapGeometry) and counters.
// A constant: tests exercise the pre-landing rules through the *Landed
// variants, never by flipping it.
const sharedVerdictEmitterLanded = true

// sharedVerdictCountersShape is the admitted shape of the counters map.
var sharedVerdictCountersShape = operators.NativeMapResource{
	Type: uint32(ebpf.PerCPUArray), KeySize: 4, ValueSize: 8, MaxEntries: SharedVerdictCounters,
}

// ErrSharedVerdictCountersAbsent is KernelEventCounters' error for a live
// object without SharedVerdictCountersMap (no verdict emitter).
var ErrSharedVerdictCountersAbsent = errors.New("verdict counters map " + SharedVerdictCountersMap + " not present in this object")

// ErrSharedVerdictEventLoss is the Degraded label of verdict event loss (G020
// user decision D2): Lost grew within the last FailClosedRateDegradedWindow,
// or the counters could not be read. Ready joins it; it is never NotReady,
// never a teardown fault and never counted by the fail-closed rate: a lost
// event loses an observation, never a verdict (the exec was evaluated).
var ErrSharedVerdictEventLoss = errors.New("verdict event loss (Degraded)")

// validateSharedVerdictCounters pins the counters map shape when present and
// requires it once the emitter landed.
func validateSharedVerdictCounters(resources *operators.NativeResources) error {
	return validateSharedVerdictCountersLanded(resources, sharedVerdictEmitterLanded)
}

func validateSharedVerdictCountersLanded(resources *operators.NativeResources, landed bool) error {
	var m operators.NativeMapResource
	ok := false
	if resources != nil {
		m, ok = resources.Maps[SharedVerdictCountersMap]
	}
	switch {
	case !ok && landed:
		return fmt.Errorf("shared object lacks the verdict counters map %s", SharedVerdictCountersMap)
	case ok && (m != sharedVerdictCountersShape || m.InnerMap != nil):
		return fmt.Errorf("shared verdict counters map %s malformed: %+v", SharedVerdictCountersMap, m)
	}
	return nil
}

// admitSharedEventABI refuses an image whose event ABI annotation names
// another version, and, once the emitter landed, one without it.
func admitSharedEventABI(metadata *viper.Viper) error {
	return admitSharedEventABILanded(metadata, sharedVerdictEmitterLanded)
}

func admitSharedEventABILanded(metadata *viper.Viper, landed bool) error {
	key := "annotations." + SharedEventABIAnnotation
	switch {
	case !metadata.IsSet(key):
		if landed {
			return fmt.Errorf("shared image lacks the %s annotation (want %q)", SharedEventABIAnnotation, SharedEventABIVersion)
		}
	case metadata.GetString(key) != SharedEventABIVersion:
		return fmt.Errorf("shared image %s %q, this node decodes %q", SharedEventABIAnnotation, metadata.GetString(key), SharedEventABIVersion)
	}
	return nil
}

type sharedVerdictCountersRead func() (KernelEventCounters, error)

// borrowSharedVerdictCounters clones the counters map the eBPF operator
// published (operators.MapPrefix): the clone outlives the manager's teardown,
// so the final reading after detach includes reservations racing it. release
// closes the clone.
func borrowSharedVerdictCounters(gc operators.GadgetContext) (sharedVerdictCountersRead, func() error, error) {
	value, _ := gc.GetVar(operators.MapPrefix + SharedVerdictCountersMap)
	m, _ := value.(*ebpf.Map)
	if m == nil {
		return nil, nil, fmt.Errorf("shared candidate map %s was not published", SharedVerdictCountersMap)
	}
	info, err := m.Info()
	if err == nil {
		err = validateCounterMap(info)
	}
	if err != nil {
		return nil, nil, err
	}
	clone, err := m.Clone()
	if err != nil {
		return nil, nil, err
	}
	read := func() (KernelEventCounters, error) {
		var result KernelEventCounters
		for key, field := range []*uint64{&result.Submitted, &result.Lost, &result.ObservationErrors} {
			var values []uint64
			if err := clone.Lookup(uint32(key), &values); err != nil {
				return KernelEventCounters{}, fmt.Errorf("read shared verdict counter %d: %w", key, err)
			}
			if len(values) == 0 {
				return KernelEventCounters{}, fmt.Errorf("empty shared verdict per-CPU counter %d", key)
			}
			for _, v := range values {
				*field += v
			}
		}
		return result, nil
	}
	return read, clone.Close, nil
}

// sharedLiveVerdict is the verdict counters of the live node, with Owner's
// KernelEventCounters semantics: live reads are per-CPU sums (not atomic
// across CPUs or cells), an error keeps the last successful sample, and the
// snapshot is Final only once taken after verified detach.
type sharedLiveVerdict struct {
	read    sharedVerdictCountersRead
	release func() error
	clock   func() time.Time // nil: time.Now
	mu      sync.Mutex
	last    KernelEventCounters
	err     error // the final reading's error, once final
	final   bool
	// lostAt is when Lost last grew (zero: never).
	lostAt time.Time
}

func (v *sharedLiveVerdict) now() time.Time {
	if v.clock != nil {
		return v.clock()
	}
	return time.Now()
}

// sampleLocked reads the counters and records Lost growth; v.mu is held.
func (v *sharedLiveVerdict) sampleLocked() error {
	c, err := v.read()
	if err != nil {
		return err
	}
	if c.Submitted < v.last.Submitted || c.Lost < v.last.Lost || c.ObservationErrors < v.last.ObservationErrors {
		return fmt.Errorf("shared verdict counters moved backwards (%+v -> %+v)", v.last, c)
	}
	if c.Lost > v.last.Lost {
		v.lostAt = v.now()
	}
	v.last = c
	return nil
}

func (v *sharedLiveVerdict) counters() (KernelEventCounters, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.final {
		return v.last, v.err
	}
	err := v.sampleLocked()
	return v.last, err
}

// degraded is the D2 health label: ErrSharedVerdictEventLoss while Lost grew
// within the last FailClosedRateDegradedWindow or the counters are unreadable.
func (v *sharedLiveVerdict) degraded() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.final {
		return nil // detached: no longer node health
	}
	if err := v.sampleLocked(); err != nil {
		return fmt.Errorf("shared verdict counters unknown (%w): %w", err, ErrSharedVerdictEventLoss)
	}
	if !v.lostAt.IsZero() && v.now().Sub(v.lostAt) < FailClosedRateDegradedWindow {
		return fmt.Errorf("shared verdict events lost=%d (submitted %d) within %s: %w",
			v.last.Lost, v.last.Submitted, FailClosedRateDegradedWindow, ErrSharedVerdictEventLoss)
	}
	return nil
}

// finalize takes the Final snapshot and releases the clone. Called only after
// ReleaseAfterDetach verified the host manager's detach.
func (v *sharedLiveVerdict) finalize() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.final {
		return
	}
	v.err = v.sampleLocked()
	if v.release != nil {
		v.err = errors.Join(v.err, v.release())
	}
	v.final = true
	v.last.Final = true
}

// close releases the clone of a candidate that was never installed.
func (v *sharedLiveVerdict) close() {
	if v != nil && v.release != nil {
		_ = v.release()
	}
}

// newLiveVerdict opens the verdict counters of an admitted object (nil, nil
// for an object without them).
func (n *NodeEnforcer) newLiveVerdict(gc operators.GadgetContext, admitted *operators.NativeResources) (*sharedLiveVerdict, error) {
	if admitted == nil {
		return nil, nil
	}
	if _, ok := admitted.Maps[SharedVerdictCountersMap]; !ok {
		return nil, nil
	}
	if err := validateSharedVerdictCounters(admitted); err != nil {
		return nil, err
	}
	borrow := n.host.verdictCounters
	if borrow == nil {
		borrow = borrowSharedVerdictCounters
	}
	read, release, err := borrow(gc)
	if err != nil || read == nil {
		return nil, errors.Join(err, fmt.Errorf("shared candidate verdict counters unavailable"))
	}
	v := &sharedLiveVerdict{read: read, release: release, clock: n.host.verdictClock}
	if err := v.sampleLocked(); err != nil {
		v.close()
		return nil, fmt.Errorf("shared candidate verdict counters unreadable: %w", err)
	}
	return v, nil
}

// liveVerdict is the live node's verdict counters (nil without).
func (n *NodeEnforcer) liveVerdict() (*sharedLiveVerdict, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.host == nil || n.host.live == nil {
		return nil, false
	}
	return n.host.live.verdict, true
}

// KernelEventCounters reports the node's verdict event counters (G020): the
// events submitted, lost (failed ring-buffer reservations) and observation
// errors, as per-CPU sums since the collection loaded. Live reads are not
// atomic across CPUs or cells; an error returns the last successful sample.
// After StopNode's verified detach (ReleaseAfterDetach) the snapshot is
// Final: taken once over a clone of the map that survived the manager's
// teardown, then returned (with its error) unchanged. It is read-only and
// never affects health or publication. ErrSharedNativeUnavailable without a
// live node; ErrSharedVerdictCountersAbsent when the object has no verdict
// emitter.
func (n *NodeEnforcer) KernelEventCounters() (KernelEventCounters, error) {
	v, live := n.liveVerdict()
	switch {
	case !live:
		return KernelEventCounters{}, ErrSharedNativeUnavailable
	case v == nil:
		return KernelEventCounters{}, ErrSharedVerdictCountersAbsent
	}
	return v.counters()
}

// verdictLossDegraded is the node-health form of the verdict counters
// (Degraded only, D2); nil without them.
func (n *NodeEnforcer) verdictLossDegraded() error {
	v, _ := n.liveVerdict()
	if v == nil {
		return nil
	}
	return v.degraded()
}

// finalizeVerdictCounters takes the Final snapshot after verified detach.
func (n *NodeEnforcer) finalizeVerdictCounters() {
	if v, _ := n.liveVerdict(); v != nil {
		v.finalize()
	}
}
