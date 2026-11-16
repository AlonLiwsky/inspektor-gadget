// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// G019 gap 3 (per-record route holders): a revision commits while the
// previous record still has holders (early claims, source pins, readers);
// that record becomes RETIRING and keeps them, and is dropped
// (opaque_real_route_drop_retired) once they are gone. A revision whose
// candidate record is still that RETIRING one waits for it: the commander
// drops it as soon as its holders are gone, with a bounded backoff.

// RevisionDrainTimeout is the Degraded report of a revision that waited
// longer than the drain timeout for the slot's RETIRING record to lose its
// holders (counted early claims, source pins and readers). The revision is
// refused retryably (ErrSharedRevisionDraining), its staged object
// discarded; the binding keeps its last-good policy. Cleared by the slot's
// next committed revision. Not NotReady: the route keeps enforcing.
const RevisionDrainTimeout = "RevisionDrainTimeout"

// RevisionObjectStarved is the Degraded report of a slot whose revisions
// found no free policy object (a retryable stage refusal: every spare
// object still held by a RETIRING record) for longer than the drain
// timeout. Cleared by the slot's next staged revision.
const RevisionObjectStarved = "RevisionObjectStarved"

// ErrSharedRevisionDraining is the retryable refusal of a revision whose
// slot's RETIRING record kept holders past the drain timeout.
var ErrSharedRevisionDraining = fmt.Errorf("revision: %w: the retiring record still has holders", ErrSharedRetryableRefusal)

// Drain timeout bounds (G019 gap 3): the default, and the largest
// configurable value.
const (
	DefaultRevisionDrainTimeout = 10 * time.Second
	MaxRevisionDrainTimeout     = 60 * time.Second
	sharedDrainBackoffMin       = time.Millisecond
	sharedDrainBackoffMax       = 250 * time.Millisecond
)

// SharedRevisionStatus is a slot's Degraded revision report.
type SharedRevisionStatus struct {
	Reason string
	Slot   uint32
	// Generation is the RETIRING record's generation (RevisionDrainTimeout).
	Generation uint64
	// EarlyClaims, SourcePins and Readers are its holders at the report.
	EarlyClaims, SourcePins, Readers uint32
}

// se_bindings value layout (struct se_shared_binding): the two records of
// struct se_binding_snapshots start at 64, each struct se_snapshot is 784
// bytes with claims (its readers) at 40. Pinned to the headers' BTF by
// TestSharedRevisionDrainLayoutMatchesBTF.
const (
	sharedBindingRecordsOffset = 64
	sharedSnapshotBytes        = 784
	sharedSnapshotClaimsOffset = 40
)

// drainTimeout is the configured drain timeout, clamped.
func (c *productCommander) drainTimeout() time.Duration {
	switch d := c.revisionDrainTimeout; {
	case d <= 0:
		return DefaultRevisionDrainTimeout
	case d > MaxRevisionDrainTimeout:
		return MaxRevisionDrainTimeout
	default:
		return d
	}
}

func (c *productCommander) clock() time.Time {
	if c.now != nil {
		return c.now()
	}
	return time.Now()
}

func (c *productCommander) wait(ctx context.Context, d time.Duration) error {
	if c.sleep != nil {
		return c.sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// retiring reads the slot's RETIRING record (ok false: none) and its
// readers (0 when the bindings map is not available).
func (c *productCommander) retiring(slot uint32) (sharedProductRoute, int, uint32, bool, error) {
	route, err := c.productRoute(slot)
	if err != nil {
		return sharedProductRoute{}, 0, 0, false, err
	}
	for i, rec := range route.Rec {
		if rec.Phase != sharedSnapshotRetiring || rec.Generation == 0 {
			continue
		}
		var readers uint32
		if c.bindings != nil {
			if raw, err := c.bindings.LookupBytes(slot); err == nil {
				if o := sharedBindingRecordsOffset + i*sharedSnapshotBytes + sharedSnapshotClaimsOffset; len(raw) >= o+4 {
					readers = binary.LittleEndian.Uint32(raw[o:])
				}
			}
		}
		return route, i, readers, true, nil
	}
	return route, 0, 0, false, nil
}

// dropRetired issues opaque_real_route_drop_retired for the slot's RETIRING
// record, if any: dropped (or nothing to drop), holders remain (false), or
// an error (the command's invariant, authentication or a lost reply).
func (c *productCommander) dropRetired(ctx context.Context, slot uint32) (bool, error) {
	route, i, _, ok, err := c.retiring(slot)
	if err != nil || !ok {
		return err == nil, err
	}
	code, err := c.control.run(ctx, "opaque_real_route_drop_retired", sharedProductDropBody(slot, route.State.Scope, route.Rec[i].Generation))
	switch {
	case err != nil:
		return false, fmt.Errorf("drop_retired slot %d: %w", slot, err)
	case code == sharedProductOK:
		return true, nil
	case code == sharedProductRetry:
		return false, nil
	}
	return false, sharedProductCodeError(fmt.Sprintf("drop_retired slot %d generation %d", slot, route.Rec[i].Generation), code, nil)
}

// drainForRevision waits, until deadline, for the slot's RETIRING record to
// be dropped: true once the revision may be retried. On timeout it reports
// RevisionDrainTimeout with the holders it last saw and returns false.
func (c *productCommander) drainForRevision(ctx context.Context, slot uint32, deadline time.Time) (bool, error) {
	backoff := sharedDrainBackoffMin
	for {
		dropped, err := c.dropRetired(ctx, slot)
		if err != nil {
			return false, err
		}
		if dropped {
			return true, nil
		}
		if !c.clock().Before(deadline) {
			route, i, readers, ok, _ := c.retiring(slot)
			st := SharedRevisionStatus{Reason: RevisionDrainTimeout, Slot: slot, Readers: readers}
			if ok {
				st.Generation = route.Rec[i].Generation
				st.EarlyClaims, st.SourcePins = route.Rec[i].EarlyClaims, route.Rec[i].SourcePins
			}
			c.reportRevision(st)
			return false, nil
		}
		if err := c.wait(ctx, backoff); err != nil {
			return false, err
		}
		backoff = min(2*backoff, sharedDrainBackoffMax)
	}
}

// starved tracks a slot's retryable stage refusals: past the drain timeout
// since the first one, the slot is reported RevisionObjectStarved.
func (c *productCommander) starved(slot uint32) {
	c.mu.Lock()
	since, ok := c.starvedSince[slot]
	if !ok {
		c.starvedSince[slot] = c.clock()
	}
	c.mu.Unlock()
	if ok && c.clock().Sub(since) >= c.drainTimeout() {
		c.reportRevision(SharedRevisionStatus{Reason: RevisionObjectStarved, Slot: slot})
	}
}

func (c *productCommander) reportRevision(st SharedRevisionStatus) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revisionStatus[st.Slot] = &st
}

// clearRevision ends a slot's starvation window and, when the slot's
// revision committed (committed), its Degraded report.
func (c *productCommander) clearRevision(slot uint32, committed bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.starvedSince, slot)
	if st := c.revisionStatus[slot]; st != nil && (committed || st.Reason == RevisionObjectStarved) {
		delete(c.revisionStatus, slot)
	}
}

// revisionReport returns the slot's Degraded revision report, if any.
func (c *productCommander) revisionReport(slot uint32) (SharedRevisionStatus, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	st := c.revisionStatus[slot]
	if st == nil {
		return SharedRevisionStatus{}, false
	}
	return *st, true
}

// revisionReports returns every Degraded revision report.
func (c *productCommander) revisionReports() []SharedRevisionStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]SharedRevisionStatus, 0, len(c.revisionStatus))
	for _, st := range c.revisionStatus {
		out = append(out, *st)
	}
	return out
}

// sharedRevisionReporter is implemented by a publisher whose commander
// reports Degraded revisions (the product publisher).
type sharedRevisionReporter interface {
	revisionReport(slot uint32) (SharedRevisionStatus, bool)
	revisionReports() []SharedRevisionStatus
}

func (p *productRoutePublisher) revisionReport(slot uint32) (SharedRevisionStatus, bool) {
	if r, ok := p.cmd.(sharedRevisionReporter); ok {
		return r.revisionReport(slot)
	}
	return SharedRevisionStatus{}, false
}

func (p *productRoutePublisher) revisionReports() []SharedRevisionStatus {
	if r, ok := p.cmd.(sharedRevisionReporter); ok {
		return r.revisionReports()
	}
	return nil
}

// revisionDegraded is the node-health form of the revision reports: one
// error per Degraded slot (never NotReady on its own), nil when none.
func (n *NodeEnforcer) revisionDegraded() error {
	publisher, err := n.livePublisher(false)
	if err != nil {
		return nil // no live publisher: reported by the other health inputs
	}
	r, ok := publisher.(sharedRevisionReporter)
	if !ok {
		return nil
	}
	var result error
	for _, st := range r.revisionReports() {
		result = errors.Join(result, fmt.Errorf("degraded: slot %d revision %s (retiring generation %d: early claims %d, source pins %d, readers %d)",
			st.Slot, st.Reason, st.Generation, st.EarlyClaims, st.SourcePins, st.Readers))
	}
	return result
}
