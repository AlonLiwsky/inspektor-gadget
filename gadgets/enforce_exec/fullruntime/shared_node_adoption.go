// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// sharedAdoptionReporter is implemented by a publisher that adopts root
// tasks (productRoutePublisher): its per-slot refusal reports and per-node
// counters.
type sharedAdoptionReporter interface {
	adoptionStatus(slot uint32) (SharedAdoptionStatus, bool)
	adoptionReport() ([]SharedAdoptionStatus, map[string]uint64)
}

// sharedRouteRecycler is implemented by a publisher whose withdrawn routes
// must be recycled before their slot is reused (G4). Recycle returns nil
// once the slot is free, errSharedRecycleContended while TASK credits of the
// withdrawn route are still held.
type sharedRouteRecycler interface {
	Recycle(ctx context.Context, slot uint32, cgroup uint64) error
}

// sharedRecycleMaxDelay caps the backoff of the withdraw -> recycle loop.
const sharedRecycleMaxDelay = time.Second

// AdoptionReport returns every slot whose root-task adoption was refused
// (reported until the slot is recycled; Degraded), every MigratedAfterRelease
// residual (reported until node teardown; Degraded) and the per-node refusal
// counters by reason (AdoptionStuck and MigratedAfterRelease included). Without an adopting
// publisher it reports nothing.
func (n *NodeEnforcer) AdoptionReport() ([]SharedAdoptionStatus, map[string]uint64, error) {
	publisher, err := n.livePublisher(false)
	if err != nil {
		return nil, nil, err
	}
	r, ok := publisher.(sharedAdoptionReporter)
	if !ok {
		return nil, map[string]uint64{}, nil
	}
	slots, counts := r.adoptionReport()
	return slots, counts, nil
}

// adoptionDegraded is the node-health form of AdoptionReport: one error per
// reported slot (Degraded), nil when none.
func (n *NodeEnforcer) adoptionDegraded() error {
	slots, _, err := n.AdoptionReport()
	if err != nil {
		return nil // no live publisher: reported by the other health inputs
	}
	var result error
	for _, st := range slots {
		reason := st.Reason
		if st.Stuck {
			reason += ", " + AdoptionStuck
		}
		result = errors.Join(result, fmt.Errorf("degraded: slot %d cgroup %d init %d adoption refused (%s; marked %d, missed %d, gone %d)",
			st.Slot, st.Cgroup, st.InitTGID, reason, st.Marked, st.Missed, st.Gone))
	}
	return result
}

// startRecycle runs the withdraw -> recycle loop of a slot whose route this
// account withdrew (G4): recycle, retrying while contended, then free the
// slot for reuse. Any other refusal keeps the slot reserved (never reused)
// and is a sticky node fault. Joined by stopLiveCollection before the
// publisher closes. A loop may still be retrying a contended recycle when
// teardown starts: that is intended; stopRecycles cancels it and the slot
// dies with the collection.
func (n *NodeEnforcer) startRecycle(a *sharedPhysicalScope, slot uint32, r sharedRouteRecycler) {
	n.mu.Lock()
	live := n.host.live
	if live == nil || n.host.gadgetStopped || live.recycleStopped || live.publisher == nil {
		// Teardown: the slot stays reserved and dies with the collection.
		n.mu.Unlock()
		return
	}
	if live.recycleCtx == nil {
		live.recycleCtx, live.recycleCancel = context.WithCancel(context.Background())
	}
	ctx := live.recycleCtx
	live.recyclers.Add(1)
	n.mu.Unlock()
	go func() {
		defer live.recyclers.Done()
		delay := 10 * time.Millisecond
		for {
			err := r.Recycle(ctx, slot, a.cgroup)
			if err == nil {
				n.freeRecycledSlot(a, slot)
				return
			}
			if !errors.Is(err, errSharedRecycleContended) {
				if ctx.Err() == nil {
					n.mu.Lock()
					live.recycleFault = errors.Join(live.recycleFault, fmt.Errorf("recycle route slot %d: %w", slot, err))
					n.mu.Unlock()
				}
				return
			}
			t := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				t.Stop()
				return // node teardown: the slot dies with the collection
			case <-t.C:
			}
			delay = min(2*delay, sharedRecycleMaxDelay)
		}
	}()
}

// freeRecycledSlot returns a recycled slot to the node's free slots. The
// recycle proved the slot quiescent (its TASK account drained, its route
// FREE and cleaned), so the withdrawn account also releases its pins and
// becomes a retired tombstone: it keeps its terminal record (the cgroup is
// never bound again) but holds no slot or pin and no binding capacity. A
// pin close failure keeps the pins (released at teardown) and the capacity.
func (n *NodeEnforcer) freeRecycledSlot(a *sharedPhysicalScope, slot uint32) {
	a.mu.Lock()
	defer a.mu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.host == nil || !a.native.reserved || a.native.slot != slot || int(slot) >= len(n.host.scopeSlots) || n.host.scopeSlots[slot] != a {
		return
	}
	n.host.scopeSlots[slot] = nil
	a.native.reserved = false
	// Reached from the recycle loop of a Remove's withdrawal (the session is
	// being removed) or, for a refused adoption, only once its session is
	// gone (releasedAdoptionSlot, removePhysicalSession).
	if !a.withdrawn || n.scopes[a.cgroup] != a {
		return
	}
	if err := a.pins.Close(); err != nil {
		if live := n.host.live; live != nil {
			live.recycleFault = errors.Join(live.recycleFault, fmt.Errorf("release pins of withdrawn cgroup %d: %w", a.cgroup, err))
		}
		return
	}
	a.pins = nil
	a.retired = true
	n.markWithdrawnLocked(a.cgroup)
	delete(n.scopes, a.cgroup) // the terminal record stays in withdrawnCgroups
}

// markWithdrawn records cgroup as withdrawn (terminal) on this node.
func (n *NodeEnforcer) markWithdrawn(cgroup uint64) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.markWithdrawnLocked(cgroup)
}

func (n *NodeEnforcer) markWithdrawnLocked(cgroup uint64) {
	if n.withdrawnCgroups == nil {
		n.withdrawnCgroups = map[uint64]struct{}{}
	}
	n.withdrawnCgroups[cgroup] = struct{}{}
}

func (n *NodeEnforcer) isWithdrawnLocked(cgroup uint64) bool {
	_, ok := n.withdrawnCgroups[cgroup]
	return ok
}

// stopRecycles cancels and joins the recycle loops.
func (n *NodeEnforcer) stopRecycles(live *sharedLiveCandidate) {
	n.mu.Lock()
	live.recycleStopped = true // no startRecycle Add after this point
	cancel := live.recycleCancel
	n.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	live.recyclers.Wait()
}

// Initial namespace inodes (include/linux/proc_ns.h).
const (
	sharedProcPIDInitIno  = 0xEFFFFFFC
	sharedProcTimeInitIno = 0xEFFFFFFA
)

// sharedNamespaceCheck is checkSharedInitNamespaces; tests replace it.
var sharedNamespaceCheck = checkSharedInitNamespaces

// checkSharedInitNamespaces enforces design 13.8: Strict adoption reads
// cgroup.threads tids (bpf_task_from_pid takes init-namespace tids) and
// /proc start ticks (host boottime), so the agent must run in the initial
// pid and time namespaces: /proc/self/ns/{pid,time} must equal
// /proc/1/ns/{pid,time} and be the kernel's initial namespaces. A kernel
// without time namespaces (both links absent) has only host time.
func checkSharedInitNamespaces() error {
	for _, ns := range []struct {
		name string
		ino  uint64
	}{{"pid", sharedProcPIDInitIno}, {"time", sharedProcTimeInitIno}} {
		var self, init unix.Stat_t
		selfErr := unix.Stat("/proc/self/ns/"+ns.name, &self)
		initErr := unix.Stat("/proc/1/ns/"+ns.name, &init)
		if ns.name == "time" && errors.Is(selfErr, os.ErrNotExist) && errors.Is(initErr, os.ErrNotExist) {
			continue
		}
		if selfErr != nil || initErr != nil {
			return fmt.Errorf("%s namespace unreadable: %w", ns.name, errors.Join(selfErr, initErr))
		}
		if self.Dev != init.Dev || self.Ino != init.Ino || self.Ino != ns.ino {
			return fmt.Errorf("agent %s namespace %d is not the initial one (%d)", ns.name, self.Ino, ns.ino)
		}
	}
	return nil
}

// releasedAdoptionSlot is the poller's callback after it withdrew and
// recycled a refused adoption's slot (the kernel route is FREE). The
// account becomes withdrawn (terminal); if its session was already removed
// the slot is freed and the account retired now, otherwise Remove frees it.
func (n *NodeEnforcer) releasedAdoptionSlot(slot uint32, cgroup uint64) {
	n.mu.Lock()
	var a *sharedPhysicalScope
	if n.host != nil && int(slot) < len(n.host.scopeSlots) {
		a = n.host.scopeSlots[slot]
	}
	n.mu.Unlock()
	if a == nil {
		return
	}
	a.mu.Lock()
	if !a.native.reserved || a.native.slot != slot || a.cgroup != cgroup {
		a.mu.Unlock()
		return // the slot was already freed and reused by another cgroup
	}
	a.withdrawn = true
	a.route = sharedLiveRoute{}
	a.released = true
	n.markWithdrawn(cgroup) // account lock, then node lock
	a.mu.Unlock()
	n.mu.Lock()
	bound := n.bindings[cgroup] != nil
	n.mu.Unlock()
	if !bound {
		n.freeRecycledSlot(a, slot)
	}
}
