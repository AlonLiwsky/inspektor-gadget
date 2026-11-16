// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// sharedFakeBytesMap is a read-only map of raw values keyed by uint32.
type sharedFakeBytesMap struct {
	mu     sync.Mutex
	values map[uint32][]byte
	size   int
}

func (m *sharedFakeBytesMap) LookupBytes(key interface{}) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if v, ok := m.values[key.(uint32)]; ok {
		return append([]byte(nil), v...), nil
	}
	if m.size == 0 {
		return nil, fmt.Errorf("fake: key %v", key)
	}
	return make([]byte, m.size), nil
}

func (m *sharedFakeBytesMap) set(key uint32, value []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.values == nil {
		m.values = map[uint32][]byte{}
	}
	m.values[key] = value
}

type sharedCommanderFixture struct {
	cmd                         *productCommander
	fakes                       map[string]*sharedFakeCommand
	routes, objects, adoptState *sharedFakeBytesMap
}

func newSharedCommanderFixture(t *testing.T) *sharedCommanderFixture {
	t.Helper()
	return newSharedCommanderFixtureFor(t, sharedCandidateQualificationProfile())
}

// sharedFloorProfile is the qualification profile at the admission floor,
// Bindings + 1 policy objects (the product default is 2 x Bindings): the
// starvation and exhaustion cases are pinned there.
func sharedFloorProfile() SharedProfile {
	p := sharedCandidateQualificationProfile()
	p.PolicySlots = [4]uint64{p.Bindings + 1, 0, 0, 0}
	return p
}

func newSharedCommanderFixtureFor(t *testing.T, p SharedProfile) *sharedCommanderFixture {
	t.Helper()
	programs, fakes := sharedProductPrograms()
	control, err := newSharedProductControl(t.Context(), p, sharedProductManifest(p), &sharedFakeAdminMap{}, &sharedFakeAdminMap{}, programs)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := control.close(); err != nil {
			t.Error(err)
		}
	})
	f := &sharedCommanderFixture{
		fakes:      fakes,
		routes:     &sharedFakeBytesMap{size: sharedProductRouteAnchorBytes},
		objects:    &sharedFakeBytesMap{size: sharedProductObjectBytes},
		adoptState: &sharedFakeBytesMap{size: sharedProductAdoptStateBytes},
	}
	f.cmd = newProductCommander(control, f.routes, f.objects, f.adoptState, p)
	return f
}

func sharedCompiledTestPolicy(t *testing.T) (SharedBindingPolicy, sharedCompiledPolicy) {
	t.Helper()
	policy, err := SharedBindingPolicy{
		Source:    sharedTestSourcePolicy("p", "1", "app"),
		Container: "app",
	}.compile(1, nil)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := sharedCompiledPolicyOf(policy.program, policy.object)
	if err != nil {
		t.Fatal(err)
	}
	return policy, compiled
}

func sharedStageOps(requests [][]byte) []uint32 {
	ops := make([]uint32, 0, len(requests))
	for _, r := range requests {
		ops = append(ops, binary.LittleEndian.Uint32(r[sharedProductHeaderBytes+16:]))
	}
	return ops
}

// TestProductCommanderPublishFirstEncoding: a first publication stages the
// compiled program into a FREE object (BEGIN at its current generation, one
// WRITE per cell, FINALIZE with the compiled rule count and class), then
// publishes it with init_role = the compiled root role, bank = slot and the
// single policy's UID/root epoch and container in the metadata.
func TestProductCommanderPublishFirstEncoding(t *testing.T) {
	f := newSharedCommanderFixture(t)
	policy, compiled := sharedCompiledTestPolicy(t)
	init := SharedInitIdentity{TGID: 77, StartTicks: 4242, MountNS: 4026531999}
	if code, err := f.cmd.publishFirst(t.Context(), 1, 0xc0, policy, init); err != nil || code != sharedProductOK {
		t.Fatalf("publish: %d %v", code, err)
	}
	stage := f.fakes["opaque_real_policy_stage"].requests
	ops := sharedStageOps(stage)
	if len(ops) != len(compiled.Entries)+2 || ops[0] != sharedStageBegin || ops[len(ops)-1] != sharedStageFinalize {
		t.Fatalf("stage ops %v for %d cells", ops, len(compiled.Entries))
	}
	le := binary.LittleEndian
	begin, finalize := stage[0][sharedProductHeaderBytes:], stage[len(stage)-1][sharedProductHeaderBytes:]
	if le.Uint64(begin) != 0 || le.Uint64(begin[8:]) == 0 || le.Uint32(begin[28:]) != uint32(len(compiled.Entries)) {
		t.Fatalf("BEGIN %x", begin[:40])
	}
	if le.Uint64(finalize) != 1 || le.Uint64(finalize[8:]) != le.Uint64(begin[8:]) ||
		le.Uint32(finalize[28:]) != compiled.Rules || le.Uint32(finalize[32:]) != compiled.Class {
		t.Fatalf("FINALIZE %x", finalize[:40])
	}
	for i, r := range stage[1 : len(stage)-1] {
		body := r[sharedProductHeaderBytes:]
		if le.Uint32(body[24:]) != uint32(i) || string(body[40:40+fullpolicy.KernelBlobSize]) != string(compiled.Entries[i][:]) {
			t.Fatalf("WRITE %d", i)
		}
	}
	var cell fullpolicy.Blob
	copy(cell[:], stage[1+fullpolicy.KernelPolicyBase][sharedProductHeaderBytes+40:])
	staged, err := fullpolicy.Decode[fullpolicy.KernelPolicy](cell)
	if err != nil || staged.RootEpoch != 0 || staged.UID != compiled.UID || compiled.RootEpoch == 0 {
		t.Fatalf("staged policy cell %+v %v: a shared object carries root_epoch 0, the epoch (%d) goes in the metadata", staged.UID, err, compiled.RootEpoch)
	}
	publish := f.fakes["opaque_real_route_publish"].requests
	if len(publish) != 1 || len(publish[0]) != sharedProductPublishRequestBytes {
		t.Fatalf("publish requests %d", len(publish))
	}
	b := publish[0][sharedProductHeaderBytes:]
	m := b[80:]
	for name, ok := range map[string]bool{
		"cgroup":              le.Uint64(b) == 0xc0,
		"scope":               le.Uint64(b[8:]) != 0,
		"generation_expected": le.Uint64(b[16:]) == 0,
		"object_generation":   le.Uint64(b[24:]) == 1,
		"init":                le.Uint64(b[32:]) == 4242 && le.Uint64(b[40:]) == 4026531999 && le.Uint32(b[68:]) == 77,
		"init_role":           le.Uint64(b[48:]) == compiled.RootRole && compiled.RootRole != 0,
		"slot/class/object":   le.Uint32(b[56:]) == 1 && le.Uint32(b[60:]) == compiled.Class && le.Uint32(b[64:]) == le.Uint32(begin[20:]),
		"bank = slot":         le.Uint32(b[72:]) == 1,
		"metadata policy":     le.Uint64(m) == compiled.RootEpoch && le.Uint64(m[64:]) == compiled.UID && le.Uint64(m[8:]) == 0 && le.Uint64(m[72:]) == 0,
		"metadata container":  le.Uint32(m[144:]) == 3 && string(m[148:151]) == "app",
	} {
		if !ok {
			t.Errorf("publish %s wrong", name)
		}
	}
}

// TestProductCommanderRefusals: no compiled program, a refused cell write
// (the object is aborted) and a refused publication (no slot recorded) all
// fail without a published route.
func TestProductCommanderRefusals(t *testing.T) {
	f := newSharedCommanderFixture(t)
	init := SharedInitIdentity{TGID: 77, StartTicks: 1, MountNS: 1}
	if _, err := f.cmd.publishFirst(t.Context(), 0, 1, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}, init); err == nil {
		t.Fatal("uncompiled policy published")
	}
	if n := len(f.fakes["opaque_real_policy_stage"].requests) + len(f.fakes["opaque_real_route_publish"].requests); n != 0 {
		t.Fatalf("%d commands ran for an uncompiled policy", n)
	}
	policy, _ := sharedCompiledTestPolicy(t)
	f.fakes["opaque_real_policy_stage"].respond = func(r []byte) uint32 {
		if binary.LittleEndian.Uint32(r[sharedProductHeaderBytes+16:]) == sharedStageWrite {
			return sharedProductRetry
		}
		return sharedProductOK
	}
	if _, err := f.cmd.publishFirst(t.Context(), 0, 1, policy, init); err == nil {
		t.Fatal("refused write published")
	}
	if ops := sharedStageOps(f.fakes["opaque_real_policy_stage"].requests); len(ops) != 3 || ops[1] != sharedStageWrite || ops[2] != sharedStageAbort {
		t.Fatalf("refused write: ops %v, want BEGIN,WRITE,ABORT", ops)
	}
	if len(f.fakes["opaque_real_route_publish"].requests) != 0 || len(f.cmd.used) != 0 {
		t.Fatal("aborted object published or held")
	}
	f.fakes["opaque_real_policy_stage"].respond = nil
	f.fakes["opaque_real_route_publish"].code = sharedProductReused
	if code, err := f.cmd.publishFirst(t.Context(), 0, 1, policy, init); err != nil || code != sharedProductReused {
		t.Fatalf("reused cgroup: %d %v", code, err)
	}
	if len(f.cmd.slots) != 0 || len(f.cmd.used) != 0 {
		t.Fatalf("refused publication kept slot %v objects %v", f.cmd.slots, f.cmd.used)
	}
}

// TestProductCommanderQuarantineAndRoute: quarantine code 1 is incomplete
// (with the adopt state's counts), never done; a phase-0 route is free.
func TestProductCommanderQuarantineAndRoute(t *testing.T) {
	f := newSharedCommanderFixture(t)
	state := make([]byte, sharedProductAdoptStateBytes)
	binary.LittleEndian.PutUint32(state[36:], 3)
	binary.LittleEndian.PutUint32(state[40:], 1)
	f.adoptState.set(0, state)
	f.fakes["opaque_real_adopt_quarantine"].code = sharedProductRetry
	result, err := f.cmd.quarantine(t.Context(), 0, 9)
	if err != nil || result.Complete || result.Quarantined != 3 || result.Missed != 1 {
		t.Fatalf("incomplete quarantine %+v %v", result, err)
	}
	f.fakes["opaque_real_adopt_quarantine"].code = sharedProductAuthFailed
	if _, err := f.cmd.quarantine(t.Context(), 0, 9); err == nil {
		t.Fatal("refused quarantine accepted")
	}
	if _, err := f.cmd.route(0); !errors.Is(err, ErrSharedRouteFree) {
		t.Fatalf("free route: %v", err)
	}
}

func sharedAdoptStateRaw(iterated, adopted, exiting, finishes, quarantined, missed, gone uint32) []byte {
	raw := make([]byte, sharedProductAdoptStateBytes)
	le := binary.LittleEndian
	le.PutUint32(raw[12:], adopted)
	le.PutUint32(raw[16:], iterated)
	le.PutUint32(raw[36:], quarantined)
	le.PutUint32(raw[40:], missed)
	le.PutUint32(raw[44:], exiting)
	le.PutUint32(raw[52:], finishes)
	le.PutUint32(raw[56:], gone)
	return raw
}

// TestProductCommanderFinishDetailFromItsOwnRun (review L-7): finish's
// refusal detail is used only when the finishes sequence advanced by
// exactly one; an early refusal leaves verify's counts, which must not be
// read as a ThreadExited.
func TestProductCommanderFinishDetailFromItsOwnRun(t *testing.T) {
	f := newSharedCommanderFixture(t)
	f.adoptState.set(0, sharedAdoptStateRaw(1, 2, 0, 7, 0, 0, 0)) // verify's leftovers
	f.fakes["opaque_real_adopt_finish"].code = sharedProductRefused
	code, detail, err := f.cmd.finish(t.Context(), 0, 9)
	if err != nil || code != sharedProductRefused || detail != (sharedFinishDetail{}) {
		t.Fatalf("early refusal: %d %+v %v, want an empty detail", code, detail, err)
	}
	f.fakes["opaque_real_adopt_finish"].respond = func([]byte) uint32 {
		f.adoptState.set(0, sharedAdoptStateRaw(3, 2, 1, 8, 0, 0, 0))
		return sharedProductRefused
	}
	code, detail, err = f.cmd.finish(t.Context(), 0, 9)
	if err != nil || code != sharedProductRefused || detail.Iterated != 3 || detail.Adopted != 2 || !detail.Exiting {
		t.Fatalf("counted refusal: %d %+v %v", code, detail, err)
	}
}

// TestProductCommanderQuarantineGoneIsComplete (review I-3): entries whose
// TASK is gone have nothing to mark: complete, with the gone count.
func TestProductCommanderQuarantineGoneIsComplete(t *testing.T) {
	f := newSharedCommanderFixture(t)
	f.adoptState.set(0, sharedAdoptStateRaw(0, 0, 0, 0, 2, 0, 3))
	result, err := f.cmd.quarantine(t.Context(), 0, 9)
	if err != nil || !result.Complete || result.Quarantined != 2 || result.Gone != 3 || result.Missed != 0 {
		t.Fatalf("gone entries: %+v %v", result, err)
	}
}

// TestProductCommanderStagingSerializedAndOrphans (review L-8): concurrent
// first publications never stage into the same object, and an object whose
// release failed stays held and is released by the next stage.
func TestProductCommanderStagingSerializedAndOrphans(t *testing.T) {
	f := newSharedCommanderFixture(t)
	policy, _ := sharedCompiledTestPolicy(t)
	init := SharedInitIdentity{TGID: 1, StartTicks: 1, MountNS: 1}
	var wg sync.WaitGroup
	for slot := range uint32(2) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if code, err := f.cmd.publishFirst(t.Context(), slot, uint64(100+slot), policy, init); err != nil || code != sharedProductOK {
				t.Errorf("slot %d: %d %v", slot, code, err)
			}
		}()
	}
	wg.Wait()
	f.cmd.mu.Lock()
	a, b := f.cmd.slots[0], f.cmd.slots[1]
	f.cmd.mu.Unlock()
	if a == nil || b == nil || a.object == b.object {
		t.Fatalf("concurrent publications share an object: %+v %+v", a, b)
	}
	// Free slot 1's object for the refused publication below.
	if code, err := f.cmd.recycle(t.Context(), 1); err != nil || code != sharedProductOK {
		t.Fatalf("recycle slot 1: %d %v", code, err)
	}
	// A refused publication whose object is READY but cannot be retired.
	ready := make([]byte, sharedProductObjectBytes)
	binary.LittleEndian.PutUint64(ready[8:], 1)
	binary.LittleEndian.PutUint32(ready[48:], sharedObjectReady)
	retire := true
	f.fakes["opaque_real_policy_stage"].respond = func(r []byte) uint32 {
		op := binary.LittleEndian.Uint32(r[sharedProductHeaderBytes+16:])
		object := binary.LittleEndian.Uint32(r[sharedProductHeaderBytes+20:])
		if op == sharedStageFinalize {
			f.objects.set(object, ready)
		}
		if op == sharedStageRetire && retire {
			return sharedProductRetry
		}
		if op == sharedStageReclaim {
			f.objects.set(object, make([]byte, sharedProductObjectBytes))
		}
		return sharedProductOK
	}
	f.fakes["opaque_real_route_publish"].code = sharedProductRetry
	if code, _ := f.cmd.publishFirst(t.Context(), 2, 102, policy, init); code != sharedProductRetry {
		t.Fatalf("refused publication: %d", code)
	}
	f.cmd.mu.Lock()
	orphans := append([]uint32(nil), f.cmd.orphans...)
	f.cmd.mu.Unlock()
	if len(orphans) != 1 || !f.cmd.used[orphans[0]] {
		t.Fatalf("unreleasable object not kept as a held orphan: %v used %v", orphans, f.cmd.used)
	}
	retire = false
	if code, _ := f.cmd.publishFirst(t.Context(), 2, 102, policy, init); code != sharedProductRetry {
		t.Fatalf("second refused publication: %d", code)
	}
	f.cmd.mu.Lock()
	defer f.cmd.mu.Unlock()
	if len(f.cmd.orphans) != 0 || f.cmd.used[orphans[0]] {
		t.Fatalf("orphan %d not released by the next stage: orphans %v used %v", orphans[0], f.cmd.orphans, f.cmd.used)
	}
}

// sharedHonestKernel models the policy-object pins exactly as the product
// publisher sets and drops them (review step 0, the revision deadlock): a
// committed object is pinned; a revision's commit leaves the previous record
// RETIRING, still pinning its object, and drops it at once (best effort);
// a revision's start, withdraw and recycle drop the slot's RETIRING records
// too. RETIRE (the release of a READY object) is refused while it is pinned.
// Nothing else unpins: no test toggles pins behind the kernel's back.
type sharedHonestKernel struct {
	mu       sync.Mutex
	pins     map[uint32]int
	active   map[uint32]uint32   // slot -> committed object
	retiring map[uint32][]uint32 // slot -> objects of RETIRING records not dropped yet
	// holdDrop: every drop is refused (a failed ticket command);
	// failRetire: every RETIRE is refused (a failed command).
	holdDrop, failRetire bool
	// beforePublish runs before a publish takes effect (outside mu).
	beforePublish func()
	// G019 gap 3: holders (early claims) of each slot's ACTIVE record and
	// of its RETIRING one; a commit moves the active holders with their
	// record; a RETIRING record with holders is never dropped. The route
	// anchor (generation, scope, se_route_rec) is written to f.routes.
	holders, retiringHolders map[uint32]uint32
	generation, scope        map[uint32]uint64
	routes                   *sharedFakeBytesMap
	// epochCell is each slot's accepted-epoch cell (scope, uid, epoch),
	// written by the first publication only: a revision with another root
	// epoch is refused up front (code 2) and changes nothing.
	epochCell map[uint32][3]uint64
}

func installSharedHonestKernel(f *sharedCommanderFixture) *sharedHonestKernel {
	k := &sharedHonestKernel{
		pins: map[uint32]int{}, active: map[uint32]uint32{}, retiring: map[uint32][]uint32{},
		holders: map[uint32]uint32{}, retiringHolders: map[uint32]uint32{}, generation: map[uint32]uint64{}, scope: map[uint32]uint64{},
		routes: f.routes, epochCell: map[uint32][3]uint64{},
	}
	le := binary.LittleEndian
	ready := make([]byte, sharedProductObjectBytes)
	le.PutUint64(ready[8:], 1)
	le.PutUint32(ready[48:], sharedObjectReady)
	f.fakes["opaque_real_policy_stage"].respond = func(r []byte) uint32 {
		op := le.Uint32(r[sharedProductHeaderBytes+16:])
		object := le.Uint32(r[sharedProductHeaderBytes+20:])
		k.mu.Lock()
		defer k.mu.Unlock()
		switch {
		case op == sharedStageFinalize:
			f.objects.set(object, ready)
		case op == sharedStageRetire && (k.failRetire || k.pins[object] > 0):
			return sharedProductRetry
		case op == sharedStageReclaim:
			f.objects.set(object, make([]byte, sharedProductObjectBytes))
		}
		return sharedProductOK
	}
	f.fakes["opaque_real_route_publish"].respond = func(r []byte) uint32 {
		k.mu.Lock()
		hook := k.beforePublish
		k.mu.Unlock()
		if hook != nil {
			hook()
		}
		body := r[sharedProductHeaderBytes:]
		slot, object := le.Uint32(body[56:]), le.Uint32(body[64:])
		k.mu.Lock()
		defer k.mu.Unlock()
		defer k.encodeLocked(slot)
		old, revision := k.active[slot]
		meta := body[80:]
		uid, epoch := le.Uint64(meta[64:]), le.Uint64(meta)
		if cell, ok := k.epochCell[slot]; revision && ok && (cell[1] != uid || cell[2] != epoch) {
			return sharedProductRefused // UID or root epoch changed
		}
		if revision && !k.dropLocked(slot) {
			return sharedProductRetry // the revision's start drop
		}
		if !revision {
			k.epochCell[slot] = [3]uint64{le.Uint64(body[8:]), uid, epoch}
		}
		k.pins[object]++
		k.active[slot] = object
		k.scope[slot] = le.Uint64(body[8:])
		k.generation[slot]++
		if revision {
			k.retiring[slot] = append(k.retiring[slot], old)
			k.retiringHolders[slot], k.holders[slot] = k.holders[slot], 0
			k.dropLocked(slot) // after commit, best effort
		}
		return sharedProductOK
	}
	f.fakes["opaque_real_route_drop_retired"].respond = func(r []byte) uint32 {
		body := r[sharedProductHeaderBytes:]
		slot, generation := le.Uint32(body), le.Uint64(body[16:])
		k.mu.Lock()
		defer k.mu.Unlock()
		defer k.encodeLocked(slot)
		switch {
		case len(k.retiring[slot]) != 0 && generation == k.generation[slot]-1:
			if !k.dropLocked(slot) {
				return sharedProductRetry
			}
			return sharedProductOK
		case generation < k.generation[slot]:
			return sharedProductOK // dropped already
		}
		return sharedProductInvariant
	}
	f.fakes["opaque_real_route_recycle"].respond = func(r []byte) uint32 {
		slot := le.Uint32(r[sharedProductHeaderBytes:])
		k.mu.Lock()
		defer k.mu.Unlock()
		defer k.encodeLocked(slot)
		if k.holders[slot]+k.retiringHolders[slot] != 0 {
			return sharedProductRetry // withdrawal needs no holder
		}
		if object, ok := k.active[slot]; ok {
			k.retiring[slot] = append(k.retiring[slot], object)
			delete(k.active, slot)
		}
		if !k.dropLocked(slot) {
			return sharedProductRetry
		}
		return sharedProductOK
	}
	return k
}

// dropLocked releases the tickets of the slot's RETIRING records, unless
// one still has holders (or holdDrop refuses every drop).
func (k *sharedHonestKernel) dropLocked(slot uint32) bool {
	if (k.holdDrop || k.retiringHolders[slot] != 0) && len(k.retiring[slot]) != 0 {
		return false
	}
	for _, object := range k.retiring[slot] {
		k.pins[object]--
	}
	delete(k.retiring, slot)
	return true
}

// encodeLocked writes the slot's 176-byte route anchor: scope, generation,
// the active record (generation parity) and both struct se_route_rec.
func (k *sharedHonestKernel) encodeLocked(slot uint32) {
	le := binary.LittleEndian
	raw := make([]byte, sharedProductRouteAnchorBytes)
	g := k.generation[slot]
	if g == 0 {
		k.routes.set(slot, raw)
		return
	}
	active := uint32((g - 1) % 2)
	le.PutUint64(raw[16:], k.scope[slot])
	le.PutUint64(raw[24:], g)
	le.PutUint32(raw[52:], active)
	le.PutUint32(raw[64:], k.holders[slot]+k.retiringHolders[slot])
	rec := func(i uint32, generation uint64, holders, phase uint32) {
		o := 112 + 32*int(i)
		le.PutUint64(raw[o:], generation)
		le.PutUint64(raw[o+8:], generation)
		le.PutUint32(raw[o+16:], holders)
		le.PutUint32(raw[o+24:], phase)
	}
	rec(active, g, k.holders[slot], sharedSnapshotActive)
	if len(k.retiring[slot]) != 0 && g > 1 {
		rec(active^1, g-1, k.retiringHolders[slot], sharedSnapshotRetiring)
	}
	k.routes.set(slot, raw)
}

func (k *sharedHonestKernel) set(fn func(*sharedHonestKernel)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	fn(k)
	for slot := range k.generation {
		k.encodeLocked(slot)
	}
}

// TestProductCommanderStageExhaustion: with no FREE object, stage refuses
// terminally when every object is held by a live route, but with the
// publisher's retryable refusal when a held object is a revision's stale
// object awaiting its pins' drain, or a revision is in flight. Every case
// runs over sharedHonestKernel.
func TestProductCommanderStageExhaustion(t *testing.T) {
	policy, _ := sharedCompiledTestPolicy(t)
	init := SharedInitIdentity{TGID: 1, StartTicks: 1, MountNS: 1}
	floor := sharedFloorProfile()
	objects := uint32(floor.PolicySlots[0])
	if p := sharedCandidateQualificationProfile(); p.PolicySlots != sharedProductPolicySlots || p.PolicySlots[0] != 2*p.Bindings || uint64(objects) != p.Bindings+1 {
		t.Fatalf("default profile %v / %d bindings is not 2 x Bindings, or the floor %d is not Bindings+1", p.PolicySlots, p.Bindings, objects)
	}
	newFixture := func(t *testing.T, publish uint32) (*sharedCommanderFixture, *sharedHonestKernel) {
		f := newSharedCommanderFixtureFor(t, floor)
		k := installSharedHonestKernel(f)
		for slot := range publish {
			if code, err := f.cmd.publishFirst(t.Context(), slot, uint64(100+slot), policy, init); err != nil || code != sharedProductOK {
				t.Fatalf("slot %d: %d %v", slot, code, err)
			}
		}
		return f, k
	}
	revise := func(t *testing.T, f *sharedCommanderFixture, slot uint32) {
		t.Helper()
		if code, err := f.cmd.revise(t.Context(), slot, uint64(100+slot), policy); err != nil || code != sharedProductOK {
			t.Fatalf("revision of slot %d: %d %v", slot, code, err)
		}
	}
	const retryable = "retryable refusal (in-flight claims or pins)"

	t.Run("exhausted by live routes is terminal", func(t *testing.T) {
		f, _ := newFixture(t, objects)
		_, err := f.cmd.publishFirst(t.Context(), objects, 200, policy, init)
		if err == nil || errors.Is(err, ErrSharedRetryableRefusal) || strings.Contains(err.Error(), "retryable") || !strings.Contains(err.Error(), "no free policy object") {
			t.Fatalf("exhausted stage: %v, want the terminal refusal", err)
		}
	})

	// Review step 0 (the revision deadlock): with every binding published
	// and one spare object, alternating revisions of both bindings never
	// stall, because each commit drops the previous record and its object
	// is released at once.
	t.Run("alternating revisions of two bindings never deadlock", func(t *testing.T) {
		f, k := newFixture(t, 2)
		for _, slot := range []uint32{0, 1, 0, 1, 0, 1} {
			revise(t, f, slot)
		}
		f.cmd.mu.Lock()
		defer f.cmd.mu.Unlock()
		k.mu.Lock()
		defer k.mu.Unlock()
		if len(f.cmd.used) != 2 || len(f.cmd.staging) != 0 || len(f.cmd.orphans) != 0 ||
			len(f.cmd.slots[0].stale) != 0 || len(f.cmd.slots[1].stale) != 0 {
			t.Fatalf("after the sequence: used %v staging %v orphans %v", f.cmd.used, f.cmd.staging, f.cmd.orphans)
		}
		for object, pins := range k.pins {
			if want := f.cmd.used[object]; (pins == 1) != want || pins > 1 {
				t.Fatalf("object %d pins %d, held %v", object, pins, want)
			}
		}
	})

	// A drop the kernel refuses after commit (a holder or a failed ticket
	// command) keeps the old object pinned: the commander keeps it stale and
	// every stage refuses retryably, never terminally; the slot's recycle
	// (which drops its records again) frees it and revisions resume.
	t.Run("stale object pending drain is retryable", func(t *testing.T) {
		f, k := newFixture(t, 2)
		k.set(func(k *sharedHonestKernel) { k.holdDrop = true })
		revise(t, f, 0)
		f.cmd.mu.Lock()
		stale := append([]uint32(nil), f.cmd.slots[0].stale...)
		f.cmd.mu.Unlock()
		if len(stale) != 1 || !f.cmd.used[stale[0]] {
			t.Fatalf("undropped old object not kept stale: %v", stale)
		}
		for _, slot := range []uint32{1, 0} {
			if _, err := f.cmd.revise(t.Context(), slot, uint64(100+slot), policy); !errors.Is(err, ErrSharedRetryableRefusal) || !strings.Contains(err.Error(), retryable) {
				t.Fatalf("revision of slot %d with the old object pinned: %v, want the retryable refusal", slot, err)
			}
		}
		k.set(func(k *sharedHonestKernel) { k.holdDrop = false })
		if code, err := f.cmd.recycle(t.Context(), 0); err != nil || code != sharedProductOK {
			t.Fatalf("recycle slot 0: %d %v", code, err)
		}
		revise(t, f, 1)
		f.cmd.mu.Lock()
		defer f.cmd.mu.Unlock()
		if len(f.cmd.used) != 1 || len(f.cmd.orphans) != 0 {
			t.Fatalf("after the recycle and revision: used %v orphans %v", f.cmd.used, f.cmd.orphans)
		}
	})

	// Review M1: revision A stages into the single spare and, before it
	// records its previous object as stale, revision B finds no FREE object.
	// A's previous object is neither stale nor orphaned yet, so only A's
	// in-flight staged object shows a release is coming: B's refusal is
	// retryable, and B's retry after A commits succeeds.
	t.Run("concurrent revisions at Bindings+1 objects are retryable", func(t *testing.T) {
		f, k := newFixture(t, 2)
		// Hold A in its publish (on the admin thread): B's refused stage
		// runs no command, so it completes meanwhile.
		inPublish, proceed := make(chan struct{}), make(chan struct{})
		var once sync.Once
		k.set(func(k *sharedHonestKernel) {
			k.beforePublish = func() {
				once.Do(func() {
					close(inPublish)
					<-proceed
				})
			}
		})
		revisionA := make(chan error, 1)
		go func() {
			code, err := f.cmd.revise(t.Context(), 0, 100, policy)
			if err == nil && code != sharedProductOK {
				err = fmt.Errorf("code %d", code)
			}
			revisionA <- err
		}()
		<-inPublish
		_, err := f.cmd.revise(t.Context(), 1, 101, policy)
		close(proceed)
		if !errors.Is(err, ErrSharedRetryableRefusal) || !strings.Contains(err.Error(), retryable) {
			t.Fatalf("revision B while A is in flight: %v, want the retryable refusal", err)
		}
		if err := <-revisionA; err != nil {
			t.Fatalf("revision A: %v", err)
		}
		revise(t, f, 1)
		f.cmd.mu.Lock()
		defer f.cmd.mu.Unlock()
		if len(f.cmd.staging) != 0 || len(f.cmd.used) != int(objects)-1 || f.cmd.slots[0].object == f.cmd.slots[1].object {
			t.Fatalf("after both revisions: staging %v used %v slots %+v %+v", f.cmd.staging, f.cmd.used, f.cmd.slots[0], f.cmd.slots[1])
		}
	})

	// A release that completes between a stage's scan and its refusal makes
	// the refusal retryable (the freed object was missed by the scan).
	t.Run("release after the scan is retryable", func(t *testing.T) {
		f, _ := newFixture(t, 0)
		f.cmd.mu.Lock()
		since := f.cmd.releases
		f.cmd.releases++
		f.cmd.mu.Unlock()
		if !f.cmd.drainPending(1, since) {
			t.Fatal("a release after the scan refused terminally")
		}
		if f.cmd.drainPending(1, since+1) {
			t.Fatal("no held, staged or released object, yet retryable")
		}
	})
}

// sharedHookBytesMap runs hook before each lookup of the inner map.
type sharedHookBytesMap struct {
	inner sharedBytesMap
	hook  func(key uint32)
}

func (m *sharedHookBytesMap) LookupBytes(key interface{}) ([]byte, error) {
	m.hook(key.(uint32))
	return m.inner.LookupBytes(key)
}

// TestProductCommanderRecycleDuringRetryStale (review M2): a recycle that
// detaches a slot while retryStale is releasing that slot's stale object
// never leaks it: an object whose release fails becomes a held orphan (not
// a failure appended to the detached record), released by a later stage.
// Over sharedHonestKernel: the stale object stays pinned because the
// commit's drop was refused; the recycle drops it, but RETIRE commands fail
// meanwhile.
func TestProductCommanderRecycleDuringRetryStale(t *testing.T) {
	f := newSharedCommanderFixture(t)
	k := installSharedHonestKernel(f)
	policy, _ := sharedCompiledTestPolicy(t)
	init := SharedInitIdentity{TGID: 1, StartTicks: 1, MountNS: 1}
	if code, err := f.cmd.publishFirst(t.Context(), 0, 100, policy, init); err != nil || code != sharedProductOK {
		t.Fatalf("publish: %d %v", code, err)
	}
	k.set(func(k *sharedHonestKernel) { k.holdDrop = true })
	if code, err := f.cmd.revise(t.Context(), 0, 100, policy); err != nil || code != sharedProductOK {
		t.Fatalf("revise: %d %v", code, err)
	}
	f.cmd.mu.Lock()
	stale := append([]uint32(nil), f.cmd.slots[0].stale...)
	active := f.cmd.slots[0].object
	f.cmd.mu.Unlock()
	if len(stale) != 1 {
		t.Fatalf("undropped old object not stale: %v", stale)
	}
	// retryStale takes slot 0's stale object; before its release fails, a
	// recycle detaches slot 0 (dropping its records in the kernel) while
	// RETIRE commands fail.
	var recycled bool
	f.cmd.objects = &sharedHookBytesMap{inner: f.objects, hook: func(key uint32) {
		if key != stale[0] || recycled {
			return
		}
		recycled = true
		k.set(func(k *sharedHonestKernel) { k.holdDrop, k.failRetire = false, true })
		if code, err := f.cmd.recycle(t.Context(), 0); err != nil || code != sharedProductOK {
			t.Errorf("recycle: %d %v", code, err)
		}
	}}
	f.cmd.retryStale(t.Context())
	if !recycled {
		t.Fatal("recycle did not interleave with retryStale")
	}
	f.cmd.mu.Lock()
	orphans := append([]uint32(nil), f.cmd.orphans...)
	f.cmd.mu.Unlock()
	if len(orphans) != 2 || !slices.Contains(orphans, stale[0]) || !slices.Contains(orphans, active) {
		t.Fatalf("orphans %v, want the stale %d and active %d objects", orphans, stale[0], active)
	}
	k.set(func(k *sharedHonestKernel) { k.failRetire = false })
	f.cmd.retryOrphans(t.Context())
	f.cmd.mu.Lock()
	defer f.cmd.mu.Unlock()
	if len(f.cmd.orphans) != 0 || len(f.cmd.used) != 0 || f.cmd.releasing != 0 {
		t.Fatalf("after the drain: orphans %v used %v releasing %d", f.cmd.orphans, f.cmd.used, f.cmd.releasing)
	}
}

// sharedTestSourcePolicy is a minimal authored policy with one rule (a
// policy without rules is refused, review L4).
func sharedTestSourcePolicy(id, revision, role string) *fullpolicy.Policy {
	return &fullpolicy.Policy{
		ID: id, Revision: revision, Mode: fullpolicy.Enforce, RootRole: role, Default: fullpolicy.Deny,
		Rules: []fullpolicy.Rule{{Name: "root", Action: fullpolicy.Allow, Actor: fullpolicy.Actor{UID: []int64{0}}}},
	}
}

// TestSharedCompiledPolicyRefusals (review L2/L4): the staged cells and the
// role-epoch compilation must describe the same policy (UID and root role),
// the shared object must carry root_epoch 0, and a policy without rules is
// refused before anything is staged.
func TestSharedCompiledPolicyRefusals(t *testing.T) {
	compile := func(p *fullpolicy.Policy) (*fullpolicy.KernelProgram, *fullpolicy.SharedPolicy) {
		t.Helper()
		program, err := fullpolicy.CompileKernelWithRoleEpochs([]fullpolicy.Policy{*p}, 1, "app", nil)
		if err != nil {
			t.Fatal(err)
		}
		object, err := fullpolicy.CompileSharedPolicy(*p)
		if err != nil {
			t.Fatal(err)
		}
		return program, object
	}
	program, object := compile(sharedTestSourcePolicy("p", "1", "app"))
	if c, err := sharedCompiledPolicyOf(program, object); err != nil || c.RootEpoch == 0 || c.Rules != 1 {
		t.Fatalf("valid policy: %+v %v", c, err)
	}
	otherUID, otherUIDObject := compile(sharedTestSourcePolicy("q", "1", "app"))
	otherRole, otherRoleObject := compile(sharedTestSourcePolicy("p", "1", "web"))
	noRules := sharedTestSourcePolicy("p", "1", "app")
	noRules.Rules = nil
	noRulesProgram, noRulesObject := compile(noRules)
	for name, tc := range map[string]struct {
		program *fullpolicy.KernelProgram
		entries []fullpolicy.Blob
		uid     uint64
	}{
		"UID mismatch between the compiles":       {otherUID, object.Entries(), object.UID()},
		"root role mismatch between the compiles": {otherRole, object.Entries(), object.UID()},
		"object UID differs from its cells":       {program, object.Entries(), otherUIDObject.UID()},
		"object carries a root epoch":             {program, program.Entries, object.UID()},
		"no rules":                                {noRulesProgram, noRulesObject.Entries(), noRulesObject.UID()},
		"role object, epoch program swapped":      {program, otherRoleObject.Entries(), otherRoleObject.UID()},
	} {
		if c, err := sharedCompiledPolicyOfCells(tc.program, tc.entries, tc.uid); err == nil {
			t.Errorf("%s: accepted %+v", name, c)
		}
	}
}

// TestProductCommanderUnconfirmedFirstPublish (review M2): a lost reply is
// resolved by the route read back. This node's scope and cgroup on a live
// route: committed, recorded, revisable and withdrawable. A FREE route:
// nothing committed, the object is released. A failed undo (-1) or a
// foreign route: latched (errSharedPublishUnknown), the object stays held.
func TestProductCommanderUnconfirmedFirstPublish(t *testing.T) {
	policy, _ := sharedCompiledTestPolicy(t)
	init := SharedInitIdentity{TGID: 1, StartTicks: 1, MountNS: 1}
	lost := errors.New("reply lost")
	routeOf := func(r []byte, cgroup uint64) []byte {
		b := r[sharedProductHeaderBytes:]
		route := make([]byte, sharedProductRouteAnchorBytes)
		binary.LittleEndian.PutUint64(route[8:], cgroup)
		binary.LittleEndian.PutUint64(route[16:], binary.LittleEndian.Uint64(b[8:])) // the request's scope
		binary.LittleEndian.PutUint64(route[24:], 1)
		binary.LittleEndian.PutUint32(route[56:], 2)
		binary.LittleEndian.PutUint32(route[60:], 2)
		return route
	}
	t.Run("committed", func(t *testing.T) {
		f := newSharedCommanderFixture(t)
		f.fakes["opaque_real_route_publish"].respond = func(r []byte) uint32 { f.routes.set(0, routeOf(r, 0xc0)); return 0 }
		f.fakes["opaque_real_route_publish"].runErr = lost
		code, err := f.cmd.publishFirst(t.Context(), 0, 0xc0, policy, init)
		if err != nil || code != sharedProductOK || f.cmd.slots[0] == nil {
			t.Fatalf("committed lost reply: %d %v slot %v", code, err, f.cmd.slots[0])
		}
	})
	t.Run("not committed", func(t *testing.T) {
		f := newSharedCommanderFixture(t)
		f.fakes["opaque_real_route_publish"].runErr = lost
		code, err := f.cmd.publishFirst(t.Context(), 0, 0xc0, policy, init)
		if !errors.Is(err, lost) || errors.Is(err, errSharedPublishUnknown) || f.cmd.slots[0] != nil || len(f.cmd.used) != 0 {
			t.Fatalf("uncommitted lost reply: %d %v used %v", code, err, f.cmd.used)
		}
	})
	// C3: an unknown outcome carries the scope this commander minted (the
	// request's), typed, while errors.Is on the sentinel and the cause holds.
	minted := func(t *testing.T, err error, scope uint64) {
		t.Helper()
		var unknown *ErrSharedPublishUnknown
		if !errors.As(err, &unknown) || unknown.Slot != 0 || unknown.Cgroup != 0xc0 || unknown.Scope == 0 || unknown.Scope != scope {
			t.Fatalf("typed unknown outcome %+v (want slot 0 cgroup 0xc0 scope %d): %v", unknown, scope, err)
		}
	}
	requestScope := func(r []byte) uint64 { return binary.LittleEndian.Uint64(r[sharedProductHeaderBytes+8:]) }
	t.Run("failed undo", func(t *testing.T) {
		f := newSharedCommanderFixture(t)
		var scope uint64
		f.fakes["opaque_real_route_publish"].respond = func(r []byte) uint32 {
			scope = requestScope(r)
			f.routes.set(0, routeOf(r, 0xc0))
			return sharedProductInvariant
		}
		_, err := f.cmd.publishFirst(t.Context(), 0, 0xc0, policy, init)
		if !errors.Is(err, errSharedPublishUnknown) || f.cmd.slots[0] != nil || len(f.cmd.used) != 1 {
			t.Fatalf("failed undo: %v used %v", err, f.cmd.used)
		}
		minted(t, err, scope)
	})
	t.Run("foreign route", func(t *testing.T) {
		f := newSharedCommanderFixture(t)
		var scope uint64
		f.fakes["opaque_real_route_publish"].respond = func(r []byte) uint32 {
			scope = requestScope(r)
			f.routes.set(0, routeOf(r, 0xd0))
			return 0
		}
		f.fakes["opaque_real_route_publish"].runErr = lost
		_, err := f.cmd.publishFirst(t.Context(), 0, 0xc0, policy, init)
		if !errors.Is(err, errSharedPublishUnknown) || !errors.Is(err, lost) {
			t.Fatalf("foreign route: %v", err)
		}
		minted(t, err, scope)
	})
}

// TestErrSharedPublishUnknownNilErr: a zero-value typed error falls back to
// the sentinel instead of panicking.
func TestErrSharedPublishUnknownNilErr(t *testing.T) {
	err := error(&ErrSharedPublishUnknown{Scope: 1})
	if err.Error() != errSharedPublishUnknown.Error() || !errors.Is(err, errSharedPublishUnknown) {
		t.Fatalf("nil Err: %q", err)
	}
}

// TestProductCommanderRevisionKeepsIdentity: a revision changing the root
// role (same UID) or the UID is refused before anything is staged.
func TestProductCommanderRevisionKeepsIdentity(t *testing.T) {
	f := newSharedCommanderFixture(t)
	policy, _ := sharedCompiledTestPolicy(t)
	if code, err := f.cmd.publishFirst(t.Context(), 0, 0xc0, policy, SharedInitIdentity{TGID: 1, StartTicks: 1, MountNS: 1}); err != nil || code != 0 {
		t.Fatal(code, err)
	}
	staged := len(f.fakes["opaque_real_policy_stage"].requests)
	for _, source := range []*fullpolicy.Policy{sharedTestSourcePolicy("p", "2", "web"), sharedTestSourcePolicy("q", "1", "app")} {
		next, err := SharedBindingPolicy{Source: source, Container: "app"}.compile(2, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.cmd.revise(t.Context(), 0, 0xc0, next); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "UID or root role") {
			t.Fatalf("%s/%s revision: %v", source.ID, source.RootRole, err)
		}
	}
	if n := len(f.fakes["opaque_real_policy_stage"].requests); n != staged {
		t.Fatalf("a refused revision staged %d cells", n-staged)
	}
}

// TestProductCommanderVerifyExiting: a verify refusal whose only mismatches
// were exiting tasks is a thread that exited mid-adoption; any other
// mismatch (or an unreadable state) is an identity refusal.
func TestProductCommanderVerifyExiting(t *testing.T) {
	f := newSharedCommanderFixture(t)
	f.fakes["opaque_real_adopt_verify"].code = sharedProductRefused
	state := func(iterated, bad, exiting uint32) []byte {
		raw := make([]byte, sharedProductAdoptStateBytes)
		binary.LittleEndian.PutUint32(raw[16:], iterated)
		binary.LittleEndian.PutUint32(raw[20:], bad)
		binary.LittleEndian.PutUint32(raw[44:], exiting)
		return raw
	}
	for name, tc := range map[string]struct {
		raw  []byte
		want bool
	}{
		"exiting only":           {state(3, 1, 1), true},
		"exiting leader":         {state(1, 1, 1), true},
		"exiting and a mismatch": {state(3, 2, 1), false},
		"mismatch only":          {state(3, 1, 0), false},
		"over the quota":         {state(uint32(f.cmd.profile.PerBinding.Tasks)+1, 1, 1), false},
	} {
		f.adoptState.set(0, tc.raw)
		code, exited, err := f.cmd.verify(t.Context(), 0, 9, SharedInitIdentity{})
		if err != nil || code != sharedProductRefused || exited != tc.want {
			t.Errorf("%s: %d %v %v, want exited %v", name, code, exited, err, tc.want)
		}
	}
}

// TestProductCommanderRefusesBeforeInstall: no route is published or
// revised before the product control installed the configuration (the
// gate that arms the hooks); nothing is staged.
func TestProductCommanderRefusesBeforeInstall(t *testing.T) {
	f := newSharedCommanderFixture(t)
	policy, _ := sharedCompiledTestPolicy(t)
	f.cmd.control.installed = false
	if _, err := f.cmd.publishFirst(t.Context(), 0, 1, policy, SharedInitIdentity{TGID: 1, StartTicks: 1, MountNS: 1}); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("publish before install: %v", err)
	}
	if _, err := f.cmd.revise(t.Context(), 0, 1, policy); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("revise before install: %v", err)
	}
	if n := len(f.fakes["opaque_real_policy_stage"].requests) + len(f.fakes["opaque_real_route_publish"].requests); n != 0 {
		t.Fatalf("%d commands ran before install", n)
	}
}

// sharedDrainClock is the commander's fake clock: every sleep advances it
// and is recorded, and onSleep (if set) runs after each one.
type sharedDrainClock struct {
	mu      sync.Mutex
	t       time.Time
	sleeps  []time.Duration
	onSleep func(elapsed time.Duration)
}

func installSharedDrainClock(c *productCommander) *sharedDrainClock {
	clock := &sharedDrainClock{t: time.Unix(1000, 0)}
	start := clock.t
	c.now = func() time.Time { clock.mu.Lock(); defer clock.mu.Unlock(); return clock.t }
	c.sleep = func(ctx context.Context, d time.Duration) error {
		clock.mu.Lock()
		clock.t = clock.t.Add(d)
		clock.sleeps = append(clock.sleeps, d)
		elapsed, hook := clock.t.Sub(start), clock.onSleep
		clock.mu.Unlock()
		if hook != nil {
			hook(elapsed)
		}
		return ctx.Err()
	}
	return clock
}

// TestProductCommanderRevisionDrain (G019 gap 3): a revision whose
// candidate record is still RETIRING with holders waits for them, dropping
// the record (opaque_real_route_drop_retired) as soon as they are gone,
// with a 1 ms -> 250 ms backoff, up to the drain timeout; on timeout its
// staged object is discarded, the refusal is retryable
// (ErrSharedRevisionDraining) and the slot is Degraded RevisionDrainTimeout
// with the holders; the next committed revision clears it.
func TestProductCommanderRevisionDrain(t *testing.T) {
	policy, _ := sharedCompiledTestPolicy(t)
	init := SharedInitIdentity{TGID: 1, StartTicks: 1, MountNS: 1}
	setup := func(t *testing.T) (*sharedCommanderFixture, *sharedHonestKernel, *sharedDrainClock) {
		f := newSharedCommanderFixture(t)
		k := installSharedHonestKernel(f)
		clock := installSharedDrainClock(f.cmd)
		if code, err := f.cmd.publishFirst(t.Context(), 0, 100, policy, init); err != nil || code != sharedProductOK {
			t.Fatalf("publish: %d %v", code, err)
		}
		// Generation 1 is held (two early claims) when generation 2
		// commits: it stays RETIRING with its holders.
		k.set(func(k *sharedHonestKernel) { k.holders[0] = 2 })
		if code, err := f.cmd.revise(t.Context(), 0, 100, policy); err != nil || code != sharedProductOK {
			t.Fatalf("revision 2 while generation 1 is held: %d %v", code, err)
		}
		return f, k, clock
	}

	t.Run("timeout", func(t *testing.T) {
		f, k, clock := setup(t)
		f.cmd.revisionDrainTimeout = 2 * time.Second
		_, err := f.cmd.revise(t.Context(), 0, 100, policy)
		if !errors.Is(err, ErrSharedRevisionDraining) || !errors.Is(err, ErrSharedRetryableRefusal) || !strings.Contains(err.Error(), "retryable refusal (in-flight claims or pins)") {
			t.Fatalf("revision 3 with generation 1 held: %v, want ErrSharedRevisionDraining", err)
		}
		st, ok := f.cmd.revisionReport(0)
		if !ok || st.Reason != RevisionDrainTimeout || st.Generation != 1 || st.EarlyClaims != 2 {
			t.Fatalf("report %+v %v", st, ok)
		}
		var waited time.Duration
		for i, d := range clock.sleeps {
			if want := min(time.Millisecond<<i, 250*time.Millisecond); d != want {
				t.Fatalf("sleep %d is %s, want %s (backoff 1 ms doubling to 250 ms)", i, d, want)
			}
			waited += d
		}
		if waited < 2*time.Second || waited > 2*time.Second+250*time.Millisecond {
			t.Fatalf("waited %s for a 2 s drain timeout", waited)
		}
		f.cmd.mu.Lock()
		staged := len(f.cmd.staging)
		used := len(f.cmd.used)
		f.cmd.mu.Unlock()
		// Held: generation 2's object and generation 1's (stale, pinned);
		// generation 3's staged object was discarded.
		if staged != 0 || used != 2 {
			t.Fatalf("after the timeout: staging %d used %d, want the staged object discarded", staged, used)
		}
		// The holders leave: the next revision drops generation 1 and
		// commits; the report clears.
		k.set(func(k *sharedHonestKernel) { k.retiringHolders[0] = 0 })
		if code, err := f.cmd.revise(t.Context(), 0, 100, policy); err != nil || code != sharedProductOK {
			t.Fatalf("revision 3 after the holders left: %d %v", code, err)
		}
		if _, ok := f.cmd.revisionReport(0); ok {
			t.Fatal("RevisionDrainTimeout not cleared by the committed revision")
		}
	})

	t.Run("drained within the timeout", func(t *testing.T) {
		f, k, clock := setup(t)
		clock.onSleep = func(elapsed time.Duration) {
			if elapsed >= 50*time.Millisecond {
				k.set(func(k *sharedHonestKernel) { k.retiringHolders[0] = 0 })
			}
		}
		if code, err := f.cmd.revise(t.Context(), 0, 100, policy); err != nil || code != sharedProductOK {
			t.Fatalf("revision 3 drained mid-wait: %d %v", code, err)
		}
		if _, ok := f.cmd.revisionReport(0); ok || len(clock.sleeps) == 0 {
			t.Fatalf("drained revision: report %v, %d sleeps", ok, len(clock.sleeps))
		}
		if d := f.fakes["opaque_real_route_drop_retired"]; len(d.requests) == 0 {
			t.Fatal("no opaque_real_route_drop_retired issued")
		} else if body := d.requests[0][sharedProductHeaderBytes:]; binary.LittleEndian.Uint32(body) != 0 ||
			binary.LittleEndian.Uint64(body[8:]) == 0 || binary.LittleEndian.Uint64(body[16:]) != 1 {
			t.Fatalf("drop_retired request %x, want slot 0, the route scope and generation 1", body)
		}
	})

	t.Run("drain timeout is clamped", func(t *testing.T) {
		c := &productCommander{}
		for set, want := range map[time.Duration]time.Duration{0: DefaultRevisionDrainTimeout, -1: DefaultRevisionDrainTimeout, time.Second: time.Second, time.Hour: MaxRevisionDrainTimeout} {
			c.revisionDrainTimeout = set
			if got := c.drainTimeout(); got != want {
				t.Errorf("drain timeout %s -> %s, want %s", set, got, want)
			}
		}
	})
}

// TestProductCommanderObjectStarved (G019 gap 3): at Bindings+1 objects (the
// admission floor; the product default is 2 x Bindings, see
// TestProductCommanderNotStarvedAtDefault) a
// RETIRING record with holders keeps the only spare object; the other
// slot's revision is refused retryably and, past the drain timeout, its slot
// is Degraded RevisionObjectStarved; once the holders leave, the next stage
// drops the record (drop_retired before the release) and the revision
// commits, clearing the report.
func TestProductCommanderObjectStarved(t *testing.T) {
	policy, _ := sharedCompiledTestPolicy(t)
	init := SharedInitIdentity{TGID: 1, StartTicks: 1, MountNS: 1}
	f := newSharedCommanderFixtureFor(t, sharedFloorProfile())
	k := installSharedHonestKernel(f)
	clock := installSharedDrainClock(f.cmd)
	f.cmd.revisionDrainTimeout = time.Second
	for slot := range uint32(2) {
		if code, err := f.cmd.publishFirst(t.Context(), slot, uint64(100+slot), policy, init); err != nil || code != sharedProductOK {
			t.Fatalf("slot %d: %d %v", slot, code, err)
		}
	}
	k.set(func(k *sharedHonestKernel) { k.holders[0] = 1 })
	if code, err := f.cmd.revise(t.Context(), 0, 100, policy); err != nil || code != sharedProductOK {
		t.Fatalf("revision of slot 0 while held: %d %v", code, err)
	}
	for i := 0; i < 2; i++ {
		if _, err := f.cmd.revise(t.Context(), 1, 101, policy); !errors.Is(err, ErrSharedRetryableRefusal) || !strings.Contains(err.Error(), "retryable") {
			t.Fatalf("slot 1 revision %d with no spare object: %v, want the retryable refusal", i, err)
		}
		if st, ok := f.cmd.revisionReport(1); ok != (i == 1) || (ok && st.Reason != RevisionObjectStarved) {
			t.Fatalf("slot 1 refusal %d: report %+v %v", i, st, ok)
		}
		clock.mu.Lock()
		clock.t = clock.t.Add(time.Second)
		clock.mu.Unlock()
	}
	k.set(func(k *sharedHonestKernel) { k.retiringHolders[0] = 0 })
	if code, err := f.cmd.revise(t.Context(), 1, 101, policy); err != nil || code != sharedProductOK {
		t.Fatalf("slot 1 revision after the holders left: %d %v", code, err)
	}
	if _, ok := f.cmd.revisionReport(1); ok {
		t.Fatal("RevisionObjectStarved not cleared")
	}
}

// TestProductCommanderNotStarvedAtDefault (G020 carryover, D3 user
// decision): at the product default of 2 x Bindings objects, slot 0's
// RETIRING record held by a blocked exec keeps its object, yet slot 1 still
// revises (twice: each commit releases its own previous object) with no
// refusal and no report. The held slot itself is the residual: its next
// revision needs the held record (a binding has two records) and waits for
// its drain (Degraded RevisionDrainTimeout past the timeout, the last good
// revision still enforced: TestProductCommanderRevisionDrain).
func TestProductCommanderNotStarvedAtDefault(t *testing.T) {
	policy, _ := sharedCompiledTestPolicy(t)
	init := SharedInitIdentity{TGID: 1, StartTicks: 1, MountNS: 1}
	f := newSharedCommanderFixture(t)
	if p := sharedCandidateQualificationProfile(); p.PolicySlots[0] != 2*p.Bindings {
		t.Fatalf("default profile %v / %d bindings is not 2 x Bindings", p.PolicySlots, p.Bindings)
	}
	k := installSharedHonestKernel(f)
	installSharedDrainClock(f.cmd)
	for slot := range uint32(2) {
		if code, err := f.cmd.publishFirst(t.Context(), slot, uint64(100+slot), policy, init); err != nil || code != sharedProductOK {
			t.Fatalf("slot %d: %d %v", slot, code, err)
		}
	}
	k.set(func(k *sharedHonestKernel) { k.holders[0] = 1 })
	if code, err := f.cmd.revise(t.Context(), 0, 100, policy); err != nil || code != sharedProductOK {
		t.Fatalf("revision of slot 0 while held: %d %v", code, err)
	}
	for i := range 2 {
		if code, err := f.cmd.revise(t.Context(), 1, 101, policy); err != nil || code != sharedProductOK {
			t.Fatalf("slot 1 revision %d with slot 0's RETIRING record held: %d %v, want it committed (2 x Bindings)", i, code, err)
		}
		if st, ok := f.cmd.revisionReport(1); ok {
			t.Fatalf("slot 1 revision %d: report %+v", i, st)
		}
	}
}

// TestProductCommanderRevisionRootEpochRefused (G019 gap 3 hardening): the
// binding's catalogue is write-once per (scope, UID), so a revision with
// another root epoch is refused up front, terminally (code 2, no retry):
// its staged object is released, the slot keeps its object and the epoch
// cell is unchanged; the request carried the new epoch in its metadata.
func TestProductCommanderRevisionRootEpochRefused(t *testing.T) {
	f := newSharedCommanderFixture(t)
	k := installSharedHonestKernel(f)
	policy, compiled := sharedCompiledTestPolicy(t)
	init := SharedInitIdentity{TGID: 1, StartTicks: 1, MountNS: 1}
	if code, err := f.cmd.publishFirst(t.Context(), 0, 100, policy, init); err != nil || code != sharedProductOK {
		t.Fatalf("publish: %d %v", code, err)
	}
	other, err := SharedBindingPolicy{Source: sharedTestSourcePolicy("p", "1", "app"), Container: "app"}.compile(7, nil)
	if err != nil {
		t.Fatal(err)
	}
	otherCompiled, err := sharedCompiledPolicyOf(other.program, other.object)
	if err != nil || otherCompiled.UID != compiled.UID || otherCompiled.RootEpoch == compiled.RootEpoch {
		t.Fatalf("fixture: root epochs %d / %d (UIDs %d / %d): %v", compiled.RootEpoch, otherCompiled.RootEpoch, compiled.UID, otherCompiled.UID, err)
	}
	k.mu.Lock()
	cellBefore := k.epochCell[0]
	k.mu.Unlock()
	f.cmd.mu.Lock()
	objectBefore := f.cmd.slots[0].object
	f.cmd.mu.Unlock()
	code, err := f.cmd.revise(t.Context(), 0, 100, other)
	if err != nil || code != sharedProductRefused {
		t.Fatalf("revision with root epoch %d: %d %v, want the terminal refusal (code 2)", otherCompiled.RootEpoch, code, err)
	}
	requests := f.fakes["opaque_real_route_publish"].requests
	if meta := requests[len(requests)-1][sharedProductHeaderBytes+80:]; binary.LittleEndian.Uint64(meta) != otherCompiled.RootEpoch {
		t.Fatalf("revision request root epoch %d, want %d", binary.LittleEndian.Uint64(meta), otherCompiled.RootEpoch)
	}
	if len(requests) != 2 {
		t.Fatalf("%d publish requests: a terminal refusal is never retried", len(requests))
	}
	k.mu.Lock()
	cellAfter := k.epochCell[0]
	k.mu.Unlock()
	f.cmd.mu.Lock()
	defer f.cmd.mu.Unlock()
	if cellAfter != cellBefore || f.cmd.slots[0].object != objectBefore || len(f.cmd.slots[0].stale) != 0 || len(f.cmd.used) != 1 || len(f.cmd.staging) != 0 {
		t.Fatalf("after the refusal: cell %v (was %v), object %d (was %d), stale %v, used %v", cellAfter, cellBefore, f.cmd.slots[0].object, objectBefore, f.cmd.slots[0].stale, f.cmd.used)
	}
}
