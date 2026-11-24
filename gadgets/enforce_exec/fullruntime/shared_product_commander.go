// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// Stage operations (OPAQUE_REAL_STAGE_*) and wire sizes of the product
// commands not covered in shared_product_wire.go.
const (
	sharedStageBegin    = 1
	sharedStageWrite    = 2
	sharedStageFinalize = 3
	sharedStageAbort    = 4
	sharedStageRetire   = 5
	sharedStageReclaim  = 6

	sharedProductStageRequestBytes   = 352 // struct opaque_real_policy_stage_request
	sharedProductPublishRequestBytes = 520 // struct opaque_real_route_publish_request
	sharedProductObjectBytes         = 80  // struct se_shared_object (lock, se_object)
	sharedSnapshotMetadataBytes      = 416 // struct se_snapshot_metadata
)

// sharedObjectPhase values (SE_OBJECT_*).
const (
	sharedObjectFree  = 0
	sharedObjectReady = 2
)

// sharedBytesMap is the read-only map surface the commander needs.
type sharedBytesMap interface {
	LookupBytes(key interface{}) ([]byte, error)
}

// productCommander encodes the product commands over the node's admin
// thread (sharedProductControl) and reads back the maps they change. It owns
// the per-slot route scope and the policy objects each slot holds.
type productCommander struct {
	control                     *sharedProductControl
	routes, objects, adoptState sharedBytesMap
	profile                     SharedProfile
	random                      func() (uint64, error)

	// stageMu serializes object selection and staging: two concurrent first
	// publications never pick the same FREE object.
	stageMu sync.Mutex
	mu      sync.Mutex
	slots   map[uint32]*productSlot
	used    map[uint32]bool // object indexes held (staged, published or awaiting release)
	// orphans are objects of failed publications whose release failed; each
	// stage retries them first, so a release failure never leaks c.used.
	orphans []uint32
	// staging holds the objects a publication or revision staged whose
	// outcome is not recorded yet (stageMu is released before the publish):
	// once recorded, a revision's previous object becomes stale and a failed
	// publication's object is released, so a stage that finds no FREE object
	// while any is in flight refuses retryably, never terminally (review M1).
	staging map[uint32]bool
	// releasing counts objects taken off a stale list whose release is in
	// progress; releases counts completed releases. A stage that finds no
	// FREE object refuses retryably while either shows an object may have
	// been freed after its scan.
	releasing int
	releases  uint64

	// G019 gap 3: the revision drain (shared_revision_drain.go).
	// revisionDrainTimeout bounds the wait for a RETIRING record's holders
	// (0: DefaultRevisionDrainTimeout); now and sleep are clock seams;
	// bindings (optional) reads a record's readers for the reports.
	revisionDrainTimeout time.Duration
	now                  func() time.Time
	sleep                func(context.Context, time.Duration) error
	bindings             sharedBytesMap
	starvedSince         map[uint32]time.Time
	revisionStatus       map[uint32]*SharedRevisionStatus

	// image is the G020 image index (shared_product_image.go); nil: every
	// publication carries no image (handle 0).
	image *productImageIndex
}

type productSlot struct {
	scope         uint64
	uid, rootRole uint64 // the published policy's identity (revisions keep it)
	object        uint32 // the ACTIVE record's object
	stale         []uint32
}

// sharedProductInvariant is a command's -1: an undo that failed; the
// command's outcome is unknown.
const sharedProductInvariant = ^uint32(0)

// errSharedPublishUnknown: a first publication whose outcome could not be
// confirmed (lost reply or failed undo) and whose route read back is not
// this node's committed route, or unreadable. The slot is latched: its
// object stays held and the route is never withdrawn or reused before node
// teardown (reported Degraded, PublishUnconfirmed).
var errSharedPublishUnknown = errors.New("first publication outcome unknown")

// ErrSharedPublishUnknown is the typed errSharedPublishUnknown (it wraps it
// and the cause, so errors.Is on either still holds). Scope is the route
// scope this commander minted for the request: the latched route, if the
// kernel committed it, carries it in its events. It is NOT a confirmed
// scope: a caller may use it only to tombstone the binding's late events
// on unbind, never to attribute one (the outcome stays unknown).
type ErrSharedPublishUnknown struct {
	Slot   uint32
	Cgroup uint64
	Scope  uint64
	Err    error
}

func (e *ErrSharedPublishUnknown) Error() string { return e.Unwrap().Error() }

// Unwrap returns Err, or the sentinel when Err is nil (never panics).
func (e *ErrSharedPublishUnknown) Unwrap() error {
	if e.Err == nil {
		return errSharedPublishUnknown
	}
	return e.Err
}

func newProductCommander(control *sharedProductControl, routes, objects, adoptState sharedBytesMap, profile SharedProfile) *productCommander {
	return &productCommander{
		control: control, routes: routes, objects: objects, adoptState: adoptState, profile: profile,
		random: sharedRandomIdentity, slots: map[uint32]*productSlot{}, used: map[uint32]bool{},
		staging: map[uint32]bool{}, starvedSince: map[uint32]time.Time{}, revisionStatus: map[uint32]*SharedRevisionStatus{},
	}
}

// sharedObjectState is the part of se_object the stager reads.
type sharedObjectState struct {
	Generation   uint64
	Phase, Pins  uint32
	Length, Rule uint32
}

func decodeSharedObject(raw []byte) (sharedObjectState, error) {
	if len(raw) != sharedProductObjectBytes {
		return sharedObjectState{}, fmt.Errorf("object is %d bytes, want %d", len(raw), sharedProductObjectBytes)
	}
	// se_shared_object: lock (4) + pad (4), then se_object.
	return sharedObjectState{
		Generation: binary.LittleEndian.Uint64(raw[8:]),
		Phase:      binary.LittleEndian.Uint32(raw[48:]),
		Length:     binary.LittleEndian.Uint32(raw[52:]),
		Pins:       binary.LittleEndian.Uint32(raw[60:]),
		Rule:       binary.LittleEndian.Uint32(raw[68:]),
	}, nil
}

// sharedObjectCapacity mirrors se_object_capacity / se_object_range: object
// indexes are laid out by class (256, 1024, 4096, 16384 cells).
func sharedObjectCapacity(p SharedProfile, object uint32) (uint32, bool) {
	sizes := [4]uint32{256, 1024, 4096, 16384}
	index := uint64(object)
	for class, count := range p.PolicySlots {
		if index < count {
			return sizes[class], true
		}
		index -= count
	}
	return 0, false
}

func sharedProductStageBody(op, object, index, count, class uint32, generation, attempt uint64, cell *fullpolicy.Blob) []byte {
	b := make([]byte, sharedProductStageRequestBytes-sharedProductHeaderBytes)
	binary.LittleEndian.PutUint64(b[0:], generation)
	binary.LittleEndian.PutUint64(b[8:], attempt)
	binary.LittleEndian.PutUint32(b[16:], op)
	binary.LittleEndian.PutUint32(b[20:], object)
	binary.LittleEndian.PutUint32(b[24:], index)
	binary.LittleEndian.PutUint32(b[28:], count)
	binary.LittleEndian.PutUint32(b[32:], class)
	if cell != nil {
		copy(b[40:], cell[:])
	}
	return b
}

// sharedPublishFields is the body of opaque_real_route_publish.
type sharedPublishFields struct {
	cgroup, scope, generationExpected, objectGeneration uint64
	init                                                SharedInitIdentity
	initRole                                            uint64
	slot, class, object, bank                           uint32
	policy                                              sharedCompiledPolicy
	container                                           string
	// imageHandle/imageDev: the binding's sealed image set and its root
	// overlay's kernel dev_t (G020); both zero without one.
	imageHandle uint64
	imageDev    uint32
	// execMap: se_snapshot_metadata.exec_map_flags (sharedExecMapFlags).
	execMap uint32
}

func sharedProductPublishBody(f sharedPublishFields) ([]byte, error) {
	if len(f.container) == 0 || len(f.container) > 255 {
		return nil, fmt.Errorf("container name length %d", len(f.container))
	}
	b := make([]byte, sharedProductPublishRequestBytes-sharedProductHeaderBytes)
	le := binary.LittleEndian
	for i, v := range []uint64{f.cgroup, f.scope, f.generationExpected, f.objectGeneration, f.init.StartTicks, f.init.MountNS, f.initRole} {
		le.PutUint64(b[8*i:], v)
	}
	for i, v := range []uint32{f.slot, f.class, f.object, f.init.TGID, f.bank} {
		le.PutUint32(b[56+4*i:], v)
	}
	if (f.imageHandle == 0) != (f.imageDev == 0) || f.imageDev>>sharedKernelMinorBits != 0 {
		return nil, fmt.Errorf("image handle %d with overlay dev %#x", f.imageHandle, f.imageDev)
	}
	if f.execMap&^sharedExecMapFlagsKnown != 0 || (f.execMap&sharedExecMapFlagJudge != 0 && f.imageHandle == 0) ||
		(f.execMap != 0 && f.execMap&sharedExecMapFlagJudge == 0) {
		return nil, fmt.Errorf("executable-mapping flags %#x with image handle %d", f.execMap, f.imageHandle)
	}
	// struct se_snapshot_metadata: root_epochs[8], policy_uids[8],
	// image_handle, role_writers, required_known, container_length,
	// container[256], image_dev, exec_map_flags, exec_map_reserved. One
	// policy (count 1).
	m := b[80 : 80+sharedSnapshotMetadataBytes]
	le.PutUint64(m[0:], f.policy.RootEpoch)
	le.PutUint64(m[64:], f.policy.UID)
	le.PutUint64(m[128:], f.imageHandle)
	le.PutUint32(m[144:], uint32(len(f.container)))
	copy(m[148:], f.container)
	le.PutUint32(m[404:], f.imageDev)
	le.PutUint32(m[sharedExecMapMetadataOffset:], f.execMap)
	return b, nil
}

func (c *productCommander) object(index uint32) (sharedObjectState, error) {
	raw, err := c.objects.LookupBytes(index)
	if err != nil {
		return sharedObjectState{}, err
	}
	return decodeSharedObject(raw)
}

// stage writes the compiled policy into the smallest FREE object whose class
// fits it and returns the object and its new generation. A failure aborts
// the object. A staged object stays in flight (c.staging) until the caller
// settles it after recording the publication's outcome.
func (c *productCommander) stage(ctx context.Context, policy sharedCompiledPolicy) (uint32, uint64, error) {
	c.stageMu.Lock()
	defer c.stageMu.Unlock()
	c.retryOrphans(ctx)
	c.retryStale(ctx)
	admission, err := c.profile.Validate()
	if err != nil {
		return 0, 0, err
	}
	cells := uint32(len(policy.Entries))
	c.mu.Lock()
	releases := c.releases
	c.mu.Unlock()
	chosen, best := uint32(0), uint32(0)
	for index := uint32(0); index < uint32(admission.PolicyObjects); index++ {
		capacity, _ := sharedObjectCapacity(c.profile, index)
		c.mu.Lock()
		used := c.used[index]
		c.mu.Unlock()
		if used || capacity < cells || (best != 0 && capacity >= best) {
			continue
		}
		state, err := c.object(index)
		if err != nil {
			return 0, 0, err
		}
		if state.Phase == sharedObjectFree && state.Pins == 0 {
			chosen, best = index, capacity
		}
	}
	if best == 0 {
		// A held object a revision or recycle retired (stale) or a failed
		// publication left (orphan) is freed once its pins drain, and an
		// in-flight publication frees one once its outcome is recorded:
		// retry later (the publisher's retryable refusal). Only when every
		// fitting object is held by a live route is the refusal terminal.
		if c.drainPending(cells, releases) {
			return 0, 0, fmt.Errorf("stage: %w: no free policy object for %d cells until a retired object's pins drain", ErrSharedRetryableRefusal, cells)
		}
		return 0, 0, fmt.Errorf("no free policy object for %d cells", cells)
	}
	state, err := c.object(chosen)
	if err != nil {
		return 0, 0, err
	}
	attempt, err := c.random()
	if err != nil {
		return 0, 0, err
	}
	generation := state.Generation + 1
	run := func(body []byte) error {
		code, err := c.control.run(ctx, "opaque_real_policy_stage", body)
		return sharedProductCodeError("stage", code, err)
	}
	if err := run(sharedProductStageBody(sharedStageBegin, chosen, 0, cells, 0, state.Generation, attempt, nil)); err != nil {
		return 0, 0, err
	}
	c.mu.Lock()
	c.used[chosen] = true // held from BEGIN: a failed stage releases it below
	c.mu.Unlock()
	stageErr := func() error {
		for i := range policy.Entries {
			if err := run(sharedProductStageBody(sharedStageWrite, chosen, uint32(i), 0, 0, generation, attempt, &policy.Entries[i])); err != nil {
				return err
			}
		}
		return run(sharedProductStageBody(sharedStageFinalize, chosen, 0, policy.Rules, policy.Class, generation, attempt, nil))
	}()
	if stageErr != nil {
		abort := run(sharedProductStageBody(sharedStageAbort, chosen, 0, 0, 0, generation, attempt, nil))
		c.mu.Lock()
		if abort == nil {
			delete(c.used, chosen)
		} else {
			c.orphans = append(c.orphans, chosen)
		}
		c.mu.Unlock()
		return 0, 0, fmt.Errorf("stage object %d: %w", chosen, joinIfErr(stageErr, abort))
	}
	c.mu.Lock()
	c.staging[chosen] = true
	c.mu.Unlock()
	return chosen, generation, nil
}

// settle ends a staged object's flight once its publication's outcome is
// recorded (published, stale, released or orphaned).
func (c *productCommander) settle(object uint32) {
	c.mu.Lock()
	delete(c.staging, object)
	c.mu.Unlock()
}

// drainPending: an object may be freed without this node publishing
// anything new: a publication or revision is in flight, a release is in
// progress or completed after the scan (releases moved past since), or a
// held object that fits cells is stale (retired by a revision or recycle)
// or orphaned (a failed publication's) and still awaiting release, i.e. it
// is freed once its pins drain.
func (c *productCommander) drainPending(cells uint32, since uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.staging) != 0 || c.releasing != 0 || c.releases != since {
		return true
	}
	fits := func(object uint32) bool {
		capacity, ok := sharedObjectCapacity(c.profile, object)
		return ok && capacity >= cells && c.used[object]
	}
	for _, object := range c.orphans {
		if fits(object) {
			return true
		}
	}
	for _, slot := range c.slots {
		for _, object := range slot.stale {
			if fits(object) {
				return true
			}
		}
	}
	return false
}

func joinIfErr(err, cleanup error) error {
	if cleanup == nil {
		return err
	}
	return errors.Join(err, fmt.Errorf("cleanup: %w", cleanup))
}

// discard releases the object of a failed publication; one whose release
// fails is kept as an orphan (still held) and retried by the next stage.
func (c *productCommander) discard(ctx context.Context, object uint32) {
	if !c.release(ctx, object) {
		c.mu.Lock()
		c.orphans = append(c.orphans, object)
		c.mu.Unlock()
	}
}

// retryOrphans retries the release of every orphaned object (stageMu held).
func (c *productCommander) retryOrphans(ctx context.Context) {
	c.mu.Lock()
	orphans := c.orphans
	c.orphans = nil
	c.mu.Unlock()
	for _, object := range orphans {
		c.discard(ctx, object)
	}
}

// retryStale retries the release of every published slot's retired objects
// (stageMu held), so a retryable stage refusal makes progress once their
// pins drain, without waiting for that slot's next revision.
func (c *productCommander) retryStale(ctx context.Context) {
	c.mu.Lock()
	records := make(map[uint32]*productSlot, len(c.slots))
	for slot, record := range c.slots {
		if len(record.stale) != 0 {
			records[slot] = record
		}
	}
	c.mu.Unlock()
	for slot, record := range records {
		c.releaseStale(ctx, slot, record)
	}
}

// release retires and reclaims an object no record pins any more; an object
// still pinned stays held and is retried by the slot's next recycle. A
// LOADING object (an abort that failed) is aborted first.
func (c *productCommander) release(ctx context.Context, object uint32) bool {
	state, err := c.object(object)
	if err != nil {
		return false
	}
	if state.Phase == sharedObjectReady {
		if code, err := c.control.run(ctx, "opaque_real_policy_stage", sharedProductStageBody(sharedStageRetire, object, 0, 0, 0, state.Generation, 0, nil)); err != nil || code != sharedProductOK {
			return false
		}
	}
	if state.Phase != sharedObjectFree {
		if code, err := c.control.run(ctx, "opaque_real_policy_stage", sharedProductStageBody(sharedStageReclaim, object, 0, 0, 0, state.Generation, 0, nil)); err != nil || code != sharedProductOK {
			return false
		}
	}
	c.mu.Lock()
	delete(c.used, object)
	c.releases++
	c.mu.Unlock()
	return true
}

func (c *productCommander) compiled(policy SharedBindingPolicy) (sharedCompiledPolicy, error) {
	if policy.program == nil {
		return sharedCompiledPolicy{}, fmt.Errorf("product publication requires a compiled policy (Source)")
	}
	return sharedCompiledPolicyOf(policy.program, policy.object)
}

// armed refuses publication unless the product control is installed (the
// configuration gate armed the hooks): a route is never published over
// unarmed hooks (G019 chain14).
func (c *productCommander) armed() error {
	if c.control == nil || !c.control.installed {
		return fmt.Errorf("product control not installed (hooks unarmed): %w", ErrSharedNativeUnavailable)
	}
	return nil
}

func (c *productCommander) publishFirst(ctx context.Context, slot uint32, cgroup uint64, policy SharedBindingPolicy, init SharedInitIdentity) (uint32, error) {
	if err := c.armed(); err != nil {
		return 0, err
	}
	compiled, err := c.compiled(policy)
	if err != nil {
		return 0, err
	}
	if compiled.RootRole == 0 {
		return 0, fmt.Errorf("compiled policy has no root role")
	}
	if uint64(slot) >= c.profile.AcceptedUIDs {
		return 0, fmt.Errorf("slot %d has no epoch bank (accepted UIDs %d)", slot, c.profile.AcceptedUIDs)
	}
	scope, err := c.random()
	if err != nil {
		return 0, err
	}
	// G020: the binding's image set, built before the route opens (its
	// PREPARE references it). Required by a FromImage policy; otherwise
	// best effort (a binding without one publishes handle 0).
	imageHandle, imageDev, err := c.image.build(ctx, slot, scope, init)
	if err != nil {
		if sharedPolicyUsesImage(policy.Source) {
			return 0, fmt.Errorf("publish slot %d (FromImage policy): %w", slot, err)
		}
		imageHandle, imageDev = 0, 0
	}
	execMap, err := sharedExecMapFlags(policy.ExecMap, policy.Source, imageHandle)
	if err != nil {
		return 0, joinIfErr(fmt.Errorf("publish slot %d: %w", slot, err), c.image.discard(context.WithoutCancel(ctx), slot))
	}
	object, generation, err := c.stage(ctx, compiled)
	if err != nil {
		return 0, joinIfErr(err, c.image.discard(context.WithoutCancel(ctx), slot))
	}
	defer c.settle(object)
	// M4: one policy per binding, so the slot's epoch-bank cell is its own
	// (bank = slot; AcceptedUIDs >= Bindings is checked above).
	body, err := sharedProductPublishBody(sharedPublishFields{
		cgroup: cgroup, scope: scope, objectGeneration: generation, init: init, initRole: compiled.RootRole,
		slot: slot, class: compiled.Class, object: object, bank: slot, policy: compiled, container: policy.Container,
		imageHandle: imageHandle, imageDev: imageDev, execMap: execMap,
	})
	if err != nil {
		c.discard(context.WithoutCancel(ctx), object)
		return 0, joinIfErr(err, c.image.discard(context.WithoutCancel(ctx), slot))
	}
	code, err := c.control.run(ctx, "opaque_real_route_publish", body)
	record := func() {
		c.mu.Lock()
		c.slots[slot] = &productSlot{scope: scope, uid: compiled.UID, rootRole: compiled.RootRole, object: object}
		c.mu.Unlock()
	}
	switch {
	case err == nil && code == sharedProductOK:
		record()
		return code, nil
	case err == nil && code != sharedProductInvariant:
		// Refused: BPF undid everything it did, the image reference
		// included (the set is RETIRING or was never referenced): free it.
		c.discard(context.WithoutCancel(ctx), object)
		return code, c.image.discard(context.WithoutCancel(ctx), slot)
	}
	// Outcome unknown (lost reply, or an undo that failed): the route read
	// back decides (review M2). Only this node's own scope and cgroup on a
	// non-FREE route after a lost reply count as committed; the scope is
	// the one this commander generated, never taken from the kernel.
	route, readErr := c.productRoute(slot)
	switch {
	case readErr == nil && route.State.Phase == 0:
		c.discard(context.WithoutCancel(ctx), object)
		return code, joinIfErr(err, c.image.discard(context.WithoutCancel(ctx), slot))
	case readErr == nil && err != nil && route.State.Scope == scope && route.State.Cgroup == cgroup:
		// Committed, then the reply was lost: record it (scope, object,
		// identity; the epoch is the compiled one this request carried),
		// so revision, adoption and withdraw work as after a confirmed one.
		record()
		return sharedProductOK, nil
	}
	cause := errors.Join(err, readErr)
	if cause == nil {
		cause = fmt.Errorf("invariant code %d", int32(code))
	}
	return code, &ErrSharedPublishUnknown{
		Slot: slot, Cgroup: cgroup, Scope: scope,
		Err: fmt.Errorf("publish slot %d (route read back %+v): %w: %w", slot, route.State, cause, errSharedPublishUnknown),
	}
}

func (c *productCommander) revise(ctx context.Context, slot uint32, cgroup uint64, policy SharedBindingPolicy) (uint32, error) {
	if err := c.armed(); err != nil {
		return 0, err
	}
	compiled, err := c.compiled(policy)
	if err != nil {
		return 0, err
	}
	c.mu.Lock()
	record := c.slots[slot]
	c.mu.Unlock()
	if record == nil {
		return 0, fmt.Errorf("slot %d has no product route", slot)
	}
	// G019 limit (lead decision, fail-closed): a revision keeps the policy
	// UID and its root role; either change is terminal.
	if compiled.UID != record.uid || compiled.RootRole != record.rootRole {
		return 0, fmt.Errorf("revision changes the policy UID or root role: %w", ErrSharedNativeUnavailable)
	}
	route, err := c.productRoute(slot)
	if err != nil {
		return 0, err
	}
	// G020: a revision keeps the binding's image set (no refresh: the
	// container's rootfs is immutable for its lifetime); both records
	// reference it during the grace period. The mapping gate's flags are
	// checked against it before anything is staged.
	imageHandle, imageDev := c.image.sealed(slot, record.scope)
	execMap, err := sharedExecMapFlags(policy.ExecMap, policy.Source, imageHandle)
	if err != nil {
		return 0, fmt.Errorf("revise slot %d: %w", slot, err)
	}
	object, generation, err := c.stage(ctx, compiled)
	if err != nil {
		// G019 gap 3: no free object while every spare one is held by a
		// RETIRING record; past the drain timeout the slot is Degraded
		// (RevisionObjectStarved). The refusal stays retryable.
		if errors.Is(err, ErrSharedRetryableRefusal) {
			c.starved(slot)
		}
		return 0, err
	}
	c.clearRevision(slot, false)
	defer c.settle(object)
	if imageHandle == 0 && sharedPolicyUsesImage(policy.Source) {
		c.discard(context.WithoutCancel(ctx), object)
		return 0, fmt.Errorf("revise slot %d (FromImage policy): %w: the binding has no sealed image set", slot, ErrSharedImageIndexUnavailable)
	}
	body, err := sharedProductPublishBody(sharedPublishFields{
		cgroup: cgroup, scope: record.scope, generationExpected: route.State.Generation, objectGeneration: generation,
		initRole: compiled.RootRole, slot: slot, class: compiled.Class, object: object, bank: slot, policy: compiled, container: policy.Container,
		imageHandle: imageHandle, imageDev: imageDev, execMap: execMap,
	})
	if err != nil {
		c.discard(context.WithoutCancel(ctx), object)
		return 0, err
	}
	// G019 gap 3: a retryable refusal while the slot's candidate record is
	// still RETIRING with holders waits for them (dropping the record as
	// soon as they are gone), bounded by the drain timeout; on timeout the
	// staged object is discarded and the slot reported Degraded.
	deadline := c.clock().Add(c.drainTimeout())
	for {
		code, err := c.control.run(ctx, "opaque_real_route_publish", body)
		if err == nil && code == sharedProductOK {
			break
		}
		if err == nil && code == sharedProductRetry {
			if _, _, _, held, rerr := c.retiring(slot); rerr == nil && held {
				drained, derr := c.drainForRevision(ctx, slot, deadline)
				if derr == nil && drained && c.clock().Before(deadline) {
					continue
				}
				c.discard(context.WithoutCancel(ctx), object)
				if derr != nil {
					return code, derr
				}
				if drained {
					c.reportRevision(SharedRevisionStatus{Reason: RevisionDrainTimeout, Slot: slot})
				}
				return code, ErrSharedRevisionDraining
			}
		}
		c.discard(context.WithoutCancel(ctx), object)
		return code, err
	}
	c.clearRevision(slot, true)
	code := uint32(sharedProductOK)
	c.mu.Lock()
	previous := record.object
	record.object = object
	record.stale = append(record.stale, previous)
	c.mu.Unlock()
	c.releaseStale(ctx, slot, record)
	return code, nil
}

// releaseStale releases the objects of retired records that are no longer
// pinned; the rest stay held for a later attempt: on the record while it is
// still the slot's, as orphans once a recycle detached it (review M2: a
// failure appended to a detached record would leak the object's c.used).
func (c *productCommander) releaseStale(ctx context.Context, slot uint32, record *productSlot) {
	// G019 gap 3: a stale object is pinned by the slot's RETIRING record
	// until that record is dropped (best effort here; holders keep it).
	_, _ = c.dropRetired(ctx, slot)
	c.mu.Lock()
	stale := c.takeStaleLocked(record)
	c.mu.Unlock()
	c.releaseTaken(ctx, slot, record, stale)
}

// takeStaleLocked takes the record's stale objects for release (c.mu
// held); they count as releasing until releaseTaken settles each.
func (c *productCommander) takeStaleLocked(record *productSlot) []uint32 {
	stale := record.stale
	record.stale = nil
	c.releasing += len(stale)
	return stale
}

func (c *productCommander) releaseTaken(ctx context.Context, slot uint32, record *productSlot, stale []uint32) {
	for _, object := range stale {
		released := c.release(ctx, object)
		c.mu.Lock()
		switch {
		case released:
		case c.slots[slot] == record:
			record.stale = append(record.stale, object)
		default:
			c.orphans = append(c.orphans, object)
		}
		c.releasing--
		c.mu.Unlock()
	}
}

func (c *productCommander) adopt(ctx context.Context, command string, slot uint32, cgroup uint64, tid uint32) (uint32, error) {
	return c.control.run(ctx, command, sharedProductAdoptBody(cgroup, slot, tid))
}

// verify runs adopt_verify. A refusal whose only mismatches were tasks
// already exiting (exiting > 0, bad == exiting, within the TASK quota; the
// leader may be the exiting one) is a thread that exited mid-adoption
// (AdoptionThreadExited), not an identity mismatch.
func (c *productCommander) verify(ctx context.Context, slot uint32, cgroup uint64, _ SharedInitIdentity) (uint32, bool, error) {
	code, err := c.adopt(ctx, "opaque_real_adopt_verify", slot, cgroup, 0)
	if err != nil || code != sharedProductRefused {
		return code, false, err
	}
	state, err := c.slotState(slot)
	if err != nil {
		return code, false, nil // unreadable detail: an identity refusal
	}
	exited := state.Exiting > 0 && state.Bad == state.Exiting && uint64(state.Iterated) <= c.profile.PerBinding.Tasks
	return code, exited, nil
}

func (c *productCommander) adoptTask(ctx context.Context, slot uint32, cgroup uint64, tid uint32, _ SharedInitIdentity) (uint32, error) {
	return c.adopt(ctx, "opaque_real_adopt_task", slot, cgroup, tid)
}

// finish runs adopt_finish. Its refusal detail comes from this run's own
// counts only: the state's finishes sequence must advance by exactly one
// (finish reset and recounted iterated/bad/exiting); otherwise (an early
// refusal, or a concurrent run) the detail is empty, a generic
// AdoptionFinishRefused, never verify's leftover counts.
func (c *productCommander) finish(ctx context.Context, slot uint32, cgroup uint64) (uint32, sharedFinishDetail, error) {
	before, err := c.slotState(slot)
	if err != nil {
		return 0, sharedFinishDetail{}, err
	}
	code, err := c.adopt(ctx, "opaque_real_adopt_finish", slot, cgroup, 0)
	if err != nil || code != sharedProductRefused {
		return code, sharedFinishDetail{}, err
	}
	state, err := c.slotState(slot)
	if err != nil {
		return code, sharedFinishDetail{}, err
	}
	if state.Finishes != before.Finishes+1 {
		return code, sharedFinishDetail{}, nil
	}
	route, err := c.productRoute(slot)
	if err != nil {
		return code, sharedFinishDetail{}, err
	}
	return code, sharedFinishDetailOf(state, route), nil
}

func (c *productCommander) quarantine(ctx context.Context, slot uint32, cgroup uint64) (sharedQuarantineResult, error) {
	code, err := c.adopt(ctx, "opaque_real_adopt_quarantine", slot, cgroup, 0)
	if err != nil {
		return sharedQuarantineResult{}, err
	}
	switch code {
	case sharedProductOK, sharedProductRetry:
		state, err := c.slotState(slot)
		if err != nil {
			return sharedQuarantineResult{}, err
		}
		return sharedQuarantineResult{
			Complete: code == sharedProductOK && state.Missed == 0, Quarantined: state.Quarantined, Missed: state.Missed, Gone: state.Gone,
		}, nil
	}
	return sharedQuarantineResult{}, sharedProductCodeError("quarantine", code, nil)
}

func (c *productCommander) withdraw(ctx context.Context, slot uint32, cgroup uint64) (uint32, error) {
	c.mu.Lock()
	record := c.slots[slot]
	c.mu.Unlock()
	// The scope is only ever the one this commander published: never a
	// kernel read-back, which would let a withdraw match a route this node
	// did not publish.
	if record == nil {
		return 0, fmt.Errorf("withdraw slot %d: no product route published by this node", slot)
	}
	return c.control.run(ctx, "opaque_real_route_withdraw", sharedProductWithdrawBody(cgroup, record.scope, slot))
}

func (c *productCommander) recycle(ctx context.Context, slot uint32) (uint32, error) {
	code, err := c.control.run(ctx, "opaque_real_route_recycle", sharedProductRecycleBody(slot))
	if err != nil || code != sharedProductOK {
		return code, err
	}
	// Detach the record and take its objects for release in one step, so a
	// concurrent stage always sees them as releasing (drainPending).
	c.mu.Lock()
	record := c.slots[slot]
	delete(c.slots, slot)
	var stale []uint32
	if record != nil {
		record.stale = append(record.stale, record.object)
		stale = c.takeStaleLocked(record)
	}
	c.mu.Unlock()
	if record != nil {
		// The slot record is gone: objects still pinned become orphans
		// (still held), retried by the next stage.
		c.releaseTaken(ctx, slot, record, stale)
	}
	// G020: both records are FREE, so the image set is RETIRING: exact
	// deletes and reclaim. A failure keeps it charged (health: Degraded)
	// and the slot's next first publication retries the discard.
	_ = c.image.discard(ctx, slot)
	return code, nil
}

func (c *productCommander) productRoute(slot uint32) (sharedProductRoute, error) {
	raw, err := c.routes.LookupBytes(slot)
	if err != nil {
		return sharedProductRoute{}, err
	}
	return decodeSharedProductRoute(raw)
}

func (c *productCommander) route(slot uint32) (SharedRouteState, error) {
	r, err := c.productRoute(slot)
	if err != nil {
		return SharedRouteState{}, err
	}
	if r.State.Phase == 0 {
		return SharedRouteState{}, fmt.Errorf("route slot %d: %w", slot, ErrSharedRouteFree)
	}
	return r.State, nil
}

func (c *productCommander) adopting(slot uint32) (bool, uint32, error) {
	r, err := c.productRoute(slot)
	if err != nil {
		return false, 0, err
	}
	return r.Adopting != 0, r.State.Class, nil
}

func (c *productCommander) slotState(slot uint32) (sharedProductAdoptState, error) {
	raw, err := c.adoptState.LookupBytes(slot)
	if err != nil {
		return sharedProductAdoptState{}, err
	}
	return decodeSharedProductAdoptState(raw)
}
