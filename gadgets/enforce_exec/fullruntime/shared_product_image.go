// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// G020 image index, command side (bpf/opaque_real_owner_product_image.h):
// the agent resolves a container's lower layers (sharedImageLayerResolver),
// builds a sealed key set for the binding's slot with the authenticated
// opaque_real_image_command, and publishes its handle and overlay dev_t in
// the snapshot metadata. The kernel references the set at PREPARE and
// releases it when the record is FREE again, so a reader's claim always
// holds a sealed set; the agent deletes and reclaims a set only after the
// last record released it (the descriptor is RETIRING).
const (
	sharedImageCommand     = "opaque_real_image_command"
	sharedImageKeysMap     = "se_image_keys"
	sharedImageBindingsMap = "se_image_bindings"
	sharedImageWitnessMap  = "se_image_witness"
	sharedImageScratchMap  = "se_image_scratch"

	sharedImageBegin   = 1
	sharedImageKeys    = 2
	sharedImageSeal    = 3
	sharedImageAbort   = 4
	sharedImageDelete  = 5
	sharedImageReclaim = 6
	sharedImageInspect = 7

	sharedImageKeysPerCommand      = 16
	sharedProductImageRequestBytes = 320 // struct opaque_real_image_request
	sharedImageBindingBytes        = 216 // struct se_binding_images
	sharedImageWitnessBytes        = 104 // struct se_image_class_witness
	sharedImageScratchBytes        = 304 // struct real_owner_image_loop

	// sharedProductUncertain: a key operation's outcome is unknown; it
	// stays pending and charged until INSPECT reconciles it.
	sharedProductUncertain = 8
	// sharedProductImage (route_publish): the metadata's image handle was
	// not a sealed descriptor of the binding with that overlay dev_t; the
	// PREPARE was undone and PREPARE_REFUSED counted.
	sharedProductImage = 9
)

// Descriptor phases (SE_IMAGE_*, full/shared_image.h).
const (
	sharedImageFree     = 0
	sharedImageBuilding = 1
	sharedImageComplete = 2
	sharedImageRetiring = 3
)

// ErrSharedImageIndexUnavailable reports that the binding has no sealed image index
// (no containerd source or container ID, an unsupported or unattested
// rootfs, or an index command refused). A policy with a FromImage predicate
// is not published without one (the binding stays NotReady with this
// reason); any other policy is published without an index (handle 0).
var ErrSharedImageIndexUnavailable = errors.New("shared image index unavailable")

// errSharedImageUncertain: a key operation stays UNCERTAIN in the kernel
// after reconciliation; the set stays charged and the node is Degraded.
var errSharedImageUncertain = errors.New("image key operation uncertain")

// sharedImageDescriptor is struct se_image_descriptor (72 B).
type sharedImageDescriptor struct {
	Scope, Handle, NextOperation, PendingSequence uint64
	PendingKey                                    SharedImageLayerKey
	Expected, Present, Phase, References          uint32
	PendingKind, OverlayDev                       uint32
}

// sharedImageReference is struct se_image_reference (24 B).
type sharedImageReference struct {
	Serial, Handle   uint64
	Descriptor, Held uint32
}

// sharedImageBinding is struct se_binding_images (216 B), one slot's image
// state in se_image_bindings.
type sharedImageBinding struct {
	Scope, LastHandle uint64
	Limit, Reserved   uint32
	Descriptors       [2]sharedImageDescriptor
	Snapshots         [2]sharedImageReference
}

func decodeSharedImageBinding(raw []byte) (sharedImageBinding, error) {
	if len(raw) != sharedImageBindingBytes {
		return sharedImageBinding{}, fmt.Errorf("image binding is %d bytes, want %d", len(raw), sharedImageBindingBytes)
	}
	le := binary.LittleEndian
	b := sharedImageBinding{Scope: le.Uint64(raw[0:]), LastHandle: le.Uint64(raw[8:]), Limit: le.Uint32(raw[16:]), Reserved: le.Uint32(raw[20:])}
	for i := range b.Descriptors {
		d := raw[24+72*i:]
		b.Descriptors[i] = sharedImageDescriptor{
			Scope: le.Uint64(d[0:]), Handle: le.Uint64(d[8:]), NextOperation: le.Uint64(d[16:]), PendingSequence: le.Uint64(d[24:]),
			PendingKey: SharedImageLayerKey{Ino: le.Uint64(d[32:]), Major: le.Uint32(d[40:]), Minor: le.Uint32(d[44:])},
			Expected:   le.Uint32(d[48:]), Present: le.Uint32(d[52:]), Phase: le.Uint32(d[56:]), References: le.Uint32(d[60:]),
			PendingKind: le.Uint32(d[64:]), OverlayDev: le.Uint32(d[68:]),
		}
	}
	for i := range b.Snapshots {
		r := raw[168+24*i:]
		b.Snapshots[i] = sharedImageReference{Serial: le.Uint64(r[0:]), Handle: le.Uint64(r[8:]), Descriptor: le.Uint32(r[16:]), Held: le.Uint32(r[20:])}
	}
	return b, nil
}

// present is the slot's kernel key cells: every non-FREE descriptor's
// present count.
func (b sharedImageBinding) present() uint64 {
	var n uint64
	for _, d := range b.Descriptors {
		if d.Phase != sharedImageFree {
			n += uint64(d.Present)
		}
	}
	return n
}

// sharedProductImageBody is the body of opaque_real_image_command after
// the header: {u64 scope, handle; u32 op, slot, descriptor, expected,
// overlay_dev, count; struct se_image_key keys[16]}.
func sharedProductImageBody(op, slot, descriptor, expected, overlayDev uint32, scope, handle uint64, keys []SharedImageLayerKey) ([]byte, error) {
	if len(keys) > sharedImageKeysPerCommand {
		return nil, fmt.Errorf("%d image keys in one command (at most %d)", len(keys), sharedImageKeysPerCommand)
	}
	b := make([]byte, sharedProductImageRequestBytes-sharedProductHeaderBytes)
	le := binary.LittleEndian
	le.PutUint64(b[0:], scope)
	le.PutUint64(b[8:], handle)
	for i, v := range []uint32{op, slot, descriptor, expected, overlayDev, uint32(len(keys))} {
		le.PutUint32(b[16+4*i:], v)
	}
	for i, k := range keys {
		le.PutUint64(b[40+16*i:], k.Ino)
		le.PutUint32(b[48+16*i:], k.Major)
		le.PutUint32(b[52+16*i:], k.Minor)
	}
	return b, nil
}

// sharedImageResolving is the resolver surface the index needs
// (sharedImageLayerResolver; tests substitute it).
type sharedImageResolving interface {
	Resolve(ctx context.Context, containerID string, init SharedInitIdentity) (*SharedImageLayers, error)
	Keys(layers *SharedImageLayers) ([]SharedImageLayerKey, error)
	Reattest(ctx context.Context, layers *SharedImageLayers) error
}

// productImageSlot is one slot's image set: the descriptor the agent built
// and its keys in insertion order (the kernel's present count is always a
// prefix of them: KEYS and DELETE stop at the first key not APPLIED).
type productImageSlot struct {
	scope, handle uint64
	descriptor    uint32
	overlayDev    uint32
	keys          []SharedImageLayerKey
	// deleted counts the keys exact DELETEs removed, from the front: the
	// keys still present are keys[deleted : deleted+present].
	deleted int
	sealed  bool
	// fault is a reconciliation that did not settle (still UNCERTAIN) or an
	// exact delete that failed: the set stays charged, the node Degraded.
	fault error
}

// productImageIndex runs the image commands for the product commander.
type productImageIndex struct {
	run      func(ctx context.Context, name string, body []byte) (uint32, error)
	bindings sharedBytesMap
	resolver sharedImageResolving // nil: no containerd source configured
	ledger   *sharedImageLedger
	slotsMax uint32
	// overlayUnavailable (nil: always available) is the node's overlay layout
	// failure; a build is refused while it reports one.
	overlayUnavailable func() error

	mu    sync.Mutex
	slots map[uint32]*productImageSlot
	// busy counts the slot's mutating operations in flight (build,
	// discard) and generation their completions, both under mu: health
	// compares kernel and ledger only for a slot quiescent across its reads
	// (review M5: a command between the kernel read and the ledger read is
	// not a fault).
	busy       map[uint32]int
	generation map[uint32]uint64
}

// enter marks a mutating operation on slot in flight; the returned func
// ends it.
func (x *productImageIndex) enter(slot uint32) func() {
	x.mu.Lock()
	x.busy[slot]++
	x.mu.Unlock()
	return func() {
		x.mu.Lock()
		x.busy[slot]--
		x.generation[slot]++
		x.mu.Unlock()
	}
}

// quiescent returns the slot's operation generation and whether no
// mutating operation is in flight.
func (x *productImageIndex) quiescent(slot uint32) (uint64, bool) {
	x.mu.Lock()
	defer x.mu.Unlock()
	return x.generation[slot], x.busy[slot] == 0
}

func newProductImageIndex(run func(context.Context, string, []byte) (uint32, error), bindings sharedBytesMap, resolver sharedImageResolving, p SharedProfile) (*productImageIndex, error) {
	ledger, err := newSharedImageLedger(p.PerBinding.Images, p.Images)
	if err != nil {
		return nil, err
	}
	return &productImageIndex{run: run, bindings: bindings, resolver: resolver, ledger: ledger, slotsMax: uint32(p.Bindings), slots: map[uint32]*productImageSlot{}, busy: map[uint32]int{}, generation: map[uint32]uint64{}}, nil
}

func (x *productImageIndex) state(slot uint32) (sharedImageBinding, error) {
	raw, err := x.bindings.LookupBytes(slot)
	if err != nil {
		return sharedImageBinding{}, err
	}
	return decodeSharedImageBinding(raw)
}

func (x *productImageIndex) command(ctx context.Context, op, slot uint32, s *productImageSlot, expected uint32, keys []SharedImageLayerKey) (uint32, error) {
	body, err := sharedProductImageBody(op, slot, s.descriptor, expected, s.overlayDev, s.scope, s.handle, keys)
	if err != nil {
		return 0, err
	}
	return x.run(ctx, sharedImageCommand, body)
}

// sealed returns the slot's sealed set for a publication (0, 0 without).
func (x *productImageIndex) sealed(slot uint32, scope uint64) (uint64, uint32) {
	if x == nil {
		return 0, 0
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	s := x.slots[slot]
	if s == nil || !s.sealed || s.scope != scope || s.fault != nil {
		return 0, 0
	}
	return s.handle, s.overlayDev
}

// build resolves the container's lower layers and builds and seals a key
// set for slot under scope: Resolve -> BEGIN -> KEYS -> Reattest -> SEAL,
// every step's kernel counts recorded in the ledger. Any failure discards
// the set (abort, exact deletes, reclaim) and wraps
// ErrSharedImageIndexUnavailable. A set left from an earlier publication
// of the slot is discarded first.
func (x *productImageIndex) build(ctx context.Context, slot uint32, scope uint64, init SharedInitIdentity) (uint64, uint32, error) {
	if x == nil || x.resolver == nil {
		return 0, 0, fmt.Errorf("%w: no container runtime source", ErrSharedImageIndexUnavailable)
	}
	if x.overlayUnavailable != nil {
		if err := x.overlayUnavailable(); err != nil {
			return 0, 0, fmt.Errorf("%w: %w", ErrSharedImageIndexUnavailable, err)
		}
	}
	if init.ContainerID == "" {
		return 0, 0, fmt.Errorf("%w: the binding has no container ID", ErrSharedImageIndexUnavailable)
	}
	defer x.enter(slot)()
	if err := x.discard(ctx, slot); err != nil {
		return 0, 0, fmt.Errorf("%w: slot %d holds an earlier image set: %w", ErrSharedImageIndexUnavailable, slot, err)
	}
	layers, err := x.resolver.Resolve(ctx, init.ContainerID, init)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: %w", ErrSharedImageIndexUnavailable, err)
	}
	keys, err := x.resolver.Keys(layers)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: %w", ErrSharedImageIndexUnavailable, err)
	}
	handle, err := x.begin(ctx, slot, scope, layers.OverlayDev, keys)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: %w", ErrSharedImageIndexUnavailable, err)
	}
	if err := x.fill(ctx, slot, layers); err != nil {
		return 0, 0, fmt.Errorf("%w: %w", ErrSharedImageIndexUnavailable, joinIfErr(err, x.discard(context.WithoutCancel(ctx), slot)))
	}
	return handle, layers.OverlayDev, nil
}

// begin picks a FREE descriptor, runs BEGIN and reserves the ledger cells.
// The handle is BEGIN's own authenticated sequence, read back.
func (x *productImageIndex) begin(ctx context.Context, slot uint32, scope uint64, overlayDev uint32, keys []SharedImageLayerKey) (uint64, error) {
	if len(keys) == 0 {
		return 0, fmt.Errorf("no lower layer keys")
	}
	before, err := x.state(slot)
	if err != nil {
		return 0, err
	}
	index := uint32(2)
	for i, d := range before.Descriptors {
		if d.Phase == sharedImageFree {
			index = uint32(i)
			break
		}
	}
	if index == 2 {
		return 0, fmt.Errorf("slot %d has no FREE image descriptor", slot)
	}
	s := &productImageSlot{scope: scope, descriptor: index, overlayDev: overlayDev, keys: keys}
	code, err := x.command(ctx, sharedImageBegin, slot, s, uint32(len(keys)), nil)
	if err := sharedProductCodeError("image begin", code, err); err != nil {
		return 0, err
	}
	after, err := x.state(slot)
	if err != nil {
		return 0, err
	}
	d := after.Descriptors[index]
	if d.Phase != sharedImageBuilding || d.Scope != scope || d.Handle == 0 || d.Expected != uint32(len(keys)) || d.OverlayDev != overlayDev || d.Present != 0 {
		return 0, fmt.Errorf("image begin read back %+v", d)
	}
	s.handle = d.Handle
	x.mu.Lock()
	x.slots[slot] = s
	x.mu.Unlock()
	if err := x.ledger.Reserve(slot, s.handle, uint64(len(keys))); err != nil {
		return 0, joinIfErr(err, x.discard(context.WithoutCancel(ctx), slot))
	}
	return s.handle, nil
}

// fill inserts the keys (16 per command), re-attests and seals.
func (x *productImageIndex) fill(ctx context.Context, slot uint32, layers *SharedImageLayers) error {
	x.mu.Lock()
	s := x.slots[slot]
	x.mu.Unlock()
	for start := 0; start < len(s.keys); {
		end := min(start+sharedImageKeysPerCommand, len(s.keys))
		code, err := x.command(ctx, sharedImageKeys, slot, s, 0, s.keys[start:end])
		present, rerr := x.settle(ctx, slot, s, code, err)
		if rerr != nil {
			return rerr
		}
		if code != sharedProductOK || err != nil {
			return sharedProductCodeError("image keys", code, err)
		}
		if present != uint32(end) {
			return fmt.Errorf("image keys: %d present after %d keys", present, end)
		}
		start = end
	}
	if err := x.resolver.Reattest(ctx, layers); err != nil {
		return err
	}
	code, err := x.command(ctx, sharedImageSeal, slot, s, 0, nil)
	if err := sharedProductCodeError("image seal", code, err); err != nil {
		return err
	}
	x.mu.Lock()
	s.sealed = true
	x.mu.Unlock()
	return nil
}

// settle reconciles an UNCERTAIN key command (INSPECT), then records the
// kernel's present count in the ledger and returns it.
func (x *productImageIndex) settle(ctx context.Context, slot uint32, s *productImageSlot, code uint32, err error) (uint32, error) {
	if err == nil && code == sharedProductUncertain {
		icode, ierr := x.command(ctx, sharedImageInspect, slot, s, 0, nil)
		if ierr = sharedProductCodeError("image inspect", icode, ierr); ierr != nil {
			x.mu.Lock()
			s.fault = fmt.Errorf("slot %d image handle %d: %w: %w", slot, s.handle, errSharedImageUncertain, ierr)
			x.mu.Unlock()
		}
	}
	state, rerr := x.state(slot)
	if rerr != nil {
		return 0, rerr
	}
	d := state.Descriptors[s.descriptor]
	if d.Handle != s.handle || d.Scope != s.scope {
		return 0, fmt.Errorf("image descriptor %d of slot %d is no longer handle %d", s.descriptor, slot, s.handle)
	}
	if d.PendingSequence != 0 {
		x.mu.Lock()
		if s.fault == nil {
			s.fault = fmt.Errorf("slot %d image handle %d: %w", slot, s.handle, errSharedImageUncertain)
		}
		fault := s.fault
		x.mu.Unlock()
		return d.Present, fault
	}
	if err := x.ledger.SetPresent(slot, s.handle, uint64(d.Present)); err != nil {
		return d.Present, err
	}
	return d.Present, nil
}

// discard retires and frees the slot's set once no snapshot record
// references it: ABORT (an unreferenced BUILDING or COMPLETE set), exact
// DELETEs of the present prefix of its keys, RECLAIM, then the ledger
// release. A set still referenced (a published record) is kept and
// reported; an unsettled operation keeps it charged (Degraded).
func (x *productImageIndex) discard(ctx context.Context, slot uint32) error {
	if x == nil {
		return nil
	}
	defer x.enter(slot)()
	x.mu.Lock()
	s := x.slots[slot]
	x.mu.Unlock()
	if s == nil {
		return nil
	}
	state, err := x.state(slot)
	if err != nil {
		return err
	}
	d := state.Descriptors[s.descriptor]
	if d.Phase == sharedImageFree || d.Handle != s.handle {
		// Never begun in the kernel (or reclaimed already): nothing held.
		return x.forget(slot, s)
	}
	if d.PendingSequence != 0 {
		if _, err := x.settle(ctx, slot, s, sharedProductUncertain, nil); err != nil {
			return err
		}
		if state, err = x.state(slot); err != nil {
			return err
		}
		d = state.Descriptors[s.descriptor]
	}
	if d.References != 0 {
		return fmt.Errorf("slot %d image handle %d is still referenced by %d snapshot records", slot, s.handle, d.References)
	}
	if d.Phase == sharedImageBuilding || d.Phase == sharedImageComplete {
		code, err := x.command(ctx, sharedImageAbort, slot, s, 0, nil)
		if err := sharedProductCodeError("image abort", code, err); err != nil {
			return err
		}
	}
	present := int(d.Present)
	if s.deleted+present > len(s.keys) {
		return x.faulted(slot, s, fmt.Errorf("slot %d image handle %d has %d keys present after %d deletes, %d were inserted", slot, s.handle, present, s.deleted, len(s.keys)))
	}
	for present > 0 {
		start := s.deleted
		end := start + min(present, sharedImageKeysPerCommand)
		code, err := x.command(ctx, sharedImageDelete, slot, s, 0, s.keys[start:end])
		left, serr := x.settle(ctx, slot, s, code, err)
		if serr != nil {
			return serr
		}
		if code == sharedProductRefused {
			// An owned key is absent: the exact accounting is broken.
			return x.faulted(slot, s, fmt.Errorf("slot %d image handle %d: a present key was not deleted", slot, s.handle))
		}
		if err == nil && code != sharedProductOK && code != sharedProductUncertain {
			return sharedProductCodeError("image delete", code, nil)
		}
		if err != nil {
			return sharedProductCodeError("image delete", code, err)
		}
		if int(left) >= present {
			return fmt.Errorf("image delete made no progress (%d present)", left)
		}
		// DELETE removes keys in order and stops at the first one not
		// APPLIED: the removed ones are the front of this run.
		x.mu.Lock()
		s.deleted += present - int(left)
		x.mu.Unlock()
		present = int(left)
	}
	code, err := x.command(ctx, sharedImageReclaim, slot, s, 0, nil)
	if err := sharedProductCodeError("image reclaim", code, err); err != nil {
		return err
	}
	return x.forget(slot, s)
}

func (x *productImageIndex) forget(slot uint32, s *productImageSlot) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if x.slots[slot] == s {
		delete(x.slots, slot)
	}
	if _, ok := x.ledger.Entry(slot, s.handle); ok {
		return x.ledger.Release(slot, s.handle)
	}
	return nil
}

func (x *productImageIndex) faulted(slot uint32, s *productImageSlot, err error) error {
	x.mu.Lock()
	defer x.mu.Unlock()
	if s.fault == nil {
		s.fault = err
	}
	return err
}

// health compares every quiescent slot's kernel key cells with the ledger
// and reports any set left uncertain or with a failed exact delete. Every
// error is an index integrity fault: Degraded, never NotReady (G020
// ruling M5). A slot with an operation in flight, or one that ran during
// the reads, is skipped: its counts are compared at a later check, and an
// operation that does not settle records a sticky slot fault.
func (x *productImageIndex) health() error {
	if x == nil {
		return nil
	}
	var result error
	for slot := range x.slotsMax {
		generation, idle := x.quiescent(slot)
		if !idle {
			continue
		}
		state, err := x.state(slot)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("image slot %d: %w", slot, err))
			continue
		}
		ledgerErr := x.ledger.CheckKernel(slot, state.present())
		if after, idle := x.quiescent(slot); !idle || after != generation {
			continue
		}
		result = errors.Join(result, ledgerErr)
		for i, d := range state.Descriptors {
			if d.PendingSequence != 0 {
				result = errors.Join(result, fmt.Errorf("image slot %d descriptor %d: %w", slot, i, errSharedImageUncertain))
			}
		}
	}
	x.mu.Lock()
	for _, s := range x.slots {
		if s.fault != nil {
			result = errors.Join(result, s.fault)
		}
	}
	x.mu.Unlock()
	return result
}

// sharedPolicyUsesImage reports whether any rule or exception of p uses a
// FromImage predicate (actor or target).
func sharedPolicyUsesImage(p *fullpolicy.Policy) bool {
	if p == nil {
		return false
	}
	uses := func(a fullpolicy.Actor, t fullpolicy.Target) bool {
		kinds := sharedPredicateKinds(a, t)
		return slices.Contains(kinds, SharedPredicateActorImage) || slices.Contains(kinds, SharedPredicateTargetImage)
	}
	for _, r := range p.Rules {
		if uses(r.Actor, r.Target) {
			return true
		}
		for _, ex := range r.Except {
			if uses(ex.Actor, ex.Target) {
				return true
			}
		}
	}
	return false
}

// sharedImageReporter is a live publisher with an image index: its health
// is part of the node's (sharedLiveHealth.check).
type sharedImageReporter interface {
	imageHealth() error
}

// imageHealth is the image index's health (nil without one): any ledger
// vs kernel count mismatch, and any UNCERTAIN or failed exact delete.
func (p *productRoutePublisher) imageHealth() error {
	cmd, ok := p.cmd.(*productCommander)
	if !ok || cmd.image == nil {
		return nil
	}
	if err := cmd.image.health(); err != nil {
		return fmt.Errorf("image index: %w", err)
	}
	return nil
}
