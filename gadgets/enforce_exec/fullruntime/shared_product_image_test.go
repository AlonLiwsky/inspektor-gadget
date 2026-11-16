// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

func encodeSharedImageBinding(b sharedImageBinding) []byte {
	raw := make([]byte, sharedImageBindingBytes)
	le := binary.LittleEndian
	le.PutUint64(raw[0:], b.Scope)
	le.PutUint64(raw[8:], b.LastHandle)
	le.PutUint32(raw[16:], b.Limit)
	le.PutUint32(raw[20:], b.Reserved)
	for i, d := range b.Descriptors {
		o := raw[24+72*i:]
		for j, v := range []uint64{d.Scope, d.Handle, d.NextOperation, d.PendingSequence, d.PendingKey.Ino} {
			le.PutUint64(o[8*j:], v)
		}
		for j, v := range []uint32{d.PendingKey.Major, d.PendingKey.Minor, d.Expected, d.Present, d.Phase, d.References, d.PendingKind, d.OverlayDev} {
			le.PutUint32(o[40+4*j:], v)
		}
	}
	for i, r := range b.Snapshots {
		o := raw[168+24*i:]
		le.PutUint64(o[0:], r.Serial)
		le.PutUint64(o[8:], r.Handle)
		le.PutUint32(o[16:], r.Descriptor)
		le.PutUint32(o[20:], r.Held)
	}
	return raw
}

// sharedImageFakeKernel models opaque_real_image_command and the image
// lifetime of opaque_real_route_publish/recycle exactly as the BPF does
// (full/shared_image.h, full/shared_image_snapshot.h): handles are BEGIN's
// sequence, KEYS/DELETE stop at the first key not APPLIED, an UNCERTAIN key
// stays pending until INSPECT, PREPARE references a sealed set and FREE
// releases it (the last release retires it).
type sharedImageFakeKernel struct {
	mu    sync.Mutex
	state [2]sharedImageBinding
	keys  map[[2]uint64]SharedImageLayerKey // {handle, ino}
	// uncertain: the n-th key operation (1-based, inserts and deletes)
	// reports UNCERTAIN; applied says whether it physically happened.
	uncertain, ops int
	applied        bool
	// inspectRefused: INSPECT cannot settle (malformed membership).
	inspectRefused bool
	// refuseKey: a key whose insert is NOT_APPLIED (already present).
	refuseKey uint64
	// publishCode: route_publish refuses after referencing (BPF undo).
	publishCode uint32
	published   []sharedImageMeta
	quota       uint32
}

type sharedImageMeta struct {
	handle uint64
	dev    uint32
}

func (k *sharedImageFakeKernel) LookupBytes(key interface{}) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	slot := key.(uint32)
	if slot >= 2 {
		return nil, fmt.Errorf("fake image binding %d", slot)
	}
	return encodeSharedImageBinding(k.state[slot]), nil
}

func (k *sharedImageFakeKernel) has(handle uint64, key SharedImageLayerKey) bool {
	v, ok := k.keys[[2]uint64{handle, key.Ino}]
	return ok && v == key
}

func (k *sharedImageFakeKernel) command(request []byte) uint32 {
	k.mu.Lock()
	defer k.mu.Unlock()
	le := binary.LittleEndian
	sequence := le.Uint64(request[16:])
	b := request[sharedProductHeaderBytes:]
	scope, handle := le.Uint64(b[0:]), le.Uint64(b[8:])
	op, slot, index, expected, dev, count := le.Uint32(b[16:]), le.Uint32(b[20:]), le.Uint32(b[24:]), le.Uint32(b[28:]), le.Uint32(b[32:]), le.Uint32(b[36:])
	if slot >= 2 || index >= 2 || scope == 0 {
		return sharedProductRetry
	}
	s := &k.state[slot]
	d := &s.Descriptors[index]
	match := d.Scope == scope && d.Handle == handle && d.Phase != sharedImageFree && s.Scope == scope
	switch op {
	case sharedImageBegin:
		if s.Scope != scope {
			if s.Reserved != 0 || s.Snapshots[0].Held != 0 || s.Snapshots[1].Held != 0 || s.Descriptors[0].Phase != 0 || s.Descriptors[1].Phase != 0 {
				return sharedProductRetry
			}
			*s = sharedImageBinding{Scope: scope, LastHandle: s.LastHandle, Limit: k.quota}
			d = &s.Descriptors[index]
		}
		if handle != 0 || d.Phase != sharedImageFree || sequence <= s.LastHandle || expected > s.Limit-s.Reserved || dev == 0 || dev>>20 != 0 {
			return sharedProductRetry
		}
		*d = sharedImageDescriptor{Scope: scope, Handle: sequence, Expected: expected, Phase: sharedImageBuilding, OverlayDev: dev}
		s.LastHandle = sequence
		s.Reserved += expected
		return sharedProductOK
	case sharedImageKeys, sharedImageDelete:
		insert := op == sharedImageKeys
		for i := range count {
			kb := b[40+16*i:]
			key := SharedImageLayerKey{Ino: le.Uint64(kb), Major: le.Uint32(kb[8:]), Minor: le.Uint32(kb[12:])}
			if !match || d.PendingSequence != 0 || d.References != 0 ||
				(insert && (d.Phase != sharedImageBuilding || d.Present == d.Expected)) ||
				(!insert && (d.Phase != sharedImageRetiring || d.Present == 0)) {
				return sharedProductRetry
			}
			k.ops++
			if k.ops == k.uncertain {
				d.NextOperation++
				d.PendingSequence, d.PendingKey = d.NextOperation, key
				d.PendingKind = 1
				if !insert {
					d.PendingKind = 2
				}
				if k.applied {
					if insert {
						k.keys[[2]uint64{handle, key.Ino}] = key
					} else {
						delete(k.keys, [2]uint64{handle, key.Ino})
					}
				}
				return sharedProductUncertain
			}
			if insert && (key.Ino == k.refuseKey || k.has(handle, key)) || !insert && !k.has(handle, key) {
				return sharedProductRefused
			}
			if insert {
				k.keys[[2]uint64{handle, key.Ino}] = key
				d.Present++
			} else {
				delete(k.keys, [2]uint64{handle, key.Ino})
				d.Present--
			}
		}
		return sharedProductOK
	case sharedImageInspect:
		if !match || k.inspectRefused {
			return sharedProductRetry
		}
		if d.PendingSequence != 0 {
			present := k.has(handle, d.PendingKey)
			if (d.PendingKind == 1) == present {
				if present {
					d.Present++
				} else {
					d.Present--
				}
			}
			d.PendingSequence, d.PendingKind, d.PendingKey = 0, 0, SharedImageLayerKey{}
		}
		return sharedProductOK
	case sharedImageSeal:
		if !match || d.Phase != sharedImageBuilding || d.PendingSequence != 0 || d.Present != d.Expected {
			return sharedProductRetry
		}
		d.Phase = sharedImageComplete
		return sharedProductOK
	case sharedImageAbort:
		if !match || d.References != 0 || d.PendingSequence != 0 {
			return sharedProductRetry
		}
		d.Phase = sharedImageRetiring
		return sharedProductOK
	case sharedImageReclaim:
		if !match || d.Phase != sharedImageRetiring || d.References != 0 || d.PendingSequence != 0 || d.Present != 0 {
			return sharedProductRetry
		}
		s.Reserved -= d.Expected
		*d = sharedImageDescriptor{}
		return sharedProductOK
	}
	return sharedProductRetry
}

// publish references the metadata's sealed set (PREPARE) and, with a
// refusal code, undoes it (the abort's FREE releases it).
func (k *sharedImageFakeKernel) publish(request []byte) uint32 {
	k.mu.Lock()
	defer k.mu.Unlock()
	le := binary.LittleEndian
	b := request[sharedProductHeaderBytes:]
	slot := le.Uint32(b[56:])
	m := b[80:]
	handle, dev := le.Uint64(m[128:]), le.Uint32(m[404:])
	k.published = append(k.published, sharedImageMeta{handle, dev})
	if handle == 0 {
		return k.publishCode
	}
	s := &k.state[slot]
	for i := range s.Descriptors {
		d := &s.Descriptors[i]
		if d.Handle == handle && d.Phase == sharedImageComplete && d.OverlayDev == dev && d.References < 2 {
			d.References++
			if k.publishCode != sharedProductOK {
				k.releaseLocked(slot, i)
			}
			return k.publishCode
		}
	}
	return sharedProductImage
}

func (k *sharedImageFakeKernel) releaseLocked(slot uint32, i int) {
	d := &k.state[slot].Descriptors[i]
	d.References--
	if d.References == 0 {
		d.Phase = sharedImageRetiring
	}
}

// recycle frees both records: every reference released.
func (k *sharedImageFakeKernel) recycle(request []byte) uint32 {
	k.mu.Lock()
	defer k.mu.Unlock()
	slot := binary.LittleEndian.Uint32(request[sharedProductHeaderBytes:])
	for i := range k.state[slot].Descriptors {
		for k.state[slot].Descriptors[i].References > 0 {
			k.releaseLocked(slot, i)
		}
	}
	return sharedProductOK
}

type sharedFakeImageResolver struct {
	keys     []SharedImageLayerKey
	dev      uint32
	resolve  error
	reattest error
	calls    []string
}

func (r *sharedFakeImageResolver) Resolve(_ context.Context, containerID string, init SharedInitIdentity) (*SharedImageLayers, error) {
	r.calls = append(r.calls, "resolve "+containerID)
	if r.resolve != nil {
		return nil, r.resolve
	}
	return &SharedImageLayers{ContainerID: containerID, Init: init, OverlayDev: r.dev}, nil
}

func (r *sharedFakeImageResolver) Keys(layers *SharedImageLayers) ([]SharedImageLayerKey, error) {
	r.calls = append(r.calls, "keys")
	layers.Keys, layers.Expected = r.keys, uint64(len(r.keys))
	return r.keys, nil
}

func (r *sharedFakeImageResolver) Reattest(context.Context, *SharedImageLayers) error {
	r.calls = append(r.calls, "reattest")
	return r.reattest
}

func sharedTestImageKeys(n int) []SharedImageLayerKey {
	keys := make([]SharedImageLayerKey, n)
	for i := range keys {
		keys[i] = SharedImageLayerKey{Ino: uint64(100 + i), Major: 259, Minor: 1}
	}
	return keys
}

type sharedImageIndexFixture struct {
	*sharedCommanderFixture
	kernel   *sharedImageFakeKernel
	resolver *sharedFakeImageResolver
}

func newSharedImageIndexFixture(t *testing.T, keys int) *sharedImageIndexFixture {
	t.Helper()
	f := newSharedCommanderFixture(t)
	p := sharedCandidateQualificationProfile()
	kernel := &sharedImageFakeKernel{keys: map[[2]uint64]SharedImageLayerKey{}, quota: uint32(p.PerBinding.Images)}
	resolver := &sharedFakeImageResolver{keys: sharedTestImageKeys(keys), dev: 0x2a}
	index, err := newProductImageIndex(f.cmd.control.run, kernel, resolver, p)
	if err != nil {
		t.Fatal(err)
	}
	f.cmd.image = index
	f.fakes[sharedImageCommand].respond = kernel.command
	f.fakes["opaque_real_route_publish"].respond = kernel.publish
	f.fakes["opaque_real_route_recycle"].respond = kernel.recycle
	return &sharedImageIndexFixture{sharedCommanderFixture: f, kernel: kernel, resolver: resolver}
}

func sharedImageOps(requests [][]byte) []uint32 {
	var ops []uint32
	for _, r := range requests {
		ops = append(ops, binary.LittleEndian.Uint32(r[sharedProductHeaderBytes+16:]))
	}
	return ops
}

var sharedImageTestInit = SharedInitIdentity{TGID: 77, StartTicks: 4242, MountNS: 4026531999, ContainerID: "c0ffee"}

// TestSharedProductImageWire pins the request and state layouts against
// the BPF structs (opaque_real_image_request 320 B, se_binding_images 216
// B) and the metadata words (image_handle at m[128:], image_dev at m[404:]).
func TestSharedProductImageWire(t *testing.T) {
	keys := sharedTestImageKeys(16)
	body, err := sharedProductImageBody(sharedImageKeys, 1, 1, 7, 0x2a, 0x5c09e, 0x44, keys)
	if err != nil || len(body)+sharedProductHeaderBytes != sharedProductImageRequestBytes {
		t.Fatalf("body %d %v", len(body), err)
	}
	le := binary.LittleEndian
	if le.Uint64(body) != 0x5c09e || le.Uint64(body[8:]) != 0x44 || le.Uint32(body[16:]) != sharedImageKeys || le.Uint32(body[20:]) != 1 ||
		le.Uint32(body[24:]) != 1 || le.Uint32(body[28:]) != 7 || le.Uint32(body[32:]) != 0x2a || le.Uint32(body[36:]) != 16 ||
		le.Uint64(body[40+16*15:]) != 115 || le.Uint32(body[48+16*15:]) != 259 || le.Uint32(body[52+16*15:]) != 1 {
		t.Fatalf("image request %x", body[:64])
	}
	if _, err := sharedProductImageBody(sharedImageKeys, 0, 0, 0, 0, 1, 1, sharedTestImageKeys(17)); err == nil {
		t.Fatal("17 keys in one command encoded")
	}
	want := sharedImageBinding{
		Scope: 9, LastHandle: 8, Limit: 128, Reserved: 3,
		Descriptors: [2]sharedImageDescriptor{{Scope: 9, Handle: 8, NextOperation: 4, PendingSequence: 4, PendingKey: keys[2], Expected: 3, Present: 2, Phase: 1, References: 0, PendingKind: 1, OverlayDev: 0x2a}},
		Snapshots:   [2]sharedImageReference{{}, {Serial: 5, Handle: 8, Descriptor: 0, Held: 1}},
	}
	got, err := decodeSharedImageBinding(encodeSharedImageBinding(want))
	if err != nil || got != want {
		t.Fatalf("binding round trip %+v %v", got, err)
	}
	if _, err := decodeSharedImageBinding(make([]byte, 215)); err == nil {
		t.Fatal("short binding decoded")
	}
	policy, compiled := sharedCompiledTestPolicy(t)
	f := sharedPublishFields{cgroup: 1, scope: 2, slot: 0, policy: compiled, container: policy.Container, imageHandle: 0x44, imageDev: 0x2a}
	b, err := sharedProductPublishBody(f)
	if err != nil || le.Uint64(b[80+128:]) != 0x44 || le.Uint32(b[80+404:]) != 0x2a {
		t.Fatalf("metadata image words %v", err)
	}
	for name, bad := range map[string]sharedPublishFields{
		"handle without dev": {imageHandle: 1},
		"dev without handle": {imageDev: 1},
		"dev with a major":   {imageHandle: 1, imageDev: 1 << sharedKernelMinorBits},
	} {
		bad.container, bad.policy = "app", compiled
		if _, err := sharedProductPublishBody(bad); err == nil {
			t.Errorf("%s encoded", name)
		}
	}
}

// TestSharedProductImageBuildAndPublish: Resolve -> BEGIN (the handle is
// BEGIN's own sequence) -> KEYS in commands of 16 -> Reattest -> SEAL, then
// the publication carries the handle and overlay dev; the ledger matches
// the kernel; a revision reuses the handle; recycle deletes and reclaims.
func TestSharedProductImageBuildAndPublish(t *testing.T) {
	f := newSharedImageIndexFixture(t, 20)
	policy, _ := sharedCompiledTestPolicy(t)
	if code, err := f.cmd.publishFirst(t.Context(), 1, 0xc0, policy, sharedImageTestInit); err != nil || code != sharedProductOK {
		t.Fatalf("publish: %d %v", code, err)
	}
	image := f.fakes[sharedImageCommand].requests
	if ops := sharedImageOps(image); fmt.Sprint(ops) != fmt.Sprint([]uint32{sharedImageBegin, sharedImageKeys, sharedImageKeys, sharedImageSeal}) {
		t.Fatalf("image ops %v", ops)
	}
	if strings.Join(f.resolver.calls, ",") != "resolve c0ffee,keys,reattest" {
		t.Fatalf("resolver calls %v", f.resolver.calls)
	}
	begin := binary.LittleEndian.Uint64(image[0][16:])
	state := f.kernel.state[1]
	d := state.Descriptors[0]
	if d.Handle != begin || d.Phase != sharedImageComplete || d.Present != 20 || d.References != 1 || d.OverlayDev != 0x2a {
		t.Fatalf("descriptor %+v, BEGIN sequence %d", d, begin)
	}
	if fmt.Sprint(f.kernel.published) != fmt.Sprint([]sharedImageMeta{{begin, 0x2a}}) {
		t.Fatalf("published metadata %v", f.kernel.published)
	}
	if e := f.cmd.image.ledger.Binding(1); e.Reserved != 20 || e.Present != 20 {
		t.Fatalf("ledger %+v", e)
	}
	if err := f.cmd.image.health(); err != nil {
		t.Fatalf("health: %v", err)
	}
	if _, err := f.cmd.revise(t.Context(), 1, 0xc0, policy); err != nil {
		t.Fatalf("revise: %v", err)
	}
	if fmt.Sprint(f.kernel.published) != fmt.Sprint([]sharedImageMeta{{begin, 0x2a}, {begin, 0x2a}}) || f.kernel.state[1].Descriptors[0].References != 2 {
		t.Fatalf("revision metadata %v refs %d (grace period: both records)", f.kernel.published, f.kernel.state[1].Descriptors[0].References)
	}
	if code, err := f.cmd.recycle(t.Context(), 1); err != nil || code != sharedProductOK {
		t.Fatalf("recycle: %d %v", code, err)
	}
	if ops := sharedImageOps(f.fakes[sharedImageCommand].requests[4:]); fmt.Sprint(ops) != fmt.Sprint([]uint32{sharedImageDelete, sharedImageDelete, sharedImageReclaim}) {
		t.Fatalf("unbind ops %v", ops)
	}
	if len(f.kernel.keys) != 0 || f.kernel.state[1].Descriptors[0] != (sharedImageDescriptor{}) || f.kernel.state[1].Reserved != 0 {
		t.Fatalf("unbind left %d keys, %+v", len(f.kernel.keys), f.kernel.state[1])
	}
	if e := f.cmd.image.ledger.Totals(); e != (SharedImageLedgerEntry{}) {
		t.Fatalf("ledger after unbind %+v", e)
	}
	if err := f.cmd.image.health(); err != nil {
		t.Fatalf("health after unbind: %v", err)
	}
}

// TestSharedProductImageFailures: a refused key, a failed re-attestation
// and a refused publication each discard the set exactly (abort, deletes of
// the inserted prefix, reclaim) and keep the ledger equal to the kernel; a
// policy without FromImage then publishes without an index, a FromImage
// policy is not published.
func TestSharedProductImageFailures(t *testing.T) {
	policy, _ := sharedCompiledTestPolicy(t)
	clean := func(t *testing.T, f *sharedImageIndexFixture, slot uint32) {
		t.Helper()
		if len(f.kernel.keys) != 0 || f.kernel.state[slot].Reserved != 0 || f.kernel.state[slot].Descriptors != [2]sharedImageDescriptor{} {
			t.Fatalf("set not discarded: %d keys %+v", len(f.kernel.keys), f.kernel.state[slot])
		}
		if e := f.cmd.image.ledger.Totals(); e != (SharedImageLedgerEntry{}) {
			t.Fatalf("ledger %+v", e)
		}
		if err := f.cmd.image.health(); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("refused key", func(t *testing.T) {
		f := newSharedImageIndexFixture(t, 20)
		f.kernel.refuseKey = 118 // the 19th key: 18 inserted, then NOT_APPLIED
		if code, err := f.cmd.publishFirst(t.Context(), 0, 1, policy, sharedImageTestInit); err != nil || code != sharedProductOK {
			t.Fatalf("publish without an index: %d %v", code, err)
		}
		ops := sharedImageOps(f.fakes[sharedImageCommand].requests)
		if fmt.Sprint(ops) != fmt.Sprint([]uint32{sharedImageBegin, sharedImageKeys, sharedImageKeys, sharedImageAbort, sharedImageDelete, sharedImageDelete, sharedImageReclaim}) {
			t.Fatalf("ops %v", ops)
		}
		if fmt.Sprint(f.kernel.published) != fmt.Sprint([]sharedImageMeta{{0, 0}}) {
			t.Fatalf("published %v, want no index", f.kernel.published)
		}
		clean(t, f, 0)
	})
	t.Run("reattestation", func(t *testing.T) {
		f := newSharedImageIndexFixture(t, 3)
		f.resolver.reattest = sharedImageAttestFailed(SharedImageReasonLowerIdentity, "changed")
		fromImage := policy
		source := *policy.Source
		source.Rules = append([]fullpolicy.Rule(nil), source.Rules...)
		yes := true
		source.Rules[0].Target.FromImage = &yes
		fromImage.Source = &source
		_, err := f.cmd.publishFirst(t.Context(), 0, 1, fromImage, sharedImageTestInit)
		if !errors.Is(err, ErrSharedImageIndexUnavailable) || !errors.Is(err, ErrSharedImageAttestation) {
			t.Fatalf("FromImage without a sealed set: %v", err)
		}
		if len(f.fakes["opaque_real_route_publish"].requests) != 0 || len(f.fakes["opaque_real_policy_stage"].requests) != 0 {
			t.Fatal("FromImage policy staged or published without an index")
		}
		clean(t, f, 0)
	})
	t.Run("overlay layout unavailable", func(t *testing.T) {
		// Degraded (G020 ruling): a policy without a FromImage predicate
		// publishes without an index; a FromImage policy is refused before
		// anything is staged or published.
		f := newSharedImageIndexFixture(t, 3)
		f.cmd.image.overlayUnavailable = func() error { return errors.New("overlay layout unavailable: test") }
		if code, err := f.cmd.publishFirst(t.Context(), 0, 1, policy, sharedImageTestInit); err != nil || code != sharedProductOK {
			t.Fatalf("non-FromImage publish with the overlay unavailable: %d %v", code, err)
		}
		if ops := sharedImageOps(f.fakes[sharedImageCommand].requests); len(ops) != 0 || fmt.Sprint(f.kernel.published) != fmt.Sprint([]sharedImageMeta{{0, 0}}) {
			t.Fatalf("image ops %v published %v, want none and no index", ops, f.kernel.published)
		}
		clean(t, f, 0)
		g := newSharedImageIndexFixture(t, 3)
		g.cmd.image.overlayUnavailable = func() error { return errors.New("overlay layout unavailable: test") }
		fromImage := policy
		source := *policy.Source
		source.Rules = append([]fullpolicy.Rule(nil), source.Rules...)
		yes := true
		source.Rules[0].Target.FromImage = &yes
		fromImage.Source = &source
		if _, err := g.cmd.publishFirst(t.Context(), 0, 1, fromImage, sharedImageTestInit); !errors.Is(err, ErrSharedImageIndexUnavailable) || !strings.Contains(err.Error(), "overlay layout unavailable") {
			t.Fatalf("FromImage publish with the overlay unavailable: %v", err)
		}
		if len(g.fakes["opaque_real_route_publish"].requests) != 0 || len(g.fakes["opaque_real_policy_stage"].requests) != 0 {
			t.Fatal("FromImage policy staged or published without an overlay layout")
		}
	})
	t.Run("refused publication", func(t *testing.T) {
		f := newSharedImageIndexFixture(t, 3)
		f.kernel.publishCode = sharedProductRetry
		if code, err := f.cmd.publishFirst(t.Context(), 0, 1, policy, sharedImageTestInit); err != nil || code != sharedProductRetry {
			t.Fatalf("refused publication: %d %v", code, err)
		}
		clean(t, f, 0)
	})
	t.Run("no container ID", func(t *testing.T) {
		f := newSharedImageIndexFixture(t, 3)
		init := sharedImageTestInit
		init.ContainerID = ""
		if code, err := f.cmd.publishFirst(t.Context(), 0, 1, policy, init); err != nil || code != sharedProductOK {
			t.Fatalf("publish: %d %v", code, err)
		}
		if len(f.fakes[sharedImageCommand].requests) != 0 || len(f.resolver.calls) != 0 {
			t.Fatal("image index built without a container ID")
		}
	})
}

// TestSharedProductImageUncertain: an UNCERTAIN key is reconciled by
// INSPECT (physically applied: counted; not applied: retried by nothing,
// the set is discarded); one INSPECT cannot settle keeps the set charged,
// never sealed or reclaimed, and the node Degraded.
func TestSharedProductImageUncertain(t *testing.T) {
	policy, _ := sharedCompiledTestPolicy(t)
	t.Run("applied", func(t *testing.T) {
		f := newSharedImageIndexFixture(t, 4)
		f.kernel.uncertain, f.kernel.applied = 2, true
		code, err := f.cmd.publishFirst(t.Context(), 0, 1, policy, sharedImageTestInit)
		if err != nil || code != sharedProductOK {
			t.Fatalf("publish: %d %v", code, err)
		}
		// The KEYS command stopped at the uncertain key: its run reported
		// UNCERTAIN, so the set is discarded (no partial seal).
		ops := sharedImageOps(f.fakes[sharedImageCommand].requests)
		if fmt.Sprint(ops) != fmt.Sprint([]uint32{sharedImageBegin, sharedImageKeys, sharedImageInspect, sharedImageAbort, sharedImageDelete, sharedImageReclaim}) {
			t.Fatalf("ops %v", ops)
		}
		if len(f.kernel.keys) != 0 || f.kernel.state[0].Reserved != 0 {
			t.Fatalf("left %d keys %+v", len(f.kernel.keys), f.kernel.state[0])
		}
		if err := f.cmd.image.health(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unsettled", func(t *testing.T) {
		f := newSharedImageIndexFixture(t, 4)
		f.kernel.uncertain, f.kernel.inspectRefused = 3, true
		if code, err := f.cmd.publishFirst(t.Context(), 0, 1, policy, sharedImageTestInit); err != nil || code != sharedProductOK {
			t.Fatalf("publish without an index: %d %v", code, err)
		}
		d := f.kernel.state[0].Descriptors[0]
		if d.PendingSequence == 0 || d.Phase != sharedImageBuilding || f.kernel.state[0].Reserved != 4 {
			t.Fatalf("uncertain set not retained charged: %+v", f.kernel.state[0])
		}
		for _, op := range sharedImageOps(f.fakes[sharedImageCommand].requests) {
			if op == sharedImageSeal || op == sharedImageReclaim {
				t.Fatalf("uncertain set sealed or reclaimed: %v", sharedImageOps(f.fakes[sharedImageCommand].requests))
			}
		}
		if err := f.cmd.image.health(); !errors.Is(err, errSharedImageUncertain) {
			t.Fatalf("health %v, want Degraded (uncertain)", err)
		}
		// Reconciled later (the next build of the slot discards first).
		f.kernel.inspectRefused = false
		if err := f.cmd.image.discard(t.Context(), 0); err != nil {
			t.Fatal(err)
		}
		if len(f.kernel.keys) != 0 || f.kernel.state[0].Reserved != 0 {
			t.Fatalf("left %d keys %+v", len(f.kernel.keys), f.kernel.state[0])
		}
	})
}

// TestSharedProductImageHealthMismatch: any ledger vs kernel count
// difference is Degraded.
func TestSharedProductImageHealthMismatch(t *testing.T) {
	f := newSharedImageIndexFixture(t, 3)
	policy, _ := sharedCompiledTestPolicy(t)
	if code, err := f.cmd.publishFirst(t.Context(), 0, 1, policy, sharedImageTestInit); err != nil || code != sharedProductOK {
		t.Fatalf("publish: %d %v", code, err)
	}
	f.kernel.mu.Lock()
	f.kernel.state[0].Descriptors[0].Present--
	f.kernel.mu.Unlock()
	if err := f.cmd.image.health(); !errors.Is(err, ErrSharedImageLedger) {
		t.Fatalf("health %v, want a ledger mismatch", err)
	}
	f.kernel.mu.Lock()
	f.kernel.state[0].Descriptors[0].Present++
	f.kernel.state[1].Descriptors[1] = sharedImageDescriptor{Phase: sharedImageBuilding, Present: 1}
	f.kernel.mu.Unlock()
	if err := f.cmd.image.health(); !errors.Is(err, ErrSharedImageLedger) {
		t.Fatalf("health %v, want the unaccounted slot 1 cell", err)
	}
	var reporter sharedImageReporter = &productRoutePublisher{cmd: f.cmd}
	if err := reporter.imageHealth(); err == nil || !strings.Contains(err.Error(), "image index") {
		t.Fatalf("live health %v", err)
	}
}

// TestSharedProductImageHealthRace (review M5): health while a build is
// between a kernel KEYS command and its ledger record, and concurrently
// with publish/recycle cycles, reports no integrity fault; a slot that is
// quiescent again is compared.
func TestSharedProductImageHealthRace(t *testing.T) {
	f := newSharedImageIndexFixture(t, 20)
	policy, _ := sharedCompiledTestPolicy(t)
	var during []error
	f.fakes[sharedImageCommand].respond = func(request []byte) uint32 {
		code := f.kernel.command(request)
		if binary.LittleEndian.Uint32(request[sharedProductHeaderBytes+16:]) == sharedImageKeys {
			// The kernel holds the keys; the ledger does not yet.
			during = append(during, f.cmd.image.health())
		}
		return code
	}
	if code, err := f.cmd.publishFirst(t.Context(), 1, 0xc0, policy, sharedImageTestInit); err != nil || code != sharedProductOK {
		t.Fatalf("publish: %d %v", code, err)
	}
	if len(during) != 2 || errors.Join(during...) != nil {
		t.Fatalf("health during the build: %v", during)
	}
	f.kernel.mu.Lock()
	f.kernel.state[1].Descriptors[0].Present--
	f.kernel.mu.Unlock()
	if err := f.cmd.image.health(); !errors.Is(err, ErrSharedImageLedger) {
		t.Fatalf("quiescent health %v, want a ledger mismatch", err)
	}
	f.kernel.mu.Lock()
	f.kernel.state[1].Descriptors[0].Present++
	f.kernel.mu.Unlock()

	f.fakes[sharedImageCommand].respond = f.kernel.command
	done := make(chan struct{})
	faults := make(chan error, 1)
	go func() {
		defer close(faults)
		for {
			select {
			case <-done:
				return
			default:
			}
			if err := f.cmd.image.health(); err != nil {
				faults <- err
				return
			}
		}
	}()
	for range 20 {
		if code, err := f.cmd.recycle(t.Context(), 1); err != nil || code != sharedProductOK {
			t.Fatalf("recycle: %d %v", code, err)
		}
		if code, err := f.cmd.publishFirst(t.Context(), 1, 0xc0, policy, sharedImageTestInit); err != nil || code != sharedProductOK {
			t.Fatalf("publish: %d %v", code, err)
		}
	}
	close(done)
	if err := <-faults; err != nil {
		t.Fatalf("health during publish/recycle cycles: %v", err)
	}
}

// TestSharedContainerIDValidation: Bind accepts only a containerd
// identifier; the policy predicate scan finds FromImage in rules and
// exceptions.
func TestSharedContainerIDValidation(t *testing.T) {
	for id, ok := range map[string]bool{
		strings.Repeat("ab", 32): true, "c0ffee": true, "a.b_c-d": true,
		"": false, "-a": false, "a-": false, "a..b": false, "a/b": false, strings.Repeat("a", 77): false,
	} {
		if ValidSharedContainerID(id) != ok {
			t.Errorf("ValidSharedContainerID(%q) != %v", id, ok)
		}
	}
	n := &NodeEnforcer{bindings: map[uint64]*BindingSession{}}
	if _, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 1, InitHostPID: 1, ContainerID: "a/b", Acquire: func(context.Context) (BindingLease, error) { return nil, nil }}); err == nil || !strings.Contains(err.Error(), "containerd identifier") {
		t.Fatalf("invalid container ID bound: %v", err)
	}
	yes := true
	p := sharedTestSourcePolicy("p", "1", "app")
	if sharedPolicyUsesImage(p) || sharedPolicyUsesImage(nil) {
		t.Fatal("no FromImage predicate found one")
	}
	p.Rules[0].Except = append(p.Rules[0].Except, fullpolicy.Exception{Actor: fullpolicy.Actor{FromImage: &yes}})
	if !sharedPolicyUsesImage(p) {
		t.Fatal("exception FromImage missed")
	}
}

// TestSharedProductImageSourcePins pins the PREPARE/FREE image lifetime in
// the product publisher and the image command's shape.
func TestSharedProductImageSourcePins(t *testing.T) {
	read := func(path string) string {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return squashSpace(string(raw))
	}
	publisher := read("bpf/opaque_real_owner_product_publisher.h")
	image := read("bpf/opaque_real_owner_product_image.h")
	program := read("../full/program.bpf.c")
	snapshot := read("../full/shared_snapshot.h")
	for _, pin := range []struct {
		name, source, text string
		count              int
	}{
		// Every FREE transition of a product record releases its image
		// reference in the same locked transition: the drop's reclaim is
		// the only one (abort, withdraw, recycle, drop_retired and the
		// revision's drops all go through real_owner_snapshot_drop).
		{"drop reclaims through the image release", publisher, "se_image_snapshot_reclaim_locked( images, &binding->state, real_owner_record(record))", 1},
		{"no reclaim without release", publisher, "se_snapshot_reclaim_locked(", 0},
		{"PREPARE references (first and revision)", publisher, "se_image_snapshot_prepare_locked(", 2},
		{"refused PREPARE counted", publisher, "real_owner_image_witness(SE_IMAGE_CLASS_PREPARE_REFUSED);", 2},
		{"refused first PREPARE undoes the open", publisher, "b->records[0] = (struct se_snapshot){}; real_owner_binding_clear_locked(b);", 1},
		{"command authenticated", image, "if (!r || !real_owner_cmd_authenticate(&r->header)) return OPAQUE_REAL_CMD_AUTH;", 1},
		{"handle is the consumed sequence", image, "__u64 sequence = r->header.sequence;", 1},
		{"keys through bpf_loop", image, "bpf_loop(count, real_owner_image_step, 0, 0);", 1},
		{"uncertain counted", image, "SE_IMAGE_CLASS_INSERT_UNCERTAIN : SE_IMAGE_CLASS_DELETE_UNCERTAIN);", 1},
		{"legacy image maps not in the shared node", program, "#ifndef ENFORCE_EXEC_SHARED_NODE static __always_inline int origin_ready(void);", 1},
		{"metadata image validity", snapshot, "!m->image_handle != !m->image_dev || (m->image_dev >> 20) ||", 1},
	} {
		if got := strings.Count(pin.source, squashSpace(pin.text)); got != pin.count {
			t.Errorf("%s: %d occurrences, want %d", pin.name, got, pin.count)
		}
	}
	if !regexp.MustCompile(`structse_snapshot_metadata\{[^}]*__u32image_dev;\};`).MatchString(snapshot) {
		t.Error("se_snapshot_metadata.image_dev is not the last word")
	}
}

// TestSharedProductConstants (review M8, M7): a product object is admitted
// only with se_image_ovl_layout (4 bytes) and se_verdict_load_epoch (8
// bytes) set; every collection load gets a fresh nonzero epoch.
func TestSharedProductConstants(t *testing.T) {
	if err := validateSharedProductConstants(sharedProductFakeManifest()); err != nil {
		t.Fatal(err)
	}
	for name, constants := range map[string]map[string]uint32{
		"none":         nil,
		"no layout":    {sharedVerdictLoadEpochConstant: 8},
		"no epoch":     {sharedImageOverlayLayoutConstant: 4},
		"32-bit epoch": {sharedImageOverlayLayoutConstant: 4, sharedVerdictLoadEpochConstant: 4},
	} {
		r := sharedProductFakeManifest()
		r.Constants = constants
		if err := validateSharedProductConstants(r); err == nil || !strings.Contains(err.Error(), "native constant") {
			t.Errorf("%s: %v, want a refusal", name, err)
		}
	}
	first, err := sharedImageOverlayConstants()
	if err != nil {
		t.Fatal(err)
	}
	second, err := sharedImageOverlayConstants()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := first[sharedImageOverlayLayoutConstant].(uint32); !ok {
		t.Fatalf("layout %T, want uint32", first[sharedImageOverlayLayoutConstant])
	}
	a, ok1 := first[sharedVerdictLoadEpochConstant].(uint64)
	b, ok2 := second[sharedVerdictLoadEpochConstant].(uint64)
	if !ok1 || !ok2 || a == 0 || b == 0 || a == b {
		t.Fatalf("load epochs %#x %#x, want two distinct nonzero uint64", a, b)
	}
}
