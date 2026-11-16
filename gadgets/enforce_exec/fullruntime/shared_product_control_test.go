// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"encoding/binary"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedFakeAdminMap records the admin install's writes and freezes. As the
// se_admin map it also stands in for the admin thread's PIDFD_THREAD
// (sharedAdminPidfdOpener): it records the thread that asked and returns a
// plain eventfd, so these tests run on host kernels without PIDFD_THREAD.
type sharedFakeAdminMap struct {
	mu        sync.Mutex
	puts      map[uint32]any
	frozen    bool
	initial   sharedNodeWire
	putErr    error
	pidfdTIDs []int
}

func (m *sharedFakeAdminMap) openAdminPidfd(tid int) (int, error) {
	m.mu.Lock()
	m.pidfdTIDs = append(m.pidfdTIDs, tid)
	m.mu.Unlock()
	return unix.Eventfd(0, unix.EFD_CLOEXEC)
}

func (m *sharedFakeAdminMap) Put(key, value interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.putErr != nil {
		return m.putErr
	}
	if m.frozen {
		return errors.New("fake: frozen")
	}
	if m.puts == nil {
		m.puts = map[uint32]any{}
	}
	m.puts[key.(uint32)] = value
	return nil
}

func (m *sharedFakeAdminMap) Freeze() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.frozen = true
	return nil
}

func (m *sharedFakeAdminMap) Lookup(_, valueOut interface{}) error {
	*valueOut.(*sharedNodeWire) = m.initial
	return nil
}

// sharedFakeCommand records the thread and request of each run.
type sharedFakeCommand struct {
	mu       sync.Mutex
	code     uint32
	respond  func(request []byte) uint32 // overrides code when set
	runErr   error                       // returned with the code: an unknown outcome (lost reply)
	requests [][]byte
	tids     []int
}

func (c *sharedFakeCommand) Run(o *ebpf.RunOptions) (uint32, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	request := o.Context.([]byte)
	c.requests = append(c.requests, request)
	c.tids = append(c.tids, unix.Gettid())
	if c.respond != nil {
		return c.respond(request), c.runErr
	}
	return c.code, c.runErr
}

func sharedProductManifest(p SharedProfile) *operators.NativeResources {
	r := sharedCandidateFakeManifest()
	geometry, _, err := sharedOpaqueOwnerGeometry(p)
	if err != nil {
		panic(err)
	}
	maps.Copy(r.Maps, geometry)
	maps.Copy(r.Maps, sharedExitCreditGeometry(p))
	maps.Copy(r.Maps, sharedProductAdminGeometry)
	product, err := sharedProductMapGeometry(p)
	if err != nil {
		panic(err)
	}
	maps.Copy(r.Maps, product)
	b := uint32(p.Bindings)
	r.Maps["se_routes"] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: sharedProductRouteAnchorBytes, MaxEntries: b}
	r.Maps["se_bindings"] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 1632, MaxEntries: b}
	r.Maps["se_route_index"] = operators.NativeMapResource{Type: uint32(ebpf.Hash), KeySize: 8, ValueSize: 8, MaxEntries: b}
	for _, name := range sharedProductCommands {
		r.Programs[name] = operators.NativeProgramResource{Type: uint32(ebpf.Syscall)}
	}
	for _, c := range sharedProductTailCalls {
		r.Maps[c.Map] = operators.NativeMapResource{Type: uint32(ebpf.ProgramArray), KeySize: 4, ValueSize: 4, MaxEntries: 1}
		r.Programs[c.Program] = operators.NativeProgramResource{Type: uint32(ebpf.LSM), Target: sharedProgramDisabled}
	}
	r.TailCalls = slices.Clone(sharedProductTailCalls)
	for name, valueSize := range sharedProductCapsuleMaps {
		r.Maps[name] = operators.NativeMapResource{Type: uint32(ebpf.TaskStorage), KeySize: 4, ValueSize: valueSize, Flags: unix.BPF_F_NO_PREALLOC}
	}
	r.Maps[WorkSyncWitnessMap] = sharedProductWorkSync
	// G020: the verdict emitter's counters (its ring is in product).
	r.Maps[SharedVerdictCountersMap] = sharedVerdictCountersShape
	// M8: the native constants the eBPF operator set (sharedImageOverlayConstants).
	r.Constants = map[string]uint32{sharedImageOverlayLayoutConstant: 4, sharedVerdictLoadEpochConstant: 8}
	return r
}

func sharedProductPrograms() (map[string]sharedCommandProgram, map[string]*sharedFakeCommand) {
	out, fakes := map[string]sharedCommandProgram{}, map[string]*sharedFakeCommand{}
	for _, name := range sharedProductCommands {
		f := &sharedFakeCommand{}
		out[name], fakes[name] = f, f
	}
	return out, fakes
}

func TestSharedProductControlAdmission(t *testing.T) {
	p := sharedCandidateQualificationProfile()
	if err := validateSharedProductControl(p, sharedProductManifest(p)); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*operators.NativeResources){
		"protocol route anchor (88 B)": func(r *operators.NativeResources) {
			m := r.Maps["se_routes"]
			m.ValueSize = 88
			r.Maps["se_routes"] = m
		},
		"routes for 3 bindings": func(r *operators.NativeResources) {
			m := r.Maps["se_routes"]
			m.MaxEntries = 3
			r.Maps["se_routes"] = m
		},
		"missing se_admin":                    func(r *operators.NativeResources) { delete(r.Maps, "se_admin") },
		"without the synchronous WORK return": func(r *operators.NativeResources) { delete(r.Maps, WorkSyncWitnessMap) },
		"short synchronous WORK return witness": func(r *operators.NativeResources) {
			m := r.Maps[WorkSyncWitnessMap]
			m.MaxEntries--
			r.Maps[WorkSyncWitnessMap] = m
		},
		"missing receipt": func(r *operators.NativeResources) { delete(r.Maps, "opaque_real_cmd_receipt") },
		"writable se_configuration": func(r *operators.NativeResources) {
			m := r.Maps["se_configuration"]
			m.Flags = 0
			r.Maps["se_configuration"] = m
		},
		"missing adopt_finish": func(r *operators.NativeResources) { delete(r.Programs, "opaque_real_adopt_finish") },
		"adopt state of the 112 B layout": func(r *operators.NativeResources) {
			m := r.Maps["opaque_real_adopt_state"]
			m.ValueSize = 112
			r.Maps["opaque_real_adopt_state"] = m
		},
		"adopted set smaller than the TASK pool": func(r *operators.NativeResources) {
			m := r.Maps["opaque_real_adopted"]
			m.MaxEntries--
			r.Maps["opaque_real_adopted"] = m
		},
		"adopt roles not per-CPU": func(r *operators.NativeResources) {
			m := r.Maps["opaque_real_adopt_roles"]
			m.Type = uint32(ebpf.Array)
			r.Maps["opaque_real_adopt_roles"] = m
		},
		"tail call missing": func(r *operators.NativeResources) { r.TailCalls = r.TailCalls[1:] },
		"tail call extra": func(r *operators.NativeResources) {
			r.TailCalls = append(r.TailCalls, operators.NativeTailCall{Map: "opaque_real_rule_strict", Index: 0, Program: "opaque_real_owner_rule_audit"})
		},
		"tail call to another target": func(r *operators.NativeResources) {
			r.TailCalls[1].Program = "opaque_real_owner_prepare_audit"
		},
		"unpopulated program array": func(r *operators.NativeResources) {
			r.Maps["opaque_real_unreviewed_targets"] = operators.NativeMapResource{Type: uint32(ebpf.ProgramArray), KeySize: 4, ValueSize: 4, MaxEntries: 1}
		},
		"program array with an empty slot": func(r *operators.NativeResources) {
			m := r.Maps["opaque_real_finish_audit"]
			m.MaxEntries = 2
			r.Maps["opaque_real_finish_audit"] = m
		},
		"attached tail call target": func(r *operators.NativeResources) {
			r.Programs["opaque_real_owner_child_target_candidate"] = operators.NativeProgramResource{Type: uint32(ebpf.LSM), Target: "task_alloc"}
		},
		"userspace test gate": func(r *operators.NativeResources) {
			r.Maps["opaque_real_owner_child_gate"] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 4, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG}
		},
		"capsule store as a one-entry array": func(r *operators.NativeResources) {
			r.Maps["se_exec_capsules"] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 104, MaxEntries: 1}
		},
		"capsule store as a pid_max-sized array": func(r *operators.NativeResources) {
			r.Maps["se_exec_capsules"] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 104, MaxEntries: 1 << 22}
		},
		"marker store as an array": func(r *operators.NativeResources) {
			r.Maps["se_exec_markers"] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 16, MaxEntries: 1 << 22}
		},
		"capsule task storage of another value size": func(r *operators.NativeResources) {
			m := r.Maps["se_exec_capsules"]
			m.ValueSize = 96
			r.Maps["se_exec_capsules"] = m
		},
		"missing capsule store": func(r *operators.NativeResources) { delete(r.Maps, "se_exec_capsules") },
		"missing attempts":      func(r *operators.NativeResources) { delete(r.Maps, "opaque_real_attempts") },
		// G019 gaps 1 and 2: the birth park is per-task storage of its
		// exact value, its witness the 8-cell RDONLY array.
		"missing birth park":         func(r *operators.NativeResources) { delete(r.Maps, sharedBirthParkMap) },
		"missing birth-park witness": func(r *operators.NativeResources) { delete(r.Maps, BirthParkStatsMap) },
		"birth park as an array": func(r *operators.NativeResources) {
			r.Maps[sharedBirthParkMap] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: sharedBirthParkBytes, MaxEntries: 1}
		},
		"birth park of another value size": func(r *operators.NativeResources) {
			m := r.Maps[sharedBirthParkMap]
			m.ValueSize = 72
			r.Maps[sharedBirthParkMap] = m
		},
		"4-cell birth-park witness": func(r *operators.NativeResources) {
			m := r.Maps[BirthParkStatsMap]
			m.MaxEntries = 4
			r.Maps[BirthParkStatsMap] = m
		},
		"11-cell fail-closed witness": func(r *operators.NativeResources) {
			m := r.Maps["opaque_real_fail_closed_rates"]
			m.MaxEntries = 11
			r.Maps["opaque_real_fail_closed_rates"] = m
		},
		"se_objects of 72 B": func(r *operators.NativeResources) {
			m := r.Maps["se_objects"]
			m.ValueSize = 72
			r.Maps["se_objects"] = m
		},
		"se_arena one cell short": func(r *operators.NativeResources) {
			m := r.Maps["se_arena"]
			m.MaxEntries--
			r.Maps["se_arena"] = m
		},
		"attached publish": func(r *operators.NativeResources) {
			r.Programs["opaque_real_route_publish"] = operators.NativeProgramResource{Type: uint32(ebpf.Syscall), Target: "x"}
		},
		"TASK geometry of another quota": func(r *operators.NativeResources) {
			m := r.Maps["se_opaque_charges"]
			m.MaxEntries *= 2
			r.Maps["se_opaque_charges"] = m
		},
	} {
		r := sharedProductManifest(p)
		edit(r)
		if err := validateSharedProductControl(p, r); err == nil {
			t.Errorf("%s admitted", name)
		}
	}
}

// TestSharedProductControlRevisionHeadroom: revision stages into a FREE
// object before the old one is released, so a product profile with no
// spare policy object (objects <= bindings) is refused, each manifest built
// for its own profile (no geometry mismatch hides the refusal).
func TestSharedProductControlRevisionHeadroom(t *testing.T) {
	for _, c := range []struct {
		slots [4]uint64
		ok    bool
	}{
		{[4]uint64{2, 0, 0, 0}, false},
		{[4]uint64{1, 1, 0, 0}, false},
		{[4]uint64{3, 0, 0, 0}, true},
		{[4]uint64{2, 1, 0, 0}, true},
		{[4]uint64{4, 0, 0, 0}, true}, // the PoC default: 2 x Bindings
	} {
		p := sharedProductProfileFor(128, 16)
		p.ExitTombstones = sharedProductExitTombstones
		p.PolicySlots = c.slots
		if p.Bindings != 2 {
			t.Fatalf("profile has %d bindings, want 2", p.Bindings)
		}
		err := validateSharedProductControl(p, sharedProductManifest(p))
		switch {
		case c.ok && err != nil:
			t.Errorf("%v / 2 bindings refused: %v", c.slots, err)
		case !c.ok && (err == nil || !strings.Contains(err.Error(), "revision needs at least one spare object")):
			t.Errorf("%v / 2 bindings: %v, want the revision headroom refusal", c.slots, err)
		}
	}
}

// TestSharedProductControlInstallsAdminOnItsThread: the admin thread writes
// its own se_admin entry and the configuration, freezes both, and runs every
// command on that thread; an initialized configuration is refused.
func TestSharedProductControlInstallsAdminOnItsThread(t *testing.T) {
	p := sharedCandidateQualificationProfile()
	admin, configuration := &sharedFakeAdminMap{}, &sharedFakeAdminMap{}
	programs, fakes := sharedProductPrograms()
	c, err := newSharedProductControl(t.Context(), p, sharedProductManifest(p), admin, configuration, programs)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := c.close(); err != nil {
			t.Error(err)
		}
	}()
	if !admin.frozen || !configuration.frozen || len(admin.puts) != 1 || len(configuration.puts) != 1 {
		t.Fatalf("admin install: admin %+v configuration %+v", admin, configuration)
	}
	// The se_admin key is the admin thread's own pidfd: asked for once, by
	// the thread that later runs every command. Only the fake admin map
	// supplies it; the product map (*ebpf.Map) has no seam.
	if len(admin.pidfdTIDs) != 1 || len(configuration.pidfdTIDs) != 0 {
		t.Fatalf("admin pidfd requested by %v (configuration %v), want one admin-thread request", admin.pidfdTIDs, configuration.pidfdTIDs)
	}
	if _, ok := any((*ebpf.Map)(nil)).(sharedAdminPidfdOpener); ok {
		t.Fatal("*ebpf.Map implements the admin pidfd test seam")
	}
	for _, nonce := range admin.puts {
		if nonce != c.config.Nonce || c.config.Nonce == 0 || c.config.NodeCookie == 0 {
			t.Fatalf("se_admin holds %v, config %+v", nonce, c.config)
		}
	}
	if got := configuration.puts[0]; got != c.config || c.config.Bindings != 2 {
		t.Fatalf("configuration %+v, want %+v", got, c.config)
	}
	fakes["opaque_real_adopt_task"].code = 2
	for range 2 {
		if code, err := c.run(t.Context(), "opaque_real_adopt_task", []byte{1, 2, 3}); err != nil || code != 2 {
			t.Fatalf("run: code %d err %v", code, err)
		}
	}
	for _, tid := range fakes["opaque_real_adopt_task"].tids {
		if tid != admin.pidfdTIDs[0] {
			t.Fatalf("command ran on thread %d, admin pidfd opened on %d", tid, admin.pidfdTIDs[0])
		}
	}
	// Each request is the 24-byte authenticated header (node cookie, nonce,
	// a fresh increasing sequence) followed by the body.
	requests := fakes["opaque_real_adopt_task"].requests
	for i, request := range requests {
		want := sharedProductRequest(c.config, uint64(i+1), []byte{1, 2, 3})
		if len(request) != sharedProductHeaderBytes+3 || string(request) != string(want) {
			t.Fatalf("request %d: %x, want %x", i, request, want)
		}
	}
	if binary.LittleEndian.Uint64(requests[0][0:8]) != c.config.NodeCookie || binary.LittleEndian.Uint64(requests[0][8:16]) != c.config.Nonce {
		t.Fatal("header does not carry the node cookie and nonce")
	}
	if _, err := c.run(t.Context(), "se_command", nil); err == nil {
		t.Fatal("unknown command ran")
	}

	initialized := &sharedFakeAdminMap{initial: sharedNodeWire{NodeCookie: 1}}
	if _, err := newSharedProductControl(t.Context(), p, sharedProductManifest(p), &sharedFakeAdminMap{}, initialized, programs); err == nil || !strings.Contains(err.Error(), "already initialized") {
		t.Fatalf("initialized configuration: %v", err)
	}
	delete(programs, "opaque_real_route_recycle")
	if _, err := newSharedProductControl(t.Context(), p, sharedProductManifest(p), &sharedFakeAdminMap{}, &sharedFakeAdminMap{}, programs); err == nil {
		t.Fatal("control built without a published command")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := newSharedProductControl(canceled, p, sharedProductManifest(p), &sharedFakeAdminMap{}, &sharedFakeAdminMap{}, programs); err == nil {
		t.Fatal("canceled control built")
	}
}

func TestSharedProductControlAdminFailureFailsClosed(t *testing.T) {
	p := sharedCandidateQualificationProfile()
	programs, _ := sharedProductPrograms()
	c, err := newSharedProductControl(t.Context(), p, sharedProductManifest(p), &sharedFakeAdminMap{putErr: errors.New("EPERM")}, &sharedFakeAdminMap{}, programs)
	if err == nil {
		t.Fatal("admin install failure ignored")
	}
	if _, runErr := c.run(t.Context(), "opaque_real_route_publish", nil); runErr == nil {
		t.Fatal("command ran without an admin thread")
	}
	if err := c.close(); err != nil {
		t.Fatal(err)
	}
}
