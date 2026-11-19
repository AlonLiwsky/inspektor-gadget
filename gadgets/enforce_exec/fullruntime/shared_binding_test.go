// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func installSharedPinTest(n *NodeEnforcer) {
	n.prepareBinding = func(ctx context.Context, c SharedBindingConfig, l BindingLease) (*sharedPhysicalPins, error) {
		if err := l.Check(ctx); err != nil {
			return &sharedPhysicalPins{lease: l}, err
		}
		return &sharedPhysicalPins{
			lease: l, cgroupID: c.CgroupID, initPID: c.InitHostPID, start: "test-start", identity: [2]uint64{1, c.CgroupID},
			checkTest:    func(context.Context) error { return nil },
			identityTest: &SharedInitIdentity{TGID: c.InitHostPID, StartTicks: 4242, MountNS: 4026531840 + c.CgroupID},
		}, nil
	}
}

func TestSharedBindingRetainsPhysicalAccountAcrossRemove(t *testing.T) {
	c := &sharedTestCollection{}
	n, err := startSharedNode(t.Context(), SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "dev"}, func(context.Context, SharedNodeConfig, SharedAdmission) (sharedCollection, error) { return c, nil })
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	first, second := &sharedTestLease{}, &sharedTestLease{}
	bind := func(l BindingLease, pid uint32) (*BindingSession, error) {
		return n.Bind(t.Context(), SharedBindingConfig{CgroupID: 42, InitHostPID: pid, Acquire: func(context.Context) (BindingLease, error) { return l, nil }})
	}
	a, err := bind(first, 10)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Remove(t.Context(), 0); err != nil {
		t.Fatal(err)
	}
	if first.closes != 0 {
		t.Fatal("logical removal closed physical pin")
	}
	b, err := bind(second, 10)
	if err != nil {
		t.Fatal(err)
	}
	if a.PreparedID() != b.PreparedID() || a.ScopeCookie() != 0 || b.ScopeCookie() != 0 || second.closes != 1 {
		t.Fatal("rebind reset history account or retained redundant lease")
	}
	if b.Inspect().RootAuthorized || b.Inspect().Ready {
		t.Fatal("native preparation claimed kernel root authority")
	}
	if err := b.Remove(t.Context(), 0); err != nil {
		t.Fatal(err)
	}
	wrong := &sharedTestLease{}
	if _, err := bind(wrong, 11); err == nil {
		t.Fatal("new init silently adopted old scope")
	}
	if first.closes != 0 || wrong.closes != 1 {
		t.Fatal("identity refusal discarded retained scope")
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
	if first.closes != 1 || c.closes != 1 {
		t.Fatal("detached collection did not release retained physical scope")
	}
}

func TestSharedBindingRequiresTrustedInitBeforeAcquire(t *testing.T) {
	n, err := NewNodeEnforcer(SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "dev"})
	if err != nil {
		t.Fatal(err)
	}
	called := false
	_, err = n.Bind(t.Context(), SharedBindingConfig{CgroupID: 7, Acquire: func(context.Context) (BindingLease, error) { called = true; return nil, errors.New("must not acquire") }})
	if err == nil || called {
		t.Fatal("missing trusted init acquired lease")
	}
}

type sharedPhysicalTestLease struct {
	sharedTestLease
	proc, cgroup, mount *os.File
}

func (l *sharedPhysicalTestLease) InitProc() *os.File { return l.proc }

func (l *sharedPhysicalTestLease) Cgroup() *os.File { return l.cgroup }

func (l *sharedPhysicalTestLease) MountNamespace() *os.File { return l.mount }

func (l *sharedPhysicalTestLease) HostMountNamespace() *os.File { return l.mount }

func TestSharedPhysicalPreparationRejectsNonCgroupAndRetainsPartialPins(t *testing.T) {
	cg, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer cg.Close()
	proc, err := os.Open("/proc/self")
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	mount, err := os.Open("/proc/self/ns/mnt")
	if err != nil {
		t.Fatal(err)
	}
	defer mount.Close()
	var stat unix.Stat_t
	if err := unix.Fstat(int(cg.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	lease := &sharedPhysicalTestLease{proc: proc, cgroup: cg, mount: mount}
	pins, err := prepareSharedPhysicalPins(t.Context(), SharedBindingConfig{CgroupID: stat.Ino, InitHostPID: uint32(os.Getpid())}, lease)
	if err == nil || pins == nil || pins.cgroup == nil || pins.proc == nil {
		t.Fatalf("non-cgroup accepted or partial pins lost: %v", err)
	}
	if pins.cgroup.Fd() == cg.Fd() || pins.proc.Fd() == proc.Fd() {
		t.Fatal("borrowed pins were not duplicated")
	}
	if err := pins.Close(); err != nil {
		t.Fatal(err)
	}
	if lease.closes != 1 {
		t.Fatal("trusted lease not released")
	}
	if _, err := cg.Stat(); err != nil {
		t.Fatal("closed borrowed cgroup descriptor")
	}
}

func TestSharedRetainedScopeQuotaDoesNotDisappearOnRemove(t *testing.T) {
	n := &NodeEnforcer{config: SharedNodeConfig{Profile: sharedTestProfile()}, bindings: map[uint64]*BindingSession{}}
	installSharedPinTest(n)
	for _, id := range []uint64{1, 2} {
		s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: id, InitHostPID: 10, Acquire: func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }})
		if err != nil {
			t.Fatal(err)
		}
		if err = s.Remove(t.Context(), 0); err != nil {
			t.Fatal(err)
		}
	}
	called := false
	if _, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 3, InitHostPID: 10, Acquire: func(context.Context) (BindingLease, error) { called = true; return nil, nil }}); err == nil || called {
		t.Fatal("retained account quota was released by logical Remove")
	}
	if err := n.releasePhysicalScopes(); err == nil {
		t.Fatal("pins released before detached collection proof")
	}
	n.collectionClosed = true
	if err := n.releasePhysicalScopes(); err != nil {
		t.Fatal(err)
	}
}

func TestSharedRegisteredScopeRejectsPreparationCleanup(t *testing.T) {
	n := &NodeEnforcer{config: SharedNodeConfig{Profile: sharedTestProfile()}, bindings: map[uint64]*BindingSession{}}
	installSharedPinTest(n)
	lease := &sharedTestLease{}
	s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 42, InitHostPID: 10, Acquire: func(context.Context) (BindingLease, error) { return lease, nil }})
	if err != nil {
		t.Fatal(err)
	}
	// Private injection models an already authenticated receipt; it is NOT a
	// production registration API or proof of kernel command execution.
	s.account.registration = sharedReceiptWire{Operation: sharedBindingOpen, Sequence: 450}
	if s.ScopeCookie() != 450 || s.PreparedID() == 450 {
		t.Fatal("kernel sequence replaced by Go reservation")
	}
	if err := s.Remove(t.Context(), 0); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatal("registered scope bypassed withdrawal", err)
	}
	if lease.closes != 0 {
		t.Fatal("registered scope pin closed")
	}
	n.collectionClosed = true
	delete(n.bindings, 42)
	if err := n.releasePhysicalScopes(); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatal("closed FD state substituted for kernel retirement", err)
	}
	if lease.closes != 0 {
		t.Fatal("registered scope lost physical pin")
	}
}
