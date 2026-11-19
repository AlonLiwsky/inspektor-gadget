// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullruntime

import (
	"context"
	"errors"
	"math"
	"os"
	"testing"
)

type sharedTestCollection struct{ closes int }

func (c *sharedTestCollection) Close() error { c.closes++; return nil }

type sharedTestLease struct {
	BindingLease
	closes int
}

func (*sharedTestLease) Check(context.Context) error { return nil }
func (*sharedTestLease) InitProc() *os.File          { return nil }
func (l *sharedTestLease) Close() error              { l.closes++; return nil }
func TestSharedNodeAdmissionAndOwnership(t *testing.T) {
	ctx := context.Background()
	cfg := SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "isolated-shared-development"}
	starts := 0
	c := &sharedTestCollection{}
	start := func(context.Context, SharedNodeConfig, SharedAdmission) (sharedCollection, error) {
		starts++
		return c, nil
	}
	bad := cfg
	bad.Profile.PossibleCPUs = 65
	if _, err := startSharedNode(ctx, bad, start); err == nil || starts != 0 {
		t.Fatal("allocated before profile admission")
	}
	bad = cfg
	bad.ABI3Development = false
	if _, err := startSharedNode(ctx, bad, start); err == nil || starts != 0 {
		t.Fatal("default selected development")
	}
	if _, err := StartNode(ctx, cfg); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatal("unimplemented production startup must refuse", err)
	}
	n, err := startSharedNode(ctx, cfg, start)
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	a, b := &sharedTestLease{}, &sharedTestLease{}
	bind := func(id uint64, l *sharedTestLease) *BindingSession {
		t.Helper()
		s, e := n.Bind(ctx, SharedBindingConfig{InitHostPID: 10, CgroupID: id, Acquire: func(context.Context) (BindingLease, error) { return l, nil }})
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	sa, sb := bind(10, a), bind(20, b)
	if starts != 1 || sa.PreparedID() == sb.PreparedID() {
		t.Fatal("collection or scope ownership split incorrectly")
	}
	acquired := false
	if _, err := n.Bind(ctx, SharedBindingConfig{InitHostPID: 10, CgroupID: 10, Acquire: func(context.Context) (BindingLease, error) { acquired = true; return a, nil }}); err == nil || acquired {
		t.Fatal("duplicate acquired lease")
	}
	if sa.Inspect().Ready || sb.Inspect().Ready {
		t.Fatal("native foundation claimed Ready")
	}
	if err := sa.Remove(ctx, 0); err != nil {
		t.Fatal(err)
	}
	if a.closes != 0 || b.closes != 0 || c.closes != 0 {
		t.Fatal("removal affected neighbor/collection")
	}
	if err := n.StopNode(ctx); err != nil {
		t.Fatal(err)
	}
	if b.closes != 1 || c.closes != 1 {
		t.Fatal("stop did not join cleanup")
	}
	if err := n.StopNode(ctx); err != nil || c.closes != 1 {
		t.Fatal("duplicate stop")
	}
}

func TestSharedBindingAcquisitionDoesNotBlockNeighbor(t *testing.T) {
	ctx := context.Background()
	c := &sharedTestCollection{}
	n, err := startSharedNode(ctx, SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "development"}, func(context.Context, SharedNodeConfig, SharedAdmission) (sharedCollection, error) { return c, nil })
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, e := n.Bind(ctx, SharedBindingConfig{InitHostPID: 10, CgroupID: 1, Acquire: func(context.Context) (BindingLease, error) { close(entered); <-release; return &sharedTestLease{}, nil }})
		done <- e
	}()
	<-entered
	b, err := n.Bind(ctx, SharedBindingConfig{InitHostPID: 10, CgroupID: 2, Acquire: func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }})
	if err != nil {
		close(release)
		t.Fatal(err)
	}
	if err = b.Remove(ctx, 0); err != nil {
		close(release)
		t.Fatal(err)
	}
	close(release)
	if err = <-done; err != nil {
		t.Fatal(err)
	}
	if err = n.StopNode(ctx); err != nil {
		t.Fatal(err)
	}
}

type sharedFailCloseLease struct {
	sharedTestLease
	fail bool
}

func (l *sharedFailCloseLease) Close() error {
	if l.fail {
		return errors.New("retained pin")
	}
	return l.sharedTestLease.Close()
}

func TestSharedNodeRetainsFailedCleanup(t *testing.T) {
	ctx := context.Background()
	c := &sharedTestCollection{}
	n, err := startSharedNode(ctx, SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "development"}, func(context.Context, SharedNodeConfig, SharedAdmission) (sharedCollection, error) { return c, nil })
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	lease := &sharedFailCloseLease{fail: true}
	s, err := n.Bind(ctx, SharedBindingConfig{InitHostPID: 10, CgroupID: 1, Acquire: func(context.Context) (BindingLease, error) { return lease, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err = n.StopNode(ctx); err == nil || c.closes != 1 {
		t.Fatal("failed retained pin cleanup was not reported after detach")
	}
	if s.Inspect().Ready {
		t.Fatal("failed cleanup Ready")
	}
	lease.fail = false
	if err = n.StopNode(ctx); err != nil || c.closes != 1 || lease.closes != 1 {
		t.Fatal("cleanup retry", err)
	}
}

func TestSharedNodePartialStartOwnership(t *testing.T) {
	ctx := context.Background()
	c := &sharedTestCollection{}
	want := errors.New("partial attachment")
	n, err := startSharedNode(ctx, SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "development"}, func(context.Context, SharedNodeConfig, SharedAdmission) (sharedCollection, error) { return c, want })
	if n == nil || !errors.Is(err, want) {
		t.Fatal("lost partial collection ownership", err)
	}
	acquired := false
	if _, err = n.Bind(ctx, SharedBindingConfig{InitHostPID: 10, CgroupID: 1, Acquire: func(context.Context) (BindingLease, error) { acquired = true; return &sharedTestLease{}, nil }}); err == nil || acquired {
		t.Fatal("partial node accepted binding")
	}
	if err = n.StopNode(ctx); err != nil || c.closes != 1 {
		t.Fatal("partial cleanup", err)
	}
}

func TestSharedScopeCookieDoesNotReachReservedSentinel(t *testing.T) {
	n := &NodeEnforcer{config: SharedNodeConfig{Profile: sharedTestProfile()}, bindings: map[uint64]*BindingSession{}, nextPreparedID: math.MaxUint64 - 1}
	called := false
	if _, err := n.Bind(context.Background(), SharedBindingConfig{InitHostPID: 10, CgroupID: 1, Acquire: func(context.Context) (BindingLease, error) { called = true; return &sharedTestLease{}, nil }}); err == nil || called {
		t.Fatal("reserved scope cookie acquired")
	}
}
