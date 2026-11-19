// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"os"
	"testing"
)

type sharedRegistrationTransport struct{ sharedCommandFaultTransport }

func (f *sharedRegistrationTransport) runSharedCommand() (uint32, error) {
	result, err := f.sharedCommandFaultTransport.runSharedCommand()
	f.receipt.Serial, f.receipt.Generation, f.receipt.Value = 0, 0, 0
	return result, err
}

// Inject only the private verified-protocol capability for lifecycle unit tests.
// Real Start must derive it from exact manifest AND loaded resource validation.
func sharedRegistrationHost(t *testing.T) (*NodeEnforcer, *sharedHostContext) {
	n, gc := sharedPreparedHost(t)
	n.host.control.config = sharedNodeWire{NodeCookie: 11, Nonce: 22}
	n.host.protocol = &sharedProtocolCapability{}
	n.host.handshakeComplete = true
	n.host.scopeSlots = make([]*sharedPhysicalScope, n.config.Profile.Bindings)
	return n, gc
}

func sharedRegistrationSession(t *testing.T, n *NodeEnforcer, id uint64) (*BindingSession, *sharedTestLease) {
	t.Helper()
	lease := &sharedTestLease{}
	s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: id, InitHostPID: 10, Acquire: func(context.Context) (BindingLease, error) { return lease, nil }})
	if err != nil {
		t.Fatal(err)
	}
	return s, lease
}

func TestSharedRegistrationUsesReservedSlotAndAcknowledgedSequence(t *testing.T) {
	n, _ := sharedRegistrationHost(t)
	n.nextPreparedID = 100
	first, _ := sharedRegistrationSession(t, n, 42)
	second, _ := sharedRegistrationSession(t, n, 43)
	f := &sharedRegistrationTransport{}
	if err := first.registerSharedScopeUsing(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	if f.command.Binding != 0 || first.PreparedID() != 101 || first.ScopeCookie() != f.command.Sequence || first.ScopeCookie() == first.PreparedID() {
		t.Fatal("native prepared ID substituted for kernel slot/cookie")
	}
	if err := second.registerSharedScopeUsing(t.Context(), f); err != nil {
		t.Fatal(err)
	}
	if f.command.Binding != 1 || second.ScopeCookie() != f.command.Sequence || second.ScopeCookie() == first.ScopeCookie() {
		t.Fatal("scope slot/cookie alias")
	}
	if err := first.registerSharedScopeUsing(t.Context(), f); err != nil || f.runs != 2 {
		t.Fatal("registered scope reopened", err)
	}
	if first.Inspect().Ready || first.Inspect().RootAuthorized {
		t.Fatal("BindingOpen inferred qualification")
	}
	if err := first.Remove(t.Context(), 0); err == nil {
		t.Fatal("ordinary Remove bypassed registered-account guard")
	}
}

func TestSharedRegistrationCanceledCompletedCallRetainedUntilDetach(t *testing.T) {
	n, gc := sharedRegistrationHost(t)
	s, lease := sharedRegistrationSession(t, n, 42)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f := &sharedRegistrationTransport{sharedCommandFaultTransport: sharedCommandFaultTransport{afterRun: cancel}}
	if err := s.registerSharedScopeUsing(ctx, f); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s.ScopeCookie() == 0 || !s.account.native.attempted || n.host.scopeSlots[0] != s.account {
		t.Fatal("completed canceled open discarded")
	}
	file, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	n.host.borrowed = []sharedBorrowedFD{sharedTestBorrowedFD{file}}
	if err := n.BeforeStop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if lease.closes != 0 || s.Inspect().Removed || !n.host.commandsJoined {
		t.Fatal("logical stop released registered pins")
	}
	if err := n.Close(gc); err != nil {
		t.Fatal(err)
	}
	if err := n.ReleaseAfterDetach(); err == nil || lease.closes != 0 {
		t.Fatal("live borrowed FD accepted as teardown")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := n.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
	if lease.closes != 1 || !s.Inspect().Removed || !s.account.native.destroyed {
		t.Fatal("whole-node destruction not recorded/released")
	}
	if err := n.ReleaseAfterDetach(); err != nil || lease.closes != 1 {
		t.Fatal("duplicate release", err)
	}
}

func TestSharedRegistrationUnresolvedOutcomeDestroyedOnlyWithProtocolCollection(t *testing.T) {
	n, gc := sharedRegistrationHost(t)
	s, lease := sharedRegistrationSession(t, n, 42)
	f := &sharedRegistrationTransport{sharedCommandFaultTransport: sharedCommandFaultTransport{readErr: errors.New("unreadable open receipt")}}
	if err := s.registerSharedScopeUsing(t.Context(), f); err == nil {
		t.Fatal("unknown open accepted")
	}
	if s.ScopeCookie() != 0 || !s.account.native.attempted {
		t.Fatal("unknown open inferred or forgotten")
	}
	// Inject the same transport only for shutdown reconciliation, not authority.
	if err := n.beforeStopProtocolUsing(t.Context(), f); err == nil {
		t.Fatal("unknown cleanup diagnostic lost")
	}
	if !n.host.commandsJoined || lease.closes != 0 || s.account.native.destroyed {
		t.Fatal("unresolved was confused with unjoined or already destroyed")
	}
	if err := n.Close(gc); err == nil || !n.host.operatorClosed {
		t.Fatal("protocol detach permission or sticky diagnostic lost")
	}
	if err := n.ReleaseAfterDetach(); err != nil {
		t.Fatal(err)
	}
	if lease.closes != 1 || !s.account.native.destroyed || s.account.registration.Sequence != 0 || f.runs != 1 {
		t.Fatal("destroyed-with-collection fabricated an acknowledged operation")
	}
}

func TestSharedRegistrationStopJoinsBoundedOpenOutsideNodeLock(t *testing.T) {
	n, gc := sharedRegistrationHost(t)
	s, lease := sharedRegistrationSession(t, n, 42)
	entered, release := make(chan struct{}), make(chan struct{})
	f := &sharedRegistrationTransport{sharedCommandFaultTransport: sharedCommandFaultTransport{afterRun: func() { close(entered); <-release }}}
	done := make(chan error, 1)
	go func() { done <- s.registerSharedScopeUsing(context.Background(), f) }()
	<-entered
	n.mu.Lock()
	registeredOperation := s.account.native.done != nil
	n.mu.Unlock() // The held command cannot retain the node mutex.
	if !registeredOperation {
		t.Fatal("held command has no bounded operation record")
	}
	if err := s.registerSharedScopeUsing(t.Context(), f); err == nil {
		t.Fatal("duplicate concurrent scope operation admitted")
	}
	stopctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := n.BeforeStop(stopctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if n.host.commandsJoined || lease.closes != 0 {
		t.Fatal("unjoined open allowed teardown")
	}
	close(release)
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("stop did not cancel open", err)
	}
	if err := n.Close(gc); err != nil {
		t.Fatal(err)
	}
	if err := n.ReleaseAfterDetach(); err != nil || lease.closes != 1 {
		t.Fatal("joined protocol teardown failed", err)
	}
}

func TestSharedRegistrationRequiresVerifiedProtocolCapability(t *testing.T) {
	n, _ := sharedPreparedHost(t)
	s, lease := sharedRegistrationSession(t, n, 42)
	f := &sharedRegistrationTransport{}
	if err := s.registerSharedScopeUsing(t.Context(), f); err == nil || f.runs != 0 {
		t.Fatal("unvalidated capability registered")
	}
	s.account.registration = sharedReceiptWire{Operation: sharedBindingOpen, Sequence: 1}
	if err := n.BeforeStop(t.Context()); err == nil || n.host.commandsJoined || lease.closes != 0 {
		t.Fatal("unvalidated collection waived registered-scope guard")
	}
}

func TestSharedRegistrationReattestsPinsBeforeOpen(t *testing.T) {
	n, _ := sharedRegistrationHost(t)
	s, _ := sharedRegistrationSession(t, n, 42)
	s.account.pins.checkTest = func(context.Context) error { return errors.New("trusted init changed") }
	f := &sharedRegistrationTransport{}
	if err := s.registerSharedScopeUsing(t.Context(), f); err == nil || f.runs != 0 || s.account.native.attempted || s.account.native.reserved {
		t.Fatal("unverified physical input opened a native scope")
	}
}

func TestSharedRegistrationWaitsForSuccessfulStartupHandshake(t *testing.T) {
	n, _ := sharedRegistrationHost(t)
	s, _ := sharedRegistrationSession(t, n, 42)
	f := &sharedRegistrationTransport{}
	n.host.handshakeComplete = false
	if err := s.registerSharedScopeUsing(t.Context(), f); err == nil || f.runs != 0 {
		t.Fatal("failed handshake allowed binding")
	}
	n.host.handshakeComplete = true
	n.host.startup.done = make(chan struct{})
	if err := s.registerSharedScopeUsing(t.Context(), f); err == nil || f.runs != 0 {
		t.Fatal("unjoined startup allowed binding")
	}
	n.host.startup = sharedStartupOperation{}
}

type sharedRegistrationRetryLease struct {
	sharedTestLease
	fail bool
}

func (l *sharedRegistrationRetryLease) Close() error {
	l.closes++
	if l.fail {
		return errors.New("lease close failed")
	}
	return nil
}

func TestSharedRegistrationDetachedPinCloseRetryRetainsAccount(t *testing.T) {
	n, gc := sharedRegistrationHost(t)
	lease := &sharedRegistrationRetryLease{fail: true}
	s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 42, InitHostPID: 10, Acquire: func(context.Context) (BindingLease, error) { return lease, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.registerSharedScopeUsing(t.Context(), &sharedRegistrationTransport{}); err != nil {
		t.Fatal(err)
	}
	if err := n.Close(gc); err != nil {
		t.Fatal(err)
	}
	if err := n.ReleaseAfterDetach(); err == nil || lease.closes != 1 || n.scopes[42] != s.account || n.host.scopeSlots[0] != s.account {
		t.Fatal("failed pin cleanup discarded account")
	}
	lease.fail = false
	if err := n.ReleaseAfterDetach(); err != nil || lease.closes != 2 || len(n.scopes) != 0 || n.host.scopeSlots[0] != nil {
		t.Fatal("pin cleanup retry failed", err)
	}
	if err := n.ReleaseAfterDetach(); err != nil || lease.closes != 2 {
		t.Fatal("successful pin close repeated", err)
	}
}

func TestSharedRegistrationFailedStartupAllocatesNoSlotTableOrCapability(t *testing.T) {
	n, err := NewNodeEnforcer(SharedNodeConfig{Profile: sharedTestProfile(), ABI3Development: true, Image: "development"})
	if err != nil {
		t.Fatal(err)
	}
	if n.host.scopeSlots != nil || n.host.protocol != nil {
		t.Fatal("native table allocated before admission")
	}
	gc := &sharedHostContext{vars: map[string]any{}, image: "development"}
	n.host.claimed = true
	n.host.context = gc
	if err := n.Start(gc); err == nil || n.host.scopeSlots != nil || n.host.protocol != nil || n.host.startup.done != nil {
		t.Fatal("failed loaded admission minted capability/table or leaked startup", err)
	}
}

func TestSharedProtocolReferencedMapBoundary(t *testing.T) {
	for _, name := range []string{"se_configuration", "se_admin", "se_commands", "se_receipts", "se_objects", "se_bindings", "se_arena", "se_routes"} {
		if !sharedProgramRequiresMap(name, false) || !sharedProgramRequiresMap(name, true) {
			t.Fatalf("used map %s not required", name)
		}
	}
	if sharedProgramRequiresMap("se_route_index", false) || !sharedProgramRequiresMap("se_route_index", true) {
		t.Fatal("unused command locator must remain required for full hook union")
	}
	for _, name := range []string{".bss", ".rodata"} {
		if sharedProgramRequiresMap(name, false) || sharedProgramRequiresMap(name, true) {
			t.Fatal("unused compiler data map required", name)
		}
	}
	// This is only a reference exception, never a loaded-resource exception.
	profile, manifest := sharedResourcesFixture()
	delete(manifest.Maps, "se_route_index")
	if _, err := validateSharedProtocolResources(profile, manifest); err == nil {
		t.Fatal("missing loaded locator accepted")
	}
}
