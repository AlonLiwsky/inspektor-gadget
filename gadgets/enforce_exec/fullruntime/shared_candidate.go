// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
)

// Minted only after exact protocol manifest and actual loaded-resource identity
// validation. The sole Syscall program is never attached. This is NOT a full
// enforcement-image capability or a caller-controlled teardown override.
type (
	sharedProtocolCapability struct{}
	sharedStartupOperation   struct {
		cancel context.CancelFunc
		done   chan struct{}
	}
	sharedProtocolHostOwnership struct {
		protocol          *sharedProtocolCapability
		scopeSlots        []*sharedPhysicalScope
		startup           sharedStartupOperation
		cleanupErr        error
		handshakeComplete bool
	}
)

type sharedScopeCommandState struct {
	slot                           uint32
	reserved, attempted, destroyed bool
	cancel                         context.CancelFunc
	done                           chan struct{}
}

// registerSharedScope supplies only physical scope identity. Acknowledged
// BINDING_OPEN creates the scope cookie; it grants no root/history/Ready proof.
// No public candidate API is exposed until the remaining qualification exists.
func (s *BindingSession) registerSharedScope(ctx context.Context) error {
	return s.registerSharedScopeUsing(ctx, nil)
}

func (s *BindingSession) registerSharedScopeUsing(ctx context.Context, transport sharedCommandTransport) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n, a := s.node, s.account
	n.mu.Lock()
	if a == nil || n.host == nil || n.host.protocol == nil || !n.host.handshakeComplete || n.host.startup.done != nil || n.host.control == nil || n.closing || n.closed || n.bindings[s.cgroup] != s || a.native.done != nil {
		n.mu.Unlock()
		return ErrSharedNativeUnavailable
	}
	// One accepted operation per retained physical account; admission happens
	// BEFORE waiting on session/account locks or touching trusted lease inputs.
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	a.native.cancel, a.native.done = cancel, done
	control := n.host.control
	n.mu.Unlock()
	defer func() {
		cancel()
		n.mu.Lock()
		a.native.cancel, a.native.done = nil, nil
		close(done)
		n.mu.Unlock()
	}()
	s.mu.Lock()
	defer s.mu.Unlock()
	a.mu.Lock()
	defer a.mu.Unlock()
	if s.removed || a.pins == nil {
		return fmt.Errorf("physical scope preparation unavailable")
	}
	if err := a.pins.Check(ctx); err != nil {
		return err
	}
	if a.registration.Sequence != 0 {
		if a.registration.Operation != sharedBindingOpen || a.registration.NodeCookie != control.config.NodeCookie || a.registration.Status != 0 || !a.native.reserved {
			return fmt.Errorf("retained scope registration identity mismatch")
		}
		return ctx.Err()
	}
	n.mu.Lock()
	if n.closing || n.closed {
		n.mu.Unlock()
		return fmt.Errorf("node stopping")
	}
	if !a.native.reserved {
		found := false
		for slot, owner := range n.host.scopeSlots {
			if owner == nil {
				a.native.slot = uint32(slot)
				a.native.reserved = true
				n.host.scopeSlots[slot] = a
				found = true
				break
			}
		}
		if !found {
			n.mu.Unlock()
			return fmt.Errorf("native binding slots exhausted")
		}
	}
	n.mu.Unlock()
	a.native.attempted = true // Ambiguous/canceled execution retains slot and pins.
	return a.openSharedScope(ctx, control, transport)
}

// Account lock held, outside node lock. Retry the exact request: sharedControl
// reconciles an unresolved receipt without replaying the syscall operation.
func (a *sharedPhysicalScope) openSharedScope(ctx context.Context, control *sharedControl, transport sharedCommandTransport) error {
	command := sharedCommandWire{Operation: sharedBindingOpen, Binding: a.native.slot, CgroupIdentity: a.cgroup}
	var receipt sharedReceiptWire
	var err error
	if transport == nil {
		receipt, err = control.call(ctx, command)
	} else {
		receipt, err = control.callWithTransport(ctx, command, transport)
	}
	if receipt.Sequence == 0 {
		if err == nil {
			err = fmt.Errorf("binding open has no validated outcome")
		}
		return err
	}
	if receipt.Operation != sharedBindingOpen || receipt.Status != 0 || receipt.NodeCookie != control.config.NodeCookie || receipt.Generation != 0 || receipt.Serial != 0 || receipt.Value != 0 {
		return errors.Join(err, fmt.Errorf("binding open refused or incompatible receipt"))
	}
	// Classify completed receipt BEFORE error/cancellation: do not forget an
	// installed binding or blindly reissue BINDING_OPEN after a canceled call.
	a.registration = receipt
	return err
}

func (n *NodeEnforcer) settleProtocolScopes(ctx context.Context, control *sharedControl, transport sharedCommandTransport) error {
	n.mu.Lock()
	// Closing plus joined operations excludes slot changes until host detach.
	accounts := n.host.scopeSlots
	n.mu.Unlock()
	var result error
	for _, a := range accounts {
		if a != nil {
			a.mu.Lock()
			if a.native.attempted && a.registration.Sequence == 0 {
				result = errors.Join(result, a.openSharedScope(ctx, control, transport))
			}
			a.mu.Unlock()
		}
	}
	return result
}

// This is collection destruction, NEVER an acknowledged scope withdrawal.
// Caller has verified exact protocol capability, joined admin and host operator
// teardown, closed borrowed FDs and absence of accepted native operations.
func (n *NodeEnforcer) retireProtocolSessionsAfterDetach() {
	for {
		n.mu.Lock()
		var session *BindingSession
		for _, s := range n.bindings {
			session = s
			break
		}
		n.mu.Unlock()
		if session == nil {
			return
		}
		session.mu.Lock()
		n.mu.Lock()
		if n.bindings[session.cgroup] == session {
			delete(n.bindings, session.cgroup)
			session.removed = true
		}
		n.mu.Unlock()
		session.mu.Unlock()
	}
}
