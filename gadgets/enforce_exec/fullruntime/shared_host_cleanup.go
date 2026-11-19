// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import "context"

// Cancellation never grants teardown permission. A callback that ignores it
// keeps its preparation registered until its LAST lease/FD cleanup access.
func (n *NodeEnforcer) cancelAndJoinPreparations(ctx context.Context) error {
	n.mu.Lock()
	n.closing = true
	pending := make([]*BindingSession, 0, len(n.preparations))
	for s := range n.preparations {
		pending = append(pending, s)
	}
	native := make([]sharedStartupOperation, 0, len(n.scopes)+2)
	if n.host != nil && n.host.startup.done != nil {
		native = append(native, n.host.startup)
	}
	for _, a := range n.scopes {
		if a.native.done != nil {
			native = append(native, sharedStartupOperation{cancel: a.native.cancel, done: a.native.done})
		}
	}
	if n.objects != nil && n.objects.operation.done != nil {
		native = append(native, n.objects.operation)
	}
	n.mu.Unlock()
	for _, op := range native {
		op.cancel()
	}
	for _, s := range pending {
		s.prepareCancel()
	}
	for _, op := range native {
		select {
		case <-op.done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	for _, s := range pending {
		select {
		case <-s.prepareDone:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return ctx.Err()
}

// Keep every borrowed handle, including those obtained before a partial-start
// error. This ledger owns no FD and never closes a host-owned resource.
func (r sharedControlResources) borrowedHandles() []sharedBorrowedFD {
	handles := make([]sharedBorrowedFD, 0, len(r.maps)+len(r.programs)+1)
	for _, m := range r.maps {
		if m != nil {
			handles = append(handles, m)
		}
	}
	for _, p := range r.programs {
		if p != nil {
			handles = append(handles, p)
		}
	}
	if r.program != nil {
		handles = append(handles, r.program)
	}
	return handles
}
