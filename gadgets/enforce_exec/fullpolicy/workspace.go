// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"errors"
	"unsafe"
)

var (
	errWorkspaceLimit = errors.New("compiler workspace capacity exceeded")
	errWorkspaceOwner = errors.New("invalid compiler workspace ownership")
)

// compilerWorkspace accounts logical project-owned allocations only. It is
// single-owner, not concurrent, and must not be copied. The private model core
// combines a bulk envelope with Blob/validator reservations; unrestricted
// nil-workspace paths remain unmetered. This counter does not establish a
// qualified production runtime budget. Token metadata is cumulative for this one
// attempt: no reset/reuse/end API or escaping-token closure is implied. No RSS/GC claim.
type compilerWorkspace struct{ limit, used, peak, metadata uint64 }

// workspaceReservation moves by pointer with its allocation. self binds release
// authority to the original allocation: value copies cannot refund even while
// another reservation keeps the owner balance sufficient. Clearing owner also
// consumes pointer aliases. Token metadata remains charged for the entire attempt
// because outstanding aliases may retain even consumed reservation records.
// Only records allocated by reserve are counted, not caller-created value copies
// or workspace/holder storage. Copy rejection protects ownership, not allocation.
type workspaceReservation struct {
	self  *workspaceReservation
	owner *compilerWorkspace
	bytes uint64
}

func (w *compilerWorkspace) reserve(bytes uint64) (*workspaceReservation, error) {
	if w == nil {
		return nil, nil
	}
	if w.metadata > w.used {
		return nil, errWorkspaceOwner
	}
	if w.used > w.limit {
		return nil, errWorkspaceLimit
	}
	metadata := uint64(unsafe.Sizeof(workspaceReservation{}))
	available := w.limit - w.used
	if metadata > available || bytes > available-metadata {
		return nil, errWorkspaceLimit
	}
	// Both sums are bounded by limit before allocating the token. Metadata is
	// never refunded: pointer aliases can outlive logical payload ownership.
	w.used += bytes + metadata
	w.metadata += metadata
	w.peak = max(w.peak, w.used)
	reservation := &workspaceReservation{owner: w, bytes: bytes}
	reservation.self = reservation
	return reservation, nil
}

func (r *workspaceReservation) release() error {
	if r == nil || r.self != r || r.owner == nil || r.owner.metadata > r.owner.used || r.bytes > r.owner.used-r.owner.metadata {
		return errWorkspaceOwner
	}
	r.owner.used -= r.bytes
	r.owner = nil
	return nil
}
