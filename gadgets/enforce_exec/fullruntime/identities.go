// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"sync"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// MaxHistoricalIdentities bounds all policy/role names seen during one persistent
// binding owner's lifetime. Deletion and failed publication never free entries:
// a task may still carry an older hashed identity. Exhaustion requires a new,
// explicitly bootstrapped owner, never silent recycling of role state.
const MaxHistoricalIdentities = 65536

// IdentityRegistry belongs to exactly one persistent role-state owner. It must
// outlive every candidate, retired policy map, and task carrying that owner's
// roles. Its zero value is ready for use. Do not copy after first use.
type IdentityRegistry struct {
	mu    sync.Mutex
	names map[uint64]string
}

// Reserve validates a complete compiler-produced candidate, then permanently
// remembers its identities BEFORE any task seeding or map publication. A failed
// validation/collision/capacity check is atomic. Once reservation succeeds, later
// publication or bootstrap failure must not roll it back.
func (r *IdentityRegistry) Reserve(program *fullpolicy.KernelProgram) error {
	if err := fullpolicy.ValidateKernelProgram(program); err != nil {
		return fmt.Errorf("identity candidate: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	added := 0
	for id, name := range program.Identities {
		if previous, ok := r.names[id]; ok {
			if previous != name {
				return fmt.Errorf("historical identity collision for %#x", id)
			}
		} else {
			added++
		}
	}
	if added > MaxHistoricalIdentities-len(r.names) {
		return fmt.Errorf("historical identity capacity exceeds %d", MaxHistoricalIdentities)
	}
	if r.names == nil {
		r.names = make(map[uint64]string, len(program.Identities))
	}
	for id, name := range program.Identities {
		r.names[id] = name
	}
	return nil
}

// Len includes identities from candidates whose publication subsequently failed.
func (r *IdentityRegistry) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.names)
}
