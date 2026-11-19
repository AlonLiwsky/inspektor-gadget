// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

const (
	OwnerIdle uint32 = iota
	OwnerStaging
	OwnerValidated
	OwnerPublishing
	OwnerCommitted
	OwnerStopped
)

type publicationControl interface {
	Call(context.Context, ControlCommand) (ControlHealth, error)
	Phase() (ControlPhase, error)
	Health() (ControlHealth, error)
	GenerationFault(uint64) (uint64, error)
}

// PublicationResult separates the irreversible map commit from admission. A
// postcommit failure is NOT rollback; Resume must finish the retained transaction
// or the native owner must retire it before detaching. Ready is intentionally
// absent: runtime leases, resource budgets and hook health remain native duties.
type PublicationResult struct {
	Committed  bool
	Generation uint64
	Admitting  bool
}

// Publisher coordinates ONE already attached, identity-authorized owner. It is
// not a runtime manager. The caller retains all binding pins, serializes root
// authorization/start/stop with these operations, and exclusively owns slot and
// control. verify must re-attest trusted runtime/proc/cgroup leases, not policy
// metadata; it is called on both sides of bootstrap and before admission.
type Publisher struct {
	mu      sync.Mutex
	slot    *ProgramSlot
	control publicationControl
	verify  func(context.Context) error
	pending *publicationAttempt
	retired bool
}
type publicationAttempt struct {
	update     *ProgramUpdate
	generation uint64
	mask       uint32
	committed  bool
}

// NewPublisher requires prepared on first startup: Begin must close admission and stage
// the first program BEFORE NewOwnerControl freezes/activates the configuration.
// This prevents a gap with active membership but no immutable program. Pass nil
// only for an already published owner with no pending transaction.
func NewPublisher(slot *ProgramSlot, control *OwnerControl, verify func(context.Context) error, prepared *ProgramUpdate) (*Publisher, error) {
	if slot == nil || control == nil || verify == nil {
		return nil, fmt.Errorf("program slot, qualified control and trusted lease verifier required")
	}
	if control.config.ABI == OwnerDevelopmentABI {
		// This constructor still owns ABI2 map replacement and drained gates.
		// Never turn that receipt into an ABI3 activation while the fixed-bank
		// candidate/ARM publisher is being integrated.
		return nil, fmt.Errorf("development publication requires authenticated fixed-bank ARM, not legacy activation")
	}
	slot.mu.Lock()
	defer slot.mu.Unlock()
	if slot.closed || slot.retiring || slot.broken != nil {
		return nil, fmt.Errorf("unavailable program owner")
	}
	p := &Publisher{slot: slot, control: control, verify: verify}
	if prepared != nil {
		a := prepared.state
		if a == nil || a.owner != slot || slot.update != a || a.done || a.committed {
			return nil, fmt.Errorf("exclusive uncommitted startup preparation required")
		}
		p.pending = &publicationAttempt{update: prepared, generation: a.generation, mask: a.newMask}
	} else if slot.update != nil || slot.generation == 0 {
		return nil, fmt.Errorf("first publication must be prepared before scope activation")
	}
	return p, nil
}

// Publish automatically attempts bounded precommit rollback on refusal. Failed
// rollback retains a closed transaction; callers must Resume/Abort/Retire, never
// replace this owner or independently reopen its gate. Postcommit errors never
// invoke Abort, including partial successful-epoch publication.
func (p *Publisher) Publish(ctx context.Context, program *fullpolicy.KernelProgram) (PublicationResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.retired {
		return PublicationResult{}, ErrGateRetired
	}
	if p.pending != nil {
		return p.result(), ErrGateBusy
	}
	if err := p.verify(ctx); err != nil {
		return p.result(), err
	}
	update, err := p.slot.Begin(ctx, program)
	if err != nil {
		return p.result(), err
	}
	p.pending = &publicationAttempt{update: update, generation: update.state.generation, mask: update.NewUIDMask()}
	result, err := p.resume(ctx)
	if err != nil && p.pending != nil && !p.pending.committed {
		rollback, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancel()
		err = errors.Join(err, p.abort(rollback))
		result = p.result()
	}
	return result, err
}

func (p *Publisher) result() PublicationResult {
	generation := p.slot.Generation()
	r := PublicationResult{Generation: generation, Committed: p.pending != nil && p.pending.committed}
	closed, count, err := p.slot.gate.State()
	r.Admitting = err == nil && !closed && count <= MaxAdmittedExecs && !p.retired
	return r
}

func (p *Publisher) call(ctx context.Context, operation uint32, mask uint32) error {
	_, err := p.control.Call(ctx, ControlCommand{Operation: operation, Generation: p.pending.generation, NewUIDMask: mask})
	return err
}

func (p *Publisher) identity(ctx context.Context) error {
	if err := p.verify(ctx); err != nil {
		return err
	}
	h, err := p.control.Call(ctx, ControlCommand{Operation: OwnerRootCheck})
	if err != nil {
		return err
	}
	if h.RootMatch != 1 {
		return fmt.Errorf("trusted root-group continuity lost")
	}
	return nil
}

func (p *Publisher) healthy(generation uint64) error {
	h, err := p.control.Health()
	if err != nil {
		return err
	}
	if h.Faults != 0 || h.MovementFault != 0 || h.Retired != 0 || h.MovementArmed != 1 || h.MovementSequence&1 != 0 {
		return fmt.Errorf("owner health refuses publication")
	}
	faults, err := p.control.GenerationFault(generation)
	if err != nil {
		return err
	}
	if faults != 0 {
		return fmt.Errorf("generation %d has observation/semantic faults: %#x", generation, faults)
	}
	return nil
}

// Resume does not compile or consume another generation. Kernel phase receipts
// resolve a command whose acknowledgement was lost after execution/cancellation.
func (p *Publisher) Resume(ctx context.Context) (PublicationResult, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.retired {
		return p.result(), ErrGateRetired
	}
	if p.pending == nil {
		return p.result(), fmt.Errorf("no pending publication")
	}
	return p.resume(ctx)
}

func (p *Publisher) resume(ctx context.Context) (PublicationResult, error) {
	a := p.pending
	if err := ctx.Err(); err != nil {
		return p.result(), err
	}
	if err := p.identity(ctx); err != nil {
		return p.result(), err
	}
	phase, err := p.control.Phase()
	if err != nil {
		return p.result(), err
	}
	if phase.Busy != 0 {
		return p.result(), ErrGateBusy
	}
	if phase.State != OwnerIdle && phase.CandidateGeneration != a.generation {
		return p.result(), fmt.Errorf("foreign owner publication phase")
	}
	if phase.State == OwnerIdle && !a.committed {
		phase.State = OwnerStaging
	}
	if phase.State == OwnerStaging {
		// Re-run A on a resumed partial attempt: A's barrier is invalidated before
		// each pass, and retained accepted roles are never rerooted.
		if err = p.call(ctx, OwnerBootstrapA, a.mask); err != nil {
			return p.result(), err
		}
		if err = p.call(ctx, OwnerBootstrapB, a.mask); err != nil {
			return p.result(), err
		}
		phase.State = OwnerValidated
	}
	if phase.State == OwnerValidated {
		if err = p.call(ctx, OwnerValidate, a.mask); err != nil {
			return p.result(), err
		}
		if err = p.identity(ctx); err != nil {
			return p.result(), err
		}
		if err = p.healthy(a.generation); err != nil {
			return p.result(), err
		}
		if err = p.call(ctx, OwnerPublicationBegin, a.mask); err != nil {
			return p.result(), err
		}
		phase.State = OwnerPublishing
	}
	if phase.State == OwnerPublishing {
		if err = p.identity(ctx); err != nil {
			return p.result(), err
		}
		if err = p.healthy(a.generation); err != nil {
			return p.result(), err
		}
		commit, commitErr := a.update.Commit()
		a.committed = commit.Committed
		if commitErr != nil {
			return p.result(), commitErr
		}
		if err = p.call(ctx, OwnerPublicationCommitted, a.mask); err != nil {
			return p.result(), err
		}
		phase.State = OwnerCommitted
	}
	if phase.State == OwnerCommitted {
		// A movement after the swap invalidates the old receipt, not the commit.
		// Read-only validation of active accepted state can renew that receipt.
		if err = p.call(ctx, OwnerValidate, 0); err != nil {
			return p.result(), err
		}
		if err = p.identity(ctx); err != nil {
			return p.result(), err
		}
		if err = p.healthy(a.generation); err != nil {
			return p.result(), err
		}
		if err = p.call(ctx, OwnerPhaseClear, a.mask); err != nil {
			return p.result(), err
		}
		phase.State = OwnerIdle
	}
	if phase.State != OwnerIdle || !a.committed {
		return p.result(), fmt.Errorf("incomplete owner publication")
	}
	h, err := p.control.Health()
	if err != nil {
		return p.result(), err
	}
	if h.ActiveGeneration != a.generation || h.ReadyGeneration != a.generation || h.PendingBirths != 0 {
		return p.result(), fmt.Errorf("owner publication receipt incomplete")
	}
	if err = p.identity(ctx); err != nil {
		return p.result(), err
	}
	if err = p.healthy(a.generation); err != nil {
		return p.result(), err
	}
	err = a.update.Finish()
	// Finish consumes its lease even on reopen/auxiliary cleanup failure.
	p.pending = nil
	result := p.result()
	result.Committed = true
	return result, err
}

func (p *Publisher) Abort(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.abort(ctx)
}

func (p *Publisher) abort(ctx context.Context) error {
	a := p.pending
	if a == nil {
		return nil
	}
	if a.committed {
		return fmt.Errorf("committed publication cannot abort")
	}
	phase, err := p.control.Phase()
	if err != nil {
		return err
	}
	if phase.Busy != 0 {
		return ErrGateBusy
	}
	if phase.State != OwnerIdle {
		if phase.CandidateGeneration != a.generation {
			return fmt.Errorf("foreign publication cannot abort")
		}
		if err = p.call(ctx, OwnerBootstrapAbort, a.mask); err != nil {
			return err
		}
	}
	// Even an acknowledged command must leave the bootstrap phase clear before
	// reopening the old immutable program. Do not infer this from an error code.
	phase, err = p.control.Phase()
	if err != nil {
		return err
	}
	if phase.Busy != 0 || phase.State != OwnerIdle {
		return fmt.Errorf("owner abort did not clear phase")
	}
	err = a.update.Abort()
	p.pending = nil
	return err
}

// Retire is the only supported pre-detach path. On drain failure the caller MUST
// keep hooks, maps, worker and identity pins. On command failure gate remains
// retired/closed and Retire may be retried; no publication can resume thereafter.
func (p *Publisher) Retire(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.slot.Retire(ctx); err != nil {
		return err
	}
	p.retired = true
	h, err := p.control.Health()
	if err != nil {
		return err
	}
	if h.Retired != 0 {
		return nil
	}
	_, err = p.control.Call(ctx, ControlCommand{Operation: OwnerRetire})
	return err
}
