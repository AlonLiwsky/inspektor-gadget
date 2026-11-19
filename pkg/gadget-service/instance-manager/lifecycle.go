// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package instancemanager

import (
	"context"
	"fmt"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

// lockLifecycle permits canceled waiters to leave without changing any instance.
// Once acquired, the caller retains ownership through its required cleanup.
func (m *Manager) lockLifecycle(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.lifecycleOnce.Do(func() { m.lifecycleMu = make(chan struct{}, 1) })
	select {
	case <-ctx.Done():
		return ctx.Err()
	case m.lifecycleMu <- struct{}{}:
		// Cancellation and lock availability can become ready together.
		if err := ctx.Err(); err != nil {
			m.unlockLifecycle()
			return err
		}
		return nil
	}
}

func (m *Manager) unlockLifecycle() {
	<-m.lifecycleMu
}

// StartGadget waits until every operator has started successfully. Options may
// supply additional operators; the manager owns the WithOnStarted callback.
// The context bounds startup, not the lifetime of the resulting instance.
// Failed or canceled startup cancels the candidate and waits for its cleanup.
func (m *Manager) StartGadget(ctx context.Context, desired *api.GadgetInstance, options ...gadgetcontext.Option) error {
	if err := m.lockLifecycle(ctx); err != nil {
		return err
	}
	defer m.unlockLifecycle()
	return m.startGadget(ctx, desired, options...)
}

func (m *Manager) startGadget(ctx context.Context, desired *api.GadgetInstance, options ...gadgetcontext.Option) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	gi, err := m.runGadget(desired, options...)
	if err != nil {
		return err
	}
	err = gi.WaitStarted(ctx)
	if err == nil {
		return nil
	}
	gi.cancel()
	// Do not return a failed start while its resources are still active.
	_ = gi.WaitStopped(context.Background())
	_ = m.removeGadget(gi.id)
	return err
}

// ReplaceGadget starts a distinct candidate before stopping the old instance.
// A startup failure leaves the old instance running. IDs must differ so both
// instances can own independent runtime resources throughout the overlap.
// Once startup succeeds replacement is committed: cancellation while waiting
// for old cleanup does not roll back the new instance. StopGadget can finish
// waiting for the old ID.
func (m *Manager) ReplaceGadget(ctx context.Context, oldID string, desired *api.GadgetInstance, options ...gadgetcontext.Option) error {
	if err := m.lockLifecycle(ctx); err != nil {
		return err
	}
	defer m.unlockLifecycle()
	if desired == nil || desired.Id == oldID {
		return fmt.Errorf("replacement requires a distinct gadget ID")
	}
	m.mu.Lock()
	old := m.gadgetInstances[oldID]
	m.mu.Unlock()
	if old == nil {
		return ErrNotFound
	}
	if err := m.startGadget(ctx, desired, options...); err != nil {
		return err
	}
	if err := m.stopGadget(ctx, oldID); err != nil {
		return fmt.Errorf("replacement %q started; waiting for old instance %q cleanup: %w", desired.Id, oldID, err)
	}
	return nil
}

// StopGadget cancels an instance and waits for runtime and operator cleanup.
// A canceled wait leaves the instance registered so callers can wait again.
func (m *Manager) StopGadget(ctx context.Context, id string) error {
	if err := m.lockLifecycle(ctx); err != nil {
		return err
	}
	defer m.unlockLifecycle()
	return m.stopGadget(ctx, id)
}

func (m *Manager) stopGadget(ctx context.Context, id string) error {
	m.mu.Lock()
	gi := m.gadgetInstances[id]
	m.mu.Unlock()
	if gi == nil {
		return ErrNotFound
	}
	gi.cancel()
	err := gi.WaitStopped(ctx)
	select {
	case <-gi.stopped:
		_ = m.removeGadget(id)
	default:
	}
	return err
}

// WaitStarted waits for successful startup, startup failure, or cancellation.
func (p *GadgetInstance) WaitStarted(ctx context.Context) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-p.stopped:
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.error != nil {
			return p.error
		}
		return fmt.Errorf("gadget already stopped")
	case <-p.started:
		if err := ctx.Err(); err != nil {
			return err
		}
		select {
		case <-p.stopped:
			return fmt.Errorf("gadget already stopped")
		default:
			return nil
		}
	}
}

// WaitStopped waits until Run and all cleanup have returned.
func (p *GadgetInstance) WaitStopped(ctx context.Context) error {
	select {
	case <-p.stopped:
		p.mu.Lock()
		defer p.mu.Unlock()
		return p.error
	case <-ctx.Done():
		return ctx.Err()
	}
}
