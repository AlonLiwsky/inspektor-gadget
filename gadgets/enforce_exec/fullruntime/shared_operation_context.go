// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"sync"
	"time"
)

// sharedOperationContext owns cancellation without registering children or
// AfterFuncs in the borrowed caller graph. It is NOT a drop-in WithCancel:
// WithoutCancel deliberately hides a parent's custom Cause; Cause here is Err.
// Providers must not retain this context beyond the synchronous operation.
// Joining retires logical ownership, not allocator/GC or scheduler resources.
// Bootstrap allocation charging awaits the whole-attempt applicability seam.
type sharedOperationContext struct {
	node          *NodeEnforcer
	values        context.Context
	caller        context.Context
	callerDone    <-chan struct{}
	deadline      time.Time
	hasDeadline   bool
	cancelled     chan struct{}
	relayJoined   chan struct{}
	operationDone chan struct{}
	terminal      sync.Once
	err           error
}

func (c *sharedOperationContext) Deadline() (time.Time, bool) { return c.deadline, c.hasDeadline }
func (c *sharedOperationContext) Done() <-chan struct{}       { return c.cancelled }
func (c *sharedOperationContext) Value(key any) any           { return c.values.Value(key) }
func (c *sharedOperationContext) Err() error {
	select {
	case <-c.cancelled:
		return c.err // Published before close; immutable thereafter.
	default:
	}
	// Observe an already-cancelled caller synchronously at command boundaries;
	// the relay may not yet have been scheduled after a provider cancels it.
	select {
	case <-c.callerDone:
		c.cancel(c.caller.Err())
		return c.err
	default:
		return nil
	}
}

func (c *sharedOperationContext) cancel(err error) {
	c.terminal.Do(func() { c.err = err; close(c.cancelled) })
}
func (c *sharedOperationContext) stop() { c.cancel(context.Canceled) }

// Closing relayJoined is the relay's final access to operation-owned state.
// Parent Err follows the Context contract (a stable cancellation sentinel).
func (c *sharedOperationContext) relay() {
	select {
	case <-c.callerDone:
		c.cancel(c.caller.Err())
	case <-c.cancelled:
	}
	close(c.relayJoined)
}

// The sole synchronous owner calls finish after callbacks, commands and their
// cleanup. Stop may cancel concurrently, but cannot unregister this operation.
func (c *sharedOperationContext) finish() {
	c.stop()
	<-c.relayJoined
	c.node.mu.Lock()
	c.node.objects.operation = sharedStartupOperation{}
	close(c.operationDone)
	c.node.mu.Unlock()
}
