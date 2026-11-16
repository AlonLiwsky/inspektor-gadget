// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build linux

package containerhook

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// hookEventCollector owns callback data independently of the notifier lifetime.
// wake is deliberately never closed: notifier.Close does not join callbacks.
type hookEventCollector struct {
	mu       sync.Mutex
	events   []ContainerEvent
	arrivals []time.Duration
	started  time.Time
	wake     chan struct{}
}

func newHookEventCollector() *hookEventCollector {
	return &hookEventCollector{started: time.Now(), wake: make(chan struct{}, 1)}
}

func (c *hookEventCollector) add(event ContainerEvent) {
	event.ContainerName = ""
	event.ContainerPID = 0
	event.ContainerConfig = ""
	event.Bundle = ""
	c.mu.Lock()
	c.events = append(c.events, event)
	c.arrivals = append(c.arrivals, time.Since(c.started))
	c.mu.Unlock()
	select {
	case c.wake <- struct{}{}:
	default:
	}
}

func (c *hookEventCollector) snapshot() []ContainerEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]ContainerEvent(nil), c.events...)
}

func (c *hookEventCollector) wait(expected ContainerEvent, budget time.Duration) ([]ContainerEvent, bool) {
	timer := time.NewTimer(budget)
	defer timer.Stop()
	matches := func(events []ContainerEvent) bool {
		for _, event := range events {
			if event == expected {
				return true
			}
		}
		return false
	}
	for {
		events := c.snapshot()
		if matches(events) {
			return events, true
		}
		select {
		case <-c.wake:
		case <-timer.C:
			// Include callbacks racing with the timer in the final snapshot.
			events = c.snapshot()
			return events, matches(events)
		}
	}
}

func (c *hookEventCollector) logMissing(t *testing.T, expected ContainerEvent, events []ContainerEvent) {
	t.Helper()
	c.mu.Lock()
	arrivals := append([]time.Duration(nil), c.arrivals[:len(events)]...)
	c.mu.Unlock()
	t.Logf("missing exact normalized event type=%d containerID=%q mntnsID=%d after 100ms observation budget; arrivals relative to collector creation:", expected.Type, expected.ContainerID, expected.MntnsID)
	for i, event := range events {
		t.Logf("arrival=%s type=%d containerID=%q mntnsID=%d", arrivals[i], event.Type, event.ContainerID, event.MntnsID)
	}
}

func TestHookEventCollectorConcurrentSnapshots(t *testing.T) {
	c := newHookEventCollector()
	var producers sync.WaitGroup
	for p := 0; p < 8; p++ {
		producers.Add(1)
		go func(p int) {
			defer producers.Done()
			for i := 0; i < 100; i++ {
				c.add(ContainerEvent{Type: EventTypeAddContainer, ContainerID: fmt.Sprintf("%d-%d", p, i), ContainerConfig: "private"})
				snapshot := c.snapshot()
				snapshot[0].ContainerID = "changed"
			}
		}(p)
	}
	producers.Wait()
	events := c.snapshot()
	require.Len(t, events, 800)
	ids := make(map[string]bool)
	for _, event := range events {
		require.NotEqual(t, "changed", event.ContainerID)
		require.Empty(t, event.ContainerConfig)
		ids[event.ContainerID] = true
	}
	require.Len(t, ids, 800)
}

func TestHookEventCollectorWait(t *testing.T) {
	expected := ContainerEvent{Type: EventTypeAddContainer, ContainerID: "target"}
	t.Run("already arrived and normalized", func(t *testing.T) {
		c := newHookEventCollector()
		c.add(ContainerEvent{Type: EventTypeAddContainer, ContainerID: "target", ContainerName: "name", ContainerPID: 1, ContainerConfig: "private", Bundle: "private"})
		events, matched := c.wait(expected, 0)
		require.True(t, matched)
		require.Equal(t, []ContainerEvent{expected}, events)
	})
	t.Run("later exact match", func(t *testing.T) {
		c := newHookEventCollector()
		// Same ID or same type alone must not satisfy the predicate.
		c.add(ContainerEvent{Type: EventTypeRemoveContainer, ContainerID: "target"})
		c.add(ContainerEvent{Type: EventTypeAddContainer, ContainerID: "other"})
		c.add(ContainerEvent{Type: EventTypeAddContainer, ContainerID: "target", MntnsID: 1})
		done := make(chan struct{})
		// Delay this synthetic producer to exercise wake-up after waiting begins.
		timer := time.AfterFunc(5*time.Millisecond, func() {
			defer close(done)
			c.add(expected)
		})
		defer timer.Stop()
		events, matched := c.wait(expected, time.Second)
		<-done
		require.True(t, matched)
		require.Contains(t, events, expected)
	})
	t.Run("unrelated events time out", func(t *testing.T) {
		c := newHookEventCollector()
		c.add(ContainerEvent{Type: EventTypeRemoveContainer, ContainerID: "target"})
		c.add(ContainerEvent{Type: EventTypeAddContainer, ContainerID: "other"})
		c.add(ContainerEvent{Type: EventTypeAddContainer, ContainerID: "target", MntnsID: 1})
		events, matched := c.wait(expected, time.Millisecond)
		require.False(t, matched)
		require.Len(t, events, 3)
		// Callbacks may outlive the wait and notifier Close: notification stays open.
		c.add(expected)
		events, matched = c.wait(expected, 0)
		require.True(t, matched)
		require.Len(t, events, 4)
	})
	t.Run("empty timeout", func(t *testing.T) {
		c := newHookEventCollector()
		events, matched := c.wait(expected, time.Millisecond)
		require.False(t, matched)
		require.Empty(t, events)
	})
}
