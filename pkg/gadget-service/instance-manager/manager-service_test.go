// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package instancemanager

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type attachmentStream struct {
	api.GadgetManager_RunGadgetServer
	ctx       context.Context
	sent      int
	sendError error
	onSend    func()
}

func (s *attachmentStream) Context() context.Context { return s.ctx }
func (s *attachmentStream) Send(*api.GadgetEvent) error {
	s.sent++
	if s.onSend != nil {
		s.onSend()
	}
	return s.sendError
}

func TestAttachReportsInitializationFailure(t *testing.T) {
	m := testManager(t)
	d := desired("failed")
	d.GadgetConfig.Version = 0
	m.RunGadget(d)
	instance := m.LookupInstance("failed")
	require.NotNil(t, instance)
	failure := instance.WaitStopped(context.Background())
	require.Error(t, failure)
	t.Cleanup(func() { require.NoError(t, m.RemoveGadget("failed")) })

	stream := &attachmentStream{ctx: context.Background()}
	result := make(chan error, 1)
	go func() { result <- m.AttachToGadgetInstance("failed", stream) }()
	require.ErrorIs(t, receive(t, result), failure)
	require.Zero(t, stream.sent, "failed initialization must not send metadata or events")
	require.Empty(t, instance.clients)
}

func TestAttachReportsMetadataSendFailure(t *testing.T) {
	m := testManager(t)
	require.NoError(t, m.StartGadget(context.Background(), desired("running")))
	t.Cleanup(func() { require.NoError(t, m.StopGadget(context.Background(), "running")) })
	failure := errors.New("metadata send failed")
	stream := &attachmentStream{ctx: context.Background(), sendError: failure}
	require.ErrorIs(t, m.AttachToGadgetInstance("running", stream), failure)
	require.Equal(t, 1, stream.sent)
	require.Empty(t, m.LookupInstance("running").clients)
}

func TestAttachSuccessfulCompletion(t *testing.T) {
	m := testManager(t)
	require.NoError(t, m.StartGadget(context.Background(), desired("running")))
	t.Cleanup(func() { require.NoError(t, m.StopGadget(context.Background(), "running")) })
	sent := make(chan struct{})
	stream := &attachmentStream{ctx: context.Background(), onSend: func() { close(sent) }}
	result := make(chan error, 1)
	go func() { result <- m.AttachToGadgetInstance("running", stream) }()
	select {
	case <-sent:
	case <-time.After(5 * time.Second):
		t.Fatal("metadata was not sent")
	}
	m.LookupInstance("running").RemoveClients()
	require.NoError(t, receive(t, result))
	require.Equal(t, 1, stream.sent)
	require.Empty(t, m.LookupInstance("running").clients)
}

type blockedMetadataRuntime struct {
	lifecycleRuntime
	entered, release chan struct{}
}

func (r blockedMetadataRuntime) RunGadget(runtime.GadgetContext, *params.Params, api.ParamValues) error {
	close(r.entered)
	<-r.release
	return errors.New("initialization failed after release")
}

func TestAttachCancellationWhileMetadataInitializationBlocked(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		name := "canceled"
		if deadline {
			name = "deadline"
		}
		t.Run(name, func(t *testing.T) {
			r := blockedMetadataRuntime{entered: make(chan struct{}), release: make(chan struct{})}
			m, err := New(r)
			require.NoError(t, err)
			m.RunGadget(desired("blocked"))
			<-r.entered
			instance := m.LookupInstance("blocked")
			require.NotNil(t, instance)
			t.Cleanup(func() {
				close(r.release)
				require.Error(t, instance.WaitStopped(context.Background()))
				require.NoError(t, m.RemoveGadget("blocked"))
			})
			var ctx context.Context
			var cancel context.CancelFunc
			expected := context.Canceled
			if deadline {
				ctx, cancel = context.WithTimeout(context.Background(), 20*time.Millisecond)
				expected = context.DeadlineExceeded
			} else {
				ctx, cancel = context.WithCancel(context.Background())
			}
			defer cancel()
			stream := &attachmentStream{ctx: ctx}
			result := make(chan error, 1)
			go func() { result <- m.AttachToGadgetInstance("blocked", stream) }()
			if !deadline {
				cancel()
			}
			require.ErrorIs(t, receive(t, result), expected)
			require.Zero(t, stream.sent)
			instance.mu.Lock()
			clients := len(instance.clients)
			instance.mu.Unlock()
			require.Zero(t, clients)
			select {
			case <-instance.ready:
				t.Fatal("initialization was not blocked")
			default:
			}
		})
	}
}

func TestAttachCanceledClientDoesNotSendReadyMetadata(t *testing.T) {
	m := testManager(t)
	require.NoError(t, m.StartGadget(context.Background(), desired("ready")))
	t.Cleanup(func() { require.NoError(t, m.StopGadget(context.Background(), "ready")) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	stream := &attachmentStream{ctx: ctx}
	require.ErrorIs(t, m.AttachToGadgetInstance("ready", stream), context.Canceled)
	require.Zero(t, stream.sent)
	require.Empty(t, m.LookupInstance("ready").clients)
}

func TestParamValuesReturnsIndependentSnapshot(t *testing.T) {
	m := testManager(t)
	d := desired("params")
	d.GadgetConfig.ParamValues = api.ParamValues{"key": "original"}
	require.NoError(t, m.StartGadget(context.Background(), d))
	t.Cleanup(func() { require.NoError(t, m.StopGadget(context.Background(), "params")) })

	instance := m.LookupInstance("params")
	values := instance.ParamValues()
	values["key"] = "changed"
	values["extra"] = "added"
	require.Equal(t, api.ParamValues{"key": "original"}, instance.ParamValues())
}

func TestAddClientFailureResultBufferedAndClosedOnce(t *testing.T) {
	m := testManager(t)
	require.NoError(t, m.StartGadget(context.Background(), desired("running")))
	t.Cleanup(func() { require.NoError(t, m.StopGadget(context.Background(), "running")) })
	failure := errors.New("metadata send failed")
	instance := m.LookupInstance("running")
	stream := &attachmentStream{ctx: context.Background(), sendError: failure}
	result := instance.AddClient(stream) // Deliberately receive after AddClient returns.
	require.ErrorIs(t, <-result, failure)
	_, open := <-result
	require.False(t, open, "attachment result must close after one result")
	require.Empty(t, instance.clients)
}
