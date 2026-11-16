// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package instancemanager

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type lifecycleRuntime struct{ runtime.Runtime }

func (lifecycleRuntime) ParamDescs() params.ParamDescs { return nil }
func (lifecycleRuntime) RunGadget(ctx runtime.GadgetContext, _ *params.Params, values api.ParamValues) error {
	return ctx.Run(values)
}

func desired(id string) *api.GadgetInstance {
	return &api.GadgetInstance{Id: id, GadgetConfig: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: "test"}}
}

func testManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(lifecycleRuntime{})
	require.NoError(t, err)
	return m
}

func receive(t *testing.T, ch <-chan error) error {
	t.Helper()
	select {
	case err := <-ch:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("lifecycle operation did not finish")
		return nil
	}
}

func TestReplaceWaitsForStartupAndCleanup(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	oldStopping, releaseOld := make(chan struct{}), make(chan struct{})
	oldOp := simple.New("old", simple.OnStop(func(operators.GadgetContext) error {
		close(oldStopping)
		<-releaseOld
		return nil
	}))
	require.NoError(t, m.StartGadget(ctx, desired("old"), gadgetcontext.WithAdditionalDataOperators(oldOp)))
	candidateStarting, releaseCandidate := make(chan struct{}), make(chan struct{})
	newOp := simple.New("candidate", simple.OnStart(func(operators.GadgetContext) error {
		close(candidateStarting)
		<-releaseCandidate
		return nil
	}))
	result := make(chan error, 1)
	go func() {
		result <- m.ReplaceGadget(ctx, "old", desired("new"), gadgetcontext.WithAdditionalDataOperators(newOp))
	}()
	<-candidateStarting
	state, err := m.InstanceState("new")
	require.NoError(t, err)
	require.NotEqual(t, api.GadgetInstanceStatus_StatusRunning, state.Status)
	select {
	case <-oldStopping:
		t.Fatal("old stopped before candidate ready")
	default:
	}
	close(releaseCandidate)
	<-oldStopping
	state, err = m.InstanceState("new")
	require.NoError(t, err)
	require.Equal(t, api.GadgetInstanceStatus_StatusRunning, state.Status)
	select {
	case <-result:
		t.Fatal("replacement returned before old cleanup")
	default:
	}
	close(releaseOld)
	require.NoError(t, receive(t, result))
	require.Nil(t, m.LookupInstance("old"))
	require.NoError(t, m.StopGadget(ctx, "new"))
}

func TestFailedCandidatePreservesOld(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	require.NoError(t, m.StartGadget(ctx, desired("old")))
	defer func() { require.NoError(t, m.StopGadget(ctx, "old")) }()
	failure := errors.New("binding failed")
	op := simple.New("candidate", simple.OnStart(func(operators.GadgetContext) error { return failure }))
	require.ErrorIs(t, m.ReplaceGadget(ctx, "old", desired("new"), gadgetcontext.WithAdditionalDataOperators(op)), failure)
	require.Nil(t, m.LookupInstance("new"))
	state, err := m.InstanceState("old")
	require.NoError(t, err)
	require.Equal(t, api.GadgetInstanceStatus_StatusRunning, state.Status)
}

func TestCanceledStartupCleansCandidateAndKeepsOld(t *testing.T) {
	m := testManager(t)
	require.NoError(t, m.StartGadget(context.Background(), desired("old")))
	defer func() { require.NoError(t, m.StopGadget(context.Background(), "old")) }()
	entered := make(chan struct{})
	op := simple.New("candidate", simple.OnStart(func(ctx operators.GadgetContext) error {
		close(entered)
		<-ctx.Context().Done()
		return ctx.Context().Err()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- m.ReplaceGadget(ctx, "old", desired("new"), gadgetcontext.WithAdditionalDataOperators(op))
	}()
	<-entered
	cancel()
	require.ErrorIs(t, receive(t, done), context.Canceled)
	require.Nil(t, m.LookupInstance("new"))
	require.NotNil(t, m.LookupInstance("old"))
}

func TestStopCancellationCanBeWaitedAgain(t *testing.T) {
	m := testManager(t)
	stopping, release := make(chan struct{}), make(chan struct{})
	op := simple.New("test", simple.OnStop(func(operators.GadgetContext) error {
		close(stopping)
		<-release
		return nil
	}))
	require.NoError(t, m.StartGadget(context.Background(), desired("one"), gadgetcontext.WithAdditionalDataOperators(op)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.StopGadget(ctx, "one") }()
	<-stopping
	cancel()
	require.ErrorIs(t, receive(t, done), context.Canceled)
	require.NotNil(t, m.LookupInstance("one"))
	close(release)
	require.NoError(t, m.StopGadget(context.Background(), "one"))
	require.Nil(t, m.LookupInstance("one"))
}

func TestStartupFailureReleasesMetadataWaiters(t *testing.T) {
	m := testManager(t)
	d := desired("bad")
	d.GadgetConfig.Version = 0
	m.RunGadget(d)
	gi := m.LookupInstance("bad")
	done := make(chan error, 1)
	go func() { _, err := gi.GadgetInfo(); done <- err }()
	require.Error(t, receive(t, done))
	require.NoError(t, m.RemoveGadget("bad"))
}

func TestConcurrentReplacementsSerialize(t *testing.T) {
	m := testManager(t)
	ctx := context.Background()
	require.NoError(t, m.StartGadget(ctx, desired("old")))
	entered, release := make(chan struct{}), make(chan struct{})
	op := simple.New("candidate", simple.OnStart(func(operators.GadgetContext) error {
		close(entered)
		<-release
		return nil
	}))
	first, second := make(chan error, 1), make(chan error, 1)
	go func() {
		first <- m.ReplaceGadget(ctx, "old", desired("first"), gadgetcontext.WithAdditionalDataOperators(op))
	}()
	<-entered
	go func() { second <- m.ReplaceGadget(ctx, "old", desired("second")) }()
	close(release)
	require.NoError(t, receive(t, first))
	require.ErrorIs(t, receive(t, second), ErrNotFound)
	require.Nil(t, m.LookupInstance("second"))
	require.NoError(t, m.StopGadget(ctx, "first"))
}

func TestStopReportsCleanupFailure(t *testing.T) {
	m := testManager(t)
	failure := errors.New("cleanup failed")
	op := simple.New("test", simple.OnStop(func(operators.GadgetContext) error { return failure }))
	require.NoError(t, m.StartGadget(context.Background(), desired("one"), gadgetcontext.WithAdditionalDataOperators(op)))
	require.ErrorIs(t, m.StopGadget(context.Background(), "one"), failure)
	require.Nil(t, m.LookupInstance("one"))
}

func TestLifecycleWaitHonorsContextWithoutMutation(t *testing.T) {
	operations := map[string]func(*Manager, context.Context) error{
		"start": func(m *Manager, ctx context.Context) error { return m.StartGadget(ctx, desired("new")) },
		"replace": func(m *Manager, ctx context.Context) error {
			return m.ReplaceGadget(ctx, "old", desired("new"))
		},
		"stop": func(m *Manager, ctx context.Context) error { return m.StopGadget(ctx, "old") },
	}
	for name, operation := range operations {
		t.Run(name, func(t *testing.T) {
			m := testManager(t)
			require.NoError(t, m.StartGadget(context.Background(), desired("old")))
			t.Cleanup(func() { require.NoError(t, m.StopGadget(context.Background(), "old")) })
			require.NoError(t, m.lockLifecycle(context.Background()))
			func() {
				defer m.unlockLifecycle()
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- operation(m, ctx) }()
				require.ErrorIs(t, receive(t, done), context.DeadlineExceeded)
			}()
			// An already canceled caller must not acquire an available lock either.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			require.ErrorIs(t, operation(m, ctx), context.Canceled)
			require.Nil(t, m.LookupInstance("new"))
			old := m.LookupInstance("old")
			require.NotNil(t, old)
			select {
			case <-old.stopped:
				t.Fatal("canceled lifecycle waiter stopped the old instance")
			default:
			}
		})
	}
}

func TestCanceledStartupJoinsWhileOtherWaitersCanCancel(t *testing.T) {
	m := testManager(t)
	entered, release := make(chan struct{}), make(chan struct{})
	op := simple.New("blocked", simple.OnStart(func(operators.GadgetContext) error {
		close(entered)
		<-release
		return errors.New("startup failed")
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := make(chan error, 1)
	go func() {
		start <- m.StartGadget(ctx, desired("blocked"), gadgetcontext.WithAdditionalDataOperators(op))
	}()
	<-entered
	defer func() {
		close(release)
		require.ErrorIs(t, receive(t, start), context.Canceled)
		require.Nil(t, m.LookupInstance("blocked"))
	}()
	cancel()
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer waitCancel()
	stop := make(chan error, 1)
	go func() { stop <- m.StopGadget(waitCtx, "blocked") }()
	require.ErrorIs(t, receive(t, stop), context.DeadlineExceeded)
	select {
	case <-start:
		t.Fatal("canceled startup returned before its runtime cleanup")
	default:
	}
}
