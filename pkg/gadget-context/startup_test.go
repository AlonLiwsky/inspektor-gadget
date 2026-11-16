// Copyright 2025 The Inspektor Gadget authors
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

package gadgetcontext

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type startupOperator struct {
	*fakeOperator
	afterStart func()
	stopError  error
}

func (o *startupOperator) InstantiateDataOperator(operators.GadgetContext, api.ParamValues) (operators.DataOperatorInstance, error) {
	return o, nil
}

func (o *startupOperator) Start(ctx operators.GadgetContext) error {
	if err := o.fakeOperator.Start(ctx); err != nil {
		return err
	}
	if o.afterStart != nil {
		o.afterStart()
	}
	return nil
}

func (o *startupOperator) PreStop(operators.GadgetContext) error { return o.runMethod("prestop") }
func (o *startupOperator) Stop(operators.GadgetContext) error {
	_ = o.runMethod("stop")
	return o.stopError
}

func TestOnStartedLifecycle(t *testing.T) {
	callbackError := errors.New("release failed")
	stopError := errors.New("stop failed")
	for _, tc := range []struct {
		name          string
		failStart     bool
		cancelOnStart bool
		callbackError error
		stopError     error
	}{
		{name: "success"},
		{name: "start failure", failStart: true},
		{name: "canceled startup", cancelOnStart: true},
		{name: "callback failure", callbackError: callbackError},
		{name: "callback and cleanup failure", callbackError: callbackError, stopError: stopError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			first := &startupOperator{fakeOperator: &fakeOperator{name: "first", priority: 1, called: &calls}, stopError: tc.stopError}
			second := &startupOperator{fakeOperator: &fakeOperator{name: "second", priority: 2, called: &calls}}
			if tc.failStart {
				second.fails = []string{"start"}
			}
			if tc.cancelOnStart {
				second.afterStart = cancel
			}
			var gadgetCtx *GadgetContext
			callbackCalls := 0
			gadgetCtx = New(ctx, "test", WithDataOperators(second, first), WithOnStarted(func() error {
				callbackCalls++
				require.Equal(t, []string{"first_prestart", "second_prestart", "first_start", "second_start"}, calls)
				calls = append(calls, "callback")
				cancel()
				return tc.callbackError
			}))
			err := gadgetCtx.Run(nil)
			if tc.failStart {
				require.ErrorContains(t, err, "starting operator")
				require.Zero(t, callbackCalls)
				require.Equal(t, []string{"first_prestart", "second_prestart", "first_start", "first_stop", "first_poststop", "second_close", "first_close"}, calls)
				return
			}
			expected := []string{"first_prestart", "second_prestart", "first_start", "second_start"}
			if tc.cancelOnStart {
				require.Zero(t, callbackCalls)
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.Equal(t, 1, callbackCalls)
				expected = append(expected, "callback")
				if tc.callbackError != nil {
					require.ErrorIs(t, err, tc.callbackError)
				} else {
					require.NoError(t, err)
				}
			}
			if tc.stopError != nil {
				require.ErrorIs(t, err, tc.stopError)
			}
			expected = append(expected, "second_prestop", "first_prestop", "second_stop", "first_stop", "second_poststop", "first_poststop", "second_close", "first_close")
			require.Equal(t, expected, calls)
		})
	}
}

func TestOnStartedNotCalledForGadgetInfo(t *testing.T) {
	called := false
	ctx := New(context.Background(), "test", WithDataOperators(&fakeOperator{name: "test"}), WithOnStarted(func() error { called = true; return nil }))
	defer ctx.Cancel()
	require.NoError(t, ctx.PrepareGadgetInfo(nil))
	require.False(t, called)
}

func TestAdditionalDataOperatorsParticipateInStartup(t *testing.T) {
	var calls []string
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := &fakeOperator{name: "first", priority: 1, called: &calls}
	second := &fakeOperator{name: "second", priority: 2, called: &calls}
	gadgetCtx := New(ctx, "test", WithDataOperators(first), WithAdditionalDataOperators(second), WithOnStarted(func() error {
		require.Equal(t, []string{"first_prestart", "second_prestart", "first_start", "second_start"}, calls)
		cancel()
		return nil
	}))
	require.NoError(t, gadgetCtx.Run(nil))
}

type readinessOperator struct {
	*startupOperator
	check func() error
}

func (o *readinessOperator) InstantiateDataOperator(operators.GadgetContext, api.ParamValues) (operators.DataOperatorInstance, error) {
	return o, nil
}

func (o *readinessOperator) Ready(operators.GadgetContext) error {
	*o.called = append(*o.called, o.name+"_ready")
	return o.check()
}

func TestFinalReadinessAfterAllStarts(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "late coverage failure"}[fail], func(t *testing.T) {
			var calls []string
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			lateFailure := errors.New("late binding failed")
			var discoveredError error
			first := &readinessOperator{startupOperator: &startupOperator{fakeOperator: &fakeOperator{name: "first", priority: 1, called: &calls}}, check: func() error {
				require.Equal(t, []string{"first_prestart", "second_prestart", "first_start", "second_start", "first_ready"}, calls)
				return discoveredError
			}}
			second := &startupOperator{fakeOperator: &fakeOperator{name: "second", priority: 2, called: &calls}, afterStart: func() {
				if fail {
					discoveredError = lateFailure
				}
			}}
			callbackCalls := 0
			gc := New(ctx, "test", WithDataOperators(second, first), WithOnStarted(func() error { callbackCalls++; calls = append(calls, "callback"); cancel(); return nil }))
			err := gc.Run(nil)
			expected := []string{"first_prestart", "second_prestart", "first_start", "second_start", "first_ready"}
			if fail {
				require.ErrorIs(t, err, lateFailure)
				require.Zero(t, callbackCalls)
			} else {
				require.NoError(t, err)
				require.Equal(t, 1, callbackCalls)
				expected = append(expected, "callback")
			}
			expected = append(expected, "second_prestop", "first_prestop", "second_stop", "first_stop", "second_poststop", "first_poststop", "second_close", "first_close")
			require.Equal(t, expected, calls)
		})
	}
}
