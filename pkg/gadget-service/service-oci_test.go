// Copyright 2024-2025 The Inspektor Gadget authors
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

package gadgetservice

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"testing/synctest"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

// heldMetadataStream detects Send overlap and output preceding completed metadata.
// Other ServerStream methods are unused by Service.RunGadget.
type heldMetadataStream struct {
	grpc.ServerStream
	ctx             context.Context
	controls        chan *api.GadgetControlRequest
	metadataEntered chan struct{}
	metadataRelease chan struct{}
	metadataErr     error
	mu              sync.Mutex
	active          int
	concurrent      bool
	premature       bool
	metadataSent    bool
	events          []*api.GadgetEvent
}

func (s *heldMetadataStream) Context() context.Context { return s.ctx }
func (s *heldMetadataStream) Recv() (*api.GadgetControlRequest, error) {
	select {
	case request := <-s.controls:
		return request, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func (s *heldMetadataStream) Send(event *api.GadgetEvent) error {
	s.mu.Lock()
	s.active++
	s.concurrent = s.concurrent || s.active > 1
	if event.Type != api.EventTypeGadgetInfo && !s.metadataSent {
		s.premature = true
	}
	s.events = append(s.events, proto.Clone(event).(*api.GadgetEvent))
	s.mu.Unlock()
	defer func() { s.mu.Lock(); s.active--; s.mu.Unlock() }()
	if event.Type == api.EventTypeGadgetInfo {
		close(s.metadataEntered)
		select {
		case <-s.metadataRelease:
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
		if s.metadataErr != nil {
			return s.metadataErr
		}
		s.mu.Lock()
		s.metadataSent = true
		s.mu.Unlock()
	}
	return nil
}

func (s *heldMetadataStream) snapshot() ([]*api.GadgetEvent, bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*api.GadgetEvent(nil), s.events...), s.concurrent, s.premature
}

type sendOrderFixture struct {
	stream    *heldMetadataStream
	cancel    context.CancelFunc
	result    chan error
	gadgetCtx operators.GadgetContext
	ds        datasource.DataSource
	started   bool
	stopped   bool
}

func newSendOrderFixture(metadataErr error) *sendOrderFixture {
	ctx, cancel := context.WithCancel(context.Background())
	f := &sendOrderFixture{
		cancel: cancel, result: make(chan error, 1),
		stream: &heldMetadataStream{ctx: ctx, controls: make(chan *api.GadgetControlRequest, 1), metadataEntered: make(chan struct{}), metadataRelease: make(chan struct{}), metadataErr: metadataErr},
	}
	producer := simple.New("producer", simple.OnInit(func(ctx operators.GadgetContext) error {
		f.gadgetCtx = ctx
		var err error
		f.ds, err = ctx.RegisterDataSource(datasource.TypeSingle, "events")
		return err
	}), simple.OnStart(func(operators.GadgetContext) error { f.started = true; return nil }), simple.OnStop(func(operators.GadgetContext) error { f.stopped = true; return nil }))
	fallback := log.New()
	fallback.SetOutput(io.Discard)
	service := &Service{runtime: local.New(), logger: fallback, eventBufferLength: 128, operators: map[operators.DataOperator]*params.Params{producer: nil}, ctrRunGadget: noop.Int64Counter{}}
	f.stream.controls <- &api.GadgetControlRequest{Event: &api.GadgetControlRequest_RunRequest{RunRequest: &api.GadgetRunRequest{Version: api.VersionGadgetRunProtocol, ImageName: "send-order-test", LogLevel: uint32(logger.DebugLevel)}}}
	go func() {
		err := service.RunGadget(f.stream)
		// gRPC cancels the server stream context when the handler returns.
		cancel()
		f.result <- err
	}()
	return f
}

func queueInitialOutput(t *testing.T, f *sendOrderFixture) {
	t.Helper()
	f.gadgetCtx.Logger().Debug("queued before metadata completed")
	for range 2 {
		packet, err := f.ds.NewPacketSingle()
		require.NoError(t, err)
		require.NoError(t, f.ds.EmitAndRelease(packet))
	}
}

func TestRunGadgetMetadataPrecedesQueuedOutput(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newSendOrderFixture(nil)
		defer f.cancel()
		<-f.stream.metadataEntered
		queueInitialOutput(t, f)
		synctest.Wait()
		held, concurrent, premature := f.stream.snapshot()
		require.False(t, concurrent, "Send must not run concurrently with held metadata")
		require.False(t, premature, "queued output must not precede successful metadata")
		require.Len(t, held, 1)
		require.Equal(t, api.EventTypeGadgetInfo, held[0].Type)
		require.False(t, f.started)
		close(f.stream.metadataRelease)
		synctest.Wait()
		events, concurrent, premature := f.stream.snapshot()
		require.False(t, concurrent)
		require.False(t, premature)
		require.True(t, f.started)
		info := &api.GadgetInfo{}
		require.NoError(t, proto.Unmarshal(events[0].Payload, info))
		require.Len(t, info.DataSources, 1)
		require.Equal(t, "events", info.DataSources[0].Name)
		var sequences []uint32
		queuedLog := false
		for _, event := range events[1:] {
			if string(event.Payload) == "queued before metadata completed" {
				queuedLog = true
			}
			if event.Type == api.EventTypeGadgetPayload {
				require.Equal(t, info.DataSources[0].Id, event.DataSourceID)
				sequences = append(sequences, event.Seq)
			}
		}
		require.True(t, queuedLog)
		require.Equal(t, []uint32{1, 2}, sequences)
		f.stream.controls <- &api.GadgetControlRequest{Event: &api.GadgetControlRequest_StopRequest{StopRequest: &api.GadgetStopRequest{}}}
		require.NoError(t, <-f.result)
		synctest.Wait()
		require.True(t, f.stopped)
		require.ErrorIs(t, f.gadgetCtx.Context().Err(), context.Canceled)
	})
}

func TestRunGadgetMetadataFailureDoesNotStartPump(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		sendErr := errors.New("metadata send failed")
		f := newSendOrderFixture(sendErr)
		defer f.cancel()
		<-f.stream.metadataEntered
		queueInitialOutput(t, f)
		close(f.stream.metadataRelease)
		synctest.Wait()
		// Avoid a wall-clock timeout on the unfixed implementation, which wrongly
		// starts the gadget and remains running after ignoring the metadata error.
		var result error
		select {
		case result = <-f.result:
		default:
			f.cancel()
			result = <-f.result
		}
		synctest.Wait()
		require.ErrorIs(t, result, sendErr)
		require.False(t, f.started)
		require.False(t, f.stopped, "an unstarted operator must not receive Stop")
		events, concurrent, premature := f.stream.snapshot()
		require.Len(t, events, 1, "no message pump may run after metadata failure")
		require.False(t, concurrent)
		require.False(t, premature)
		require.ErrorIs(t, f.gadgetCtx.Context().Err(), context.Canceled)
	})
}

func TestRunGadgetCancellationWhileSendingMetadata(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		f := newSendOrderFixture(nil)
		defer f.cancel()
		<-f.stream.metadataEntered
		queueInitialOutput(t, f)
		f.cancel()
		require.ErrorIs(t, <-f.result, context.Canceled)
		synctest.Wait()
		require.False(t, f.started)
		events, concurrent, premature := f.stream.snapshot()
		require.Len(t, events, 1)
		require.False(t, concurrent)
		require.False(t, premature)
		require.ErrorIs(t, f.gadgetCtx.Context().Err(), context.Canceled)
	})
}
