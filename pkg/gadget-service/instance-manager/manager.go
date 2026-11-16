// Copyright 2023-2025 The Inspektor Gadget authors
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

package instancemanager

import (
	"context"
	"fmt"
	"strings"
	"sync"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"

	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime"
)

type mgrError string

func (err mgrError) Error() string {
	return string(err)
}

const (
	ErrNotFound = mgrError("gadget not found")
)

type Service interface {
	GetOperatorMap() map[operators.DataOperator]*params.Params
}

// Manager manages running gadgets headless. It can run gadgets in the background as
// well as buffer and multiplex their output.
type Manager struct {
	// lifecycleMu serializes lifecycle operations; initialization is safe for a zero-value Manager.
	lifecycleOnce sync.Once
	lifecycleMu   chan struct{}

	// mu is to be used whenever a gadget is installed or a new client wants to attach to a gadget
	mu              sync.Mutex
	gadgetInstances map[string]*GadgetInstance

	// The waiting room is used for clients that --attach to a gadget instance that hasn't been reconciled, yet.
	// The connection will then wait in the waitingRoom for reconciliation and then get attached to the newly created
	// gadget instance.
	waitingRoom sync.Map

	// asyncGadgetRunCreation tells the Manager whether it is completely in control of creating gadget
	// runs, or if those are (also) externally managed, like through custom resources in a kubernetes environment
	asyncGadgetRunCreation bool

	runtime runtime.Runtime

	Service
}

func New(runtime runtime.Runtime, options ...Option) (*Manager, error) {
	mgr := &Manager{
		gadgetInstances: make(map[string]*GadgetInstance),
		runtime:         runtime,
	}
	for _, opt := range options {
		err := opt(mgr)
		if err != nil {
			return nil, err
		}
	}
	return mgr, nil
}

// RemoveGadget cancels and removes a gadget
func (m *Manager) RemoveGadget(id string) error {
	_ = m.lockLifecycle(context.Background())
	defer m.unlockLifecycle()
	return m.removeGadget(id)
}

func (m *Manager) removeGadget(id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	gadgetInstance, ok := m.gadgetInstances[id]
	if !ok {
		return ErrNotFound
	}
	gadgetInstance.cancel()
	delete(m.gadgetInstances, id)
	return nil
}

func (m *Manager) RunGadget(instance *api.GadgetInstance) {
	_ = m.lockLifecycle(context.Background())
	defer m.unlockLifecycle()
	if _, err := m.runGadget(instance); err != nil {
		log.Errorf("creating gadget: %v", err)
	}
}

func (m *Manager) runGadget(instance *api.GadgetInstance, options ...gadgetcontext.Option) (*GadgetInstance, error) {
	if instance == nil || instance.GadgetConfig == nil || instance.Id == "" {
		return nil, fmt.Errorf("missing gadget ID or configuration")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, exists := m.gadgetInstances[instance.Id]; exists {
		return nil, fmt.Errorf("gadget %q already exists", instance.Id)
	}
	instance = proto.Clone(instance).(*api.GadgetInstance)
	ctx, cancel := context.WithCancel(context.Background())
	gi := &GadgetInstance{
		id:              instance.Id,
		name:            instance.Name,
		mgr:             m,
		request:         proto.Clone(instance.GadgetConfig).(*api.GadgetRunRequest),
		eventBuffer:     make([]*bufferedEvent, 1024),
		eventBufferOffs: 0,
		cancel:          cancel,
		clients:         map[*GadgetInstanceClient]struct{}{},
		ready:           make(chan struct{}),
		started:         make(chan struct{}),
		stopped:         make(chan struct{}),
	}
	m.gadgetInstances[gi.id] = gi
	go func() {
		defer cancel()
		l := log.StandardLogger()
		l.SetFormatter(&log.JSONFormatter{})
		lwr := &logWrapper{Entry: l.WithFields(log.Fields{
			"type":         "gadget-log",
			"instanceID":   instance.Id,
			"instanceName": instance.Name,
			"gadget":       instance.GadgetConfig.ImageName,
		}), logLevel: logger.Level(instance.GadgetConfig.LogLevel)}
		err := gi.Run(ctx, m.runtime, lwr, options...)
		gi.mu.Lock()
		if gi.state != stateRunning && err == nil {
			err = fmt.Errorf("gadget exited before startup completed")
		}
		if err != nil {
			gi.state = stateError
			gi.error = err
		} else {
			gi.state = stateInvalid
		}
		gi.mu.Unlock()
		if err != nil {
			log.Errorf("running gadget: %v", err)
		}
		gi.readyOnce.Do(func() { close(gi.ready) })
		gi.RemoveClients()
		close(gi.stopped)
	}()
	return gi, nil
}

func (m *Manager) LookupInstance(gadgetInstanceID string) *GadgetInstance {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 1. Match by complete ID
	if gi, ok := m.gadgetInstances[gadgetInstanceID]; ok {
		return gi
	}

	// 2. Match by name
	for _, gi := range m.gadgetInstances {
		if gi.name == gadgetInstanceID {
			return gi
		}
	}

	// 3. Partial match by ID
	for gid, gi := range m.gadgetInstances {
		if strings.HasPrefix(gid, gadgetInstanceID) {
			return gi
		}
	}

	return nil
}

func (m *Manager) InstanceState(gadgetInstanceID string) (*api.GadgetInstanceState, error) {
	gi := m.LookupInstance(gadgetInstanceID)
	if gi == nil {
		return nil, ErrNotFound
	}
	gi.mu.Lock()
	defer gi.mu.Unlock()
	var msg string
	if gi.error != nil {
		msg = gi.error.Error()
	}
	return &api.GadgetInstanceState{
		Status:  gi.state.ToGadgetStatus(),
		Message: msg,
	}, nil
}
