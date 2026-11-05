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

package common

import (
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type ContainersPublisher struct {
	collection *containercollection.ContainerCollection

	containersDs              datasource.DataSource
	eventTypeField            datasource.FieldAccessor
	idField                   datasource.FieldAccessor
	runtimeField              datasource.FieldAccessor
	cgroupIDField             datasource.FieldAccessor
	cgroupV2PathField         datasource.FieldAccessor
	mountNsIDField            datasource.FieldAccessor
	nameField                 datasource.FieldAccessor
	containerConfigField      datasource.FieldAccessor
	containersSubscriptionKey string
}

func NewContainersPublisher(gadgetCtx operators.GadgetContext, collection *containercollection.ContainerCollection) (*ContainersPublisher, error) {
	publisher := &ContainersPublisher{}
	var err error

	publisher.containersDs, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, "containers")
	if err != nil {
		return nil, fmt.Errorf("creating datasource: %w", err)
	}
	publisher.containersDs.AddAnnotation("cli.default-output-mode", "none")

	publisher.eventTypeField, err = publisher.containersDs.AddField("event_type", api.Kind_String)
	if err != nil {
		return nil, fmt.Errorf("adding field event_type: %w", err)
	}

	publisher.idField, err = publisher.containersDs.AddField("container_id", api.Kind_String)
	if err != nil {
		return nil, fmt.Errorf("adding field container_id: %w", err)
	}

	publisher.runtimeField, err = publisher.containersDs.AddField("runtime", api.Kind_String)
	if err != nil {
		return nil, fmt.Errorf("adding field runtime: %w", err)
	}

	publisher.cgroupV2PathField, err = publisher.containersDs.AddField("cgroup_v2_path", api.Kind_String)
	if err != nil {
		return nil, fmt.Errorf("adding field cgroup_v2_path: %w", err)
	}

	publisher.cgroupIDField, err = publisher.containersDs.AddField("cgroup_id", api.Kind_Uint64)
	if err != nil {
		return nil, fmt.Errorf("adding field cgroup_id: %w", err)
	}

	publisher.mountNsIDField, err = publisher.containersDs.AddField("mntns_id", api.Kind_Uint64)
	if err != nil {
		return nil, fmt.Errorf("adding field mntns_id: %w", err)
	}

	publisher.nameField, err = publisher.containersDs.AddField("name", api.Kind_String)
	if err != nil {
		return nil, fmt.Errorf("adding field name: %w", err)
	}

	publisher.containerConfigField, err = publisher.containersDs.AddField("container_config", api.Kind_String)
	if err != nil {
		return nil, fmt.Errorf("adding field container_config: %w", err)
	}

	publisher.collection = collection

	return publisher, nil
}

func (publisher *ContainersPublisher) emitContainersDatasourceEvent(eventType containercollection.EventType, container *containercollection.Container, k8s bool) error {
	ev, err := publisher.containersDs.NewPacketSingle()
	if err != nil {
		return fmt.Errorf("creating new containers datasource packet: %w", err)
	}

	publisher.eventTypeField.PutString(ev, eventType.String())
	publisher.idField.PutString(ev, container.Runtime.ContainerID)
	publisher.runtimeField.PutString(ev, container.Runtime.RuntimeName.String())
	publisher.cgroupIDField.PutUint64(ev, container.CgroupID)
	publisher.cgroupV2PathField.PutString(ev, container.CgroupV2)
	publisher.mountNsIDField.PutUint64(ev, container.Mntns)
	if k8s {
		publisher.nameField.PutString(ev, container.K8s.ContainerName)
	} else {
		publisher.nameField.PutString(ev, container.Runtime.ContainerName)
	}

	publisher.containerConfigField.PutString(ev, container.OciConfig)

	err = publisher.containersDs.EmitAndRelease(ev)
	if err != nil {
		return fmt.Errorf("emitting containers datasource event: %w", err)
	}

	return nil
}

// scopedContainerEventMatches is an additional boundary check for authenticated
// namespace-scoped streams. Collection.Subscribe deliberately delivers all
// PRECREATE events before namespace enrichment, so its selector is not enough.
func scopedContainerEventMatches(eventType containercollection.EventType, container *containercollection.Container, selector containercollection.ContainerSelector) bool {
	switch eventType {
	case containercollection.EventTypeAddContainer, containercollection.EventTypeRemoveContainer,
		containercollection.EventTypePreCreateContainer, containercollection.EventTypeExecContainer:
	default:
		return false
	}
	if container == nil || container.K8s.Namespace == "" {
		return false
	}
	// An empty or exclusion-only selector is not proof of authorization.
	authorized := false
	for _, namespace := range strings.Split(selector.K8s.Namespace, ",") {
		if namespace == container.K8s.Namespace {
			authorized = true
			break
		}
	}
	return authorized && containercollection.ContainerSelectorMatches(&selector, container)
}

func (publisher *ContainersPublisher) emitSelectedContainersDatasourceEvent(eventType containercollection.EventType, container *containercollection.Container, k8s bool, selector containercollection.ContainerSelector, namespaceScopeRequired bool) error {
	if namespaceScopeRequired && !scopedContainerEventMatches(eventType, container, selector) {
		return nil
	}
	return publisher.emitContainersDatasourceEvent(eventType, container, k8s)
}

// namespaceScopeRequired is a restrictive emission signal: callers set
// it for an authenticated policy context or a persisted scoped-policy marker.
// Neither the marker nor a user-supplied selector is an authorization grant.
// The optional argument preserves unscoped callers without such a policy.
func (publisher *ContainersPublisher) PublishContainers(k8s bool, extraContainers []*containercollection.Container, containerSelector containercollection.ContainerSelector, namespaceScopeRequired ...bool) (err error) {
	scoped := len(namespaceScopeRequired) > 0 && namespaceScopeRequired[0]
	// Subscribe snapshots the collection atomically, but publishing that snapshot
	// takes time. Queue concurrent changes until the snapshot has been delivered.
	var mu sync.Mutex
	replaying, failed := true, false
	var pending []containercollection.PubSubEvent
	defer func() {
		if err != nil {
			mu.Lock()
			failed = true
			pending = nil
			mu.Unlock()
			publisher.Unsubscribe()
		}
	}()
	var containers []*containercollection.Container

	if publisher.collection != nil {
		publisher.containersSubscriptionKey = uuid.New().String()

		log.Debugf("add datasource containers subscription to container collection")
		containers = publisher.collection.Subscribe(
			publisher.containersSubscriptionKey,
			containerSelector,
			func(event containercollection.PubSubEvent) {
				mu.Lock()
				defer mu.Unlock()
				if failed {
					return
				}
				if replaying {
					pending = append(pending, event)
					return
				}
				err := publisher.emitSelectedContainersDatasourceEvent(event.Type, event.Container, k8s, containerSelector, scoped)
				if err != nil {
					log.Errorf("publishing new container event: %v", err)
				}
			},
		)
	}

	if len(extraContainers) > 0 {
		containers = append(containers, extraContainers...)
	}

	for _, container := range containers {
		err := publisher.emitSelectedContainersDatasourceEvent(containercollection.EventTypeAddContainer, container, k8s, containerSelector, scoped)
		if err != nil {
			return fmt.Errorf("publishing existing container event: %w", err)
		}
	}

	for {
		mu.Lock()
		if len(pending) == 0 {
			replaying = false
			mu.Unlock()
			return nil
		}
		batch := pending
		pending = nil
		mu.Unlock()
		for _, event := range batch {
			if err := publisher.emitSelectedContainersDatasourceEvent(event.Type, event.Container, k8s, containerSelector, scoped); err != nil {
				return fmt.Errorf("publishing queued container event: %w", err)
			}
		}
	}
}

func (publisher *ContainersPublisher) Unsubscribe() {
	if publisher.containersSubscriptionKey != "" {
		publisher.collection.Unsubscribe(publisher.containersSubscriptionKey)
	}
}
