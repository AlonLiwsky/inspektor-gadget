// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package localmanager

import (
	"context"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
)

// A gadget consuming container notifications need not request mount-namespace
// filtering or expose process fields. Its manager must still publish targets.
func TestContainersDatasourceOnlyActivatesManager(t *testing.T) {
	collection := &containercollection.ContainerCollection{}
	require.NoError(t, collection.Initialize(containercollection.WithPubSub()))
	t.Cleanup(collection.Close)
	container := &containercollection.Container{CgroupID: 123, CgroupV2: "/test/container"}
	container.Runtime.ContainerID = "known-container"
	collection.AddContainer(container)
	gc := gadgetcontext.New(context.Background(), "test")
	require.NoError(t, gc.SetMetadata([]byte("annotations:\n  enable-containers-datasource: true\n")))
	tracers, err := tracercollection.NewTracerCollectionTest(collection)
	require.NoError(t, err)
	manager := &localManager{containerCollection: collection, tracerCollection: tracers}
	instance, err := manager.InstantiateDataOperator(gc, nil)
	require.NoError(t, err)
	require.NotNil(t, instance, "container datasource alone must activate the manager")
	ds := gc.GetDataSources()["containers"]
	require.NotNil(t, ds)
	var ids []string
	require.NoError(t, ds.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
		id, err := ds.GetField("container_id").String(data)
		if err != nil {
			return err
		}
		ids = append(ids, id)
		return nil
	}, 0))
	// The test tracer collection exercises ownership without requiring BPF privileges.
	wrapper := instance.(*localManagerTraceWrapper)
	require.NoError(t, wrapper.PreStart(gc))
	require.Equal(t, 1, tracers.TracerCount())
	require.Empty(t, wrapper.subscriptionKey)
	require.NoError(t, instance.Start(gc))
	require.Equal(t, []string{"known-container"}, ids)
	require.NoError(t, instance.Stop(gc))
	require.NoError(t, instance.Close(gc))
	require.Zero(t, tracers.TracerCount())
	require.NoError(t, instance.Close(gc))
}

// Some legacy gadgets also receive the map through a setter. The wrapper must
// reuse its existing tracer and clean it up even if Start was never reached.
type mountNsSetter struct{}

func (*mountNsSetter) SetMountNsMap(*ebpf.Map) {}

func TestCloseBeforeStartReleasesMountNsTracer(t *testing.T) {
	collection := &containercollection.ContainerCollection{}
	require.NoError(t, collection.Initialize(containercollection.WithPubSub()))
	t.Cleanup(collection.Close)
	tracers, err := tracercollection.NewTracerCollectionTest(collection)
	require.NoError(t, err)
	manager := &localManager{containerCollection: collection, tracerCollection: tracers}
	gc := gadgetcontext.New(context.Background(), "test")
	require.NoError(t, gc.SetMetadata([]byte("annotations:\n  enable-containers-datasource: true\n")))
	gc.SetVar("ebpfInstance", &mountNsSetter{})
	instance, err := manager.InstantiateDataOperator(gc, nil)
	require.NoError(t, err)
	wrapper := instance.(*localManagerTraceWrapper)
	require.NoError(t, wrapper.PreStart(gc))
	require.Equal(t, 1, tracers.TracerCount(), "wrapper and setter must share the tracer")
	require.NotEmpty(t, wrapper.tracerID)
	require.Empty(t, wrapper.subscriptionKey)
	require.NoError(t, instance.Close(gc))
	require.Zero(t, tracers.TracerCount())
}
