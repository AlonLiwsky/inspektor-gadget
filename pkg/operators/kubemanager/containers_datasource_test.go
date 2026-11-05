// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kubemanager

import (
	"context"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	kubemanagerpolicy "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager/policy"
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
	manager := &KubeManager{containerCollection: collection}
	instance, err := manager.InstantiateDataOperator(gc, nil)
	require.NoError(t, err)
	require.NotNil(t, instance, "container datasource alone must activate the manager")
	require.False(t, instance.(*KubeManagerInstance).namespaceScopeRequired)
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
	// Exercise notification publishing without invoking root-only tracer setup.
	t.Cleanup(instance.(*KubeManagerInstance).containersPublisher.Unsubscribe)
	require.NoError(t, instance.Start(gc))
	require.Equal(t, []string{"known-container"}, ids)
}

func TestScopedContainersDatasourceOnlyIsNotIsolationCapability(t *testing.T) {
	for _, tc := range []struct {
		name              string
		independentEvents bool
	}{
		{name: "notifications only"},
		{name: "independent unfiltered events", independentEvents: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gc := gadgetcontext.New(policyContext("team-a"), "test")
			require.NoError(t, gc.SetMetadata([]byte("annotations:\n  enable-containers-datasource: true\n")))
			if tc.independentEvents {
				_, err := gc.RegisterDataSource(datasource.TypeSingle, "events")
				require.NoError(t, err)
			}
			manager := &KubeManager{containerCollection: &containercollection.ContainerCollection{}}
			instance, err := manager.InstantiateDataOperator(gc, api.ParamValues{})
			require.Nil(t, instance)
			require.Equal(t, codes.PermissionDenied, status.Code(err))
		})
	}
}

func TestLegacyScopedMountNsRequestStillActivatesManager(t *testing.T) {
	gc := gadgetcontext.New(policyContext("team-a"), "test")
	require.NoError(t, gc.SetMetadata([]byte("annotations:\n  enable-containers-datasource: true\n")))
	// This is the pre-existing map-request activation path, not a proof that
	// every gadget datasource actually invokes the mount-namespace filter.
	gc.SetVar(gadgets.MntNsFilterMapName, (*ebpf.Map)(nil))
	manager := &KubeManager{containerCollection: &containercollection.ContainerCollection{}}
	instance, err := manager.InstantiateDataOperator(gc, api.ParamValues{"namespace": "team-a"})
	require.NoError(t, err)
	require.NotNil(t, instance)
	require.True(t, instance.(*KubeManagerInstance).namespaceScopeRequired)
}

func TestPersistedScopedManagerStartKeepsPublisherBoundary(t *testing.T) {
	stored := api.ParamValues{"operator.KubeManager.namespace": "team-a"}
	require.NoError(t, kubemanagerpolicy.EnforcePolicyScopeOnParamValues(policyContext("team-a"), stored))
	require.Equal(t, "true", stored["operator.KubeManager."+paramPolicyScope])

	for _, tc := range []struct {
		name   string
		ctx    context.Context
		values api.ParamValues
	}{
		{
			name:   "persisted marker without request context",
			ctx:    context.Background(),
			values: stored.ExtractPrefixedValues("operator.KubeManager"),
		},
		{
			name:   "authenticated scope overrides explicit false marker",
			ctx:    policyContext("team-a"),
			values: api.ParamValues{"namespace": "team-a", paramPolicyScope: "false"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			collection := &containercollection.ContainerCollection{}
			require.NoError(t, collection.Initialize(containercollection.WithPubSub()))
			t.Cleanup(collection.Close)
			gc := gadgetcontext.New(tc.ctx, "test")
			require.NoError(t, gc.SetMetadata([]byte("annotations:\n  enable-containers-datasource: true\n")))
			// Exercise the pre-existing activation route used by a persisted
			// gadget; this map request alone is not all-output proof.
			gc.SetVar(gadgets.MntNsFilterMapName, (*ebpf.Map)(nil))
			manager := &KubeManager{containerCollection: collection}
			instance, err := manager.InstantiateDataOperator(gc, tc.values)
			require.NoError(t, err)
			require.True(t, instance.(*KubeManagerInstance).namespaceScopeRequired)
			t.Cleanup(instance.(*KubeManagerInstance).containersPublisher.Unsubscribe)

			ds := gc.GetDataSources()["containers"]
			var ids []string
			require.NoError(t, ds.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
				id, err := ds.GetField("container_id").String(data)
				if err != nil {
					return err
				}
				ids = append(ids, id)
				return nil
			}, 0))
			require.NoError(t, instance.Start(gc))
			for _, namespace := range []string{"team-b", "team-a"} {
				container := &containercollection.Container{}
				container.Runtime.ContainerID = namespace
				container.K8s.Namespace = namespace
				collection.AddContainer(container)
			}
			require.Equal(t, []string{"team-a"}, ids)
		})
	}
}
