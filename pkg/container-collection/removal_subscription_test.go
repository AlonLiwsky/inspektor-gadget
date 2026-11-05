// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package containercollection

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSubscribeDuringRemovalExcludesDeletingContainer(t *testing.T) {
	collection := &ContainerCollection{}
	require.NoError(t, collection.Initialize(WithPubSub()))
	defer collection.Close()
	container := &Container{Mntns: 123, Netns: 456}
	container.Runtime.ContainerID = "deleting"
	collection.AddContainer(container)
	entered, release, removed := make(chan struct{}), make(chan struct{}), make(chan struct{})
	collection.Subscribe("blocking", ContainerSelector{}, func(event PubSubEvent) {
		if event.Type == EventTypeRemoveContainer {
			close(entered)
			<-release
		}
	})
	go func() { collection.RemoveContainer("deleting"); close(removed) }()
	var once sync.Once
	defer func() { once.Do(func() { close(release) }); <-removed }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("removal callback did not start")
	}
	// Enrichment lookups remain available until existing subscribers finish.
	require.Same(t, container, collection.GetContainer("deleting"))
	snapshot := collection.Subscribe("candidate", ContainerSelector{}, func(PubSubEvent) {})
	require.Empty(t, snapshot, "candidate missed the in-flight deletion but replayed its container")
	once.Do(func() { close(release) })
	<-removed
	require.Nil(t, collection.GetContainer("deleting"))
}

func TestConcurrentRemoveContainerWaitsForSubscriberCleanup(t *testing.T) {
	collection := &ContainerCollection{}
	require.NoError(t, collection.Initialize(WithPubSub()))
	defer collection.Close()
	container := &Container{Mntns: 123, Netns: 456}
	container.Runtime.ContainerID = "deleting"
	collection.AddContainer(container)

	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan struct{})
	secondDone := make(chan struct{})
	var releaseOnce sync.Once
	collection.Subscribe("blocking", ContainerSelector{}, func(event PubSubEvent) {
		if event.Type == EventTypeRemoveContainer {
			close(entered)
			<-release
		}
	})
	defer func() {
		releaseOnce.Do(func() { close(release) })
		<-firstDone
		<-secondDone
	}()
	go func() { collection.RemoveContainer("deleting"); close(firstDone) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("removal callback did not start")
	}
	go func() { collection.RemoveContainer("deleting"); close(secondDone) }()
	select {
	case <-secondDone:
		t.Fatal("concurrent removal returned before subscriber cleanup")
	case <-time.After(100 * time.Millisecond):
	}
	require.Same(t, container, collection.GetContainer("deleting"))
	releaseOnce.Do(func() { close(release) })
	<-firstDone
	<-secondDone
	require.Nil(t, collection.GetContainer("deleting"))
	require.Nil(t, collection.LookupContainerByMntns(container.Mntns))
	require.Empty(t, collection.LookupContainersByNetns(container.Netns))
}
