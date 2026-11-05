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

func TestRemovalKeepsReaddedContainerAndDoesNotRollForward(t *testing.T) {
	collection := &ContainerCollection{}
	require.NoError(t, collection.Initialize(WithPubSub()))
	defer collection.Close()
	first := &Container{Mntns: 123, Netns: 456}
	first.Runtime.ContainerID = "reused"
	collection.AddContainer(first)
	entered, release, callbackDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	firstDone, secondDone := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	collection.Subscribe("blocking", ContainerSelector{}, func(event PubSubEvent) {
		if event.Type == EventTypeRemoveContainer && event.Container == first {
			close(entered)
			<-release
			close(callbackDone)
		}
	})
	defer func() {
		releaseOnce.Do(func() { close(release) })
		<-firstDone
		<-secondDone
	}()
	go func() { collection.RemoveContainer("reused"); close(firstDone) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("removal callback did not start")
	}
	go func() { collection.RemoveContainer("reused"); close(secondDone) }()
	select {
	case <-secondDone:
		t.Fatal("second removal returned before first finished")
	case <-time.After(50 * time.Millisecond):
	}

	// The primary and namespace transitions must use the same lock. With the
	// lock held, a completed callback cannot expose a gap where B can be added
	// before A's namespace entries are cleaned up.
	collection.mu.Lock()
	releaseOnce.Do(func() { close(release) })
	<-callbackDone
	select {
	case <-firstDone:
		collection.mu.Unlock()
		t.Fatal("removal completed while namespace lock was held")
	case <-time.After(50 * time.Millisecond):
	}
	stillPresent := collection.GetContainer("reused")
	collection.mu.Unlock()
	require.Same(t, first, stillPresent)
	<-firstDone

	second := &Container{Mntns: first.Mntns, Netns: first.Netns}
	second.Runtime.ContainerID = "reused"
	collection.AddContainer(second)
	<-secondDone
	require.Same(t, second, collection.GetContainer("reused"))
	require.Same(t, second, collection.LookupContainerByMntns(second.Mntns))
	require.Equal(t, []*Container{second}, collection.LookupContainersByNetns(second.Netns))
}

func TestRemovalCallbackMayRemoveOtherIDAndScheduleSameID(t *testing.T) {
	collection := &ContainerCollection{}
	require.NoError(t, collection.Initialize(WithPubSub()))
	defer collection.Close()
	first := &Container{Mntns: 123, Netns: 456}
	first.Runtime.ContainerID = "first"
	other := &Container{Mntns: 124, Netns: 457}
	other.Runtime.ContainerID = "other"
	collection.AddContainer(first)
	collection.AddContainer(other)
	asynchronousDone := make(chan struct{})
	collection.Subscribe("nested", ContainerSelector{}, func(event PubSubEvent) {
		if event.Type != EventTypeRemoveContainer || event.Container != first {
			return
		}
		collection.RemoveContainer("other")
		go func() { collection.RemoveContainer("first"); close(asynchronousDone) }()
	})
	collection.RemoveContainer("first")
	select {
	case <-asynchronousDone:
	case <-time.After(5 * time.Second):
		t.Fatal("asynchronous same-ID removal did not finish")
	}
	require.Nil(t, collection.GetContainer("first"))
	require.Nil(t, collection.GetContainer("other"))
}

func TestCloseDoesNotHoldCollectionLockWhileJoiningCallbacks(t *testing.T) {
	collection := &ContainerCollection{}
	require.NoError(t, collection.Initialize(WithPubSub()))
	cleanupEntered := make(chan struct{})
	enterSubscriber := make(chan struct{})
	watcherDone := make(chan struct{})
	closeDone := make(chan struct{})
	collection.cleanUpFuncs = append(collection.cleanUpFuncs, func() {
		close(cleanupEntered)
		<-watcherDone
	})
	go func() {
		<-enterSubscriber
		collection.Subscribe("during-close", ContainerSelector{}, func(PubSubEvent) {})
		close(watcherDone)
	}()
	go func() { collection.Close(); close(closeDone) }()
	select {
	case <-cleanupEntered:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not enter cleanup")
	}
	close(enterSubscriber)
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Close held collection lock while joining callback")
	}
}

func TestCloseClearsLiveContainerLookups(t *testing.T) {
	collection := &ContainerCollection{}
	require.NoError(t, collection.Initialize())
	container := &Container{Mntns: 123, Netns: 456}
	container.Runtime.ContainerID = "live"
	collection.AddContainer(container)
	collection.Close()
	require.Nil(t, collection.GetContainer("live"))
	require.Nil(t, collection.LookupContainerByMntns(container.Mntns))
	require.Empty(t, collection.LookupContainersByNetns(container.Netns))
}

func TestCloseRejectsNewAddWithoutBreakingInflightRemoval(t *testing.T) {
	collection := &ContainerCollection{}
	require.NoError(t, collection.Initialize(WithPubSub()))
	collection.cachedContainers = &sync.Map{}
	collection.cleanUpFuncs = append(collection.cleanUpFuncs, func() {
		collection.cachedContainers.Range(func(key, _ interface{}) bool {
			collection.cachedContainers.Delete(key)
			return true
		})
	})
	first := &Container{Mntns: 123, Netns: 456}
	first.Runtime.ContainerID = "first"
	collection.AddContainer(first)
	live := &Container{Mntns: 125, Netns: 458}
	live.Runtime.ContainerID = "live"
	collection.AddContainer(live)
	entered, release := make(chan struct{}), make(chan struct{})
	removeDone, secondRemoveDone, closeDone := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	collection.Subscribe("blocking", ContainerSelector{}, func(event PubSubEvent) {
		if event.Type == EventTypeRemoveContainer {
			close(entered)
			<-release
		}
	})
	defer func() {
		releaseOnce.Do(func() { close(release) })
		<-removeDone
		<-secondRemoveDone
		<-closeDone
	}()
	go func() { collection.RemoveContainer("first"); close(removeDone) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("removal callback did not start")
	}
	go func() { collection.Close(); close(closeDone) }()
	select {
	case <-collection.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not begin")
	}
	second := &Container{Mntns: 124, Netns: 457}
	second.Runtime.ContainerID = "second"
	collection.AddContainer(second)
	go func() { collection.RemoveContainer("first"); close(secondRemoveDone) }()
	require.Nil(t, collection.GetContainer("second"))
	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not finish while removal callback was blocked")
	}
	require.Nil(t, collection.GetContainer("live"))
	require.Nil(t, collection.LookupContainerByMntns(live.Mntns))
	require.Empty(t, collection.LookupContainersByNetns(live.Netns))
	require.Same(t, first, collection.GetContainer("first"))
	require.Same(t, first, collection.LookupContainerByMntns(first.Mntns))
	require.Equal(t, []*Container{first}, collection.LookupContainersByNetns(first.Netns))
	select {
	case <-removeDone:
		t.Fatal("removal completed before subscriber cleanup")
	case <-secondRemoveDone:
		t.Fatal("concurrent removal returned before subscriber cleanup")
	case <-time.After(50 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	<-removeDone
	<-secondRemoveDone
	<-closeDone
	require.Nil(t, collection.GetContainer("first"))
	require.Nil(t, collection.LookupContainerByMntns(first.Mntns))
	require.Empty(t, collection.LookupContainersByNetns(first.Netns))
	_, cached := collection.cachedContainers.Load("first")
	require.False(t, cached, "removal must not refill the cache after Close drained it")
}
