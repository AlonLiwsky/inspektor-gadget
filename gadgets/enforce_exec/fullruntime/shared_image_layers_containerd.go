// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"fmt"

	containerd "github.com/containerd/containerd/v2/client"
)

// sharedImageContainerdNamespace is the containerd namespace the CRI plugin
// (kubelet) uses; a CRI container ID is the containerd container ID there.
const sharedImageContainerdNamespace = "k8s.io"

// sharedImageContainerdSource resolves rootfs mounts from containerd. The
// snapshot key and snapshotter come from the containerd container record
// (containers.Container.SnapshotKey/Snapshotter), the authoritative source
// CRI itself uses; CRI ContainerStatus verbose info only echoes it as JSON.
// The mounts are the snapshotter's Mounts(key), not a parse of the live
// mount table, which Resolve cross-checks separately.
type sharedImageContainerdSource struct {
	client *containerd.Client
}

// newSharedImageContainerdSource connects to the containerd socket
// (e.g. /run/containerd/containerd.sock); namespace "" selects k8s.io.
func newSharedImageContainerdSource(address, namespace string) (*sharedImageContainerdSource, error) {
	if namespace == "" {
		namespace = sharedImageContainerdNamespace
	}
	client, err := containerd.New(address, containerd.WithDefaultNamespace(namespace))
	if err != nil {
		return nil, fmt.Errorf("containerd %s: %w", address, err)
	}
	return &sharedImageContainerdSource{client: client}, nil
}

func (s *sharedImageContainerdSource) RootfsMounts(ctx context.Context, containerID string) (sharedImageRootfs, error) {
	record, err := s.client.ContainerService().Get(ctx, containerID)
	if err != nil {
		return sharedImageRootfs{}, fmt.Errorf("containerd container %s: %w", containerID, err)
	}
	if record.Snapshotter == "" || record.SnapshotKey == "" {
		return sharedImageRootfs{}, fmt.Errorf("containerd container %s has no rootfs snapshot", containerID)
	}
	mounts, err := s.client.SnapshotService(record.Snapshotter).Mounts(ctx, record.SnapshotKey)
	if err != nil {
		return sharedImageRootfs{}, fmt.Errorf("snapshotter %s mounts %s: %w", record.Snapshotter, record.SnapshotKey, err)
	}
	out := sharedImageRootfs{Snapshotter: record.Snapshotter, Key: record.SnapshotKey}
	for _, m := range mounts {
		out.Mounts = append(out.Mounts, sharedImageMount{Type: m.Type, Source: m.Source, Options: append([]string(nil), m.Options...)})
	}
	return out, nil
}

func (s *sharedImageContainerdSource) Close() error { return s.client.Close() }
