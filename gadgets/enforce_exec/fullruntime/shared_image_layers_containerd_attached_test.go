// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestSharedImageLayersContainerdAttached resolves a live container's image
// layers against a real containerd (VM/EKS runs only). Run as root on the
// node with:
//
//	IG_SHARED_IMAGE_CONTAINERD=1
//	IG_SHARED_IMAGE_CONTAINER_ID=<CRI container ID>
//	IG_SHARED_IMAGE_INIT_PID=<host PID of the container init>
//	IG_SHARED_IMAGE_CONTAINERD_SOCKET (default /run/containerd/containerd.sock)
//	IG_SHARED_IMAGE_CONTAINERD_NAMESPACE (default k8s.io)
//	IG_SHARED_IMAGE_HOST_ROOT / IG_SHARED_IMAGE_PROC_ROOT (default / and /proc)
func TestSharedImageLayersContainerdAttached(t *testing.T) {
	if os.Getenv("IG_SHARED_IMAGE_CONTAINERD") != "1" {
		t.Skip("set IG_SHARED_IMAGE_CONTAINERD=1 to resolve layers against a real containerd")
	}
	id := os.Getenv("IG_SHARED_IMAGE_CONTAINER_ID")
	pid, err := strconv.ParseUint(os.Getenv("IG_SHARED_IMAGE_INIT_PID"), 10, 32)
	if id == "" || err != nil || pid == 0 {
		t.Fatal("IG_SHARED_IMAGE_CONTAINER_ID and IG_SHARED_IMAGE_INIT_PID required")
	}
	socket := os.Getenv("IG_SHARED_IMAGE_CONTAINERD_SOCKET")
	if socket == "" {
		socket = "/run/containerd/containerd.sock"
	}
	host := sharedImageProcHost{ProcRoot: os.Getenv("IG_SHARED_IMAGE_PROC_ROOT"), HostRoot: os.Getenv("IG_SHARED_IMAGE_HOST_ROOT")}
	procRoot := host.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	dir, err := os.Open(procRoot + "/" + strconv.FormatUint(pid, 10))
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	start, err := readPinnedInitStart(dir, uint32(pid))
	if err != nil {
		t.Fatal(err)
	}
	ticks, _ := strconv.ParseUint(start, 10, 64)
	var ns unix.Stat_t
	if err := unix.Fstatat(int(dir.Fd()), "ns/mnt", &ns, 0); err != nil {
		t.Fatal(err)
	}
	init := SharedInitIdentity{TGID: uint32(pid), StartTicks: ticks, MountNS: ns.Ino}

	source, err := newSharedImageContainerdSource(socket, os.Getenv("IG_SHARED_IMAGE_CONTAINERD_NAMESPACE"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	r, err := newSharedImageLayerResolver(source, host, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	layers, err := r.Resolve(ctx, id, init)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(layers)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Reattest(ctx, layers); err != nil {
		t.Fatal(err)
	}
	t.Logf("container %s snapshot %s/%s upper %s overlay dev %#x: %d lowers, %d keys %+v",
		id, layers.Snapshotter, layers.SnapshotKey, layers.UpperDir, layers.OverlayDev, len(layers.Lowers), layers.Expected, keys)
}
