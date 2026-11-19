// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"encoding/binary"
	"os"
	"os/exec"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// This opt-in probe observes the actual successful-fork tracepoint only. It
// neither qualifies the child nor establishes a product enforcement backend.
func TestOpaqueSuccessfulBirthIdentityLive(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_SUCCESSFUL_BIRTH_IDENTITY_OBJECT")
	if object == "" {
		t.Skip("set the isolated successful-birth identity BPF object")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		t.Fatal("requires root on Linux/amd64")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer collection.Close()
	var seed [40]byte
	binary.LittleEndian.PutUint32(seed[:4], uint32(os.Getpid()))
	if err := collection.Maps["birth_identity_observation"].Update(uint32(0), seed, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	attached, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: "sched_process_fork", Program: collection.Programs["observe_successful_fork"],
	})
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	child := exec.Command("/bin/true")
	if err := child.Run(); err != nil {
		t.Fatal(err)
	}
	raw, err := collection.Maps["birth_identity_observation"].LookupBytes(uint32(0))
	if err != nil || len(raw) != 40 {
		t.Fatalf("observation: raw=%x err=%v", raw, err)
	}
	parent := binary.LittleEndian.Uint64(raw[8:16])
	born := binary.LittleEndian.Uint64(raw[16:24])
	current := binary.LittleEndian.Uint64(raw[24:32])
	pid := binary.LittleEndian.Uint32(raw[32:36])
	if binary.LittleEndian.Uint32(raw[:4]) != uint32(os.Getpid()) ||
		binary.LittleEndian.Uint32(raw[4:8]) != 1 ||
		parent == 0 || born == 0 || born == parent || parent != current ||
		pid != uint32(child.Process.Pid) {
		t.Fatalf("fork identity mismatch: parent=%#x child=%#x current=%#x pid=%d want=%d raw=%x",
			parent, born, current, pid, child.Process.Pid, raw)
	}
	t.Logf("post-success fork identity: parent=current=%#x child=%#x child_pid=%d", parent, born, pid)
}
