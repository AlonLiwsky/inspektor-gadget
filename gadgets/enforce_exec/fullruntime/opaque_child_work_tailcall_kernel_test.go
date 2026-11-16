// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Loads both diagnostic task_alloc stages into one collection and freezes the
// exact target edge. It never arms a gate or attaches a hook: loading is not
// evidence that charged WORK handoff, fallback, or child birth runs correctly.
func TestOpaqueChildWorkTailcallPairKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_CHILD_WORK_TAILCALL_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_CHILD_WORK_TAILCALL_OBJECT for paired verifier load")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required for BPF verifier load")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	const sourceName = "opaque_lifecycle_child_work_handoff_probe"
	const targetName = "opaque_lifecycle_child_work_target_probe"
	source, target := spec.Programs[sourceName], spec.Programs[targetName]
	if source == nil || target == nil || source.Type != ebpf.LSM || target.Type != ebpf.LSM ||
		source.AttachTo != "task_alloc" || target.AttachTo != "task_alloc" {
		t.Fatal("diagnostic pair must contain two task_alloc LSM programs")
	}
	gate := spec.Maps["opaque_lifecycle_gate"]
	targets := spec.Maps["opaque_lifecycle_child_work_targets"]
	if gate == nil || gate.Type != ebpf.Array || gate.MaxEntries != 1 ||
		gate.Flags != unix.BPF_F_RDONLY_PROG || targets == nil ||
		targets.Type != ebpf.ProgramArray || targets.MaxEntries != 1 {
		t.Fatal("diagnostic pair requires a default-zero frozen gate and one target slot")
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{sourceName: source, targetName: target}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("paired task_alloc verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	var unarmed [24]byte
	if err := collection.Maps["opaque_lifecycle_gate"].Lookup(uint32(0), &unarmed); err != nil ||
		unarmed != ([24]byte{}) {
		t.Fatalf("diagnostic pair gate must be unarmed: %x %v", unarmed, err)
	}
	targetProgram := collection.Programs[targetName]
	info, err := targetProgram.Info()
	if err != nil {
		t.Fatal(err)
	}
	targetID, ok := info.ID()
	if !ok {
		t.Fatal("target has no kernel program ID")
	}
	if err := collection.Maps["opaque_lifecycle_child_work_targets"].Update(
		uint32(0), targetProgram, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["opaque_lifecycle_child_work_targets"].Freeze(); err != nil {
		t.Fatal(err)
	}
	var linkedID uint32
	if err := collection.Maps["opaque_lifecycle_child_work_targets"].Lookup(
		uint32(0), &linkedID); err != nil || linkedID != uint32(targetID) {
		t.Fatalf("wrong frozen target ID: got=%d want=%d err=%v", linkedID, targetID, err)
	}
	t.Log("paired task_alloc programs loaded with frozen target and unarmed gate; no attachment")
}
