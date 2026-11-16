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

// Isolated ABI premise only: the supplied candidate ELF is loaded but never
// attached or TEST_RUN. This does not qualify the selected lifecycle image.
func TestSharedPoolABIMapIntegrityKernel(t *testing.T) {
	object := os.Getenv("IG_SHARED_POOL_ABI_OBJECT")
	if object == "" {
		t.Skip("set IG_SHARED_POOL_ABI_OBJECT to a compiled isolated candidate")
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
	profile := sharedTestProfile()
	profile.Tasks, profile.Scratch = 16384, 256
	profile.PerBinding.Tasks, profile.PerBinding.Scratch = 8192, 128
	want, _, err := sharedPoolGeometry(profile)
	if err != nil {
		t.Fatal(err)
	}
	for name, shape := range want {
		m := spec.Maps[name]
		if m == nil || uint32(m.Type) != shape.Type || m.KeySize != shape.KeySize ||
			m.ValueSize != shape.ValueSize || m.MaxEntries != shape.MaxEntries ||
			m.Flags != shape.Flags {
			t.Fatalf("candidate pool map %s differs from reviewed source geometry", name)
		}
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("candidate pool verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	if err := freezeSharedPoolZeroTemplates(map[string]sharedZeroTemplateMap{
		"se_pool_task_zero": collection.Maps["se_pool_task_zero"],
		"se_pool_work_zero": collection.Maps["se_pool_work_zero"],
	}); err != nil {
		t.Fatal(err)
	}
	for name, size := range map[string]int{
		"se_pool_task_payload": 1280,
		"se_pool_reap_receipt": 128,
	} {
		if err := collection.Maps[name].Update(uint32(0), make([]byte, size), ebpf.UpdateAny); err == nil {
			t.Fatalf("userspace-readonly candidate map %s accepted update", name)
		}
	}
	if err := collection.Maps["se_pool_task_zero"].Update(uint32(0), make([]byte, 1280), ebpf.UpdateAny); err == nil {
		t.Fatal("frozen candidate TASK zero template accepted update")
	}
	if spec.Maps["se_pool_task_meta"].Flags != unix.BPF_F_RDONLY {
		t.Fatal("spinlock-bearing TASK metadata lacks UAPI read-only flag")
	}
	t.Logf("loaded %d candidate programs and %d maps; templates frozen, UAPI updates refused, no attachment", len(collection.Programs), len(collection.Maps))
}
