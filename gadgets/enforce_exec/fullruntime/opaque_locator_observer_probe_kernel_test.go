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

// This probe is deliberately load-only. It answers whether the real verifier
// accepts the observer's split lookup/read/hold/relookup shape, not whether a
// writer, task lifecycle, policy authority or selected image is correct.
func TestOpaqueLocatorObserverProbeKernel(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_LOCATOR_OBSERVER_PROBE_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_LOCATOR_OBSERVER_PROBE_OBJECT to a compiled load-only probe")
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
	if m := spec.Maps["opaque_task_keys"]; m == nil || m.Type != ebpf.Hash ||
		m.KeySize != 8 || m.ValueSize != 8 || m.MaxEntries != 4 ||
		m.Flags != unix.BPF_F_WRONLY {
		t.Fatal("unexpected opaque-key observer map ABI")
	}
	if m := spec.Maps["opaque_task_meta"]; m == nil || m.Type != ebpf.Array ||
		m.KeySize != 4 || m.ValueSize != 128 || m.MaxEntries != 4 ||
		m.Flags != unix.BPF_F_WRONLY {
		t.Fatal("unexpected observer metadata map ABI")
	}
	for _, name := range []string{"opaque_locator_observer_alloc_probe", "opaque_locator_observer_free_probe"} {
		if p := spec.Programs[name]; p == nil || p.Type != ebpf.LSM {
			t.Fatalf("unexpected LSM probe %s", name)
		}
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("opaque locator observer verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	t.Log("opaque locator observer loaded without attachment")
}
