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

// This opt-in load-only fixture tests one verifier primitive. It does not
// approve pointer archival, userspace read restrictions or a product locator.
func TestOpaqueTaskArchiveProbeKernel(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_TASK_ARCHIVE_PROBE_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_TASK_ARCHIVE_PROBE_OBJECT to a compiled load-only probe")
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
	if m := spec.Maps["opaque_task_archive"]; m == nil || m.Type != ebpf.Array ||
		m.KeySize != 4 || m.ValueSize != 8 || m.MaxEntries != 1 ||
		m.Flags != unix.BPF_F_WRONLY {
		t.Fatal("unexpected archive probe map ABI")
	}
	if p := spec.Programs["opaque_task_archive_alloc_probe"]; p == nil || p.Type != ebpf.LSM {
		t.Fatal("unexpected archive LSM probe")
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("opaque archive verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	var archived uint64
	lookupErr := collection.Maps["opaque_task_archive"].Lookup(uint32(0), &archived)
	t.Logf("userspace archive lookup: %v", lookupErr)
	if lookupErr == nil {
		t.Fatal("opaque archive map allowed userspace read")
	}
	t.Log("typed LSM opaque archive helper probe loaded without attachment")
}
