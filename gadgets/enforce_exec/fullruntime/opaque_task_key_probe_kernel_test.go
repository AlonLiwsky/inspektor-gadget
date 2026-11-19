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

// This opt-in probe loads actual LSM program types but attaches neither hook.
// Acceptance answers only the opaque-key/scalar-CAS verifier ABI question; it
// does not approve a HASH backing-reuse protocol or qualify G005.
func TestOpaqueTaskKeyProbeKernel(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_TASK_KEY_PROBE_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_TASK_KEY_PROBE_OBJECT to a compiled load-only probe")
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
		m.KeySize != 8 || m.ValueSize != 8 || m.MaxEntries != 2 ||
		m.Flags != unix.BPF_F_WRONLY {
		t.Fatal("unexpected opaque-key probe map ABI")
	}
	for _, name := range []string{"opaque_task_key_alloc_probe", "opaque_task_key_free_probe"} {
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
			t.Logf("opaque-key verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	probeMap := collection.Maps["opaque_task_keys"]
	// Only a synthetic key is inserted; no actual task pointer is exposed.
	const syntheticKey uint64 = 0x1234
	putErr := probeMap.Put(syntheticKey, uint64(0))
	var value, next uint64
	lookupErr := probeMap.Lookup(syntheticKey, &value)
	nextErr := probeMap.NextKey(nil, &next)
	t.Logf("userspace synthetic-key put=%v lookup=%v next-key=%v next=%#x", putErr, lookupErr, nextErr, next)
	t.Log("typed LSM opaque-key helper probe loaded without attachment")
}
