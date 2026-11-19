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

// This deliberately bypasses native publication and seeds only an isolated
// Audit parent for later attached lifecycle diagnostics. Loading it disarmed
// proves neither callback execution nor product authority.
func TestOpaqueRealOwnerLiveBootstrapKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_REAL_LIVE_BOOTSTRAP_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_REAL_LIVE_BOOTSTRAP_OBJECT to the diagnostic object")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	gate := spec.Maps["opaque_real_live_bootstrap_gate"]
	if gate == nil || gate.Type != ebpf.Array || gate.KeySize != 4 ||
		gate.ValueSize != 24 || gate.MaxEntries != 1 ||
		gate.Flags != unix.BPF_F_RDONLY_PROG {
		t.Fatalf("invalid default-inert bootstrap gate: %+v", gate)
	}
	want := map[string]ebpf.ProgramType{
		"opaque_real_live_bootstrap_control": ebpf.SchedCLS,
		"opaque_real_live_bootstrap_birth":   ebpf.LSM,
		"opaque_real_live_bootstrap_qualify": ebpf.LSM,
		"opaque_real_live_reap_work":         ebpf.SchedCLS,
		"opaque_real_live_reap_task":         ebpf.SchedCLS,
	}
	selected := make(map[string]*ebpf.ProgramSpec, len(want))
	for name, kind := range want {
		p := spec.Programs[name]
		if p == nil || p.Type != kind {
			t.Fatalf("missing typed diagnostic %s: %+v", name, p)
		}
		selected[name] = p
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for disarmed verifier load")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec.Programs = selected
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("real-map bootstrap verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	var armed [24]byte
	if err := collection.Maps["opaque_real_live_bootstrap_gate"].Lookup(uint32(0), &armed); err != nil ||
		armed != ([24]byte{}) {
		t.Fatalf("bootstrap loaded armed: %x %v", armed, err)
	}
	if _, _, err := collection.Programs["opaque_real_live_bootstrap_control"].Test(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := collection.Programs["opaque_real_live_reap_work"].Test(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := collection.Programs["opaque_real_live_reap_task"].Test(make([]byte, 64)); err != nil {
		t.Fatal(err)
	}
	var key uint64
	if err := collection.Maps["se_route_index"].NextKey(nil, &key); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("disarmed bootstrap published route: key=%d err=%v", key, err)
	}
}
