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

// This is a load-only composition premise, not an enforcement test. The TC
// probe has no TASK/WORK callbacks and must never be attached as the product.
func TestOpaqueRealRouteAdmissionProbeKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_REAL_ROUTE_PROBE_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_REAL_ROUTE_PROBE_OBJECT to a compiled probe")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	probe := spec.Programs["opaque_real_route_admission_probe"]
	if probe == nil || probe.Type != ebpf.SchedCLS {
		t.Fatal("missing default-inert real-route TC probe")
	}
	finalFree := spec.Programs["opaque_real_route_final_free_probe"]
	if finalFree == nil || finalFree.Type != ebpf.LSM || finalFree.AttachTo != "task_free" {
		t.Fatalf("missing load-only real-map task_free seam: %+v", finalFree)
	}
	gate := spec.Maps["opaque_real_route_probe_gate"]
	if gate == nil || gate.Type != ebpf.Array || gate.KeySize != 4 ||
		gate.ValueSize != 4 || gate.MaxEntries != 1 ||
		gate.Flags != unix.BPF_F_RDONLY_PROG {
		t.Fatalf("invalid default-inert probe gate: %+v", gate)
	}
	for name, want := range map[string]struct {
		typ                    ebpf.MapType
		key, value, max, flags uint32
	}{
		"se_route_index": {ebpf.Hash, 8, 8, 2, unix.BPF_F_RDONLY},
		"se_routes":      {ebpf.Array, 4, 88, 2, unix.BPF_F_RDONLY},
		"se_bindings":    {ebpf.Array, 4, 1632, 2, unix.BPF_F_RDONLY},
		"se_epoch_index": {ebpf.Hash, 16, 4, 32, unix.BPF_F_RDONLY},
		"se_epoch_bank":  {ebpf.Array, 4, 32, 32, unix.BPF_F_RDONLY},
	} {
		m := spec.Maps[name]
		if m == nil || m.Type != want.typ || m.KeySize != want.key ||
			m.ValueSize != want.value || m.MaxEntries != want.max ||
			m.Flags != want.flags {
			t.Fatalf("real control map %s differs from expected ABI: %+v", name, m)
		}
	}
	profile := sharedTestProfile()
	profile.Tasks, profile.PerBinding.Tasks = 128, 64
	profile.Scratch, profile.PerBinding.Scratch = 32, 16
	wantOwner, _, err := sharedOpaqueOwnerGeometry(profile)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range wantOwner {
		m := spec.Maps[name]
		if m == nil || uint32(m.Type) != want.Type ||
			m.KeySize != want.KeySize || m.ValueSize != want.ValueSize ||
			m.MaxEntries != want.MaxEntries || m.Flags != want.Flags {
			t.Fatalf("opaque owner map %s differs from shared profile: %+v", name, m)
		}
	}
	for _, name := range []string{
		"se_tasks", "se_invocations",
		"se_pool_task_meta", "se_pool_task_payload",
		"writer_probe_route", "writer_probe_snapshots",
		"opaque_lifecycle_gate", "opaque_lifecycle_policy_object",
	} {
		if spec.Maps[name] != nil {
			t.Fatalf("real-route diagnostic includes legacy or synthetic map %s", name)
		}
	}
	if len(spec.Maps) != 29 {
		t.Fatalf("expected 14 opaque maps, 14 real control maps and one gate; got %d", len(spec.Maps))
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for load-only verifier check")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{
		"opaque_real_route_admission_probe":  probe,
		"opaque_real_route_final_free_probe": finalFree,
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("real-route admission verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	var armed uint32
	if err := collection.Maps["opaque_real_route_probe_gate"].Lookup(uint32(0), &armed); err != nil || armed != 0 {
		t.Fatalf("real-route probe must load unarmed: armed=%d err=%v", armed, err)
	}
	t.Log("real-route/opaque owner cohort loaded; no hook attached")
}
