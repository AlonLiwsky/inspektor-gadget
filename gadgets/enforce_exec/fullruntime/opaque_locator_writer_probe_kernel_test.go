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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// This opt-in test checks the compiled owner manifest, then loads but never
// attaches a synthetic writer/reaper object unless inventory-only is set.
// Its default-zero probe gate is not armed. Verifier acceptance cannot prove
// charge ownership, real task_free, callbacks, races, or product admission.
func TestOpaqueLocatorWriterProbeKernel(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_LOCATOR_WRITER_PROBE_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_LOCATOR_WRITER_PROBE_OBJECT to a compiled load-only probe")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]struct {
		typ                    ebpf.MapType
		key, value, max, flags uint32
	}{
		"se_opaque_keys":          {ebpf.Hash, 8, 8, 128, unix.BPF_F_RDONLY},
		"se_opaque_archive":       {ebpf.Array, 4, 8, 128, unix.BPF_F_RDONLY},
		"se_opaque_meta":          {ebpf.Array, 4, 128, 128, unix.BPF_F_RDONLY},
		"se_opaque_payload":       {ebpf.Array, 4, 1280, 128, unix.BPF_F_RDONLY},
		"se_opaque_payload_zero":  {ebpf.Array, 4, 1280, 1, unix.BPF_F_RDONLY_PROG},
		"se_opaque_accounts":      {ebpf.Array, 4, 40, 2, unix.BPF_F_RDONLY},
		"se_opaque_charges":       {ebpf.Array, 4, 40, 128, unix.BPF_F_RDONLY},
		"se_opaque_sequence":      {ebpf.Array, 4, 16, 1, unix.BPF_F_RDONLY},
		"writer_probe_route":      {ebpf.Array, 4, 88, 2, unix.BPF_F_RDONLY},
		"writer_probe_snapshots":  {ebpf.Array, 4, 1632, 2, unix.BPF_F_RDONLY},
		"writer_probe_gate":       {ebpf.Array, 4, 4, 1, unix.BPF_F_RDONLY_PROG},
		"se_opaque_work_accounts": {ebpf.Array, 4, 40, 2, unix.BPF_F_RDONLY},
		"se_opaque_work_charges":  {ebpf.Array, 4, 56, 64, unix.BPF_F_RDONLY},
		"se_opaque_work_sequence": {ebpf.Array, 4, 16, 1, unix.BPF_F_RDONLY},
		"se_opaque_work_meta":     {ebpf.Array, 4, 80, 64, unix.BPF_F_RDONLY},
		"se_opaque_work_payload":  {ebpf.Array, 4, 19456, 64, unix.BPF_F_RDONLY},
		"se_opaque_work_zero":     {ebpf.Array, 4, 19456, 1, unix.BPF_F_RDONLY_PROG},
	} {
		m := spec.Maps[name]
		if m == nil || m.Type != want.typ || m.KeySize != want.key ||
			m.ValueSize != want.value || m.MaxEntries != want.max ||
			m.Flags != want.flags {
			t.Fatalf("unexpected writer probe map %s ABI", name)
		}
	}
	// This ABI is a replacement TASK owner, not a bridge beside the legacy
	// address-keyed TASK or the abandoned address-mixer pool maps.
	for _, old := range []string{
		"se_tasks", "se_pool_task_meta",
		"se_pool_task_payload", "se_pool_directory",
	} {
		if spec.Maps[old] != nil {
			t.Fatalf("opaque TASK candidate unexpectedly contains %s", old)
		}
	}
	if len(spec.Maps) != 17 {
		t.Fatalf("opaque TASK/WORK candidate must have fourteen owner maps and three fixture maps, got %d maps", len(spec.Maps))
	}
	profile := sharedTestProfile()
	profile.Tasks, profile.PerBinding.Tasks = 128, 64
	profile.Scratch, profile.PerBinding.Scratch = 64, 32
	wantOwner, wantUsage, err := sharedOpaqueOwnerGeometry(profile)
	if err != nil {
		t.Fatal(err)
	}
	ownerMaps := make(map[string]operators.NativeMapResource, len(wantOwner))
	for name, want := range wantOwner {
		got := spec.Maps[name]
		if got == nil || uint32(got.Type) != want.Type ||
			got.KeySize != want.KeySize || got.ValueSize != want.ValueSize ||
			got.MaxEntries != want.MaxEntries || got.Flags != want.Flags {
			t.Fatalf("compiled opaque owner map %s differs from native resource geometry", name)
		}
		ownerMaps[name] = operators.NativeMapResource{
			Type: uint32(got.Type), KeySize: got.KeySize,
			ValueSize: got.ValueSize, MaxEntries: got.MaxEntries,
			Flags: got.Flags,
		}
	}
	if usage, err := validateSharedOpaqueOwnerResources(profile,
		&operators.NativeResources{Maps: ownerMaps}); err != nil || usage != wantUsage {
		t.Fatalf("compiled owner cohort rejected: usage=%+v err=%v", usage, err)
	}
	if p := spec.Programs["opaque_locator_writer_alloc_probe"]; p == nil || p.Type != ebpf.LSM {
		t.Fatal("unexpected writer alloc LSM probe")
	}
	if p := spec.Programs["opaque_locator_replace_alloc_probe"]; p == nil || p.Type != ebpf.LSM {
		t.Fatal("unexpected replacement alloc LSM probe")
	}
	if p := spec.Programs["opaque_locator_final_free_probe"]; p == nil || p.Type != ebpf.LSM {
		t.Fatal("unexpected typed final-free LSM probe")
	}
	if p := spec.Programs["opaque_locator_charge_alloc_probe"]; p == nil || p.Type != ebpf.LSM {
		t.Fatal("unexpected charged constructor LSM probe")
	}
	if p := spec.Programs["opaque_locator_route_claim_probe"]; p == nil || p.Type != ebpf.LSM {
		t.Fatal("unexpected route/opaque composition LSM probe")
	}
	if p := spec.Programs["opaque_locator_route_recycle_probe"]; p == nil || p.Type != ebpf.SchedCLS {
		t.Fatal("unexpected account-authoritative route recycle TC probe")
	}
	if p := spec.Programs["opaque_locator_payload_handle_probe"]; p == nil || p.Type != ebpf.LSM {
		t.Fatal("unexpected lexical payload-handle LSM probe")
	}
	if p := spec.Programs["opaque_locator_work_credit_probe"]; p == nil || p.Type != ebpf.LSM {
		t.Fatal("unexpected opaque WORK credit LSM probe")
	}
	if p := spec.Programs["opaque_locator_writer_reaper_probe"]; p == nil || p.Type != ebpf.SchedCLS {
		t.Fatal("unexpected writer reaper TC probe")
	}
	if p := spec.Programs["opaque_locator_refund_probe"]; p == nil || p.Type != ebpf.SchedCLS {
		t.Fatal("unexpected refund TC probe")
	}
	if p := spec.Programs["opaque_locator_payload_zero_probe"]; p == nil || p.Type != ebpf.SchedCLS {
		t.Fatal("unexpected payload-zero TC probe")
	}
	if p := spec.Programs["opaque_locator_work_reap_probe"]; p == nil || p.Type != ebpf.SchedCLS {
		t.Fatal("unexpected opaque WORK reaper TC probe")
	}
	if os.Getenv("IG_OPAQUE_LOCATOR_WRITER_PROBE_INVENTORY_ONLY") == "1" {
		t.Log("compiled TASK/WORK owner manifest matches host contract; no kernel load")
		return
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required for BPF verifier load")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	programOnly := os.Getenv("IG_OPAQUE_LOCATOR_WRITER_PROBE_PROGRAM_ONLY")
	if programOnly != "" {
		program := spec.Programs[programOnly]
		if program == nil {
			t.Fatalf("missing selected diagnostic program %s", programOnly)
		}
		spec.Programs = map[string]*ebpf.ProgramSpec{programOnly: program}
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("opaque locator writer verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	if programOnly != "" {
		t.Logf("single diagnostic program %s loaded without attachment", programOnly)
		return
	}
	// Spinlock-bearing maps cannot be frozen on the tested kernel. Their
	// BPF_F_RDONLY source flag is the UAPI write barrier. Freeze only the
	// helper source and default-zero gate, before inspecting or attaching.
	for _, name := range []string{
		"se_opaque_payload_zero", "writer_probe_gate", "se_opaque_work_zero",
	} {
		if err := collection.Maps[name].Freeze(); err != nil {
			t.Fatalf("freeze candidate map %s: %v", name, err)
		}
	}
	var armed uint32
	if err := collection.Maps["writer_probe_gate"].Lookup(uint32(0), &armed); err != nil || armed != 0 {
		t.Fatalf("never-attached probe gate must remain zero: armed=%d err=%v", armed, err)
	}
	var empty [1280]byte
	if err := collection.Maps["se_opaque_payload_zero"].Lookup(uint32(0), &empty); err != nil || empty != ([1280]byte{}) {
		t.Fatalf("candidate payload zero template must be all zero: err=%v", err)
	}
	if err := collection.Maps["writer_probe_gate"].Update(uint32(0), uint32(1), ebpf.UpdateAny); err == nil {
		t.Fatal("frozen candidate gate accepted userspace arming")
	}
	if err := collection.Maps["se_opaque_payload_zero"].Update(uint32(0), [1280]byte{}, ebpf.UpdateAny); err == nil {
		t.Fatal("frozen candidate zero template accepted userspace update")
	}
	var emptyWork [19456]byte
	if err := collection.Maps["se_opaque_work_zero"].Lookup(uint32(0), &emptyWork); err != nil || emptyWork != ([19456]byte{}) {
		t.Fatalf("candidate WORK zero template must be all zero: err=%v", err)
	}
	if err := collection.Maps["se_opaque_work_zero"].Update(uint32(0), emptyWork, ebpf.UpdateAny); err == nil {
		t.Fatal("frozen WORK zero template accepted userspace update")
	}
	for name, size := range map[string]int{
		"se_opaque_archive":       8,
		"se_opaque_meta":          128,
		"se_opaque_payload":       1280,
		"se_opaque_accounts":      40,
		"se_opaque_charges":       40,
		"se_opaque_sequence":      16,
		"writer_probe_route":      88,
		"writer_probe_snapshots":  1632,
		"se_opaque_work_accounts": 40,
		"se_opaque_work_charges":  56,
		"se_opaque_work_sequence": 16,
		"se_opaque_work_meta":     80,
		"se_opaque_work_payload":  19456,
	} {
		if err := collection.Maps[name].Update(uint32(0), make([]byte, size), ebpf.UpdateAny); err == nil {
			t.Fatalf("userspace-readonly candidate map %s accepted update", name)
		}
	}
	if err := collection.Maps["se_opaque_keys"].Update(uint64(0xabc), uint64(1), ebpf.UpdateNoExist); err == nil {
		t.Fatal("userspace-readonly candidate locator HASH accepted insert")
	}
	t.Log("opaque locator writer loaded, gate zero, no attachment")
}
