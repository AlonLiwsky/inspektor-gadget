// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// TestProgramSlotKernel proves native frozen map-in-map publication only. It
// attaches no hooks, does not grant lineage, and does not prove exec admission.
func TestProgramSlotKernel(t *testing.T) {
	if os.Getenv("IG_EXEC_PROGRAM_SLOT_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable-kernel opt-in required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	slots, err := ebpf.NewMap(ProgramSlotsSpec())
	if err != nil {
		t.Fatal(err)
	}
	defer slots.Close()
	epochs, err := ebpf.NewMap(AcceptedEpochsSpec())
	if err != nil {
		t.Fatal(err)
	}
	defer epochs.Close()
	g, _ := testGate(t)
	owner, err := NewProgramSlot(g, slots, epochs)
	if err != nil {
		t.Fatal(err)
	}
	// Calls below are synchronous test_run with no attached hooks. Destruction is
	// deliberately ordered like confirmed native detach, not a live drain shortcut.
	tmp := t.TempDir()
	btf, err := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c").Output()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(tmp, "vmlinux.h"), btf, 0o600); err != nil {
		t.Fatal(err)
	}
	source := os.Getenv("IG_EXEC_PROGRAM_SLOT_BPF_SOURCE")
	if source == "" {
		source = "bpf/program_slot_test.bpf.c"
	}
	object := filepath.Join(tmp, "slot.bpf.o")
	if out, err := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-I"+tmp, "-c", source, "-o", object).CombinedOutput(); err != nil {
		t.Fatalf("compile:%v %s", err, out)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := spec.Copy()
	delete(spec.Programs, "forbidden_delete")
	for name := range forbidden.Programs {
		if name != "forbidden_delete" {
			delete(forbidden.Programs, name)
		}
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{"programs": slots}})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("%+v", verifier)
		}
		t.Fatal(err)
	}
	defer func() {
		collection.Close()
		if err := owner.CloseAfterDetach(); err != nil {
			t.Error(err)
		}
	}()
	// Read probes proved the same map ABI loads. Only the forbidden helper
	// differs, so require an actual verifier rejection, not a map-creation error.
	bad, rejected := ebpf.NewCollectionWithOptions(forbidden, ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{"programs": slots}})
	if bad != nil {
		bad.Close()
	}
	var verifier *ebpf.VerifierError
	if !errors.As(rejected, &verifier) || !strings.Contains(fmt.Sprintf("%+v", verifier), "map_delete_elem") {
		t.Fatalf("outer deletion not rejected by verifier: %v", rejected)
	}
	probe := func(name string, want uint32) {
		t.Helper()
		got, err := collection.Programs[name].Run(&ebpf.RunOptions{Data: make([]byte, 64)})
		if err != nil || got != want {
			t.Fatalf("%s generation=%d err=%v want=%d", name, got, err, want)
		}
	}
	probe("ps_active", 0)
	probe("ps_staging", 0)
	first := slotProgram(t, owner, 1, "uid-a")
	update, err := owner.Begin(t.Context(), first)
	if err != nil {
		t.Fatal(err)
	}
	image, err := update.Map()
	if err != nil {
		t.Fatal(err)
	}
	if err = image.Put(uint32(0), first.Entries[0]); !errors.Is(err, unix.EPERM) {
		t.Fatalf("frozen map mutation=%v", err)
	}
	probe("ps_active", 0)
	probe("ps_staging", 1)
	result, err := update.Commit()
	if err != nil || !result.Committed {
		t.Fatal(result, err)
	}
	requireState(t, g, true, 0)
	probe("ps_active", 1)
	probe("ps_staging", 1)
	row, _ := fullpolicy.Decode[fullpolicy.KernelPolicy](first.Entries[fullpolicy.KernelPolicyBase])
	var epoch uint64
	if err = epochs.Lookup(row.UID, &epoch); err != nil || epoch != 1 {
		t.Fatal("successful epoch missing", epoch, err)
	}
	if err = update.Finish(); err != nil {
		t.Fatal(err)
	}
	probe("ps_active", 1)
	probe("ps_staging", 0)
	second := slotProgram(t, owner, 2, "uid-b")
	failed, err := owner.Begin(t.Context(), second)
	if err != nil {
		t.Fatal(err)
	}
	probe("ps_active", 1)
	probe("ps_staging", 2)
	if err = failed.Abort(); err != nil {
		t.Fatal(err)
	}
	probe("ps_active", 1)
	probe("ps_staging", 0)
	if owner.Epochs()["uid-b"] != 0 {
		t.Fatal("failed staging established UID")
	}
	third := slotProgram(t, owner, 3, "uid-b")
	next, err := owner.Begin(t.Context(), third)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := next.Commit(); err != nil || !r.Committed {
		t.Fatal(r, err)
	}
	if err = next.Finish(); err != nil {
		t.Fatal(err)
	}
	probe("ps_active", 3)
	probe("ps_staging", 0)
	if _, err = image.Info(); err == nil {
		t.Fatal("retired owned FD remains open")
	}
	if owner.Epochs()["uid-a"] != 1 || owner.Epochs()["uid-b"] != 3 {
		t.Fatal("success catalogue changed")
	}
	t.Log("readonly frozen inner ABI, staging/commit/abort and successful epoch retention proved; no hooks attached")
}
