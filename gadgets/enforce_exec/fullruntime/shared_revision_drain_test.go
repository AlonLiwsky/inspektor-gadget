// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// TestSharedRevisionDrainLayoutMatchesBTF pins the offsets the revision
// drain reads a RETIRING record's readers at (sharedBindingRecordsOffset,
// sharedSnapshotBytes, sharedSnapshotClaimsOffset) to the BTF of struct
// se_shared_binding from an object compiled here from the same headers
// (full/shared_snapshot.h; the se_bindings map value of every verdict
// object), so a layout change on the BPF side fails here. The source
// declares the two helpers shared_snapshot.h calls instead of including
// libbpf's bpf/bpf_helpers.h, so it needs only clang (the unprivileged CI
// job has no libbpf headers); neither declaration affects the layout.
func TestSharedRevisionDrainLayoutMatchesBTF(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("clang unavailable")
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "binding_layout.bpf.c")
	if err := os.WriteFile(source, []byte(`#include "vmlinux.h"
#define SEC(name) __attribute__((section(name), used))
static long (*bpf_spin_lock)(struct bpf_spin_lock *lock) = (void *)BPF_FUNC_spin_lock;
static long (*bpf_spin_unlock)(struct bpf_spin_lock *lock) = (void *)BPF_FUNC_spin_unlock;
#include "shared_snapshot.h"
struct se_shared_binding se_layout_binding SEC(".data.layout");
char LICENSE[] SEC("license") = "GPL";
`), 0o600); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(dir, "binding_layout.o")
	if out, err := exec.CommandContext(t.Context(), clang, "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror",
		"-Wno-missing-declarations", "-Wno-unused-function",
		"-I", "../../../include/gadget/amd64", "-I", "../../../include", "-iquote", "../full", "-iquote", "../fullpolicy/bpf",
		"-c", source, "-o", object).CombinedOutput(); err != nil {
		t.Fatalf("compile binding layout object: %v\n%s", err, out)
	}
	spec, err := btf.LoadSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	member := func(name, field string) (btf.Member, *btf.Struct) {
		t.Helper()
		var s *btf.Struct
		if err := spec.TypeByName(name, &s); err != nil {
			t.Fatalf("struct %s: %v", name, err)
		}
		for _, m := range s.Members {
			if m.Name == field {
				return m, s
			}
		}
		t.Fatalf("struct %s has no member %s", name, field)
		return btf.Member{}, nil
	}
	state, _ := member("se_shared_binding", "state")
	records, _ := member("se_binding_snapshots", "records")
	recordsArray, ok := btf.UnderlyingType(records.Type).(*btf.Array)
	if !ok || recordsArray.Nelems != 2 {
		t.Fatalf("se_binding_snapshots.records is %v, want two struct se_snapshot", records.Type)
	}
	claims, snapshot := member("se_snapshot", "claims")
	if recordType, ok := btf.UnderlyingType(recordsArray.Type).(*btf.Struct); !ok || recordType.Name != "se_snapshot" {
		t.Fatalf("se_binding_snapshots.records element is %v, want struct se_snapshot", recordsArray.Type)
	}
	if size, err := btf.Sizeof(btf.UnderlyingType(claims.Type)); err != nil || size != 4 {
		t.Errorf("se_snapshot.claims is %d bytes (%v), want a __u32", size, err)
	}
	for name, pair := range map[string][2]int{
		"sharedBindingRecordsOffset": {int(state.Offset.Bytes() + records.Offset.Bytes()), sharedBindingRecordsOffset},
		"sharedSnapshotBytes":        {int(snapshot.Size), sharedSnapshotBytes},
		"sharedSnapshotClaimsOffset": {int(claims.Offset.Bytes()), sharedSnapshotClaimsOffset},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: BTF %d, Go %d", name, pair[0], pair[1])
		}
	}
}
