// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"fmt"
	"strings"
	"testing"
)

func TestRoleEpochsRetainSuccessfulUIDsOnly(t *testing.T) {
	// Reverse lexical order catches accidental association with input ordering.
	policies := []Policy{{ID: "z-retained", Revision: "new", Mode: Enforce, RootRole: "changed-root"}, {ID: "a-new", Revision: "new", Mode: Enforce, RootRole: "new-root"}}
	p, err := CompileKernelWithRoleEpochs(policies, 9, "app", map[string]uint64{"z-retained": 2, "temporarily-absent": 3})
	if err != nil {
		t.Fatal(err)
	}
	for i := range policies {
		entry, err := Decode[KernelPolicy](p.Entries[KernelPolicyBase+i])
		if err != nil {
			t.Fatal(err)
		}
		want := uint64(9)
		if p.Identities[entry.UID] == "z-retained" {
			want = 2
		}
		if entry.RootEpoch != want {
			t.Fatalf("UID%s epoch%d want%d", p.Identities[entry.UID], entry.RootEpoch, want)
		}
	}
	// A failed candidate must not enter the SUCCESSFUL catalogue: retry uses its
	// new epoch/root, so any previously staged slot has a mismatched epoch.
	retry, err := CompileKernelWithRoleEpochs([]Policy{{ID: "a-new", Revision: "retry", Mode: Enforce, RootRole: "retry-root"}}, 10, "app", map[string]uint64{"z-retained": 2})
	if err != nil {
		t.Fatal(err)
	}
	entry, err := Decode[KernelPolicy](retry.Entries[KernelPolicyBase])
	if err != nil {
		t.Fatal(err)
	}
	if entry.RootEpoch != 10 || retry.Identities[entry.RootRole] != "retry-root" {
		t.Fatal("failed attempt established root")
	}
}

func TestRoleEpochValidation(t *testing.T) {
	policies := []Policy{{ID: "uid", Revision: "revision", Mode: Enforce}}
	for _, bad := range []uint64{0, 11, UnknownRoleEpoch} {
		if p, err := CompileKernelWithRoleEpochs(policies, 10, "app", map[string]uint64{"absent": bad}); err == nil || p != nil {
			t.Fatal("invalid epoch accepted")
		}
	}
	for _, bad := range []uint64{0, 11, UnknownRoleEpoch} {
		p, err := CompileKernel(policies, 10, "app")
		if err != nil {
			t.Fatal(err)
		}
		entry, err := Decode[KernelPolicy](p.Entries[KernelPolicyBase])
		if err != nil {
			t.Fatal(err)
		}
		entry.RootEpoch = bad
		p.Entries[KernelPolicyBase], err = encode(entry)
		if err != nil {
			t.Fatal(err)
		}
		if ValidateKernelProgram(p) == nil {
			t.Fatal("forged epoch accepted")
		}
	}
}

func TestRoleEpochHistoryBounds(t *testing.T) {
	policies := []Policy{{ID: "uid", Revision: "revision", Mode: Enforce}}
	for _, id := range []string{"", strings.Repeat("x", 256), string([]byte{0xff})} {
		if p, err := CompileKernelWithRoleEpochs(policies, 1, "app", map[string]uint64{id: 1}); err == nil || p != nil {
			t.Fatal("invalid historical UID accepted")
		}
	}
	oversized := make(map[string]uint64, MaxRoleEpochHistory+1)
	for i := 0; i <= MaxRoleEpochHistory; i++ {
		oversized[fmt.Sprint(i)] = 1
	}
	if p, err := CompileKernelWithRoleEpochs(policies, 1, "app", oversized); err == nil || p != nil {
		t.Fatal("oversized history accepted")
	}
}

func TestUnknownRoleEpochCannotBecomeGeneration(t *testing.T) {
	policies := []Policy{{ID: "uid", Revision: "revision", Mode: Enforce}}
	if p, err := CompileKernel(policies, UnknownRoleEpoch, "app"); err == nil || p != nil {
		t.Fatal("reserved epoch compiled")
	}
	p, err := CompileKernel(policies, 1, "app")
	if err != nil {
		t.Fatal(err)
	}
	h, err := Decode[KernelHeader](p.Entries[0])
	if err != nil {
		t.Fatal(err)
	}
	h.Generation = UnknownRoleEpoch
	p.Entries[0], err = encode(h)
	if err != nil {
		t.Fatal(err)
	}
	if ValidateKernelProgram(p) == nil {
		t.Fatal("forged reserved generation accepted")
	}
}
