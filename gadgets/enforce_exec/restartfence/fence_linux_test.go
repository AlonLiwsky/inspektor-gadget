// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package restartfence

import (
	"encoding/binary"
	"os"
	"testing"
)

func TestSharedPodRowABI(t *testing.T) {
	var b binding
	if got := binary.Size(b); got != 32 {
		t.Fatalf("fence pod row size = %d, want 32", got)
	}
	b = binding{
		Owner: 0x12344321, PodUIDHash: 0x01020304,
		StrictSections: 1, AuditSections: 2, BoundSections: 4, Reserved: 8,
	}
	got, err := binary.Append(nil, binary.LittleEndian, b)
	if err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint64(got[:8]) != b.Owner ||
		binary.LittleEndian.Uint64(got[8:16]) != b.PodUIDHash ||
		binary.LittleEndian.Uint32(got[16:20]) != b.StrictSections ||
		binary.LittleEndian.Uint32(got[20:24]) != b.AuditSections ||
		binary.LittleEndian.Uint32(got[24:28]) != b.BoundSections ||
		binary.LittleEndian.Uint32(got[28:]) != b.Reserved {
		t.Fatalf("fence pod row does not match ABI: %x", got)
	}
}

func TestMarkAndMoveRowValidation(t *testing.T) {
	for _, tt := range []struct {
		name string
		row  binding
		want bool
	}{
		{"strict mark has no owner", binding{PodUIDHash: 1, StrictSections: 1}, true},
		{"audit mark has no owner", binding{PodUIDHash: 1, AuditSections: 1}, true},
		{"bound exec", binding{PodUIDHash: 1, StrictSections: 1, Owner: 9, BoundSections: 1}, true},
		{"invalid mode overlap", binding{PodUIDHash: 1, StrictSections: 1, AuditSections: 1}, false},
		{"refuse overwriting a future shared row", binding{PodUIDHash: 1, StrictSections: 3}, false},
		{"refuse removing nonexec mark", binding{PodUIDHash: 1, AuditSections: 2}, false},
		{"owner without attested handover", binding{PodUIDHash: 1, StrictSections: 1, Owner: 9}, false},
		{"handover without owner", binding{PodUIDHash: 1, StrictSections: 1, BoundSections: 1}, false},
		{"unknown reserved data", binding{PodUIDHash: 1, StrictSections: 1, Reserved: 1}, false},
		{"invalid identity", binding{StrictSections: 1}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if f1Binding(tt.row) != tt.want {
				t.Fatalf("f1Binding(%+v) != %v", tt.row, tt.want)
			}
		})
	}
	for _, mode := range []Mode{Strict, Audit} {
		b, err := makeBinding(mode, 1)
		if err != nil || !f1Binding(b) || b.Owner != 0 || b.BoundSections != 0 {
			t.Fatalf("invalid unbound mark for mode %v: %+v %v", mode, b, err)
		}
	}
	if _, err := makeBinding(0, 1); err == nil {
		t.Fatal("invalid mode accepted")
	}
}

func TestRefuseUnverifiedCgroupID(t *testing.T) {
	dir, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	for _, f := range []*os.File{nil, dir} {
		if _, err := PodCgroupID(f); err == nil {
			t.Fatalf("accepted unverified host pod cgroup %v", f)
		}
	}
	if !unifiedCgroupEntry("0::/system.slice/service\n") || !unifiedCgroupEntry("0::/\n") {
		t.Fatal("refused unified host membership")
	}
	for _, bad := range []string{"", "5:cpu:/", "0::/\n5:cpu:/legacy\n", "0::bogus"} {
		if unifiedCgroupEntry(bad) {
			t.Fatalf("accepted unsupported hierarchy %q", bad)
		}
	}
}
