// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"sync"
	"testing"

	"github.com/cilium/ebpf"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func testBudget(t *testing.T, n uint64) *Budget {
	t.Helper()
	b, err := NewBudget(BudgetLimits{n, n * OwnerMapPayloadLimit, n * OwnerInstructionLimit, n * OwnerHistoryLimit})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBudgetScopeCapacityAndSharedHandles(t *testing.T) {
	b := testBudget(t, 1)
	r, err := b.reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = b.reserve(1); err == nil {
		t.Fatal("duplicate scope accepted")
	}
	if _, err = b.reserve(2); err == nil {
		t.Fatal("capacity exceeded")
	}
	copy := *r
	r.release()
	next, err := b.reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	copy.release()
	if b.Usage().Owners != 1 {
		t.Fatal("stale copy released later owner")
	}
	next.release()
	if b.Usage() != (BudgetLimits{}) {
		t.Fatal("budget leaked")
	}
}

func TestBudgetConcurrentCopies(t *testing.T) {
	b := testBudget(t, LegacyOwnerHardCap)
	var wg sync.WaitGroup
	for scope := uint64(1); scope <= LegacyOwnerHardCap; scope++ {
		r, err := b.reserve(scope)
		if err != nil {
			t.Fatal(err)
		}
		copy := *r
		for range 8 {
			wg.Go(func() { copy.release() })
		}
	}
	wg.Wait()
	if b.Usage() != (BudgetLimits{}) {
		t.Fatal("concurrent release lost accounting")
	}
}

func testResourceManifest() *operators.NativeResources {
	r := &operators.NativeResources{Maps: map[string]operators.NativeMapResource{"eo_work": {Type: uint32(ebpf.TaskStorage), KeySize: 4, ValueSize: 1096}}, Programs: map[string]operators.NativeProgramResource{}}
	for n, h := range ownerHooks {
		r.Programs[n] = operators.NativeProgramResource{Type: uint32(h.kind), Target: h.target, Instructions: 1}
	}
	r.Programs["eo_command"] = operators.NativeProgramResource{Type: uint32(ebpf.Syscall), Instructions: 1}
	return r
}

func TestResourcePreflightBounds(t *testing.T) {
	if err := validateOwnerResources(testResourceManifest(), 8); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*operators.NativeResources){
		"oversized hash": func(r *operators.NativeResources) {
			r.Maps["extra"] = operators.NativeMapResource{Type: uint32(ebpf.Hash), KeySize: 8, ValueSize: 0xffffffff, MaxEntries: 0xffffffff}
		},
		"unknown storage": func(r *operators.NativeResources) {
			r.Maps["extra"] = operators.NativeMapResource{Type: uint32(ebpf.TaskStorage), ValueSize: 8}
		},
		"oversized ring": func(r *operators.NativeResources) {
			r.Maps["extra"] = operators.NativeMapResource{Type: uint32(ebpf.RingBuf), MaxEntries: 0xffffffff}
		},
		"disabled hook": func(r *operators.NativeResources) {
			p := r.Programs["eo_task_exit"]
			p.Target = "gadget_program_disabled"
			r.Programs["eo_task_exit"] = p
		},
		"missing hook": func(r *operators.NativeResources) { delete(r.Programs, "eo_task_alloc") },
		"noncommand": func(r *operators.NativeResources) {
			r.Programs["eo_command"] = operators.NativeProgramResource{Type: uint32(ebpf.LSM), Instructions: 1}
		},
		"instructions": func(r *operators.NativeResources) {
			r.Programs["extra"] = operators.NativeProgramResource{Instructions: OwnerInstructionLimit + 1}
		},
		"unbounded map": func(r *operators.NativeResources) {
			r.Maps["extra"] = operators.NativeMapResource{Type: uint32(ebpf.Hash), ValueSize: 1}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r := testResourceManifest()
			mutate(r)
			if err := validateOwnerResources(r, 8); err == nil {
				t.Fatal("unsupported resources accepted")
			}
		})
	}
	if err := validateOwnerResources(testResourceManifest(), 4097); err == nil {
		t.Fatal("CPU bound ignored")
	}
}

func TestOwnerResourceBudgetRevalidatedAfterMapSizing(t *testing.T) {
	gc := gadgetcontext.New(t.Context(), "trusted:test")
	defer gc.Cancel()
	initial := testResourceManifest()
	initial.Maps["parameterized"] = operators.NativeMapResource{Type: uint32(ebpf.Hash), KeySize: 8, ValueSize: 288, MaxEntries: 1}
	if err := admitOwnerResources(gc, initial, 8); err != nil {
		t.Fatal(err)
	}
	value, _ := gc.GetVar(operators.NativeResourceValidatorKey)
	validate, ok := value.(func(*operators.NativeResources) error)
	if !ok {
		t.Fatal("allocation-boundary validation not installed")
	}
	if err := validate(initial); err != nil {
		t.Fatal(err)
	}
	final := testResourceManifest()
	final.Maps["parameterized"] = operators.NativeMapResource{Type: uint32(ebpf.Hash), KeySize: 8, ValueSize: 288, MaxEntries: 1 << 20}
	if err := validate(final); err == nil {
		t.Fatal("post-parameter map expansion exceeded owner payload ceiling")
	}
	if err := validate(nil); err == nil {
		t.Fatal("missing final manifest accepted")
	}
}

func TestOwnerAccountsInnerMapTemplates(t *testing.T) {
	for _, tc := range []struct {
		name  string
		inner *operators.NativeMapResource
		valid bool
	}{
		{"bounded", &operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 288, MaxEntries: 16}, true},
		{"oversized", &operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 288, MaxEntries: 1 << 20}, false},
		{"missing", nil, false},
		{"nested", &operators.NativeMapResource{Type: uint32(ebpf.ArrayOfMaps), KeySize: 4, ValueSize: 4, MaxEntries: 1, InnerMap: &operators.NativeMapResource{}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := testResourceManifest()
			r.Maps["outer"] = operators.NativeMapResource{Type: uint32(ebpf.ArrayOfMaps), KeySize: 4, ValueSize: 4, MaxEntries: 1, InnerMap: tc.inner}
			if err := validateOwnerResources(r, 8); (err == nil) != tc.valid {
				t.Fatalf("validateOwnerResources = %v, valid=%v", err, tc.valid)
			}
		})
	}
}
