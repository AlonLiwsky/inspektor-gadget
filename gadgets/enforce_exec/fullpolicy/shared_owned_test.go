// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"reflect"
	"strings"
	"testing"
	"unsafe"
)

func TestSharedOwnedSourceDoesNotRetainSubstringBacking(t *testing.T) {
	backing := strings.Repeat("x", 1<<20) + "policyrevisionauditagentallowruleorigin/bin/appcontainertmpfsargrole"
	sub := func(s string) string { i := strings.LastIndex(backing, s); return backing[i : i+len(s)] }
	yes := true
	paths := make([]string, 1, 1<<16)
	paths[0] = sub("/bin/app")
	p := Policy{ID: sub("policy"), Revision: sub("revision"), Mode: Mode(sub("audit")), RootRole: sub("agent"), Default: Action(sub("allow")), Rules: make([]Rule, 1, 1<<12)}
	p.Rules[0] = Rule{Name: sub("rule"), Origin: sub("origin"), Action: Action(sub("allow")), Mode: Mode(sub("audit")), Actor: Actor{Path: paths, FromImage: &yes, Ancestor: &Ancestor{Path: paths, Depth: 1}, Role: []string{sub("agent")}, UID: []int64{1}, Container: []string{sub("container")}}, Target: Target{Path: paths, FromImage: &yes, FSType: []string{sub("tmpfs")}, Argv: &Argv{Contains: []string{sub("arg")}, Prefix: []string{sub("arg")}, StdinIsPipe: &yes}, SetRole: sub("role")}}
	inputs := map[string]Policy{"p": p}
	object, err := CompileSharedPolicy(inputs["p"])
	if err != nil {
		t.Fatal(err)
	}
	r := object.source.Rules[0]
	all := []string{object.source.ID, object.source.Revision, string(object.source.Mode), object.source.RootRole, string(object.source.Default), r.Name, r.Origin, string(r.Action), string(r.Mode), r.Target.SetRole}
	for _, values := range [][]string{r.Actor.Path, r.Actor.Ancestor.Path, r.Actor.Role, r.Actor.Container, r.Target.Path, r.Target.FSType, r.Target.Argv.Contains, r.Target.Argv.Prefix} {
		all = append(all, values...)
	}
	start := uintptr(unsafe.Pointer(unsafe.StringData(backing)))
	end := start + uintptr(len(backing))
	for _, s := range all {
		ptr := uintptr(unsafe.Pointer(unsafe.StringData(s)))
		if ptr >= start && ptr < end {
			t.Fatalf("retained caller substring backing for %q", s)
		}
	}
	if cap(object.source.Rules) >= cap(p.Rules) || cap(r.Actor.Path) >= cap(paths) {
		t.Fatal("retained oversized caller slice capacity")
	}
	before := object.Digest()
	sourceBefore := *object.source
	sourceBefore.Rules = append([]Rule(nil), object.source.Rules...)
	p.Rules[0].Name = "changed"
	p.Rules[0].Actor.UID[0] = 99
	p.Rules[0].Actor.Ancestor.Depth = 16
	p.Rules[0].Target.Argv.Contains[0] = "changed"
	paths[0] = "/changed"
	yes = false
	delete(inputs, "p")
	if object.Digest() != before || object.source.Rules[0].Name != sourceBefore.Rules[0].Name || r.Actor.Path[0] != "/bin/app" || !*r.Actor.FromImage || !*r.Target.Argv.StdinIsPipe || r.Actor.UID[0] != 1 || r.Actor.Ancestor.Depth != 1 || r.Target.Argv.Contains[0] != "arg" {
		t.Fatal("caller mutation changed owned source")
	}
}

func TestSharedOwnedEntryCopiesAndLogicalSize(t *testing.T) {
	p := base()
	p.Rules = nil
	object, err := CompileSharedPolicy(p)
	if err != nil {
		t.Fatal(err)
	}
	if int(object.EntryCount()) != len(object.entries) {
		t.Fatal("entry count")
	}
	entry, err := object.Entry(0)
	if err != nil {
		t.Fatal(err)
	}
	if allocations := testing.AllocsPerRun(100, func() {
		_, _ = object.Entry(0)
	}); allocations != 0 {
		t.Fatal("individual cell read allocated", allocations)
	}
	want := object.entries[0]
	entry[0] ^= 0xff
	again, err := object.Entry(0)
	if err != nil || again != want {
		t.Fatal("entry exposes mutable arena")
	}
	if _, err = object.Entry(object.EntryCount()); err == nil {
		t.Fatal("out of range entry accepted")
	}
	var absent *SharedPolicy
	if absent.EntryCount() != 0 {
		t.Fatal("nil count")
	}
	if _, err = absent.Entry(0); err == nil {
		t.Fatal("nil entry")
	}
	if _, err = absent.RetainedBytes(); err == nil {
		t.Fatal("nil accounting")
	}
	size, err := object.RetainedBytes()
	if err != nil {
		t.Fatal(err)
	}
	s := object.source
	expected := uint64(unsafe.Sizeof(*object)+unsafe.Sizeof(*s)) + uint64(cap(object.entries))*uint64(unsafe.Sizeof(Blob{})) + uint64(cap(s.Rules))*uint64(unsafe.Sizeof(Rule{})) + uint64(len(s.ID)+len(s.Revision)+len(s.Mode)+len(s.RootRole)+len(s.Default))
	if size != expected {
		t.Fatalf("retained size=%d want=%d", size, expected)
	}
	clone, err := CompileSharedPolicy(p)
	if err != nil || !object.Equal(clone) || !reflect.DeepEqual(object.Entries(), clone.Entries()) {
		t.Fatal("ownership changed canonical content", err)
	}
}

func TestSharedOwnedRetainedSizeCountsNestedStorageAndCapacity(t *testing.T) {
	yes := true
	values := func(capacity int) []string { v := make([]string, 1, capacity); v[0] = "abc"; return v }
	source := Policy{ID: "id", Revision: "rev", Mode: Audit, RootRole: "root", Default: Allow, Rules: make([]Rule, 1, 3)}
	source.Rules[0] = Rule{Name: "name", Origin: "origin", Mode: Enforce, Action: Deny, Actor: Actor{Path: values(2), Role: values(3), Container: values(4), UID: make([]int64, 1, 5), FromImage: &yes, Ancestor: &Ancestor{Depth: 1, Path: values(6)}}, Target: Target{Path: values(7), FSType: values(8), FromImage: &yes, SetRole: "role", Argv: &Argv{Contains: values(9), Prefix: values(10), StdinIsPipe: &yes}}}
	// Synthetic internal layout verifies accounting itself; production sources
	// come only from the validated compiler and have independent pointer copies.
	object := &SharedPolicy{entries: make([]Blob, 1, 4), source: &source}
	got, err := object.RetainedBytes()
	if err != nil {
		t.Fatal(err)
	}
	expected := uint64(unsafe.Sizeof(SharedPolicy{})) + uint64(unsafe.Sizeof(Policy{})) + 4*uint64(unsafe.Sizeof(Blob{})) + 3*uint64(unsafe.Sizeof(Rule{})) +
		uint64(2+3+len(Audit)+4+len(Allow)+4+6+len(Enforce)+len(Deny)+4) +
		uint64(2+3+4+6+7+8+9+10)*uint64(unsafe.Sizeof(string(""))) + 8*3 + 5*uint64(unsafe.Sizeof(int64(0))) +
		uint64(unsafe.Sizeof(Ancestor{})) + uint64(unsafe.Sizeof(Argv{})) + 3*uint64(unsafe.Sizeof(bool(false)))
	if got != expected {
		t.Fatalf("logical retained storage=%d want=%d", got, expected)
	}
	var sum sharedOwnedSize
	sum.bytes = ^uint64(0)
	sum.add(1)
	if !sum.overflow {
		t.Fatal("sum overflow ignored")
	}
	sum = sharedOwnedSize{}
	sum.array(2, ^uintptr(0))
	if unsafe.Sizeof(uintptr(0)) == 8 && !sum.overflow {
		t.Fatal("product overflow ignored")
	}
}

func TestSharedOwnedExecutionClassUsesCompilerUnionClassification(t *testing.T) {
	for _, mode := range []Mode{Audit, Enforce} {
		for _, override := range []Mode{"", Audit, Enforce} {
			for _, fallback := range []Action{"", Allow, Deny} {
				p := base()
				p.Mode = mode
				p.Default = fallback
				p.Rules = []Rule{{Name: "rule", Action: Allow, Mode: override, Actor: Actor{Role: []string{"agent"}}, Target: Target{SetRole: "child"}}}
				object, err := CompileSharedPolicy(p)
				if err != nil {
					t.Fatal(err)
				}
				program, err := CompileKernel([]Policy{p}, 1, "test")
				if err != nil {
					t.Fatal(err)
				}
				summary, err := sharedExecutionMetadata(program.Entries, []SharedPolicyRef{{Object: object}})
				if err != nil {
					t.Fatal(err)
				}
				class, err := object.ExecutionClass()
				if err != nil || class != summary.metadata.ExecutionClass {
					t.Fatalf("mode=%s override=%s fallback=%s class=%d want=%d err=%v", mode, override, fallback, class, summary.metadata.ExecutionClass, err)
				}
			}
		}
	}
	for _, object := range []*SharedPolicy{nil, {}} {
		if _, err := object.ExecutionClass(); err == nil {
			t.Fatal("missing compiler object accepted")
		}
	}
}
