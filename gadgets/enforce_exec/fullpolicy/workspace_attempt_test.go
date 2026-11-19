// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
)

func TestSharedPolicyModelBoundary(t *testing.T) {
	p := base()
	p.Rules = []Rule{{Name: "rule", Action: Allow, Actor: Actor{Path: []string{"/bin/*", "/[a-z]/**"}}}}
	model, err := sharedPolicyModelDebit(p)
	if err != nil {
		t.Fatal(err)
	}
	want, err := CompileSharedPolicyCompact(p)
	if err != nil {
		t.Fatal(err)
	}
	got, debit, err := compileSharedPolicyModel(p, model.total)
	if err != nil || got == nil || !got.Equal(want) || debit != model.total {
		t.Fatalf("exact: debit=%d/%d err=%v", debit, model.total, err)
	}
	if got, debit, err := compileSharedPolicyModel(p, model.total-1); got != nil || debit != 0 || err != compactFailure(DiagnosticCapacity, DiagnosticNone) { //nolint:errorlint // Exact static capacity sentinel.
		t.Fatalf("short: %v %d %v", got, debit, err)
	}
	if allocs := testing.AllocsPerRun(10, func() { _, _, _ = compileSharedPolicyModel(p, 0) }); allocs != 0 {
		t.Fatalf("refusal allocations=%v", allocs)
	}
}

func TestSharedPolicyModelFailureDebit(t *testing.T) {
	for _, path := range []string{"/[a-z]/[z-a]", "/[", "", strings.Repeat("x", 256)} {
		p := base()
		p.Rules = []Rule{{Name: "rule", Action: Allow, Actor: Actor{Path: []string{path}}}}
		_, want := CompileSharedPolicyCompact(p)
		got, debit, err := compileSharedPolicyModel(p, math.MaxUint64)
		if got != nil || debit == 0 || err != want { //nolint:errorlint // Exact immutable compact diagnostic identity is the compatibility oracle.
			t.Fatalf("path %q: got=%v debit=%d err=%v want=%v", path, got, debit, err, want)
		}
	}
}

func TestSharedPolicyModelRejectedPathBacking(t *testing.T) {
	p := base()
	for i := 0; i < 4; i++ {
		p.Rules = append(p.Rules, Rule{Name: string(rune('a' + i)), Action: Allow, Actor: Actor{Path: make([]string, 256)}})
	}
	for i := range p.Rules {
		for j := range p.Rules[i].Actor.Path {
			p.Rules[i].Actor.Path[j] = "/a"
		}
	}
	p.Rules = append(p.Rules, Rule{Name: "tail", Action: Allow, Actor: Actor{Path: make([]string, 256)}})
	for i := range p.Rules[4].Actor.Path {
		p.Rules[4].Actor.Path[i] = "/a"
	}
	model, err := sharedPolicyModelDebit(p)
	if err != nil || model.pathSlots != 1280 {
		t.Fatalf("slots=%d err=%v", model.pathSlots, err)
	}
	_, want := CompileSharedPolicyCompact(p)
	got, debit, err := compileSharedPolicyModel(p, model.total)
	if got != nil || debit != model.total || err != want { //nolint:errorlint // Exact immutable compact diagnostic identity is the compatibility oracle.
		t.Fatalf("prefix: %v %d %v want=%v", got, debit, err, want)
	}
}

func TestSharedPolicyModelOwnsSource(t *testing.T) {
	p := base()
	p.Rules = []Rule{{Name: "a", Action: Allow, Actor: Actor{Path: []string{"/a"}}}}
	got, _, err := compileSharedPolicyModel(p, math.MaxUint64)
	if err != nil {
		t.Fatal(err)
	}
	before := got.Digest()
	p.Rules[0].Actor.Path[0] = "/other"
	if got.Digest() != before || reflect.DeepEqual(got.source.Rules, p.Rules) {
		t.Fatal("source alias")
	}
	typ := reflect.TypeFor[SharedPolicy]()
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type == reflect.TypeFor[*compilerWorkspace]() || typ.Field(i).Type == reflect.TypeFor[*workspaceReservation]() {
			t.Fatal("escaped workspace authority")
		}
	}
}

func TestSharedPolicyModelOriginalOccurrences(t *testing.T) {
	p := base()
	for i := 0; i < MaxRules; i++ {
		p.Rules = append(p.Rules, Rule{Name: fmt.Sprint(i), Action: Allow, Actor: Actor{Path: []string{"/a", "/a", "/a", "/a"}}})
	}
	model, err := sharedPolicyModelDebit(p)
	if err != nil || model.pathSlots != MaxPatterns {
		t.Fatalf("model=%+v err=%v", model, err)
	}
	got, debit, err := compileSharedPolicyModel(p, model.total)
	want, wantErr := CompileSharedPolicyCompact(p)
	if err != nil || wantErr != nil || !got.Equal(want) || debit != model.total {
		t.Fatalf("maximum: %d %v %v", debit, err, wantErr)
	}
	p.Rules[0].Actor.Path = p.Rules[0].Actor.Path[:1]
	smaller, err := sharedPolicyModelDebit(p)
	if err != nil || smaller.total >= model.total {
		t.Fatal("dedup refunded original occurrences", err)
	}
}

func TestSharedPolicyModelBoundedHostileInput(t *testing.T) {
	p := base()
	p.Rules = make([]Rule, MaxRules+1000)
	for i := range p.Rules {
		p.Rules[i] = Rule{Name: "duplicate", Action: Allow, Actor: Actor{Path: []string{strings.Repeat("x", 1000)}}}
	}
	first, err := sharedPolicyModelDebit(p)
	if err != nil {
		t.Fatal(err)
	}
	p.Rules = p.Rules[:MaxRules]
	second, err := sharedPolicyModelDebit(p)
	if err != nil || first != second {
		t.Fatalf("unreachable tail charged: %+v %+v %v", first, second, err)
	}
	if allocs := testing.AllocsPerRun(10, func() { _, _ = sharedPolicyModelDebit(p) }); allocs != 0 {
		t.Fatalf("preflight allocates: %v", allocs)
	}
	s := attemptSum{bytes: math.MaxUint64}
	s.add(1)
	if s.err == nil {
		t.Fatal("unchecked debit overflow")
	}
	if _, err := attemptByteCapacity(math.MaxUint64); err == nil {
		t.Fatal("unchecked rounding overflow")
	}
}

func TestSharedPolicyModelPrefixDiagnosticOrder(t *testing.T) {
	for _, invalidFirst := range []bool{false, true} {
		p := base()
		for i := 0; i < 5; i++ {
			paths := make([]string, 256)
			for j := range paths {
				paths[j] = "/a"
			}
			p.Rules = append(p.Rules, Rule{Name: fmt.Sprint(i), Action: Allow, Actor: Actor{Path: paths}})
		}
		if invalidFirst {
			p.Rules[0].Actor.Path[0] = "/["
		} else {
			p.Rules[4].Actor.Path[0] = "/["
		}
		_, want := CompileSharedPolicyCompact(p)
		got, debit, err := compileSharedPolicyModel(p, math.MaxUint64)
		if got != nil || debit == 0 || err != want { //nolint:errorlint // Exact immutable compact diagnostic identity is the compatibility oracle.
			t.Fatalf("order %t: %d %v want=%v", invalidFirst, debit, err, want)
		}
	}
}

func TestSharedPolicyModelLargeClassAndLongConversions(t *testing.T) {
	p := base()
	p.ID = strings.Repeat("i", 255)
	p.RootRole = strings.Repeat("r", 255)
	p.Rules = []Rule{{Name: "wide", Action: Allow, Actor: Actor{Path: []string{"/[" + strings.Repeat("a", 240) + "]"}, Role: []string{p.RootRole}, Container: []string{strings.Repeat("c", 255)}}}}
	model, err := sharedPolicyModelDebit(p)
	if err != nil {
		t.Fatal(err)
	}
	got, debit, err := compileSharedPolicyModel(p, model.total)
	want, wantErr := CompileSharedPolicyCompact(p)
	if err != wantErr || debit != model.total || (err == nil && !got.Equal(want)) { //nolint:errorlint // Exact immutable compact diagnostic identity is the compatibility oracle.
		t.Fatalf("large class/conversion: %d %v %v", debit, err, wantErr)
	}
}

func TestSharedPolicyModelBlobGrowthFailureAndNearCapacity(t *testing.T) {
	for _, rules := range []int{63, 64} {
		p := base()
		for i := 0; i < rules; i++ {
			uids := make([]int64, MaxValues)
			for j := range uids {
				uids[j] = int64(j)
			}
			p.Rules = append(p.Rules, Rule{Name: fmt.Sprint(i), Action: Allow, Actor: Actor{UID: uids}})
		}
		model, err := sharedPolicyModelDebit(p)
		if err != nil {
			t.Fatal(err)
		}
		got, debit, err := compileSharedPolicyModel(p, model.total)
		want, wantErr := CompileSharedPolicyCompact(p)
		if err != wantErr || debit != model.total { //nolint:errorlint // Exact immutable compact diagnostic identity includes cleanup category.
			t.Fatalf("rules=%d debit=%d/%d err=%v want=%v", rules, debit, model.total, err, wantErr)
		}
		if rules == 63 {
			if err != nil || !got.Equal(want) || got.EntryCount() < 16000 {
				t.Fatal("near capacity mismatch", err)
			}
		} else {
			if got != nil || err == nil {
				t.Fatal("capacity failure accepted")
			}
			diagnostic := err.(CompactDiagnostic) //nolint:errorlint // Direct static compact diagnostic required, not a wrapper.
			if diagnostic.Primary() != DiagnosticCapacity || diagnostic.Cleanup() != DiagnosticNone {
				t.Fatal("cleanup or category changed", diagnostic)
			}
		}
	}
}

func TestSharedPolicyModelAllPredicates(t *testing.T) {
	yes := true
	p := base()
	p.Rules = []Rule{{Name: "all", Action: Allow, Actor: Actor{Path: []string{"/a"}, FromImage: &yes, Ancestor: &Ancestor{Depth: 2, Path: []string{"/parent"}}, Role: []string{"agent"}, UID: []int64{0, 123}, Container: []string{"app"}}, Target: Target{Path: []string{"/target"}, FromImage: &yes, FSType: []string{"overlay"}, Argv: &Argv{Contains: []string{"x"}, Prefix: []string{"y"}, StdinIsPipe: &yes}, SetRole: "next"}}}
	model, err := sharedPolicyModelDebit(p)
	if err != nil {
		t.Fatal(err)
	}
	got, debit, err := compileSharedPolicyModel(p, model.total)
	want, wantErr := CompileSharedPolicyCompact(p)
	if err != nil || wantErr != nil || debit != model.total || !got.Equal(want) {
		t.Fatalf("all predicates: %v %v", err, wantErr)
	}
	p.Rules[0].Actor.Ancestor.Path[0] = "/changed"
	p.Rules[0].Target.Argv.Contains[0] = "changed"
	p.Rules[0].Actor.UID[0] = 777
	yes = false
	if got.source.Rules[0].Actor.Ancestor.Path[0] != "/parent" || got.source.Rules[0].Target.Argv.Contains[0] != "x" || got.source.Rules[0].Actor.UID[0] != 0 || !*got.source.Rules[0].Target.Argv.StdinIsPipe {
		t.Fatal("nested source ownership")
	}
}

func TestSharedPolicyModelAllocationGuards(t *testing.T) {
	for _, n := range []int{256, 257} {
		for _, invalidFirst := range []bool{false, true} {
			p := base()
			values := make([]string, n)
			for i := range values {
				values[i] = "/a"
			}
			p.Rules = []Rule{{Name: "first", Action: Allow}, {Name: "second", Action: Allow, Actor: Actor{Path: values}}}
			if invalidFirst {
				p.Rules[0].Actor.Path = []string{"/["}
			}
			model, err := sharedPolicyModelDebit(p)
			if err != nil {
				t.Fatal(err)
			}
			got, debit, err := compileSharedPolicyModel(p, model.total)
			want, wantErr := CompileSharedPolicyCompact(p)
			if err != wantErr || debit != model.total || (err == nil && !got.Equal(want)) { //nolint:errorlint // Preserve exact diagnostic order.
				t.Fatalf("guard %d/%t: %v %v", n, invalidFirst, err, wantErr)
			}
		}
	}
	for _, n := range []int{0, 256, 257} {
		p := base()
		for i := 0; i < n; i++ {
			p.Rules = append(p.Rules, Rule{Name: fmt.Sprint(i), Action: Allow})
		}
		model, err := sharedPolicyModelDebit(p)
		if err != nil {
			t.Fatal(err)
		}
		got, debit, err := compileSharedPolicyModel(p, model.total)
		want, wantErr := CompileSharedPolicyCompact(p)
		if err != wantErr || debit != model.total || (err == nil && !got.Equal(want)) { //nolint:errorlint // Preserve exact immutable diagnostic.
			t.Fatalf("rule guard %d: %v %v", n, err, wantErr)
		}
		if n > 0 {
			p.Rules[0].Actor.Path = []string{"/["}
			_, _, err = compileSharedPolicyModel(p, math.MaxUint64)
			_, wantErr = CompileSharedPolicyCompact(p)
			if err != wantErr { //nolint:errorlint // Earlier authored error must still win.
				t.Fatalf("earlier invalid before rule cap: %v %v", err, wantErr)
			}
		}
	}
}

func TestSharedPolicyModelListGuardMatrix(t *testing.T) {
	setters := []struct {
		name string
		set  func(*Rule, int)
	}{
		{"roles", func(r *Rule, n int) {
			r.Actor.Role = make([]string, n)
			for i := range r.Actor.Role {
				r.Actor.Role[i] = "agent"
			}
		}},
		{"containers", func(r *Rule, n int) {
			r.Actor.Container = make([]string, n)
			for i := range r.Actor.Container {
				r.Actor.Container[i] = "app"
			}
		}},
		{"filesystem", func(r *Rule, n int) {
			r.Target.FSType = make([]string, n)
			for i := range r.Target.FSType {
				r.Target.FSType[i] = "overlay"
			}
		}},
		{"contains", func(r *Rule, n int) {
			r.Target.Argv = &Argv{Contains: make([]string, n)}
			for i := range r.Target.Argv.Contains {
				r.Target.Argv.Contains[i] = "arg"
			}
		}},
		{"prefix", func(r *Rule, n int) {
			r.Target.Argv = &Argv{Prefix: make([]string, n)}
			for i := range r.Target.Argv.Prefix {
				r.Target.Argv.Prefix[i] = "arg"
			}
		}},
		{"uids", func(r *Rule, n int) { r.Actor.UID = make([]int64, n) }},
	}
	for _, setter := range setters {
		for _, n := range []int{256, 257} {
			for _, invalidFirst := range []bool{false, true} {
				p := base()
				r := Rule{Name: "list", Action: Allow}
				setter.set(&r, n)
				if invalidFirst {
					r.Actor.Path = []string{"/["}
				}
				p.Rules = []Rule{r}
				model, err := sharedPolicyModelDebit(p)
				if err != nil {
					t.Fatal(err)
				}
				got, debit, err := compileSharedPolicyModel(p, model.total)
				want, wantErr := CompileSharedPolicyCompact(p)
				if err != wantErr || debit != model.total || (err == nil && !got.Equal(want)) { //nolint:errorlint // Exact static diagnostic and cleanup identity is required.
					t.Fatalf("%s/%d/%t: %v %v", setter.name, n, invalidFirst, err, wantErr)
				}
			}
		}
	}
}
