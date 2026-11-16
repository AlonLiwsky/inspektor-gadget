// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"fmt"
	"testing"
)

func sourceCopyRule() Rule {
	values := func(value string) []string {
		out := make([]string, 17)
		for i := range out {
			out[i] = value
		}
		return out
	}
	return Rule{Name: "copies", Action: Allow, Actor: Actor{Path: values("/actor"), Role: values("role"), Container: values("worker"), UID: make([]int64, 17), Ancestor: &Ancestor{Depth: 1, Path: values("/ancestor")}}, Target: Target{Path: values("/target"), FSType: values("tmpfs"), Argv: &Argv{Contains: values("contains"), Prefix: values("prefix")}}}
}

func sourceCopyLists(r Rule) [][]string {
	return [][]string{r.Actor.Path, r.Actor.Role, r.Actor.Container, r.Actor.Ancestor.Path, r.Target.Path, r.Target.FSType, r.Target.Argv.Contains, r.Target.Argv.Prefix}
}

func TestSourceCopiesExactAndOwned(t *testing.T) {
	p := base()
	p.Rules = []Rule{sourceCopyRule()}
	reference, err := Compile([]Policy{p})
	if err != nil {
		t.Fatal(err)
	}
	native, err := preparePolicies([]Policy{p}, nativeGlob)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []Rule{reference.policies[0].rules[0].source, native.policies[0].rules[0].source} {
		for _, list := range sourceCopyLists(r) {
			if cap(list) != len(list) || len(list) != 17 {
				t.Fatalf("source capacity=%d len=%d", cap(list), len(list))
			}
		}
		if cap(r.Actor.UID) != 17 {
			t.Fatal("UID copy rounded capacity", cap(r.Actor.UID))
		}
	}
	for _, list := range sourceCopyLists(p.Rules[0]) {
		list[0] = "changed"
	}
	p.Rules[0].Actor.UID[0] = 12
	for _, r := range []Rule{reference.policies[0].rules[0].source, native.policies[0].rules[0].source} {
		for _, list := range sourceCopyLists(r) {
			if list[0] == "changed" {
				t.Fatal("source list aliases caller")
			}
		}
		if r.Actor.UID[0] != 0 {
			t.Fatal("UID aliases caller")
		}
	}
}

func TestSourceEmptyShapesAndPreparedPathCapacity(t *testing.T) {
	for _, empty := range [][]string{nil, {}} {
		pipe := true
		p := base()
		p.Rules = []Rule{{Name: "empty", Action: Allow, Actor: Actor{Path: empty, Role: empty, Container: empty, UID: []int64{}}, Target: Target{Path: empty, FSType: empty, Argv: &Argv{Contains: empty, Prefix: empty, StdinIsPipe: &pipe}}}}
		prepared, err := preparePolicies([]Policy{p}, nativeGlob)
		if err != nil {
			t.Fatal(err)
		}
		r := prepared.policies[0].rules[0]
		for _, list := range [][]string{r.source.Actor.Path, r.source.Actor.Role, r.source.Actor.Container, r.source.Target.Path, r.source.Target.FSType, r.source.Target.Argv.Contains, r.source.Target.Argv.Prefix} {
			if list != nil {
				t.Fatal("empty source copy became nonnil")
			}
		}
		if r.source.Actor.UID != nil || r.actor == nil || r.target == nil {
			t.Fatal("source/prepared nil-empty distinction changed")
		}
	}
	for _, n := range []int{0, 17, MaxValues} {
		paths := make([]string, n)
		for i := range paths {
			paths[i] = "/same"
		}
		count := 0
		got, err := preparePaths(paths, &count, nativeGlob)
		if err != nil || got == nil || len(got) != n || cap(got) != n || count != n {
			t.Fatal("prepared paths already-exact shape changed", n, err)
		}
	}
}

func TestSourceCopyValidationOrder(t *testing.T) {
	p := base()
	p.Rules = []Rule{{Name: "bad", Action: Allow, Actor: Actor{Path: make([]string, MaxValues+1), UID: []int64{-1}}, Target: Target{Path: []string{"relative"}}}}
	if _, err := Compile([]Policy{p}); err == nil || err.Error() != fmt.Sprintf("rule bad actor: path list exceeds %d", MaxValues) {
		t.Fatal("path validation order changed", err)
	}
	p.Rules[0].Actor.Path = nil
	p.Rules[0].Target.Path = nil
	p.Rules[0].Actor.Role = []string{""}
	if _, err := Compile([]Policy{p}); err == nil || err.Error() != "string must contain 1..255 non-NUL bytes" {
		t.Fatal("string validation moved after UID", err)
	}
	p.Rules[0].Actor.Role = nil
	p.Rules[0].Actor.UID = make([]int64, MaxValues+1)
	if _, err := Compile([]Policy{p}); err == nil || err.Error() != fmt.Sprintf("UID list exceeds %d", MaxValues) {
		t.Fatal("UID length validation changed", err)
	}
	p.Rules[0].Actor.UID = []int64{-1}
	p.Rules[0].Actor.Ancestor = &Ancestor{}
	if _, err := Compile([]Policy{p}); err == nil || err.Error() != "effective UID is out of range" {
		t.Fatal("UID value validation moved after ancestor", err)
	}
}
