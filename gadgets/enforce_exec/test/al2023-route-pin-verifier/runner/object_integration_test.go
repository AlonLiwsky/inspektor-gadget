//go:build routepinintegration

// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

func TestObjectContract(t *testing.T) {
	path := os.Getenv("ROUTE_PIN_OBJECT")
	if path == "" {
		t.Fatal("ROUTE_PIN_OBJECT required: tests must inspect a freshly compiled candidate")
	}
	load := func() *ebpf.CollectionSpec {
		t.Helper()
		s, e := ebpf.LoadCollectionSpec(path)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	if err := inspect(load()); err != nil {
		t.Fatal(err)
	}
	if targets(load())["probe_entry"] == "cgroup_kn_lock_live" {
		path := os.Getenv("ROUTE_PIN_KERNEL_BTF")
		if path == "" {
			t.Fatal("ROUTE_PIN_KERNEL_BTF required for publication object")
		}
		k, err := btf.LoadSpec(path)
		if err != nil {
			t.Fatal(err)
		}
		var f *btf.Func
		if err := k.TypeByName("cgroup_kn_lock_live", &f); err != nil {
			t.Fatal(err)
		}
		if err := checkPublicationPrototype(f); err != nil {
			t.Fatal(err)
		}
	}
	cases := map[string]func(*ebpf.CollectionSpec){
		"missing route": func(s *ebpf.CollectionSpec) { delete(s.Maps, "routes") },
		"missing BTF":   func(s *ebpf.CollectionSpec) { s.Maps["routes"].Value = nil },
		"old 88 byte layout": func(s *ebpf.CollectionSpec) {
			v := s.Maps["routes"].Value.(*btf.Struct)
			v.Size = 88
			v.Members = v.Members[:17]
		},
		"wrong source field": func(s *ebpf.CollectionSpec) { s.Maps["routes"].Value.(*btf.Struct).Members[18].Name = "wrong" },
		"wrong field offset": func(s *ebpf.CollectionSpec) { s.Maps["routes"].Value.(*btf.Struct).Members[17].Offset += 8 },
		"missing lock": func(s *ebpf.CollectionSpec) {
			s.Maps["routes"].Value.(*btf.Struct).Members[0].Type = &btf.Int{Name: "u32", Size: 4}
		},
		"sleepable":     func(s *ebpf.CollectionSpec) { s.Programs["probe_entry"].Flags = 16 },
		"wrong type":    func(s *ebpf.CollectionSpec) { s.Programs["probe_exit"].Type = ebpf.Kprobe },
		"wrong target":  func(s *ebpf.CollectionSpec) { s.Programs["probe_entry"].AttachTo = "bprm_execve" },
		"mixed targets": func(s *ebpf.CollectionSpec) { s.Programs["probe_exit"].AttachTo = "security_bprm_creds_for_exec" },
		"pin requested": func(s *ebpf.CollectionSpec) { s.Maps["routes"].Pinning = ebpf.PinByName },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := load()
			mutate(s)
			if err := inspect(s); err == nil {
				t.Fatal("unsupported object accepted")
			}
		})
	}
}
