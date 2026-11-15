// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf/btf"
)

func TestExecPrototype(t *testing.T) {
	makeFunc := func() *btf.Func {
		return &btf.Func{Name: "bprm_execve", Type: &btf.FuncProto{Return: &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}, Params: []btf.FuncParam{{Name: "bprm", Type: &btf.Pointer{Target: &btf.Struct{Name: "linux_binprm"}}}}}}
	}
	if err := checkPrototype(makeFunc(), true); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*btf.FuncProto){
		"arity":    func(p *btf.FuncProto) { p.Params = nil },
		"return":   func(p *btf.FuncProto) { p.Return = &btf.Int{Name: "long", Size: 8, Encoding: btf.Signed} },
		"argument": func(p *btf.FuncProto) { p.Params[0].Type = &btf.Pointer{Target: &btf.Struct{Name: "task_struct"}} },
	} {
		t.Run(name, func(t *testing.T) {
			f := makeFunc()
			mutate(f.Type.(*btf.FuncProto))
			if checkPrototype(f, true) == nil {
				t.Fatal("bad prototype accepted")
			}
		})
	}
}

func TestPublicationPrototype(t *testing.T) {
	makeFunc := func() *btf.Func {
		return &btf.Func{Name: "cgroup_kn_lock_live", Type: &btf.FuncProto{
			Return: &btf.Pointer{Target: &btf.Struct{Name: "cgroup"}},
			Params: []btf.FuncParam{
				{Name: "kn", Type: &btf.Pointer{Target: &btf.Struct{Name: "kernfs_node"}}},
				{Name: "drain_offline", Type: &btf.Typedef{Name: "bool", Type: &btf.Int{Name: "_Bool", Size: 1, Encoding: btf.Bool}}},
			},
		}}
	}
	if err := checkPublicationPrototype(makeFunc()); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*btf.FuncProto){
		"arity":         func(p *btf.FuncProto) { p.Params = p.Params[:1] },
		"swapped args":  func(p *btf.FuncProto) { p.Params[0], p.Params[1] = p.Params[1], p.Params[0] },
		"return":        func(p *btf.FuncProto) { p.Return = p.Params[0].Type },
		"bool size":     func(p *btf.FuncProto) { p.Params[1].Type = &btf.Int{Size: 4, Encoding: btf.Bool} },
		"bool encoding": func(p *btf.FuncProto) { p.Params[1].Type = &btf.Int{Size: 1, Encoding: btf.Unsigned} },
	} {
		t.Run(name, func(t *testing.T) {
			f := makeFunc()
			mutate(f.Type.(*btf.FuncProto))
			if checkPublicationPrototype(f) == nil {
				t.Fatal("bad publication prototype accepted")
			}
		})
	}
}

func TestPublicationRejectsOrdinaryFilesystem(t *testing.T) {
	dir := t.TempDir()
	if p, err := openPublicationTrigger(dir); err == nil || p != nil {
		t.Fatal("ordinary filesystem accepted")
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("rejection created a child: %v %v", entries, err)
	}
}

func TestPublicationStateChecks(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"cgroup.subtree_control", "cgroup.procs", "cgroup.threads"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	p := &publicationTrigger{dir: dir}
	if err := p.check(); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"cgroup.subtree_control": "memory\n", "cgroup.procs": "1\n", "cgroup.threads": "2\n"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
				t.Fatal(err)
			}
			if p.check() == nil {
				t.Fatal("changed mask or populated cgroup accepted")
			}
			if err := os.WriteFile(path, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPublicationCleanup(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "owned")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	p := &publicationTrigger{dir: dir}
	if err := p.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("owned directory remains: %v", err)
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	unexpected := filepath.Join(dir, "unexpected")
	if err := os.WriteFile(unexpected, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.close(); err == nil {
		t.Fatal("failed cleanup accepted")
	}
	if _, err := os.Stat(unexpected); err != nil {
		t.Fatalf("cleanup removed unexpected contents: %v", err)
	}
}
