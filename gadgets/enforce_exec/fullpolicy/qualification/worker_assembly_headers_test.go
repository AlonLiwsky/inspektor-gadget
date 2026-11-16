// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func workerAssemblyHeaderFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, name := range []string{"pkg/include/textflag.h", "pkg/include/funcdata.h", "pkg/include/asm_amd64.h", "pkg/include/asm_other.h", "src/runtime/cgo/abi_amd64.h"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("// "+name+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestWorkerAssemblyHeadersBindSnapshot(t *testing.T) {
	root := workerAssemblyHeaderFixture(t)
	inputs, err := workerAssemblyHeaderInputs(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(inputs) != 5 {
		t.Fatalf("unexpected header provenance set: %v", inputs)
	}
	before := workerSnapshot{Inputs: inputs}
	for _, name := range []string{"pkg/include/textflag.h", "pkg/include/funcdata.h", "pkg/include/asm_amd64.h", "pkg/include/asm_other.h", "src/runtime/cgo/abi_amd64.h"} {
		path := filepath.Join(root, name)
		original, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if inputs["toolchain/"+name] != hashBytes(original) {
			t.Fatal("missing actual header path", name)
		}
		if err = os.WriteFile(path, append(append([]byte(nil), original...), []byte("// mutation\n")...), 0o600); err != nil {
			t.Fatal(err)
		}
		changed, err := workerAssemblyHeaderInputs(root)
		if err != nil {
			t.Fatal(err)
		}
		after := workerSnapshot{Inputs: changed}
		if reflect.DeepEqual(before, after) || workerJSONHash(before.Inputs) == workerJSONHash(after.Inputs) {
			t.Fatal("header mutation absent from snapshot", name)
		}
		if err = os.WriteFile(path, original, 0o600); err != nil {
			t.Fatal(err)
		}
		restored, err := workerAssemblyHeaderInputs(root)
		if err != nil || !reflect.DeepEqual(inputs, restored) {
			t.Fatalf("header restore: %s %v", name, err)
		}
	}
	extra := filepath.Join(root, "pkg/include/new.h")
	if err := os.WriteFile(extra, []byte("// added\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := workerAssemblyHeaderInputs(root)
	if err != nil {
		t.Fatal(err)
	}
	if !workerDigest(after["toolchain/pkg/include/new.h"]) || reflect.DeepEqual(inputs, after) {
		t.Fatal("added include omitted")
	}
	// go_asm.h is generated from captured types/compiler, not an invented static input.
	for key := range after {
		if strings.HasSuffix(key, "/go_asm.h") {
			t.Fatal("invented generated header")
		}
	}
}

func TestWorkerAssemblyHeadersRejectMissingAndNonregular(t *testing.T) {
	for _, name := range []string{"pkg/include/textflag.h", "pkg/include/funcdata.h", "pkg/include/asm_amd64.h", "src/runtime/cgo/abi_amd64.h"} {
		t.Run(name, func(t *testing.T) {
			root := workerAssemblyHeaderFixture(t)
			path := filepath.Join(root, name)
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if _, err := workerAssemblyHeaderInputs(root); err == nil {
				t.Fatal("missing required header accepted")
			}
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
			if _, err := workerAssemblyHeaderInputs(root); err == nil {
				t.Fatal("directory accepted as required header")
			}
		})
	}
	root := workerAssemblyHeaderFixture(t)
	if err := os.RemoveAll(filepath.Join(root, "pkg/include")); err != nil {
		t.Fatal(err)
	}
	if _, err := workerAssemblyHeaderInputs(root); err == nil {
		t.Fatal("missing include tree accepted")
	}
}

func TestWorkerAssemblyHeadersRejectSymlinks(t *testing.T) {
	for _, name := range []string{"pkg/include/textflag.h", "pkg/include/asm_other.h", "src/runtime/cgo/abi_amd64.h"} {
		t.Run(name, func(t *testing.T) {
			root := workerAssemblyHeaderFixture(t)
			path := filepath.Join(root, name)
			target := filepath.Join(t.TempDir(), "header.h")
			if err := os.WriteFile(target, []byte("// target\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			if _, err := workerAssemblyHeaderInputs(root); err == nil {
				t.Fatal("symlink header accepted")
			}
		})
	}
	t.Run("include-root", func(t *testing.T) {
		root := workerAssemblyHeaderFixture(t)
		include := filepath.Join(root, "pkg/include")
		moved := filepath.Join(root, "actual-include")
		if err := os.Rename(include, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, include); err != nil {
			t.Fatal(err)
		}
		if _, err := workerAssemblyHeaderInputs(root); err == nil {
			t.Fatal("symlink include root accepted")
		}
	})
	t.Run("goroot", func(t *testing.T) {
		root := workerAssemblyHeaderFixture(t)
		alias := filepath.Join(t.TempDir(), "goroot")
		if err := os.Symlink(root, alias); err != nil {
			t.Fatal(err)
		}
		if _, err := workerAssemblyHeaderInputs(alias); err == nil {
			t.Fatal("symlink toolchain root accepted")
		}
	})
}
