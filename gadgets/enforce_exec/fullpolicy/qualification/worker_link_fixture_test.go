// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"debug/elf"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Execute only an isolated pure-Go extraction of the exact carrier parser/init,
// never a gadget or selected consumer binary. No positive production evidence.
func TestWorkerLinkedInitFixture(t *testing.T) {
	if runtime.Version() != "go1.27.3" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("pinned pure-Go linker fixture")
	}
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	version, err := exec.Command(goPath, "version").Output()
	if err != nil || strings.TrimSpace(string(version)) != "go version go1.27.3 linux/amd64" {
		t.Fatal("fixture requires selected pinned go executable")
	}
	goroot, err := exec.Command(goPath, "env", "GOROOT").Output()
	if err != nil {
		t.Fatal(err)
	}
	for source, want := range workerLinkerSourcePins {
		got, err := workerRegularHash(strings.TrimSpace(string(goroot)), strings.TrimPrefix(source, "toolchain/"))
		if err != nil || got != want {
			t.Fatal("selected linker source changed", source, err)
		}
	}
	source, err := parser.ParseFile(token.NewFileSet(), "../../fullruntime/shared_worker_evidence.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{"sharedWorkerEvidence": true, "sharedWorkerFrozen": true, "sharedWorkerDescriptor": true, "sharedWorkerFrozenEvidence": true, "freezeSharedWorkerEvidence": true, "decodeSharedWorkerDescriptor": true, "parseSharedWorkerEvidence": true, "sharedWorkerHex": true}
	extracted := &ast.File{Name: ast.NewIdent("fullruntime")}
	found := 0
	for _, decl := range source.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if names[d.Name.Name] {
				extracted.Decls = append(extracted.Decls, d)
				found++
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				name := ""
				switch v := spec.(type) {
				case *ast.TypeSpec:
					name = v.Name.Name
				case *ast.ValueSpec:
					if len(v.Names) == 1 {
						name = v.Names[0].Name
					}
				}
				if names[name] {
					extracted.Decls = append(extracted.Decls, &ast.GenDecl{Tok: d.Tok, Specs: []ast.Spec{spec}})
					found++
				}
			}
		}
	}
	if found != len(names) {
		t.Fatal("exact runtime parser/init extraction changed")
	}
	var code bytes.Buffer
	if err = format.Node(&code, token.NewFileSet(), extracted); err != nil {
		t.Fatal(err)
	}
	code.WriteString("\nfunc FixtureAvailable() bool { d,ok:=decodeSharedWorkerDescriptor();return ok && d.bootstrap==1 && d.tail==2 }\n")
	dir := t.TempDir()
	pkg := filepath.Join(dir, "gadgets/enforce_exec/fullruntime")
	if err = os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(pkg, "parser.go"), code.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module "+gadgetModule+"\n\ngo 1.27.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mainSource := "package main\nimport (\"os\"; p \"" + workerRuntimePackage + "\")\nfunc main(){if p.FixtureAvailable() != (len(os.Args)>1) {os.Exit(7)}}\n"
	if err = os.WriteFile(filepath.Join(dir, "main.go"), []byte(mainSource), 0o644); err != nil {
		t.Fatal(err)
	}
	carrier := "IGW10001000101" + strings.Repeat("1", 320) + "0000000000000001" + "0000000000000002"
	for i, flags := range []string{"", "-X " + workerCarrierTarget + "=" + carrier, "-s -w -X " + workerCarrierTarget + "=" + carrier, "-X " + workerCarrierTarget + "Typo=" + carrier} {
		output := filepath.Join(dir, "fixture")
		cmd := exec.Command(goPath, "build", "-ldflags", flags, "-o", output, ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOENV=off", "GOTOOLCHAIN=local", "GOWORK=off", "GOFLAGS=-mod=readonly", "CGO_ENABLED=0")
		if data, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("pure fixture build: %v %s", err, data)
		}
		if i == 1 {
			linked, err := elf.Open(output)
			if err != nil {
				t.Fatal(err)
			}
			symbols, err := linked.Symbols()
			if err != nil {
				_ = linked.Close()
				t.Fatal(err)
			}
			found := false
			for _, symbol := range symbols {
				if symbol.Name != workerCarrierTarget+".str" {
					continue
				}
				found = true
				section := linked.Sections[symbol.Section]
				data, err := section.Data()
				if err != nil {
					_ = linked.Close()
					t.Fatal(err)
				}
				offset := symbol.Value - section.Addr
				if offset > uint64(len(data)) || symbol.Size > uint64(len(data))-offset ||
					!bytes.Equal(data[offset:offset+symbol.Size], append([]byte(carrier), 0)) {
					_ = linked.Close()
					t.Fatal("linked backing is not exact366 wire bytes plus NUL")
				}
				if symbol.Size != uint64(len(carrier)+1) || symbol.Size+16+192 != 575 {
					_ = linked.Close()
					t.Fatalf("linked carrier owner: backing=%d total=%d, model wants575", symbol.Size, symbol.Size+16+192)
				}
			}
			if err := linked.Close(); err != nil {
				t.Fatal(err)
			}
			if !found {
				t.Fatal("exact linked carrier backing symbol absent")
			}
		}
		args := []string{}
		if i == 1 || i == 2 {
			args = append(args, "available")
		}
		if data, err := exec.Command(output, args...).CombinedOutput(); err != nil {
			t.Fatalf("pure fixture init did not consume carrier: %v %s", err, data)
		}
	}
}
