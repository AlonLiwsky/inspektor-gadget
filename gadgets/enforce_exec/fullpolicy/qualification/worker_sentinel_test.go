// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
)

type sentinelFixtureImporter map[string]*types.Package

func (m sentinelFixtureImporter) Import(path string) (*types.Package, error) { return m[path], nil }

func TestWorkerSentinelSemanticIdentity(t *testing.T) {
	target := types.NewPackage(workerSentinelPackage, "ebpf")
	target.Scope().Insert(types.NewVar(token.NoPos, target, "ErrNotSupported", types.Universe.Lookup("error").Type()))
	target.MarkComplete()
	other := types.NewPackage("example.org/other", "other")
	other.Scope().Insert(types.NewVar(token.NoPos, other, "ErrNotSupported", types.Universe.Lookup("error").Type()))
	other.MarkComplete()
	importer := sentinelFixtureImporter{workerSentinelPackage: target, "example.org/other": other, "unsafe": types.Unsafe}
	for _, tc := range []struct{ name, source, want string }{
		{"read", `package p; import b "github.com/cilium/ebpf"; var copy = b.ErrNotSupported`, ""},
		{"alias-write", `package p; import b "github.com/cilium/ebpf"; func f(){ b.ErrNotSupported = nil }`, "sentinel assignment"},
		{"dot-write", `package p; import . "github.com/cilium/ebpf"; func f(){ ErrNotSupported = nil }`, "sentinel assignment"},
		{"multiple-write", `package p; import b "github.com/cilium/ebpf"; func f(){ var e error; e, b.ErrNotSupported = nil, e }`, "sentinel assignment"},
		{"range-write", `package p; import b "github.com/cilium/ebpf"; func f(){ for _, b.ErrNotSupported = range []error{} {} }`, "sentinel assignment"},
		{"address", `package p; import b "github.com/cilium/ebpf"; var ptr = &(b.ErrNotSupported)`, "sentinel address"},
		{"shadow", `package p; import b "github.com/cilium/ebpf"; var copy=b.ErrNotSupported; func f(){ b:=struct{ErrNotSupported error}{}; b.ErrNotSupported=nil; _=&b.ErrNotSupported }`, ""},
		{"dot-shadow", `package p; import . "github.com/cilium/ebpf"; var copy=ErrNotSupported; func f(){ ErrNotSupported:=error(nil); ErrNotSupported=nil; _=&ErrNotSupported }`, ""},
		{"other-package", `package p; import "example.org/other"; func f(){other.ErrNotSupported=nil; _=&other.ErrNotSupported}`, ""},
		{"ill-typed", `package p; import b "github.com/cilium/ebpf"; var copy = b.DoesNotExist`, "type check"},
		{"target-linkname", "package p\nimport _ \"unsafe\"\n//go:linkname alias github.com/cilium/ebpf.ErrNotSupported\nvar alias error\n", "sentinel linkname"},
		{"other-linkname", "package p\nimport _ \"unsafe\"\n//go:linkname alias example.org/other.ErrNotSupported\nvar alias error\n", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, "fixture.go", tc.source, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			err = checkWorkerSentinelAST(fset, []*ast.File{f}, "example.org/p", "go1.27", importer)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestWorkerSentinelOwnPackage(t *testing.T) {
	for _, tc := range []struct{ name, extra, want string }{
		{"declaration", "", ""},
		{"write", "func f(){ErrNotSupported=nil}", "sentinel assignment"},
		{"address", "var ptr=&ErrNotSupported", "sentinel address"},
		{"linkname", "//go:linkname ErrNotSupported\n", "sentinel linkname"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := token.NewFileSet()
			f, err := parser.ParseFile(fs, "fixture.go", "package ebpf\nvar ErrNotSupported error\n"+tc.extra, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			err = checkWorkerSentinelAST(fs, []*ast.File{f}, workerSentinelPackage, "go1.27", sentinelFixtureImporter{})
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v want %q", err, tc.want)
			}
		})
	}
}

// This fixture compiles a tiny offline replacement graph. Its init panics if
// executed; neither the selected command nor any dependency init is ever run.
func TestWorkerSentinelSelectedExports(t *testing.T) {
	if runtime.Version() != "go1.27.3" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("requires selected toolchain")
	}
	for k, v := range requiredEnvironment {
		t.Setenv(k, v)
	}
	t.Setenv("GOFIPS140", "off")
	root := t.TempDir()
	proxy := filepath.Join(root, "proxy")
	consumer := filepath.Join(root, "consumer")
	cache := filepath.Join(root, "cache")
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(path, 0o755)
			}
			return nil
		})
	})
	t.Setenv("GOPROXY", "file://"+proxy)
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOMODCACHE", cache)
	for _, k := range []string{"GOPRIVATE", "GONOPROXY", "GONOSUMDB"} {
		t.Setenv(k, "")
	}
	writeWorkerProxyModule(t, proxy, "example.org/ebpf-fork", "v1.0.0", map[string][]byte{
		"go.mod":      []byte("module " + workerSentinelPackage + "\n\ngo 1.26\n"),
		"sentinel.go": []byte("package ebpf\nvar ErrNotSupported error\nfunc init(){panic(\"fixture must never execute\")}\n"),
	})
	if err := os.MkdirAll(filepath.Join(consumer, "cmd"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, source string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(consumer, name), []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.org/consumer\n\ngo 1.27\nrequire "+workerSentinelPackage+" v1.0.0\nreplace "+workerSentinelPackage+" => example.org/ebpf-fork v1.0.0\n")
	source := "package main\nimport b \"github.com/cilium/ebpf\"\nvar copy=b.ErrNotSupported\nfunc main(){}\n"
	write("cmd/main.go", source)
	if !filepath.IsAbs(os.Getenv("GOROOT")) {
		t.Skip("requires explicit selected GOROOT")
	}
	goPath := filepath.Join(os.Getenv("GOROOT"), "bin", "go")
	if _, err := commandOutput(goPath, consumer, selectedEnvironment(goPath), "mod", "download", "all"); err != nil {
		t.Fatal(err)
	}
	capture := func() (workerSnapshot, []workerSentinelPackageInfo) {
		t.Helper()
		data, err := commandOutput(goPath, consumer, selectedEnvironment(goPath), "list", "-deps", "-compiled", "-export", "-json", "./cmd")
		if err != nil {
			t.Fatal(err)
		}
		s := workerSnapshot{Inputs: map[string]string{}, Consumer: consumerSnapshot{GoExecutable: goPath, Root: consumer, Command: consumerCommand{Target: "./cmd"}, Profile: map[string]string{"GOVERSION": runtime.Version()}}}
		var ps []workerSentinelPackageInfo
		d := json.NewDecoder(bytes.NewReader(data))
		for {
			var p workerSentinelPackageInfo
			err = d.Decode(&p)
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			ps = append(ps, p)
			s.Packages = append(s.Packages, p.ImportPath)
			for _, list := range [][]string{p.GoFiles, p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.FFiles, p.SFiles, p.SysoFiles, p.EmbedFiles} {
				for _, name := range list {
					h, err := workerRegularHash(p.Dir, filepath.ToSlash(name))
					if err != nil {
						t.Fatal(err)
					}
					s.Inputs["closure/"+p.ImportPath+"/"+filepath.ToSlash(name)] = h
				}
			}
		}
		sort.Strings(s.Packages)
		return s, ps
	}
	baseline, packages := capture()
	evidence, err := proveWorkerSentinel(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(evidence.CheckedPackages, workerSentinelPackage) || !slices.Contains(evidence.CheckedPackages, "example.org/consumer/cmd") || !workerDigest(evidence.InputsSHA256) || !workerDigest(evidence.ExportSHA256[workerSentinelPackage]) {
		t.Fatalf("incomplete semantic evidence: %+v", evidence)
	}
	for _, tc := range []struct{ name, extra, want string }{
		{"direct-write", "func init(){b.ErrNotSupported=nil}\n", "sentinel assignment"},
		{"address", "var address=&b.ErrNotSupported\n", "sentinel address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write("cmd/main.go", source+tc.extra)
			t.Cleanup(func() { write("cmd/main.go", source) })
			s, _ := capture()
			if _, err := proveWorkerSentinel(s); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v want %q", err, tc.want)
			}
		})
	}
	t.Run("changed-source", func(t *testing.T) {
		write("cmd/main.go", source+"// changed\n")
		t.Cleanup(func() { write("cmd/main.go", source) })
		if _, err := proveWorkerSentinel(baseline); err == nil || !strings.Contains(err.Error(), "source differs") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("uncaptured-source", func(t *testing.T) {
		s := baseline
		s.Inputs = maps.Clone(baseline.Inputs)
		delete(s.Inputs, "closure/example.org/consumer/cmd/main.go")
		if _, err := checkWorkerSentinelClosure(s, packages); err == nil {
			t.Fatal("accepted missing captured input")
		}
	})
	t.Run("extra-captured-source", func(t *testing.T) {
		s := baseline
		s.Inputs = maps.Clone(baseline.Inputs)
		s.Inputs["closure/example.org/consumer/cmd/hidden.go"] = hashBytes([]byte("hidden"))
		if _, err := checkWorkerSentinelClosure(s, packages); err == nil {
			t.Fatal("accepted extra captured input")
		}
	})
	t.Run("uncaptured-generated-input", func(t *testing.T) {
		ps := slices.Clone(packages)
		ps[len(ps)-1].CompiledGoFiles = []string{"generated.go"}
		if _, err := checkWorkerSentinelClosure(baseline, ps); err == nil {
			t.Fatal("accepted mismatched compiled input")
		}
	})
	t.Run("corrupt-export", func(t *testing.T) {
		ps := slices.Clone(packages)
		bad := filepath.Join(t.TempDir(), "invalid-export")
		if err := os.WriteFile(bad, []byte("not a Go export archive"), 0o600); err != nil {
			t.Fatal(err)
		}
		for i := range ps {
			if ps[i].ImportPath == workerSentinelPackage {
				ps[i].Export = bad
			}
		}
		if _, err := checkWorkerSentinelClosure(baseline, ps); err == nil || !strings.Contains(err.Error(), "type check") {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("missing-export", func(t *testing.T) {
		ps := slices.Clone(packages)
		ps[0].Export = ""
		if _, err := checkWorkerSentinelClosure(baseline, ps); err == nil {
			t.Fatal("accepted missing export data")
		}
	})
}
