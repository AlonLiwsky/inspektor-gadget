// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// This offline fixture exercises capture, not the numerical proof or a release.
// Its minimal packages are never executed, and no PREBUILD/carrier is fabricated.
func TestWorkerCaptureRemoteDependencyReplacement(t *testing.T) {
	if runtime.Version() != "go1.27.3" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("worker capture requires audited local toolchain")
	}
	for key, value := range requiredEnvironment {
		t.Setenv(key, value)
	}
	t.Setenv("GOFIPS140", "off")
	temp := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.WalkDir(temp, func(path string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(path, 0o755)
			}
			return nil
		})
	})
	proxy := filepath.Join(temp, "proxy")
	consumer := filepath.Join(temp, "consumer")
	cache := filepath.Join(temp, "modcache")
	t.Setenv("GOPROXY", "file://"+filepath.ToSlash(proxy))
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOMODCACHE", cache)
	for _, key := range []string{"GOPRIVATE", "GONOPROXY", "GONOSUMDB"} {
		t.Setenv(key, "")
	}
	const (
		igFork = "example.org/fixture/ig"
		dep    = "example.org/fixture/dep"
		fork   = "example.org/fixture/dep-fork"
	)
	original := []byte("package dep\nconst Value = 1\n")
	forkSource := []byte("package dep\nconst Value = 2\n")
	depMod := []byte("module " + dep + "\n\ngo 1.25.0\n")
	writeWorkerProxyModule(t, proxy, dep, "v1.0.0", map[string][]byte{"go.mod": depMod, "value.go": original})
	for _, version := range []string{"v1.0.0", "v1.0.1"} {
		writeWorkerProxyModule(t, proxy, fork, version, map[string][]byte{"go.mod": depMod, "value.go": forkSource})
	}
	writeWorkerProxyModule(t, proxy, igFork, "v1.0.0", map[string][]byte{
		"go.mod": []byte("module " + gadgetModule + "\n\ngo 1.25.0\nrequire " + dep + " v1.0.0\n"),
		"go.sum": {},
		"gadgets/enforce_exec/fullpolicy/workspace_syntax.go":           []byte("package fullpolicy\n"),
		"gadgets/enforce_exec/fullpolicy/workspace_syntax_test.go":      []byte("package fullpolicy\n"),
		"gadgets/enforce_exec/fullpolicy/qualification/main.go":         []byte("package main\nfunc main() {}\n"),
		"gadgets/enforce_exec/fullpolicy/qualification/sources.json":    []byte("{}\n"),
		"gadgets/enforce_exec/fullruntime/shared_worker_integration.go": []byte("package fullruntime\nimport \"" + dep + "\"\nconst Value = dep.Value\n"),
		"gadgets/enforce_exec/fullruntime/shared_operation_context.go":  []byte("package fullruntime\n"),
		"gadgets/enforce_exec/fullruntime/proc_pin.go":                  []byte("package fullruntime\n"),
	})
	if err := os.MkdirAll(filepath.Join(consumer, "cmd"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(t *testing.T, path string, data []byte) {
		t.Helper()
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	consumerMod := []byte(fmt.Sprintf("module example.org/consumer\n\ngo 1.25.0\nrequire (\n%s v1.0.0\n%s v1.0.0 // indirect\n)\nreplace %s => %s v1.0.0\nreplace %s => %s v1.0.0\n", gadgetModule, dep, gadgetModule, igFork, dep, fork))
	write(t, filepath.Join(consumer, "go.mod"), consumerMod)
	write(t, filepath.Join(consumer, "cmd/main.go"), []byte("package main\nimport _ \""+workerRuntimePackage+"\"\nfunc main() {}\n"))
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := commandOutput(goPath, consumer, selectedEnvironment(goPath), "mod", "download", "all"); err != nil {
		t.Fatal(err)
	}
	// Download both immutable versions up front so the version-change control
	// does not confound replacement selection with a consumer checksum change.
	write(t, filepath.Join(consumer, "go.mod"), bytes.ReplaceAll(consumerMod, []byte(fork+" v1.0.0"), []byte(fork+" v1.0.1")))
	if _, err := commandOutput(goPath, consumer, selectedEnvironment(goPath), "mod", "download", "all"); err != nil {
		t.Fatal(err)
	}
	write(t, filepath.Join(consumer, "go.mod"), consumerMod)
	capture := func(t *testing.T) workerSnapshot {
		t.Helper()
		s, err := snapshotWorker(goPath, consumer, "./cmd")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := capture(t)
	for _, name := range []string{"pkg/include/textflag.h", "pkg/include/funcdata.h", "pkg/include/asm_amd64.h", "src/runtime/cgo/abi_amd64.h"} {
		want, err := workerRegularHash(before.Consumer.Profile["GOROOT"], name)
		if err != nil || before.Inputs["toolchain/"+name] != want {
			t.Fatalf("actual assembler header omitted from snapshot: %s: %v", name, err)
		}
	}
	if !reflect.DeepEqual(before, capture(t)) {
		t.Fatal("unchanged worker snapshot is unstable")
	}
	key := "closure/" + dep + "/value.go"
	if got := before.Inputs[key]; got != hashBytes(forkSource) || got == hashBytes(original) {
		t.Fatalf("closure did not capture effective fork bytes: %s", got)
	}
	if _, ok := before.Inputs["closure/"+fork+"/value.go"]; ok {
		t.Fatal("closure key lost original import identity")
	}
	manifestKey := "module/" + fork + "/go.mod"
	if before.Inputs[manifestKey] != hashBytes(depMod) {
		t.Fatal("effective fork manifest missing")
	}
	if _, ok := before.Inputs["module/"+dep+"/go.mod"]; ok {
		t.Fatal("original module manifest captured instead of replacement")
	}
	found := false
	for _, module := range before.Consumer.Modules {
		if module.Path == dep {
			found = true
			if module.Version != "v1.0.0" || module.Replace == nil || module.Replace.Path != fork || module.Replace.Version != "v1.0.0" || !strings.HasPrefix(module.Replace.Sum, "h1:") {
				t.Fatalf("incorrect original/effective MVS identities: %+v", module)
			}
		}
	}
	if !found {
		t.Fatal("original module absent from selected MVS")
	}
	for _, tc := range []struct {
		name, path, key string
		original        []byte
	}{
		{"effective-source", filepath.Join(cache, fork+"@v1.0.0/value.go"), key, forkSource},
		{"effective-manifest", filepath.Join(cache, fork+"@v1.0.0/go.mod"), manifestKey, depMod},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Chmod(tc.path, 0o600); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { write(t, tc.path, tc.original) })
			changed := append(bytes.Clone(tc.original), []byte("\n// changed effective input\n")...)
			write(t, tc.path, changed)
			after := capture(t)
			if after.Inputs[tc.key] != hashBytes(changed) || reflect.DeepEqual(before, after) || workerJSONHash(before.Inputs) == workerJSONHash(after.Inputs) {
				t.Fatal("effective input mutation not committed by worker snapshot")
			}
		})
		if !reflect.DeepEqual(before, capture(t)) {
			t.Fatal("restored effective input did not restore snapshot")
		}
	}
	t.Run("replacement-version", func(t *testing.T) {
		t.Cleanup(func() { write(t, filepath.Join(consumer, "go.mod"), consumerMod) })
		changed := bytes.ReplaceAll(consumerMod, []byte(fork+" v1.0.0"), []byte(fork+" v1.0.1"))
		write(t, filepath.Join(consumer, "go.mod"), changed)
		after := capture(t)
		if reflect.DeepEqual(before, after) || before.Inputs["consumer/go.mod"] == after.Inputs["consumer/go.mod"] || reflect.DeepEqual(before.Consumer.Modules, after.Consumer.Modules) {
			t.Fatal("replacement version change not committed by worker snapshot")
		}
		if after.Inputs[key] != before.Inputs[key] {
			t.Fatal("version control should retain identical source bytes")
		}
	})
	if !reflect.DeepEqual(before, capture(t)) {
		t.Fatal("restored replacement selection did not restore snapshot")
	}
	// runWorker compares snapshots with DeepEqual, but that boundary follows
	// numerical proof validation. This capture-only fixture deliberately cannot
	// reach it and must not manufacture a passing PREBUILD to do so.
	if _, err := deriveWorkerTail(before); err == nil {
		t.Fatal("capture fixture unexpectedly qualified numerical worker proof")
	}
}

func writeWorkerProxyModule(t *testing.T, proxy, path, version string, files map[string][]byte) {
	t.Helper()
	var archive bytes.Buffer
	writer := zip.NewWriter(&archive)
	for name, data := range files {
		entry, err := writer.Create(path + "@" + version + "/" + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = entry.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(proxy, path, "@v")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		version + ".mod": files["go.mod"], version + ".zip": archive.Bytes(),
		version + ".info": []byte(fmt.Sprintf(`{"Version":%q,"Time":"2026-10-30T00:00:00Z"}`, version)),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
