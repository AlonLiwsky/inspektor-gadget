// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func TestWorkerSentinelGeneratedCheckRequired(t *testing.T) {
	var checks []workerCheck
	for pkg, names := range requiredWorkerChecks() {
		for _, name := range names {
			checks = append(checks, workerCheck{Package: pkg, Test: name, EventsSHA256: strings.Repeat("a", 64)})
		}
	}
	for pkg, names := range workerGeneratedChecks() {
		for _, name := range names {
			checks = append(checks, workerCheck{Package: pkg, Test: name, EventsSHA256: strings.Repeat("a", 64)})
		}
	}
	if err := validateWorkerChecks(checks); err != nil {
		t.Fatal(err)
	}
	found := false
	for i, check := range checks {
		if check.Test != workerSentinelProofCheckName {
			continue
		}
		found = true
		if check.Package != testedPackage+"/qualification" {
			t.Fatal("semantic check package identity changed")
		}
		missing := append([]workerCheck(nil), checks[:i]...)
		missing = append(missing, checks[i+1:]...)
		if err := validateWorkerChecks(missing); err == nil {
			t.Fatal("missing generated semantic proof accepted")
		}
		for _, bad := range []workerCheck{
			{Package: workerRuntimePackage, Test: check.Test, EventsSHA256: check.EventsSHA256},
			{Package: check.Package, Test: "proof:sentinel-nonmutation", EventsSHA256: check.EventsSHA256},
			{Package: check.Package, Test: check.Test},
		} {
			changed := append([]workerCheck(nil), checks...)
			changed[i] = bad
			if err := validateWorkerChecks(changed); err == nil {
				t.Fatal("invalid semantic identity/scope/digest accepted")
			}
		}
	}
	if !found {
		t.Fatal("semantic check missing from generated requirements")
	}
	if _, err := deriveWorkerTail(workerProjectFixture()); err == nil || err.Error() != workerMissingDependency {
		t.Fatalf("aggregate refusal changed: %v", err)
	}
}

// This versioned offline graph reaches the real snapshot and producer helper.
// Its dependency init panics if executed; only compiler/export-data work runs.
// It deliberately cannot produce PREBUILD or reach the guarded BUILD phase.
func TestWorkerSentinelProducerSelectedConsumer(t *testing.T) {
	if runtime.Version() != "go1.27.3" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("requires selected toolchain")
	}
	for key, value := range requiredEnvironment {
		t.Setenv(key, value)
	}
	t.Setenv("GOFIPS140", "off")
	root := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(path, 0o755)
			}
			return nil
		})
	})
	proxy, consumer, cache := filepath.Join(root, "proxy"), filepath.Join(root, "consumer"), filepath.Join(root, "cache")
	t.Setenv("GOPROXY", "file://"+proxy)
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOMODCACHE", cache)
	for _, key := range []string{"GOPRIVATE", "GONOPROXY", "GONOSUMDB"} {
		t.Setenv(key, "")
	}
	const igFork = "example.org/fixture/ig"
	const ebpfFork = "example.org/fixture/ebpf"
	writeWorkerProxyModule(t, proxy, ebpfFork, "v1.0.0", map[string][]byte{
		"go.mod":      []byte("module " + workerSentinelPackage + "\n\ngo 1.26\n"),
		"sentinel.go": []byte("package ebpf\nvar ErrNotSupported error\nfunc init(){panic(\"never execute fixture\")}\n"),
	})
	writeWorkerProxyModule(t, proxy, igFork, "v1.0.0", map[string][]byte{
		"go.mod": []byte("module " + gadgetModule + "\n\ngo 1.26\nrequire " + workerSentinelPackage + " v1.0.0\n"),
		"go.sum": {},
		"gadgets/enforce_exec/fullpolicy/workspace_syntax.go":           []byte("package fullpolicy\n"),
		"gadgets/enforce_exec/fullpolicy/workspace_syntax_test.go":      []byte("package fullpolicy\n"),
		"gadgets/enforce_exec/fullpolicy/qualification/main.go":         []byte("package main\nfunc main(){}\n"),
		"gadgets/enforce_exec/fullpolicy/qualification/sources.json":    []byte("{}\n"),
		"gadgets/enforce_exec/fullruntime/shared_worker_integration.go": []byte("package fullruntime\nimport b \"" + workerSentinelPackage + "\"\nvar Copy=b.ErrNotSupported\n"),
		"gadgets/enforce_exec/fullruntime/shared_operation_context.go":  []byte("package fullruntime\n"),
		"gadgets/enforce_exec/fullruntime/proc_pin.go":                  []byte("package fullruntime\n"),
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
	write("go.mod", "module example.org/consumer\n\ngo 1.27\nrequire (\n"+gadgetModule+" v1.0.0\n"+workerSentinelPackage+" v1.0.0\n)\nreplace "+gadgetModule+" => "+igFork+" v1.0.0\nreplace "+workerSentinelPackage+" => "+ebpfFork+" v1.0.0\n")
	source := "package main\nimport _ \"" + workerRuntimePackage + "\"\nimport b \"" + workerSentinelPackage + "\"\nvar copy=b.ErrNotSupported\nfunc main(){}\n"
	write("cmd/main.go", source)
	if !filepath.IsAbs(os.Getenv("GOROOT")) {
		t.Skip("requires explicit selected GOROOT")
	}
	goPath := filepath.Join(os.Getenv("GOROOT"), "bin", "go")
	if _, err := commandOutput(goPath, consumer, selectedEnvironment(goPath), "mod", "download", "all"); err != nil {
		t.Fatal(err)
	}
	capture := func() workerSnapshot {
		t.Helper()
		s, err := snapshotWorker(goPath, consumer, "./cmd")
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := capture()
	check, err := proveWorkerSentinelCheck(before)
	if err != nil {
		t.Fatal(err)
	}
	if check.Package != testedPackage+"/qualification" || check.Test != workerSentinelProofCheckName || !workerDigest(check.EventsSHA256) {
		t.Fatalf("wrong generated check: %+v", check)
	}
	evidence, err := proveWorkerSentinel(before)
	if err != nil {
		t.Fatal(err)
	}
	runner, err := workerRunner(before)
	if err != nil {
		t.Fatal(err)
	}
	if runner.SourceLinkage != "UNPROVEN" {
		t.Fatal("runner linkage promoted")
	}
	payload := struct {
		SnapshotSHA256 string
		Runner         runnerIdentity
		Result         workerSentinelEvidence
	}{workerJSONHash(before), runner, evidence}
	if check.EventsSHA256 != workerJSONHash(payload) {
		t.Fatal("check does not bind canonical semantic result/snapshot/runner")
	}
	for _, mutate := range []func(){
		func() { payload.Result.Scope = "full-nonmutation" },
		func() {
			payload.Result.ExportSHA256 = maps.Clone(evidence.ExportSHA256)
			payload.Result.ExportSHA256[workerSentinelPackage] = strings.Repeat("e", 64)
		},
		func() { payload.Runner.SHA256 = strings.Repeat("e", 64) },
		func() {
			changed := before
			changed.Consumer.Profile = maps.Clone(before.Consumer.Profile)
			changed.Consumer.Profile["GOAMD64"] = "v2"
			payload.SnapshotSHA256 = workerJSONHash(changed)
		},
		func() {
			changed := before
			changed.Consumer.ToolHashes = maps.Clone(before.Consumer.ToolHashes)
			changed.Consumer.ToolHashes["bin/go"] = strings.Repeat("e", 64)
			payload.SnapshotSHA256 = workerJSONHash(changed)
		},
	} {
		payload.SnapshotSHA256 = workerJSONHash(before)
		payload.Runner = runner
		payload.Result = evidence
		mutate()
		if workerJSONHash(payload) == check.EventsSHA256 {
			t.Fatal("semantic check binding did not change")
		}
	}
	if !reflect.DeepEqual(before, capture()) {
		t.Fatal("generated checker changed source snapshot")
	}
	for _, tc := range []struct{ name, extra, want string }{
		{"write", "func init(){b.ErrNotSupported=nil}\n", "sentinel assignment"},
		{"address", "var address=&b.ErrNotSupported\n", "sentinel address"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			write("cmd/main.go", source+tc.extra)
			t.Cleanup(func() { write("cmd/main.go", source) })
			if _, err := proveWorkerSentinelCheck(capture()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v want %q", err, tc.want)
			}
		})
	}
	write("cmd/main.go", source+"// changed source\n")
	if _, err := proveWorkerSentinelCheck(before); err == nil {
		t.Fatal("stale source accepted")
	}
	changed := capture()
	fresh, err := proveWorkerSentinelCheck(changed)
	if err != nil {
		t.Fatal(err)
	}
	if fresh.EventsSHA256 == check.EventsSHA256 {
		t.Fatal("new source/export snapshot reused old semantic digest")
	}
	write("cmd/main.go", source)
	if !reflect.DeepEqual(before, capture()) {
		t.Fatal("fixture not restored")
	}
	if _, err := deriveWorkerTail(before); err == nil {
		t.Fatal("offline semantic fixture qualified numerical proof")
	}
}
