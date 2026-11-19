// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
)

func fixtureReport() consumerReport {
	no := false
	h := strings.Repeat("a", 64)
	profile := map[string]string{"GOVERSION": "go1.27.3"}
	for k, v := range requiredEnvironment {
		profile[k] = v
	}
	profile["GOENV"] = ""
	var manifest map[string]string
	if err := json.Unmarshal(sourceManifest, &manifest); err != nil {
		panic(err)
	}
	tools := map[string]string{}
	for _, k := range []string{"bin/go", "pkg/tool/linux_amd64/compile", "pkg/tool/linux_amd64/asm", "pkg/tool/linux_amd64/link"} {
		tools[k] = h
	}
	inputs := map[string]string{}
	for _, k := range []string{"consumer/go.mod", "consumer/go.sum", "selected-module/go.mod", "fullpolicy/workspace_syntax.go", "fullpolicy/workspace_syntax_test.go", "fullpolicy/qualification/main.go", "fullpolicy/qualification/sources.json"} {
		inputs[k] = h
	}
	module := fixtureModule()
	snapshot := consumerSnapshot{ResolverHashes: publishResolverHashes(map[string]string{}), Modules: []debug.Module{moduleIdentity(module)}, Root: "/consumer", GoExecutable: "/go/bin/go", Profile: profile, AuditedSources: manifest, ToolHashes: tools, Inputs: inputs, GraphHash: h, Package: selectedPackage{ImportPath: testedPackage, Dir: "/module/fullpolicy", Module: &module}, Command: consumerCommand{Target: "./cmd", ImportPath: "example.org/consumer/cmd", MainModule: "example.org/consumer", Files: map[string]string{"cmd/main.go": h}, IdentityLimitation: "not authenticated", ImplicitPGOAbsent: true}}
	return consumerReport{Phase: "PREBUILD", SchemaVersion: evidenceVersion, EvidenceScope: "syntax-model", NativeBudgetQualified: &no, CompleteModelRevision: json.RawMessage("null"), ArtifactLinkage: "ABSENT", AuditedSourceRevision: sourceRevision, Snapshot: snapshot, PassedTests: append([]string(nil), requiredTests...), Runner: runnerIdentity{Executable: "/runner", SHA256: h, BuildInfo: &debug.BuildInfo{GoVersion: "go1.27.3"}, SourceLinkage: "UNPROVEN"}}
}

func TestConsumerStrictReport(t *testing.T) {
	good := fixtureReport()
	data, err := json.Marshal(good)
	if err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string][]byte{
		"valid": data, "missing": []byte(`{}`), "null": []byte(`null`), "malformed": []byte(`{`), "trailing": append(append([]byte(nil), data...), []byte(`{}`)...),
		"duplicate":       []byte(strings.Replace(string(data), `"native_budget_qualified":false`, `"native_budget_qualified":true,"native_budget_qualified":false`, 1)),
		"case-alias":      []byte(strings.Replace(string(data), `"phase":"PREBUILD"`, `"Phase":"PREBUILD"`, 1)),
		"duplicate-alias": []byte(strings.Replace(string(data), `"phase":"PREBUILD"`, `"phase":"BUILD","Phase":"PREBUILD"`, 1)),
		"unknown":         []byte(strings.Replace(string(data), `"evidence_scope"`, `"unrecognized"`, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "report.json")
			if err := os.WriteFile(p, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			_, _, err := readPrebuild(p)
			if (err == nil) != (name == "valid") {
				t.Fatal(err)
			}
		})
	}
	for _, mutate := range []func(*consumerReport){func(r *consumerReport) { *r.NativeBudgetQualified = true }, func(r *consumerReport) { r.CompleteModelRevision = json.RawMessage(`"native-v1"`) }, func(r *consumerReport) { r.PassedTests = r.PassedTests[1:] }, func(r *consumerReport) { r.ArtifactLinkage = "LINKED_BINARY_ONLY" }, func(r *consumerReport) { r.Runner.SourceLinkage = "TRUSTED" }, func(r *consumerReport) { r.Binary = &binaryEvidence{} }} {
		r := fixtureReport()
		mutate(&r)
		if err := validatePrebuild(r); err == nil {
			t.Fatal("accepted incomplete/escalated record")
		}
	}
}

func TestConsumerReportDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "record.json")
	if err := writeReport(path, fixtureReport()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = writeReport(path, map[string]string{"replacement": "bad"}); err == nil {
		t.Fatal("overwrote report")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("changed existing report", err)
	}
}
