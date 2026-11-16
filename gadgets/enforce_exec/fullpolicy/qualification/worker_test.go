// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWorkerEvidenceRefusesIncompleteAndCrossScope(t *testing.T) {
	if _, err := decodeWorkerPrebuild([]byte(`{"schema_version":1,"phase":"PREBUILD","evidence_scope":"syntax-model"}`)); err == nil {
		t.Fatal("cross-scope accepted")
	}
	for _, raw := range []string{`{"phase":"PREBUILD","phase":"BUILD"}`, `{"unknown":true}`, `{}`, `{} {}`} {
		if _, err := decodeWorkerPrebuild([]byte(raw)); err == nil {
			t.Fatal("noncanonical incomplete report accepted")
		}
	}
	if _, err := deriveWorkerTail(workerSnapshot{}); err == nil {
		t.Fatal("missing source/dependency proof accepted")
	}
}

func TestWorkerLinkerAssignmentExact(t *testing.T) {
	carrier := "IGW1" + "0001" + "0001" + "01" + strings.Repeat("1", 320) + "0000000000000001" + "0000000000000002"
	exact := "-X " + workerCarrierTarget + "=" + carrier
	if err := checkWorkerLinkerFlags(exact, carrier); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", exact + " " + exact, "-X other=" + carrier, exact + " -X arbitrary=x", exact + " -buildid=x"} {
		if err := checkWorkerLinkerFlags(bad, carrier); err == nil {
			t.Fatal("unexpected linker flags accepted")
		}
	}
	if err := checkLinkerFlags(exact); err == nil {
		t.Fatal("syntax linker allowlist widened")
	}
}

func TestWorkerProcBoundPinnedAndNotWholeProof(t *testing.T) {
	s := workerSnapshot{Consumer: consumerSnapshot{Profile: map[string]string{"GOVERSION": "go1.27.3", "GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1", "CGO_ENABLED": "0", "GOEXPERIMENT": "", "GODEBUG": ""}}, Inputs: map[string]string{}}
	for k, v := range requiredEnvironment {
		s.Consumer.Profile[k] = v
	}
	s.Consumer.Profile["GOENV"] = ""
	for k, v := range workerProcSourcePins {
		s.Inputs[k] = v
	}
	if bound, err := workerProcBound(s); err != nil || bound != 1310800 {
		t.Fatal(bound, err)
	}
	for k, v := range workerProcSourcePins {
		s.Inputs[k] = strings.Repeat("f", 64)
		if _, err := workerProcBound(s); err == nil {
			t.Fatal("mutated reviewed source accepted")
		}
		s.Inputs[k] = v
	}
	s.Consumer.Profile["GOEXPERIMENT"] = "greenteagc"
	if _, err := workerProcBound(s); err == nil {
		t.Fatal("unproved alias profile admitted")
	}
}

func TestWorkerEventsRequireActualExactRuns(t *testing.T) {
	valid := []byte("{\"Action\":\"start\",\"Package\":\"p\"}\n{\"Action\":\"run\",\"Package\":\"p\",\"Test\":\"T\"}\n{\"Action\":\"pass\",\"Package\":\"p\",\"Test\":\"T\"}\n{\"Action\":\"pass\",\"Package\":\"p\"}\n")
	if _, err := checkWorkerEvents(valid, "p", []string{"T"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{strings.ReplaceAll(string(valid), "\"run\"", "\"skip\""), strings.ReplaceAll(string(valid), "\"T\"", "\"T/other\""), strings.ReplaceAll(string(valid), "\"p\"", "\"other\""), string(valid) + string(valid)} {
		if _, err := checkWorkerEvents([]byte(bad), "p", []string{"T"}); err == nil {
			t.Fatal("bad event stream admitted")
		}
	}
	if _, err := checkWorkerEvents(valid, "p", []string{"T", "missing"}); err == nil {
		t.Fatal("missing exact check admitted")
	}
}

func TestWorkerCaptureRejectsAliasAndNonregular(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file", filepath.Join(root, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alias", "../file", "./file", ""} {
		if _, err := workerRegularHash(root, name); err == nil {
			t.Fatal("invalid capture admitted")
		}
	}
	if _, err := workerRegularHash(root, "file"); err != nil {
		t.Fatal(err)
	}
}

func TestWorkerBuildRecipeAndInitEvidenceStrict(t *testing.T) {
	carrier := "IGW10001000101" + strings.Repeat("1", 320) + "0000000000000001" + "0000000000000002"
	args, err := workerBuildArgs("./cmd", "/tmp/new-output", carrier)
	if err != nil || len(args) != 7 || args[0] != "build" || args[1] != "-buildvcs=false" || args[2] != "-ldflags" || args[3] != "-X "+workerCarrierTarget+"="+carrier || args[6] != "./cmd" {
		t.Fatal("controlled argv changed", args, err)
	}
	for _, target := range []string{"main.go", "./cmd -tags=evil", "../cmd", "./..."} {
		if _, err := workerBuildArgs(target, "out", carrier); err == nil {
			t.Fatal("target modifier admitted")
		}
	}
	for _, bad := range []string{carrier[:14] + "A" + carrier[15:], carrier[:334] + strings.Repeat("f", 16) + "0000000000000001", carrier[:14] + strings.Repeat("0", 64) + carrier[78:]} {
		if err := checkWorkerLinkerFlags("-X "+workerCarrierTarget+"="+bad, bad); err == nil {
			t.Fatal("noncanonical carrier admitted")
		}
	}
	valid := workerRuntimePackage + ".init STEXT\n" + workerCarrierTarget + "(SB)\n" + workerRuntimePackage + ".parseSharedWorkerEvidence(SB)\n" + workerRuntimePackage + ".sharedWorkerFrozen\nnext STEXT"
	if err := checkWorkerInitLowering(valid); err != nil {
		t.Fatal(err)
	}
	for _, symbol := range []string{workerCarrierTarget, workerRuntimePackage + ".parseSharedWorkerEvidence", workerRuntimePackage + ".sharedWorkerFrozen"} {
		if err := checkWorkerInitLowering(strings.ReplaceAll(valid, symbol, "unrelated")); err == nil {
			t.Fatal("unconsumed carrier accepted")
		}
	}
}

func TestWorkerIncompleteProofCannotEmitCarrier(t *testing.T) {
	r := workerPrebuildV1{SchemaVersion: 1, Phase: "PREBUILD", EvidenceScope: workerScope, AccountingDomain: workerModel, ModelRevision: "worker-model-v1", NativeActivation: "NOT_QUALIFIED"}
	r.Snapshot = workerProjectFixture()
	for pkg, names := range requiredWorkerChecks() {
		for _, name := range names {
			r.Checks = append(r.Checks, workerCheck{Package: pkg, Test: name, EventsSHA256: strings.Repeat("2", 64)})
		}
	}
	for pkg, names := range workerGeneratedChecks() {
		for _, name := range names {
			r.Checks = append(r.Checks, workerCheck{Package: pkg, Test: name, EventsSHA256: strings.Repeat("2", 64)})
		}
	}
	r.InputsSHA256 = workerJSONHash(r.Snapshot.Inputs)
	r.ProfileSHA256 = workerProfileHash(r.Snapshot)
	r.ChecksSHA256 = workerJSONHash(r.Checks)
	r.TailProofSHA256 = workerJSONHash(r.TailProof)
	const unresolved = workerMissingDependency
	if _, err := workerCarrier(r, strings.Repeat("3", 64)); err == nil || err.Error() != unresolved {
		t.Fatalf("expected unresolved numerical proof refusal, got %v", err)
	}
	// A linker-pin failure is a different gate from the unresolved tail.
	// Mutate each pin independently and restore it before testing the next.
	for source, want := range workerLinkerSourcePins {
		for _, replacement := range []string{"", strings.Repeat("f", 64)} {
			r.Snapshot.Inputs[source] = replacement
			r.InputsSHA256 = workerJSONHash(r.Snapshot.Inputs)
			if _, err := workerCarrier(r, strings.Repeat("3", 64)); err == nil || err.Error() != "worker linker source pin mismatch" {
				t.Fatalf("linker mutation %s: got %v", source, err)
			}
		}
		r.Snapshot.Inputs[source] = want
	}
	r.InputsSHA256 = workerJSONHash(r.Snapshot.Inputs)
	if _, err := workerCarrier(r, strings.Repeat("3", 64)); err == nil || err.Error() != unresolved {
		t.Fatalf("restored pins must reach unresolved tail, got %v", err)
	}
	for _, change := range []func(*workerPrebuildV1){
		func(p *workerPrebuildV1) { p.EvidenceScope = "syntax-model" },
		func(p *workerPrebuildV1) { p.InputsSHA256 = strings.Repeat("4", 64) },
		func(p *workerPrebuildV1) { p.BootstrapBytes = 536; p.TailBytes = 1310800 },
		func(p *workerPrebuildV1) { p.Phase = "BUILD" },
	} {
		copy := r
		change(&copy)
		data, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := decodeWorkerPrebuild(data); err == nil {
			t.Fatal("mutated/incomplete record accepted")
		}
	}
}
