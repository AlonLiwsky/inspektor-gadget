// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"math"
	"reflect"
	"strings"
	"testing"
)

func workerCompositionChecks() []workerCheck {
	var checks []workerCheck
	for _, required := range []map[string][]string{requiredWorkerChecks(), workerGeneratedChecks()} {
		for pkg, names := range required {
			for _, name := range names {
				checks = append(checks, workerCheck{Package: pkg, Test: name, EventsSHA256: hashBytes([]byte(pkg + "/" + name))})
			}
		}
	}
	return checks
}

func TestWorkerConditionalComposition(t *testing.T) {
	s := workerDependencyFixture()
	checks := workerCompositionChecks()
	got, err := deriveWorkerConditionalComposition(s, checks)
	if err != nil || got.Bootstrap != 536 || got.Tail != 1312254 {
		t.Fatalf("%+v %v", got, err)
	}
	total, err := workerProofSum(got.Bootstrap, got.Tail)
	if err != nil || total != 1312790 {
		t.Fatal(total, err)
	}
	if len(got.Terms) != 5 {
		t.Fatal(got.Terms)
	}
	wantTerms := map[string]struct {
		source, check string
		bytes         uint64
	}{
		"bootstrap":                 {"fullruntime/shared_operation_context.go", workerRuntimePackage + "/" + workerRuntimeProofCheckName, 536},
		"project-tail":              {"fullruntime/proc_pin.go", workerRuntimePackage + "/" + workerRuntimeProofCheckName, 1310800},
		"dependency-tail":           {"closure/github.com/cilium/ebpf/map.go", workerRuntimePackage + "/" + workerDependencyProofCheckName, 1454},
		"dependency-stdlib-premise": {"toolchain/src/encoding/binary/binary.go", workerRuntimePackage + "/" + workerDependencyStdlibProofCheckName, 0},
		"compiler-debit-premise":    {"fullpolicy/workspace_limited.go", testedPackage + "/" + workerCompilerProofCheckName, 0},
	}
	associated := map[string]bool{}
	var sum uint64
	for _, term := range got.Terms {
		want, ok := wantTerms[term.Name]
		if !ok || term.Source != want.source || term.Check != want.check || term.Bytes != want.bytes {
			t.Fatal("wrong ownership/check association", term)
		}
		delete(wantTerms, term.Name)
		associated[term.Check] = true
		if term.SourceSHA256 != s.Inputs[term.Source] || !workerDigest(term.SourceSHA256) || term.Formula == "" || term.Symbol == "" || term.Lifetime == "" {
			t.Fatal("missing source/model term", term)
		}
		found := false
		for _, check := range checks {
			if term.Check == check.Package+"/"+check.Test {
				found = true
				if term.ArtifactSHA256 != check.EventsSHA256 || term.ArtifactSHA256 == term.SourceSHA256 {
					t.Fatal("wrong generated artifact", term, check)
				}
			}
		}
		if !found {
			t.Fatal("unmatched generated check", term)
		}
		sum, err = workerProofSum(sum, term.Bytes)
		if err != nil {
			t.Fatal(err)
		}
	}
	if sum != total {
		t.Fatal("startup or compiler owners incorrectly added to fixed terms", sum, total)
	}
	// Complete worker qualification stays unavailable even though arithmetic composes.
	if _, err := deriveWorkerTail(s); err == nil || err.Error() != workerMissingDependency {
		t.Fatal("aggregate refusal changed", err)
	}
	// Distinct valid artifact hashes change the recomposed record, not its bytes.
	for i, check := range checks {
		if !associated[check.Package+"/"+check.Test] {
			continue
		}
		checks[i].EventsSHA256 = hashBytes([]byte("different selected lowering"))
		changed, err := deriveWorkerConditionalComposition(s, checks)
		if err != nil || changed.Tail != got.Tail || changed.Bootstrap != got.Bootstrap || reflect.DeepEqual(changed, got) || workerJSONHash(changed) == workerJSONHash(got) {
			t.Fatal("artifact change not bound", changed, err)
		}
		checks[i] = check
	}
}

func TestWorkerConditionalCompositionRejectsIncompleteEvidence(t *testing.T) {
	s := workerDependencyFixture()
	checks := workerCompositionChecks()
	for i, check := range checks {
		missing := append([]workerCheck(nil), checks[:i]...)
		missing = append(missing, checks[i+1:]...)
		if _, err := deriveWorkerConditionalComposition(s, missing); err == nil {
			t.Fatal("missing check accepted", check)
		}
		duplicate := append(append([]workerCheck(nil), checks...), check)
		if _, err := deriveWorkerConditionalComposition(s, duplicate); err == nil {
			t.Fatal("duplicate check accepted", check)
		}
		for _, bad := range []workerCheck{
			{Package: "wrong/package", Test: check.Test, EventsSHA256: check.EventsSHA256},
			{Package: check.Package, Test: "wrong/check", EventsSHA256: check.EventsSHA256},
			{Package: check.Package, Test: check.Test, EventsSHA256: ""},
			{Package: check.Package, Test: check.Test, EventsSHA256: strings.Repeat("0", 64)},
			{Package: check.Package, Test: check.Test, EventsSHA256: strings.Repeat("A", 64)},
		} {
			checks[i] = bad
			if _, err := deriveWorkerConditionalComposition(s, checks); err == nil {
				t.Fatal("mismatched check accepted", bad)
			}
		}
		checks[i] = check
	}
	for _, key := range []string{"fullruntime/shared_operation_context.go", "fullruntime/proc_pin.go", "closure/github.com/cilium/ebpf/map.go", "toolchain/src/encoding/binary/binary.go", "fullpolicy/workspace_limited.go", "fullruntime/shared_host.go"} {
		old := s.Inputs[key]
		s.Inputs[key] = strings.Repeat("f", 64)
		if _, err := deriveWorkerConditionalComposition(s, checks); err == nil {
			t.Fatal("changed source accepted", key)
		}
		s.Inputs[key] = old
	}
	s.RawProfile["GOEXPERIMENT"] = "changed"
	if _, err := deriveWorkerConditionalComposition(s, checks); err == nil {
		t.Fatal("changed raw profile accepted")
	}
	s.RawProfile["GOEXPERIMENT"] = ""
	s.Consumer.Profile["GOFIPS140"] = "latest"
	if _, err := deriveWorkerConditionalComposition(s, checks); err == nil {
		t.Fatal("changed profile accepted")
	}
}

func TestWorkerCompositionCheckedAddition(t *testing.T) {
	// Both tail addition and bootstrap+tail use this same checked helper.
	for _, values := range [][]uint64{{math.MaxUint64, 1}, {536, math.MaxUint64}, {1310800, math.MaxUint64}} {
		if _, err := workerProofSum(values...); err == nil {
			t.Fatal("overflow accepted", values)
		}
	}
	if got, err := workerProofSum(1310800, 1454); err != nil || got != 1312254 {
		t.Fatal(got, err)
	}
}
