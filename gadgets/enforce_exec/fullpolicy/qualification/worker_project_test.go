// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"math"
	"strings"
	"testing"
)

func workerProjectFixture() workerSnapshot {
	s := workerSnapshot{Consumer: consumerSnapshot{Profile: map[string]string{}, ToolHashes: map[string]string{}}, Inputs: map[string]string{}, RawProfile: map[string]string{}}
	for k, v := range requiredEnvironment {
		s.Consumer.Profile[k] = v
		s.RawProfile[k] = v
	}
	s.Consumer.Profile["GOENV"] = ""
	s.Consumer.Profile["GOVERSION"] = "go1.27.3"
	s.Consumer.Profile["GOFIPS140"] = "off"
	for _, pins := range []map[string]string{workerProcSourcePins, workerLinkerSourcePins, workerProjectSourcePins} {
		for k, v := range pins {
			s.Inputs[k] = v
		}
	}
	for k, v := range workerProjectToolPins {
		s.Consumer.ToolHashes[k] = v
	}
	return s
}

func TestWorkerProjectFormulaAndPins(t *testing.T) {
	s := workerProjectFixture()
	p, err := deriveWorkerProject(s)
	if err != nil || p.Bootstrap != 536 || p.ProjectTail != 1310800 || p.CarrierStartup != 575 || p.AssertionSite != 24 {
		t.Fatalf("%+v %v", p, err)
	}
	for _, pins := range []map[string]string{workerProcSourcePins, workerLinkerSourcePins, workerProjectSourcePins} {
		for name, want := range pins {
			s.Inputs[name] = strings.Repeat("f", 64)
			if _, err := deriveWorkerProject(s); err == nil {
				t.Fatal("changed source accepted", name)
			}
			s.Inputs[name] = want
		}
	}
	for key, want := range s.Consumer.ToolHashes {
		s.Consumer.ToolHashes[key] = strings.Repeat("e", 64)
		if _, err := deriveWorkerProject(s); err == nil {
			t.Fatal("changed tool accepted", key)
		}
		s.Consumer.ToolHashes[key] = want
	}
	for key, want := range s.RawProfile {
		s.RawProfile[key] = "changed"
		if _, err := deriveWorkerProject(s); err == nil {
			t.Fatal("changed raw profile accepted", key)
		}
		s.RawProfile[key] = want
	}
	s.Consumer.Profile["GOFIPS140"] = "latest"
	if _, err := deriveWorkerProject(s); err == nil {
		t.Fatal("FIPS profile admitted")
	}
}

func TestWorkerProjectCheckedSum(t *testing.T) {
	if _, err := workerProofSum(math.MaxUint64, 1); err == nil {
		t.Fatal("overflow accepted")
	}
	if got, err := workerProofSum(136, 16, 3*112, 3*16); err != nil || got != 536 {
		t.Fatal(got, err)
	}
}

func TestWorkerProjectLoweringGuards(t *testing.T) {
	runtimeText := workerRuntimePackage + ".init STEXT\n" + workerCarrierTarget + "(SB)\n" + workerRuntimePackage + ".parseSharedWorkerEvidence(SB)\n" + workerRuntimePackage + ".sharedWorkerFrozen\n" +
		"budget does not escape\nintent does not escape\nop.stop escapes to heap\nop.finish escapes to heap\n..typeAssert.1 SDATA size=24\nlive at call to chansend1\ncallPrivate capturing by ref: command\nwidth=1112\ncallPrivate capturing by ref: outcome\nwidth=3"
	compilerText := "workspace_attempt.go\nworkspace_union.go\nworkspace_limited.go\n[]Policy{...} does not escape\nrefs does not escape\ncontainer does not escape\nwork escapes to heap in compileSharedPolicyModel\nwork escapes to heap in newSharedSnapshotModel\nCompileSharedPolicyLimited\nNewSharedSnapshotLimited"
	for _, c := range []struct {
		text  string
		check func(string) error
	}{{runtimeText, checkWorkerProjectRuntimeLowering}, {compilerText, checkWorkerProjectCompilerLowering}} {
		if err := c.check(c.text); err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(c.text, "\n") {
			if err := c.check(strings.ReplaceAll(c.text, line, "REMOVED")); err == nil {
				t.Fatal("missing lowering premise accepted", line)
			}
		}
	}
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
	for i := range checks {
		missing := append([]workerCheck(nil), checks[:i]...)
		missing = append(missing, checks[i+1:]...)
		if err := validateWorkerChecks(missing); err == nil {
			t.Fatal("missing required check accepted", checks[i])
		}
	}
}
