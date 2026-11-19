// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os/exec"
	"sort"
	"strings"
)

const (
	workerSentinelProofCheckName         = "proof:selected-typed-go-sentinel-writes-and-addresses"
	workerDependencyProofCheckName       = "proof:selected-dependency-lowering"
	workerDependencyStdlibProofCheckName = "proof:selected-dependency-stdlib-lowering"
	workerInitCheckName                  = "proof:selected-init-lowering"
	workerRuntimeProofCheckName          = "proof:selected-project-runtime-lowering"
	workerCompilerProofCheckName         = "proof:selected-limited-compiler-lowering"
)

func workerGeneratedChecks() map[string][]string {
	return map[string][]string{workerRuntimePackage: {workerInitCheckName, workerRuntimeProofCheckName, workerDependencyProofCheckName, workerDependencyStdlibProofCheckName}, testedPackage: {workerCompilerProofCheckName}, testedPackage + "/qualification": {workerSentinelProofCheckName}}
}

// Exact event identities, including selected subtests; never prefix-match a
// successful top-level event as evidence that its children actually ran.
func requiredWorkerChecks() map[string][]string {
	return map[string][]string{
		testedPackage + "/qualification": {"TestWorkerLinkedInitFixture", "TestWorkerBuildRecipeAndInitEvidenceStrict", "TestWorkerProjectFormulaAndPins", "TestWorkerProjectCheckedSum", "TestWorkerProjectLoweringGuards", "TestWorkerDependencyConditionalFormulaAndPins", "TestWorkerDependencyLoweringGuards", "TestWorkerSentinelGeneratedCheckRequired"},
		testedPackage:                    {"TestSharedPolicyModelBoundary", "TestSharedPolicyModelFailureDebit", "TestSharedPolicyModelOwnsSource", "TestSharedSnapshotModelBoundary", "TestSharedSnapshotModelGlobalPrefixes", "TestSharedSnapshotModelLateFailureAndOwnership"},
		workerRuntimePackage:             {"TestSharedCommandReceiptNativeScalarLayout", "TestSharedCommandReceiptNativeScalarLayout/sharedCommandWire", "TestSharedCommandReceiptNativeScalarLayout/sharedReceiptWire", "TestSharedOperationRequiresCompletedHandshake", "TestSharedIntegratedNumericalObjectsUnionStage", "TestSharedIntegratedTwoObjectsExactCumulativeDebit", "TestSharedIntegratedOneRegistrationAndStopJoin", "TestPrivateWorkerCompilerFailureRetainsPrefix", "TestPrivateWorkerCompletedCanceledPinCleansActualTicket", "TestPrivateWorkerCleanupUnderflowRetainsOwners", "TestSharedWorkerCarrierParser", "TestSharedWorkerCarrierParserNoAllocation"},
	}
}

func checkWorkerEvents(data []byte, pkg string, names []string) ([]workerCheck, error) {
	state := map[string]int{}
	for _, name := range names {
		state[name] = 0
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	started, passed := false, false
	var normalized bytes.Buffer
	encoder := json.NewEncoder(&normalized)
	for {
		var event testEvent
		if err := decoder.Decode(&event); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
		if event.Package != pkg || passed {
			return nil, errors.New("unexpected worker event package/order")
		}
		if event.Test == "" {
			switch event.Action {
			case "start":
				if started {
					return nil, errors.New("duplicate worker package start")
				}
				started = true
			case "output":
				if !started {
					return nil, errors.New("worker output before start")
				}
			case "pass":
				if !started {
					return nil, errors.New("worker pass before start")
				}
				passed = true
			default:
				return nil, errors.New("worker package failed/skipped/unexpected")
			}
		} else {
			current, ok := state[event.Test]
			if !ok || !started {
				return nil, errors.New("unexpected worker test/subtest")
			}
			switch event.Action {
			case "run":
				if current != 0 {
					return nil, errors.New("duplicate worker run")
				}
				state[event.Test] = 1
			case "pass":
				if current != 1 {
					return nil, errors.New("worker pass without run")
				}
				state[event.Test] = 2
			case "output":
				if current != 1 {
					return nil, errors.New("worker output outside run")
				}
			default:
				return nil, errors.New("worker test failed/skipped/unexpected")
			}
		}
		if event.Action != "output" {
			if err := encoder.Encode(event); err != nil {
				return nil, err
			}
		}
	}
	if !passed {
		return nil, errors.New("missing worker package pass")
	}
	checks := make([]workerCheck, 0, len(names))
	for _, name := range names {
		if state[name] != 2 {
			return nil, errors.New("missing worker test run/pass")
		}
		checks = append(checks, workerCheck{Package: pkg, Test: name, EventsSHA256: hashBytes(normalized.Bytes())})
	}
	return checks, nil
}

func validateWorkerChecks(checks []workerCheck) error {
	required := requiredWorkerChecks()
	seen := map[string]bool{}
	for _, check := range checks {
		found := false
		for _, name := range workerGeneratedChecks()[check.Package] {
			if check.Test == name {
				found = true
			}
		}
		for _, name := range required[check.Package] {
			if name == check.Test {
				found = true
			}
		}
		key := check.Package + "/" + check.Test
		if !found || seen[key] || !workerDigest(check.EventsSHA256) {
			return errors.New("invalid worker check identity/digest")
		}
		seen[key] = true
	}
	for pkg, names := range workerGeneratedChecks() {
		for _, name := range names {
			if !seen[pkg+"/"+name] {
				return errors.New("missing selected worker generated proof")
			}
		}
	}
	for pkg, names := range required {
		for _, name := range names {
			if !seen[pkg+"/"+name] {
				return errors.New("missing required worker check")
			}
		}
	}
	return nil
}

func runWorkerChecks(s workerSnapshot) ([]workerCheck, error) {
	required := requiredWorkerChecks()
	packages := make([]string, 0, len(required))
	for pkg := range required {
		packages = append(packages, pkg)
	}
	sort.Strings(packages)
	var checks []workerCheck
	for _, pkg := range packages {
		names := required[pkg]
		command := exec.Command(s.Consumer.GoExecutable, "test", "-json", "-count=1", "-run", "^("+strings.Join(names, "|")+")$", pkg)
		command.Dir = s.Consumer.Root
		command.Env = selectedEnvironment(s.Consumer.GoExecutable)
		var data bytes.Buffer
		var diagnostic goDiagnosticBuffer
		command.Stdout = &data
		command.Stderr = &diagnostic
		if err := command.Run(); err != nil {
			return nil, goCommandError("test", err, diagnostic.bytes)
		}
		got, err := checkWorkerEvents(data.Bytes(), pkg, names)
		if err != nil {
			return nil, errors.New("worker checks missing/failed/skipped; raw output withheld")
		}
		checks = append(checks, got...)
	}
	return checks, nil
}
