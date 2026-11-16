// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"strings"
)

var workerStdlibProofFiles = append([]string{
	"src/io/io.go", "src/strings/strings.go", "src/strconv/number.go",
	"src/os/file.go", "src/os/file_unix.go", "src/runtime/chan.go",
	"src/runtime/slice.go", "src/runtime/malloc.go", "src/context/context.go",
	"src/encoding/binary/binary.go", "src/cmd/link/internal/ld/data.go",
	"src/cmd/link/internal/loader/symbolbuilder.go",
}, workerProjectStdlibFiles...)

// The selected linker adds a trailing NUL to -X backing without increasing
// the Go string length. These source pins bind that startup-owner premise.
var workerLinkerSourcePins = map[string]string{
	"toolchain/src/cmd/link/internal/ld/data.go":              "2f51cea9197f1fc3dc4ccb62738f807400817a9759b960c5fbcf4403d7f5f08d",
	"toolchain/src/cmd/link/internal/loader/symbolbuilder.go": "b1afe6156efd89fcb2ce68f63a14b3180587505cd184c6ad5477cf073a256259",
}

// Fixed reviewed obligations, NOT caller-supplied numeric JSON. Conditional
// components and composition do not establish complete approved-consumer
// applicability or source-bound generated evidence. Deleting an obligation
// requires a source-reviewed specification change.
type workerProofObligation struct{ name, source, symbol, formula, lifetime, check string }

var workerProofObligations = []workerProofObligation{
	{"bootstrap", "fullruntime/shared_operation_context.go", "sharedOperationContext", "136+16+3*112+3*16", "whole-operation", "layout-and-lowering"},
	{"carrier-startup", "fullruntime/shared_worker_evidence.go", "sharedWorkerFrozen", "367+16+sizeof(frozen-descriptor)", "fixed-startup-not-worker", "init-link-layout"},
	{"pins-proc", "fullruntime/proc_pin.go", "readPinnedInitStart", "max(read-copy,stat-fields,status-split,error-overlap)", "sequential-pin-phase", "proc-all-path-lowering"},
	{"pins-scope", "fullruntime/scope.go", "checkBindingScope", "file-wrapper+selected-syscall-error-overlap", "sequential-pin-phase", "scope-all-path-lowering"},
	{"command-caller", "fullruntime/shared_private_outcome.go", "callPrivate", "32+1112+48+3+56+128", "accepted-job-join", "command-lowering"},
	{"command-selected-errors", "closure/github.com/cilium/ebpf/map.go", "Map.update/lookup;Program.run", "E_selected(t): whole-operation backing and retained pool state", "whole-operation-including-retention", "selected-adapter-all-path-proof"},
	{"class-and-sizing", "fullpolicy/shared.go", "ExecutionClass/RetainedBytes", "max(execution80,sizing/error-path)", "object-phase", "metadata-lowering"},
	{"cleanup", "fullruntime/shared_snapshot_candidate.go", "prepareSnapshotLocked", "16+max(joined-command-phase)", "same-operation-cleanup", "cleanup-lowering"},
	{"cohesive-caller", "fullruntime/shared_worker_integration.go", "prepareSharedWorkerLocked", "max(caller-preflight,union-call,stage-call)", "whole-operation-overlap", "cohesive-liveness"},
}

// The numerical components compose conditionally, but complete worker evidence
// still requires approved-consumer nonmutation/opaque-source applicability,
// source-bound generated evidence composition and release provenance. Neither
// component values nor supplied hashes discharge these obligations; refusal
// remains unconditional.
const workerMissingDependency = "worker qualification incomplete: approved-consumer nonmutation/opaque-source applicability, source-bound generated evidence composition and release provenance remain unverified"

func deriveWorkerTail(s workerSnapshot) (workerTail, error) {
	if _, err := deriveWorkerProject(s); err != nil {
		return workerTail{}, err
	}
	return workerTail{}, errors.New(workerMissingDependency)
}

type workerProjectBound struct {
	Bootstrap, ProjectTail        uint64
	CarrierStartup, AssertionSite uint64
}

// These are checked formulas over reviewed constants, not numeric caller input.
// Compiler object/union D remains cumulative and separate from ProjectTail.
func deriveWorkerProject(s workerSnapshot) (workerProjectBound, error) {
	var result workerProjectBound
	for source, want := range workerLinkerSourcePins {
		if s.Inputs[source] != want {
			return result, errors.New("worker linker source pin mismatch")
		}
	}
	pins, err := workerProcBound(s)
	if err != nil {
		return result, err
	}
	if s.Consumer.Profile["GOFIPS140"] != "off" {
		return result, errors.New("project proof FIPS profile mismatch")
	}
	for key, want := range requiredEnvironment {
		if s.RawProfile[key] != want {
			return result, errors.New("project proof raw profile mismatch")
		}
	}
	for source, want := range workerProjectSourcePins {
		if s.Inputs[source] != want {
			return result, errors.New("project proof source pin mismatch")
		}
	}
	for tool, want := range workerProjectToolPins {
		if s.Consumer.ToolHashes[tool] != want {
			return result, errors.New("project proof tool pin mismatch")
		}
	}
	bootstrap, err := workerProofSum(136, 16, 3*112, 3*16)
	if err != nil {
		return result, err
	}
	caller, err := workerProofSum(32, 1112, 48, 3, 56, 112, 16)
	if err != nil {
		return result, err
	}
	cleanupCommand, err := workerProofSum(16, caller, 1112)
	if err != nil {
		return result, err
	}
	metadata, err := workerProofSum(80, 16)
	if err != nil {
		return result, err
	}
	startup, err := workerProofSum(367, 16, 192)
	if err != nil {
		return result, err
	}
	return workerProjectBound{Bootstrap: bootstrap, ProjectTail: max(pins, metadata, cleanupCommand), CarrierStartup: startup, AssertionSite: 24}, nil
}

func workerProofSum(values ...uint64) (uint64, error) {
	var total uint64
	for _, v := range values {
		if v > ^uint64(0)-total {
			return 0, errors.New("worker proof sum overflow")
		}
		total += v
	}
	return total, nil
}

// Fixed conservative phase maximum: status text/input/start, Split headers,
// cloned token, NumError and project literal diagnostic. This is not caller data.
func workerProcBound(s workerSnapshot) (uint64, error) {
	if err := checkToolchain(s.Consumer.Profile); err != nil {
		return 0, err
	}
	if s.Consumer.Profile["GOVERSION"] != "go1.27.3" || s.Consumer.Profile["GOOS"] != "linux" ||
		s.Consumer.Profile["GOARCH"] != "amd64" || s.Consumer.Profile["GOAMD64"] != "v1" ||
		s.Consumer.Profile["CGO_ENABLED"] != "0" || s.Consumer.Profile["GOEXPERIMENT"] != "" ||
		s.Consumer.Profile["GODEBUG"] != "" {
		return 0, errors.New("proc/scope proof profile mismatch")
	}
	for source, want := range workerProcSourcePins {
		if s.Inputs[source] != want {
			return 0, errors.New("proc/scope reviewed source mismatch")
		}
	}
	return 65536*4 + 1048592 + 48 + 16, nil
}

// These predicates corroborate the reviewed exact-source derivation on the
// selected compiler; source/tool/profile pins remain necessary, not optional.
func checkWorkerProjectRuntimeLowering(text string) error {
	if err := checkWorkerInitLowering(text); err != nil {
		return err
	}
	for _, fragment := range []string{
		"budget does not escape", "intent does not escape",
		"op.stop escapes to heap", "op.finish escapes to heap",
		"..typeAssert.1 SDATA size=24", "live at call to chansend1",
		"callPrivate capturing by ref: command", "width=1112",
		"callPrivate capturing by ref: outcome", "width=3",
	} {
		if !strings.Contains(text, fragment) {
			return errors.New("selected runtime project lowering changed")
		}
	}
	return nil
}

func checkWorkerProjectCompilerLowering(text string) error {
	for _, fragment := range []string{
		"workspace_attempt.go", "workspace_union.go", "workspace_limited.go",
		"[]Policy{...} does not escape", "refs does not escape", "container does not escape",
		"work escapes to heap in compileSharedPolicyModel", "work escapes to heap in newSharedSnapshotModel",
		"CompileSharedPolicyLimited", "NewSharedSnapshotLimited",
	} {
		if !strings.Contains(text, fragment) {
			return errors.New("selected Limited compiler lowering changed")
		}
	}
	return nil
}
