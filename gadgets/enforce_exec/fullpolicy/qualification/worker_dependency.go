// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"strings"
)

// This is a conditional component, not workerTail. Caller ownership, compiler
// debit and startup-owned caches are separate. The approved consumer must not
// replace ebpf.ErrNotSupported; that premise is not established here and there
// is deliberately no caller-supplied Boolean to manufacture it.
type workerDependencyBound struct{ Write, Read, Run, Tail uint64 }

func deriveWorkerDependency(s workerSnapshot) (workerDependencyBound, error) {
	var result workerDependencyBound
	if err := checkToolchain(s.Consumer.Profile); err != nil {
		return result, err
	}
	if s.Consumer.Profile["GOFIPS140"] != "off" || s.Consumer.Profile["GOEXPERIMENT"] != "" || s.Consumer.Profile["GODEBUG"] != "" {
		return result, errors.New("dependency proof effective profile mismatch")
	}
	for name, want := range requiredEnvironment {
		if _, ok := s.Consumer.Profile[name]; !ok {
			return result, errors.New("dependency proof effective profile missing")
		}
		if value, ok := s.RawProfile[name]; !ok || value != want {
			return result, errors.New("dependency proof raw profile mismatch")
		}
	}
	for name, want := range workerDependencySourcePins {
		if s.Inputs[name] != want {
			return result, errors.New("dependency proof source pin mismatch")
		}
	}
	for name, want := range workerProjectToolPins {
		if s.Consumer.ToolHashes[name] != want {
			return result, errors.New("dependency proof tool pin mismatch")
		}
	}
	// Each sum conservatively includes all allocations within its command even
	// when their lifetimes are disjoint. Recognized errors are scalarized before
	// the joined job ends; no cohort survives into a later command or cleanup.
	// Write: encoded capacity+key, raw errno, Unwrap boxes, two wrappers/messages,
	// and the maximum decimal+errno message scratch (conservative for E2BIG).
	write, err := workerProofSum(1152, 4, 8, 4*8, 2*32, 70, 78, 20, 26)
	if err != nil {
		return result, err
	}
	read, err := workerProofSum(4, 8, 5*8, 2*32, 70, 78, 20, 26)
	if err != nil {
		return result, err
	}
	ordinary, err := workerProofSum(8, 2*8, 32, 13+49, 20, 26)
	if err != nil {
		return result, err
	}
	unsupported, err := workerProofSum(8, 2*8, 2*32, 31+7+2+13, 13+53)
	if err != nil {
		return result, err
	}
	mask, err := workerProofSum(8, 32, 25+49, 20, 26)
	if err != nil {
		return result, err
	}
	// Unmask panic can overlap the raw syscall error, before outer wrappers.
	unmask, err := workerProofSum(8, 8, 32, 27+49, 20, 26)
	if err != nil {
		return result, err
	}
	run := max(ordinary, unsupported, mask, unmask)
	return workerDependencyBound{Write: write, Read: read, Run: run, Tail: max(write, read, run)}, nil
}

// These predicates corroborate the reviewed exact-source derivation, not a
// generic allocation analyser. Match each premise inside its actual function
// section: an unrelated function's call cannot satisfy a missing operation.
var workerDependencyLoweringFunctions = map[string][]string{
	"github.com/cilium/ebpf.wrapOperationError":               {"runtime.concatstring2", "runtime.mallocgcSmallScanNoHeaderSC4", "github.com/cilium/ebpf/internal/sys.ErrnoMessage"},
	"github.com/cilium/ebpf.unsupportedRunError":              {"runtime.concatstring4", "runtime.mallocgcSmallScanNoHeaderSC4", "github.com/cilium/ebpf.ProgramType.String"},
	"github.com/cilium/ebpf.wrapMapError":                     {"errors.Is", "github.com/cilium/ebpf.wrapOperationError"},
	"github.com/cilium/ebpf.(*Map).update":                    {"github.com/cilium/ebpf/internal/sys.BPF", "github.com/cilium/ebpf.wrapMapError"},
	"github.com/cilium/ebpf.(*Map).lookup":                    {"github.com/cilium/ebpf/internal/sys.BPF", "errors.Is", "github.com/cilium/ebpf.wrapMapError"},
	"github.com/cilium/ebpf.(*Program).Run":                   {"github.com/cilium/ebpf.(*Program).run", "github.com/cilium/ebpf.wrapOperationError"},
	"github.com/cilium/ebpf.(*Program).run":                   {"github.com/cilium/ebpf/internal/sys.BPF", "github.com/cilium/ebpf.unsupportedRunError"},
	"github.com/cilium/ebpf/internal/sys.profilerSignalError": {"runtime.concatstring2", "runtime.mallocgcSmallScanNoHeaderSC4"},
	"github.com/cilium/ebpf/internal/sys.ErrnoMessage":        {"syscall.Errno.Error"},
	"github.com/cilium/ebpf/internal/sys.wrappedErrno.Unwrap": {"runtime.convT64"},
	"github.com/cilium/ebpf/internal/sys.BPF":                 {"runtime.convT64", "github.com/cilium/ebpf/internal/sys.maskProfilerSignal", "github.com/cilium/ebpf/internal/sys.unmaskProfilerSignal"},
	"github.com/cilium/ebpf/internal/sysenc.Marshal":          {"encoding/binary.Append", "runtime.makeslice"},
	"github.com/cilium/ebpf/internal/sysenc.SyscallOutput":    {"github.com/cilium/ebpf/internal/sysenc.unsafeBackingMemory"},
}

var workerDependencyStdlibLoweringFunctions = map[string][]string{
	"encoding/binary.Append":     {"runtime.growslice", "encoding/binary.(*encoder).value"},
	"syscall.Errno.Error":        {"internal/strconv.FormatInt", "runtime.concatstring2"},
	"internal/strconv.FormatInt": {"runtime.slicebytetostring"},
}

func checkWorkerDependencyFunctions(text string, functions map[string][]string) error {
	for symbol, calls := range functions {
		marker := symbol + " STEXT "
		start := strings.Index("\n"+text, "\n"+marker)
		if start < 0 {
			return errors.New("selected dependency function missing")
		}
		section := text[start:]
		if next := strings.Index(section[len(marker):], " STEXT "); next >= 0 {
			end := strings.LastIndex(section[:len(marker)+next], "\n")
			if end < 0 {
				return errors.New("selected dependency function boundary missing")
			}
			section = section[:end]
		}
		for _, call := range calls {
			if !strings.Contains(section, "CALL\t"+call+"(SB)") {
				return errors.New("selected dependency function lowering changed")
			}
		}
	}
	return nil
}

func checkWorkerDependencyLowering(text string) error {
	return checkWorkerDependencyFunctions(text, workerDependencyLoweringFunctions)
}

func checkWorkerDependencyStdlibLowering(text string) error {
	return checkWorkerDependencyFunctions(text, workerDependencyStdlibLoweringFunctions)
}
