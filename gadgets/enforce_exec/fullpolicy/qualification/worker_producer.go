// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"bytes"
	"debug/buildinfo"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
)

func workerBuildArgs(target, output, carrier string) ([]string, error) {
	if err := checkCommandTarget(target); err != nil {
		return nil, err
	}
	flags := "-X " + workerCarrierTarget + "=" + carrier
	if err := checkWorkerLinkerFlags(flags, carrier); err != nil {
		return nil, err
	}
	return []string{"build", "-buildvcs=false", "-ldflags", flags, "-o", output, target}, nil
}

func proveWorkerInitLowering(s workerSnapshot) (string, error) {
	return proveWorkerLowering(s, workerRuntimePackage, checkWorkerProjectRuntimeLowering)
}

func proveWorkerLowering(s workerSnapshot, pkg string, check func(string) error) (string, error) {
	return proveWorkerLoweringPackages(s, []string{pkg}, check)
}

func proveWorkerLoweringPackages(s workerSnapshot, packages []string, check func(string) error) (string, error) {
	dir, err := os.MkdirTemp("", "ig-worker-lowering-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	args := []string{"build", "-buildvcs=false"}
	for _, pkg := range packages {
		args = append(args, "-gcflags="+pkg+"=-S -m=2 -live")
	}
	args = append(args, "-o", filepath.Join(dir, "unqualified"), s.Consumer.Command.Target)
	command := exec.Command(s.Consumer.GoExecutable, args...)
	command.Dir = s.Consumer.Root
	command.Env = selectedEnvironment(s.Consumer.GoExecutable)
	var raw bytes.Buffer
	command.Stdout = &raw
	command.Stderr = &raw
	if err = command.Run(); err != nil {
		return "", errors.New("worker selected init lowering failed; raw output withheld")
	}
	if err = check(raw.String()); err != nil {
		return "", err
	}
	return hashBytes(raw.Bytes()), nil
}

func checkWorkerInitLowering(text string) error {
	marker := workerRuntimePackage + ".init STEXT"
	start := strings.Index(text, marker)
	if start < 0 {
		return errors.New("selected runtime init not present in lowering")
	}
	tail := text[start+len(marker):]
	if end := strings.Index(tail, " STEXT"); end >= 0 {
		tail = tail[:end]
	}
	if !strings.Contains(tail, workerCarrierTarget+"(SB)") ||
		!strings.Contains(tail, workerRuntimePackage+".parseSharedWorkerEvidence(SB)") ||
		!strings.Contains(tail, workerRuntimePackage+".sharedWorkerFrozen") {
		return errors.New("selected init does not consume exact carrier into frozen descriptor")
	}
	return nil
}

func workerRunner(s workerSnapshot) (runnerIdentity, error) {
	r, err := newConsumerReport(s.Consumer)
	return r.Runner, err
}

func runWorker(goPath, root, target, prebuildPath, output, reportPath string) error {
	if root == "" || target == "" || reportPath == "" {
		return errors.New("worker requires consumer, consumer-command and report")
	}
	if (prebuildPath == "") != (output == "") {
		return errors.New("worker BUILD requires prebuild and output together")
	}
	if _, err := os.Lstat(reportPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("worker report must not already exist")
	}
	before, err := snapshotWorker(goPath, root, target)
	if err != nil {
		return err
	}
	if prebuildPath == "" {
		checks, err := runWorkerChecks(before)
		if err != nil {
			return err
		}
		linkDigest, err := proveWorkerInitLowering(before)
		if err != nil {
			return err
		}
		checks = append(checks, workerCheck{Package: workerRuntimePackage, Test: workerInitCheckName, EventsSHA256: linkDigest})
		checks = append(checks, workerCheck{Package: workerRuntimePackage, Test: workerRuntimeProofCheckName, EventsSHA256: linkDigest})
		compilerDigest, err := proveWorkerLowering(before, testedPackage, checkWorkerProjectCompilerLowering)
		if err != nil {
			return err
		}
		checks = append(checks, workerCheck{Package: testedPackage, Test: workerCompilerProofCheckName, EventsSHA256: compilerDigest})
		dependencyChecks, err := proveWorkerDependencyChecks(before)
		if err != nil {
			return err
		}
		checks = append(checks, dependencyChecks...)
		sentinelCheck, err := proveWorkerSentinelCheck(before)
		if err != nil {
			return err
		}
		checks = append(checks, sentinelCheck)
		proof, err := deriveWorkerTail(before) //nolint:staticcheck // SA4023: stub refuses by design.
		if err != nil {                        //nolint:staticcheck // SA4023: deriveWorkerTail refuses until its dependency lands; keep guard.
			// Deliberately no PREBUILD/carrier output: an incomplete obligation is not
			// evidence that may be laundered by a later BUILD invocation.
			return err
		}
		after, err := snapshotWorker(goPath, root, target)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(before, after) {
			return errors.New("worker inputs/tools/profile changed during checks")
		}
		runner, err := workerRunner(before)
		if err != nil {
			return err
		}
		r := workerPrebuildV1{SchemaVersion: 1, Phase: "PREBUILD", EvidenceScope: workerScope, AccountingDomain: workerModel, ModelRevision: "worker-model-v1", NativeActivation: "NOT_QUALIFIED", Snapshot: before, InputsSHA256: workerJSONHash(before.Inputs), ProfileSHA256: workerProfileHash(before), Checks: checks, ChecksSHA256: workerJSONHash(checks), TailProof: proof, TailProofSHA256: workerJSONHash(proof), BootstrapBytes: proof.Bootstrap, TailBytes: proof.Tail, Runner: runner}
		if err = validateWorkerPrebuild(r); err != nil {
			return err
		}
		return writeReport(reportPath, r)
	}
	data, err := os.ReadFile(prebuildPath)
	if err != nil {
		return err
	}
	prebuild, err := decodeWorkerPrebuild(data)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, prebuild.Snapshot) {
		return errors.New("worker PREBUILD no longer matches selected inputs")
	}
	carrier, err := workerCarrier(prebuild, hashBytes(data))
	if err != nil {
		return err
	}
	if _, err = os.Lstat(output); !errors.Is(err, os.ErrNotExist) {
		return errors.New("worker binary output must not already exist")
	}
	// Build into a fresh owned directory. Publish only after complete validation.
	dir, err := os.MkdirTemp("", "ig-worker-build-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	artifact := filepath.Join(dir, "consumer")
	args, err := workerBuildArgs(target, artifact, carrier)
	if err != nil {
		return err
	}
	if _, err = commandOutput(before.Consumer.GoExecutable, before.Consumer.Root, selectedEnvironment(before.Consumer.GoExecutable), args...); err != nil {
		return err
	}
	after, err := snapshotWorker(goPath, root, target)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, after) {
		return errors.New("worker inputs/tools/profile changed during build")
	}
	executable, err := os.ReadFile(artifact)
	if err != nil {
		return err
	}
	info, err := buildinfo.Read(bytes.NewReader(executable))
	if err != nil {
		return err
	}
	if err = checkWorkerBinary(info, before, carrier); err != nil {
		return err
	}
	// Retained init proof is checked against this selected source/compiler; no
	// consumer/gadget executable is run, and BuildInfo alone is not linkage proof.
	if _, err = proveWorkerInitLowering(before); err != nil {
		return err
	}
	if _, err = proveWorkerLowering(before, testedPackage, checkWorkerProjectCompilerLowering); err != nil {
		return err
	}
	if _, err = proveWorkerDependencyChecks(before); err != nil {
		return err
	}
	if _, err = proveWorkerSentinelCheck(before); err != nil {
		return err
	}
	final, err := snapshotWorker(goPath, root, target)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, final) {
		return errors.New("worker inputs changed during link proof")
	}
	runner, err := workerRunner(before)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if _, err = out.Write(executable); err != nil {
		_ = out.Close()
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	r := workerBuildV1{SchemaVersion: 1, Phase: "BUILD", EvidenceScope: workerScope, NativeActivation: "NOT_QUALIFIED", PrebuildSHA256: hashBytes(data), Carrier: carrier, Snapshot: before, Binary: binaryEvidence{Path: output, SHA256: hashBytes(executable), BuildInfo: info}, Runner: runner}
	return writeReport(reportPath, r)
}

// Both PREBUILD and BUILD generate this evidence themselves. No supplied digest
// or positive test flag can replace fresh selected consumer compilation.
func proveWorkerDependencyChecks(s workerSnapshot) ([]workerCheck, error) {
	if _, err := deriveWorkerDependency(s); err != nil {
		return nil, err
	}
	dependency, err := proveWorkerLoweringPackages(s, []string{
		"github.com/cilium/ebpf", "github.com/cilium/ebpf/internal/sys", "github.com/cilium/ebpf/internal/sysenc",
		"github.com/cilium/ebpf/internal/unix", "golang.org/x/sys/unix",
	}, checkWorkerDependencyLowering)
	if err != nil {
		return nil, err
	}
	stdlib, err := proveWorkerLoweringPackages(s, []string{"encoding/binary", "syscall", "internal/strconv"}, checkWorkerDependencyStdlibLowering)
	if err != nil {
		return nil, err
	}
	return []workerCheck{
		{Package: workerRuntimePackage, Test: workerDependencyProofCheckName, EventsSHA256: dependency},
		{Package: workerRuntimePackage, Test: workerDependencyStdlibProofCheckName, EventsSHA256: stdlib},
	}, nil
}

// PREBUILD and BUILD generate this scoped semantic evidence themselves. The
// canonical digest binds the selected source/export result, complete snapshot
// (including profile and tools), and actual checker executable identity. Runner
// source linkage remains UNPROVEN. Opaque assembly/unsafe review is unresolved:
// this typed-Go-only check is not a full sentinel nonmutation certificate.
func proveWorkerSentinelCheck(s workerSnapshot) (workerCheck, error) {
	result, err := proveWorkerSentinel(s)
	if err != nil {
		return workerCheck{}, err
	}
	runner, err := workerRunner(s)
	if err != nil {
		return workerCheck{}, err
	}
	digest := workerJSONHash(struct {
		SnapshotSHA256 string
		Runner         runnerIdentity
		Result         workerSentinelEvidence
	}{workerJSONHash(s), runner, result})
	return workerCheck{Package: testedPackage + "/qualification", Test: workerSentinelProofCheckName, EventsSHA256: digest}, nil
}
