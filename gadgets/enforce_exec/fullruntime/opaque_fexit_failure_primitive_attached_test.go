// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// This opt-in primitive proves a real fexit return observation with a locked
// witness, not terminal receipt authority, settlement, or product readiness.
func TestOpaqueFexitFailurePrimitiveAttached(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_FEXIT_OBJECT")
	cgroup := os.Getenv("IG_OPAQUE_FEXIT_CGROUP")
	helper := os.Getenv("IG_OPAQUE_FEXIT_HELPER")
	symbol := os.Getenv("IG_OPAQUE_FEXIT_SYMBOL")
	if object == "" && cgroup == "" && helper == "" && symbol == "" {
		t.Skip("set explicit fexit object, isolated cgroup, static helper and BTF symbol")
	}
	if os.Geteuid() != 0 || !filepath.IsAbs(object) || !filepath.IsAbs(cgroup) ||
		!filepath.IsAbs(helper) || symbol == "" || !strings.HasPrefix(filepath.Base(cgroup), "ig15-g005-fexit-") {
		t.Fatal("root, absolute object/helper, dedicated ig15-g005-fexit-* cgroup and explicit BTF symbol required")
	}
	procs, err := os.ReadFile(filepath.Join(cgroup, "cgroup.procs"))
	if err != nil || len(bytes.TrimSpace(procs)) != 0 {
		t.Fatalf("isolated cgroup must initially be empty: procs=%q err=%v", procs, err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(cgroup, &stat); err != nil || stat.Ino == 0 {
		t.Fatalf("isolated cgroup: %v", err)
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}
	var function *btf.Func
	if err := kernel.TypeByName(symbol, &function); err != nil {
		t.Fatalf("explicit symbol lacks unique kernel BTF FUNC: %v", err)
	}
	bits, err := opaqueFexitReturnBits(function)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("explicit target %s: BTF=%+v return_bits=%d; no generic support claim", symbol, function.Type, bits)
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	const programName = "opaque_fexit_failure_primitive"
	program := spec.Programs[programName]
	if program == nil || program.Type != ebpf.Tracing || program.AttachType != ebpf.AttachTraceFExit {
		t.Fatal("missing non-sleepable fexit primitive")
	}
	if program.Flags != 0 {
		t.Fatal("primitive must not request sleepable or other program flags")
	}
	program.AttachTo = symbol
	spec.Programs = map[string]*ebpf.ProgramSpec{programName: program}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20, KernelTypes: kernel},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("fexit primitive verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	gate, witness := collection.Maps["fexit_primitive_gate"], collection.Maps["fexit_primitive_witness"]
	if gate == nil || witness == nil || gate.ValueSize() != 16 || witness.ValueSize() != 40 {
		t.Fatal("missing or malformed primitive maps")
	}
	invalid := filepath.Join(t.TempDir(), "invalid-exec")
	if err := os.WriteFile(invalid, []byte("invalid executable image\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cg, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer cg.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, helper)
	cmd.Env = append(os.Environ(), "IG_OPAQUE_FAIL_EXEC_PATH="+invalid)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || line != "READY\n" {
		t.Fatalf("helper readiness: line=%q err=%v stderr=%q", line, err, stderr.String())
	}
	config := struct {
		Cgroup           uint64
		TGID, ReturnBits uint32
	}{stat.Ino, uint32(cmd.Process.Pid), bits}
	if err := gate.Update(uint32(0), config, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := gate.Freeze(); err != nil {
		t.Fatal(err)
	}
	attached, err := link.AttachTracing(link.TracingOptions{Program: collection.Programs[programName]})
	if err != nil {
		t.Fatalf("attach exact fexit target %s: %v", symbol, err)
	}
	defer attached.Close()
	var observed struct {
		Lock, Reserved           uint32
		Calls, Physical, PIDTGID uint64
		Result                   int64
	}
	if err := witness.Lookup(uint32(0), &observed); err != nil || observed.Calls != 0 {
		t.Fatalf("witness must be empty before explicit trigger: %+v err=%v", observed, err)
	}
	var physical uint64
	for attempt := uint64(1); attempt <= 2; attempt++ {
		if _, err := stdin.Write([]byte("FAIL\n")); err != nil {
			t.Fatal(err)
		}
		if line, err := reader.ReadString('\n'); err != nil || line != "FAILED:8\n" {
			t.Fatalf("malformed exec: line=%q err=%v stderr=%q", line, err, stderr.String())
		}
		// No retry, sleep, exec or fork: observe while the original helper is
		// idle immediately after its userspace failure acknowledgement.
		if err := witness.Lookup(uint32(0), &observed); err != nil {
			t.Fatal(err)
		}
		wantPID := uint64(uint32(cmd.Process.Pid))
		if observed.Calls != attempt || observed.Physical == 0 || observed.Result != -int64(unix.ENOEXEC) ||
			observed.PIDTGID != wantPID<<32|wantPID || observed.Reserved != 0 || observed.Lock != 0 {
			t.Fatalf("fexit must synchronously observe exact idle helper and -ENOEXEC: %+v", observed)
		}
		if attempt == 1 {
			physical = observed.Physical
		} else if observed.Physical != physical {
			t.Fatal("failed exec changed original physical task identity")
		}
	}
	if _, err := stdin.Write([]byte("DONE\n")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper completion: %v stderr=%q", err, stderr.String())
	}
	t.Logf("%s fexit observed two -ENOEXEC returns on one live physical task using spinlock map; no receipt/settlement/product claim", symbol)
}

func opaqueFexitReturnBits(function *btf.Func) (uint32, error) {
	prototype, ok := btf.UnderlyingType(function.Type).(*btf.FuncProto)
	if !ok {
		return 0, fmt.Errorf("%s lacks BTF function prototype", function.Name)
	}
	result, ok := btf.UnderlyingType(prototype.Return).(*btf.Int)
	if !ok || result.Encoding != btf.Signed || result.Size != 4 && result.Size != 8 {
		return 0, fmt.Errorf("%s requires an exact signed 32/64-bit return, got %v", function.Name, prototype.Return)
	}
	return result.Size * 8, nil
}

func TestOpaqueFexitReturnBits(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result btf.Type
		bits   uint32
	}{
		{"int", &btf.Int{Size: 4, Encoding: btf.Signed}, 32},
		{"long", &btf.Int{Size: 8, Encoding: btf.Signed}, 64},
		{"unsigned", &btf.Int{Size: 8}, 0},
		{"short", &btf.Int{Size: 2, Encoding: btf.Signed}, 0},
		{"void", &btf.Void{}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bits, err := opaqueFexitReturnBits(&btf.Func{Name: tc.name, Type: &btf.FuncProto{Return: tc.result}})
			if bits != tc.bits || (err != nil) != (tc.bits == 0) {
				t.Fatalf("bits=%d err=%v want=%d", bits, err, tc.bits)
			}
		})
	}
}
