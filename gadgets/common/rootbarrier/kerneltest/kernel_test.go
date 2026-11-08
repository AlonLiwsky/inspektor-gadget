// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package kerneltest is an opt-in kernel test of the root barrier header and
// its Go attestation. Run it only in a disposable BPF-LSM-enabled VM, as root,
// with clang, bpftool, libbpf headers and util-linux:
//
//	IG_ROOT_BARRIER_KERNEL_TEST=1 ./kerneltest.test -test.v
//
// It compiles testdata/barrier.bpf.c, attaches the barrier programs, and
// covers only one new cgroup.
package kerneltest

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/common/rootbarrier"
)

func compile(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	dir := t.TempDir()
	vmlinux, err := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c").Output()
	if err != nil {
		t.Fatalf("bpftool: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "vmlinux.h"), vmlinux, 0o644); err != nil {
		t.Fatal(err)
	}
	arch := map[string]string{"amd64": "x86", "arm64": "arm64"}[runtime.GOARCH]
	object := filepath.Join(dir, "barrier.o")
	args := []string{
		"-g", "-O2", "-target", "bpf", "-D__TARGET_ARCH_" + arch, "-I", dir,
		"-c", "testdata/barrier.bpf.c", "-o", object,
	}
	if out, err := exec.Command("clang", args...).CombinedOutput(); err != nil {
		t.Fatalf("clang: %v\n%s", err, out)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

// inCgroup runs a shell command as a process that first moves itself into the
// cgroup.
func inCgroup(cgroup, command string) error {
	script := fmt.Sprintf("echo $$ > %s/cgroup.procs && exec %s", cgroup, command)
	out, err := exec.Command("sh", "-c", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func TestRootBarrierKernel(t *testing.T) {
	if os.Getenv("IG_ROOT_BARRIER_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel fixture opt-in required")
	}
	collection, err := ebpf.NewCollectionWithOptions(compile(t), ebpf.CollectionOptions{})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier: %+v", ve)
		}
		t.Fatal(err)
	}
	defer collection.Close()

	counters := collection.Maps[rootbarrier.CountersMap]
	probe := collection.Maps[rootbarrier.ProbeMap]
	if err := rootbarrier.Attest(counters); err == nil {
		t.Fatal("attestation passed before any program was attached")
	}
	for _, h := range rootbarrier.Hooks {
		l, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs[h.Program]})
		if err != nil {
			t.Fatalf("attaching %s: %v", h.Program, err)
		}
		defer l.Close()
	}
	if err := rootbarrier.Attest(counters); err != nil {
		t.Fatalf("attestation: %v", err)
	}
	if err := rootbarrier.SelfTest(probe); err != nil {
		t.Fatalf("self-test: %v", err)
	}

	cgroup := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("root-barrier-kerneltest-%d", os.Getpid()))
	if err := os.Mkdir(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cgroup)
	var st unix.Stat_t
	if err := unix.Stat(cgroup, &st); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["covered_cgroups"].Put(st.Ino, uint32(1)); err != nil {
		t.Fatal(err)
	}

	commands := map[rootbarrier.Op]string{
		rootbarrier.OpChroot:    "chroot / true",
		rootbarrier.OpUnshareNS: "unshare -m true",
		rootbarrier.OpUserns:    "unshare -U true",
		rootbarrier.OpSetns:     "nsenter -t 1 -m true",
	}
	for op, command := range commands {
		if err := exec.Command("sh", "-c", command).Run(); err != nil {
			t.Errorf("%s outside the covered cgroup: %v", command, err)
		}
		before, err := rootbarrier.Denials(counters)
		if err != nil {
			t.Fatal(err)
		}
		err = inCgroup(cgroup, command)
		if err == nil || !strings.Contains(err.Error(), "Operation not permitted") {
			t.Errorf("%s in the covered cgroup: %v", command, err)
		}
		after, err := rootbarrier.Denials(counters)
		if err != nil {
			t.Fatal(err)
		}
		if after[op] == before[op] {
			t.Errorf("%s: the barrier did not count %s", command, op)
		}
	}
	// Joining another namespace type stays allowed.
	if err := inCgroup(cgroup, "nsenter -t 1 -C true"); err != nil {
		t.Errorf("setns into a cgroup namespace: %v", err)
	}
}
