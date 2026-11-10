// Copyright 2026 The Kubescape Authors
// SPDX-License-Identifier: Apache-2.0

// Package kerneltest is an opt-in kernel test of the root barrier header and
// its Go attestation. Run it only in a disposable BPF-LSM-enabled VM, as root,
// with clang, bpftool, libbpf headers and util-linux:
//
//	IG_ROOT_BARRIER_KERNEL_TEST=1 ./kerneltest.test -test.v
//
// It compiles testdata/barrier.bpf.c and testdata/owner.bpf.c, attaches the
// barrier programs, and covers only one new cgroup.
package kerneltest

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/common/rootbarrier"
)

func compile(t *testing.T, source string, defines ...string) *ebpf.CollectionSpec {
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
	args := []string{"-g", "-O2", "-target", "bpf", "-D__TARGET_ARCH_" + arch, "-I", dir}
	for _, d := range defines {
		args = append(args, "-D"+d)
	}
	args = append(args, "-c", source, "-o", object)
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

func optIn(t *testing.T) {
	if os.Getenv("IG_ROOT_BARRIER_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel fixture opt-in required")
	}
}

func load(t *testing.T, spec *ebpf.CollectionSpec) *ebpf.Collection {
	t.Helper()
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("verifier: %+v", ve)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() { collection.Close() })
	return collection
}

func attach(t *testing.T, collection *ebpf.Collection, programs ...string) {
	t.Helper()
	for _, name := range programs {
		l, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs[name]})
		if err != nil {
			t.Fatalf("attaching %s: %v", name, err)
		}
		t.Cleanup(func() { l.Close() })
	}
}

func programs(hooks []rootbarrier.Hook) []string {
	var names []string
	for _, h := range hooks {
		names = append(names, h.Program)
	}
	return names
}

// coverCgroup creates a new cgroup and covers it (coverage 1).
func coverCgroup(t *testing.T, collection *ebpf.Collection) string {
	t.Helper()
	cgroup := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("root-barrier-kerneltest-%d", os.Getpid()))
	if err := os.Mkdir(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(cgroup) })
	var st unix.Stat_t
	if err := unix.Stat(cgroup, &st); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["covered_cgroups"].Put(st.Ino, uint32(1)); err != nil {
		t.Fatal(err)
	}
	return cgroup
}

func TestRootBarrierKernel(t *testing.T) {
	optIn(t)
	collection := load(t, compile(t, "testdata/barrier.bpf.c"))
	counters := collection.Maps[rootbarrier.CountersMap]
	probe := collection.Maps[rootbarrier.ProbeMap]
	if err := rootbarrier.Attest(counters, rootbarrier.Hooks); err == nil {
		t.Fatal("attestation passed before any program was attached")
	}
	attach(t, collection, programs(rootbarrier.Hooks)...)
	if err := rootbarrier.VerifyMaps(counters, probe, rootbarrier.Hooks); err != nil {
		t.Fatalf("verify: %v", err)
	}
	cgroup := coverCgroup(t, collection)

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

	// A predicate fault denies under Strict and allows under Audit, and
	// each is counted.
	var st unix.Stat_t
	if err := unix.Stat(cgroup, &st); err != nil {
		t.Fatal(err)
	}
	faultsMap := collection.Maps[rootbarrier.FaultsMap]
	for _, tc := range []struct {
		coverage uint32
		fault    rootbarrier.Fault
		denied   bool
	}{{2, rootbarrier.FaultDenied, true}, {3, rootbarrier.FaultAllowed, false}} {
		if err := collection.Maps["covered_cgroups"].Put(st.Ino, tc.coverage); err != nil {
			t.Fatal(err)
		}
		before, err := rootbarrier.Faults(faultsMap)
		if err != nil {
			t.Fatal(err)
		}
		err = inCgroup(cgroup, "chroot / true")
		if denied := err != nil && strings.Contains(err.Error(), "Operation not permitted"); denied != tc.denied {
			t.Errorf("coverage %d: chroot result %v, want denied %v", tc.coverage, err, tc.denied)
		}
		after, err := rootbarrier.Faults(faultsMap)
		if err != nil {
			t.Fatal(err)
		}
		if after[tc.fault] == before[tc.fault] {
			t.Errorf("coverage %d: fault %d not counted", tc.coverage, tc.fault)
		}
	}
}

const cloneHelperEnv = "IG_ROOT_BARRIER_CLONE_HELPER"

// TestCloneNewNSHelper is run by TestTaskAllocComposition, as a process in
// the covered cgroup: clone(CLONE_NEWNS) must fail with EPERM.
func TestCloneNewNSHelper(t *testing.T) {
	if os.Getenv(cloneHelperEnv) != "1" {
		t.Skip("helper process of TestTaskAllocComposition")
	}
	_, err := syscall.ForkExec("/nonexistent-root-barrier-probe", nil, &syscall.ProcAttr{Sys: &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}})
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("clone(CLONE_NEWNS): %v, want EPERM", err)
	}
}

// A gadget that owns task_alloc and allocates per-task state there. Inline,
// it calls the barrier first and never allocates for a denied clone. With a
// separate rb_task_alloc, one link order runs the owner first: it allocates
// for the clone that the barrier then denies, and the kernel calls task_free
// for it, so no state is left. The other order denies before the owner runs.
func TestTaskAllocComposition(t *testing.T) {
	optIn(t)
	owner := []string{"own_task_alloc", "own_task_free"}
	inline := rootbarrier.WithProgram(rootbarrier.Hooks, "task_alloc", "own_task_alloc")
	cases := []struct {
		name    string
		defines []string
		hooks   []rootbarrier.Hook
		order   []string
	}{
		{"inline", []string{"OWNER_INLINE"}, inline, append(programs(inline), "own_task_free")},
		{"owner attached first", nil, rootbarrier.Hooks, append(slices.Clone(owner), programs(rootbarrier.Hooks)...)},
		{"rb attached first", nil, rootbarrier.Hooks, append(programs(rootbarrier.Hooks), owner...)},
	}
	allocated := map[string]bool{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			collection := load(t, compile(t, "testdata/owner.bpf.c", tc.defines...))
			counters := collection.Maps[rootbarrier.CountersMap]
			attach(t, collection, tc.order...)
			if err := rootbarrier.VerifyMaps(counters, collection.Maps[rootbarrier.ProbeMap], tc.hooks); err != nil {
				t.Fatalf("verify: %v", err)
			}
			cgroup := coverCgroup(t, collection)
			before, err := rootbarrier.Denials(counters)
			if err != nil {
				t.Fatal(err)
			}
			helper := fmt.Sprintf("env %s=1 %s -test.run=^TestCloneNewNSHelper$", cloneHelperEnv, os.Args[0])
			if err := inCgroup(cgroup, helper); err != nil {
				t.Fatalf("helper: %v", err)
			}
			after, err := rootbarrier.Denials(counters)
			if err != nil {
				t.Fatal(err)
			}
			if after[rootbarrier.OpCloneNS] == before[rootbarrier.OpCloneNS] {
				t.Fatal("the barrier did not deny the clone")
			}
			var allocs uint64
			if err := collection.Maps["owner_newns_allocs"].Lookup(uint32(0), &allocs); err != nil {
				t.Fatal(err)
			}
			t.Logf("owner allocations for the denied clone: %d", allocs)
			allocated[tc.name] = allocs > 0
			if tc.name == "inline" && allocs != 0 {
				t.Errorf("inline: the owner allocated before the barrier denied")
			}
			// Every task of the covered cgroup has exited, so no state is
			// left once the kernel has freed them (after an RCU grace
			// period).
			left := 0
			for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(100 * time.Millisecond) {
				var key uint64
				var value uint32
				left = 0
				for it := collection.Maps["owner_tasks"].Iterate(); it.Next(&key, &value); {
					left++
				}
				if left == 0 || time.Now().After(deadline) {
					break
				}
			}
			if left != 0 {
				t.Errorf("%d owner task entries left, want 0 (task_free reclaim)", left)
			}
		})
	}
	// Both orders are tested: the owner allocates (and task_free reclaims)
	// in exactly one of them.
	if allocated[cases[1].name] == allocated[cases[2].name] {
		t.Errorf("separate programs: allocation in %q %v, in %q %v; want it in exactly one order",
			cases[1].name, allocated[cases[1].name], cases[2].name, allocated[cases[2].name])
	}
}
