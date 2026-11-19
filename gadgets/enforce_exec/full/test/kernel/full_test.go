// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
)

// This fixture attaches only on an explicitly opted-in disposable kernel. Every
// observation is scoped to a newly created cgroup, never the test runner's group.
func TestFullExecKernel(t *testing.T) {
	if os.Getenv("IG_FULL_EXEC_KERNEL_TEST") != "1" {
		t.Skip("requires explicit disposable BPF-LSM kernel opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	source := os.Getenv("IG_FULL_EXEC_BPF_SOURCE")
	if source == "" {
		source = "../../program.bpf.c"
	}
	include := os.Getenv("IG_EXEC_INCLUDE")
	if include == "" {
		include = "../../../../../include"
	}
	headers := os.Getenv("IG_FULL_POLICY_INCLUDE")
	if headers == "" {
		headers = "../../../fullpolicy/bpf"
	}
	temp := t.TempDir()
	cmd := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	vmlinux, err := cmd.Output()
	if err != nil {
		t.Fatalf("vmlinux: %v %s", err, stderr.String())
	}
	if err = os.WriteFile(filepath.Join(temp, "vmlinux.h"), vmlinux, 0o600); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(temp, "full.bpf.o")
	args := []string{"-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86", "-I" + temp, "-I" + include, "-I" + headers, "-c", source, "-o", object}
	if extra := os.Getenv("IG_FULL_LIBBPF_INCLUDE"); extra != "" {
		args = append([]string{"-I" + extra}, args...)
	}
	if out, err := exec.Command("clang", args...).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	base, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	cg := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("ig-full-exec-%d", os.Getpid()))
	if err = os.Mkdir(cg, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cg)
	cgfile, err := os.Open(cg)
	if err != nil {
		t.Fatal(err)
	}
	defer cgfile.Close()
	var stat syscall.Stat_t
	if err = syscall.Fstat(int(cgfile.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	actor, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	actor, err = filepath.EvalSymlinks(actor)
	if err != nil {
		t.Fatal(err)
	}
	target, err := filepath.EvalSymlinks("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	ancestor, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", os.Getppid()))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name   string
		rule   fullpolicy.Rule
		mode   fullpolicy.Mode
		denied bool
	}{
		{"fs-regular-negative", fullpolicy.Rule{Target: fullpolicy.Target{FSType: []string{"tmpfs", "memfd", "deleted", "overlay"}}}, fullpolicy.Enforce, false},
		{"fs-tmpfs", fullpolicy.Rule{Target: fullpolicy.Target{FSType: []string{"tmpfs"}}}, fullpolicy.Enforce, true},
		{"fs-memfd", fullpolicy.Rule{Target: fullpolicy.Target{FSType: []string{"memfd"}}}, fullpolicy.Enforce, true},
		{"fs-deleted", fullpolicy.Rule{Target: fullpolicy.Target{FSType: []string{"deleted"}}}, fullpolicy.Enforce, true},
		{"fs-overlay", fullpolicy.Rule{Target: fullpolicy.Target{FSType: []string{"overlay"}}}, fullpolicy.Enforce, true},
		{"fs-preexisting-unknown", fullpolicy.Rule{Target: fullpolicy.Target{FSType: []string{"memfd"}}}, fullpolicy.Enforce, true},
		{"target-image-positive", fullpolicy.Rule{}, fullpolicy.Enforce, true},
		{"target-image-negative", fullpolicy.Rule{}, fullpolicy.Enforce, false},
		{"target-image-false", fullpolicy.Rule{}, fullpolicy.Enforce, true},
		{"actor-image-positive", fullpolicy.Rule{}, fullpolicy.Enforce, true},
		{"actor-image-negative", fullpolicy.Rule{}, fullpolicy.Enforce, false},
		{"actor-image-false", fullpolicy.Rule{}, fullpolicy.Enforce, true},
		{"mixed-audit-first", fullpolicy.Rule{}, fullpolicy.Audit, true},
		{"mixed-enforce-first", fullpolicy.Rule{}, fullpolicy.Audit, true},
		{"stdin-pipe", fullpolicy.Rule{}, fullpolicy.Enforce, true},
		{"stdin-regular", fullpolicy.Rule{}, fullpolicy.Enforce, false},
		{"stdin-not-pipe", fullpolicy.Rule{}, fullpolicy.Enforce, true},
		{"multi-default", fullpolicy.Rule{}, fullpolicy.Enforce, true},
		{"target-negative", fullpolicy.Rule{Target: fullpolicy.Target{Path: []string{target + "-missing"}}}, fullpolicy.Enforce, false},
		{"uid-negative", fullpolicy.Rule{Actor: fullpolicy.Actor{UID: []int64{int64(os.Geteuid() + 1)}}}, fullpolicy.Enforce, false},
		{"argv-negative", fullpolicy.Rule{Target: fullpolicy.Target{Argv: &fullpolicy.Argv{Contains: []string{"not-present"}}}}, fullpolicy.Enforce, false},
		{"actor-negative", fullpolicy.Rule{Actor: fullpolicy.Actor{Path: []string{actor + "-missing"}}}, fullpolicy.Enforce, false},
		{"target", fullpolicy.Rule{Target: fullpolicy.Target{Path: []string{target}}}, fullpolicy.Enforce, true},
		{"uid", fullpolicy.Rule{Actor: fullpolicy.Actor{UID: []int64{int64(os.Geteuid())}}}, fullpolicy.Enforce, true},
		{"argv", fullpolicy.Rule{Target: fullpolicy.Target{Argv: &fullpolicy.Argv{Contains: []string{"deny-me"}}}}, fullpolicy.Enforce, true},
		{"argv-audit", fullpolicy.Rule{Target: fullpolicy.Target{Argv: &fullpolicy.Argv{Contains: []string{"deny-me"}}}}, fullpolicy.Audit, false},
		{"actor", fullpolicy.Rule{Actor: fullpolicy.Actor{Path: []string{actor}}}, fullpolicy.Enforce, true},
		{"ancestor", fullpolicy.Rule{Actor: fullpolicy.Actor{Ancestor: &fullpolicy.Ancestor{Path: []string{actor}, Depth: 1}}}, fullpolicy.Enforce, true},
		{"ancestor-negative", fullpolicy.Rule{Actor: fullpolicy.Actor{Ancestor: &fullpolicy.Ancestor{Path: []string{ancestor + "-missing"}, Depth: 1}}}, fullpolicy.Enforce, false},
	}
	for index, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if strings.HasPrefix(tc.name, "stdin-") {
				expected := tc.name != "stdin-not-pipe"
				tc.rule.Target.Argv = &fullpolicy.Argv{StdinIsPipe: &expected}
			}
			imageRule := strings.Contains(tc.name, "-image-")
			if imageRule {
				value := !strings.HasSuffix(tc.name, "-false")
				if strings.HasPrefix(tc.name, "actor-") {
					tc.rule.Actor.FromImage = &value
				} else {
					tc.rule.Target.FromImage = &value
				}
			}
			tc.rule.Name = "rule"
			tc.rule.Action = fullpolicy.Deny
			generation := uint64(index + 1)
			policies := []fullpolicy.Policy{{ID: "p", Revision: "r", Mode: tc.mode, Default: fullpolicy.Allow, Rules: []fullpolicy.Rule{tc.rule}}}
			if tc.name == "multi-default" {
				policies = []fullpolicy.Policy{
					{ID: "allow", Revision: "r", Mode: fullpolicy.Enforce, Default: fullpolicy.Allow},
					{ID: "deny", Revision: "r", Mode: fullpolicy.Enforce, Default: fullpolicy.Deny},
				}
			}
			if strings.HasPrefix(tc.name, "mixed-") {
				audit := fullpolicy.Rule{Name: "audit", Action: fullpolicy.Deny, Mode: fullpolicy.Audit, Target: fullpolicy.Target{Path: []string{target}}}
				enforce := audit
				enforce.Name = "enforce"
				enforce.Mode = fullpolicy.Enforce
				policies[0].Rules = []fullpolicy.Rule{audit, enforce}
				if tc.name == "mixed-enforce-first" {
					policies[0].Rules = []fullpolicy.Rule{enforce, audit}
				}
			}
			program, err := fullpolicy.CompileKernel(policies, generation, "worker")
			if err != nil {
				t.Fatal(err)
			}
			collection, err := ebpf.NewCollectionWithOptions(base.Copy(), ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 16 * 1024 * 1024}})
			if err != nil {
				var verifier *ebpf.VerifierError
				if errors.As(err, &verifier) {
					t.Logf("%+v", verifier)
				}
				t.Fatalf("verifier/load: %v", err)
			}
			defer collection.Close()
			for i, blob := range program.Entries {
				if err = collection.Maps["full_program"].Put(uint32(i), blob); err != nil {
					t.Fatal(err)
				}
			}
			if err = collection.Maps["full_program"].Freeze(); err != nil {
				t.Fatal(err)
			}
			if err = collection.Maps["policy"].Put(uint32(0), execpolicy.KernelEntry{Generation: generation, Mode: 2}); err != nil {
				t.Fatal(err)
			}
			if err = collection.Maps["policy"].Freeze(); err != nil {
				t.Fatal(err)
			}
			// Controlled synthetic membership tests the reader/evaluator plumbing,
			// not the external owner's complete lower-root attestation algorithm.
			if imageRule && strings.HasSuffix(tc.name, "-positive") {
				path := target
				if strings.HasPrefix(tc.name, "actor-") {
					path = actor
				}
				var backing syscall.Stat_t
				requireStat := syscall.Stat(path, &backing)
				if requireStat != nil {
					t.Fatal(requireStat)
				}
				key := struct {
					Inode        uint64
					Major, Minor uint32
				}{backing.Ino, unix.Major(uint64(backing.Dev)), unix.Minor(uint64(backing.Dev))}
				if err = collection.Maps["image_origins"].Put(key, uint8(1)); err != nil {
					t.Fatal(err)
				}
			}
			if err = collection.Maps["image_origins"].Freeze(); err != nil {
				t.Fatal(err)
			}
			var originReady uint32
			if imageRule {
				originReady = 1
			}
			if err = collection.Maps["image_ready"].Put(uint32(0), originReady); err != nil {
				t.Fatal(err)
			}
			if err = collection.Maps["image_ready"].Freeze(); err != nil {
				t.Fatal(err)
			}
			var executableFD *os.File
			makeMemfd := func() *os.File {
				t.Helper()
				fd, e := unix.MemfdCreate("full-policy-memfd", 0)
				if e != nil {
					t.Fatal(e)
				}
				file := os.NewFile(uintptr(fd), "memfd")
				data, e := os.ReadFile(target)
				if e != nil {
					file.Close()
					t.Fatal(e)
				}
				if _, e = file.Write(data); e != nil {
					file.Close()
					t.Fatal(e)
				}
				if e = file.Chmod(0o755); e != nil {
					file.Close()
					t.Fatal(e)
				}
				t.Cleanup(func() { file.Close() })
				return file
			}
			if tc.name == "fs-preexisting-unknown" {
				executableFD = makeMemfd()
			}
			tracker, e := link.AttachLSM(link.LSMOptions{Program: collection.Programs["enforce_exec_track_memfd"]})
			if e != nil {
				t.Fatal(e)
			}
			defer tracker.Close()
			if tc.name == "fs-memfd" {
				executableFD = makeMemfd()
			}
			if tc.name == "fs-tmpfs" || tc.name == "fs-deleted" || tc.name == "fs-overlay" {
				fsroot := t.TempDir()
				fsTarget := filepath.Join(fsroot, "target")
				data, e := os.ReadFile(target)
				if e != nil {
					t.Fatal(e)
				}
				if tc.name == "fs-tmpfs" {
					if e = unix.Mount("tmpfs", fsroot, "tmpfs", 0, "size=8m"); e != nil {
						t.Fatal(e)
					}
					defer func() {
						if e := unix.Unmount(fsroot, 0); e != nil {
							t.Errorf("tmpfs cleanup: %v", e)
						}
					}()
				}
				if tc.name == "fs-overlay" {
					lower, upper, work, merged := filepath.Join(fsroot, "lower"), filepath.Join(fsroot, "upper"), filepath.Join(fsroot, "work"), filepath.Join(fsroot, "merged")
					for _, dir := range []string{lower, upper, work, merged} {
						if e = os.Mkdir(dir, 0o755); e != nil {
							t.Fatal(e)
						}
					}
					if e = os.WriteFile(filepath.Join(lower, "target"), data, 0o755); e != nil {
						t.Fatal(e)
					}
					if e = unix.Mount("overlay", merged, "overlay", 0, fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)); e != nil {
						t.Fatal(e)
					}
					defer func() {
						if e := unix.Unmount(merged, 0); e != nil {
							t.Errorf("overlay cleanup: %v", e)
						}
					}()
					fsTarget = filepath.Join(merged, "target")
				} else if e = os.WriteFile(fsTarget, data, 0o755); e != nil {
					t.Fatal(e)
				}
				executableFD, e = os.Open(fsTarget)
				if e != nil {
					t.Fatal(e)
				}
				defer executableFD.Close()
				if tc.name == "fs-deleted" {
					if e = os.Remove(fsTarget); e != nil {
						t.Fatal(e)
					}
				}
			}
			command := func() *exec.Cmd {
				path := target
				if executableFD != nil {
					path = "/proc/self/fd/3"
				}
				cmd := exec.Command(path, "deny-me")
				if executableFD != nil {
					cmd.ExtraFiles = []*os.File{executableFD}
				}
				return cmd
			}
			attached, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs["enforce_exec_full"]})
			if err != nil {
				t.Fatal(err)
			}
			defer attached.Close()
			if err = collection.Maps["bindings"].Put(stat.Ino, uint64(0)); err != nil {
				t.Fatal(err)
			}
			defer collection.Maps["bindings"].Delete(stat.Ino)
			var stdin *os.File
			if tc.name == "stdin-pipe" {
				reader, writer, e := os.Pipe()
				if e != nil {
					t.Fatal(e)
				}
				defer reader.Close()
				defer writer.Close()
				stdin = reader
			} else if strings.HasPrefix(tc.name, "stdin-") {
				stdin, err = os.Open(target)
				if err != nil {
					t.Fatal(err)
				}
				defer stdin.Close()
			}
			run := command()
			run.Stdin = stdin
			run.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgfile.Fd())}
			err = run.Run()
			if tc.denied {
				if !errors.Is(err, syscall.EPERM) {
					t.Fatalf("expected EPERM, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("expected allow: %v", err)
			}
			var faults uint64
			if err = collection.Maps["full_faults"].Lookup(uint32(0), &faults); err != nil {
				t.Fatal(err)
			}
			if faults != 0 && tc.name != "fs-preexisting-unknown" {
				t.Fatalf("decision used an observation/evaluation error, fault mask %d", faults)
			}
			if tc.name == "fs-preexisting-unknown" && faults&4 == 0 {
				t.Fatal("unknown memfd fact did not produce sticky operational fault")
			}
			var remaining uint64
			if err = collection.Maps["observations"].NextKey(nil, &remaining); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("scratch not reclaimed: key %d error %v", remaining, err)
			}
			// In-place revision mutation must fail; the old decision remains.
			if err = collection.Maps["full_program"].Put(uint32(0), fullpolicy.Blob{}); err == nil {
				t.Fatal("frozen revision accepted mutation")
			}
			retry := command()
			retry.Stdin = stdin
			retry.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgfile.Fd())}
			err = retry.Run()
			if tc.denied {
				if !errors.Is(err, syscall.EPERM) {
					t.Fatalf("old decision after rejected mutation: %v", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			// Outside the exact binding remains unaffected, including identical argv.
			if err = command().Run(); err != nil {
				t.Fatalf("unbound control: %v", err)
			}
		})
	}
}
