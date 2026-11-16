// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	execpolicy "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/policy"
)

type entry struct {
	Generation                                     uint64
	Mode, DefaultDeny, Count, Deny, Prefix, Length uint32
	Path                                           [256]byte
}

func TestExecKernel(t *testing.T) {
	if os.Getenv("IG_EXEC_KERNEL_TEST") != "1" {
		t.Skip("set IG_EXEC_KERNEL_TEST=1 on a disposable BPF-LSM/cgroup-v2 host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	source := os.Getenv("IG_EXEC_BPF_SOURCE")
	if source == "" {
		source = "bpf/exec.bpf.c"
	}
	tmp := t.TempDir()
	run := func(t *testing.T, name string, args ...string) []byte {
		t.Helper()
		out, err := exec.Command(name, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v\n%s", name, err, out)
		}
		return out
	}
	t.Logf("kernel: %s", run(t, "uname", "-a"))
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("LSMs: %s", lsm)
	if !strings.Contains(string(lsm), "bpf") {
		t.Fatal("BPF LSM is not enabled")
	}
	// Diagnostics are not C source: bpftool may write informational warnings
	// to stderr even on success. Keep them out of the generated header.
	cmd := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c")
	var diagnostics bytes.Buffer
	cmd.Stderr = &diagnostics
	header, err := cmd.Output()
	if err != nil {
		t.Fatalf("generate vmlinux.h: %v\n%s", err, diagnostics.String())
	}
	if err := os.WriteFile(filepath.Join(tmp, "vmlinux.h"), header, 0o600); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(tmp, "exec.bpf.o")
	include := os.Getenv("IG_EXEC_INCLUDE")
	if include == "" {
		include = "../../../../include"
	}
	run(t, "clang", "-O2", "-g", "-target", "bpf", "-D__TARGET_ARCH_x86", "-I"+tmp, "-I"+include, "-c", source, "-o", object)
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024}})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("%+v", verifier)
		}
		t.Fatalf("load/verifier: %v", err)
	}
	defer func() { collection.Close() }()
	attached, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs["enforce_exec"]})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { attached.Close() }()
	observer, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs["preserve_previous"]})
	if err != nil {
		t.Fatal(err)
	}
	defer observer.Close()
	cg := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("ig-exec-test-%d", os.Getpid()))
	if err := os.Mkdir(cg, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cg)
	cgFile, err := os.Open(cg)
	if err != nil {
		t.Fatal(err)
	}
	defer cgFile.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(cgFile.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	cgid := stat.Ino
	bindings := collection.Maps["bindings"]
	defer func() { bindings.Delete(cgid) }()
	mkdir := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	allowed := filepath.Join(tmp, "allowed")
	mkdir(t, allowed)
	sibling := filepath.Join(tmp, "allowed-other")
	mkdir(t, sibling)
	copyExe := func(t *testing.T, dst string) {
		t.Helper()
		b, err := os.ReadFile("/usr/bin/true")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(dst, b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	good, bad := filepath.Join(allowed, "tool"), filepath.Join(sibling, "tool")
	copyExe(t, good)
	copyExe(t, bad)
	publish := func(t *testing.T, gen uint64, mode, def uint32, paths []string, denies []bool, modes ...[]uint32) {
		t.Helper()
		next, err := ebpf.NewCollection(spec)
		if err != nil {
			t.Fatal(err)
		}
		committed := false
		defer func() {
			if !committed {
				next.Close()
			}
		}()
		if len(paths) > execpolicy.KernelMaxRules || len(denies) != len(paths) || (len(modes) > 0 && len(modes[0]) != len(paths)) {
			t.Fatal("invalid test rules")
		}
		inner := next.Maps["policy"]
		h := entry{Generation: gen, Mode: mode, DefaultDeny: def, Count: uint32(len(paths))}
		if err := inner.Put(uint32(0), h); err != nil {
			t.Fatal(err)
		}
		for i, p := range paths {
			r := entry{}
			if len(modes) > 0 {
				r.Mode = modes[0][i]
			}
			if strings.HasSuffix(p, "/**") {
				r.Prefix = 1
				p = strings.TrimSuffix(p, "**")
			}
			if len(p) >= 256 {
				t.Fatal("test rule too long")
			}
			r.Length = uint32(len(p))
			copy(r.Path[:], p)
			if denies[i] {
				r.Deny = 1
			}
			if err := inner.Put(uint32(i+1), r); err != nil {
				t.Fatal(err)
			}
		}
		if err := inner.Freeze(); err != nil {
			t.Fatal(err)
		}
		if err := next.Maps["bindings"].Put(cgid, uint64(0)); err != nil {
			t.Fatal(err)
		}
		nextLink, err := link.AttachLSM(link.LSMOptions{Program: next.Programs["enforce_exec"]})
		if err != nil {
			t.Fatal(err)
		}
		attached.Close()
		collection.Close()
		attached, collection, bindings = nextLink, next, next.Maps["bindings"]
		committed = true
		if err := inner.Put(uint32(0), h); !errors.Is(err, syscall.EPERM) {
			t.Fatalf("frozen policy write: %v", err)
		}
	}
	execute := func(path string, managed bool) error {
		cmd := exec.Command(path)
		if managed {
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgFile.Fd())}
		}
		return cmd.Run()
	}
	expect := func(t *testing.T, path string, managed, deny bool) {
		t.Helper()
		err := execute(path, managed)
		if deny {
			if !errors.Is(err, syscall.EPERM) {
				t.Fatalf("%s expected EPERM, got %v", path, err)
			}
		} else if err != nil {
			t.Fatalf("%s expected success: %v", path, err)
		}
	}
	t.Run("scope-and-path", func(t *testing.T) {
		publish(t, 1, 2, 1, []string{allowed + "/**"}, []bool{false})
		expect(t, good, true, false)
		expect(t, bad, true, true)
		expect(t, bad, false, false)
		alias := filepath.Join(allowed, "alias")
		if err := os.Symlink(bad, alias); err != nil {
			t.Fatal(err)
		}
		expect(t, alias, true, true)
		// Object identity remains unchanged, but moving out of the allowed directory must deny.
		moved := filepath.Join(sibling, "moved")
		if err := os.Rename(good, moved); err != nil {
			t.Fatal(err)
		}
		expect(t, moved, true, true)
		copyExe(t, good)
		expect(t, good, true, false)
	})
	t.Run("modes-and-precedence", func(t *testing.T) {
		publish(t, 2, 2, 1, []string{allowed + "/**", good}, []bool{false, true})
		expect(t, good, true, true)
		publish(t, 3, 1, 1, nil, nil)
		expect(t, good, true, false)
		publish(t, 4, 0, 1, nil, nil)
		expect(t, bad, true, false)
	})
	t.Run("larger-than-eight-paths", func(t *testing.T) {
		paths := make([]string, execpolicy.KernelMaxRules)
		denies := make([]bool, len(paths))
		for i := range paths {
			paths[i] = fmt.Sprintf("/unused/%d", i)
		}
		paths[len(paths)-1] = good
		publish(t, 20, 2, 1, paths, denies)
		expect(t, good, true, false)
		expect(t, bad, true, true)
		// The last rule also participates in deny precedence.
		paths[0] = allowed + "/**"
		denies[len(denies)-1] = true
		publish(t, 21, 2, 0, paths, denies)
		expect(t, good, true, true)
	})
	t.Run("mixed-rule-modes", func(t *testing.T) {
		cases := []struct {
			name                    string
			policyMode, defaultDeny uint32
			denies                  []bool
			modes                   []uint32
			blocked, wouldDeny      bool
			verdictMode             uint32
		}{
			{"audit-override", 2, 1, []bool{true}, []uint32{1}, false, true, 1},
			{"enforce-override", 1, 0, []bool{true}, []uint32{2}, true, true, 2},
			{"audit-before-enforce", 1, 0, []bool{true, true, false}, []uint32{1, 2, 0}, true, true, 2},
			{"enforce-before-audit", 1, 0, []bool{false, true, true}, []uint32{0, 2, 1}, true, true, 2},
			{"audit-deny-beats-allow", 2, 1, []bool{false, true}, []uint32{2, 1}, false, true, 1},
			{"allow-suppresses-default", 2, 1, []bool{false}, []uint32{1}, false, false, 2},
		}
		for i, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				paths := make([]string, len(tc.denies))
				for i := range paths {
					paths[i] = good
				}
				publish(t, uint64(30+i), tc.policyMode, tc.defaultDeny, paths, tc.denies, tc.modes)
				reader, err := ringbuf.NewReader(collection.Maps["events"])
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				reader.SetDeadline(time.Now().Add(5 * time.Second))
				expect(t, good, true, tc.blocked)
				record, err := reader.Read()
				if err != nil {
					t.Fatal(err)
				}
				if len(record.RawSample) < 32 {
					t.Fatal("short verdict")
				}
				deny, mode := binary.LittleEndian.Uint32(record.RawSample[16:20]), binary.LittleEndian.Uint32(record.RawSample[20:24])
				if (deny != 0) != tc.wouldDeny || mode != tc.verdictMode {
					t.Fatalf("verdict deny=%d mode=%d", deny, mode)
				}
			})
		}
	})
	t.Run("scripts", func(t *testing.T) {
		script := filepath.Join(allowed, "script")
		if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		publish(t, 5, 2, 1, []string{allowed + "/**"}, []bool{false})
		expect(t, script, true, true)
		shell, err := filepath.EvalSymlinks("/bin/sh")
		if err != nil {
			t.Fatal(err)
		}
		publish(t, 6, 2, 1, []string{allowed + "/**", shell}, []bool{false, false})
		expect(t, script, true, false)
	})
	t.Run("path-resolution-error", func(t *testing.T) {
		longDir := filepath.Join(tmp, strings.Repeat("a", 120), strings.Repeat("b", 120))
		mkdir(t, longDir)
		longExe := filepath.Join(longDir, "tool")
		copyExe(t, longExe)
		publish(t, 7, 2, 0, nil, nil)
		expect(t, longExe, true, true)
		publish(t, 8, 1, 0, nil, nil)
		expect(t, longExe, true, false)
		var counts []uint64
		if err := collection.Maps["counters"].Lookup(uint32(4), &counts); err != nil {
			t.Fatal(err)
		}
		var failures uint64
		for _, n := range counts {
			failures += n
		}
		if failures < 1 {
			t.Fatalf("expected path resolution failures, got %d", failures)
		}
	})
	t.Run("reporting-saturation", func(t *testing.T) {
		publish(t, 7, 2, 1, nil, nil)
		for range 1000 {
			expect(t, bad, true, true)
		}
		var counts []uint64
		if err := collection.Maps["counters"].Lookup(uint32(2), &counts); err != nil {
			t.Fatal(err)
		}
		var lost uint64
		for _, v := range counts {
			lost += v
		}
		if lost == 0 {
			t.Fatal("expected ring buffer loss with no reader")
		}
		t.Logf("reports lost while blocking: %d", lost)
		if err := collection.Maps["counters"].Lookup(uint32(5), &counts); err != nil {
			t.Fatal(err)
		}
		var limited uint64
		for _, n := range counts {
			limited += n
		}
		if limited == 0 {
			t.Fatal("expected reporting rate limit while blocking")
		}
		t.Logf("reports rate limited while blocking: %d", limited)
	})
	t.Run("overlap-replacement", func(t *testing.T) {
		publish(t, 100, 2, 1, nil, nil)
		var unexpected atomic.Uint64
		stop := make(chan struct{})
		done := make(chan struct{})
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				default:
					if err := execute(bad, true); !errors.Is(err, syscall.EPERM) {
						unexpected.Add(1)
					}
				}
			}
		}()
		var once sync.Once
		finish := func() { once.Do(func() { close(stop); <-done }) }
		t.Cleanup(finish)
		for generation := uint64(101); generation < 121; generation++ {
			publish(t, generation, 2, 1, nil, nil)
			time.Sleep(time.Millisecond)
		}
		finish()
		if unexpected.Load() != 0 {
			t.Fatalf("replacement permitted %d executions", unexpected.Load())
		}
	})
	t.Run("live-binding-churn", func(t *testing.T) {
		for range 10 {
			if err := bindings.Delete(cgid); err != nil {
				t.Fatal(err)
			}
			expect(t, bad, true, false)
			if err := bindings.Put(cgid, uint64(0)); err != nil {
				t.Fatal(err)
			}
			expect(t, bad, true, true)
		}
	})
}
