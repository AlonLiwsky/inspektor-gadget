// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Command verdict-load is a test-only load gate for default-off enforce_exec
// candidate objects on an isolated exact AL2023 kernel. It loads (never
// attaches) the collection and reports per-program verifier statistics. It
// never runs a program and never pins a map.
package main

import (
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

var exactKernels = map[string]string{
	"6.12.113-138.209.amzn2023.x86_64": "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82",
	"6.18.56-125.164.amzn2023.x86_64":  "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee",
}

func kernelCheck() (string, error) {
	if runtime.GOARCH != "amd64" {
		return "", fmt.Errorf("amd64 only")
	}
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", err
	}
	release := unix.ByteSliceToString(u.Release[:])
	want, ok := exactKernels[release]
	if !ok {
		return "", fmt.Errorf("unreviewed kernel %s", release)
	}
	data, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err != nil {
		return "", err
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != want {
		return "", fmt.Errorf("kernel BTF hash mismatch: %s", got)
	}
	return release, nil
}

func tail(s string, lines int) string {
	parts := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(parts) > lines {
		parts = parts[len(parts)-lines:]
	}
	return strings.Join(parts, "\n")
}

func run() error {
	object := flag.String("object", "", "explicit object path")
	live := flag.Bool("run-isolated", false, "load on an isolated exact AL2023 kernel; default inspects only")
	pidMaxMaps := flag.String("pid-max-maps", "", "comma-separated ARRAY maps sized to /proc/sys/kernel/pid_max")
	each := flag.Bool("each", false, "load every program in isolation (single-program attribution)")
	match := flag.String("match", "", "with -each, only programs whose name contains this substring")
	verbose := flag.Int("verbose", 0, "with -each, print this many verifier log tail lines on failure")
	full := flag.Bool("full-log", false, "with -each, request the instruction-level verifier log")
	flag.Parse()
	if *object == "" {
		return fmt.Errorf("-object required")
	}
	spec, err := ebpf.LoadCollectionSpec(*object)
	if err != nil {
		return err
	}
	names := make([]string, 0, len(spec.Programs))
	for name, p := range spec.Programs {
		names = append(names, name)
		fmt.Printf("spec program %s type=%s attach=%s target=%s\n", name, p.Type, p.AttachType, p.AttachTo)
	}
	sort.Strings(names)
	for name, m := range spec.Maps {
		if m.Pinning != ebpf.PinNone {
			return fmt.Errorf("map %s requests pinning", name)
		}
	}
	fmt.Printf("spec: %d programs, %d maps\n", len(spec.Programs), len(spec.Maps))
	if !*live {
		return nil
	}
	release, err := kernelCheck()
	if err != nil {
		return err
	}
	fmt.Printf("kernel %s exact BTF\n", release)
	if *pidMaxMaps != "" {
		raw, err := os.ReadFile("/proc/sys/kernel/pid_max")
		if err != nil {
			return err
		}
		pidMax, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 32)
		if err != nil {
			return err
		}
		for _, name := range strings.Split(*pidMaxMaps, ",") {
			m := spec.Maps[name]
			if m == nil || m.Type != ebpf.Array {
				return fmt.Errorf("pid_max map %s missing or not ARRAY", name)
			}
			m.MaxEntries = uint32(pidMax)
		}
	}
	if err = rlimit.RemoveMemlock(); err != nil {
		return err
	}
	if *each {
		failed := 0
		for _, name := range names {
			if *match != "" && !strings.Contains(name, *match) {
				continue
			}
			one := spec.Copy()
			for other := range one.Programs {
				if other != name {
					delete(one.Programs, other)
				}
			}
			opts := ebpf.ProgramOptions{LogSizeStart: 1 << 20}
			if *full {
				opts = ebpf.ProgramOptions{LogLevel: ebpf.LogLevelInstruction, LogSizeStart: 1 << 30}
			}
			c, err := ebpf.NewCollectionWithOptions(one, ebpf.CollectionOptions{Programs: opts})
			if err != nil {
				failed++
				msg := err.Error()
				if i := strings.Index(msg, "\n"); i > 0 {
					msg = msg[:i]
				}
				if len(msg) > 300 {
					msg = msg[:300]
				}
				fmt.Printf("FAIL %-52s %s\n", name, msg)
				var ve *ebpf.VerifierError
				if *verbose > 0 && errors.As(err, &ve) {
					fmt.Println(tail(fmt.Sprintf("%+v", ve), *verbose))
				}
				continue
			}
			insns := uint32(0)
			if info, err := c.Programs[name].Info(); err == nil {
				insns, _ = info.VerifiedInstructions()
			}
			fmt.Printf("ok   %-52s verified_insns=%d\n", name, insns)
			c.Close()
		}
		if failed != 0 {
			return fmt.Errorf("%d of %d programs failed to load", failed, len(names))
		}
		fmt.Printf("PASS: %d programs loaded individually on %s\n", len(names), release)
		return nil
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 1 << 20},
	})
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			return fmt.Errorf("load failed: %w\n--- verifier tail ---\n%s", err, tail(fmt.Sprintf("%+v", ve), 60))
		}
		return fmt.Errorf("load failed: %w", err)
	}
	defer coll.Close()
	for _, name := range names {
		info, err := coll.Programs[name].Info()
		if err != nil {
			return err
		}
		insns, _ := info.VerifiedInstructions()
		fmt.Printf("loaded %-52s verified_insns=%d\n", name, insns)
	}
	fmt.Printf("PASS: %d programs loaded on %s (load only; nothing attached or run)\n", len(names), release)
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
