// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
// Explicit isolated observer runner. Never loads/unloads the native module.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type argvResult struct {
	ABI, Status, Argc, Bytes, Complete uint32
	Error                              int32
	Offsets                            [64]uint32
	Data                               [4096]byte
}
type sample struct {
	PIDTGID              uint64
	Prior                int64
	Bprm, Task, PendingP uint64
	Result               int32
	Reserved             uint32
	Argv                 argvResult
}

func digest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func run() error {
	object := flag.String("object", "", "reviewed observer BPF object")
	cgroup := flag.String("cgroup", "", "existing empty isolated cgroup2")
	executable := flag.String("exe", "/bin/true", "controlled ELF executable")
	scenario := flag.String("case", "short", "short,args64,bytes4096,args65,bytes4097,empty,nonascii,environment,shebang,pagecross")
	flag.Parse()
	if os.Geteuid() != 0 || !filepath.IsAbs(*object) || !filepath.IsAbs(*cgroup) || !filepath.IsAbs(*executable) || !strings.HasPrefix(filepath.Base(*cgroup), "ig15-g020-kfunc-") {
		return errors.New("root, explicit absolute object/cgroup/exe and ig15-g020-kfunc-* cgroup required")
	}
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return err
	}
	release := string(bytes.TrimRight(uname.Release[:], "\x00"))
	profiles := map[string][2]string{
		"6.12.113-138.209.amzn2023.x86_64": {"b1f1af82aafa27641685457572d1ee2b135853e2c30b37ae7c40d9dcc6252666", "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82"},
		"6.18.56-125.164.amzn2023.x86_64":  {"537cd20f54e670b9e855d0b72b8b340a2c8f526af6449d94675bfb7c363a1068", "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee"},
	}
	profile, ok := profiles[release]
	if !ok {
		return fmt.Errorf("unproved kernel %q", release)
	}
	for i, path := range []string{"/boot/vmlinuz-" + release, "/sys/kernel/btf/vmlinux"} {
		got, err := digest(path)
		if err != nil {
			return err
		}
		if got != profile[i] {
			return fmt.Errorf("identity mismatch %s: %s", path, got)
		}
	}
	if _, err := os.Stat("/sys/kernel/btf/ig_argv_kfunc"); err != nil {
		return fmt.Errorf("reviewed module BTF must already be loaded: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(*cgroup)
	if err != nil {
		return err
	}
	if resolved != *cgroup {
		return errors.New("cgroup must be canonical")
	}
	var fs unix.Statfs_t
	if err = unix.Statfs(*cgroup, &fs); err != nil {
		return err
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return errors.New("not cgroup2")
	}
	procs, err := os.ReadFile(filepath.Join(*cgroup, "cgroup.procs"))
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(procs)) != 0 {
		return errors.New("cgroup is not empty")
	}
	var st unix.Stat_t
	if err = unix.Stat(*cgroup, &st); err != nil {
		return err
	}
	args := []string{*executable, "ig15-"}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		return err
	}
	args[1] += hex.EncodeToString(random)
	env := []string{}
	oversized := false
	commandPath := *executable
	var phases [][]string
	expectedOutput := ""
	switch *scenario {
	case "short":
	case "args64", "args65":
		n := 64
		if *scenario == "args65" {
			n = 65
			oversized = true
		}
		for len(args) < n {
			args = append(args, "")
		}
	case "bytes4096", "bytes4097", "pagecross":
		n := 4096
		if *scenario == "bytes4097" {
			n++
			oversized = true
		}
		if len(args[0])+2 >= n {
			return errors.New("executable path too long")
		}
		args[1] = strings.Repeat("x", n-len(args[0])-2)
		if *scenario == "pagecross" {
			env = []string{"IG_PAGE_OFFSET=" + strings.Repeat("e", 97)}
		}
	case "empty":
		args[1] = ""
	case "nonascii":
		args[1] = "\xff\xfe\x80"
	case "shebang":
		if strings.ContainsAny(*executable, " \t\r\n") || len(*executable)+len("#! --ig-argv-phase\n") >= 256 {
			return errors.New("short whitespace-free ELF interpreter path required")
		}
		ef, err := elf.Open(*executable)
		if err != nil {
			return fmt.Errorf("controlled ELF interpreter: %w", err)
		}
		ef.Close()
		dir, err := os.MkdirTemp("/run", "ig15-g020-phase-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(dir)
		commandPath = filepath.Join(dir, "script")
		if err := os.WriteFile(commandPath, []byte("#!"+*executable+" --ig-argv-phase\n"), 0o700); err != nil {
			return err
		}
		args[0] = commandPath
		phases = [][]string{append([]string(nil), args...), {*executable, "--ig-argv-phase", commandPath, args[1]}}
		env = []string{"IG_EXPECT_SCRIPT=" + commandPath, "IG_EXPECT_NONCE=" + args[1]}
		expectedOutput = "IG_PHASE_HELPER_OK\n"
	case "environment":
		env = []string{"IG_UNRELATED=" + strings.Repeat("e", 16384)}
	default:
		return fmt.Errorf("unknown case %q", *scenario)
	}
	if phases == nil {
		phases = [][]string{args}
	}
	if err = rlimit.RemoveMemlock(); err != nil {
		return err
	}
	spec, err := ebpf.LoadCollectionSpec(*object)
	if err != nil {
		return err
	}
	p := spec.Programs["ig_argv_observe"]
	if p == nil || p.Type != ebpf.LSM || p.Flags != unix.BPF_F_SLEEPABLE || p.AttachTo != "bprm_check_security" {
		return errors.New("exact sleepable LSM observer required")
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{"ig_argv_observe": p}
	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20}})
	if err != nil {
		var v *ebpf.VerifierError
		if errors.As(err, &v) {
			return fmt.Errorf("verifier: %+w", v)
		}
		return err
	}
	defer c.Close()
	gate, seen, samples := c.Maps["ig_argv_gate"], c.Maps["ig_argv_seen"], c.Maps["ig_argv_samples"]
	if gate == nil || seen == nil || samples == nil || gate.ValueSize() != 16 || seen.ValueSize() != 8 || samples.ValueSize() != 4424 || samples.MaxEntries() != 16 {
		return errors.New("unexpected observer map ABI")
	}
	if err = gate.Update(uint32(0), struct {
		Cgroup            uint64
		Enabled, Reserved uint32
	}{st.Ino, 1, 0}, ebpf.UpdateAny); err != nil {
		return err
	}
	if err = gate.Freeze(); err != nil {
		return err
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: c.Programs["ig_argv_observe"]})
	if err != nil {
		return err
	}
	defer l.Close()
	cg, err := os.Open(*cgroup)
	if err != nil {
		return err
	}
	defer cg.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, commandPath, args[1:]...)
	cmd.Args = args
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("observer interrupted controlled exec: %w output=%q", err, output)
	}
	if *scenario == "shebang" && string(output) != expectedOutput {
		return fmt.Errorf("interpreter result mismatch: %q", output)
	}
	var count uint64
	if err = seen.Lookup(uint32(0), &count); err != nil {
		return err
	}
	if count != uint64(len(phases)) {
		return fmt.Errorf("expected %d exact phases, got %d", len(phases), count)
	}
	observations := make([]sample, len(phases))
	for i := range observations {
		if err := samples.Lookup(uint32(i), &observations[i]); err != nil {
			return err
		}
	}
	if err := validateSamples(observations, uint64(cmd.Process.Pid), phases, oversized, *scenario == "pagecross"); err != nil {
		return err
	}
	fmt.Printf("PASS %s %s: observer-only exact pending argv; no policy/Ready claim\n", release, *scenario)
	return nil
}

// Every expected phase must be present, ordered, and attributed to the same
// physical bprm/task. Pointer correlation is confined to this isolated fixture;
// it is not a reusable lifetime identity or a product authorization token.
func validateSamples(ss []sample, pid uint64, phases [][]string, oversized, pagecross bool) error {
	if len(ss) != len(phases) || len(ss) == 0 {
		return errors.New("incomplete phase sequence")
	}
	first := ss[0]
	for i, s := range ss {
		if s.PIDTGID != pid<<32|pid || s.Prior != 0 || s.Reserved != 0 || s.Bprm == 0 || s.Task == 0 || s.PendingP == 0 || s.Bprm != first.Bprm || s.Task != first.Task {
			return fmt.Errorf("phase %d identity/prior mismatch", i)
		}
		if err := validateWire(s, phases[i], oversized); err != nil {
			return fmt.Errorf("phase %d: %w", i, err)
		}
		if !oversized && (s.PendingP > ^uint64(0)-uint64(s.Argv.Bytes) || first.PendingP > ^uint64(0)-uint64(first.Argv.Bytes) || s.PendingP+uint64(s.Argv.Bytes) != first.PendingP+uint64(first.Argv.Bytes)) {
			return errors.New("rewritten argv endpoint mismatch")
		}
	}
	if pagecross {
		s := ss[0]
		if len(ss) != 1 || len(phases[0]) != 2 || oversized {
			return errors.New("invalid page-crossing fixture")
		}
		start := s.PendingP + uint64(s.Argv.Offsets[1])
		n := uint64(len(phases[0][1]) + 1)
		if n == 0 || start > ^uint64(0)-(n-1) || start/4096 == (start+n-1)/4096 {
			return errors.New("observed argument did not cross a 4KiB page")
		}
	}
	return nil
}

// Compare the entire fixed wire, including error and unused zero-filled tails.
func validateWire(s sample, args []string, oversized bool) error {
	expected := argvResult{ABI: 1}
	var result int32
	if oversized {
		result = -int32(unix.E2BIG)
		expected.Status, expected.Error = 2, result
	} else {
		canonical := []byte(strings.Join(args, "\x00") + "\x00")
		if len(args) > 64 || len(canonical) > 4096 {
			return errors.New("invalid positive fixture")
		}
		expected.Status, expected.Complete = 1, 1
		expected.Argc, expected.Bytes = uint32(len(args)), uint32(len(canonical))
		copy(expected.Data[:], canonical)
		offset := 0
		for i, arg := range args {
			expected.Offsets[i] = uint32(offset)
			offset += len(arg) + 1
		}
	}
	if s.Result != result || s.Argv != expected {
		return errors.New("complete argv wire mismatch (including errno, offsets and zero tails)")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
