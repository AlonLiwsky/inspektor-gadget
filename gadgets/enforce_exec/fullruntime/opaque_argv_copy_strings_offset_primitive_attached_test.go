// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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

type opaqueArgvOffsetProfile struct {
	release, imageSHA, btfSHA string
	profile                   uint32
	offset                    uint64
}

var opaqueArgvOffsetProfiles = []opaqueArgvOffsetProfile{
	{"6.12.113-138.209.amzn2023.x86_64", "b1f1af82aafa27641685457572d1ee2b135853e2c30b37ae7c40d9dcc6252666", "0d7b3abe2b50e1b252b167061fea565e78fb712b691d1c04dd5651872dafcd82", 1, 0x180},
	{"6.18.56-125.164.amzn2023.x86_64", "537cd20f54e670b9e855d0b72b8b340a2c8f526af6449d94675bfb7c363a1068", "d0b0dffa66e521cdfafccc4c640f530fc14fbcf9d459275d04cd9d5d481b15ee", 2, 0x1ad},
}

func opaqueArgvOffsetProfileFor(release, imageSHA, btfSHA string) (opaqueArgvOffsetProfile, error) {
	for _, profile := range opaqueArgvOffsetProfiles {
		if release == profile.release && imageSHA == profile.imageSHA && btfSHA == profile.btfSHA {
			return profile, nil
		}
	}
	return opaqueArgvOffsetProfile{}, fmt.Errorf("unproved offset layout: release=%q image=%q BTF=%q", release, imageSHA, btfSHA)
}

func TestOpaqueArgvOffsetProfileIdentity(t *testing.T) {
	for _, profile := range opaqueArgvOffsetProfiles {
		got, err := opaqueArgvOffsetProfileFor(profile.release, profile.imageSHA, profile.btfSHA)
		if err != nil || got != profile {
			t.Fatalf("exact profile: got=%+v err=%v", got, err)
		}
		for _, identity := range [][3]string{
			{"other", profile.imageSHA, profile.btfSHA},
			{profile.release, "other", profile.btfSHA},
			{profile.release, profile.imageSHA, "other"},
			{"", "", ""},
		} {
			if _, err := opaqueArgvOffsetProfileFor(identity[0], identity[1], identity[2]); err == nil {
				t.Fatalf("mismatched identity accepted: %q", identity)
			}
		}
	}
}

// This fixture observes two short, controlled argv strings only. It does not
// establish complete pending-mm argv, kernel strings, races or enforcement.
func TestOpaqueArgvCopyStringsOffsetPrimitiveAttached(t *testing.T) {
	object, cgroup, executable := os.Getenv("IG_OPAQUE_ARGV_OFFSET_OBJECT"), os.Getenv("IG_OPAQUE_ARGV_OFFSET_CGROUP"), os.Getenv("IG_OPAQUE_ARGV_OFFSET_EXECUTABLE")
	if object == "" && cgroup == "" && executable == "" {
		t.Skip("set explicit offset object, isolated cgroup and executable")
	}
	if os.Geteuid() != 0 || !filepath.IsAbs(object) || !filepath.IsAbs(cgroup) || !filepath.IsAbs(executable) || !strings.HasPrefix(filepath.Base(cgroup), "ig15-g020-argv-") || len(executable)+1 > 128 {
		t.Fatal("root, absolute paths, short executable path and dedicated ig15-g020-argv-* cgroup required")
	}
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		t.Fatal(err)
	}
	cstr := func(value []byte) string { return string(bytes.TrimRight(value, "\x00")) }
	if cstr(uname.Machine[:]) != "x86_64" {
		t.Fatal("only exact x86_64 profiles are understood")
	}
	release := cstr(uname.Release[:])
	fileSHA := func(path string) string {
		t.Helper()
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		hash := sha256.New()
		if _, err := io.Copy(hash, file); err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(hash.Sum(nil))
	}
	profile, err := opaqueArgvOffsetProfileFor(release, fileSHA("/boot/vmlinuz-"+release), fileSHA("/sys/kernel/btf/vmlinux"))
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(cgroup)
	if err != nil || resolved != cgroup {
		t.Fatalf("dedicated cgroup path must be canonical: resolved=%q err=%v", resolved, err)
	}
	var fs unix.Statfs_t
	if err := unix.Statfs(cgroup, &fs); err != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC {
		t.Fatalf("dedicated cgroup must be on cgroup2: type=%#x err=%v", fs.Type, err)
	}
	procs, err := os.ReadFile(filepath.Join(cgroup, "cgroup.procs"))
	if err != nil || len(bytes.TrimSpace(procs)) != 0 {
		t.Fatalf("cgroup must be empty: %q err=%v", procs, err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(cgroup, &stat); err != nil || stat.Ino == 0 {
		t.Fatalf("isolated cgroup: %v", err)
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	const programName = "opaque_argv_copy_strings_postcopy"
	program := spec.Programs[programName]
	if program == nil || program.Type != ebpf.Kprobe || program.Flags != 0 {
		t.Fatal("exact non-sleepable copy_strings offset observer required")
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{programName: program}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{KernelTypes: kernel, LogSizeStart: 4 << 20}})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("offset observer verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	gate, stats, samples := collection.Maps["argv_offset_gate"], collection.Maps["argv_offset_stats"], collection.Maps["argv_offset_samples"]
	if gate == nil || stats == nil || samples == nil || gate.ValueSize() != 16 || stats.ValueSize() != 48 || samples.ValueSize() != 184 || samples.MaxEntries() != 128 {
		t.Fatal("malformed offset observer maps")
	}
	config := struct {
		Cgroup            uint64
		Profile, Reserved uint32
	}{Cgroup: stat.Ino, Profile: profile.profile}
	if err := gate.Update(uint32(0), config, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := gate.Freeze(); err != nil {
		t.Fatal(err)
	}
	attached, err := link.Kprobe("copy_strings.isra.0", collection.Programs[programName], &link.KprobeOptions{Offset: profile.offset, ExactSymbol: true})
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	var counts struct{ Seen, FullCopies, FailedCopies, ReadErrors, Incomplete, Overflow uint64 }
	if err := stats.Lookup(uint32(0), &counts); err != nil || counts.Seen != 0 {
		t.Fatalf("nonempty pretrigger stats: %+v err=%v", counts, err)
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	marker := "ig15-argv-" + hex.EncodeToString(random)
	cg, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer cg.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, marker)
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated marker exec: %v output=%q", err, output)
	}
	if err := stats.Lookup(uint32(0), &counts); err != nil {
		t.Fatal(err)
	}
	if counts.FailedCopies != 0 || counts.ReadErrors != 0 || counts.Incomplete != 0 || counts.Overflow != 0 || counts.Seen != 2 || counts.FullCopies != 2 {
		t.Fatalf("incomplete bounded observation: %+v", counts)
	}
	wanted := map[string]bool{executable + "\x00": false, marker + "\x00": false}
	var task, bprm uint64
	for slot := uint32(0); slot < uint32(counts.FullCopies); slot++ {
		var sample struct {
			Task, PIDTGID, Bprm, Pending, Destination, Requested uint64
			Captured                                             uint32
			Error                                                int32
			Bytes                                                [128]byte
		}
		if err := samples.Lookup(slot, &sample); err != nil {
			t.Fatal(err)
		}
		pid := uint64(cmd.Process.Pid)
		if sample.Task == 0 || sample.Bprm == 0 || sample.Pending == 0 || sample.Destination == 0 || sample.PIDTGID != pid<<32|pid || sample.Captured == 0 || sample.Captured > 128 || uint64(sample.Captured) != sample.Requested || sample.Error != 0 {
			t.Fatalf("invalid exact sample %d: %+v", slot, sample)
		}
		if slot == 0 {
			task, bprm = sample.Task, sample.Bprm
		} else if task != sample.Task || bprm != sample.Bprm {
			t.Fatal("samples belong to different task/bprm attempts")
		}
		value := string(sample.Bytes[:sample.Captured])
		seen, ok := wanted[value]
		if !ok || seen {
			t.Fatalf("unexpected or duplicate copied argv string: %q", value)
		}
		wanted[value] = true
	}
	for value, seen := range wanted {
		if !seen {
			t.Fatalf("missing copied argv string: %q", value)
		}
	}
	t.Logf("exact %s copy_strings.isra.0+%#x observed two complete short argv strings in one task/bprm; no full argv or enforcement claim", profile.release, profile.offset)
}
