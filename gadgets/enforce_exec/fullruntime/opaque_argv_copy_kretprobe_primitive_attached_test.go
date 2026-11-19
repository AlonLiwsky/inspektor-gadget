// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
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

// This proves only whether a real exec reaches an attachable post-copy hook
// exposing our marker. Cgroup/PID gating does not establish argv attribution.
func TestOpaqueArgvCopyKretprobePrimitiveAttached(t *testing.T) {
	object, cgroup, executable := os.Getenv("IG_OPAQUE_ARGV_KRET_OBJECT"), os.Getenv("IG_OPAQUE_ARGV_KRET_CGROUP"), os.Getenv("IG_OPAQUE_ARGV_KRET_EXECUTABLE")
	if object == "" && cgroup == "" && executable == "" {
		t.Skip("set explicit copy object, isolated cgroup and executable")
	}
	if os.Geteuid() != 0 || !filepath.IsAbs(object) || !filepath.IsAbs(cgroup) || !filepath.IsAbs(executable) || !strings.HasPrefix(filepath.Base(cgroup), "ig15-g020-argv-") {
		t.Fatal("root, absolute paths and dedicated ig15-g020-argv-* cgroup required")
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
	var target *btf.Func
	if err := kernel.TypeByName("_copy_from_user", &target); err != nil {
		t.Fatal(err)
	}
	if err := opaqueArgvCopyPrototype(target); err != nil {
		t.Fatal(err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	selected := map[string]*ebpf.ProgramSpec{}
	for _, name := range []string{"opaque_argv_copy_enter", "opaque_argv_copy_return"} {
		program := spec.Programs[name]
		if program == nil || program.Type != ebpf.Kprobe || program.Flags != 0 {
			t.Fatal("exact non-sleepable _copy_from_user kprobe pair required")
		}
		selected[name] = program
	}
	spec.Programs = selected
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{KernelTypes: kernel, LogSizeStart: 4 << 20}})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("copy primitive verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	gate, stats, samples := collection.Maps["argv_kret_gate"], collection.Maps["argv_kret_stats"], collection.Maps["argv_kret_samples"]
	if gate == nil || stats == nil || samples == nil || gate.ValueSize() != 8 || stats.ValueSize() != 56 || samples.ValueSize() != 152 || samples.MaxEntries() != 128 {
		t.Fatal("malformed primitive maps")
	}
	if err := gate.Update(uint32(0), stat.Ino, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := gate.Freeze(); err != nil {
		t.Fatal(err)
	}
	returned, err := link.Kretprobe("_copy_from_user", collection.Programs["opaque_argv_copy_return"], &link.KprobeOptions{ExactSymbol: true})
	if err != nil {
		t.Fatal(err)
	}
	defer returned.Close()
	entered, err := link.Kprobe("_copy_from_user", collection.Programs["opaque_argv_copy_enter"], &link.KprobeOptions{ExactSymbol: true})
	if err != nil {
		t.Fatal(err)
	}
	defer entered.Close()
	var counts struct{ Entries, Returns, FullCopies, Overflow, ReadErrors, Incomplete, Missing uint64 }
	if err := stats.Lookup(uint32(0), &counts); err != nil || counts.Entries != 0 {
		t.Fatalf("nonempty pretrigger stats: %+v err=%v", counts, err)
	}
	random := make([]byte, 16)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	marker := []byte("ig15-argv-" + hex.EncodeToString(random))
	cg, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer cg.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, string(marker))
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("isolated marker exec: %v output=%q", err, output)
	}
	if err := stats.Lookup(uint32(0), &counts); err != nil {
		t.Fatal(err)
	}
	if counts.Overflow != 0 || counts.ReadErrors != 0 || counts.Incomplete != 0 || counts.Missing != 0 || counts.Entries != counts.Returns {
		t.Fatalf("incomplete bounded observation: %+v", counts)
	}
	frames := collection.Maps["argv_kret_frames"]
	if frames == nil {
		t.Fatal("missing entry frames")
	}
	iterator := frames.Iterate()
	var frameKey uint64
	var frame [40]byte
	if iterator.Next(&frameKey, &frame) || iterator.Err() != nil {
		t.Fatalf("entry frame retained: key=%d err=%v", frameKey, iterator.Err())
	}
	matched := 0
	for slot := uint32(0); slot < uint32(min(counts.FullCopies, uint64(128))); slot++ {
		var sample struct {
			PIDTGID, Requested uint64
			Captured           uint32
			Error              int32
			Bytes              [128]byte
		}
		if err := samples.Lookup(slot, &sample); err != nil {
			t.Fatal(err)
		}
		if sample.Captured > 128 || uint64(sample.Captured) > sample.Requested || sample.Error != 0 {
			t.Fatalf("invalid sample %d: %+v", slot, sample)
		}
		if sample.PIDTGID>>32 == uint64(cmd.Process.Pid) && bytes.Contains(sample.Bytes[:sample.Captured], marker) {
			matched++
		}
	}
	if matched == 0 {
		t.Fatalf("no copied kernel destination exposed exec marker: stats=%+v; not proof all alternatives impossible", counts)
	}
	t.Logf("post-copy marker observed in %d samples, stats=%+v; no complete argv attribution or enforcement claim", matched, counts)
}
