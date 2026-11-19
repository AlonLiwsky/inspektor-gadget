// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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

// This proves only whether a real exec reaches an attachable post-copy hook
// exposing our marker. Cgroup/PID gating does not establish argv attribution.
func TestOpaqueArgvCopyPrimitiveAttached(t *testing.T) {
	object, cgroup, executable := os.Getenv("IG_OPAQUE_ARGV_COPY_OBJECT"), os.Getenv("IG_OPAQUE_ARGV_COPY_CGROUP"), os.Getenv("IG_OPAQUE_ARGV_COPY_EXECUTABLE")
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
	const name = "opaque_argv_copy_primitive"
	program := spec.Programs[name]
	if program == nil || program.Type != ebpf.Tracing || program.AttachType != ebpf.AttachTraceFExit || program.AttachTo != "_copy_from_user" || program.Flags != 0 {
		t.Fatal("exact non-sleepable _copy_from_user fexit required")
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{name: program}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{KernelTypes: kernel, LogSizeStart: 4 << 20}})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("copy primitive verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	gate, stats, samples := collection.Maps["argv_copy_gate"], collection.Maps["argv_copy_stats"], collection.Maps["argv_copy_samples"]
	if gate == nil || stats == nil || samples == nil || gate.ValueSize() != 8 || stats.ValueSize() != 32 || samples.ValueSize() != 152 || samples.MaxEntries() != 128 {
		t.Fatal("malformed primitive maps")
	}
	if err := gate.Update(uint32(0), stat.Ino, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := gate.Freeze(); err != nil {
		t.Fatal(err)
	}
	attached, err := link.AttachTracing(link.TracingOptions{Program: collection.Programs[name]})
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	var counts struct{ Calls, FullCopies, Overflow, ReadErrors uint64 }
	if err := stats.Lookup(uint32(0), &counts); err != nil || counts.Calls != 0 {
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
	if counts.Overflow != 0 || counts.ReadErrors != 0 {
		t.Fatalf("incomplete bounded observation: %+v", counts)
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

func opaqueArgvCopyPrototype(function *btf.Func) error {
	proto, ok := btf.UnderlyingType(function.Type).(*btf.FuncProto)
	if !ok || len(proto.Params) != 3 {
		return fmt.Errorf("_copy_from_user requires three arguments")
	}
	unsigned64 := func(typ btf.Type) bool {
		i, ok := btf.UnderlyingType(typ).(*btf.Int)
		return ok && i.Size == 8 && i.Encoding == btf.Unsigned
	}
	if !unsigned64(proto.Return) || !unsigned64(proto.Params[2].Type) {
		return fmt.Errorf("_copy_from_user requires unsigned long return/size")
	}
	for _, p := range proto.Params[:2] {
		if _, ok := btf.UnderlyingType(p.Type).(*btf.Pointer); !ok {
			return fmt.Errorf("_copy_from_user requires pointer destination/source")
		}
	}
	return nil
}

func TestOpaqueArgvCopyPrototype(t *testing.T) {
	u64 := &btf.Int{Size: 8, Encoding: btf.Unsigned}
	ptr := &btf.Pointer{Target: &btf.Void{}}
	for _, tc := range []struct {
		name   string
		ret    btf.Type
		params []btf.FuncParam
		valid  bool
	}{
		{"valid", u64, []btf.FuncParam{{Type: ptr}, {Type: ptr}, {Type: u64}}, true},
		{"signed return", &btf.Int{Size: 8, Encoding: btf.Signed}, []btf.FuncParam{{Type: ptr}, {Type: ptr}, {Type: u64}}, false},
		{"short size", u64, []btf.FuncParam{{Type: ptr}, {Type: ptr}, {Type: &btf.Int{Size: 4}}}, false},
		{"scalar destination", u64, []btf.FuncParam{{Type: u64}, {Type: ptr}, {Type: u64}}, false},
		{"missing argument", u64, []btf.FuncParam{{Type: ptr}, {Type: ptr}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := opaqueArgvCopyPrototype(&btf.Func{Type: &btf.FuncProto{Return: tc.ret, Params: tc.params}})
			if (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}
