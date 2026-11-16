// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

type (
	erTestRow   struct{ UID, Epoch, Role uint64 }
	erTestState struct {
		Version uint64
		Rows    [16]erTestRow
	}
)

type erTestWork struct {
	Version, Authority uint64
	Error              int32
	Prepared           uint32
	Rows               [16]erTestRow
}
type erTestAuthority struct {
	UID, Epoch, Root uint64
	New, Reserved    uint32
}
type erTestCandidate struct {
	Count, Reserved uint32
	Active          [8]erTestAuthority
}
type erTestFrame struct {
	State           erTestState
	Work            erTestWork
	Candidate       erTestCandidate
	Source          [16]erTestRow
	Authority       uint64
	Operation       uint32
	Lineage, Result int32
	Padding         uint32
}

func erCandidate(uid, epoch, root uint64, newUID uint32) erTestCandidate {
	return erTestCandidate{Count: 1, Active: [8]erTestAuthority{{uid, epoch, root, newUID, 0}}}
}

// This fixture attaches nothing. It proves helper semantics and verifier
// acceptance only, not task-storage locks, lineage or native activation trust.
func TestEpochRolesKernel(t *testing.T) {
	if os.Getenv("IG_EXEC_EPOCH_ROLES_KERNEL_TEST") != "1" {
		t.Skip("opt in on disposable BPF guest only")
	}
	if os.Geteuid() != 0 || runtime.GOARCH != "amd64" {
		t.Fatal("disposable root x86_64 BPF guest required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	source := os.Getenv("IG_EXEC_EPOCH_ROLES_BPF_SOURCE")
	if source == "" {
		source = "bpf/epoch_roles.bpf.c"
	}
	object := filepath.Join(t.TempDir(), "epoch_roles.o")
	if out, err := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-c", source, "-o", object).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v %s", err, out)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Maps["epoch_frame"].ValueSize != uint32(binary.Size(erTestFrame{})) {
		t.Fatal("frame ABI mismatch")
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024}})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	run := func(t *testing.T, f erTestFrame, op uint32) erTestFrame {
		t.Helper()
		f.Operation = op
		f.Result = 99
		if err := collection.Maps["epoch_frame"].Put(uint32(0), f); err != nil {
			t.Fatal(err)
		}
		code, _, err := collection.Programs["epoch_roles_test"].Test(make([]byte, 64))
		if err != nil || code != 0 {
			t.Fatalf("test_run %d %v", code, err)
		}
		if err := collection.Maps["epoch_frame"].Lookup(uint32(0), &f); err != nil {
			t.Fatal(err)
		}
		return f
	}
	history := func(t *testing.T, values map[uint32]uint64) {
		t.Helper()
		for i := uint32(0); i < 64; i++ {
			if err := collection.Maps["accepted_history"].Put(i, values[i]); err != nil {
				t.Fatal(err)
			}
		}
	}
	base := func() erTestFrame {
		return erTestFrame{Authority: 100, Lineage: 1, Candidate: erCandidate(1, 9, 90, 1)}
	}
	check := func(t *testing.T, f erTestFrame, op uint32, want int32, rows [16]erTestRow) erTestFrame {
		t.Helper()
		before := f.State
		f = run(t, f, op)
		if f.Result != want {
			t.Fatalf("merge=%d want%d frame=%+v", f.Result, want, f)
		}
		if f.State != before {
			t.Fatal("merge mutated live state")
		}
		f = run(t, f, 3)
		if f.Result != want {
			t.Fatalf("publish=%d want%d", f.Result, want)
		}
		expected := before
		if want == 0 {
			expected.Version++
			expected.Rows = rows
		}
		if !reflect.DeepEqual(f.State, expected) {
			t.Fatalf("state=%+v want=%+v", f.State, expected)
		}
		return f
	}
	t.Run("failed-A-retry-B", func(t *testing.T) {
		history(t, nil)
		f := base()
		rows := [16]erTestRow{{1, 9, 90}}
		f = check(t, f, 1, 0, rows)
		f.Candidate = erCandidate(1, 10, 100, 1)
		rows[0] = erTestRow{1, 10, 100}
		check(t, f, 1, 0, rows)
	})
	t.Run("accepted-preserved-removed-readded", func(t *testing.T) {
		history(t, map[uint32]uint64{1: 2})
		f := base()
		f.State.Rows[0] = erTestRow{1, 2, 777}
		rows := f.State.Rows
		for _, candidate := range []erTestCandidate{erCandidate(1, 2, 999, 0), {}, erCandidate(1, 2, 888, 0)} {
			f.Candidate = candidate
			f = check(t, f, 1, 0, rows)
		}
		f = base()
		f.Candidate = erCandidate(1, 2, 888, 0)
		check(t, f, 1, 0, [16]erTestRow{})
	})
	t.Run("inherit-accepted-destination-wins", func(t *testing.T) {
		history(t, map[uint32]uint64{1: 2})
		f := base()
		f.Candidate = erCandidate(1, 2, 999, 0)
		f.Source[0] = erTestRow{1, 2, 444}
		f.State.Rows[0] = erTestRow{1, 2, 777}
		check(t, f, 2, 0, f.State.Rows)
		f.State = erTestState{}
		check(t, f, 2, 0, f.Source)
	})
	t.Run("inherit-staged-not-pending-or-stale", func(t *testing.T) {
		history(t, nil)
		f := base()
		f.Source[0] = erTestRow{1, 9, 90}
		check(t, f, 2, 0, f.Source)
		f.Source[0].Role = 91
		check(t, f, 2, -1, [16]erTestRow{})
		f.Source[0] = erTestRow{1, 8, 80}
		check(t, f, 2, 0, [16]erTestRow{})
	})
	t.Run("unknown-lineage", func(t *testing.T) {
		history(t, nil)
		for _, lineage := range []int32{-1, 0, 2} {
			f := base()
			f.Lineage = lineage
			check(t, f, 1, -3, [16]erTestRow{})
		}
	})
	t.Run("sixteen-retained-seventeenth-refused", func(t *testing.T) {
		h := map[uint32]uint64{}
		f := base()
		f.Candidate = erTestCandidate{}
		for i := 0; i < 16; i++ {
			h[uint32(i+1)] = 2
			f.Source[i] = erTestRow{uint64(i + 1), 2, uint64(100 + i)}
		}
		history(t, h)
		f = check(t, f, 2, 0, f.Source)
		f.Candidate = erCandidate(17, 30, 300, 1)
		check(t, f, 1, -2, f.State.Rows)
		h[17] = 2
		history(t, h)
		f.Candidate = erTestCandidate{}
		f.Source = [16]erTestRow{{17, 2, 170}}
		check(t, f, 2, -2, f.State.Rows)
	})
	t.Run("eight-active-nine-refused", func(t *testing.T) {
		history(t, nil)
		f := base()
		f.Candidate = erTestCandidate{Count: 8}
		var rows [16]erTestRow
		for i := 0; i < 8; i++ {
			f.Candidate.Active[i] = erTestAuthority{uint64(i + 1), 40, uint64(400 + i), 1, 0}
			rows[i] = erTestRow{uint64(i + 1), 40, uint64(400 + i)}
		}
		f = check(t, f, 1, 0, rows)
		f.Candidate.Count = 9
		check(t, f, 1, -1, rows)
	})
	t.Run("partial-work-capacity-rollback", func(t *testing.T) {
		h := map[uint32]uint64{}
		f := base()
		for i := 0; i < 15; i++ {
			h[uint32(i+1)] = 2
			f.State.Rows[i] = erTestRow{uint64(i + 1), 2, uint64(100 + i)}
		}
		history(t, h)
		f.Candidate = erTestCandidate{Count: 2, Active: [8]erTestAuthority{{20, 40, 400, 1, 0}, {21, 40, 401, 1, 0}}}
		f = check(t, f, 1, -2, f.State.Rows)
		if f.Work.Rows[15].UID != 20 {
			t.Fatal("did not exercise partially changed work")
		}
	})
	t.Run("stale-task-and-authority-versions", func(t *testing.T) {
		history(t, nil)
		for _, kind := range []string{"task", "authority", "overflow", "unprepared"} {
			f := base()
			f = run(t, f, 1)
			if f.Result != 0 {
				t.Fatal(f.Result)
			}
			switch kind {
			case "task":
				f.State.Version++
			case "authority":
				f.Authority++
			case "overflow":
				f.State.Version = ^uint64(0)
				f.Work.Version = f.State.Version
			case "unprepared":
				f.Work.Prepared = 0
			}
			before := f.State
			f = run(t, f, 3)
			if f.Result != -4 || f.State != before {
				t.Fatalf("%s stale publication: %+v", kind, f)
			}
		}
	})
	for _, kind := range []string{"empty-row", "duplicate-row", "accepted-epoch", "accepted-new", "missing-accepted", "unknown-history", "reserved-epoch", "duplicate-authority", "zero-role", "source-epoch"} {
		t.Run(kind, func(t *testing.T) {
			history(t, nil)
			f := base()
			op := uint32(1)
			switch kind {
			case "empty-row":
				f.State.Rows[0] = erTestRow{0, 1, 1}
			case "duplicate-row":
				f.State.Rows[0] = erTestRow{1, 9, 90}
				f.State.Rows[1] = f.State.Rows[0]
			case "accepted-epoch":
				history(t, map[uint32]uint64{1: 2})
				f.Candidate.Active[0].New = 0
			case "accepted-new":
				history(t, map[uint32]uint64{1: 9})
			case "missing-accepted":
				f.Candidate.Active[0].New = 0
			case "unknown-history":
				f.Candidate.Active[0].UID = 64
			case "reserved-epoch":
				f.Candidate.Active[0].Epoch = ^uint64(0)
			case "duplicate-authority":
				f.Candidate.Count = 2
				f.Candidate.Active[1] = f.Candidate.Active[0]
			case "zero-role":
				f.State.Rows[0] = erTestRow{1, 9, 0}
			case "source-epoch":
				history(t, map[uint32]uint64{1: 2})
				f.Candidate = erCandidate(1, 2, 20, 0)
				f.Source[0] = erTestRow{1, 9, 90}
				op = 2
			}
			check(t, f, op, -1, f.State.Rows)
		})
	}
}
