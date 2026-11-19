// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// TestGateKernel tests mmap/BPF atomic interoperability using BPF_PROG_TEST_RUN.
// It attaches nothing and does not prove whole-exec cleanup or role inheritance.
func TestGateKernel(t *testing.T) {
	if os.Getenv("IG_EXEC_GATE_KERNEL_TEST") != "1" {
		t.Skip("set IG_EXEC_GATE_KERNEL_TEST=1 on a disposable root BPF host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required on disposable BPF host")
	}
	if runtime.GOARCH != "amd64" {
		t.Fatal("gate kernel proof is currently scoped to x86_64")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	source := os.Getenv("IG_EXEC_GATE_BPF_SOURCE")
	if source == "" {
		source = "bpf/gate_test.bpf.c"
	}
	object := filepath.Join(t.TempDir(), "gate.bpf.o")
	if out, err := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-c", source, "-o", object).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
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
		t.Fatalf("gate verifier/load: %v", err)
	}
	defer collection.Close()
	maps, err := NewGateMap(collection.Maps["gate_words"])
	if err != nil {
		t.Fatal(err)
	}
	slot, gate, err := maps.Allocate()
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if !gate.retired.Load() {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if l, e := gate.BeginUpdate(ctx); e == nil {
				_ = l.Retire()
			}
		}
		if e := maps.Close(); e != nil {
			t.Errorf("gate mapping cleanup: %v", e)
		}
	}()
	run := func(operation uint32) uint32 {
		t.Helper()
		if err := collection.Maps["commands"].Put(uint32(0), struct{ Slot, Operation uint32 }{slot, operation}); err != nil {
			t.Fatal(err)
		}
		result, _, err := collection.Programs["gate_test"].Test(make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		if result < 1 || result > 5 {
			t.Fatalf("invalid result %d", result)
		}
		return result - 1
	}
	if out, err := exec.Command("uname", "-a").Output(); err == nil {
		t.Logf("kernel: %s", out)
	}
	if got := run(0); got != 0 {
		t.Fatalf("BPF enter=%d", got)
	}
	requireState(t, gate, false, 1)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	leaseCh := make(chan *UpdateLease, 1)
	errCh := make(chan error, 1)
	go func() {
		l, e := gate.BeginUpdate(ctx)
		if e != nil {
			errCh <- e
			return
		}
		leaseCh <- l
	}()
	for {
		closed, _, err := gate.State()
		if err != nil {
			t.Fatal(err)
		}
		if closed {
			break
		}
		if err = ctx.Err(); err != nil {
			t.Fatal(err)
		}
		runtime.Gosched()
	}
	if got := run(0); got != 1 {
		t.Fatalf("BPF bypassed Go closure: %d", got)
	}
	if got := run(1); got != 0 {
		t.Fatalf("BPF release=%d", got)
	}
	var lease *UpdateLease
	select {
	case lease = <-leaseCh:
	case err := <-errCh:
		t.Fatal(err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	requireState(t, gate, true, 0)
	if got := run(0); got != 1 {
		t.Fatalf("BPF admitted under publication lease: %d", got)
	}
	if err = lease.Reopen(); err != nil {
		t.Fatal(err)
	}
	if err = gate.Enter(); err != nil {
		t.Fatal(err)
	}
	if got := run(1); got != 0 {
		t.Fatalf("BPF failed to release Go admission: %d", got)
	}
	requireState(t, gate, false, 0)
	if got := run(1); got != 4 {
		t.Fatalf("BPF underflow result=%d", got)
	}
	requireState(t, gate, false, 0)
	for range MaxAdmittedExecs {
		if err = gate.Enter(); err != nil {
			t.Fatal(err)
		}
	}
	if got := run(0); got != 2 {
		t.Fatalf("BPF capacity result=%d", got)
	}
	requireState(t, gate, false, MaxAdmittedExecs)
	if got := run(1); got != 0 {
		t.Fatalf("BPF release at capacity=%d", got)
	}
	for range MaxAdmittedExecs - 1 {
		if err = gate.Leave(); err != nil {
			t.Fatal(err)
		}
	}
	// A live admission forces timeout; the BPF release must still observe count1
	// after the Go owner reopens its own closure without resetting the word.
	if got := run(0); got != 0 {
		t.Fatal(got)
	}
	short, stop := context.WithTimeout(t.Context(), 5*time.Millisecond)
	_, err = gate.BeginUpdate(short)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout: %v", err)
	}
	requireState(t, gate, false, 1)
	if got := run(1); got != 0 {
		t.Fatal(got)
	}
	// Claimed ownership releases with one atomic subtraction. Duplicate
	// completion has no claim, so must not change count or fault state.
	if got := run(0); got != 0 {
		t.Fatal(got)
	}
	if got := run(2); got != 0 {
		t.Fatalf("owned release: %d", got)
	}
	if got := run(3); got != 0 {
		t.Fatalf("duplicate completion: %d", got)
	}
	requireState(t, gate, false, 0)
	// A sticky lineage/semantic fault must remain latched, but cannot orphan
	// a valid exact-once owner whose transaction is already completing.
	if got := run(0); got != 0 {
		t.Fatal(got)
	}
	if err := collection.Maps["release_faults"].Put(uint32(0), uint64(4)); err != nil {
		t.Fatal(err)
	}
	if got := run(2); got != 0 {
		t.Fatalf("owned release under sticky fault: %d", got)
	}
	requireState(t, gate, false, 0)
	var preserved uint64
	if err := collection.Maps["release_faults"].Lookup(uint32(0), &preserved); err != nil {
		t.Fatal(err)
	}
	if preserved != 4 {
		t.Fatalf("release repaired sticky fault: %d", preserved)
	}
	if got := run(2); got != 4 {
		t.Fatalf("owned underflow: %d", got)
	}
	var faults uint64
	if err := collection.Maps["release_faults"].Lookup(uint32(0), &faults); err != nil {
		t.Fatal(err)
	}
	if faults != 5 {
		t.Fatalf("underflow did not latch fault: %d", faults)
	}
	requireState(t, gate, false, 0)
	lease, err = gate.BeginUpdate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err = lease.Retire(); err != nil {
		t.Fatal(err)
	}
	if got := run(0); got != 1 {
		t.Fatalf("retired slot admitted: %d", got)
	}
	t.Log("BPF verifier accepted; mmap/BPF admission, close/drain/reopen, capacity, underflow, timeout preservation and retirement passed; no attachment")
	t.Run("map-shape", func(t *testing.T) {
		bad, err := ebpf.NewMap(&ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1, Flags: unix.BPF_F_MMAPABLE})
		if err != nil {
			t.Fatal(err)
		}
		defer bad.Close()
		if _, err = NewGateMap(bad); err == nil {
			t.Fatal("wrong map shape accepted")
		}
	})
}
