// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedTracer runs every ptrace request of one tracee on one locked OS
// thread (ptrace requests are per tracer thread).
type sharedTracer struct {
	do   chan func()
	done chan struct{}
}

func newSharedTracer() *sharedTracer {
	tr := &sharedTracer{do: make(chan func()), done: make(chan struct{})}
	go func() {
		runtime.LockOSThread() // never unlocked: the thread exits with the goroutine
		defer close(tr.done)
		for fn := range tr.do {
			fn()
		}
	}()
	return tr
}

func (tr *sharedTracer) run(fn func() error) error {
	errc := make(chan error, 1)
	tr.do <- func() { errc <- fn() }
	return <-errc
}

func (tr *sharedTracer) close() {
	close(tr.do)
	<-tr.done
}

// TestSharedNodeRevisionDrainAttached (G019 gap 3, VM only): tracees of
// the bound cgroup (children of its adopted init, so managed TASKs) are
// stopped by PTRACE_O_TRACEEXEC inside their exec, holding their source pin
// and reader on the generation active then:
//   - the first, holding G: the revision to G+1 commits (G turns RETIRING
//     and keeps the holders); detached, its exec completes under G and its
//     child's execs under G+1, with no fail-closed refusal (eval-work,
//     construct and qualify included);
//   - the second, holding G+1: G+2 commits, the revision to G+3 waits for
//     G+1's holders, times out (RevisionDrainTimeout, default 10 s) with a
//     retryable refusal, and the binding is Degraded with the counts
//     (Inspect and Ready), never NotReady; after PTRACE_DETACH (or, with
//     IG_SHARED_DRAIN_KILL=1, SIGKILL of the stopped tracee) the holders
//     leave and G+3 commits; the report clears.
//
// Environment: IG_SHARED_DRAIN_OBJECT (a product object, or the product
// diagnostic twin), IG_SHARED_DRAIN_CGROUP (a dedicated ig15-g019-drain-*
// cgroup), IG_SHARED_DRAIN_KILL=1.
func TestSharedNodeRevisionDrainAttached(t *testing.T) {
	object := os.Getenv("IG_SHARED_DRAIN_OBJECT")
	if object == "" {
		t.Skip("set IG_SHARED_DRAIN_OBJECT on an isolated exact-kernel VM")
	}
	cgroup := os.Getenv("IG_SHARED_DRAIN_CGROUP")
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(cgroup), "ig15-g019-drain-") {
		t.Fatal("root and a dedicated ig15-g019-drain-* cgroup required")
	}
	kill := os.Getenv("IG_SHARED_DRAIN_KILL") == "1"
	if err := checkSharedInitNamespaces(); err != nil {
		t.Fatalf("design 13.8: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	node, gc, ctx := startSharedCandidateNode(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, nil)
	defer func() { _ = node.StopNode(context.WithoutCancel(ctx)) }()
	init := startSharedPipeInit(t, cgroup, "ig15-g019-drain-init")
	session, err := node.Bind(ctx, SharedBindingConfig{CgroupID: init.ino, InitHostPID: uint32(init.cmd.Process.Pid), Acquire: init.acquire})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	policy := func(revision int) SharedBindingPolicy {
		return SharedBindingPolicy{Source: sharedM4Policy("drain", strconv.Itoa(revision), fullpolicy.Enforce, fullpolicy.Deny), Container: "drain"}
	}
	if _, err := session.Publish(ctx, policy(1)); err != nil {
		t.Fatalf("publish G (adoption): %v", err)
	}
	slot := session.Inspect().RouteSlot
	routes := func() sharedProductRoute {
		value, _ := gc.GetVar(operators.MapPrefix + "se_routes")
		m, _ := value.(*ebpf.Map)
		if m == nil {
			t.Fatal("se_routes not published")
		}
		raw, err := m.LookupBytes(slot)
		if err != nil {
			t.Fatal(err)
		}
		r, err := decodeSharedProductRoute(raw)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}

	// stopTracee starts a background child of the adopted init (a managed
	// TASK) blocked on a FIFO, seizes it with PTRACE_O_TRACEEXEC, releases
	// it and waits until it stops inside its exec of line (holding its
	// source pin and reader on the generation active then).
	stopTracee := func(name, line string) (int, *sharedTracer) {
		fifo := filepath.Join(t.TempDir(), name)
		if err := unix.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}
		out, code, err := init.run(ctx, "(read l < "+fifo+"; exec "+line+") >/dev/null 2>&1 & echo $!")
		pid, perr := strconv.Atoi(strings.TrimSpace(out))
		if err != nil || code != 0 || perr != nil {
			t.Fatalf("start tracee %s: %q %d %v %v", name, out, code, err, perr)
		}
		tracer := newSharedTracer()
		if err := tracer.run(func() error {
			_, _, errno := unix.Syscall6(unix.SYS_PTRACE, unix.PTRACE_SEIZE, uintptr(pid), 0, unix.PTRACE_O_TRACEEXEC, 0, 0)
			if errno != 0 {
				return errno
			}
			return nil
		}); err != nil {
			t.Fatalf("PTRACE_SEIZE %s %d: %v", name, pid, err)
		}
		w, err := os.OpenFile(fifo, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.WriteString("go\n")
		_ = w.Close()
		if err := tracer.run(func() error {
			var status unix.WaitStatus
			if _, err := unix.Wait4(pid, &status, unix.WALL, nil); err != nil {
				return err
			}
			if !status.Stopped() || status.TrapCause() != unix.PTRACE_EVENT_EXEC {
				return errors.New("tracee did not stop at its exec event: " + strconv.Itoa(int(status)))
			}
			return nil
		}); err != nil {
			t.Fatalf("wait for %s's exec stop: %v", name, err)
		}
		return pid, tracer
	}
	gone := func(pid int) bool {
		_, err := os.Stat("/proc/" + strconv.Itoa(pid))
		return errors.Is(err, os.ErrNotExist)
	}
	failClosedDelta := func(step string, before, after sharedM4Witness) {
		t.Helper()
		v, err := FailClosedProductRate(before.rates, after.rates, before.attempts, after.attempts, 0)
		if err != nil || v.Total != 0 || v.Entry != 0 || v.Admission != 0 {
			t.Fatalf("%s: fail-closed witness %+v (%v): want no refusal (eval-work, construct, qualify included)", step, v, err)
		}
		for _, class := range []int{3, 5, FailClosedRateQualify} { // EVAL_WORK, CONSTRUCT, QUALIFY
			if after.rates[class] != before.rates[class] {
				t.Fatalf("%s: fail-closed class %d +%d", step, class, after.rates[class]-before.rates[class])
			}
		}
	}

	// Part 1: a tracee stopped in its exec under G completes under G after
	// G+1 committed, and its child execs under G+1, with no fail-closed
	// refusal.
	marker := filepath.Join(t.TempDir(), "done")
	first, firstTracer := stopTracee("first", "/bin/sh -c '/bin/true && /bin/true && : > "+marker+"'")
	defer firstTracer.close()
	g := routes()
	active := g.State.Record & 1
	held := g.Rec[active]
	t.Logf("tracee %d stopped in exec: generation %d record %d holders early %d pins %d", first, held.Generation, active, held.EarlyClaims, held.SourcePins)
	if _, err := session.Publish(ctx, policy(2)); err != nil {
		t.Fatalf("revision G+1 while G is held: %v (a held record must not block the commit)", err)
	}
	if r := routes(); r.Rec[active].Phase != sharedSnapshotRetiring || r.Rec[active].Generation != held.Generation {
		t.Fatalf("after G+1: record %d is %+v, want RETIRING generation %d", active, r.Rec[active], held.Generation)
	}
	before := sharedM4ReadWitness(t, gc)
	if err := firstTracer.run(func() error { return unix.PtraceDetach(first) }); err != nil {
		t.Fatalf("detach tracee %d: %v", first, err)
	}
	for deadline := time.Now().Add(10 * time.Second); !gone(first); time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("tracee %d still running after its detach", first)
		}
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("tracee's exec under G and its child's execs under G+1 did not all complete: %v", err)
	}
	failClosedDelta("exec completed under G, child execs under G+1", before, sharedM4ReadWitness(t, gc))

	// Part 2: a tracee holding G+1 makes the revision to G+3 (its record
	// again) time out after G+2 committed.
	second, secondTracer := stopTracee("second", "/bin/true")
	defer secondTracer.close()
	g = routes()
	active = g.State.Record & 1
	held = g.Rec[active]
	if _, err := session.Publish(ctx, policy(3)); err != nil {
		t.Fatalf("revision G+2 while G+1 is held: %v", err)
	}
	start := time.Now()
	_, err = session.Publish(ctx, policy(4))
	if err == nil || !strings.Contains(err.Error(), "retryable") {
		t.Fatalf("revision G+3 while G+1 is held: %v, want the retryable drain refusal", err)
	}
	if waited := time.Since(start); waited < DefaultRevisionDrainTimeout {
		t.Fatalf("G+3 refused after %s, before the %s drain timeout", waited, DefaultRevisionDrainTimeout)
	}
	st := session.Inspect()
	if st.Revision == nil || st.Revision.Reason != RevisionDrainTimeout || st.Revision.Generation != held.Generation ||
		st.Revision.EarlyClaims+st.Revision.SourcePins+st.Revision.Readers == 0 {
		t.Fatalf("Inspect after the timeout: revision %+v, want RevisionDrainTimeout of generation %d with its holders", st.Revision, held.Generation)
	}
	if err := node.Ready(gc); err == nil || !strings.Contains(err.Error(), RevisionDrainTimeout) {
		t.Fatalf("Ready after the timeout: %v, want the Degraded RevisionDrainTimeout", err)
	}
	t.Logf("drain timeout: %+v", *st.Revision)

	// Release the holders: detach (the exec completes) or SIGKILL.
	if err := secondTracer.run(func() error {
		if kill {
			if err := unix.Kill(second, unix.SIGKILL); err != nil {
				return err
			}
			var status unix.WaitStatus
			_, err := unix.Wait4(second, &status, unix.WALL, nil)
			return err
		}
		return unix.PtraceDetach(second)
	}); err != nil {
		t.Fatalf("release the tracee (kill=%v): %v", kill, err)
	}
	var lastErr error
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if _, lastErr = session.Publish(ctx, policy(4)); lastErr == nil {
			break
		}
		if !strings.Contains(lastErr.Error(), "retryable") {
			break
		}
	}
	if lastErr != nil {
		t.Fatalf("revision G+3 after the holders left (kill=%v): %v", kill, lastErr)
	}
	if st := session.Inspect(); st.Revision != nil {
		t.Fatalf("Inspect after G+3 committed: revision %+v, want the report cleared", *st.Revision)
	}
	if err := node.Ready(gc); !errors.Is(err, ErrSharedNativeUnavailable) || strings.Contains(err.Error(), RevisionDrainTimeout) {
		t.Fatalf("Ready after G+3 committed: %v", err)
	}
}
