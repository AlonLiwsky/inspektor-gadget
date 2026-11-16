// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// G019 M4 design 9: the adoption-failure, authentication, recycle and
// publication-fault cases on the real product publisher (G1), each on its
// own node and fresh cgroups (a refused cgroup is terminal for its node).
// Every assertion is backed by kernel state (route anchor, adopt state,
// receipt, objects) or counters, never by an Audit verdict alone.
//
// Environment (isolated exact-kernel VM, root, initial pid/time namespaces):
//   IG_SHARED_M4_OBJECT          a NON-recovery product-publisher twin with
//                                the publication fault injector (the product
//                                admin control needs se_admin; a recovery
//                                twin is refused)
//   IG_SHARED_M4_CGROUP_ROOT     an existing dedicated parent cgroup whose
//                                basename starts with ig15-g019-m4-; the test
//                                creates and removes its children
//   IG_SHARED_M4_HANDLER_SYMBOL  as for M4 (falls back to the M3 variable)

// sharedM4Env is one subtest's node over the product publisher.
type sharedM4Env struct {
	t    *testing.T
	node *NodeEnforcer
	gc   *gadgetcontext.GadgetContext
	ctx  context.Context
	pub  *productRoutePublisher
	cmd  *productCommander
	root string
}

func sharedM4Start(t *testing.T) *sharedM4Env {
	t.Helper()
	return sharedM4StartWith(t, nil)
}

// sharedM4StartWith is sharedM4Start with a node configuration hook (nil:
// the defaults).
func sharedM4StartWith(t *testing.T, configure func(*SharedNodeConfig)) *sharedM4Env {
	t.Helper()
	object, root := os.Getenv("IG_SHARED_M4_OBJECT"), os.Getenv("IG_SHARED_M4_CGROUP_ROOT")
	if object == "" || root == "" {
		t.Skip("set IG_SHARED_M4_OBJECT and IG_SHARED_M4_CGROUP_ROOT on an isolated exact-kernel VM")
	}
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(root), "ig15-g019-m4-") {
		t.Fatal("root and a dedicated ig15-g019-m4-* parent cgroup required")
	}
	if err := checkSharedInitNamespaces(); err != nil {
		t.Fatalf("design 13.8: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	node, gc, ctx := startSharedCandidateNode(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, configure)
	t.Cleanup(func() {
		if err := node.StopNode(context.WithoutCancel(ctx)); err != nil {
			t.Errorf("StopNode: %v", err)
		}
	})
	publisher, err := node.livePublisher(false)
	live, ok := publisher.(*sharedLiveProductPublisher)
	if err != nil || !ok {
		t.Fatalf("node publisher %T (%v), want the product publisher (G1)", publisher, err)
	}
	cmd, ok := live.cmd.(*productCommander)
	if !ok {
		t.Fatalf("product commander %T", live.cmd)
	}
	sharedM4RequireArmed(t, gc, cmd.control)
	return &sharedM4Env{t: t, node: node, gc: gc, ctx: ctx, pub: live.productRoutePublisher, cmd: cmd, root: root}
}

// cgroup creates a fresh child cgroup, killed and removed at cleanup.
// TestSharedNodeM4MigratedAfterReleaseAttached (G020 carryover B, the
// migrate-in residual): a refused Strict adoption (AdoptionCloneRefused, as
// TestSharedNodeM4AdoptionCloneRefused) is latched until its cgroup is
// empty; the cgroup is emptied, and a task is migrated in (a privileged
// cgroup.procs write) right after the poller's empty poll, as soon as the
// route is seen withdrawn. The WITHDRAWN route allows it unevaluated (the
// residual); the release's bounded re-read (3 reads over 250 ms, then once
// before the recycle) must report it: MigratedAfterRelease, counted once,
// Degraded in Ready, and still reported after the slot is recycled.
func TestSharedNodeM4MigratedAfterReleaseAttached(t *testing.T) {
	e := sharedM4Start(t)
	path := e.cgroup("migrated")
	init := startSharedThreadsInit(t, path, "ig15-g019-m4-migrated-init", 1)
	s := e.bind(init.sharedPipeInit)
	slot := s.Inspect().RouteSlot
	e.hookFinish(func() {
		if _, err := init.in.Write([]byte{'f'}); err != nil {
			t.Errorf("fork attempt of the adopted init: %v", err)
			return
		}
		if line, err := init.out.ReadString('\n'); err != nil || strings.TrimSpace(line) != fmt.Sprintf("fork %d", int(unix.EPERM)) {
			t.Errorf("fork attempt of the adopted init: %q %v, want EPERM", line, err)
		}
	})
	_, err := s.Publish(e.ctx, sharedM4Strict("migrated"))
	e.requireRefused(err, AdoptionCloneRefused)
	latched := e.anchor(slot)
	if latched.State.Phase == 0 || latched.Adopting != 1 || latched.State.Class != 2 {
		t.Fatalf("anchor %+v: want the Strict route latched", latched)
	}
	if e.counts()[MigratedAfterRelease] != 0 {
		t.Fatalf("counters %v before the release", e.counts())
	}
	// The migrant waits outside the cgroup; it is moved in the moment the
	// route leaves its latched state (the withdrawal), i.e. after the
	// poller's empty poll.
	migrant := exec.Command("/bin/sleep", "60")
	if err := migrant.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = migrant.Process.Kill(); _ = migrant.Wait() })
	init.stop()
	sharedM4KillCgroup(path)
	e.waitEmpty(path)
	var withdrawnAt time.Time
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		if a := e.anchor(slot); a.Adopting != 1 || a.State.Phase != latched.State.Phase {
			if err := os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(strconv.Itoa(migrant.Process.Pid)), 0); err != nil {
				t.Fatalf("migrate %d in: %v", migrant.Process.Pid, err)
			}
			withdrawnAt = time.Now()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("route never withdrawn after the cgroup emptied: anchor %+v", e.anchor(slot))
		}
	}
	if pids := sharedM4Procs(t, path); !slices.Contains(pids, migrant.Process.Pid) {
		t.Fatalf("migrant %d not in the cgroup: %v", migrant.Process.Pid, pids)
	}
	// Reported within the window (250 ms) plus the pre-recycle check.
	var report SharedAdoptionStatus
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		slots, counts, err := e.node.AdoptionReport()
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, st := range slots {
			if st.Reason == MigratedAfterRelease {
				report, found = st, true
			}
		}
		if found && counts[MigratedAfterRelease] == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no MigratedAfterRelease report %s after the migration: %+v %v", time.Since(withdrawnAt), slots, counts)
		}
	}
	if report.Slot != slot || report.Cgroup != init.ino || report.Audit || report.Stuck {
		t.Fatalf("report %+v: want slot %d cgroup %d Strict", report, slot, init.ino)
	}
	ready := e.node.Ready(e.gc)
	if !errors.Is(ready, ErrSharedNativeUnavailable) || !strings.Contains(fmt.Sprint(ready), MigratedAfterRelease) {
		t.Fatalf("Ready: %v, want Degraded MigratedAfterRelease (and ErrSharedNativeUnavailable kept)", ready)
	}
	// The migrant is not ours (no TASK): the recycle completes, the report
	// stays (sticky until node teardown), counted once.
	e.waitReleased(slot, init.ino)
	if err := s.Remove(e.ctx, 1); err != nil {
		t.Fatalf("Remove after the release: %v", err)
	}
	e.requireRetired(s, slot)
	if e.counts()[MigratedAfterRelease] != 1 || !strings.Contains(fmt.Sprint(e.node.Ready(e.gc)), MigratedAfterRelease) {
		t.Fatalf("after the recycle: counters %v Ready %v, want the sticky report", e.counts(), e.node.Ready(e.gc))
	}
	t.Logf("MIGRATED slot %d cgroup %d migrant %d reported %+v", slot, init.ino, migrant.Process.Pid, report)
}

func (e *sharedM4Env) cgroup(name string) string {
	e.t.Helper()
	path := filepath.Join(e.root, "ig15-g019-m4-"+name)
	if err := os.Mkdir(path, 0o755); err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() {
		sharedM4KillCgroup(path)
		for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if os.Remove(path) == nil {
				return
			}
		}
		e.t.Errorf("cgroup %s not removable", path)
	})
	return path
}

func sharedM4KillCgroup(path string) {
	_ = os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0)
}

func sharedM4Procs(t *testing.T, path string) []int {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(path, "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, f := range strings.Fields(string(raw)) {
		pid, err := strconv.Atoi(f)
		if err != nil {
			t.Fatal(err)
		}
		pids = append(pids, pid)
	}
	return pids
}

func (e *sharedM4Env) waitEmpty(path string) {
	e.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); len(sharedM4Procs(e.t, path)) != 0; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			e.t.Fatalf("cgroup %s not empty: %v", path, sharedM4Procs(e.t, path))
		}
	}
}

func (e *sharedM4Env) bind(init *sharedPipeInit) *BindingSession {
	e.t.Helper()
	s, err := e.node.Bind(e.ctx, SharedBindingConfig{CgroupID: init.ino, InitHostPID: uint32(init.cmd.Process.Pid), Acquire: init.acquire})
	if err != nil {
		e.t.Fatalf("Bind %s: %v", init.path, err)
	}
	return s
}

func (e *sharedM4Env) mapOf(name string) *ebpf.Map {
	e.t.Helper()
	value, _ := e.gc.GetVar(operators.MapPrefix + name)
	m, _ := value.(*ebpf.Map)
	if m == nil {
		e.t.Fatalf("map %s not published", name)
	}
	return m
}

func (e *sharedM4Env) adoptState(slot uint32) sharedProductAdoptState {
	e.t.Helper()
	raw, err := e.mapOf("opaque_real_adopt_state").LookupBytes(slot)
	if err != nil {
		e.t.Fatal(err)
	}
	st, err := decodeSharedProductAdoptState(raw)
	if err != nil {
		e.t.Fatal(err)
	}
	return st
}

func (e *sharedM4Env) anchor(slot uint32) sharedProductRoute {
	e.t.Helper()
	r, err := e.cmd.productRoute(slot)
	if err != nil {
		e.t.Fatal(err)
	}
	return r
}

// liveObjects counts the policy objects that are not FREE.
func (e *sharedM4Env) liveObjects() int {
	e.t.Helper()
	m, live := e.mapOf("se_objects"), 0
	for i := uint32(0); i < m.MaxEntries(); i++ {
		raw, err := m.LookupBytes(i)
		if err != nil {
			e.t.Fatal(err)
		}
		st, err := decodeSharedObject(raw)
		if err != nil {
			e.t.Fatal(err)
		}
		if st.Phase != sharedObjectFree {
			live++
		}
	}
	return live
}

func (e *sharedM4Env) waitReleased(slot uint32, cgroup uint64) {
	e.t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		_, reported := e.pub.adoptionStatus(slot)
		if !reported && e.anchor(slot).State.Phase == 0 {
			return
		}
		if time.Now().After(deadline) {
			st, _ := e.pub.adoptionStatus(slot)
			e.t.Fatalf("slot %d (cgroup %d) not released: status %+v anchor %+v", slot, cgroup, st, e.anchor(slot))
		}
	}
}

func (e *sharedM4Env) counts() map[string]uint64 {
	e.t.Helper()
	_, counts, err := e.node.AdoptionReport()
	if err != nil {
		e.t.Fatal(err)
	}
	return counts
}

// requireLatchedRefuses: while a refused Strict adoption keeps its route
// latched (ACTIVE, adopting), a task joining the cgroup from the host can
// neither fork (bash 254, EPERM) nor exec (126, EPERM); each is an
// admission fault, counted as one attempt and one ADMISSION (design 13.20).
func (e *sharedM4Env) requireLatchedRefuses(path string, slot uint32, step string) {
	e.t.Helper()
	// Only a latched route is probed: ACTIVE, adopting, Strict. A released
	// (FREE) or withdrawn route is not latched and would not refuse as one.
	if a := e.anchor(slot); a.State.Phase != 2 || a.Adopting != 1 || a.State.Class != 2 {
		e.t.Fatalf("%s: route %+v is not latched (ACTIVE, adopting, Strict)", step, a)
	}
	rates := sharedFailClosedCells(e.t, e.gc)
	attempts := sharedM4ReadWitness(e.t, e.gc).attempts
	for _, probe := range []struct {
		name, script, stderr string
		status               int
	}{
		// bash forks for a command that is not the last of -c: the fork
		// itself is refused (EPERM, bash 254).
		{"fork", `echo $$ > "$1/cgroup.procs" || exit 99; /bin/true; exit $?`, "fork", 254},
		// bash execs the last simple command of -c in place: the exec of the
		// untracked task is refused (EPERM, 126).
		{"exec in place", `echo $$ > "$1/cgroup.procs" || exit 99; /bin/true`, "Operation not permitted", 126},
	} {
		cmd := exec.Command("/bin/bash", "-c", probe.script, "ig15-g019-m4-latched", path)
		out, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if err == nil || !errors.As(err, &exit) || exit.ExitCode() != probe.status || !strings.Contains(string(out), probe.stderr) {
			e.t.Fatalf("%s: %s in the latched Strict cgroup not refused as %d: %q %v", step, probe.name, probe.status, out, err)
		}
	}
	// The latched route faults both and counts each (design 13.20,
	// superseding the uncounted rule of design 6): the fork at the birth
	// claim (one birth attempt, one ADMISSION) and the exec at the exec
	// reader's admission (one exec attempt, one ADMISSION); never Total or
	// ENTRY.
	after := sharedFailClosedCells(e.t, e.gc)
	for i := range after {
		want := rates[i]
		if i == FailClosedRateAdmission {
			want += 2
		}
		if after[i] != want {
			e.t.Fatalf("%s: latched refusals moved the fail-closed witness %v -> %v, want exactly two ADMISSION (fork, exec)", step, rates, after)
		}
	}
	if got := sharedM4ReadWitness(e.t, e.gc).attempts; got != [FailClosedRateAttempts]uint64{attempts[0] + 1, attempts[1] + 1} {
		e.t.Fatalf("%s: latched refusals counted attempts %v -> %v, want one birth and one exec attempt", step, attempts, got)
	}
}

// requireRetired: after the poller released a refused adoption and its
// session is gone, the slot is free and the account retired.
func (e *sharedM4Env) requireRetired(s *BindingSession, slot uint32) {
	e.t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		e.node.mu.Lock()
		free := e.node.host.scopeSlots[slot] == nil
		e.node.mu.Unlock()
		s.account.mu.Lock()
		retired := s.account.retired
		s.account.mu.Unlock()
		if free && retired {
			return
		}
		if time.Now().After(deadline) {
			e.t.Fatalf("slot %d free %v, account retired %v", slot, free, retired)
		}
	}
}

// sharedThreadsInit is the static adopt_threads helper started as a
// container-like init (cloned into the cgroup, own mount namespace).
type sharedThreadsInit struct {
	*sharedPipeInit
}

func startSharedThreadsInit(t *testing.T, cgroup, name string, threads int) *sharedThreadsInit {
	t.Helper()
	helper := os.Getenv("IG_SHARED_M4_THREADS_HELPER")
	if helper == "" {
		t.Fatal("IG_SHARED_M4_THREADS_HELPER (the static testdata/adopt_threads.c build) is required")
	}
	dir, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	cmd := exec.Command(helper, strconv.Itoa(threads))
	cmd.Args[0] = name
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS, UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s in %s: %v", helper, cgroup, err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	reader := bufio.NewReader(out)
	line, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(line) != fmt.Sprintf("ready %d", threads) {
		t.Fatalf("%s: %q %v", helper, line, err)
	}
	var st unix.Stat_t
	if err := unix.Stat(cgroup, &st); err != nil {
		t.Fatal(err)
	}
	return &sharedThreadsInit{&sharedPipeInit{cmd: cmd, in: in, out: reader, path: cgroup, ino: st.Ino}}
}

// sharedM4TaskCount counts the threads of pid.
func sharedM4TaskCount(t *testing.T, pid int) int {
	t.Helper()
	entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/task", pid))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// sharedM4Hook wraps the product commander: before finish it runs the
// scenario's hook (the adopted set is complete, adopting is set).
type sharedM4Hook struct {
	sharedProductCommander
	beforeFinish func()
}

func (h *sharedM4Hook) finish(ctx context.Context, slot uint32, cgroup uint64) (uint32, sharedFinishDetail, error) {
	if h.beforeFinish != nil {
		h.beforeFinish()
	}
	return h.sharedProductCommander.finish(ctx, slot, cgroup)
}

func (e *sharedM4Env) hookFinish(fn func()) {
	e.pub.cmd = &sharedM4Hook{sharedProductCommander: e.cmd, beforeFinish: fn}
}

func sharedM4Strict(id string) SharedBindingPolicy {
	return SharedBindingPolicy{Source: sharedM4Policy(id, "1", fullpolicy.Enforce, fullpolicy.Deny), Container: id}
}

func (e *sharedM4Env) requireRefused(err error, reason string) *ErrSharedAdoptionRefused {
	e.t.Helper()
	var refused *ErrSharedAdoptionRefused
	if !errors.As(err, &refused) || refused.Reason != reason || refused.Audit {
		e.t.Fatalf("publish: %v, want a Strict %s refusal", err, reason)
	}
	return refused
}

// TestSharedNodeM4AdoptionThreadExitedAndStuck (design 9, 13.9 a and the
// stuck slot): an adopted task exits between its adoption and finish (a
// task the test kills after the adopted set is complete). finish refuses
// (iterated < adopted): AdoptionThreadExited, counted. The quarantine is
// complete (the exited task is gone, not missed). The Strict route stays
// latched (ACTIVE, adopting) while the cgroup has tasks, AdoptionStuck is
// reported (Degraded, counted once) after 30 s, and once the cgroup is
// empty the poller withdraws and recycles it (anchor FREE).
func TestSharedNodeM4AdoptionThreadExitedAndStuck(t *testing.T) {
	e := sharedM4Start(t)
	path := e.cgroup("exited")
	// A multi-threaded init (the static adopt_threads helper): every task of
	// the cgroup is one of its threads (pass 1 admits only the init's
	// threads), created before the binding, and a thread exits on a byte
	// with no clone, so it leaves between its adoption and finish.
	const threads = 4
	init := startSharedThreadsInit(t, path, "ig15-g019-m4-exited-init", threads)
	tasks := threads + 1
	if got := sharedM4TaskCount(t, init.cmd.Process.Pid); got != tasks {
		t.Fatalf("init has %d tasks, want %d", got, tasks)
	}
	s := e.bind(init.sharedPipeInit)
	slot := s.Inspect().RouteSlot
	before := e.adoptState(slot)
	e.hookFinish(func() {
		if _, err := init.in.Write([]byte{'x'}); err != nil {
			t.Errorf("ask a thread to exit: %v", err)
		}
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(2 * time.Millisecond) {
			if sharedM4TaskCount(t, init.cmd.Process.Pid) == tasks-1 {
				return
			}
		}
		t.Errorf("no adopted thread exited")
	})
	_, err := s.Publish(e.ctx, sharedM4Strict("exited"))
	e.requireRefused(err, AdoptionThreadExited)
	st := e.adoptState(slot)
	if st.Finishes != before.Finishes+1 || st.Adopted != uint32(tasks) || st.Iterated != uint32(tasks-1) || st.Faults != 0 {
		t.Fatalf("finish counts %+v: want adopted %d, iterated %d, one finish run, no faults", st, tasks, tasks-1)
	}
	if st.Missed != 0 || st.Gone < 1 || st.Quarantined+st.Gone != uint32(tasks) {
		t.Fatalf("quarantine %+v: every entry marked or gone, none missed", st)
	}
	status, reported := e.pub.adoptionStatus(slot)
	if !reported || status.Reason != AdoptionThreadExited || !status.Quarantined || status.Failed {
		t.Fatalf("status %+v %v", status, reported)
	}
	if e.counts()[AdoptionThreadExited] != 1 {
		t.Fatalf("counters %v", e.counts())
	}
	// Latched: ACTIVE with adopting set, never withdrawn while tasks remain.
	if a := e.anchor(slot); a.State.Phase == 0 || a.Adopting != 1 || a.State.Class != 2 {
		t.Fatalf("anchor %+v: want the Strict route latched (ACTIVE, adopting)", a)
	}
	e.requireLatchedRefuses(path, slot, "latched after AdoptionThreadExited")
	if err := s.Remove(e.ctx, s.Inspect().Generation); err != nil || !s.Inspect().WithdrawPending {
		t.Fatalf("Remove of a latched slot: %v %+v", err, s.Inspect())
	}
	// Stuck: 30 s after the refusal, still latched and reported.
	time.Sleep(sharedProductStuckAfter + 2*time.Second)
	status, _ = e.pub.adoptionStatus(slot)
	if !status.Stuck || e.counts()[AdoptionStuck] != 1 {
		t.Fatalf("after %s: status %+v counters %v, want AdoptionStuck", sharedProductStuckAfter, status, e.counts())
	}
	if err := e.node.Ready(e.gc); err == nil || !strings.Contains(err.Error(), AdoptionStuck) {
		t.Fatalf("Ready: %v, want Degraded AdoptionStuck", err)
	}
	if a := e.anchor(slot); a.State.Phase == 0 || a.Adopting != 1 {
		t.Fatalf("stuck anchor %+v: still latched", a)
	}
	// Empty: the poller releases it.
	sharedM4KillCgroup(path)
	e.waitEmpty(path)
	e.waitReleased(slot, init.ino)
	if e.counts()[AdoptionStuck] != 1 {
		t.Fatalf("AdoptionStuck counted %d times, want once", e.counts()[AdoptionStuck])
	}
	e.requireRetired(s, slot) // removed while latched: freed by the release
}

// TestSharedNodeM4AdoptionCloneRefused (design 13.9 b, deterministic): the
// adopted init forks while adopting is set (after its adoption, before
// finish). Strict refuses the clone (EPERM) and counts it in the anchor's
// adopting_faults; finish refuses: AdoptionCloneRefused, counted.
func TestSharedNodeM4AdoptionCloneRefused(t *testing.T) {
	e := sharedM4Start(t)
	path := e.cgroup("clone")
	// The static adopt_threads helper, not a shell: its one fork attempt
	// ('f') reports the errno and the init stays alive whatever the outcome
	// (bash's init exits 254 on a refused fork, emptying the cgroup and
	// releasing the route before the latched probes), so the cgroup stays
	// non-empty and the refused Strict route stays latched for the probes.
	init := startSharedThreadsInit(t, path, "ig15-g019-m4-clone-init", 1)
	s := e.bind(init.sharedPipeInit)
	slot := s.Inspect().RouteSlot
	forkResult := ""
	e.hookFinish(func() {
		// One fork of the adopted init: Strict refuses it (EPERM).
		type result struct {
			line string
			err  error
		}
		done := make(chan result, 1)
		go func() {
			if _, err := init.in.Write([]byte{'f'}); err != nil {
				done <- result{err: err}
				return
			}
			line, err := init.out.ReadString('\n')
			done <- result{strings.TrimSpace(line), err}
		}()
		select {
		case r := <-done:
			forkResult = r.line
			if r.err != nil {
				t.Errorf("fork attempt of the adopted init: %q %v", r.line, r.err)
			}
		case <-time.After(5 * time.Second):
			// Never leave a reader behind: end it at EOF.
			_ = init.cmd.Process.Kill()
			t.Errorf("fork attempt of the adopted init: no report")
		}
	})
	_, err := s.Publish(e.ctx, sharedM4Strict("clone"))
	e.requireRefused(err, AdoptionCloneRefused)
	if want := fmt.Sprintf("fork %d", int(unix.EPERM)); forkResult != want {
		t.Fatalf("the adopted init's fork while adopting reported %q, want %q (Strict refuses it with EPERM)", forkResult, want)
	}
	// The refused fork is counted in the route's adopting_faults (and
	// finish snapshots it into state.faults); the init is alive, so the
	// cgroup keeps its tasks and the route stays latched.
	st, anchor := e.adoptState(slot), e.anchor(slot)
	if max(st.Faults, anchor.AdoptingFault) == 0 || st.Missed != 0 {
		t.Fatalf("adopt state %+v anchor %+v: want adopting faults counted, quarantine complete", st, anchor)
	}
	if e.counts()[AdoptionCloneRefused] != 1 {
		t.Fatalf("counters %v", e.counts())
	}
	e.requireLatchedRefuses(path, slot, "latched after AdoptionCloneRefused")
	init.stop()
	sharedM4KillCgroup(path)
	e.waitEmpty(path)
	e.waitReleased(slot, init.ino)
	// Still bound at the release: its Remove frees the slot, no withdrawal.
	if err := s.Remove(e.ctx, 1); err != nil {
		t.Fatalf("Remove after the release: %v", err)
	}
	e.requireRetired(s, slot)
}

// TestSharedM4GoInitHelper is the multi-threaded Go init of the clone-storm
// case (runc-like: a locked main thread, goroutines forcing new OS threads
// in a loop). It runs only when re-executed with IG_SHARED_M4_HELPER=storm.
func TestSharedM4GoInitHelper(t *testing.T) {
	if os.Getenv("IG_SHARED_M4_HELPER") != "storm" {
		t.Skip("helper process only")
	}
	runtime.LockOSThread()
	for {
		done := make(chan struct{})
		go func() {
			runtime.LockOSThread() // never unlocked: the thread exits with the goroutine
			close(done)
		}()
		<-done
		time.Sleep(time.Millisecond)
	}
}

// TestSharedNodeM4AdoptionGoInitStorm (design 9 #12): a real multi-threaded
// Go init keeps creating OS threads while Publish adopts it. Exactly one
// outcome is correct and each is checked on kernel state: a clean adoption
// (every task adopted, no adopting fault, the init alive) or
// AdoptionCloneRefused (adopting faults counted, the Go runtime's refused
// clone killed the init, counted, then released once empty).
func TestSharedNodeM4AdoptionGoInitStorm(t *testing.T) {
	e := sharedM4Start(t)
	path := e.cgroup("storm")
	dir, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSharedM4GoInitHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), "IG_SHARED_M4_HELPER=storm")
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS, UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	dir.Close()
	// exited is closed (not sent on) once the init is reaped: the outcome
	// checks below and the cleanup both wait on it, and a single value
	// consumed by a check would leave the cleanup blocked forever.
	var exitErr error
	exited := make(chan struct{})
	go func() { exitErr = cmd.Wait(); close(exited) }()
	t.Cleanup(func() { _ = cmd.Process.Kill(); <-exited })
	time.Sleep(500 * time.Millisecond) // the Go runtime started and the storm is running
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	init := &sharedPipeInit{cmd: cmd, path: path, ino: st.Ino}
	s := e.bind(init)
	slot := s.Inspect().RouteSlot
	_, err = s.Publish(e.ctx, sharedM4Strict("storm"))
	state := e.adoptState(slot)
	if err == nil {
		if state.Adopted == 0 || state.Adopted != state.Iterated || state.Faults != 0 || e.anchor(slot).Adopting != 0 {
			t.Fatalf("clean adoption with state %+v anchor %+v", state, e.anchor(slot))
		}
		select {
		case <-exited:
			t.Fatalf("Go init died after a clean adoption: %v", exitErr)
		default:
		}
		t.Logf("storm: clean adoption of %d tasks", state.Adopted)
		return
	}
	// The storm both creates threads (a refused clone: CloneRefused) and
	// ends them (a thread that exits mid-adoption: ThreadExited); either
	// refusal is correct, each checked on the adopt state.
	var refused *ErrSharedAdoptionRefused
	if !errors.As(err, &refused) || refused.Audit {
		t.Fatalf("storm publish: %v, want clean, AdoptionCloneRefused or AdoptionThreadExited", err)
	}
	switch refused.Reason {
	case AdoptionCloneRefused:
		if state.Faults == 0 || e.counts()[AdoptionCloneRefused] != 1 {
			t.Fatalf("CloneRefused with state %+v counters %v", state, e.counts())
		}
		select {
		case <-exited:
			t.Logf("storm: AdoptionCloneRefused, %d adopting faults, Go init exited (%v)", state.Faults, exitErr)
		case <-time.After(10 * time.Second):
			t.Fatal("Go init survived a refused clone storm")
		}
	case AdoptionThreadExited:
		// Exited at finish (iterated < adopted, or exiting) or already at
		// verify (only exiting tasks were bad).
		if state.Faults != 0 || (state.Iterated >= state.Adopted && state.Exiting == 0) || e.counts()[AdoptionThreadExited] != 1 {
			t.Fatalf("ThreadExited with state %+v counters %v", state, e.counts())
		}
		t.Logf("storm: AdoptionThreadExited, iterated %d adopted %d exiting %d", state.Iterated, state.Adopted, state.Exiting)
	default:
		t.Fatalf("storm publish: %v, want clean, AdoptionCloneRefused or AdoptionThreadExited", err)
	}
	sharedM4KillCgroup(path)
	e.waitEmpty(path)
	e.waitReleased(slot, init.ino)
}

// TestSharedNodeM4CommandAuthentication (design 13.6, code 5): a product
// command with a wrong node cookie, a wrong nonce, a replayed sequence, or
// run off the admin thread is refused with code 5 and changes nothing: the
// receipt (last consumed sequence) is unchanged. A valid command then
// consumes its sequence (the negatives were not vacuous).
func TestSharedNodeM4CommandAuthentication(t *testing.T) {
	e := sharedM4Start(t)
	control := e.cmd.control
	receipt := func() [2]uint64 {
		var r [2]uint64
		raw, err := e.mapOf("opaque_real_cmd_receipt").LookupBytes(uint32(0))
		if err != nil {
			t.Fatal(err)
		}
		r[0], r[1] = binary.LittleEndian.Uint64(raw), binary.LittleEndian.Uint64(raw[8:])
		return r
	}
	const name = "opaque_real_adopt_verify"
	body := sharedProductAdoptBody(0, 0, 0)
	runOnAdmin := func(config sharedNodeWire, sequence uint64) uint32 {
		var code uint32
		if err := control.thread.do(e.ctx, func() error {
			var err error
			code, err = control.programs[name].Run(&ebpf.RunOptions{Context: sharedProductRequest(config, sequence, body)})
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return code
	}
	// One valid command first, so the receipt holds a consumed sequence.
	if code, err := control.run(e.ctx, name, body); err != nil || code == sharedProductAuthFailed {
		t.Fatalf("valid command: %d %v", code, err)
	}
	base := receipt()
	if base[0] != control.config.NodeCookie || base[1] == 0 {
		t.Fatalf("receipt %v after a valid command", base)
	}
	next := func() uint64 {
		var seq uint64
		_ = control.thread.do(e.ctx, func() error { seq = control.sequence + 1; return nil })
		return seq
	}
	badCookie, badNonce := control.config, control.config
	badCookie.NodeCookie ^= 1
	badNonce.Nonce ^= 1
	for label, code := range map[string]func() uint32{
		"wrong node cookie": func() uint32 { return runOnAdmin(badCookie, next()) },
		"wrong nonce":       func() uint32 { return runOnAdmin(badNonce, next()) },
		"replayed sequence": func() uint32 { return runOnAdmin(control.config, base[1]) },
		"zero sequence":     func() uint32 { return runOnAdmin(control.config, 0) },
		"off the admin thread": func() uint32 {
			code, err := control.programs[name].Run(&ebpf.RunOptions{Context: sharedProductRequest(control.config, next(), body)})
			if err != nil {
				t.Fatal(err)
			}
			return code
		},
	} {
		if got := code(); got != sharedProductAuthFailed {
			t.Errorf("%s: code %d, want %d", label, int32(got), sharedProductAuthFailed)
		}
		if r := receipt(); r != base {
			t.Errorf("%s: receipt %v changed from %v", label, r, base)
		}
	}
	if code, err := control.run(e.ctx, name, body); err != nil || code == sharedProductAuthFailed {
		t.Fatalf("valid command after the negatives: %d %v", code, err)
	}
	if r := receipt(); r[1] <= base[1] {
		t.Fatalf("receipt %v: the valid command consumed no sequence", r)
	}
}

// TestSharedNodeM4RecycleRepublish (G4): three cycles of bind, adopt and
// publish, remove, end the workload, recycle; each cycle reuses the
// recycled slot for a new cgroup, the old cgroup stays terminal, and the
// policy objects return to the baseline.
func TestSharedNodeM4RecycleRepublish(t *testing.T) {
	e := sharedM4Start(t)
	baseline := e.liveObjects()
	var lastIncarnation uint32
	var lastSlot uint32
	for cycle := range 3 {
		name := fmt.Sprintf("cycle%d", cycle)
		path := e.cgroup(name)
		init := startSharedPipeInit(t, path, "ig15-g019-m4-"+name+"-init")
		s := e.bind(init)
		slot := s.Inspect().RouteSlot
		if cycle > 0 && slot != lastSlot {
			t.Fatalf("cycle %d on slot %d, want the recycled slot %d", cycle, slot, lastSlot)
		}
		if _, err := s.Publish(e.ctx, sharedM4Strict(name)); err != nil {
			t.Fatalf("cycle %d publish: %v", cycle, err)
		}
		st, a := e.adoptState(slot), e.anchor(slot)
		if st.Adopted != 1 || st.Iterated != 1 || a.Adopting != 0 || a.State.Cgroup != init.ino || a.State.Generation != 1 {
			t.Fatalf("cycle %d: adopt state %+v anchor %+v", cycle, st, a)
		}
		if cycle > 0 && a.State.Incarnation == lastIncarnation {
			t.Fatalf("cycle %d: route incarnation %d not advanced by the recycle", cycle, a.State.Incarnation)
		}
		if got := e.liveObjects(); got != baseline+1 {
			t.Fatalf("cycle %d: %d live objects, want %d", cycle, got, baseline+1)
		}
		lastIncarnation, lastSlot = a.State.Incarnation, slot
		if err := s.Remove(e.ctx, 1); err != nil {
			t.Fatalf("cycle %d remove: %v", cycle, err)
		}
		init.stop()
		for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(50 * time.Millisecond) {
			e.node.mu.Lock()
			free := e.node.host.scopeSlots[slot] == nil
			e.node.mu.Unlock()
			if free {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("cycle %d: slot %d not recycled: %v", cycle, slot, e.node.liveHealthFault())
			}
		}
		if a := e.anchor(slot); a.State.Phase != 0 {
			t.Fatalf("cycle %d: recycled anchor %+v", cycle, a)
		}
		for deadline := time.Now().Add(10 * time.Second); e.liveObjects() != baseline; time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				t.Fatalf("cycle %d: %d live objects after the recycle, want %d", cycle, e.liveObjects(), baseline)
			}
		}
		if _, err := e.node.Bind(e.ctx, SharedBindingConfig{CgroupID: init.ino, InitHostPID: 1, Acquire: init.acquire}); !errors.Is(err, ErrSharedBindingWithdrawn) {
			t.Fatalf("cycle %d: rebind of the withdrawn cgroup: %v", cycle, err)
		}
	}
	if err := e.node.liveHealthFault(); err != nil {
		t.Fatalf("health after the cycles: %v", err)
	}
}

// TestSharedNodeM4PublishFaultInjector (B4 undo paths): a fault injected
// after pin and seal (1), after the epoch index bind (2) or after the
// cgroup locator insert (3) takes the real undo path: the publication is
// refused (retryable), the anchor stays FREE, adopting is never set,
// last_cgroup is not written and the staged object is released. With the
// injector off the same binding then publishes and adopts.
func TestSharedNodeM4PublishFaultInjector(t *testing.T) {
	e := sharedM4Start(t)
	fault := e.mapOf("opaque_real_publish_fault")
	path := e.cgroup("fault")
	init := startSharedPipeInit(t, path, "ig15-g019-m4-fault-init")
	s := e.bind(init)
	slot := s.Inspect().RouteSlot
	baseline := e.liveObjects()
	for point := uint32(1); point <= 3; point++ {
		if err := fault.Update(uint32(0), point, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Publish(e.ctx, sharedM4Strict("fault")); err == nil || !strings.Contains(err.Error(), "retryable") {
			t.Fatalf("fault point %d: %v, want a retryable refusal", point, err)
		}
		if _, err := e.cmd.route(slot); !errors.Is(err, ErrSharedRouteFree) {
			t.Fatalf("fault point %d: route %v, want FREE", point, err)
		}
		st := e.adoptState(slot)
		if st.Adopting != 0 || st.LastCgroup == init.ino || st.Adopted != 0 {
			t.Fatalf("fault point %d: adopt state %+v", point, st)
		}
		if got := e.liveObjects(); got != baseline {
			t.Fatalf("fault point %d: %d live objects, want %d (staged object released)", point, got, baseline)
		}
		if _, reported := e.pub.adoptionStatus(slot); reported || s.Inspect().RoutePublished {
			t.Fatalf("fault point %d: reported or recorded as published: %+v", point, s.Inspect())
		}
	}
	if err := fault.Update(uint32(0), uint32(0), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Publish(e.ctx, sharedM4Strict("fault")); err != nil {
		t.Fatalf("publish without the injector: %v", err)
	}
	if st := e.adoptState(slot); st.Adopted != 1 || st.Iterated != 1 || st.LastCgroup != init.ino {
		t.Fatalf("adopt state after the clean publication %+v", st)
	}
}
