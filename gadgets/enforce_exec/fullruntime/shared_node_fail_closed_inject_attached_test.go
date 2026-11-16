// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// G019 fail-closed injection on the live product node (VM only): each
// fail-closed class the product counts is driven on a product diagnostic
// twin (g19pkginjf128: the product object plus the publication fault
// injector, -DSE_PRODUCT_DIAGNOSTIC_TWIN=1, the fail-closed injectors and
// their extension ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_EXT_DIAGNOSTIC)
// through the node's own product publisher, and the node's witness poller
// (FailClosedHealth, Ready) must report it.
//
// Environment (isolated exact-kernel VM, root, initial pid/time namespaces):
//   IG_SHARED_M4_OBJECT          the twin g19pkginjf128
//   IG_SHARED_M4_CGROUP_ROOT     a dedicated parent cgroup whose basename
//                                starts with ig15-g019-m4- (ig15-g019-m4-fc);
//                                the test creates and removes its children
//   IG_SHARED_M4_HANDLER_SYMBOL  as for M4 (falls back to the M3 variable)
//   IG_SHARED_FC_HELPER          the static testdata/opaque_real_live_exec_parent.c
//                                build (FORKN/FORKR/FORKG, FORKED protocol)
//   IG_SHARED_FC_KINDS           comma-separated kinds (default every kind)
//   IG_SHARED_FC_CLASS           2 Strict (default) or 1 Audit
//   IG_SHARED_FC_BIRTHS          births (or ENTRY execs) per kind, default 300
//   IG_SHARED_FC_EVERY           injector period, default 7
//   IG_SHARED_FC_POLL_INTERVAL   the node's fail-closed poll interval,
//                                default 200ms

// sharedFCKind is one injected (or natural) fail-closed class.
type sharedFCKind struct {
	// ext selects opaque_real_fc_inject_ext (else the selector map); index
	// is the period's every[] index. natural kinds have no injector.
	ext     bool
	index   int
	natural bool
	// rate is the class the fault must land in.
	rate int
	// command is the helper command (one %d: children per round); empty
	// for entry (a host-joined exec in place).
	command string
	// births and execs are the nominal birth and exec attempts per child.
	births, execs int
	// refusal is the Strict exit code of a refused child (-1: the fork
	// itself was refused, FORKED:-1:EPERM).
	refusal int
	// follow is a birth fault: in Audit the unmanaged child's exec is one
	// ENTRY per fault; in Strict the refused birth never execs.
	follow bool
	// serial runs one child per round.
	serial bool
}

var sharedFCKinds = map[string]sharedFCKind{
	// every[2]: the Nth successful first-exec qualification is a fault.
	"qualify": {index: 2, rate: 6, command: "FORKN:%d:0\n", births: 1, execs: 1, refusal: 77},
	// every[0]: the Nth first success terminal's receipt stays pending, so
	// the reexec's next exec is refused.
	"pending": {index: 0, rate: 7, command: "FORKR:%d\n", births: 1, execs: 2, refusal: 77},
	// every[1] (skip_parent = the helper): the Nth grandchild birth's target
	// cannot open its parent TASK; Strict refuses that fork (the child
	// exits 95), Audit leaves the grandchild unmanaged.
	"birth-open-parent": {index: 1, rate: FailClosedRateOpenParent, command: "FORKG:%d\n", births: 2, execs: 1, refusal: 95, follow: true},
	// ext every[0]: the Nth owned exec of a task with a TASK cannot open it.
	"exec-open-parent": {ext: true, index: 0, rate: FailClosedRateOpenParent, command: "FORKN:%d:0\n", births: 1, execs: 1, refusal: 77},
	// ext every[1]: the Nth first-pass exec admission faults.
	"exec-admission": {ext: true, index: 1, rate: FailClosedRateAdmission, command: "FORKN:%d:0\n", births: 1, execs: 1, refusal: 77},
	// ext every[2]: the Nth fork admission faults (claim released, never
	// parked); Strict refuses the fork, Audit leaves the child unmanaged.
	"birth-admission": {ext: true, index: 2, rate: FailClosedRateAdmission, command: "FORKN:%d:0\n", births: 1, execs: 1, refusal: -1, follow: true},
	// ext every[3]: the Nth fork target that took its parked claim releases
	// it and takes the target re-admission fault path (ADMISSION against
	// the source's birth attempt, never CONSTRUCT); Strict refuses the fork,
	// Audit leaves the child unmanaged.
	"target-admission": {ext: true, index: 3, rate: FailClosedRateAdmission, command: "FORKN:%d:0\n", births: 1, execs: 1, refusal: -1, follow: true},
	// ext every[4]: the Nth owned exec whose TASK opened does not begin its
	// reader: OPEN_PARENT, no reader and no verdict (Strict denies, Audit
	// allows).
	"reader-not-begun": {ext: true, index: 4, rate: FailClosedRateOpenParent, command: "FORKN:%d:0\n", births: 1, execs: 1, refusal: 77},
	// Natural: a host-joined task (no TASK) execs in place (bash -c).
	"entry": {natural: true, rate: FailClosedRateEntry, execs: 1, refusal: 126},
	// The stale-resume injector (ENFORCE_EXEC_POOL_OPAQUE_INTERP_STALE_RESUME_DIAGNOSTIC,
	// armed with one count per child): every #! exec's later pass resumes
	// its WORK with a mismatched stage class and is refused, GAP with the
	// RESUME reason; its reader is aborted quarantined. One child per round:
	// the arm count is a check-then-decrement, exact only without racing
	// continuations. (The continue_* program arrays are frozen by the
	// operator, so a slot can no longer be deleted: asserted.)
	"gap": {natural: true, rate: FailClosedRateGap, command: "FORKN:%d:0\n", births: 1, execs: 2, refusal: 77, serial: true},
}

var sharedFCDefaultKinds = []string{"qualify", "pending", "birth-open-parent", "exec-open-parent", "exec-admission", "birth-admission", "target-admission", "reader-not-begun", "entry", "gap"}

type sharedFCConfig struct {
	helper   string
	kinds    []string
	class    int
	births   int
	every    int
	interval time.Duration
}

func sharedFCConfigFromEnv(t *testing.T) sharedFCConfig {
	t.Helper()
	if os.Getenv("IG_SHARED_M4_OBJECT") == "" || os.Getenv("IG_SHARED_M4_CGROUP_ROOT") == "" {
		t.Skip("set IG_SHARED_M4_OBJECT and IG_SHARED_M4_CGROUP_ROOT on an isolated exact-kernel VM")
	}
	c := sharedFCConfig{helper: os.Getenv("IG_SHARED_FC_HELPER"), kinds: sharedFCDefaultKinds, class: 2, births: 300, every: 7, interval: 200 * time.Millisecond}
	if c.helper == "" {
		t.Fatal("IG_SHARED_FC_HELPER (the static testdata/opaque_real_live_exec_parent.c build) is required")
	}
	if raw := os.Getenv("IG_SHARED_FC_KINDS"); raw != "" {
		c.kinds = strings.Split(raw, ",")
		for _, k := range c.kinds {
			if _, ok := sharedFCKinds[k]; !ok {
				t.Fatalf("IG_SHARED_FC_KINDS: unknown kind %q", k)
			}
		}
	}
	atoi := func(name string, dst *int, lo, hi int) {
		raw := os.Getenv(name)
		if raw == "" {
			return
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < lo || n > hi {
			t.Fatalf("invalid %s=%q (%d..%d)", name, raw, lo, hi)
		}
		*dst = n
	}
	atoi("IG_SHARED_FC_CLASS", &c.class, 1, 2)
	atoi("IG_SHARED_FC_BIRTHS", &c.births, 3, 3000)
	atoi("IG_SHARED_FC_EVERY", &c.every, 1, 1<<16)
	if raw := os.Getenv("IG_SHARED_FC_POLL_INTERVAL"); raw != "" {
		d, err := time.ParseDuration(raw)
		if err != nil || d < SharedFailClosedPollMin || d > SharedFailClosedPollMax {
			t.Fatalf("invalid IG_SHARED_FC_POLL_INTERVAL=%q", raw)
		}
		c.interval = d
	}
	return c
}

// sharedHelperInit is the static live-exec-parent helper started as a
// container-like init (cloned into the cgroup, own mount namespace): every
// FORK* command forks from the adopted init, so its children are owned
// births of the bound route.
type sharedHelperInit struct {
	*sharedPipeInit
}

func startSharedHelperInit(t *testing.T, cgroup, name, helper string, env []string) *sharedHelperInit {
	t.Helper()
	dir, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	cmd := exec.Command(helper)
	cmd.Args[0] = name
	cmd.Env = append(os.Environ(), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Unshareflags: syscall.CLONE_NEWNS, UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s in %s: %v", helper, cgroup, err)
	}
	t.Cleanup(func() { _ = in.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	reader := bufio.NewReader(out)
	if line, err := reader.ReadString('\n'); err != nil || line != "READY\n" {
		t.Fatalf("%s: %q %v", helper, line, err)
	}
	var st unix.Stat_t
	if err := unix.Stat(cgroup, &st); err != nil {
		t.Fatal(err)
	}
	return &sharedHelperInit{&sharedPipeInit{cmd: cmd, in: in, out: reader, path: cgroup, ino: st.Ino}}
}

// sharedFCExit is one FORKED line: pid -1 and the errno for a refused fork.
type sharedFCExit struct{ pid, code int }

// round sends command for k children and reads its k FORKED lines (and
// FORKN's THREADED:0:0).
func (h *sharedHelperInit) round(t *testing.T, command string, k int) []sharedFCExit {
	t.Helper()
	if _, err := fmt.Fprintf(h.in, command, k); err != nil {
		t.Fatal(err)
	}
	exits := make([]sharedFCExit, 0, k)
	for range k {
		line, err := h.out.ReadString('\n')
		if err != nil {
			t.Fatalf("%q: %v", command, err)
		}
		var e sharedFCExit
		if n, _ := fmt.Sscanf(line, "FORKED:%d:%d\n", &e.pid, &e.code); n != 2 || e.pid == 0 || e.pid < -1 {
			t.Fatalf("%q: line %q", command, line)
		}
		exits = append(exits, e)
	}
	if strings.HasPrefix(command, "FORKN:") {
		if line, err := h.out.ReadString('\n'); err != nil || line != "THREADED:0:0\n" {
			t.Fatalf("%q: line %q err %v", command, line, err)
		}
	}
	return exits
}

// sharedFCEnv is one subtest's fresh node with one bound, published
// cgroup whose adopted init is the helper.
type sharedFCEnv struct {
	*sharedM4Env
	cfg      sharedFCConfig
	helper   *sharedHelperInit
	path     string
	physical uint64 // the helper's task (se_opaque_keys)
	tasks    uint32 // TASK/WORK baseline after adoption
	works    uint32
}

func sharedFCStart(t *testing.T, cfg sharedFCConfig, name string, class int, env []string) *sharedFCEnv {
	t.Helper()
	e := sharedM4StartWith(t, func(c *SharedNodeConfig) { c.FailClosedPollInterval = cfg.interval })
	if h, err := e.node.FailClosedHealth(); err != nil || !h.Gated || !h.Product {
		t.Fatalf("fail-closed witness %+v (%v): want a gated product witness, Healthy at start", h, err)
	}
	path := e.cgroup("fc-" + name)
	helper := startSharedHelperInit(t, path, "ig15-g019-m4-fc-init", cfg.helper, env)
	s := e.bind(helper.sharedPipeInit)
	mode := fullpolicy.Audit
	if class == 2 {
		mode = fullpolicy.Enforce
	}
	if _, err := s.Publish(e.ctx, SharedBindingPolicy{Source: sharedM4Policy("fc-"+name, "1", mode, fullpolicy.Deny), Container: "fc"}); err != nil {
		t.Fatalf("publish (adoption): %v", err)
	}
	sharedM4RequireAdopted(t, e.gc, s.Inspect().RouteSlot)
	f := &sharedFCEnv{sharedM4Env: e, cfg: cfg, helper: helper, path: path}
	// The adopted helper is the only task with a TASK on this fresh node.
	var physical, locator uint64
	keys := e.mapOf("se_opaque_keys").Iterate()
	if !keys.Next(&physical, &locator) || physical == 0 || keys.Next(&physical, &locator) || keys.Err() != nil {
		t.Fatalf("se_opaque_keys: want exactly the adopted helper's TASK (%v)", keys.Err())
	}
	f.physical = physical
	f.tasks, f.works = f.accounts()
	return f
}

// accounts sums the used TASK and WORK credits of every binding account;
// a faulted account fails the test.
func (f *sharedFCEnv) accounts() (tasks, works uint32) {
	f.t.Helper()
	for i, name := range []string{"se_opaque_accounts", "se_opaque_work_accounts"} {
		m := f.mapOf(name)
		for a := uint32(0); a < m.MaxEntries(); a++ {
			raw, err := m.LookupBytes(a)
			if err != nil || len(raw) < 12 {
				f.t.Fatalf("%s[%d]: %v", name, a, err)
			}
			// Layout: lock, used, fault, incarnation.
			if fault := binary.LittleEndian.Uint32(raw[8:12]); fault != 0 {
				f.t.Fatalf("%s[%d] faulted (fault word %#x)", name, a, fault)
			}
			used := binary.LittleEndian.Uint32(raw[4:8])
			if i == 0 {
				tasks += used
			} else {
				works += used
			}
		}
	}
	return tasks, works
}

// settle waits (at most 60 s) until every TASK/WORK credit is back at the
// post-adoption baseline and no exec terminal receipt is left.
func (f *sharedFCEnv) settle(label string) {
	f.t.Helper()
	receipts := f.mapOf("se_exec_terminal_receipts")
	for deadline := time.Now().Add(time.Minute); ; time.Sleep(5 * time.Millisecond) {
		tasks, works := f.accounts()
		var key uint64
		var value []byte
		stray := receipts.Iterate().Next(&key, &value)
		if tasks == f.tasks && works == f.works && !stray {
			return
		}
		if time.Now().After(deadline) {
			f.t.Fatalf("%s: TASK %d WORK %d (baseline %d/%d), stray receipt %v (%#x): a fault leaked a credit", label, tasks, works, f.tasks, f.works, stray, key)
		}
	}
}

// injectorSet writes period n at the kind's index (0 disables).
func (f *sharedFCEnv) injectorSet(k sharedFCKind, n int) {
	f.t.Helper()
	if k.ext {
		// Mirrors struct opaque_real_fc_inject_ext.
		var value struct {
			Every    [5]uint32
			Reserved uint32
		}
		value.Every[k.index] = uint32(n)
		if err := f.mapOf("opaque_real_fc_inject_ext").Update(uint32(0), &value, ebpf.UpdateAny); err != nil {
			f.t.Fatalf("opaque_real_fc_inject_ext: %v", err)
		}
		return
	}
	// Mirrors struct opaque_real_fc_inject_selector.
	var value struct {
		Every      [3]uint32
		Reserved   uint32
		SkipParent uint64
	}
	value.Every[k.index] = uint32(n)
	value.SkipParent = f.physical
	if err := f.mapOf("opaque_real_fc_inject_selector").Update(uint32(0), &value, ebpf.UpdateAny); err != nil {
		f.t.Fatalf("opaque_real_fc_inject_selector: %v", err)
	}
}

// injectorCounts returns the kind's (edges, injected) counters: the
// selector's [0..2]/[3..5], the extended injector's [0..4]/[5..9].
func (f *sharedFCEnv) injectorCounts(k sharedFCKind) (uint64, uint64) {
	f.t.Helper()
	name, periods := "opaque_real_fc_inject_counts", 3
	if k.ext {
		name, periods = "opaque_real_fc_inject_ext_counts", 5
	}
	m := f.mapOf(name)
	var edges, injected uint64
	if err := m.Lookup(uint32(k.index), &edges); err != nil {
		f.t.Fatalf("%s[%d]: %v", name, k.index, err)
	}
	if err := m.Lookup(uint32(periods+k.index), &injected); err != nil {
		f.t.Fatalf("%s[%d]: %v", name, periods+k.index, err)
	}
	return edges, injected
}

// requireContinueFrozen: the operator froze the class's continue_*
// program array after installing its slot, so userspace cannot delete
// (nor replace) it: EPERM.
func (f *sharedFCEnv) requireContinueFrozen(strict bool) {
	f.t.Helper()
	name := "opaque_real_continue_audit"
	if strict {
		name = "opaque_real_continue_strict"
	}
	if err := f.mapOf(name).Delete(uint32(0)); !errors.Is(err, unix.EPERM) {
		f.t.Fatalf("delete %s[0]: %v, want EPERM (a frozen program array)", name, err)
	}
}

// interpStats reads the interpreter continuation witness.
func (f *sharedFCEnv) interpStats() [InterpContinuationStats]uint64 {
	f.t.Helper()
	var cells [InterpContinuationStats]uint64
	m := f.mapOf(InterpContinuationStatsMap)
	for i := range cells {
		if err := m.Lookup(uint32(i), &cells[i]); err != nil {
			f.t.Fatalf("%s[%d]: %v", InterpContinuationStatsMap, i, err)
		}
	}
	return cells
}

// evalWorkOutcomes reads cells [3] (reader aborted quarantined) and [4] of
// opaque_real_eval_work_outcomes.
func (f *sharedFCEnv) evalWorkOutcomes() [2]uint64 {
	f.t.Helper()
	var cells [2]uint64
	m := f.mapOf("opaque_real_eval_work_outcomes")
	for i := range cells {
		if err := m.Lookup(uint32(3+i), &cells[i]); err != nil {
			f.t.Fatalf("opaque_real_eval_work_outcomes[%d]: %v", 3+i, err)
		}
	}
	return cells
}

// entryExec runs one host-joined exec in place in the cgroup (a task with
// no TASK on an OWNED route: ENTRY) and returns its exit code.
func (f *sharedFCEnv) entryExec() int {
	f.t.Helper()
	cmd := exec.Command("/bin/bash", "-c", `echo $$ > "$1/cgroup.procs" || exit 99; /bin/true`, "ig15-g019-m4-fc-entry", f.path)
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	}
	f.t.Fatalf("entry exec: %v", err)
	return 0
}

// run drives n births (or n ENTRY execs) of kind through the helper in
// rounds of at most 3, settling after each round; it returns the exits.
func (f *sharedFCEnv) run(k sharedFCKind, n int) map[int]int {
	f.t.Helper()
	exits := map[int]int{}
	if k.command == "" {
		for range n {
			exits[f.entryExec()]++
		}
		return exits
	}
	for sent := 0; sent < n; {
		c := min(3, n-sent)
		if k.serial {
			c = 1
		}
		for _, e := range f.helper.round(f.t, k.command, c) {
			if e.pid < 0 {
				exits[-e.code]++ // a refused fork: -errno
			} else {
				exits[e.code]++
			}
		}
		sent += c
		f.settle(fmt.Sprintf("round %d", sent))
	}
	return exits
}

// healthWait polls FailClosedHealth until want, at most within, failing on
// Unknown; it returns the report and its error.
func (f *sharedFCEnv) healthWait(want SharedFailClosedState, within time.Duration) (SharedFailClosedHealth, error) {
	f.t.Helper()
	deadline := time.Now().Add(within)
	for {
		h, err := f.node.FailClosedHealth()
		if h.State == SharedFailClosedUnknown || errors.Is(err, ErrSharedFailClosedUnknown) {
			f.t.Fatalf("fail-closed witness Unknown: %+v %v", h, err)
		}
		if h.State == want || time.Now().After(deadline) {
			return h, err
		}
		time.Sleep(f.cfg.interval / 4)
	}
}

// requireHealth requires state want (with its error, Ready carrying the
// same) within 2 intervals + 1 s.
func (f *sharedFCEnv) requireHealth(label string, want SharedFailClosedState) SharedFailClosedHealth {
	f.t.Helper()
	within := 2*f.cfg.interval + time.Second
	h, err := f.healthWait(want, within)
	if h.State != want || !h.Gated {
		f.t.Fatalf("%s: fail-closed health %s (gated %v) after %s, want %s: %v", label, h.State, h.Gated, within, want, err)
	}
	ready := f.node.Ready(f.gc)
	if !errors.Is(ready, ErrSharedNativeUnavailable) {
		f.t.Fatalf("%s: Ready %v, want ErrSharedNativeUnavailable kept", label, ready)
	}
	var wantErr error
	switch want {
	case SharedFailClosedNotReady:
		wantErr = ErrSharedFailClosedNotReady
	case SharedFailClosedDegraded:
		wantErr = ErrSharedFailClosedDegraded
	}
	if wantErr == nil {
		if err != nil || errors.Is(ready, ErrSharedFailClosedDegraded) || errors.Is(ready, ErrSharedFailClosedNotReady) {
			f.t.Fatalf("%s: Healthy with health error %v, Ready %v", label, err, ready)
		}
		return h
	}
	if !errors.Is(err, wantErr) || !errors.Is(ready, wantErr) {
		f.t.Fatalf("%s: health error %v, Ready %v, want %v in both", label, err, ready, wantErr)
	}
	return h
}

// TestSharedNodeFailClosedInjectAttached (G019, VM only): each kind on a
// fresh node and a fresh cgroup whose adopted init is the helper. A
// calibration round (injector off) must move no fail-closed cell and gives
// the attempt overhead; the injected round must then count exactly:
//   - injected == the every-Nth share of the edges seen (natural kinds:
//     every birth or ENTRY exec), and the target class delta == injected;
//   - every other cell 0, except a birth fault's pinned follow-on: in
//     Audit the unmanaged child's exec is one ENTRY per fault (Strict
//     refused that birth, so it never execs);
//   - FailClosedProductRate consistent (Total, Admission, Entry);
//   - attempts[0]/[1] deltas == nominal births/execs + the calibrated
//     overhead (Strict: minus the execs of refused births);
//   - exits: Strict refusals exactly the injected ones (FORKED:-1:EPERM
//     only for birth-admission and target-admission), Audit all 0;
//   - TASK/WORK back to baseline and no stray receipt within 60 s;
//   - the poller: Total and ADMISSION kinds NotReady within 2 intervals +
//     1 s (FailClosedHealth and Ready, ErrSharedFailClosedNotReady,
//     gated); ENTRY stays Healthy.
func TestSharedNodeFailClosedInjectAttached(t *testing.T) {
	cfg := sharedFCConfigFromEnv(t)
	for _, name := range cfg.kinds {
		t.Run(name, func(t *testing.T) {
			sharedFCInjectKind(t, cfg, name)
		})
	}
}

func sharedFCInjectKind(t *testing.T, cfg sharedFCConfig, name string) {
	k := sharedFCKinds[name]
	strict := cfg.class == 2
	var env []string
	if name == "gap" {
		script := filepath.Join(t.TempDir(), "fc-gap")
		if err := os.WriteFile(script, []byte("#!/bin/true\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		env = append(env, "IG_OPAQUE_FORK_SCRIPT="+script)
	}
	f := sharedFCStart(t, cfg, name, cfg.class, env)
	// Calibration: the same command and births, no injector (entry: a plain
	// FORKN round, its own execs are exact).
	cal := k
	if name == "entry" {
		cal = sharedFCKinds["exec-open-parent"]
	}
	before := sharedM4ReadWitness(t, f.gc)
	var interpBefore [InterpContinuationStats]uint64
	if name == "gap" {
		interpBefore = f.interpStats()
	}
	calExits := f.run(cal, cfg.births)
	after := sharedM4ReadWitness(t, f.gc)
	if name == "gap" {
		// Calibration continues every script's later pass (depth 1).
		var want [InterpContinuationStats]uint64
		want[InterpContinuedDepth1] = uint64(cfg.births)
		if got := f.interpStats(); sharedFCDelta(interpBefore, got) != want {
			t.Fatalf("calibration interpreter stats %v -> %v, want %d continued at depth 1", interpBefore, got, cfg.births)
		}
	}
	for i := range after.rates {
		if after.rates[i] != before.rates[i] {
			t.Fatalf("calibration moved the fail-closed witness %v -> %v", before.rates, after.rates)
		}
	}
	if calExits[0] != cfg.births {
		t.Fatalf("calibration exits %v, want %d allowed", calExits, cfg.births)
	}
	overhead := [FailClosedRateAttempts]int64{
		int64(after.attempts[0]-before.attempts[0]) - int64(cal.births*cfg.births),
		int64(after.attempts[1]-before.attempts[1]) - int64(cal.execs*cfg.births),
	}
	if overhead[0] < 0 || overhead[1] < 0 {
		t.Fatalf("calibration attempts %v -> %v below nominal %d births / %d execs", before.attempts, after.attempts, cal.births*cfg.births, cal.execs*cfg.births)
	}
	if name == "entry" {
		overhead = [FailClosedRateAttempts]int64{}
	}
	if h := f.requireHealth("calibration", SharedFailClosedHealthy); h.Counters != [FailClosedRateCounters]uint64{} {
		t.Fatalf("calibration: health counters %v", h.Counters)
	}

	// The injected round.
	edgesBefore, injectedBefore := uint64(0), uint64(0)
	var arm *ebpf.Map
	var interpStart [InterpContinuationStats]uint64
	var outcomesStart [2]uint64
	switch {
	case !k.natural:
		edgesBefore, injectedBefore = f.injectorCounts(k)
		f.injectorSet(k, cfg.every)
	case name == "gap":
		f.requireContinueFrozen(strict)
		arm = f.mapOf("opaque_real_interp_stale_resume")
		interpStart, outcomesStart = f.interpStats(), f.evalWorkOutcomes()
		if err := arm.Update(uint32(0), uint64(cfg.births), ebpf.UpdateAny); err != nil {
			t.Fatalf("arm opaque_real_interp_stale_resume: %v", err)
		}
		t.Cleanup(func() { _ = arm.Update(uint32(0), uint64(0), ebpf.UpdateAny) })
	}
	before = sharedM4ReadWitness(t, f.gc)
	exits := f.run(k, cfg.births)
	if !k.natural {
		f.injectorSet(k, 0)
	}
	after = sharedM4ReadWitness(t, f.gc)
	if arm != nil {
		var left uint64
		if err := arm.Lookup(uint32(0), &left); err != nil || left != 0 {
			t.Errorf("stale-resume injector not consumed exactly: %d left (%v)", left, err)
		}
		var want [InterpContinuationStats]uint64
		want[InterpRefusedResume] = uint64(cfg.births)
		if got := f.interpStats(); sharedFCDelta(interpStart, got) != want {
			t.Errorf("interpreter stats %v -> %v, want exactly %d RESUME refusals", interpStart, got, cfg.births)
		}
		if got := f.evalWorkOutcomes(); got[0]-outcomesStart[0] != uint64(cfg.births) || got[1] != outcomesStart[1] {
			t.Errorf("eval WORK outcomes [3,4] %v -> %v, want [3] +%d (reader aborted quarantined), [4] unchanged", outcomesStart, got, cfg.births)
		}
	}
	done := time.Now()
	edges, injected := uint64(cfg.births), uint64(cfg.births)
	if !k.natural {
		edgesAfter, injectedAfter := f.injectorCounts(k)
		edges, injected = edgesAfter-edgesBefore, injectedAfter-injectedBefore
		n := uint64(cfg.every)
		if injected == 0 || injected != edgesAfter/n-edgesBefore/n {
			t.Errorf("%d injected for %d edges (%d -> %d) every %d", injected, edges, edgesBefore, edgesAfter, n)
		}
	}
	var deltas [FailClosedRateCounters]uint64
	for i := range deltas {
		deltas[i] = after.rates[i] - before.rates[i]
	}
	var want [FailClosedRateCounters]uint64
	want[k.rate] = injected
	if k.follow && !strict {
		want[FailClosedRateEntry] += injected
	}
	if deltas != want {
		t.Errorf("rate deltas %v, want %v (target [%d] = %d injected)", deltas, want, k.rate, injected)
	}
	v, err := FailClosedProductRate(before.rates, after.rates, before.attempts, after.attempts, 0)
	wantTotal := uint64(0)
	if k.rate < FailClosedRateClasses {
		wantTotal = injected
	}
	switch {
	case err != nil:
		t.Errorf("FailClosedProductRate: %v", err)
	case v.Total != wantTotal || v.Admission != want[FailClosedRateAdmission] || v.Entry != want[FailClosedRateEntry]:
		t.Errorf("verdict %+v: want Total %d, Admission %d, Entry %d", v, wantTotal, want[FailClosedRateAdmission], want[FailClosedRateEntry])
	}
	refusedBirths := int64(0)
	if k.follow && strict {
		refusedBirths = int64(injected)
	}
	wantAttempts := [FailClosedRateAttempts]int64{
		int64(k.births*cfg.births) + overhead[0],
		int64(k.execs*cfg.births) - refusedBirths + overhead[1],
	}
	gotAttempts := [FailClosedRateAttempts]int64{int64(after.attempts[0] - before.attempts[0]), int64(after.attempts[1] - before.attempts[1])}
	if gotAttempts != wantAttempts {
		t.Errorf("attempts +%v, want %v (nominal + calibrated overhead %v)", gotAttempts, wantAttempts, overhead)
	}
	refusal := k.refusal
	if refusal == -1 {
		refusal = -int(syscall.EPERM)
	}
	if strict {
		if uint64(exits[refusal]) != injected || exits[0]+exits[refusal] != cfg.births {
			t.Errorf("Strict exits %v, want %d refused (%d) and the rest 0", exits, injected, refusal)
		}
	} else if exits[0] != cfg.births {
		t.Errorf("Audit exits %v, want all %d allowed (0)", exits, cfg.births)
	}
	// The node's poller (requireHealth: within 2 intervals + 1 s), then
	// every credit back and no stray receipt.
	var h SharedFailClosedHealth
	if name == "entry" {
		time.Sleep(time.Until(done.Add(2*cfg.interval + time.Second)))
		h = f.requireHealth("entry", SharedFailClosedHealthy)
		if h.Counters[FailClosedRateEntry] != injected {
			t.Errorf("health ENTRY %d, want %d", h.Counters[FailClosedRateEntry], injected)
		}
	} else {
		h = f.requireHealth(name, SharedFailClosedNotReady)
	}
	f.settle("after injection")
	t.Logf("FCINJ kind=%s class=%d births=%d every=%d edges=%d injected=%d deltas=%v attempts=%v overhead=%v exits=%v cal-exits=%v health=%s sustained-total=%d admission=%d entry=%d",
		name, cfg.class, cfg.births, cfg.every, edges, injected, deltas, gotAttempts, overhead, exits, calExits, h.State, h.Sustained.Total, h.Sustained.Admission, h.Sustained.Entry)
}

// TestSharedNodeFailClosedHealthAttached (G019, VM only, Strict, 200 ms
// poll by default): the runtime reporting rule on the live node.
//   - rate: Healthy at start; one ENTRY stays Healthy; after a 1500-birth
//     clean warm-up one qualification fault is Degraded (Recent), not
//     Sustained; 10 more faults within 100 attempts are NotReady; about
//     6000 clean births dilute the rate, and a quiet Degraded window later
//     the node is Healthy again (Ready carries no fail-closed error);
//   - admission (a fresh node: a diluted node's 5-minute window could not
//     show it): 5 exec ADMISSION faults are NotReady by AdmissionRate alone
//     (Total 0);
//   - throughout: never Unknown, never a sticky fault.
func TestSharedNodeFailClosedHealthAttached(t *testing.T) {
	cfg := sharedFCConfigFromEnv(t)
	cfg.class = 2
	// watch polls the health in the background and records any Unknown.
	watch := func(f *sharedFCEnv) func() {
		stop, done := make(chan struct{}), make(chan struct{})
		var mu sync.Mutex
		var unknown []string
		go func() {
			defer close(done)
			for {
				select {
				case <-stop:
					return
				case <-time.After(f.cfg.interval / 2):
				}
				if h, err := f.node.FailClosedHealth(); h.State == SharedFailClosedUnknown || errors.Is(err, ErrSharedFailClosedUnknown) {
					mu.Lock()
					unknown = append(unknown, fmt.Sprint(err))
					mu.Unlock()
				}
			}
		}()
		return func() {
			close(stop)
			<-done
			if len(unknown) != 0 {
				f.t.Errorf("fail-closed witness Unknown during the run: %v", unknown)
			}
		}
	}
	qualify := sharedFCKinds["qualify"]
	forkn := func(f *sharedFCEnv, births, k int) map[int]int {
		exits := map[int]int{}
		for sent := 0; sent < births; sent += k {
			for _, e := range f.helper.round(f.t, "FORKN:%d:0\n", min(k, births-sent)) {
				exits[e.code]++
			}
		}
		return exits
	}
	t.Run("rate", func(t *testing.T) {
		f := sharedFCStart(t, cfg, "health", 2, nil)
		defer watch(f)()
		start := time.Now()
		f.requireHealth("start", SharedFailClosedHealthy)
		if code := f.entryExec(); code != 126 {
			t.Fatalf("Strict ENTRY exec exited %d, want 126", code)
		}
		time.Sleep(2*cfg.interval + time.Second)
		if h := f.requireHealth("entry", SharedFailClosedHealthy); h.Counters[FailClosedRateEntry] != 1 {
			t.Fatalf("ENTRY %d, want 1", h.Counters[FailClosedRateEntry])
		}
		if exits := forkn(f, 1500, 8); exits[0] != 1500 {
			t.Fatalf("warm-up exits %v", exits)
		}
		f.requireHealth("warm-up", SharedFailClosedHealthy)
		_, before := f.injectorCounts(qualify)
		f.injectorSet(qualify, 1)
		exits := forkn(f, 1, 1)
		f.injectorSet(qualify, 0)
		if exits[77] != 1 {
			t.Fatalf("single fault exits %v, want one refused (77)", exits)
		}
		h := f.requireHealth("single fault", SharedFailClosedDegraded)
		if !h.Recent.Degraded || h.Sustained.Degraded || h.Recent.Total != 1 {
			t.Fatalf("single fault: Recent %+v Sustained %+v, want Degraded by Recent only", h.Recent, h.Sustained)
		}
		f.injectorSet(qualify, 5)
		exits = forkn(f, 50, 5)
		f.injectorSet(qualify, 0)
		lastFault := time.Now()
		_, after := f.injectorCounts(qualify)
		if after-before != 11 || exits[77] != 10 || exits[0] != 40 {
			t.Fatalf("burst: %d injected in total, exits %v; want 1 + 10 refused within 100 attempts", after-before, exits)
		}
		h = f.requireHealth("burst", SharedFailClosedNotReady)
		if !h.Sustained.Degraded || h.Sustained.Rate <= FailClosedRateNotReadyThreshold {
			t.Fatalf("burst: Sustained %+v, want a rate above %.1f%%", h.Sustained, 100*FailClosedRateNotReadyThreshold)
		}
		if exits := forkn(f, 6000, 8); exits[0] != 6000 {
			t.Fatalf("dilution exits %v", exits)
		}
		quiet := lastFault.Add(FailClosedRateDegradedWindow + 2*cfg.interval)
		if wait := time.Until(quiet); wait > 0 {
			time.Sleep(wait)
		}
		h = f.requireHealth("diluted", SharedFailClosedHealthy)
		f.settle("diluted")
		t.Logf("HEALTH rate: warm-up 1500, faults 11, dilution 6000 in %s; Sustained %+v over %s; counters %v attempts %v",
			time.Since(start).Round(time.Millisecond), h.Sustained, h.SustainedSpan, h.Counters, h.Attempts)
	})
	t.Run("admission", func(t *testing.T) {
		f := sharedFCStart(t, cfg, "health-admission", 2, nil)
		defer watch(f)()
		f.requireHealth("start", SharedFailClosedHealthy)
		admission := sharedFCKinds["exec-admission"]
		f.injectorSet(admission, 1)
		exits := forkn(f, 5, 5)
		f.injectorSet(admission, 0)
		if exits[77] != 5 {
			t.Fatalf("admission exits %v, want 5 refused (77)", exits)
		}
		h := f.requireHealth("admission", SharedFailClosedNotReady)
		if h.Sustained.Total != 0 || h.Sustained.Admission != 5 || h.Sustained.AdmissionRate <= FailClosedRateNotReadyThreshold {
			t.Fatalf("admission: Sustained %+v, want NotReady by AdmissionRate alone (Total 0, Admission 5)", h.Sustained)
		}
		f.settle("admission")
		t.Logf("HEALTH admission: Sustained %+v counters %v attempts %v", h.Sustained, h.Counters, h.Attempts)
	})
}

// sharedFCDelta is after - before, cell by cell.
func sharedFCDelta(before, after [InterpContinuationStats]uint64) [InterpContinuationStats]uint64 {
	var d [InterpContinuationStats]uint64
	for i := range d {
		d[i] = after[i] - before[i]
	}
	return d
}
