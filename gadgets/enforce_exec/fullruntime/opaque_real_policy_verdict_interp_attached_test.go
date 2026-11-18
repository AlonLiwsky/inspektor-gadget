// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf/btf"

	"golang.org/x/sys/unix"
)

// G019 gap 4 (review H1): the same-bprm script-interpreter continuation,
// driven by TestOpaqueRealPolicyVerdictAttached with
// IG_OPAQUE_REAL_VERDICT_INTERP=1 on an object built with
// ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE (and MIGRATE=1 for
// the mid-exec migration case). Each case is one child of the qualified
// parent; it checks the exact number of evaluations (one per evaluated
// pass of the same exec), the continued/refused passes by cell, the GAP
// and PENDING fail-closed classes, one evaluation WORK per exec (no pass
// charges a credit), the exact TASK settlement, and that the parent stays
// QUALIFIED (its next fork works).

// opaqueInterpFiles is the scripts directory: s0 (#!/bin/true), the nested
// chain n0..n5 (n<d-1> runs d continued passes; n5 is exec_binprm depth 6:
// -ELOOP), miss (#! a missing interpreter), plain (no #!, not ELF:
// ENOEXEC), and the binfmt_misc files x.igp/x.igf/x.igo.
type opaqueInterpFiles struct {
	dir, hold string
}

func newOpaqueInterpFiles(t interface {
	Helper()
	TempDir() string
	Fatal(...any)
},
) opaqueInterpFiles {
	t.Helper()
	dir := t.TempDir()
	// The interpreter is a private copy, so a fanotify mark on it holds
	// only these execs (never the harness's own /bin/true).
	hold := filepath.Join(dir, "true")
	raw, err := os.ReadFile("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{"true": string(raw)}
	files["s0"] = "#!" + hold + "\n"
	files["n0"] = files["s0"]
	for d := 1; d <= 5; d++ {
		files["n"+strconv.Itoa(d)] = "#!" + filepath.Join(dir, "n"+strconv.Itoa(d-1)) + "\n"
	}
	files["miss"] = "#!" + filepath.Join(dir, "missing") + "\n"
	files["plain"] = "exit 3\n"
	for _, ext := range []string{"igp", "igf", "igo"} {
		files["x."+ext] = "binfmt_misc payload\n"
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Scripts must be readable and the directory searchable by uid 1000:
	// testing.T.TempDir creates its per-test parent 0700, which made the
	// uid-1000 exec fail EACCES before any policy decision.
	chmodTempAncestors(t, dir)
	return opaqueInterpFiles{dir: dir, hold: hold}
}

type opaqueInterpCase struct {
	label, command string
	// passes evaluated (each one rule evaluation of the same exec).
	passes uint64
	// continued[d-1]: passes continued at exec_binprm depth d.
	continued [5]uint64
	// refused: refusal cells (InterpRefused*) that must each move by 1;
	// each is one GAP.
	refused  []int
	wantExit int
	errno    syscall.Errno
	// works: completed child WORKs (birth + one evaluation WORK per
	// evaluated exec); execs: evaluated execs (terminals).
	works, execs int
	// held: XH command; onHeld runs while the interpreter open is held.
	held   bool
	onHeld func(pid int)
	// killed: the child dies by SIGKILL (no exit code, no errno report).
	killed bool
	// tasks: charged child TASKs of the case (0 means 1); a non-leader
	// thread exec has two (the forked child and its pthread, each a birth
	// through task_alloc).
	tasks int
	// quarantined: the case is a continuation refusal, whose fail-closed
	// cleanup quarantines the exec'ing TASK (real_owner_continue_refuse:
	// real_owner_policy_failure_global aborts the reader quarantined, then
	// real_owner_reader_quarantine_pending sets SE_TASK_QUARANTINED). Every
	// child TASK of the case must then carry SE_TASK_QUARANTINED.
	quarantined bool
}

// interpSettle waits for every child TASK of a case to finish its final
// free, checks it settled (no reader, no exec, no receipt), checks its
// quarantine against the case and, for an unquarantined TASK, its role
// history; then returns their exact refunds.
func (v *opaqueVerdictRun) interpSettle(label string, n int, quarantined bool) []opaqueVerdictRefund {
	v.t.Helper()
	children := v.childTasks(label)
	if len(children) != n {
		v.t.Fatalf("%s: expected %d child TASKs, got %d", label, n, len(children))
	}
	var refunds []opaqueVerdictRefund
	for _, entry := range children {
		v.finalFree(label, entry)
		flags, cookie, settled := v.task(entry.physical, entry.locator)
		if !settled {
			v.t.Fatalf("%s: child TASK slot %d not settled (flags=%d)", label, entry.slot, flags)
		}
		if quarantined != (flags&2 != 0) {
			v.t.Fatalf("%s: child TASK slot %d flags=%d, want quarantined=%v", label, entry.slot, flags, quarantined)
		}
		if old, ok := v.seen[entry.physical]; ok {
			v.reuses++
			if cookie <= old {
				v.t.Fatalf("%s: physical reuse kept stale identity", label)
			}
		}
		v.seen[entry.physical] = cookie
		if !quarantined {
			v.expectRole(label, entry.physical, entry.locator)
		}
		refunds = append(refunds, opaqueVerdictRefund{entry.slot, cookie})
	}
	return refunds
}

// interpSub runs one step of the matrix as a subtest of the running test:
// a failure ends only that step, so one live run reports every case (the
// next step starts after it; a desynchronised helper fails later steps
// visibly, never silently).
func (v *opaqueVerdictRun) interpSub(name string, step func()) {
	parent := v.t
	ok := parent.Run(name, func(t *testing.T) {
		v.t = t
		defer func() { v.t = parent }()
		step()
	})
	if ok {
		return
	}
	// A failed step may leave its children's TASK/WORK charged: drain them
	// (final free, exact refund) in a cleanup step of its own so the next
	// case starts from the parent alone. The failure stays reported.
	parent.Run("cleanup after "+name, func(t *testing.T) {
		v.t = t
		defer func() { v.t = parent }()
		v.interpDrain("cleanup after " + name)
	})
}

// interpDrain returns every remaining child TASK (after its final free)
// and WORK, asserting nothing about the failed step's outcome.
func (v *opaqueVerdictRun) interpDrain(label string) {
	v.t.Helper()
	for _, entry := range v.childTasks(label) {
		v.finalFree(label, entry)
		v.reap("task", entry.slot, entry.cookie)
	}
	v.settleRound(label, -1)
	v.parentQualified(label)
}

func (v *opaqueVerdictRun) interpCase(c opaqueInterpCase) {
	v.interpSub(c.label, func() { v.interpCaseRun(c) })
}

func (v *opaqueVerdictRun) interpCaseRun(c opaqueInterpCase) {
	v.t.Helper()
	label := "interp " + c.label
	rates := v.c.Maps["opaque_real_fail_closed_rates"]
	cells := v.rateCells(label, rates)
	beforeRates := v.counters(label, rates, cells)
	beforeInterp := v.interpStats(label)
	beforeEvals, _ := v.progress()
	beforeOutcomes := v.terminalOutcomes()
	beforeSync := v.counters(label, v.c.Maps[WorkSyncWitnessMap], workSyncCounters)
	if _, err := v.stdin.Write([]byte(c.command)); err != nil {
		v.t.Fatal(err)
	}
	line, err := v.stdout.ReadString('\n')
	// A hold that never engaged (XHN: the interpreter open was not
	// intercepted) is a loud failure of the case, after its XSD line is
	// consumed so the helper protocol stays in step.
	if strings.HasPrefix(line, "XHN:") {
		next, _ := v.stdout.ReadString('\n')
		v.t.Fatalf("%s: the interpreter open was never held (%q, then %q): the case did not run between the passes", label, line, next)
	}
	if c.killed {
		// XHK:<pid>:<1: died while its interpreter open was held>.
		var held, dead int
		if n, _ := fmt.Sscanf(line, "XHK:%d:%d\n", &held, &dead); err != nil || n != 2 || dead != 1 {
			next, _ := v.stdout.ReadString('\n')
			v.t.Fatalf("%s: child not killed while its interpreter open was held: %q then %q", label, line, next)
		}
		line, err = v.stdout.ReadString('\n')
	}
	if c.held {
		var pid int
		if n, _ := fmt.Sscanf(line, "XHELD:%d\n", &pid); err != nil || n != 1 {
			v.dump(label)
			v.t.Fatalf("%s: interpreter open never held: line=%q err=%v stderr=%q", label, line, err, v.stderr.String())
		}
		// GO is always sent and the XSD line always consumed, even when
		// onHeld fails the case: the helper waits for it.
		released := false
		release := func() {
			if released {
				return
			}
			released = true
			if _, err := v.stdin.Write([]byte("GO\n")); err != nil {
				v.t.Fatal(err)
			}
			line, err = v.stdout.ReadString('\n')
		}
		func() {
			defer func() {
				if !released {
					release()
				}
			}()
			if c.onHeld != nil {
				c.onHeld(pid)
			}
		}()
		release()
	}
	var pid, exit, errno int
	if n, _ := fmt.Sscanf(line, "XSD:%d:%d:%d\n", &pid, &exit, &errno); err != nil || n != 3 {
		v.dump(label)
		v.t.Fatalf("%s: line=%q err=%v stderr=%q", label, line, err, v.stderr.String())
	}
	if c.killed {
		if exit != -1 {
			v.t.Fatalf("%s: child exit %d, want killed", label, exit)
		}
	} else if exit != c.wantExit || syscall.Errno(errno) != c.errno {
		v.dump(label)
		v.t.Fatalf("%s: child exit %d errno %v, want %d %v", label, exit, syscall.Errno(errno), c.wantExit, c.errno)
	}
	tasks := c.tasks
	if tasks == 0 {
		tasks = 1
	}
	refunds := v.interpSettle(label, tasks, c.quarantined)
	works := v.settleRound(label, -1)
	_, syncExec, syncReturned := v.syncSettled(label, beforeSync)
	works += int(syncReturned)
	evals, _ := v.progress()
	if got := evals - beforeEvals; got != c.passes {
		v.dump(label)
		v.t.Fatalf("%s: %d evaluations, want %d (one per evaluated pass)", label, got, c.passes)
	}
	if works != c.works {
		v.t.Fatalf("%s: %d completed child WORKs, want %d (no pass charges a credit)", label, works, c.works)
	}
	if v.syncReturn() && syncExec != uint64(c.execs) {
		v.t.Fatalf("%s: %d exec terminals settled synchronously, want %d", label, syncExec, c.execs)
	}
	outcomes := v.terminalOutcomes()
	if d := outcomes[0] - beforeOutcomes[0]; d != uint64(c.execs) {
		v.t.Fatalf("%s: %d terminals completed into their evaluation WORK, want %d (outcomes %v -> %v)", label, d, c.execs, beforeOutcomes, outcomes)
	}
	for i := 1; i < len(outcomes); i++ {
		if outcomes[i] != beforeOutcomes[i] {
			v.t.Fatalf("%s: terminal outcome %d moved %d -> %d", label, i, beforeOutcomes[i], outcomes[i])
		}
	}
	afterInterp := v.interpStats(label)
	want := make([]uint64, InterpContinuationStats)
	for d, n := range c.continued {
		want[InterpContinuedDepth1+d] = n
	}
	for _, cell := range c.refused {
		want[cell]++
	}
	for i := range want {
		if afterInterp[i]-beforeInterp[i] != want[i] {
			v.dump(label)
			v.t.Fatalf("%s: interpreter stats %v -> %v, want deltas %v", label, beforeInterp, afterInterp, want)
		}
	}
	afterRates := v.counters(label, rates, cells)
	if d := afterRates[FailClosedRateGap] - beforeRates[FailClosedRateGap]; d != uint64(len(c.refused)) {
		v.t.Fatalf("%s: GAP moved by %d, want %d", label, d, len(c.refused))
	}
	if cells > FailClosedRateAdmission && afterRates[FailClosedRateAdmission] != beforeRates[FailClosedRateAdmission] {
		v.t.Fatalf("%s: ADMISSION moved %d -> %d (the interpreter pass re-claims the original route)", label, beforeRates[FailClosedRateAdmission], afterRates[FailClosedRateAdmission])
	}
	if afterRates[FailClosedRatePending] != beforeRates[FailClosedRatePending] {
		v.t.Fatalf("%s: PENDING moved %d -> %d (an interpreter pass is never a pending receipt)", label, beforeRates[FailClosedRatePending], afterRates[FailClosedRatePending])
	}
	// Exact TASK refunds, so the next case starts from the parent alone.
	for _, r := range refunds {
		v.reap("task", r.slot, r.cookie)
	}
	v.t.Logf("%s: pid %d exit %d errno %d, %d evaluations, %d WORKs, refunds %v", label, pid, exit, errno, c.passes, works, refunds)
	v.parentQualified(label)
}

// interpBinfmt registers one binfmt_misc entry (extension igp/igf/igo,
// flags "", F or O) whose interpreter is files.hold, and returns its
// unregister.
func (v *opaqueVerdictRun) interpBinfmt(files opaqueInterpFiles, name, ext, flags string) func() {
	v.t.Helper()
	const root = "/proc/sys/fs/binfmt_misc"
	if _, err := os.Stat(filepath.Join(root, "register")); err != nil {
		if err := unix.Mount("binfmt_misc", root, "binfmt_misc", 0, ""); err != nil {
			v.t.Fatalf("binfmt_misc: %v", err)
		}
	}
	entry := fmt.Sprintf(":%s:E::%s::%s:%s", name, ext, files.hold, flags)
	if err := os.WriteFile(filepath.Join(root, "register"), []byte(entry), 0o200); err != nil {
		v.t.Fatalf("binfmt_misc register %q: %v", entry, err)
	}
	return func() {
		if err := os.WriteFile(filepath.Join(root, name), []byte("-1"), 0o200); err != nil {
			v.t.Errorf("binfmt_misc unregister %s: %v", name, err)
		}
	}
}

func interpKernel618(v *opaqueVerdictRun) bool {
	// D3: on a probed kernel the behaviour follows the feature, not the
	// release: AT_EXECVE_CHECK exists iff linux_binprm has is_check.
	if sharedProbedKernelOverride() {
		kernel, err := btf.LoadKernelSpec()
		if err != nil {
			v.t.Fatal(err)
		}
		_, err = btfMemberOffsetAny(kernel, "linux_binprm", "is_check")
		return err == nil
	}
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		v.t.Fatal(err)
	}
	return strings.HasPrefix(unix.ByteSliceToString(u.Release[:]), "6.18")
}

// interpMatrix runs every interpreter continuation case under the run's
// class (Strict or Audit) and fallback.
func (v *opaqueVerdictRun) interpMatrix(files opaqueInterpFiles, migrate bool, migration opaqueMigration, republish bool) {
	v.t.Helper()
	strictDeny := v.class == 2 && v.fallback == 2
	one := [5]uint64{1}
	// Allowed script and allowed interpreter: two evaluations of one exec.
	v.interpCase(opaqueInterpCase{label: "allowed script", command: "XS:s0\n", passes: 2, continued: one, works: 2, execs: 1})
	// A non-leader thread execs the script (de_thread): the same exec.
	v.interpCase(opaqueInterpCase{label: "non-leader thread", command: "XT:s0\n", passes: 2, continued: one, tasks: 2, works: 3, execs: 1})
	// Nested #! depth 1..5: depth d continues d passes; depth 6 is -ELOOP
	// after six evaluated passes (the failure terminal settles at 18).
	for d := 1; d <= 5; d++ {
		var c [5]uint64
		for i := 0; i < d; i++ {
			c[i] = 1
		}
		v.interpCase(opaqueInterpCase{
			label: fmt.Sprintf("nested depth %d", d), command: fmt.Sprintf("XS:n%d\n", d-1),
			passes: uint64(d + 1), continued: c, works: 2, execs: 1,
		})
	}
	v.interpCase(opaqueInterpCase{
		label: "ELOOP at depth 6", command: "XS:n5\n", passes: 6, continued: [5]uint64{1, 1, 1, 1, 1},
		wantExit: 76, errno: unix.ELOOP, works: 2, execs: 1,
	})
	// A missing interpreter: only the script pass ran; FAILURE settles.
	v.interpCase(opaqueInterpCase{
		label: "missing interpreter", command: "XS:miss\n", passes: 1,
		wantExit: 76, errno: unix.ENOENT, works: 2, execs: 1,
	})
	// ENOEXEC, then the libc /bin/sh fallback: two separate execs.
	v.interpCase(opaqueInterpCase{
		label: "ENOEXEC then sh", command: "XE:plain\n", passes: 2,
		wantExit: 3, errno: unix.ENOEXEC, works: 3, execs: 2,
	})
	// AT_EXECVE_CHECK runs no bprm_check (6.18): never evaluated, no
	// receipt (documented residual). 6.12 refuses the flag (EINVAL).
	checkErrno := unix.EINVAL
	if interpKernel618(v) {
		checkErrno = 0
	}
	v.interpCase(opaqueInterpCase{label: "AT_EXECVE_CHECK", command: "XC:s0\n", wantExit: 75, errno: checkErrno, works: 1})
	// binfmt_misc: plain, F (interpreter opened at registration) and O
	// (binary passed open): the interpreter pass is continued like #!.
	for _, b := range []struct{ name, ext, flags string }{
		{"igtestp", "igp", ""}, {"igtestf", "igf", "F"}, {"igtesto", "igo", "O"},
	} {
		unregister := v.interpBinfmt(files, b.name, b.ext, b.flags)
		v.interpCase(opaqueInterpCase{
			label: "binfmt_misc " + b.name, command: "XS:x." + b.ext + "\n",
			passes: 2, continued: one, works: 2, execs: 1,
		})
		unregister()
	}
	// SIGKILL between the passes (interpreter open held by fanotify): the
	// exec fails, the failure terminal settles the pass-0 WORK, no leak.
	v.interpCase(opaqueInterpCase{
		label: "SIGKILL between passes", command: "XH:s0:k\n", passes: 1, killed: true,
		works: 2, execs: 1,
	})
	// Migration between the passes: the interpreter pass keeps the
	// capsule's ORIGINAL route and class (never the destination's).
	if migrate {
		v.interpCase(opaqueInterpCase{
			label: "migration between passes", command: "XH:s0:w\n", passes: 2, continued: one,
			works: 2, execs: 1, held: true,
			onHeld: func(pid int) {
				procs := filepath.Join(migration.path, "cgroup.procs")
				if err := os.WriteFile(procs, []byte(strconv.Itoa(pid)), 0o200); err != nil {
					v.t.Fatalf("migrate held child %d: %v", pid, err)
				}
			},
		})
	}
	// Denied script (uid 1000 under the deny fallback): Strict refuses the
	// script pass, the interpreter is never evaluated. Audit records the
	// deny and continues: the interpreter pass is evaluated too.
	if strictDeny {
		v.interpCase(opaqueInterpCase{
			label: "denied script", command: "XS:s0:1000\n", passes: 1,
			wantExit: 76, errno: unix.EPERM, works: 2, execs: 1,
		})
	} else {
		v.interpCase(opaqueInterpCase{
			label: "uid 1000 script", command: "XS:s0:1000\n", passes: 2, continued: one,
			works: 2, execs: 1,
		})
	}
	// Republish (RELOAD=1: the test-only generation advance through the
	// product commit preflight) while the interpreter open is held: the
	// held exec's reader and capsule pin keep the original route busy, so
	// the advance is refused (never a relabel mid-exec) and the interpreter
	// pass is continued on the original generation; the advance publishes
	// once the exec settled, and the next script runs under it.
	if republish {
		v.interpSub("republish", func() { v.interpRepublish(one) })
	}
	// The parent's next fork still works (TASK QUALIFIED, no quarantine).
	v.interpSub("fork after matrix", func() { v.child("fork after interpreter matrix", "FORK\n", 0, true) })
	v.interpSub("leaks", func() { v.leaks("interpreter matrix") })
}

// interpRepublish: see the republish comment in interpMatrix.
func (v *opaqueVerdictRun) interpRepublish(one [5]uint64) {
	{
		before := v.binding()
		var heldCode int32
		v.interpCaseRun(opaqueInterpCase{
			label: "republish between passes", command: "XH:s0:w\n", passes: 2, continued: one,
			works: 2, execs: 1, held: true,
			onHeld: func(int) {
				code, err := v.advanceStep(0)
				if err != nil {
					v.t.Fatalf("republish while held: %v", err)
				}
				heldCode = code
			},
		})
		if heldCode != 1 || v.binding().generation != before.generation {
			v.t.Fatalf("republish while held: advance code %d (want 1, busy) binding %+v -> %+v", heldCode, before, v.binding())
		}
		code, err := v.advanceStep(0)
		if err != nil || code != 0 || v.binding().generation != before.generation+1 {
			v.t.Fatalf("republish after the exec: code=%d err=%v binding %+v -> %+v", code, err, before, v.binding())
		}
		v.interpCaseRun(opaqueInterpCase{label: "script after republish", command: "XS:s0\n", passes: 2, continued: one, works: 2, execs: 1})
	}
}

// interpGraphMiss: with the continuation graph empty, the script's
// interpreter pass is refused (GAP, reason graph miss): Strict denies the
// exec, Audit lets it run unevaluated. The pass-0 WORK is consumed by the
// refusal's cleanup and its receipt retired, so no terminal completes into
// it; the parent itself is untouched.
func (v *opaqueVerdictRun) interpGraphMiss() {
	v.t.Helper()
	c := opaqueInterpCase{
		label: "graph miss", command: "XS:s0\n", passes: 1,
		refused: []int{InterpRefusedGraphMiss}, works: 2, quarantined: true,
	}
	if v.class == 2 {
		c.wantExit, c.errno = 76, unix.EPERM
	}
	v.interpCase(c)
	v.interpSub("fork after graph miss", func() { v.child("fork after graph miss", "FORK\n", 0, true) })
	v.interpSub("leaks", func() { v.leaks("interpreter graph miss") })
}

// interpStaleResume: the injector forces one continuation's WORK resume to
// a mismatched stage class (a STALE replay). The pass is refused: GAP and
// the RESUME reason cell move by one; Strict denies the exec, Audit allows
// it unevaluated; the refusal's cleanup consumes the pass-0 WORK at its
// terminal stage and aborts the reader quarantined (evaluation WORK witness
// [3]), so no terminal completes into it.
func (v *opaqueVerdictRun) interpStaleResume() {
	v.t.Helper()
	arm := v.c.Maps["opaque_real_interp_stale_resume"]
	if arm == nil {
		v.t.Fatal("IG_OPAQUE_REAL_VERDICT_INTERP_STALE_RESUME needs ENFORCE_EXEC_POOL_OPAQUE_INTERP_STALE_RESUME_DIAGNOSTIC")
	}
	witness := v.c.Maps["opaque_real_eval_work_outcomes"]
	before := v.counters("stale resume", witness, 5)
	if err := arm.Update(uint32(0), uint64(1), 0); err != nil {
		v.t.Fatal(err)
	}
	c := opaqueInterpCase{
		label: "stale resume", command: "XS:s0\n", passes: 1,
		refused: []int{InterpRefusedResume}, works: 2, quarantined: true,
	}
	if v.class == 2 {
		c.wantExit, c.errno = 76, unix.EPERM
	}
	v.interpCase(c)
	var left uint64
	if err := arm.Lookup(uint32(0), &left); err != nil || left != 0 {
		v.t.Fatalf("stale resume injector not consumed: %d err=%v", left, err)
	}
	if witness != nil {
		after := v.counters("stale resume", witness, 5)
		if after[3]-before[3] != 1 || after[4] != before[4] {
			v.t.Fatalf("stale resume: abort-quarantine witness %v -> %v, want [3] +1 and [4] unchanged", before, after)
		}
	}
	// The next script (injector disarmed) is continued normally.
	v.interpCase(opaqueInterpCase{label: "after stale resume", command: "XS:s0\n", passes: 2, continued: [5]uint64{1}, works: 2, execs: 1})
	v.interpSub("fork after stale resume", func() { v.child("fork after stale resume", "FORK\n", 0, true) })
	v.interpSub("leaks", func() { v.leaks("interpreter stale resume") })
}
