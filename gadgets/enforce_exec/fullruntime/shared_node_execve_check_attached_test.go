// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// TestSharedNodeExecveCheckAttached (G020 carryover D, user decision D4:
// AT_EXECVE_CHECK is a documented residual). execveat(AT_EXECVE_CHECK) runs
// security_bprm_creds_for_exec and returns before exec_binprm, so it never
// reaches bprm_check_security: the product does not evaluate it. On a
// Strict binding whose policy denies path P:
//   - 6.18: execveat(P, AT_EXECVE_CHECK) returns what the kernel says (0
//     for an executable file) with no event for P and no counter beyond the
//     helper's own exec (the attempts delta equals a calibration run of the
//     same helper without the call; every fail-closed cell unchanged);
//   - 6.12: the kernel rejects the flag (EINVAL), the same no-evaluation
//     assertions hold;
//   - both: the real exec of P is evaluated and denied (EPERM: bash 126)
//     with exactly one decision event (deny, Strict, rule "check").
//
// Environment (isolated exact-kernel VM, root): IG_SHARED_VERDICT_OBJECT (an
// emitter object, g19pkgevf128), IG_SHARED_VERDICT_CGROUP_ROOT (a dedicated
// ig15-g020-events* cgroup), IG_SHARED_EXECVE_CHECK_HELPER (the static
// testdata/shared_execve_check.c build), IG_SHARED_M4_HANDLER_SYMBOL as M4.
func TestSharedNodeExecveCheckAttached(t *testing.T) {
	object, helper := os.Getenv("IG_SHARED_VERDICT_OBJECT"), os.Getenv("IG_SHARED_EXECVE_CHECK_HELPER")
	if object == "" || helper == "" {
		t.Skip("set IG_SHARED_VERDICT_OBJECT and IG_SHARED_EXECVE_CHECK_HELPER on an isolated exact-kernel VM")
	}
	root := os.Getenv("IG_SHARED_VERDICT_CGROUP_ROOT")
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(root), "ig15-g020-events") {
		t.Fatal("root and a dedicated ig15-g020-events* cgroup root required")
	}
	if err := checkSharedInitNamespaces(); err != nil {
		t.Fatalf("design 13.8: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		t.Fatal(err)
	}
	release := unix.ByteSliceToString(uts.Release[:])
	wantCheck := 0 // 6.18: an executable regular file passes the check
	switch {
	case strings.HasPrefix(release, "6.12."):
		wantCheck = int(unix.EINVAL)
	case strings.HasPrefix(release, "6.18."):
	default:
		t.Fatalf("kernel %s: want AL2023 6.12 or 6.18", release)
	}
	files := newSharedFactFiles(t)
	c := &sharedVerdictCollector{}
	node, gc, ctx := startSharedVerdictNode(t, object, c)
	defer func() { _ = node.StopNode(context.WithoutCancel(ctx)) }()
	cgroup := filepath.Join(root, "check")
	if err := os.MkdirAll(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(cgroup) })
	init := startSharedPipeInitShell(t, cgroup, "ig15-g020-events-init-check", "/usr/bin/bash")
	t.Cleanup(init.stop)
	s, err := node.Bind(ctx, SharedBindingConfig{CgroupID: init.ino, InitHostPID: uint32(init.cmd.Process.Pid), Acquire: init.acquire})
	if err != nil {
		t.Fatal(err)
	}
	deny := fullpolicy.Rule{Name: "check", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{files.interp}}}
	policy := &fullpolicy.Policy{ID: "g020-check", Revision: "1", Mode: fullpolicy.Enforce, RootRole: "app", Default: fullpolicy.Allow, Rules: []fullpolicy.Rule{deny}}
	if _, err := s.Publish(ctx, SharedBindingPolicy{Source: policy, Container: "check"}); err != nil {
		t.Fatalf("publish: %v", err)
	}
	rc := func(label, command string) int {
		t.Helper()
		out, code, err := init.run(ctx, command+"; echo rc=$?")
		i := strings.LastIndex(out, "rc=")
		if err != nil || code != 0 || i < 0 {
			t.Fatalf("%s: %q code %d: %v", label, out, code, err)
		}
		n, err := strconv.Atoi(strings.TrimSpace(out[i+3:]))
		if err != nil {
			t.Fatalf("%s: status %q", label, out)
		}
		return n
	}
	// events returns, after a grace period, the binding's events since from
	// by path.
	events := func(from int) map[string][]sharedVerdictEvent {
		time.Sleep(500 * time.Millisecond)
		out := map[string][]sharedVerdictEvent{}
		for _, e := range c.since(from, init.ino) {
			out[e.path] = append(out[e.path], e)
		}
		return out
	}
	// run runs command and returns its status, its events and its witness
	// deltas (fail-closed cells, attempts).
	run := func(label, command string) (int, map[string][]sharedVerdictEvent, [FailClosedRateCounters]uint64, [FailClosedRateAttempts]uint64) {
		t.Helper()
		from, before := c.count(), sharedM4ReadWitness(t, gc)
		status := rc(label, command)
		got := events(from)
		after := sharedM4ReadWitness(t, gc)
		var rates [FailClosedRateCounters]uint64
		var attempts [FailClosedRateAttempts]uint64
		for i := range rates {
			rates[i] = after.rates[i] - before.rates[i]
		}
		for i := range attempts {
			attempts[i] = after.attempts[i] - before.attempts[i]
		}
		return status, got, rates, attempts
	}
	// Calibration: the helper without a path (exit 2, no execveat).
	calStatus, calEvents, calRates, calAttempts := run("calibration", helper)
	if calStatus != 2 || len(calEvents[helper]) != 1 || calEvents[helper][0].deny != 0 || calRates != [FailClosedRateCounters]uint64{} {
		t.Fatalf("calibration: status %d events %+v rates %v, want 2, one allow event for the helper, no fault", calStatus, calEvents, calRates)
	}
	// The check of the denied path: never evaluated.
	status, got, rates, attempts := run("AT_EXECVE_CHECK", helper+" "+files.interp)
	if status != wantCheck {
		t.Fatalf("%s: execveat(%s, AT_EXECVE_CHECK) = %d, want %d", release, files.interp, status, wantCheck)
	}
	if len(got[files.interp]) != 0 || len(got[helper]) != 1 || got[helper][0].deny != 0 || len(got) != len(calEvents) {
		t.Fatalf("%s AT_EXECVE_CHECK: events %+v, want none for %s and only the helper's own (as calibration %+v)", release, got, files.interp, calEvents)
	}
	if rates != [FailClosedRateCounters]uint64{} || attempts != calAttempts {
		t.Fatalf("%s AT_EXECVE_CHECK: fail-closed deltas %v attempts +%v, want none and the calibration's +%v", release, rates, attempts, calAttempts)
	}
	checkEvents := len(got[files.interp])
	// The real exec of the same file: evaluated and denied, one event.
	status, got, rates, _ = run("exec", files.interp)
	if status != 126 {
		t.Fatalf("exec %s: rc %d, want 126 (EPERM)", files.interp, status)
	}
	ev := got[files.interp]
	if len(ev) != 1 || ev[0].deny != 1 || ev[0].mode != 2 || ev[0].execClass != 2 || ev[0].errorCode != 0 || rates != [FailClosedRateCounters]uint64{} {
		t.Fatalf("exec %s: events %+v rates %v, want exactly one Strict deny decision, no fault", files.interp, ev, rates)
	}
	if bits := ev[0].rules(); len(bits) != 1 || bits[0] != 0 {
		t.Fatalf("exec %s: matched rules %v, want [0] (check)", files.interp, bits)
	}
	t.Logf("EXECVECHECK kernel=%s check-status=%d check-events=%d cal-attempts=%v check-attempts=%v exec-status=%d exec-event=%+v",
		release, wantCheck, checkEvents, calAttempts, attempts, status, ev[0])
}
