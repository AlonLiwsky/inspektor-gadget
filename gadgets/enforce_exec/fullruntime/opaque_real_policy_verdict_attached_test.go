// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Verdict-class graphs installed by the loader (one static class each).
var opaqueVerdictGraphs = map[string]string{
	"opaque_real_policy_audit":   "opaque_real_owner_policy_audit",
	"opaque_real_policy_strict":  "opaque_real_owner_policy_strict",
	"opaque_real_prepare_audit":  "opaque_real_owner_prepare_audit",
	"opaque_real_prepare_strict": "opaque_real_owner_prepare_strict",
	"opaque_real_stage_audit":    "opaque_real_owner_stage_audit",
	"opaque_real_stage_strict":   "opaque_real_owner_stage_strict",
	"opaque_real_rule_audit":     "opaque_real_owner_rule_audit",
	"opaque_real_rule_strict":    "opaque_real_owner_rule_strict",
	"opaque_real_finish_audit":   "opaque_real_owner_finish_audit",
	"opaque_real_finish_strict":  "opaque_real_owner_finish_strict",
}

// G019 gap 4 (review H1): the interpreter continuation entries, present
// only in objects built with
// ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE (every product
// object). Installed when present; required by the script re-check.
var opaqueVerdictInterpGraphs = map[string]string{
	"opaque_real_continue_audit":  "opaque_real_owner_continue_audit",
	"opaque_real_continue_strict": "opaque_real_owner_continue_strict",
}

// The capsule's death retire (lsm/task_free) is attached with the task_free
// programs, before every other capsule hook, and detached after them.
const opaqueVerdictCapsuleFree = "real_owner_capsule_free"

// Capsule hooks in the mandatory attach order (terminal first).
var opaqueVerdictCapsuleOrder = []string{
	"real_owner_capsule_terminal",
	"real_owner_capsule_entry",
	"real_owner_capsule_begin",
}

// TestOpaqueRealPolicyVerdictAttached is a disposable, isolated exact-kernel
// diagnostic for the real-policy verdict build with source-capsule admission.
// It seeds synthetic test authority (never product admission) and checks:
// Strict allow when the effective-UID-0 rule matches, policy-caused and
// recoverable EPERM for euid 1000 under a Strict deny fallback, a nonblocking
// Audit known deny, preserved prior LSM denial, and that the qualified parent
// is never quarantined. It is not product enforcement or Ready.
func TestOpaqueRealPolicyVerdictAttached(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_REAL_VERDICT_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_REAL_VERDICT_OBJECT on an isolated exact-kernel VM")
	}
	cgroup := os.Getenv("IG_OPAQUE_REAL_LIVE_BOOTSTRAP_CGROUP")
	helper := os.Getenv("IG_OPAQUE_REAL_LIVE_BOOTSTRAP_HELPER")
	class, err := strconv.Atoi(os.Getenv("IG_OPAQUE_REAL_VERDICT_CLASS"))
	if err != nil || class < 1 || class > 2 {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_CLASS must be 1 (Audit) or 2 (Strict)")
	}
	fallback, err := strconv.Atoi(os.Getenv("IG_OPAQUE_REAL_VERDICT_FALLBACK"))
	if err != nil || fallback < 0 || fallback > 2 {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_FALLBACK must be 0, 1 or 2")
	}
	rules := 1
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_RULES"); raw != "" {
		if rules, err = strconv.Atoi(raw); err != nil || rules < 1 || rules > 256 {
			t.Fatalf("invalid rule count %q", raw)
		}
	}
	setRole := 0
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_SET_ROLE"); raw != "" {
		if setRole, err = strconv.Atoi(raw); err != nil || setRole < 0 || setRole > 7 {
			t.Fatalf("invalid set role %q", raw)
		}
	}
	births := 0
	if raw := os.Getenv("IG_OPAQUE_REAL_LIVE_CHURN"); raw != "" {
		if births, err = strconv.Atoi(raw); err != nil || births < 0 || births > 8192 {
			t.Fatalf("invalid churn %q", raw)
		}
	}
	// Thread churn: pthread births in the qualified parent, in batches that
	// fit the WORK quota, reaped between batches.
	threadChurn := 0
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_THREAD_CHURN"); raw != "" {
		if threadChurn, err = strconv.Atoi(raw); err != nil || threadChurn < 1 || threadChurn > 65536 {
			t.Fatalf("invalid thread churn %q", raw)
		}
	}
	// Failed birth: pids.max refuses a fork in cgroup_can_fork, after
	// security_task_alloc already charged the child.
	failedBirth := os.Getenv("IG_OPAQUE_REAL_VERDICT_FAILED_BIRTH") == "1"
	// Decoupled reclamation: racing births while an independent reaper
	// goroutine returns DONE WORK and DEAD TASK credits.
	concurrent := 0
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_CONCURRENT"); raw != "" {
		if concurrent, err = strconv.Atoi(raw); err != nil || concurrent < 1 || concurrent > 65536 {
			t.Fatalf("invalid concurrent births %q", raw)
		}
	}
	// Concurrent-mode faults (G025). ABORT_EVERY=N makes every Nth child
	// constructor take the exact semantic abort (object built with
	// ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC). EXHAUST=1 drops
	// the WORK backpressure so CONCURRENT_STREAMS racing children (1-8)
	// can exhaust evaluation WORK, which must fail closed.
	concurrentOpts := opaqueConcurrentOptions{streams: 3}
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_ABORT_EVERY"); raw != "" {
		if concurrentOpts.abortEvery, err = strconv.Atoi(raw); err != nil || concurrentOpts.abortEvery < 0 || concurrentOpts.abortEvery > 1<<20 {
			t.Fatalf("invalid abort selector %q", raw)
		}
	}
	concurrentOpts.exhaust = os.Getenv("IG_OPAQUE_REAL_VERDICT_EXHAUST") == "1"
	// INTERP_BURST=1 (G019 gap 4): every BURST child execs a #! script
	// (two evaluations of one exec); needs the interpreter continuation.
	interpBurst := os.Getenv("IG_OPAQUE_REAL_VERDICT_INTERP_BURST") == "1"
	if interpBurst {
		concurrentOpts.passes = 2
	}
	// INTERP=1 (G019 gap 4, review H1): the interpreter continuation
	// matrix (opaque_real_policy_verdict_interp_attached_test.go) after
	// the parent's own exec, then the run ends.
	interpMatrix := os.Getenv("IG_OPAQUE_REAL_VERDICT_INTERP") == "1"
	// INTERP_GRAPH_MISS=1 (with INTERP): the continuation graph is left
	// empty (frozen), so every interpreter pass is a counted GAP refusal.
	interpGraphMiss := os.Getenv("IG_OPAQUE_REAL_VERDICT_INTERP_GRAPH_MISS") == "1"
	// INTERP_STALE_RESUME=1 (with INTERP): an object built with
	// ENFORCE_EXEC_POOL_OPAQUE_INTERP_STALE_RESUME_DIAGNOSTIC forces one
	// continuation's WORK resume to a mismatched stage class.
	interpStale := os.Getenv("IG_OPAQUE_REAL_VERDICT_INTERP_STALE_RESUME") == "1"
	if interpStale && !interpMatrix {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_INTERP_STALE_RESUME needs IG_OPAQUE_REAL_VERDICT_INTERP")
	}
	if interpGraphMiss && !interpMatrix {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_INTERP_GRAPH_MISS needs IG_OPAQUE_REAL_VERDICT_INTERP")
	}
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_CONCURRENT_STREAMS"); raw != "" {
		if concurrentOpts.streams, err = strconv.Atoi(raw); err != nil || concurrentOpts.streams < 1 || concurrentOpts.streams > 32 {
			t.Fatalf("invalid concurrent streams %q (1-32)", raw)
		}
	}
	// EXPECT_REFUSALS=1 (G019 option C, with BURST): the run is designed to
	// overflow the WORK quota (streams far above the burst capacity), so it
	// must count at least one refusal; an over-capacity run that refused
	// nothing proved nothing about the counted-refusal path.
	concurrentOpts.expectRefusals = os.Getenv("IG_OPAQUE_REAL_VERDICT_EXPECT_REFUSALS") == "1"
	// CONCURRENT_FAILED_BIRTHS=N: N rounds add one fork that fails in
	// cgroup_can_fork (pids.max) after security_task_alloc, while that
	// round's children are still unreaped. SMALL_STORAGE=1: the object was
	// built with SE_TEST_DEFERRED_STORAGE_ENTRIES (receipt/frame HASHes
	// shrunk). TERMINAL_CONTENDER=1: a late TC completion contender races the
	// real terminals of live verdict children.
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_CONCURRENT_FAILED_BIRTHS"); raw != "" {
		if concurrentOpts.failedBirths, err = strconv.Atoi(raw); err != nil || concurrentOpts.failedBirths < 0 || concurrentOpts.failedBirths > 8192 {
			t.Fatalf("invalid concurrent failed births %q", raw)
		}
	}
	// SMALL_STORAGE=terminal (G025 step 4b): the object shrinks only the
	// terminal receipts (SE_TEST_TERMINAL_RECEIPT_ENTRIES) while birth
	// receipts and failure frames stay full size, so the terminal receipt
	// insert refusal must be reached.
	switch raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_SMALL_STORAGE"); raw {
	case "", "0":
	case "1":
		concurrentOpts.smallStorage = true
	case "terminal":
		concurrentOpts.smallStorage, concurrentOpts.terminalStorage = true, true
	default:
		t.Fatalf("invalid small storage mode %q (1 or terminal)", raw)
	}
	concurrentOpts.contender = os.Getenv("IG_OPAQUE_REAL_VERDICT_TERMINAL_CONTENDER") == "1"
	// REAPER_TICK=<duration> (G025 batch D): the test reaper's period, so
	// the refusal rate can be measured against reaper latency.
	concurrentOpts.reaperTick = 2 * time.Millisecond
	reaperTick := os.Getenv("IG_OPAQUE_REAL_VERDICT_REAPER_TICK")
	if reaperTick != "" {
		if concurrentOpts.reaperTick, err = time.ParseDuration(reaperTick); err != nil ||
			concurrentOpts.reaperTick < 100*time.Microsecond || concurrentOpts.reaperTick > time.Second {
			t.Fatalf("invalid reaper tick %q (100us-1s)", reaperTick)
		}
	}
	// BIRTH_RATE=<births/sec> (G025 batch E): births paced open loop on a
	// fixed per-birth schedule (helper FORKP) with at most CONCURRENT_STREAMS
	// live children. Pacing never waits on account state, so it implies
	// EXHAUST semantics (no WORK backpressure).
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_BIRTH_RATE"); raw != "" {
		if concurrentOpts.birthRate, err = strconv.Atoi(raw); err != nil || concurrentOpts.birthRate < 1 || concurrentOpts.birthRate > 100000 {
			t.Fatalf("invalid birth rate %q (1-100000 births/sec)", raw)
		}
		if threadChurn > 0 || concurrentOpts.failedBirths > 0 {
			t.Fatal("IG_OPAQUE_REAL_VERDICT_BIRTH_RATE is exclusive with _THREAD_CHURN and _CONCURRENT_FAILED_BIRTHS")
		}
		concurrentOpts.exhaust = true
	}
	// REQUIRE_NO_REUSE_FAILURES=1 (G025 batch F): with the final-free
	// directory withdrawal, no constructor may lose to a DEAD predecessor
	// at its task address: birth outcomes STALE and CONTENDED and every
	// replacement-failure site must stay 0 (the paced sweep enforces it).
	concurrentOpts.requireNoReuseFailures = os.Getenv("IG_OPAQUE_REAL_VERDICT_REQUIRE_NO_REUSE_FAILURES") == "1"
	// REQUIRE_ZERO_FAIL_CLOSED=1 (G025 steady-state gate): the run must
	// leave the fail-closed rate witness unmoved in every class and every
	// forked child evaluated: 0 Strict fail-closed refusals, 0 Audit
	// unevaluated children. A missing witness is unknown, never zero.
	concurrentOpts.requireZeroFailClosed = os.Getenv("IG_OPAQUE_REAL_VERDICT_REQUIRE_ZERO_FAIL_CLOSED") == "1"
	// PRODUCT_REAPER=1 (G019 M1): the product Reaper replaces the polling
	// test reaper (object built with
	// ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE). BURST=1 (G019 burst
	// gate, "gate at capacity"): CONCURRENT births back to back, no WORK
	// backpressure, the product reaper and REQUIRE_ZERO_FAIL_CLOSED. Up to
	// the burst capacity (CONCURRENT_STREAMS <= ConcurrentBirthCapacity of
	// the object's WORK quota: 15 at the product's 128/32, 7 at a 128/16
	// twin; the product must zero-gate 8 streams, user decision) the zero
	// gate applies: 0
	// fail-closed refusals and 0 unevaluated children. Above it the run is a
	// measured over-capacity run (burstOverCapacityGate): every refusal
	// exactly counted in its witness class, Degraded on any, full drain.
	concurrentOpts.productReaper = os.Getenv("IG_OPAQUE_REAL_VERDICT_PRODUCT_REAPER") == "1"
	if concurrentOpts.streams > 8 && os.Getenv("IG_OPAQUE_REAL_VERDICT_BURST") != "1" {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_CONCURRENT_STREAMS above 8 needs IG_OPAQUE_REAL_VERDICT_BURST (the helper's paced and injector modes stay at 8)")
	}
	if concurrentOpts.expectRefusals && os.Getenv("IG_OPAQUE_REAL_VERDICT_BURST") != "1" {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_EXPECT_REFUSALS needs IG_OPAQUE_REAL_VERDICT_BURST")
	}
	if os.Getenv("IG_OPAQUE_REAL_VERDICT_BURST") == "1" {
		if concurrentOpts.birthRate > 0 || reaperTick != "" {
			t.Fatal("IG_OPAQUE_REAL_VERDICT_BURST is exclusive with _BIRTH_RATE and _REAPER_TICK")
		}
		concurrentOpts.burst, concurrentOpts.exhaust = true, true
		concurrentOpts.productReaper, concurrentOpts.requireZeroFailClosed = true, true
	}
	if concurrentOpts.productReaper && reaperTick != "" {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_PRODUCT_REAPER is exclusive with _REAPER_TICK")
	}
	if concurrent == 0 && (concurrentOpts.productReaper || concurrentOpts.abortEvery > 0 || concurrentOpts.exhaust ||
		concurrentOpts.failedBirths > 0 || concurrentOpts.smallStorage || concurrentOpts.contender || reaperTick != "" ||
		concurrentOpts.requireNoReuseFailures || concurrentOpts.requireZeroFailClosed) {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_ABORT_EVERY, _EXHAUST, _CONCURRENT_FAILED_BIRTHS, _SMALL_STORAGE, _TERMINAL_CONTENDER, _REAPER_TICK, _BIRTH_RATE, _REQUIRE_NO_REUSE_FAILURES, _REQUIRE_ZERO_FAIL_CLOSED, _PRODUCT_REAPER and _BURST need IG_OPAQUE_REAL_VERDICT_CONCURRENT")
	}
	// G019 fail-closed injectors (object built with
	// ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_DIAGNOSTIC), one at a
	// time: IG_OPAQUE_REAL_VERDICT_INJECT_{PENDING,OPEN_PARENT,QUALIFY}_EVERY=N
	// replaces the concurrent run by CONCURRENT racing children in which
	// every Nth pending receipt, birth parent open or first-exec
	// qualification is faulted (see failClosedInject).
	injectKind, injectEvery := "", 0
	for _, kind := range []string{"pending", "open-parent", "qualify"} {
		name := "IG_OPAQUE_REAL_VERDICT_INJECT_" + strings.ToUpper(strings.ReplaceAll(kind, "-", "_")) + "_EVERY"
		raw := os.Getenv(name)
		if raw == "" {
			continue
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 1<<20 || injectKind != "" {
			t.Fatalf("invalid or second fail-closed injector %s=%q", name, raw)
		}
		injectKind, injectEvery = kind, n
	}
	if injectKind != "" && (concurrent == 0 || concurrentOpts.productReaper || concurrentOpts.abortEvery > 0 || concurrentOpts.exhaust ||
		concurrentOpts.failedBirths > 0 || concurrentOpts.smallStorage || concurrentOpts.contender || reaperTick != "" ||
		concurrentOpts.birthRate > 0 || concurrentOpts.requireNoReuseFailures || concurrentOpts.requireZeroFailClosed) {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_INJECT_*_EVERY needs IG_OPAQUE_REAL_VERDICT_CONCURRENT and excludes every other concurrent option")
	}
	// FREE_DELAY=N (G019 credit at exit, object built with
	// ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE): the userspace
	// free-delay injector (see freeDelay). INJECT_EXIT_DIR_EVERY=K (also
	// ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_DIAGNOSTIC) refuses the
	// exit-time withdrawal of every Kth exit during it (DIR_PENDING).
	// INJECT_EXIT_MODE selects the fault (REAL_OWNER_EXIT_INJECT_*): 1 (the
	// default) before stage 1, 2 after stage 1, 3 after stage 2, 4 every Kth
	// exit settles nothing with CONTENDED (UNSETTLED), 5 with CORRUPT
	// (UNSETTLED_FAULT). An object built with SE_TEST_EXIT_TOMBSTONE_ENTRIES
	// below N per binding drives the per-binding tombstone overflow.
	// EXIT_STALE=1 (with REUSE_RACE, the injector object) plants stale
	// tombstones and checks the address's next lifetime (see exitStale and
	// exitStalePending). EXIT_GATE_DISARM=1 (with FREE_DELAY) disarms the
	// image gate between the zombies' exits and their reap: every free runs
	// with the gate off and must still consume its tombstone (the gate map
	// is left unfrozen for it).
	freeDelay, exitDirEvery, exitMode := 0, 0, 1
	exitStale := os.Getenv("IG_OPAQUE_REAL_VERDICT_EXIT_STALE") == "1"
	exitGateDisarm := os.Getenv("IG_OPAQUE_REAL_VERDICT_EXIT_GATE_DISARM") == "1"
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_FREE_DELAY"); raw != "" {
		if freeDelay, err = strconv.Atoi(raw); err != nil || freeDelay < 1 || freeDelay > 4096 {
			t.Fatalf("invalid free delay %q (1-4096 zombie children)", raw)
		}
	}
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_INJECT_EXIT_DIR_EVERY"); raw != "" {
		if exitDirEvery, err = strconv.Atoi(raw); err != nil || exitDirEvery < 1 || exitDirEvery > 1<<20 || freeDelay == 0 {
			t.Fatalf("invalid exit withdrawal injector %q (1-%d, needs IG_OPAQUE_REAL_VERDICT_FREE_DELAY)", raw, 1<<20)
		}
	}
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_INJECT_EXIT_MODE"); raw != "" {
		if exitMode, err = strconv.Atoi(raw); err != nil || exitMode < 1 || exitMode > 5 || exitDirEvery == 0 {
			t.Fatalf("invalid exit injector mode %q (1-5, needs IG_OPAQUE_REAL_VERDICT_INJECT_EXIT_DIR_EVERY)", raw)
		}
	}
	if freeDelay > 0 && (concurrent > 0 || injectKind != "") {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_FREE_DELAY is exclusive with _CONCURRENT and the _INJECT_*_EVERY injectors")
	}
	// A disarmed gate runs no task_free fallback (as before credit at
	// exit), so only exits settled at exit (no unsettled injector mode)
	// may be reaped under it.
	if exitGateDisarm && (freeDelay == 0 || (exitDirEvery > 0 && exitMode > 3)) {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_EXIT_GATE_DISARM needs IG_OPAQUE_REAL_VERDICT_FREE_DELAY and no unsettled exit injector mode (4, 5)")
	}
	if concurrentOpts.requireZeroFailClosed && (concurrentOpts.abortEvery > 0 || concurrentOpts.failedBirths > 0 ||
		concurrentOpts.smallStorage || concurrentOpts.contender) {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_REQUIRE_ZERO_FAIL_CLOSED is exclusive with the fault injectors (_ABORT_EVERY, _CONCURRENT_FAILED_BIRTHS, _SMALL_STORAGE, _TERMINAL_CONTENDER)")
	}
	// REUSE_RACE=1 (G025 batch F): deterministic physical-address reuse of
	// a DEAD predecessor whose directory withdrawal the reaper has not
	// finished, on one pinned CPU (REUSE_CPU, default 0), plus the
	// reader-hold fallback to the reaper path. The fix (the final-free
	// directory withdrawal) is in every object; the witnesses need
	// ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE and
	// ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC (witness, hold).
	// G019 M4 review M2: the parent's own verdict exec is a #! script whose
	// interpreter is the helper, on an object built with the test-only
	// ENFORCE_EXEC_POOL_OPAQUE_CAPSULE_UNCOVERED_DIAGNOSTIC (no exec
	// "matters" at entry/begin, so every exec is uncovered): the script's
	// first admission freezes uncovered with the route identity, and M2
	// turns the interpreter's re-check from a capsule fault into an
	// original-route claim (no capsule FAULT). G019 gap 4 (review H1): the
	// object also carries the interpreter continuation
	// (ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE), so the
	// re-check is the script's continued interpreter pass: evaluated for
	// the helper, allowed in both classes, no GAP or PENDING refusal, and
	// the parent stays QUALIFIED for the rest of the run (before gap 4 the
	// pending-receipt gate refused or quarantined it: flags 7).
	scriptRecheck := os.Getenv("IG_OPAQUE_REAL_VERDICT_SCRIPT_RECHECK") == "1"
	reuseRace := os.Getenv("IG_OPAQUE_REAL_VERDICT_REUSE_RACE") == "1"
	if exitStale && !reuseRace {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_EXIT_STALE needs IG_OPAQUE_REAL_VERDICT_REUSE_RACE")
	}
	reuseCPU := 0
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_REUSE_CPU"); raw != "" {
		if reuseCPU, err = strconv.Atoi(raw); err != nil || reuseCPU < 0 || reuseCPU > 1023 {
			t.Fatalf("invalid reuse CPU %q (0-1023)", raw)
		}
	}
	// MIGRATE=1 (G025 step 7): a second route of the opposite class on a
	// sibling cgroup; children move to it mid-birth, between fork and exec
	// and mid-exec. RELOAD=1|fault (step 8): test-only generation advance
	// during churn; "fault" also injects a mid-publication failure.
	migrate := os.Getenv("IG_OPAQUE_REAL_VERDICT_MIGRATE") == "1"
	reload := os.Getenv("IG_OPAQUE_REAL_VERDICT_RELOAD")
	if reload != "" && reload != "1" && reload != "fault" {
		t.Fatalf("invalid reload mode %q (1 or fault)", reload)
	}
	reloadRounds := 64
	if raw := os.Getenv("IG_OPAQUE_REAL_VERDICT_RELOAD_ROUNDS"); raw != "" {
		if reloadRounds, err = strconv.Atoi(raw); err != nil || reloadRounds < 2 || reloadRounds > 4096 {
			t.Fatalf("invalid reload rounds %q (2-4096)", raw)
		}
	}
	if (migrate || reload != "") && (concurrent > 0 || (migrate && reload != "")) {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_MIGRATE and _RELOAD are exclusive with each other and with _CONCURRENT")
	}
	// The advance maps record r to fixed object r, and the reload policy
	// differs only in its fallback, which must be a known allow or deny.
	if reload != "" && (fallback == 0 || rules+11 > 256) {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_RELOAD needs FALLBACK 1 or 2 and at most 245 rules")
	}
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(cgroup), "ig15-g005-reallive-") ||
		!filepath.IsAbs(helper) {
		t.Fatal("root, dedicated ig15-g005-reallive-* cgroup and absolute helper required")
	}
	var st unix.Stat_t
	if err := unix.Stat(cgroup, &st); err != nil || st.Ino == 0 {
		t.Fatalf("isolated cgroup: %v", err)
	}
	var migration opaqueMigration
	if migrate {
		migration = newOpaqueMigration(t, cgroup)
	}
	if failedBirth || concurrentOpts.failedBirths > 0 {
		pidsMax := filepath.Join(cgroup, "pids.max")
		original, err := os.ReadFile(pidsMax)
		if err != nil {
			t.Fatalf("failed birth needs the pids controller on %s (+pids in the parent's cgroup.subtree_control): %v", cgroup, err)
		}
		// The helper restores pids.max itself; this covers a helper that
		// died inside its failing-fork window.
		t.Cleanup(func() {
			if err := os.WriteFile(pidsMax, original, 0); err != nil {
				t.Errorf("restore %s: %v", pidsMax, err)
			}
		})
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	// G019 M4 (ii): the exec capsule and its entry marker live in task
	// local storage on the executing task, never in a loader-sized ARRAY.
	for _, name := range []string{"se_exec_capsules", "se_exec_markers"} {
		m := spec.Maps[name]
		if m == nil || m.Type != ebpf.TaskStorage || m.Flags&unix.BPF_F_NO_PREALLOC == 0 || m.MaxEntries != 0 {
			t.Fatalf("verdict object lacks the task-storage capsule map %s", name)
		}
	}
	selected := map[string]*ebpf.ProgramSpec{}
	need := []string{
		"opaque_real_live_bootstrap_control", "opaque_real_live_bootstrap_birth",
		"opaque_real_live_bootstrap_qualify", "opaque_real_owner_child_source_candidate",
		"opaque_real_owner_child_target_candidate", "opaque_real_owner_child_final_free_candidate",
		"opaque_real_owner_reader_begin_probe", "opaque_real_owner_reader_success_probe",
		"opaque_real_owner_failure_outer_enter", "opaque_real_owner_failure_handler_enter",
		"opaque_real_owner_failure_handler_exit", "opaque_real_owner_failure_outer_exit",
		"opaque_real_live_reap_work", "opaque_real_live_reap_task",
		"opaque_real_owner_policy_seed_diagnostic",
		// Failure terminal: publishes FAILURE and completes the exact WORK.
		"opaque_real_owner_failure_fexit_probe",
		// Controller completion entrypoint (load coverage; terminals now
		// complete into the evaluation WORK and are not quota-deferred).
		"opaque_real_owner_work_completion_probe",
	}
	if concurrentOpts.contender {
		need = append(need, "opaque_real_owner_terminal_race_complete")
	}
	if concurrentOpts.smallStorage {
		// Only the deferred receipt/frame HASHes are shrunk, and the
		// insert-refusal witness must be present.
		tasks := spec.Maps["se_opaque_charges"]
		if spec.Maps["opaque_real_deferred_storage_refusals"] == nil || tasks == nil {
			t.Fatal("small storage needs an object built with ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC")
		}
		for _, name := range []string{
			"se_exec_terminal_receipts", "se_failure_outer_frames",
			"se_failure_handler_frames", "opaque_birth_receipts",
		} {
			m := spec.Maps[name]
			if m == nil {
				t.Fatalf("verdict object lacks %s", name)
			}
			// Terminal-only: exactly the terminal receipts are shrunk.
			shrunk := !concurrentOpts.terminalStorage || name == "se_exec_terminal_receipts"
			if shrunk && m.MaxEntries >= tasks.MaxEntries {
				t.Fatalf("small storage needs an object built with SE_TEST_DEFERRED_STORAGE_ENTRIES or SE_TEST_TERMINAL_RECEIPT_ENTRIES < %d (%s)", tasks.MaxEntries, name)
			}
			if !shrunk && m.MaxEntries != tasks.MaxEntries {
				t.Fatalf("terminal-only small storage needs full-size %s (%d, want %d)", name, m.MaxEntries, tasks.MaxEntries)
			}
		}
	}
	if migrate {
		need = append(need, "opaque_real_live_bootstrap_second_route", "opaque_real_owner_second_policy_seed")
	}
	if reuseRace {
		for _, name := range []string{
			"opaque_real_fail_closed_rates", "opaque_real_replace_failures",
			"opaque_real_reuse_hold_request",
		} {
			if spec.Maps[name] == nil {
				t.Fatalf("reuse race needs an object built with ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE and ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC (missing %s)", name)
			}
		}
		need = append(need, "opaque_real_reuse_hold")
	}
	if reload != "" {
		need = append(need, "opaque_real_live_bootstrap_advance", "opaque_real_owner_second_policy_seed")
	}
	if concurrentOpts.productReaper || freeDelay > 0 || (reuseRace && spec.Programs["opaque_real_reap"] != nil) {
		// NewReaper runs the syscall reap command; keep it in the selection
		// (the reuse race runs it concurrently on a FREE_PENDING charge).
		need = append(need, "opaque_real_reap")
	}
	// G019 credit at exit: present only in objects built with
	// ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE.
	const exitProgram = "opaque_real_owner_child_exit_candidate"
	exitCredit := spec.Programs[exitProgram] != nil
	if exitCredit {
		need = append(need, exitProgram)
	} else if freeDelay > 0 || exitStale {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_FREE_DELAY and _EXIT_STALE need an object built with ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE")
	}
	if exitStale && spec.Maps["opaque_real_exit_inject_every"] == nil {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_EXIT_STALE needs ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_DIAGNOSTIC")
	}
	need = append(need, opaqueVerdictCapsuleFree)
	need = append(need, opaqueVerdictCapsuleOrder...)
	for _, program := range opaqueVerdictGraphs {
		need = append(need, program)
	}
	interp := spec.Programs["opaque_real_owner_continue_audit"] != nil
	if (scriptRecheck || interpMatrix || interpBurst) && !interp {
		t.Fatal("IG_OPAQUE_REAL_VERDICT_SCRIPT_RECHECK needs ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE (G019 gap 4)")
	}
	if interp {
		for _, program := range opaqueVerdictInterpGraphs {
			need = append(need, program)
		}
	}
	for _, name := range need {
		if spec.Programs[name] == nil {
			t.Fatalf("verdict object lacks %s", name)
		}
		selected[name] = spec.Programs[name]
	}
	if err := selectOpaqueNormalChurnBirthPrograms(spec, selected); err != nil {
		t.Fatal(err)
	}
	spec.Programs = selected
	kernelTypes, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}
	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20, KernelTypes: kernelTypes},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer c.Close()
	// Every link is detached in exact reverse of its attach order, like the
	// eBPF operator's native transaction (nativeattach.Rank).
	var links []link.Link
	defer func() {
		for i := len(links) - 1; i >= 0; i-- {
			_ = links[i].Close()
		}
	}()
	gate := struct {
		Cgroup, Scope           uint64
		Enabled, ExecutionClass uint32
	}{st.Ino, 10, 1, uint32(class)}
	mustUpdate := func(name string, key, value any) {
		t.Helper()
		if err := c.Maps[name].Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatalf("update %s: %v", name, err)
		}
	}
	mustFreeze := func(name string) {
		t.Helper()
		if err := c.Maps[name].Freeze(); err != nil {
			t.Fatalf("freeze %s: %v", name, err)
		}
	}
	mustUpdate("opaque_real_live_bootstrap_gate", uint32(0), gate)
	mustUpdate("opaque_real_owner_child_gate", uint32(0), uint32(1))
	// Node config must equal the compiled profile: 2x256 cells, optionally
	// one 1024-cell object (needed for more than 245 seeded rules).
	wire := sharedNodeWire{
		NodeCookie: 11, Nonce: 22, ABI: 3, ProfileVersion: 1,
		Bindings: 2, Objects: 2, Cells: 512, Slots: [4]uint32{2},
	}
	if c.Maps["se_arena"] != nil {
		if info, err := c.Maps["se_arena"].Info(); err == nil && info.MaxEntries == 1536 {
			wire.Objects, wire.Cells, wire.Slots = 3, 1536, [4]uint32{2, 1}
		}
	}
	if rules+11 > 256 && wire.Slots[1] == 0 {
		t.Fatal("more than 245 rules need an object built with SE_PROFILE_SLOTS_1024=1")
	}
	mustUpdate("se_configuration", uint32(0), wire)
	mustUpdate("opaque_real_policy_verdict_fallback", uint32(0), uint32(fallback))
	mustUpdate("opaque_real_owner_rule_uid_expect", uint32(0), uint32(0))
	mustUpdate("opaque_real_policy_verdict_rules", uint32(0), uint32(rules))
	mustUpdate("opaque_real_policy_verdict_set_role", uint32(0), uint32(setRole))
	frozen := []string{
		"se_configuration", "opaque_real_live_bootstrap_gate",
		"se_opaque_payload_zero", "se_opaque_work_zero",
		"opaque_real_policy_verdict_fallback", "opaque_real_owner_rule_uid_expect",
		"opaque_real_policy_verdict_rules", "opaque_real_policy_verdict_set_role",
	}
	if !exitGateDisarm {
		frozen = append(frozen, "opaque_real_owner_child_gate")
	}
	// Second policy (object 1): the migration route's opposite-class policy
	// (binding 1), or the reload policy of the same class whose fallback
	// is flipped (binding 0, unpinned until the generation advance).
	type secondPolicy struct{ ExecutionClass, Fallback, Binding, Enabled uint32 }
	reloadFallback := [2]int{fallback, 3 - fallback}
	if migrate {
		mustUpdate("opaque_real_live_second_route_gate", uint32(0), struct {
			Cgroup, Scope           uint64
			Enabled, ExecutionClass uint32
		}{migration.ino, 11, 1, uint32(3 - class)})
		mustUpdate("opaque_real_second_policy", uint32(0), secondPolicy{uint32(3 - class), uint32(fallback), 1, 1})
		frozen = append(frozen, "opaque_real_live_second_route_gate", "opaque_real_second_policy")
	}
	if reload != "" {
		mustUpdate("opaque_real_second_policy", uint32(0), secondPolicy{uint32(class), uint32(reloadFallback[1]), 0, 1})
		frozen = append(frozen, "opaque_real_second_policy")
	}
	for _, name := range frozen {
		mustFreeze(name)
	}
	if code, _, err := c.Programs["opaque_real_live_bootstrap_control"].Test(make([]byte, 64)); err != nil || code != 0 {
		t.Fatalf("test-only control seed: code=%d err=%v", code, err)
	}
	if migrate {
		if code, _, err := c.Programs["opaque_real_live_bootstrap_second_route"].Test(make([]byte, 64)); err != nil || code != 0 {
			t.Fatalf("test-only second route seed: code=%d err=%v", code, err)
		}
	}
	if code, _, err := c.Programs["opaque_real_owner_policy_seed_diagnostic"].Test(make([]byte, 64)); err != nil || code != 0 {
		t.Fatalf("test-only %s policy seed: code=%d err=%v", map[int]string{1: "Audit", 2: "Strict"}[class], code, err)
	}
	if migrate || reload != "" {
		if code, _, err := c.Programs["opaque_real_owner_second_policy_seed"].Test(make([]byte, 64)); err != nil || code != 0 {
			t.Fatalf("test-only second policy seed: code=%d err=%v", code, err)
		}
	}
	for graph, program := range opaqueVerdictGraphs {
		mustUpdate(graph, uint32(0), c.Programs[program])
		mustFreeze(graph)
	}
	if interp {
		for graph, program := range opaqueVerdictInterpGraphs {
			if !interpGraphMiss {
				mustUpdate(graph, uint32(0), c.Programs[program])
			}
			mustFreeze(graph)
		}
	}
	var locator uint64
	if err := c.Maps["se_route_index"].Lookup(st.Ino, &locator); err != nil || locator != uint64(1)<<32 {
		t.Fatalf("test-only route index: locator=%#x err=%v", locator, err)
	}
	if migrate {
		if err := c.Maps["se_route_index"].Lookup(migration.ino, &locator); err != nil || locator != uint64(1)<<32|1 {
			t.Fatalf("test-only second route index: locator=%#x err=%v", locator, err)
		}
	}
	attachLSM := func(name string) link.Link {
		t.Helper()
		l, err := link.AttachLSM(link.LSMOptions{Program: c.Programs[name]})
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		links = append(links, l)
		return l
	}
	// Attach order (nativeattach.Rank; detached in exact reverse): the
	// task_free programs first (the release and the capsule's death retire
	// exist before anything they release and outlive it), then the
	// credit-at-exit link, whose settlement task_free consumes, then the
	// task_alloc programs, so every charged task's death has a settlement
	// path and exit credit never runs without task_free.
	attachLSM("opaque_real_owner_child_final_free_candidate")
	attachLSM(opaqueVerdictCapsuleFree)
	if exitCredit {
		l, err := link.AttachTracing(link.TracingOptions{Program: c.Programs[exitProgram]})
		if err != nil {
			t.Fatalf("attach %s: %v", exitProgram, err)
		}
		links = append(links, l)
	}
	qualifyLink := attachLSM("opaque_real_live_bootstrap_qualify")
	birthLink := attachLSM("opaque_real_live_bootstrap_birth")
	timeout := 2 * time.Minute
	if births > 1 || threadChurn > 0 || concurrent > 0 {
		timeout = 30 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/bin/bash", "-c",
		"echo $$ > \"$1/cgroup.procs\" || exit 97; \"$2\" <&0 & child=$!; wait \"$child\"",
		"ig15-real-verdict-launcher", cgroup, helper)
	invalid := filepath.Join(t.TempDir(), "invalid-executable")
	if err := os.WriteFile(invalid, []byte("invalid executable image\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd.Env = append(os.Environ(), "IG_OPAQUE_FAIL_EXEC_PATH="+invalid, "IG_OPAQUE_PIDS_CGROUP="+cgroup)
	parentExec := "EXEC\n"
	if scriptRecheck {
		script := filepath.Join(t.TempDir(), "recheck-script")
		if err := os.WriteFile(script, []byte("#!"+helper+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		cmd.Env = append(cmd.Env, "IG_OPAQUE_SCRIPT_PATH="+script)
		parentExec = "SCRIPT\n"
	}
	var interpFiles opaqueInterpFiles
	if interpMatrix || interpBurst {
		interpFiles = newOpaqueInterpFiles(t)
		cmd.Env = append(cmd.Env, "IG_OPAQUE_INTERP_DIR="+interpFiles.dir,
			"IG_OPAQUE_INTERP_HOLD="+interpFiles.hold)
		if interpBurst {
			cmd.Env = append(cmd.Env, "IG_OPAQUE_FORK_SCRIPT="+filepath.Join(interpFiles.dir, "s0"))
		}
	}
	if migrate {
		cmd.Env = append(cmd.Env, "IG_OPAQUE_MIGRATE_CGROUP="+migration.path,
			"IG_OPAQUE_MIGRATE_SCRIPT="+migration.script, "IG_OPAQUE_MIGRATE_INTERP="+migration.interp)
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Wait()
		}
	}()
	reader := bufio.NewReader(stdout)
	if line, err := reader.ReadString('\n'); err != nil || line != "READY\n" {
		t.Fatalf("seeded parent: line=%q err=%v stderr=%q", line, err, stderr.String())
	}
	if err := birthLink.Close(); err != nil {
		t.Fatal(err)
	}
	if err := qualifyLink.Close(); err != nil {
		t.Fatal(err)
	}
	var physical, taskLocator uint64
	keys := c.Maps["se_opaque_keys"].Iterate()
	if !keys.Next(&physical, &taskLocator) || keys.Err() != nil || physical == 0 ||
		taskLocator == 0 || keys.Next(&physical, &taskLocator) {
		t.Fatalf("expected one real opaque TASK: err=%v", keys.Err())
	}
	kallsyms, err := os.Open("/proc/kallsyms")
	if err != nil {
		t.Fatal(err)
	}
	outer, err := opaqueDiagnosticExecOuterSymbol(kallsyms)
	if err == nil {
		_, err = kallsyms.Seek(0, io.SeekStart)
	}
	var handler string
	if err == nil {
		handler, err = opaqueDiagnosticExecHandlerSymbol(kallsyms, os.Getenv("IG_OPAQUE_REAL_LIVE_HANDLER_SYMBOL"))
	}
	kallsyms.Close()
	if err != nil {
		t.Fatalf("resolve diagnostic exec frames: %v", err)
	}
	attachKprobe := func(symbol, name string, ret bool) {
		t.Helper()
		var l link.Link
		var err error
		if ret {
			l, err = link.Kretprobe(symbol, c.Programs[name], nil)
		} else {
			l, err = link.Kprobe(symbol, c.Programs[name], nil)
		}
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		links = append(links, l)
	}
	attachKprobe(outer, "opaque_real_owner_failure_outer_exit", true)
	attachKprobe(handler, "opaque_real_owner_failure_handler_exit", true)
	attachKprobe(handler, "opaque_real_owner_failure_handler_enter", false)
	attachKprobe(outer, "opaque_real_owner_failure_outer_enter", false)
	// The capsule's death retire (opaqueVerdictCapsuleFree) is already
	// attached with the task_free programs, before every capsule hook.
	for _, name := range append([]string{
		"opaque_real_owner_reader_success_probe",
		"opaque_real_owner_failure_fexit_probe",
	}, opaqueVerdictCapsuleOrder...) {
		l, err := link.AttachTracing(link.TracingOptions{Program: c.Programs[name]})
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		links = append(links, l)
	}
	attachLSM("opaque_real_owner_reader_begin_probe")

	v := &opaqueVerdictRun{
		t: t, c: c, spec: spec, stdin: stdin, stdout: reader,
		stderr: &stderr, parent: physical, parentLocator: taskLocator, class: class,
		fallback: fallback, cgroup: st.Ino, rules: rules, setRole: setRole,
	}
	v.init()
	var capBefore [opaqueCapStats]uint64
	var interpBefore, ratesBefore []uint64
	if scriptRecheck {
		capBefore = v.capsuleStats()
		interpBefore = v.interpStats("script re-check before")
		ratesBefore = v.counters("script re-check rates before", c.Maps["opaque_real_fail_closed_rates"], v.rateCells("rates", c.Maps["opaque_real_fail_closed_rates"]))
	}
	if _, err := stdin.Write([]byte(parentExec)); err != nil {
		t.Fatal(err)
	}
	// G019 gap 4: the script's interpreter pass is continued and allowed
	// in both classes (before: Strict SCRIPTERR:EPERM).
	wantParentExec := "AFTER\n"
	if line, err := reader.ReadString('\n'); err != nil || line != wantParentExec {
		v.dump("parent exec")
		_ = cmd.Wait()
		t.Fatalf("parent exec under class %d: line=%q (want %q) err=%v exit=%v stderr=%q", class, line, wantParentExec, err, cmd.ProcessState, stderr.String())
	}
	if scriptRecheck {
		capAfter := v.capsuleStats()
		uncovered := capAfter[opaqueCapFrozenUncover] - capBefore[opaqueCapFrozenUncover]
		original := capAfter[opaqueCapOriginalClaim] - capBefore[opaqueCapOriginalClaim]
		faults := capAfter[opaqueCapFault] - capBefore[opaqueCapFault]
		t.Logf("script re-check: uncovered freezes %d, original-route re-claims %d, begins %d, capsule faults %d", uncovered,
			original, capAfter[opaqueCapBegin]-capBefore[opaqueCapBegin], faults)
		if uncovered < 1 || original < 1 || capAfter[opaqueCapBegin] != capBefore[opaqueCapBegin] {
			t.Fatal("script re-check: needs an uncovered freeze and an original-route re-claim (object built with ENFORCE_EXEC_POOL_OPAQUE_CAPSULE_UNCOVERED_DIAGNOSTIC)")
		}
		if faults != 0 {
			t.Fatalf("script re-check: %d capsule FAULTs, want none (M2: an original-route claim, not a capsule fault)", faults)
		}
		// G019 gap 4: two evaluations (script, then interpreter at depth
		// 1), no refusal of any reason, no GAP and no PENDING; the parent
		// stays qualified and the run continues (the next fork works).
		interpAfter := v.interpStats("script re-check after")
		ratesAfter := v.counters("script re-check rates after", c.Maps["opaque_real_fail_closed_rates"], len(ratesBefore))
		if d := interpAfter[InterpContinuedDepth1] - interpBefore[InterpContinuedDepth1]; d != 1 {
			v.dump("script re-check")
			t.Fatalf("script re-check under class %d: %d interpreter passes continued at depth 1, want 1 (stats %v)", class, d, interpAfter)
		}
		for i := InterpRefusedFrame; i < InterpContinuationStats; i++ {
			if interpAfter[i] != interpBefore[i] {
				t.Fatalf("script re-check under class %d: interpreter refusal cell %d %d -> %d", class, i, interpBefore[i], interpAfter[i])
			}
		}
		for _, i := range []int{FailClosedRateGap, FailClosedRatePending} {
			if ratesAfter[i] != ratesBefore[i] {
				t.Fatalf("script re-check under class %d: fail-closed class %d %d -> %d, want unchanged", class, i, ratesBefore[i], ratesAfter[i])
			}
		}
	}
	v.parentQualified("parent after its own verdict exec")
	// UID history: the bootstrap parent holds role 1 for policy uid 1. Its
	// allowed exec commits the matching rule's proposed role; every child
	// then carries it through birth projection.
	v.wantRole = 1
	if setRole != 0 {
		v.wantRole = uint64(setRole)
	}
	v.expectRole("parent after allowed exec", v.parent, v.parentLocator)
	v.settleRound("parent exec", 0)
	v.attachChildSource(attachLSM)
	if interpMatrix {
		if interpGraphMiss {
			v.interpGraphMiss()
			return
		}
		if interpStale {
			v.interpStaleResume()
			return
		}
		v.interpMatrix(interpFiles, migrate, migration, reload != "")
		return
	}

	strictDeny := class == 2 && fallback == 2
	v.child("euid 0 rule match", "FORK\n", 0, true)
	wantU := 0
	if strictDeny {
		wantU = 77
	}
	v.child("euid 1000 fallback", "FORKU\n", wantU, false)
	v.child("euid 0 after fallback (recoverable)", "FORK\n", 0, true)
	prior := attachOpaqueBirthPriorDenial(t, st.Ino)
	// The independent prior LSM returns -EACCES; the helper child exits 79
	// only for EACCES, so the preserved errno itself is asserted.
	v.child("prior LSM denial", "FORK\n", 79, false)
	if err := prior.Close(); err != nil {
		t.Fatal(err)
	}
	v.child("euid 0 after prior denial", "FORK\n", 0, true)
	v.child("allowed policy, failed exec (ENOEXEC)", "FORKF\n", 78, true)
	if os.Getenv("IG_OPAQUE_REAL_VERDICT_RACING") == "1" {
		// Previously RED (v4-6.12-racing-retry.log): racing births
		// exhausted the 8-credit WORK account. Birth now retries a lost
		// CONTENDED charge and the terminal completes into the evaluation
		// WORK (2 per child), so two racing children peak at 2+2*2 < 8.
		v.children("two racing births", "FORK2\n", 2, 0, true)
	}
	if reuseRace {
		v.reuseRace(reuseCPU, exitStale)
	}
	for i := 0; i < births; i++ {
		v.child(fmt.Sprintf("churn %d", i), "FORK\n", 0, true)
		if i == 0 || (i+1)%512 == 0 || i == births-1 {
			t.Logf("ordinary selected-policy churn %d/%d: reuses=%d", i+1, births, v.reuses)
		}
	}
	if births > 4096 && v.reuses == 0 {
		t.Fatal("churn beyond 4096 births did not reuse a physical task address")
	}
	if threadChurn > 0 {
		// Each thread holds one birth WORK until reaped; the parent keeps
		// its retained WORKs, so a batch must fit the remaining quota.
		batch := min(4, int(v.workQuota)-len(v.parentWorks))
		if batch < 1 {
			t.Fatalf("parent retains %d of %d WORK credits: no room for a thread batch", len(v.parentWorks), v.workQuota)
		}
		reuses := v.reuses
		for done := 0; done < threadChurn; {
			n := min(batch, threadChurn-done)
			v.threads(fmt.Sprintf("thread churn %d", done), n)
			done += n
			if done == n || (done-n)/512 != done/512 || done == threadChurn {
				t.Logf("thread churn %d/%d: reuses=%d", done, threadChurn, v.reuses-reuses)
			}
		}
		if threadChurn > 4096 && v.reuses == reuses {
			t.Fatal("thread churn beyond 4096 births did not reuse a physical task address")
		}
		t.Logf("thread churn: %d pthread births in batches of %d, each exactly 1 TASK + 1 birth WORK, no evaluation or terminal, all refunded; %d physical reuses",
			threadChurn, batch, v.reuses-reuses)
	}
	if failedBirth {
		v.failedBirth(cgroup)
		v.child("euid 0 after failed birth", "FORK\n", 0, true)
	}
	if migrate {
		v.migrate(migration)
	}
	if reload != "" {
		v.reload(reloadRounds, reload == "fault", reloadFallback)
	}
	if concurrent > 0 {
		threadsPerRound := 0
		if threadChurn > 0 {
			threadsPerRound = 2
		}
		concurrentOpts.threadsPerRound = threadsPerRound
		if injectKind != "" {
			v.failClosedInject(injectKind, injectEvery, concurrent)
		} else {
			v.concurrent(concurrent, concurrentOpts)
		}
	}
	if freeDelay > 0 {
		v.freeDelay(freeDelay, exitDirEvery, exitMode, exitGateDisarm)
	}
	v.capsuleBalanced()
	t.Logf("child terminal outcomes resumed_completed=%d resumed_failed=%d fallback_charged=%d fallback_refused=%d",
		v.outcomes[0], v.outcomes[1], v.outcomes[2], v.outcomes[3])
	if _, err := stdin.Write([]byte("DONE\n")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper exit: %v stderr=%q", err, stderr.String())
	}
	t.Logf("verdict class=%d fallback=%d rules=%d: %d children (+5 controls), %d physical reuses, WORK per outcome %v, parent never quarantined; synthetic test authority, not product Ready",
		class, fallback, rules, births, v.reuses, v.worksPerKind)
}

type opaqueVerdictRun struct {
	t                     *testing.T
	c                     *ebpf.Collection
	spec                  *ebpf.CollectionSpec
	stdin                 io.Writer
	stdout                *bufio.Reader
	stderr                *bytes.Buffer
	parent, parentLocator uint64
	class, fallback       int
	cgroup                uint64
	rules                 int
	setRole               int
	wantRole              uint64
	worksPerKind          map[string]int
	lastDeny              int
	taskType, metaType    *btf.Struct
	invocationType        *btf.Struct
	parentCookie          uint64
	parentWorks           map[uint32]uint64
	seen                  map[uint64]uint64
	reuses                int
	evals, matches        uint64
	outcomes              [4]uint64
	taskQuota, workQuota  uint32
}

type opaqueVerdictRefund struct {
	slot   uint32
	cookie uint64
}

func (v *opaqueVerdictRun) init() {
	if err := v.spec.Types.TypeByName("se_task_state", &v.taskType); err != nil {
		v.t.Fatal(err)
	}
	if err := v.spec.Types.TypeByName("se_ol_meta", &v.metaType); err != nil {
		v.t.Fatal(err)
	}
	if err := v.spec.Types.TypeByName("se_invocation", &v.invocationType); err != nil {
		v.t.Fatal(err)
	}
	// Per-account quotas (SE_PROFILE_TASK_QUOTA, SE_PROFILE_SCRATCH_QUOTA).
	for _, q := range []struct {
		charges, accounts string
		quota             *uint32
	}{
		{"se_opaque_charges", "se_opaque_accounts", &v.taskQuota},
		{"se_opaque_work_charges", "se_opaque_work_accounts", &v.workQuota},
	} {
		charges, accounts := v.spec.Maps[q.charges], v.spec.Maps[q.accounts]
		if charges == nil || accounts == nil || accounts.MaxEntries == 0 ||
			charges.MaxEntries%accounts.MaxEntries != 0 {
			v.t.Fatalf("verdict object lacks exact %s/%s geometry", q.charges, q.accounts)
		}
		*q.quota = charges.MaxEntries / accounts.MaxEntries
	}
	v.worksPerKind = map[string]int{}
	v.seen = map[uint64]uint64{}
	if err := v.c.Maps["opaque_birth_receipt_zero"].Freeze(); err != nil {
		v.t.Fatalf("freeze birth receipt zero template: %v", err)
	}
}

func (v *opaqueVerdictRun) field(root *btf.Struct, raw []byte, path ...string) uint64 {
	v.t.Helper()
	offset, size := opaqueSourceField(v.t, root, path)
	if offset+size > len(raw) {
		v.t.Fatalf("field %v outside value", path)
	}
	if size == 4 {
		return uint64(binary.LittleEndian.Uint32(raw[offset : offset+size]))
	}
	return binary.LittleEndian.Uint64(raw[offset : offset+size])
}

func (v *opaqueVerdictRun) charge(name string, slot uint32) uint64 {
	v.t.Helper()
	raw, err := v.c.Maps[name].LookupBytes(slot)
	if err != nil || len(raw) < 8 {
		v.t.Fatalf("%s slot %d: %v", name, slot, err)
	}
	return binary.LittleEndian.Uint64(raw[:8])
}

// task returns flags, cookie and whether reader/exec/receipt are settled.
func (v *opaqueVerdictRun) task(physical, locator uint64) (flags, cookie uint64, settled bool) {
	v.t.Helper()
	slot := uint32(locator & ((1 << 14) - 1))
	raw, err := v.c.Maps["se_opaque_payload"].LookupBytes(slot)
	if err != nil {
		v.t.Fatal(err)
	}
	settled = v.field(v.taskType, raw, "reader", "owned") == 0 &&
		v.field(v.taskType, raw, "exec", "owned") == 0
	var receipt [64]byte
	if err := v.c.Maps["se_exec_terminal_receipts"].Lookup(physical, &receipt); !errors.Is(err, ebpf.ErrKeyNotExist) {
		settled = false
	}
	return v.field(v.taskType, raw, "flags"), v.field(v.taskType, raw, "physical_cookie"), settled
}

func (v *opaqueVerdictRun) parentQualified(label string) {
	v.t.Helper()
	flags, cookie, settled := v.task(v.parent, v.parentLocator)
	if flags != 5 || !settled || cookie == 0 {
		v.t.Fatalf("%s: parent flags=%d settled=%v cookie=%d (5 = qualified, never quarantined)", label, flags, settled, cookie)
	}
	if v.parentCookie == 0 {
		v.parentCookie = cookie
	} else if cookie != v.parentCookie {
		v.t.Fatalf("%s: parent identity changed", label)
	}
}

func (v *opaqueVerdictRun) reap(kind string, slot uint32, cookie uint64) {
	v.t.Helper()
	request := struct {
		Cookie        uint64
		Slot, Enabled uint32
	}{cookie, slot, 1}
	if err := v.c.Maps["opaque_real_live_"+kind+"_reap_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
		v.t.Fatal(err)
	}
	for step := 0; step < 20; step++ {
		code, _, err := v.c.Programs["opaque_real_live_reap_"+kind].Test(make([]byte, 64))
		if err != nil {
			v.t.Fatal(err)
		}
		if kind == "work" && code == 1 || kind == "task" && code == 2 {
			return
		}
		if kind == "work" && code > 1 || kind == "task" && code >= 4 {
			v.t.Fatalf("exact %s reap rejected: slot=%d cookie=%d code=%d", kind, slot, cookie, code)
		}
	}
	v.t.Fatalf("exact %s credit not returned", kind)
}

// settleRound reaps every non-parent WORK and returns the count reaped.
func (v *opaqueVerdictRun) settleRound(label string, want int) int {
	v.t.Helper()
	works := 0
	for slot := uint32(0); slot < v.spec.Maps["se_opaque_work_charges"].MaxEntries; slot++ {
		cookie := v.charge("se_opaque_work_charges", slot)
		if cookie == 0 {
			continue
		}
		if v.parentWorks == nil {
			continue
		}
		if saved, ok := v.parentWorks[slot]; ok && saved == cookie {
			continue
		}
		works++
		// se_invocation is at payload offset 0 (static-asserted wire).
		if raw, err := v.c.Maps["se_opaque_work_payload"].LookupBytes(slot); err == nil && len(raw) > 0 {
			// A finished evaluation always carries a nonzero decision mode.
			if mode := int(v.field(v.invocationType, raw, "observation", "evaluator", "decision", "mode")); mode != 0 {
				deny := int(v.field(v.invocationType, raw, "observation", "evaluator", "decision", "deny"))
				v.lastDeny = deny*10 + mode
			}
		}
		v.reap("work", slot, cookie)
	}
	if v.parentWorks == nil {
		v.parentWorks = map[uint32]uint64{}
		for slot := uint32(0); slot < v.spec.Maps["se_opaque_work_charges"].MaxEntries; slot++ {
			if cookie := v.charge("se_opaque_work_charges", slot); cookie != 0 {
				v.parentWorks[slot] = cookie
			}
		}
		v.t.Logf("%s: parent retains %d completed WORK", label, len(v.parentWorks))
		// Identify each retained WORK (G019 option C review): its meta phase
		// (se_owk_meta.phase at offset 4), charge state (se_owk_charge.state
		// at offset 44) and owner TASK slot (charge.owner_slot at offset 48)
		// next to the parent's own TASK slot.
		for slot, cookie := range v.parentWorks {
			meta, merr := v.c.Maps["se_opaque_work_meta"].LookupBytes(slot)
			charge, cerr := v.c.Maps["se_opaque_work_charges"].LookupBytes(slot)
			if merr != nil || cerr != nil || len(meta) < 8 || len(charge) < 52 {
				v.t.Logf("%s: retained WORK slot %d cookie %d: unreadable (%v %v)", label, slot, cookie, merr, cerr)
				continue
			}
			v.t.Logf("%s: retained WORK slot %d cookie %d: meta phase %d charge state %d owner TASK slot %d (parent TASK slot %d)",
				label, slot, cookie, binary.LittleEndian.Uint32(meta[4:8]), binary.LittleEndian.Uint32(charge[44:48]),
				binary.LittleEndian.Uint32(charge[48:52]), v.parentSlot())
		}
	} else if want >= 0 && works != want {
		v.t.Logf("%s: reaped %d child WORKs (diagnostic expectation %d)", label, works, want)
	}
	return works
}

func (v *opaqueVerdictRun) attachChildSource(attach func(string) link.Link) {
	v.t.Helper()
	if err := v.c.Maps["opaque_real_owner_child_targets"].Update(uint32(0),
		v.c.Programs["opaque_real_owner_child_target_candidate"], ebpf.UpdateAny); err != nil {
		v.t.Fatal(err)
	}
	if err := v.c.Maps["opaque_real_owner_child_targets"].Freeze(); err != nil {
		v.t.Fatal(err)
	}
	attach("opaque_real_owner_child_source_candidate")
	birth, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: "sched_process_fork", Program: v.c.Programs["opaque_real_owner_successful_birth_candidate"],
	})
	if err != nil {
		v.t.Fatal(err)
	}
	v.t.Cleanup(func() { _ = birth.Close() })
	free, err := link.Kprobe("free_task", v.c.Programs["opaque_real_owner_birth_free_task_candidate"], nil)
	if err != nil {
		v.t.Fatal(err)
	}
	v.t.Cleanup(func() { _ = free.Close() })
}

// expectRole checks the committed UID history row for policy uid 1/epoch 1.
func (v *opaqueVerdictRun) expectRole(label string, physical, locator uint64) {
	v.t.Helper()
	slot := uint32(locator & ((1 << 14) - 1))
	raw, err := v.c.Maps["se_opaque_payload"].LookupBytes(slot)
	if err != nil {
		v.t.Fatal(err)
	}
	offset, _ := opaqueSourceField(v.t, v.taskType, []string{"committed", "rows"})
	const rowSize, rows = 32, 16
	found := 0
	for i := 0; i < rows; i++ {
		row := raw[offset+i*rowSize : offset+(i+1)*rowSize]
		uid, epoch := binary.LittleEndian.Uint64(row[0:]), binary.LittleEndian.Uint64(row[8:])
		role, knowledge := binary.LittleEndian.Uint64(row[16:]), binary.LittleEndian.Uint32(row[24:])
		if uid != 1 || epoch != 1 {
			continue
		}
		found++
		if role != v.wantRole || knowledge != 1 {
			v.t.Fatalf("%s: TASK %#x history uid 1 role=%d knowledge=%d, want known role %d", label, physical, role, knowledge, v.wantRole)
		}
	}
	if found != 1 {
		v.t.Fatalf("%s: TASK %#x has %d history rows for uid 1", label, physical, found)
	}
}

func (v *opaqueVerdictRun) windows() uint64 {
	v.t.Helper()
	var n uint64
	if err := v.c.Maps["opaque_real_owner_rule_windows"].Lookup(uint32(0), &n); err != nil {
		v.t.Fatal(err)
	}
	return n
}

func (v *opaqueVerdictRun) progress() (evals, matches uint64) {
	v.t.Helper()
	var p struct {
		StageBegin, RuleEval, Matched, ObservedUID int32
		RuleEvalCount, MatchedCount                uint64
	}
	if err := v.c.Maps["opaque_real_owner_rule_progress"].Lookup(uint32(0), &p); err != nil {
		v.t.Fatal(err)
	}
	return p.RuleEvalCount, p.MatchedCount
}

// child forks one helper child running command; wantExit is its exit code.
// evaluated reports whether the euid-0 rule must have matched.
// terminalOutcomes reads resumed_completed, resumed_failed, fallback_charged
// and fallback_refused from the terminal completion counter.
func (v *opaqueVerdictRun) terminalOutcomes() [4]uint64 {
	v.t.Helper()
	var out [4]uint64
	for i := range out {
		if err := v.c.Maps["opaque_real_terminal_outcomes"].Lookup(uint32(i), &out[i]); err != nil {
			v.t.Fatalf("terminal outcomes[%d]: %v", i, err)
		}
	}
	return out
}

func (v *opaqueVerdictRun) child(label, command string, wantExit int, matched bool) {
	v.t.Helper()
	v.children(label, command, 1, wantExit, matched)
}

// children runs a helper command producing n concurrently born children.
func (v *opaqueVerdictRun) children(label, command string, n, wantExit int, matched bool) {
	v.t.Helper()
	beforeEvals, beforeMatches := v.progress()
	beforeWindows := v.windows()
	beforeOutcomes := v.terminalOutcomes()
	beforeSync := v.counters(label, v.c.Maps[WorkSyncWitnessMap], workSyncCounters)
	v.lastDeny = -1
	v.decisionReset(label)
	if _, err := v.stdin.Write([]byte(command)); err != nil {
		v.t.Fatal(err)
	}
	for k := 0; k < n; k++ {
		line, err := v.stdout.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "FORKED:") ||
			!strings.HasSuffix(line, ":"+strconv.Itoa(wantExit)+"\n") {
			v.t.Fatalf("%s: line=%q want exit %d err=%v stderr=%q", label, line, wantExit, err, v.stderr.String())
		}
	}
	evals, matches := v.progress()
	windows := v.windows() - beforeWindows
	wantWindows := uint64(n * ((v.rules+15)/16 - 1))
	ruleZeroMatches := matched && v.rules == 1
	switch {
	case wantExit == 79: // earlier EACCES denial short-circuits: no evaluation
		if evals != beforeEvals || windows != 0 {
			v.t.Fatalf("%s: earlier denial still evaluated policy (%d -> %d, windows %d)", label, beforeEvals, evals, windows)
		}
	case windows != wantWindows:
		v.t.Fatalf("%s: rule windows %d, want %d for %d rules", label, windows, wantWindows, v.rules)
	case ruleZeroMatches:
		if evals != beforeEvals+uint64(n) || matches != beforeMatches+uint64(n) {
			v.t.Fatalf("%s: rule evaluation %d->%d matches %d->%d, want one matching evaluation",
				label, beforeEvals, evals, beforeMatches, matches)
		}
	default:
		if evals != beforeEvals+uint64(n) || matches != beforeMatches {
			v.t.Fatalf("%s: rule evaluation %d->%d matches %d->%d, want one non-matching evaluation",
				label, beforeEvals, evals, beforeMatches, matches)
		}
	}
	// Wait for the child's final free, then refund its TASK exactly.
	refunds := v.settleTasks(label, n)
	works := v.settleRound(label, -1)
	// With the synchronous WORK return the settling programs already
	// returned these WORKs: count them from the witness, per site.
	syncBirth, syncExec, syncReturned := v.syncSettled(label, beforeSync)
	works += int(syncReturned)
	v.decisionFromWitness(label)
	if works%n != 0 {
		v.t.Fatalf("%s: %d WORKs not divisible by %d children", label, works, n)
	}
	works /= n
	kind := map[bool]string{true: "allowed", false: "refused"}[wantExit == 0]
	switch wantExit {
	case 79:
		kind = "prior"
	case 78:
		kind = "failed-exec"
	}
	// Exact completed child WORKs per outcome: birth + evaluation, whose WORK
	// the exec terminal (success or failure) completes into instead of
	// charging a third. An earlier denial short-circuits evaluation and has
	// no receipt, so only the birth WORK remains.
	exactWorks := map[string]int{"allowed": 2, "refused": 2, "failed-exec": 2, "prior": 1}
	if works != exactWorks[kind] {
		v.t.Fatalf("%s: %d completed child WORKs for %s outcome, want %d", label, works, kind, exactWorks[kind])
	}
	// Per-site settlement of the synchronous return: every child's birth
	// WORK at the fork and, unless an earlier denial short-circuited the
	// exec, its evaluation WORK at the exec terminal.
	if v.syncReturn() {
		wantExec := uint64(n)
		if kind == "prior" {
			wantExec = 0
		}
		if syncBirth != uint64(n) || syncExec != wantExec || syncReturned != uint64(works*n) {
			v.t.Fatalf("%s: synchronous WORK return settled birth %d exec %d returned %d, want %d/%d/%d for %s outcome",
				label, syncBirth, syncExec, syncReturned, n, wantExec, works*n, kind)
		}
	}
	v.worksPerKind[kind] = works
	// Every evaluated child's terminal must resume its evaluation WORK and
	// complete; an earlier denial has no terminal at all.
	afterOutcomes := v.terminalOutcomes()
	wantOutcomes := [4]uint64{uint64(n), 0, 0, 0}
	if kind == "prior" {
		wantOutcomes[0] = 0
	}
	for i := range afterOutcomes {
		delta := afterOutcomes[i] - beforeOutcomes[i]
		if delta != wantOutcomes[i] {
			v.t.Fatalf("%s: terminal outcome deltas %v -> %v, want %v for %s outcome",
				label, beforeOutcomes, afterOutcomes, wantOutcomes, kind)
		}
		v.outcomes[i] += delta
	}
	// Decision witness (deny*10+mode) from the evaluation WORK before reap;
	// terminal completion rewrites only its history/catalogue, not the
	// evaluator observation. With the synchronous WORK return the payload is
	// zeroed at the return: the same fields come from the test-only
	// decision witness, snapshotted right before the zero.
	switch {
	case wantExit == 79:
		if v.lastDeny != -1 {
			v.t.Fatalf("%s: earlier denial left an evaluation (%d)", label, v.lastDeny)
		}
	case matched || wantExit == 78:
		if v.lastDeny != v.class {
			v.t.Fatalf("%s: matched rule produced decision %d", label, v.lastDeny)
		}
	case v.fallback == 2:
		if v.lastDeny != 10+v.class {
			v.t.Fatalf("%s: fallback decision %d, want deny with mode %d", label, v.lastDeny, v.class)
		}
	case v.fallback == 1:
		if v.lastDeny != v.class {
			v.t.Fatalf("%s: fallback decision %d, want allow with mode %d", label, v.lastDeny, v.class)
		}
	}
	for _, r := range refunds {
		v.reap("task", r.slot, r.cookie)
	}
	v.parentQualified(label)
}

// settleTasks waits for the final free (DEAD, receipt retired) of the n
// non-parent TASKs and checks each is settled, unquarantined and carries the
// expected UID history. It returns their exact TASK refunds.
func (v *opaqueVerdictRun) settleTasks(label string, n int) []opaqueVerdictRefund {
	v.t.Helper()
	children := v.childTasks(label)
	if len(children) != n {
		v.t.Fatalf("%s: expected %d child TASKs, got %d", label, n, len(children))
	}
	var refunds []opaqueVerdictRefund
	for _, entry := range children {
		child, locator, slot := entry.physical, entry.locator, entry.slot
		v.finalFree(label, entry)
		flags, cookie, settled := v.task(child, locator)
		if !settled {
			raw, _ := v.c.Maps["se_opaque_payload"].LookupBytes(slot)
			var receipt [64]byte
			rerr := v.c.Maps["se_exec_terminal_receipts"].Lookup(child, &receipt)
			acct, _ := v.c.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
			v.t.Fatalf("%s: child not settled: flags=%d reader.owned=%d exec.owned=%d receipt=%v phase=%x work-account=%x",
				label, v.field(v.taskType, raw, "flags"), v.field(v.taskType, raw, "reader", "owned"),
				v.field(v.taskType, raw, "exec", "owned"), rerr == nil, receipt[56:64], acct[:min(len(acct), 16)])
		}
		if flags&2 != 0 {
			v.t.Fatalf("%s: child quarantined (flags=%d)", label, flags)
		}
		if old, ok := v.seen[child]; ok {
			v.reuses++
			if cookie <= old {
				v.t.Fatalf("%s: physical reuse kept stale identity", label)
			}
		}
		v.seen[child] = cookie
		v.expectRole(label, child, locator)
		refunds = append(refunds, opaqueVerdictRefund{slot, cookie})
	}
	return refunds
}

// opaqueChildTask is one charged non-parent TASK: its slot, its physical key
// (the slot's archive, wiped only by the reaper) and its locator.
type opaqueChildTask struct {
	slot              uint32
	physical, locator uint64
	cookie            uint64
}

// childTasks lists every charged non-parent TASK from the charges, not from
// se_opaque_keys: with the final-free withdrawal a dead child's directory
// key is already gone when its TASK is settled.
func (v *opaqueVerdictRun) childTasks(label string) []opaqueChildTask {
	v.t.Helper()
	var children []opaqueChildTask
	parentSlot := v.parentSlot()
	for slot := uint32(0); slot < v.spec.Maps["se_opaque_charges"].MaxEntries; slot++ {
		if slot == parentSlot {
			continue
		}
		cookie := v.charge("se_opaque_charges", slot)
		if cookie == 0 {
			continue
		}
		meta, err := v.c.Maps["se_opaque_meta"].LookupBytes(slot)
		if err != nil {
			v.t.Fatalf("%s: TASK meta %d: %v", label, slot, err)
		}
		var physical uint64
		if err := v.c.Maps["se_opaque_archive"].Lookup(slot, &physical); err != nil {
			v.t.Fatalf("%s: TASK archive %d: %v", label, slot, err)
		}
		locator := v.field(v.metaType, meta, "locator")
		// Only the reaper wipes the archive (ARCHIVE_ZEROED, then
		// REFUND_PENDING); a TASK it has not reached keeps its key bytes.
		phase := v.field(v.metaType, meta, "phase")
		wiped := physical == 0 && (phase == 7 || phase == 8)
		if (physical == 0 && !wiped) || uint32(locator&((1<<14)-1)) != slot || v.field(v.metaType, meta, "cookie") != cookie {
			v.t.Fatalf("%s: charged TASK slot %d has archive %#x locator %#x cookie %d (charge %d)",
				label, slot, physical, locator, v.field(v.metaType, meta, "cookie"), cookie)
		}
		children = append(children, opaqueChildTask{slot, physical, locator, cookie})
	}
	return children
}

// finalFree waits until the child's task_free callback has finished: DEAD,
// its death lease released and its terminal receipt retired (no terminal
// retry can run afterwards). The final-free withdrawal (in every object)
// leaves the directory entry exactly in the reaper's DELETED state.
func (v *opaqueVerdictRun) finalFree(label string, child opaqueChildTask) []byte {
	v.t.Helper()
	meta := v.waitFinalFree(label, child)
	v.withdrawn(label, child, meta)
	return meta
}

// waitFinalFree waits for finalFree's condition and returns the metadata.
func (v *opaqueVerdictRun) waitFinalFree(label string, child opaqueChildTask) []byte {
	v.t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var receipt [64]byte
	for {
		meta, err := v.c.Maps["se_opaque_meta"].LookupBytes(child.slot)
		if err != nil {
			v.t.Fatal(err)
		}
		if len(meta) == 128 && v.field(v.metaType, meta, "phase") == opaqueTaskPhaseDead &&
			v.field(v.metaType, meta, "active_leases") == 0 &&
			errors.Is(v.c.Maps["se_exec_terminal_receipts"].Lookup(child.physical, &receipt), ebpf.ErrKeyNotExist) &&
			v.exitFreed(child) {
			return meta
		}
		if time.Now().After(deadline) {
			v.t.Fatalf("%s: child final-free not observed or terminal receipt survived it (phase=%x)",
				label, receipt[56:64])
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// exitFreed: with credit at exit, a child settled at exit is DEAD with its
// lease released while it is still a zombie or awaiting its RCU-deferred
// free; its task_free has run only once its own tombstone is gone (or left
// FREE_PENDING/RETIRING for the reaper). The slab free follows task_free in
// the same callback, so a later birth may reuse the address only then.
func (v *opaqueVerdictRun) exitFreed(child opaqueChildTask) bool {
	tombs := v.c.Maps["se_exit_tombstones"]
	if tombs == nil {
		return true
	}
	var tomb [opaqueExitTombSize]byte
	if err := tombs.Lookup(child.physical, &tomb); err != nil {
		return errors.Is(err, ebpf.ErrKeyNotExist)
	}
	// RESERVED (an exit in flight, its identity not yet written) is never
	// freed, whatever its cookie field holds.
	stage := binary.LittleEndian.Uint32(tomb[opaqueExitTombStage:])
	if stage == opaqueExitReserved {
		return false
	}
	return binary.LittleEndian.Uint64(tomb[0:8]) != child.cookie ||
		stage == opaqueExitFreePending || stage == opaqueExitRetiring
}

// se_ol_directory_state (full/shared_pool_opaque_lookup_candidate.h) and
// SE_OL_DIR_DONE.
const (
	opaqueDirectoryPublished     = 4
	opaqueDirectoryWithdrawClaim = 5
	opaqueDirectoryWithdrawnZero = 6
	opaqueDirectoryDeleted       = 7
	opaqueCleanupDirDone         = 16
)

// withdrawn checks the reaper-equivalent state the final free must leave:
// DELETED with DIR_DONE, no exclusive owner, and no directory key.
func (v *opaqueVerdictRun) withdrawn(label string, child opaqueChildTask, meta []byte) {
	v.t.Helper()
	var value uint64
	keyErr := v.c.Maps["se_opaque_keys"].Lookup(child.physical, &value)
	if v.field(v.metaType, meta, "directory_state") != opaqueDirectoryDeleted ||
		v.field(v.metaType, meta, "cleanup_done")&opaqueCleanupDirDone == 0 ||
		v.field(v.metaType, meta, "exclusive") != 0 || v.field(v.metaType, meta, "exclusive_owner") != 0 ||
		v.field(v.metaType, meta, "reader_holds") != 0 || !errors.Is(keyErr, ebpf.ErrKeyNotExist) {
		v.t.Fatalf("%s: final free of TASK %#x (slot %d) left directory_state=%d cleanup_done=%#x exclusive=%d owner=%#x reader_holds=%d key=%v, want DELETED, DIR_DONE, unowned, no key",
			label, child.physical, child.slot, v.field(v.metaType, meta, "directory_state"),
			v.field(v.metaType, meta, "cleanup_done"), v.field(v.metaType, meta, "exclusive"),
			v.field(v.metaType, meta, "exclusive_owner"), v.field(v.metaType, meta, "reader_holds"), keyErr)
	}
}

func (v *opaqueVerdictRun) parentSlot() uint32 {
	return uint32(v.parentLocator & ((1 << 14) - 1))
}

// accounts returns the used TASK and WORK credits of the parent's account;
// a faulted account fails the test.
func (v *opaqueVerdictRun) accounts(label string) (tasks, works uint32) {
	v.t.Helper()
	tasks, works, err := v.usedAccounts()
	if err != nil {
		v.t.Fatalf("%s: %v", label, err)
	}
	return tasks, works
}

// usedAccounts is accounts without failing the test (reaper goroutine).
func (v *opaqueVerdictRun) usedAccounts() (tasks, works uint32, err error) {
	account := v.parentSlot() / v.taskQuota
	for i, name := range []string{"se_opaque_accounts", "se_opaque_work_accounts"} {
		raw, err := v.c.Maps[name].LookupBytes(account)
		if err != nil || len(raw) < 12 {
			return 0, 0, fmt.Errorf("%s[%d]: %w", name, account, err)
		}
		// Layout: lock, used, fault, incarnation (static-asserted wires).
		if fault := binary.LittleEndian.Uint32(raw[8:12]); fault != 0 {
			// Bit 0 is the fault; with the test-only fault-site witness
			// (ENFORCE_EXEC_POOL_OPAQUE_WORK_FAULT_SITE_DIAGNOSTIC) bits
			// 1-9 name the WORK account sites that fired.
			return 0, 0, fmt.Errorf("%s[%d] faulted (fault word %#x)", name, account, fault)
		}
		used := binary.LittleEndian.Uint32(raw[4:8])
		if i == 0 {
			tasks = used
		} else {
			works = used
		}
	}
	return tasks, works, nil
}

// threads runs n sequential pthread births in the parent. Each thread birth
// is the same source/target task_alloc as a process birth: exactly one
// charged TASK and one birth WORK (DONE at construction), no exec, so no
// evaluation WORK, rule window or terminal outcome. Final free marks the
// thread TASK DEAD; both credits return only through the exact reapers.
func (v *opaqueVerdictRun) threads(label string, n int) {
	v.t.Helper()
	beforeEvals, beforeMatches := v.progress()
	beforeWindows := v.windows()
	beforeOutcomes := v.terminalOutcomes()
	beforeSync := v.counters(label, v.c.Maps[WorkSyncWitnessMap], workSyncCounters)
	baseTasks, baseWorks := v.accounts(label)
	v.decisionReset(label)
	if _, err := fmt.Fprintf(v.stdin, "THREADS:%d\n", n); err != nil {
		v.t.Fatal(err)
	}
	if line, err := v.stdout.ReadString('\n'); err != nil || line != fmt.Sprintf("THREADED:%d:0\n", n) {
		v.t.Fatalf("%s: line=%q err=%v stderr=%q", label, line, err, v.stderr.String())
	}
	refunds := v.settleTasks(label, n)
	// With the synchronous WORK return each thread's birth WORK is already
	// returned by the task_alloc target.
	wantHeld := uint32(n)
	if v.syncReturn() {
		wantHeld = 0
	}
	if tasks, works := v.accounts(label); tasks != baseTasks+uint32(n) || works != baseWorks+wantHeld {
		v.t.Fatalf("%s: %d thread births charged TASK %d->%d WORK %d->%d, want +1 TASK each and +%d WORK held",
			label, n, baseTasks, tasks, baseWorks, works, wantHeld)
	}
	v.lastDeny = -1
	works := v.settleRound(label, -1)
	syncBirth, syncExec, syncReturned := v.syncSettled(label, beforeSync)
	v.decisionFromWitness(label)
	if works+int(syncReturned) != n || (v.syncReturn() && (syncBirth != uint64(n) || syncExec != 0)) {
		v.t.Fatalf("%s: reaped %d WORKs + %d returned synchronously (settled birth %d exec %d) for %d thread births, want one birth WORK each",
			label, works, syncReturned, syncBirth, syncExec, n)
	}
	if v.lastDeny != -1 {
		v.t.Fatalf("%s: thread birth WORK carried an evaluation decision %d", label, v.lastDeny)
	}
	evals, matches := v.progress()
	if evals != beforeEvals || matches != beforeMatches || v.windows() != beforeWindows ||
		v.terminalOutcomes() != beforeOutcomes {
		v.t.Fatalf("%s: thread births evaluated policy or produced a terminal outcome", label)
	}
	for _, r := range refunds {
		v.reap("task", r.slot, r.cookie)
	}
	v.parentQualified(label)
	if tasks, works := v.accounts(label); tasks != baseTasks || works != baseWorks {
		v.t.Fatalf("%s: account TASK %d WORK %d after refunds, want baseline %d/%d", label, tasks, works, baseTasks, baseWorks)
	}
}

// failedBirth refuses one fork in cgroup_can_fork (pids.max == pids.current).
// copy_process has already run security_task_alloc, so the source/target
// charged a child TASK and birth WORK; the error path then runs
// security_task_free (final free: DEAD, receipt retired) and free_task.
func (v *opaqueVerdictRun) failedBirth(cgroup string) {
	v.t.Helper()
	label := "failed birth (pids.max)"
	retired := func() [2]uint64 {
		v.t.Helper()
		var out [2]uint64
		m := v.c.Maps["opaque_birth_failed_retired"]
		if m == nil {
			v.t.Fatal("verdict object lacks the opaque_birth_failed_retired witness")
		}
		for i := range out {
			if err := m.Lookup(uint32(i), &out[i]); err != nil {
				v.t.Fatal(err)
			}
		}
		return out
	}
	beforeRetired := retired()
	beforeEvals, beforeMatches := v.progress()
	beforeWindows := v.windows()
	beforeOutcomes := v.terminalOutcomes()
	beforeSync := v.counters(label, v.c.Maps[WorkSyncWitnessMap], workSyncCounters)
	baseTasks, baseWorks := v.accounts(label)
	v.decisionReset(label)
	pidsMax := filepath.Join(cgroup, "pids.max")
	original, err := os.ReadFile(pidsMax)
	if err != nil {
		v.t.Fatal(err)
	}
	restored := false
	restore := func() {
		if !restored {
			restored = true
			if err := os.WriteFile(pidsMax, original, 0); err != nil {
				v.t.Errorf("restore %s: %v", pidsMax, err)
			}
		}
	}
	defer restore()
	current, err := os.ReadFile(filepath.Join(cgroup, "pids.current"))
	if err != nil {
		v.t.Fatal(err)
	}
	if err := os.WriteFile(pidsMax, bytes.TrimSpace(current), 0); err != nil {
		v.t.Fatal(err)
	}
	if _, err := v.stdin.Write([]byte("FORKA\n")); err != nil {
		v.t.Fatal(err)
	}
	line, err := v.stdout.ReadString('\n')
	restore()
	if want := fmt.Sprintf("FORKED:-1:%d\n", int(unix.EAGAIN)); err != nil || line != want {
		v.t.Fatalf("%s: line=%q want %q (pids.max=%q) err=%v stderr=%q",
			label, line, want, bytes.TrimSpace(current), err, v.stderr.String())
	}
	refunds := v.settleTasks(label, 1)
	// With the synchronous WORK return the birth WORK is already returned
	// by the task_alloc target (the constructor succeeded before
	// cgroup_can_fork refused the fork).
	wantHeld := uint32(1)
	if v.syncReturn() {
		wantHeld = 0
	}
	if tasks, works := v.accounts(label); tasks != baseTasks+1 || works != baseWorks+wantHeld {
		v.t.Fatalf("%s: failed birth charged TASK %d->%d WORK %d->%d, want +1 TASK and +%d WORK held",
			label, baseTasks, tasks, baseWorks, works, wantHeld)
	}
	// security_task_free (lsm/task_free) runs before free_task and retires
	// the issued receipt that sched_process_fork never observed.
	if after := retired(); after[0]-beforeRetired[0] != 1 || after[1] != beforeRetired[1] {
		v.t.Fatalf("%s: failed-birth witness %v -> %v, want task_free path +1 and free_task path +0",
			label, beforeRetired, after)
	}
	v.lastDeny = -1
	works := v.settleRound(label, -1)
	syncBirth, syncExec, syncReturned := v.syncSettled(label, beforeSync)
	v.decisionFromWitness(label)
	if works+int(syncReturned) != 1 || (v.syncReturn() && (syncBirth != 1 || syncExec != 0)) {
		v.t.Fatalf("%s: reaped %d WORKs + %d returned synchronously (settled birth %d exec %d), want exactly the birth WORK",
			label, works, syncReturned, syncBirth, syncExec)
	}
	evals, matches := v.progress()
	if v.lastDeny != -1 || evals != beforeEvals || matches != beforeMatches ||
		v.windows() != beforeWindows || v.terminalOutcomes() != beforeOutcomes {
		v.t.Fatalf("%s: failed birth evaluated policy or produced a terminal outcome", label)
	}
	v.reap("task", refunds[0].slot, refunds[0].cookie)
	v.parentQualified(label)
	if tasks, works := v.accounts(label); tasks != baseTasks || works != baseWorks {
		v.t.Fatalf("%s: account TASK %d WORK %d after refunds, want baseline %d/%d", label, tasks, works, baseTasks, baseWorks)
	}
	v.worksPerKind["failed-birth"] = 1
	v.t.Logf("%s: fork EAGAIN after task_alloc; 1 TASK + 1 birth WORK refunded exactly; receipt retired by task_free", label)
}

// reapStep runs one exact reap visit without failing the test, so the
// independent reaper goroutine can use it.
func (v *opaqueVerdictRun) reapStep(kind string, slot uint32, cookie uint64) (uint32, error) {
	request := struct {
		Cookie        uint64
		Slot, Enabled uint32
	}{cookie, slot, 1}
	if err := v.c.Maps["opaque_real_live_"+kind+"_reap_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
		return 0, err
	}
	code, _, err := v.c.Programs["opaque_real_live_reap_"+kind].Test(make([]byte, 64))
	return code, err
}

type opaqueReaperStats struct {
	tasks, works, abortedWorks, abortedTasks int
	// Child TASKs reaped from DEAD with SE_TASK_QUARANTINED: a reader the
	// abort handoff quarantined after its evaluation WORK was refused.
	quarantinedTasks int
	// Charges whose reap started; later passes continue them regardless of
	// phase. Values are the exact cookies.
	workStarted, taskStarted map[uint32]uint64
	// TASK reaps started from ABORTED, keyed by slot (exact cookie in
	// taskStarted), so a reap continued by a later pass is still counted.
	taskAborted map[uint32]bool
	// Reaper latency (no BPF timestamp of the final free): deadSeen[slot]
	// holds the start of the previous pass (the final free came later) and
	// the moment this pass first saw DEAD. On return, reapLat samples
	// return - first seen DEAD and reapBound return - previous pass start,
	// an upper bound on final free -> credit return.
	deadSeen           map[uint32][2]time.Time
	lastPass           time.Time
	reapLat, reapBound []time.Duration
	taskHigh, workHigh uint32
}

// opaqueConcurrentOptions selects the concurrent-mode faults (G025).
type opaqueConcurrentOptions struct {
	streams, threadsPerRound int
	// abortEvery N > 0: every Nth child constructor takes the exact abort.
	abortEvery int
	// exhaust: no WORK backpressure; evaluation WORK may be refused.
	exhaust bool
	// failedBirths N > 0: N rounds add one fork refused by pids.max after
	// security_task_alloc, spread evenly over the rounds.
	failedBirths int
	// smallStorage: the object shrinks the deferred receipt/frame HASHes;
	// at least one insert must be refused, and each refusal fails closed.
	smallStorage bool
	// terminalStorage: only the terminal receipts are shrunk; a terminal
	// receipt insert must be refused and no other deferred insert.
	terminalStorage bool
	// contender: a TC completion contender races the real terminals.
	contender bool
	// reaperTick: the independent test reaper's period (default 2ms).
	reaperTick time.Duration
	// birthRate > 0: births/sec paced open loop by the helper (FORKP).
	birthRate int
	// requireNoReuseFailures: no constructor may lose to a DEAD
	// predecessor at its address (STALE/CONTENDED, replacement failures).
	requireNoReuseFailures bool
	// passes > 1 (G019 gap 4, INTERP_BURST): every child execs a #! script,
	// so each evaluated child runs this many evaluations (script, then
	// interpreter) of one exec: one evaluation WORK, one terminal.
	passes int
	// requireZeroFailClosed: the fail-closed rate witness must not move and
	// every forked child must be evaluated (the steady-state gate).
	requireZeroFailClosed bool
	// productReaper (G019 M1): the product Reaper (reaper.go: ringbuf
	// wakeups, syscall reap command, 50 ms fallback sweep) replaces the
	// polling test reaper; every exact assert is unchanged.
	productReaper bool
	// burst (G019 burst gate): back-to-back births, no backpressure, with
	// the product reaper; the zero fail-closed gate up to the burst
	// capacity (ConcurrentBirthCapacity), the over-capacity gate above it.
	burst bool
	// expectRefusals: an over-capacity burst designed to overflow must
	// count at least one refusal.
	expectRefusals bool
}

// se_exec_terminal_receipt.phase (offset 56): the real producer published
// SUCCESS or FAILURE and its completion has not yet retired the receipt.
const (
	opaqueReceiptPhaseOffset  = 56
	opaqueReceiptPhaseSuccess = 2
	opaqueReceiptPhaseFailure = 3
)

// opaqueContenderStats counts the late terminal contender's TC calls.
type opaqueContenderStats struct {
	calls, scans int
	err          error
}

// contend runs the test-only late terminal contender until stop closes: for
// every live child receipt whose real producer has published SUCCESS or
// FAILURE (its completion is in flight), it selects that physical key and
// runs opaque_real_owner_terminal_race_complete. Only one receipt can be
// selected at a time, so one goroutine drives it.
func (v *opaqueVerdictRun) contend(stop <-chan struct{}, s *opaqueContenderStats) {
	selector := v.c.Maps["opaque_real_owner_work_completion_selector"]
	program := v.c.Programs["opaque_real_owner_terminal_race_complete"]
	var keys []uint64
	for {
		select {
		case <-stop:
			return
		default:
		}
		s.scans++
		keys = keys[:0]
		var key uint64
		var receipt [64]byte
		it := v.c.Maps["se_exec_terminal_receipts"].Iterate()
		for it.Next(&key, &receipt) {
			phase := binary.LittleEndian.Uint32(receipt[opaqueReceiptPhaseOffset:])
			if key != v.parent && (phase == opaqueReceiptPhaseSuccess || phase == opaqueReceiptPhaseFailure) {
				keys = append(keys, key)
			}
		}
		// A key deleted during iteration only ends this scan early.
		if err := it.Err(); err != nil && !errors.Is(err, ebpf.ErrIterationAborted) {
			s.err = err
			return
		}
		for _, key := range keys {
			if err := selector.Update(uint32(0), key, ebpf.UpdateAny); err != nil {
				s.err = err
				return
			}
			if code, _, err := program.Test(make([]byte, 64)); err != nil || code != 0 {
				s.err = fmt.Errorf("contender test-run: code=%d err=%w", code, err)
				return
			}
			s.calls++
		}
	}
}

// se_ol_phase (full/shared_pool_opaque_lookup_candidate.h): DEAD after final
// free; ABORTED after an exact abort of a charged, unpublished constructor.
// A refused task_alloc never reaches task_free, so ABORTED is terminal.
const (
	opaqueTaskPhaseDead    = 2 // SE_OL_DEAD
	opaqueTaskPhaseAborted = 6 // SE_OL_ABORTED
)

// reapPass visits the parent's account once: WORK only from DONE/ABORTED
// (never the parent's retained WORKs), TASK only from DEAD/ABORTED (never
// the parent). A quarantined DEAD child is reaped and counted apart; an
// ABORTED TASK must still hold its charge OWNED. Reaper refusals (PENDING/STALE/ALREADY_RETURNED, or TASK
// EMPTY/PENDING) mean "not yet"; only a fault is an error.
func (v *opaqueVerdictRun) reapPass(s *opaqueReaperStats, flagsOffset, flagsSize int) error {
	account := v.parentSlot() / v.taskQuota
	prevPass := s.lastPass
	s.lastPass = time.Now()
	// High-water sample just before this pass returns anything.
	tasks, works, err := v.usedAccounts()
	if err != nil {
		return err
	}
	s.taskHigh, s.workHigh = max(s.taskHigh, tasks), max(s.workHigh, works)
	for slot := account * v.workQuota; slot < (account+1)*v.workQuota; slot++ {
		raw, err := v.c.Maps["se_opaque_work_charges"].LookupBytes(slot)
		if err != nil || len(raw) < 8 {
			return fmt.Errorf("WORK charge %d: %w", slot, err)
		}
		cookie := binary.LittleEndian.Uint64(raw[:8])
		if cookie == 0 || v.parentWorks[slot] == cookie {
			continue
		}
		aborted := false
		if s.workStarted[slot] != cookie {
			meta, err := v.c.Maps["se_opaque_work_meta"].LookupBytes(slot)
			if err != nil || len(meta) < 16 {
				return fmt.Errorf("WORK meta %d: %w", slot, err)
			}
			// se_owk_meta: lock, phase, cookie. 4 = DONE, 5 = ABORTED.
			phase := binary.LittleEndian.Uint32(meta[4:8])
			if (phase != 4 && phase != 5) || binary.LittleEndian.Uint64(meta[8:16]) != cookie {
				continue
			}
			aborted = phase == 5
			s.workStarted[slot] = cookie
		}
		for step := 0; ; step++ {
			code, err := v.reapStep("work", slot, cookie)
			if err != nil {
				return err
			}
			if code == 1 { // SE_OWK_RETURNED
				s.works++
				if aborted {
					s.abortedWorks++
				}
				delete(s.workStarted, slot)
				break
			}
			if code == 0 && step < 32 { // SE_OWK_PROGRESS
				continue
			}
			if code == reapWorkClaimHeld {
				// The synchronous WORK return (option C) holds the WORK's
				// visit claim and finishes it (a synchronous slow path
				// that leaves it unfinished fails the run).
				delete(s.workStarted, slot)
				break
			}
			if code == 0 || code >= 5 { // SE_OWK_CORRUPT
				return fmt.Errorf("WORK slot %d cookie %d reap code %d", slot, cookie, code)
			}
			break // PENDING, STALE, ALREADY_RETURNED: not yet
		}
	}
	parentSlot := v.parentSlot()
	for slot := account * v.taskQuota; slot < (account+1)*v.taskQuota; slot++ {
		if slot == parentSlot {
			continue
		}
		raw, err := v.c.Maps["se_opaque_charges"].LookupBytes(slot)
		if err != nil || len(raw) < 40 {
			return fmt.Errorf("TASK charge %d: %w", slot, err)
		}
		cookie := binary.LittleEndian.Uint64(raw[:8])
		if cookie == 0 {
			continue
		}
		if s.taskStarted[slot] != cookie {
			meta, err := v.c.Maps["se_opaque_meta"].LookupBytes(slot)
			if err != nil || len(meta) < 24 {
				return fmt.Errorf("TASK meta %d: %w", slot, err)
			}
			// se_ol_meta: lock, phase, locator, cookie.
			phase := binary.LittleEndian.Uint32(meta[4:8])
			if (phase != opaqueTaskPhaseDead && phase != opaqueTaskPhaseAborted) ||
				binary.LittleEndian.Uint64(meta[16:24]) != cookie {
				continue
			}
			s.taskAborted[slot] = phase == opaqueTaskPhaseAborted
			// se_oc_charge: cookie, last_returned, scope, locator,
			// incarnation, state. The exact abort leaves it OWNED (2); a
			// FAULT_HELD charge would mean an inexact abort.
			if state := binary.LittleEndian.Uint32(raw[36:40]); phase == opaqueTaskPhaseAborted && state != 2 {
				return fmt.Errorf("ABORTED TASK slot %d cookie %d charge state %d, want OWNED (2)", slot, cookie, state)
			}
			payload, err := v.c.Maps["se_opaque_payload"].LookupBytes(slot)
			if err != nil || len(payload) < flagsOffset+flagsSize {
				return fmt.Errorf("TASK payload %d: %w", slot, err)
			}
			flags := uint64(binary.LittleEndian.Uint32(payload[flagsOffset:]))
			if flagsSize == 8 {
				flags = binary.LittleEndian.Uint64(payload[flagsOffset:])
			}
			if flags&2 != 0 {
				if phase != opaqueTaskPhaseDead {
					return fmt.Errorf("ABORTED child TASK slot %d cookie %d quarantined (flags=%d)", slot, cookie, flags)
				}
				s.quarantinedTasks++
			}
			s.taskStarted[slot] = cookie
			if phase == opaqueTaskPhaseDead {
				s.deadSeen[slot] = [2]time.Time{prevPass, time.Now()}
			}
		}
		for step := 0; ; step++ {
			code, err := v.reapStep("task", slot, cookie)
			if err != nil {
				return err
			}
			if code == 2 { // SE_OR_RETURNED
				s.tasks++
				if seen, ok := s.deadSeen[slot]; ok {
					now := time.Now()
					s.reapLat = append(s.reapLat, now.Sub(seen[1]))
					if !seen[0].IsZero() {
						s.reapBound = append(s.reapBound, now.Sub(seen[0]))
					}
					delete(s.deadSeen, slot)
				}
				if s.taskAborted[slot] {
					s.abortedTasks++
				}
				delete(s.taskStarted, slot)
				delete(s.taskAborted, slot)
				break
			}
			if code == 1 && step < 32 { // SE_OR_PROGRESS
				continue
			}
			if code == 1 || code >= 4 { // SE_OR_FAULT
				return fmt.Errorf("TASK slot %d cookie %d reap code %d", slot, cookie, code)
			}
			break // EMPTY, PENDING: not yet
		}
	}
	return nil
}

// pollingReaper is the test reaper: one reapPass per tick until stop.
func (v *opaqueVerdictRun) pollingReaper(stop <-chan struct{}, done chan<- struct{}, tick time.Duration,
	stats *opaqueReaperStats, flagsOffset, flagsSize int, reaperErr *error,
) {
	defer close(done)
	ticker := time.NewTicker(tick)
	defer ticker.Stop()
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
		}
		if err := v.reapPass(stats, flagsOffset, flagsSize); err != nil {
			*reaperErr = err
			return
		}
	}
}

// productReaperHooks gives the product Reaper the reapPass rules and stats:
// never the parent TASK or its retained WORKs, the same exact checks when a
// TASK reap starts (ABORTED keeps its charge OWNED, quarantine only from
// DEAD), and the same counters. Latency is the product's event -> credit.
func (v *opaqueVerdictRun) productReaperHooks(s *opaqueReaperStats, flagsOffset, flagsSize int) ReaperHooks {
	parentSlot := v.parentSlot()
	workAborted := map[uint32]bool{}
	return ReaperHooks{
		BeforeVisit: func() error {
			tasks, works, err := v.usedAccounts()
			if err != nil {
				return err
			}
			s.taskHigh, s.workHigh = max(s.taskHigh, tasks), max(s.workHigh, works)
			return nil
		},
		Skip: func(kind ReapKind, slot uint32, cookie uint64) bool {
			if kind == ReapWork {
				return v.parentWorks[slot] == cookie
			}
			return slot == parentSlot
		},
		Start: func(kind ReapKind, slot uint32, cookie uint64, phase uint32) error {
			if kind == ReapWork {
				workAborted[slot] = phase == ReapWorkPhaseAborted
				return nil
			}
			raw, err := v.c.Maps["se_opaque_charges"].LookupBytes(slot)
			if err != nil || len(raw) < 40 {
				return fmt.Errorf("TASK charge %d: %w", slot, err)
			}
			if state := binary.LittleEndian.Uint32(raw[36:40]); phase == ReapTaskPhaseAborted && state != 2 {
				return fmt.Errorf("ABORTED TASK slot %d cookie %d charge state %d, want OWNED (2)", slot, cookie, state)
			}
			payload, err := v.c.Maps["se_opaque_payload"].LookupBytes(slot)
			if err != nil || len(payload) < flagsOffset+flagsSize {
				return fmt.Errorf("TASK payload %d: %w", slot, err)
			}
			flags := uint64(binary.LittleEndian.Uint32(payload[flagsOffset:]))
			if flagsSize == 8 {
				flags = binary.LittleEndian.Uint64(payload[flagsOffset:])
			}
			if flags&2 != 0 {
				if phase != ReapTaskPhaseDead {
					return fmt.Errorf("ABORTED child TASK slot %d cookie %d quarantined (flags=%d)", slot, cookie, flags)
				}
				s.quarantinedTasks++
			}
			s.taskAborted[slot] = phase == ReapTaskPhaseAborted
			return nil
		},
		Returned: func(r ReapRecord) {
			if r.Kind == ReapWork {
				s.works++
				if workAborted[r.Slot] {
					s.abortedWorks++
				}
				delete(workAborted, r.Slot)
				return
			}
			s.tasks++
			if s.taskAborted[r.Slot] {
				s.abortedTasks++
			} else if r.Event {
				s.reapLat = append(s.reapLat, r.Latency)
			}
			delete(s.taskAborted, r.Slot)
		},
	}
}

// concurrent runs births racing children (k = streams per round, plus
// threadsPerRound pthread births while they run) with no per-round reaping.
// A reaper goroutine on its own ticker returns credits independently. A
// transiently full WORK account may make a Strict birth or exec fail closed
// (fork EPERM, exit 77); those are counted and reported, never leaked.
// opts.abortEvery injects exact constructor aborts; opts.exhaust drops the
// WORK backpressure so evaluation WORK refusals quarantine their readers.
func (v *opaqueVerdictRun) concurrent(births int, opts opaqueConcurrentOptions) {
	v.t.Helper()
	label := "concurrent"
	streams, threadsPerRound := opts.streams, opts.threadsPerRound
	strict := v.class == 2
	baseTasks, baseWorks := v.accounts(label)
	beforeEvals, beforeMatches := v.progress()
	beforeWindows := v.windows()
	beforeOutcomes := v.terminalOutcomes()
	beforeBirths := v.birthOutcomes(label)
	var beforeInterp []uint64
	if opts.passes > 1 {
		beforeInterp = v.interpStats(label)
	}
	// Test-only witnesses; absent from objects built without them.
	abortCounts := v.c.Maps["opaque_real_abort_counts"]
	evalWitness := v.c.Maps["opaque_real_eval_work_outcomes"]
	if opts.abortEvery > 0 && abortCounts == nil {
		v.t.Fatalf("%s: abort injection needs an object built with ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC", label)
	}
	if opts.exhaust && evalWitness == nil {
		v.t.Fatalf("%s: WORK exhaustion needs an object built with ENFORCE_EXEC_POOL_OPAQUE_EVAL_WORK_WITNESS_DIAGNOSTIC", label)
	}
	storageWitness := v.c.Maps["opaque_real_deferred_storage_refusals"]
	raceWitness := v.c.Maps["opaque_real_terminal_race_witness"]
	if opts.smallStorage && storageWitness == nil {
		v.t.Fatalf("%s: small storage needs ENFORCE_EXEC_POOL_OPAQUE_DEFERRED_STORAGE_WITNESS_DIAGNOSTIC", label)
	}
	if opts.contender && raceWitness == nil {
		v.t.Fatalf("%s: the terminal contender needs ENFORCE_EXEC_POOL_OPAQUE_TERMINAL_RACE_DIAGNOSTIC", label)
	}
	beforeAborts := v.counters(label, abortCounts, 3)
	beforeEvalWork := v.counters(label, evalWitness, 5)
	beforeStorage := v.counters(label, storageWitness, 5)
	beforeRetired := v.counters(label, v.c.Maps["opaque_birth_failed_retired"], 2)
	replaceWitness := v.c.Maps["opaque_real_replace_failures"]
	if opts.requireNoReuseFailures && replaceWitness == nil {
		v.t.Fatalf("%s: REQUIRE_NO_REUSE_FAILURES needs ENFORCE_EXEC_POOL_OPAQUE_ABORT_INJECTOR_DIAGNOSTIC", label)
	}
	beforeReplace := v.counters(label, replaceWitness, 4)
	// Product-visible fail-closed rate witness (decision 3); absent from
	// objects built without ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE.
	rateWitness := v.c.Maps["opaque_real_fail_closed_rates"]
	if opts.requireZeroFailClosed && rateWitness == nil {
		v.t.Fatalf("%s: REQUIRE_ZERO_FAIL_CLOSED needs ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_RATE_CANDIDATE: a missing witness is unknown, never zero", label)
	}
	beforeRates := v.counters(label, rateWitness, v.rateCells(label, rateWitness))
	// Exact WORK high-water witness of this binding's account (test-only
	// ENFORCE_EXEC_POOL_OPAQUE_WORK_HIGH_WATER_DIAGNOSTIC; absent elsewhere):
	// reset here so it covers this run alone.
	highWater := v.c.Maps["opaque_real_work_high_water"]
	workAccount := v.parentSlot() / v.taskQuota
	if highWater != nil {
		if err := highWater.Update(workAccount, [2]uint64{}, ebpf.UpdateExist); err != nil {
			v.t.Fatalf("%s: reset WORK high-water[%d]: %v", label, workAccount, err)
		}
	}
	// G019 option C synchronous WORK return witness; absent from objects
	// built without ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE. Its
	// presence also selects the burst capacity (W-1)/2.
	syncWitness := v.c.Maps[WorkSyncWitnessMap]
	beforeSync := v.counters(label, syncWitness, workSyncCounters)
	// G019 credit-at-exit witness; absent from objects built without
	// ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE.
	exitWitness := v.c.Maps["opaque_real_exit_credit"]
	beforeExit := v.exitCounters(label)
	// Test-only exact witness of the G019 M0 classes (successful-birth
	// diagnostic): [0] exec qualification fault, [1] exec pending-receipt
	// quarantine, [2] birth target parent open failure.
	exclusionWitness := v.c.Maps["opaque_real_exec_exclusions"]
	beforeExclusions := v.counters(label, exclusionWitness, 3)
	// Race witness: attempts, commits, inflight, overlap, authenticated,
	// auth_inflight, auth_overlap (struct of seven u64).
	raceCounters := func() [7]uint64 {
		var out [7]uint64
		if raceWitness != nil {
			raw, err := raceWitness.LookupBytes(uint32(0))
			if err != nil || len(raw) < 56 {
				v.t.Fatalf("%s: terminal race witness: %v", label, err)
			}
			for i := range out {
				out[i] = binary.LittleEndian.Uint64(raw[8*i:])
			}
		}
		return out
	}
	beforeRace := raceCounters()
	setAbortEvery := func(n int) {
		if abortCounts != nil {
			if err := v.c.Maps["opaque_real_abort_every"].Update(uint32(0), uint32(n), ebpf.UpdateAny); err != nil {
				v.t.Fatalf("%s: abort selector: %v", label, err)
			}
		}
	}
	setAbortEvery(opts.abortEvery)
	defer setAbortEvery(0)
	flagsOffset, flagsSize := opaqueSourceField(v.t, v.taskType, []string{"flags"})
	stats := &opaqueReaperStats{
		workStarted: map[uint32]uint64{}, taskStarted: map[uint32]uint64{},
		taskAborted: map[uint32]bool{}, deadSeen: map[uint32][2]time.Time{},
	}
	var reaperErr error
	stop, done := make(chan struct{}), make(chan struct{})
	var product *Reaper
	if opts.productReaper {
		var err error
		if product, err = NewReaper(v.c, ReaperConfig{Hooks: v.productReaperHooks(stats, flagsOffset, flagsSize)}); err != nil {
			v.t.Fatalf("%s: product reaper: %v", label, err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		if err := product.Start(ctx); err != nil {
			cancel()
			v.t.Fatalf("%s: product reaper: %v", label, err)
		}
		go func() {
			<-stop
			cancel()
		}()
		go func() {
			defer close(done)
			reaperErr = product.Wait()
		}()
	} else {
		go v.pollingReaper(stop, done, opts.reaperTick, stats, flagsOffset, flagsSize, &reaperErr)
	}
	stopped := false
	stopReaper := func() {
		if !stopped {
			stopped = true
			close(stop)
			<-done
		}
	}
	defer stopReaper()
	// The late terminal contender runs only while children are born and
	// complete; it is stopped (and disarmed) before quiescence.
	contender := &opaqueContenderStats{}
	contenderStopped := true
	stopContender := func() {}
	if opts.contender {
		if err := v.c.Maps["opaque_real_owner_work_completion_gate"].Update(uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
			v.t.Fatalf("%s: arm contender: %v", label, err)
		}
		cstop, cdone := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(cdone)
			v.contend(cstop, contender)
		}()
		contenderStopped = false
		stopContender = func() {
			if !contenderStopped {
				contenderStopped = true
				close(cstop)
				<-cdone
				if err := v.c.Maps["opaque_real_owner_work_completion_gate"].Update(uint32(0), uint32(0), ebpf.UpdateAny); err != nil {
					v.t.Errorf("%s: disarm contender: %v", label, err)
				}
			}
		}
	}
	defer stopContender()
	exits, forkRefused, threadErrs := map[int]int{}, map[int]int{}, map[int]int{}
	threadsOK, threadsFailed := 0, 0
	// Failed births: errno of each refused fork, and any that unexpectedly
	// succeeded (exit code).
	failedErrno, failedBorn := map[int]int{}, map[int]int{}
	taskHigh, workHigh := baseTasks, baseWorks // sampled used high-water marks
	failing := 0
	if opts.failedBirths > 0 {
		failing = 1
	}
	// Each child needs a birth and an evaluation WORK, each thread and a
	// failed birth a birth WORK. A round must fit the WORK account next to
	// the retained baseline, or a child's evaluation WORK is refused and its
	// exec reader quarantined (fail closed), which this test must never
	// provoke. With opts.exhaust the round is not fitted and no room is
	// awaited: a refused evaluation WORK must quarantine the child.
	perRound := streams
	if !opts.exhaust {
		perRound = min(streams, (int(v.workQuota)-int(baseWorks)-threadsPerRound-failing)/2)
	}
	if perRound < 1 {
		v.t.Fatalf("%s: WORK quota %d cannot fit one child + %d threads + %d failed births next to %d retained WORKs",
			label, v.workQuota, threadsPerRound, failing, baseWorks)
	}
	rounds := (births + perRound - 1) / perRound
	failEvery := 1
	if opts.failedBirths > 0 {
		if opts.failedBirths > rounds {
			v.t.Fatalf("%s: %d failed births need at least as many rounds (%d)", label, opts.failedBirths, rounds)
		}
		failEvery = rounds / opts.failedBirths
	}
	failedSent := 0
	// Birth pacing (opts.birthRate): one FORKP command; the helper forks on
	// its own absolute schedule and reports each child as it is reaped.
	var pacedSpan, pacedMaxLate, pacedSumLate time.Duration
	pacedWaits := 0
	sendStart := time.Now()
	if opts.birthRate > 0 {
		interval := time.Second / time.Duration(opts.birthRate)
		if _, err := fmt.Fprintf(v.stdin, "FORKP:%d:%d:%d\n", births, streams, interval.Nanoseconds()); err != nil {
			v.t.Fatal(err)
		}
		for i := 0; i < births; i++ {
			line, err := v.stdout.ReadString('\n')
			var pid, code int
			if err != nil {
				v.t.Fatalf("%s: %v stderr=%q", label, err, v.stderr.String())
			}
			if n, _ := fmt.Sscanf(line, "FORKED:%d:%d\n", &pid, &code); n != 2 {
				v.t.Fatalf("%s: line=%q", label, line)
			}
			if pid < 0 {
				forkRefused[code]++
			} else {
				exits[code]++
			}
			tasks, works := v.accounts(label)
			taskHigh, workHigh = max(taskHigh, tasks), max(workHigh, works)
			if (i+1)%512 == 0 || i+1 == births {
				v.t.Logf("%s: %d/%d paced births reported", label, i+1, births)
			}
		}
		line, err := v.stdout.ReadString('\n')
		var span, maxLate, sumLate int64
		if err != nil {
			v.t.Fatalf("%s: %v stderr=%q", label, err, v.stderr.String())
		}
		if n, _ := fmt.Sscanf(line, "PACED:%d:%d:%d:%d\n", &span, &maxLate, &sumLate, &pacedWaits); n != 4 || span < 0 {
			v.t.Fatalf("%s: line=%q", label, line)
		}
		pacedSpan, pacedMaxLate, pacedSumLate = time.Duration(span), time.Duration(maxLate), time.Duration(sumLate)
	}
	for sent, round := 0, 0; opts.birthRate == 0 && sent < births; round++ {
		k := min(perRound, births-sent)
		f := 0
		if failedSent < opts.failedBirths && round%failEvery == 0 {
			f = 1
		}
		// Backpressure only (read-only): wait for the reaper to make room for
		// this round's 2 WORKs per child and 1 per thread or failed birth.
		roomy := opts.exhaust
		for deadline := time.Now().Add(10 * time.Second); !roomy && time.Now().Before(deadline); time.Sleep(time.Millisecond) {
			tasks, works := v.accounts(label)
			taskHigh, workHigh = max(taskHigh, tasks), max(workHigh, works)
			if int(works)+2*k+threadsPerRound+f <= int(v.workQuota) {
				roomy = true
				break
			}
		}
		if !roomy {
			v.t.Fatalf("%s: reaper made no WORK room for a %d-child round in 10s", label, k)
		}
		command := fmt.Sprintf("FORKN:%d:%d\n", k, threadsPerRound)
		if f == 1 {
			command = fmt.Sprintf("FORKN:%d:%d:1\n", k, threadsPerRound)
		}
		if _, err := io.WriteString(v.stdin, command); err != nil {
			v.t.Fatal(err)
		}
		for i := 0; i < k; i++ {
			line, err := v.stdout.ReadString('\n')
			var pid, code int
			if err != nil {
				v.t.Fatalf("%s: %v stderr=%q", label, err, v.stderr.String())
			}
			if n, _ := fmt.Sscanf(line, "FORKED:%d:%d\n", &pid, &code); n != 2 {
				v.t.Fatalf("%s: line=%q", label, line)
			}
			if pid < 0 {
				forkRefused[code]++
			} else {
				exits[code]++
			}
		}
		if f == 1 {
			line, err := v.stdout.ReadString('\n')
			var pid, code int
			if err != nil {
				v.t.Fatalf("%s: %v stderr=%q", label, err, v.stderr.String())
			}
			if n, _ := fmt.Sscanf(line, "FAILBIRTH:%d:%d\n", &pid, &code); n != 2 {
				v.t.Fatalf("%s: line=%q", label, line)
			}
			if pid < 0 {
				failedErrno[code]++
			} else {
				failedBorn[code]++
			}
			failedSent++
		}
		line, err := v.stdout.ReadString('\n')
		var created, threadErr int
		if err != nil {
			v.t.Fatalf("%s: %v stderr=%q", label, err, v.stderr.String())
		}
		if n, _ := fmt.Sscanf(line, "THREADED:%d:%d\n", &created, &threadErr); n != 2 ||
			created < 0 || created > threadsPerRound || (created < threadsPerRound) != (threadErr != 0) {
			v.t.Fatalf("%s: line=%q", label, line)
		}
		if tasks, _ := v.accounts(label); tasks > taskHigh {
			taskHigh = tasks
		}
		threadsOK += created
		threadsFailed += threadsPerRound - created
		if threadErr != 0 {
			threadErrs[threadErr]++
		}
		sent += k
		if (sent-k)/512 != sent/512 || sent == births {
			v.t.Logf("%s: %d/%d births sent", label, sent, births)
		}
	}
	// Achieved birth rate: paced, (births-1) over the helper's first..last
	// fork span; back to back, births over the Go-side send time.
	sendSpan := time.Since(sendStart)
	achieved := float64(births) / sendSpan.Seconds()
	if opts.birthRate > 0 {
		achieved = 0
		if births > 1 && pacedSpan > 0 {
			achieved = float64(births-1) / pacedSpan.Seconds()
		}
		v.t.Logf("%s: paced births: target %d/s achieved %.1f/s over %s; fork start late max %s mean %s; %d births waited for the %d-stream cap",
			label, opts.birthRate, achieved, pacedSpan, pacedMaxLate, pacedSumLate/time.Duration(births), pacedWaits, streams)
	}
	// No constructor may be aborted after the last birth: the injected count
	// below is then final. Every child of the last round has completed, so
	// the late contender has nothing left to race.
	setAbortEvery(0)
	stopContender()
	// Quiesce: the helper is idle; only the reaper may return the credits.
	quiesced := false
	for deadline := time.Now().Add(time.Minute); !quiesced && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		select {
		case <-done:
			deadline = time.Now()
			continue
		default:
		}
		tasks, works := v.accounts(label)
		quiesced = tasks == baseTasks && works == baseWorks
	}
	// Credit at exit: the credits are back, but each exited child's
	// task_free (its tombstone) and its TASK FREED wakeup may still be due;
	// wait for both before the reaper stops.
	if exitWitness != nil && quiesced {
		v.waitExitDrained(label, beforeExit, product)
	}
	stopReaper()
	taskHigh, workHigh = max(taskHigh, stats.taskHigh), max(workHigh, stats.workHigh)
	var productStats ReaperStats
	if product != nil {
		var err error
		if productStats, err = product.Stats(); err != nil {
			v.t.Errorf("%s: product reaper stats: %v", label, err)
		}
		v.t.Logf("%s: product reaper: %s", label, productStats)
	}
	// Every check below reports; the test fails once all were reported, so
	// a quiesce/leak failure never hides a formula failure or vice versa.
	failed := false
	fail := func(format string, args ...any) {
		failed = true
		v.t.Errorf(format, args...)
	}
	if reaperErr != nil {
		fail("%s: reaper: %v", label, reaperErr)
	}
	// A reap fault quarantines its charge instead of stopping the reaper:
	// any one fails the run (its slot stays charged).
	if productStats.Faulted != 0 {
		fail("%s: product reaper quarantined %d faulted charges: %v", label, productStats.Faulted, product.Faults())
	}
	tasks, works := v.accounts(label)
	evals, matches := v.progress()
	evaluated := evals - beforeEvals
	rawEvaluations := evaluated
	if opts.passes > 1 {
		// G019 gap 4: count evaluated children; every one ran all its
		// passes (the steady-state gate below admits no partial exec).
		if evaluated%uint64(opts.passes) != 0 {
			fail("%s: %d evaluations not a multiple of %d interpreter passes", label, evaluated, opts.passes)
		}
		evaluated /= uint64(opts.passes)
		interp := v.interpStats(label)
		if d := interp[InterpContinuedDepth1] - beforeInterp[InterpContinuedDepth1]; d != evaluated {
			fail("%s: %d interpreter passes continued for %d evaluated script children", label, d, evaluated)
		}
		for i := InterpRefusedFrame; i < InterpContinuationStats; i++ {
			if interp[i] != beforeInterp[i] {
				fail("%s: interpreter refusal cell %d moved %d -> %d", label, i, beforeInterp[i], interp[i])
			}
		}
	}
	afterBirths := v.birthOutcomes(label)
	var out [8]uint64
	for i := range out {
		out[i] = afterBirths[i] - beforeBirths[i]
	}
	sourceRefusals, constructOK := out[0], out[1]
	constructFailures := out[2] + out[3] + out[4] + out[5]
	// out[7]: the source could not issue the test-only birth receipt (its
	// HASH is sized to SE_PROFILE_TASKS, and receipts of unconstructed Audit
	// children live until their RCU-deferred free), so it finished the birth
	// WORK without the target: Strict refuses, Audit runs it unconstructed.
	missingTarget := out[7]
	forked, refused := 0, 0
	for _, n := range exits {
		forked += n
	}
	for _, n := range forkRefused {
		refused += n
	}
	failedAttempts, failedBornN := 0, 0
	for _, n := range failedErrno {
		failedAttempts += n
	}
	for _, n := range failedBorn {
		failedBornN += n
	}
	failedAttempts += failedBornN
	// A Strict failed birth refused by our task_alloc (EPERM) never reaches
	// cgroup_can_fork; every EAGAIN passed security_task_alloc.
	eagain, failedEPERM := uint64(failedErrno[int(unix.EAGAIN)]), uint64(failedErrno[int(unix.EPERM)])
	attempts := uint64(forked + refused + threadsOK + threadsFailed + failedAttempts)
	deadTasks := uint64(stats.tasks - stats.abortedTasks)
	// Witness deltas (zero when the object lacks the witness).
	afterAborts := v.counters(label, abortCounts, 3)
	afterEvalWork := v.counters(label, evalWitness, 5)
	afterStorage := v.counters(label, storageWitness, 5)
	afterRetired := v.counters(label, v.c.Maps["opaque_birth_failed_retired"], 2)
	afterReplace := v.counters(label, replaceWitness, 4)
	var replaceFailures [4]uint64
	for i := range replaceFailures {
		replaceFailures[i] = afterReplace[i] - beforeReplace[i]
	}
	afterRace := raceCounters()
	var aborts [3]uint64
	var evalWork, storage [5]uint64
	var retired [2]uint64
	var race [7]uint64
	for i := range aborts {
		aborts[i] = afterAborts[i] - beforeAborts[i]
	}
	for i := range evalWork {
		evalWork[i] = afterEvalWork[i] - beforeEvalWork[i]
		storage[i] = afterStorage[i] - beforeStorage[i]
	}
	for i := range retired {
		retired[i] = afterRetired[i] - beforeRetired[i]
	}
	for i := range race {
		race[i] = afterRace[i] - beforeRace[i]
	}
	// Deferred storage refusals that quarantine a verdict reader (its exec
	// is then never evaluated: Strict 77, Audit unevaluated): a refused
	// terminal receipt [0] and failure frames that were not ready [4].
	storageQuarantined := storage[0] + storage[4]
	outcomeDelta := v.terminalOutcomes()
	for i := range outcomeDelta {
		outcomeDelta[i] -= beforeOutcomes[i]
	}
	// Transient WORKs a late completion charged (FALLBACK_CHARGED): each
	// is DONE at once and reaped like any other.
	fallbackCharged := outcomeDelta[2]
	// Synchronous WORK return (option C): the WORKs BPF returned at settle
	// never reach the reaper's Returned hook (its visit, if any, ends
	// claim-held or settled), so they complete the reaper's WORK count.
	var syncDelta [workSyncCounters]uint64
	if syncWitness != nil {
		afterSync := v.counters(label, syncWitness, workSyncCounters)
		for i := range syncDelta {
			syncDelta[i] = afterSync[i] - beforeSync[i]
		}
	}
	syncReturned := syncDelta[workSyncReturned]
	abortEdges, injected, exactAborts := aborts[0], aborts[1], aborts[2]
	evalEntered, evalRefused := evalWork[0], evalWork[1]
	evalChargedFailed, handoffQuarantined, handoffFailed := evalWork[2], evalWork[3], evalWork[4]
	v.t.Logf("%s: %d births (%d streams, %d threads/round): exits %v, fork refusals by errno %v, threads ok=%d failed=%d errs %v; evaluated=%d; source start_work refusals=%d; construct ok=%d stale=%d contended=%d limit=%d corrupt=%d unattempted=%d unconstructed-done=%d; reaper returned TASK=%d (aborted %d) WORK=%d (aborted %d), synchronously returned WORK=%d; TASK used high-water %d/%d (baseline %d)",
		label, births, streams, threadsPerRound, exits, forkRefused, threadsOK, threadsFailed, threadErrs,
		evaluated, sourceRefusals, out[1], out[2], out[3], out[4], out[5], out[6], out[7],
		stats.tasks, stats.abortedTasks, stats.works, stats.abortedWorks, syncReturned, taskHigh, v.taskQuota, baseTasks)
	v.t.Logf("%s: abort injection every %d: %d edges, %d injected, %d exact aborts (%d natural); evaluation WORK: entered=%d refused=%d charged-failed=%d; abort handoff quarantined=%d failed=%d; reaper quarantined DEAD TASKs=%d; exhaust=%v",
		label, opts.abortEvery, abortEdges, injected, exactAborts, exactAborts-min(injected, exactAborts),
		evalEntered, evalRefused, evalChargedFailed, handoffQuarantined, handoffFailed, stats.quarantinedTasks, opts.exhaust)
	v.t.Logf("%s: failed births %d: refused by errno %v, unexpectedly born %v; failed-birth receipts retired task_free=%d free_task=%d; deferred storage refusals: terminal receipt=%d outer frame=%d handler frame=%d birth receipt=%d frames-not-ready quarantine=%d (small=%v)",
		label, failedAttempts, failedErrno, failedBorn, retired[0], retired[1],
		storage[0], storage[1], storage[2], storage[3], storage[4], opts.smallStorage)
	if opts.contender {
		v.t.Logf("%s: terminal contender: %d scans, %d calls; race witness attempts=%d commits=%d overlap=%d authenticated=%d auth_overlap=%d inflight=%d auth_inflight=%d; terminal outcomes %v",
			label, contender.scans, contender.calls, race[0], race[1], race[3], race[4], race[6],
			afterRace[2], afterRace[5], outcomeDelta)
	}
	v.t.Logf("%s: physical reuse: construct stale=%d contended=%d; replacement failures (observe/read/hold/claim) %v (witness=%v)",
		label, out[2], out[3], replaceFailures, replaceWitness != nil)
	if opts.requireNoReuseFailures && (out[2]+out[3] != 0 || replaceFailures != [4]uint64{}) {
		fail("%s: %d STALE + %d CONTENDED constructors and replacement failures %v, want none with the final-free withdrawal",
			label, out[2], out[3], replaceFailures)
	}
	if !quiesced {
		fail("%s: account TASK %d WORK %d never returned to baseline %d/%d", label, tasks, works, baseTasks, baseWorks)
		v.leaks(label)
	}
	for code, n := range exits {
		if code != 0 && (!strict || code != 77) {
			fail("%s: %d children exited %d", label, n, code)
		}
	}
	for errno, n := range forkRefused {
		if !strict || errno != int(unix.EPERM) {
			fail("%s: %d forks refused with errno %d", label, n, errno)
		}
	}
	for errno, n := range threadErrs {
		if !strict || (errno != int(unix.EPERM) && errno != int(unix.EAGAIN)) {
			fail("%s: %d thread rounds failed with %d", label, n, errno)
		}
	}
	if out[6] != 0 {
		fail("%s: %d births never reached the constructor", label, out[6])
	}
	// Each attempted birth charges one source WORK unless start_work refused
	// it uncharged; the target completes it whatever the constructor status.
	// Each evaluation adds one WORK (the terminal completes into it).
	// A refused evaluation start_work charges nothing (witness [1]; a
	// failure after a charge, [2], must not occur), so the formula counts
	// only evaluations that ran: entered == evaluated + refused.
	// A late completion that found the evaluation WORK already consumed
	// charges one transient WORK (FALLBACK_CHARGED), also returned.
	if want := attempts - sourceRefusals + evaluated + fallbackCharged; uint64(stats.works)+syncReturned != want {
		fail("%s: reaper returned %d WORKs + %d returned synchronously, want %d attempts - %d source refusals + %d evaluations + %d transient terminal WORKs = %d",
			label, stats.works, syncReturned, attempts, sourceRefusals, evaluated, fallbackCharged, want)
	}
	// Published children reap from DEAD; a TASK charged by a failed
	// constructor is aborted exactly and reaps from ABORTED.
	if deadTasks != constructOK || uint64(stats.abortedTasks) > constructFailures {
		fail("%s: reaper returned %d DEAD + %d ABORTED TASKs for %d constructed and %d failed constructors",
			label, deadTasks, stats.abortedTasks, constructOK, constructFailures)
	}
	// Credit at exit: every DEAD TASK credit was settled exactly once, at
	// exit or by the task_free fallback (a failed birth never exits), and
	// every tombstone was consumed, resumed or retired exactly.
	var exit ExitCreditVerdict
	if exitWitness != nil {
		var err error
		if exit, err = ExitCredit(v.exitArray(beforeExit), v.exitArray(v.exitCounters(label)), v.exitCapacity()); err != nil {
			fail("%s: exit credit witness: %v", label, err)
		} else {
			if err := exit.Quiescent(); quiesced && err != nil {
				fail("%s: %v (%s)", label, err, exit)
			}
			if exit.DeadSettlements() != deadTasks {
				fail("%s: reaper returned %d DEAD TASKs, want %d settled at exit + %d pending at exit + %d task_free fallbacks",
					label, deadTasks, exit.Delta[ExitCreditSettled], exit.Delta[ExitCreditDirPending], exit.Delta[ExitCreditFallbackFree])
			}
			// The ringbuf may still hold wakeups emitted before the window
			// (no reader then): at most every FREED counted before it.
			if backlog := beforeExit[ExitCreditFreed]; product != nil && productStats.Drops == 0 &&
				(productStats.Freed < exit.Delta[ExitCreditFreed] || productStats.Freed-exit.Delta[ExitCreditFreed] > backlog) {
				fail("%s: product reaper read %d TASK FREED wakeups, want %d of the window (no drops) + at most %d emitted before it",
					label, productStats.Freed, exit.Delta[ExitCreditFreed], backlog)
			}
			v.t.Logf("%s: EXIT %s capacity=%d", label, exit, v.c.Maps["se_exit_tombstones"].MaxEntries())
		}
	}
	if abortCounts != nil {
		// Exact: every ABORTED reap is one exact semantic abort, which is
		// either injected or a natural replacement loss (natural =
		// exact - injected, logged above). The injector selects exactly
		// every Nth edge, and an injected constructor reports CORRUPT.
		if uint64(stats.abortedTasks) != exactAborts || exactAborts < injected {
			fail("%s: reaper returned %d ABORTED TASKs, want %d exact aborts (%d injected + natural)",
				label, stats.abortedTasks, exactAborts, injected)
		}
		if every := uint64(opts.abortEvery); every > 0 &&
			(injected != afterAborts[0]/every-beforeAborts[0]/every || injected == 0) {
			fail("%s: %d aborts injected for %d fault edges every %d", label, injected, abortEdges, opts.abortEvery)
		}
		if out[5] < injected {
			fail("%s: %d injected aborts but %d CORRUPT constructors", label, injected, out[5])
		}
	}
	// A refused evaluation WORK quarantines the child's reader through the
	// exact abort handoff, which retires the receipt: the child then has no
	// terminal, Strict denies its exec (77) and Audit runs it unevaluated.
	// The quarantined DEAD child is reaped like any other.
	// A refused terminal receipt or unready failure frame quarantines the
	// reader before evaluation (no handoff, no terminal).
	if uint64(stats.quarantinedTasks) != evalRefused+storageQuarantined || handoffQuarantined != evalRefused ||
		evalChargedFailed != 0 || handoffFailed != 0 {
		fail("%s: %d quarantined DEAD TASKs and %d exact abort handoffs (%d failed) for %d evaluation WORK refusals (%d failed after charge) + %d deferred storage quarantines",
			label, stats.quarantinedTasks, handoffQuarantined, handoffFailed, evalRefused, evalChargedFailed, storageQuarantined)
	}
	// Deferred storage: a refused birth receipt makes the source finish the
	// birth WORK without the target (counted in out[7]); unready frames
	// come only from refused frame inserts here. A small-storage run must
	// actually have refused at least one insert.
	if storage[3] > missingTarget || storage[4] > storage[1]+storage[2] {
		fail("%s: deferred storage refusals %v exceed %d missing targets / %d refused frame inserts",
			label, storage, missingTarget, storage[1]+storage[2])
	}
	if opts.smallStorage && storage[0]+storage[1]+storage[2]+storage[3] == 0 {
		fail("%s: small-storage run refused no deferred insert", label)
	}
	// Terminal-only small storage (step 4b): the terminal receipt refusal
	// must be reached and the full-size frames never refuse. Full-size
	// birth receipts can still overflow naturally while TASK is saturated
	// (Audit unconstructed births keep their receipt until free_task); each
	// such refusal must be exactly one missing target (out[7]). Every
	// terminal refusal is a storage quarantine counted exactly in the
	// quarantine, Strict-77 and Audit-unevaluated formulas.
	if opts.terminalStorage && (storage[0] == 0 || storage[1]|storage[2]|storage[4] != 0 || storage[3] != missingTarget) {
		fail("%s: terminal-only small storage refusals %v, want terminal receipt [0] > 0, [1] == [2] == [4] == 0 and birth receipt [3] == %d missing targets",
			label, storage, missingTarget)
	}
	// Failed births: only pids.max EAGAIN, or (Strict only) our own EPERM
	// refusal before cgroup_can_fork; none may be born. Every receipt the
	// task_free path retired unobserved is a failed birth, never free_task.
	for errno, n := range failedErrno {
		if errno != int(unix.EAGAIN) && (!strict || errno != int(unix.EPERM)) {
			fail("%s: %d failed births refused with errno %d", label, n, errno)
		}
	}
	if failedBornN != 0 || failedAttempts != opts.failedBirths {
		fail("%s: %d of %d failed births sent, %d born (%v)", label, failedAttempts, opts.failedBirths, failedBornN, failedBorn)
	}
	if retired[1] != 0 || retired[0] > eagain {
		fail("%s: failed-birth receipts retired task_free=%d free_task=%d for %d EAGAIN births", label, retired[0], retired[1], eagain)
	}
	if evalWitness != nil && evalEntered != evaluated+evalRefused {
		fail("%s: %d evaluations entered, want %d evaluated + %d refused", label, evalEntered, evaluated, evalRefused)
	}
	if !opts.exhaust && uint64(stats.quarantinedTasks) != storageQuarantined {
		fail("%s: backpressure run quarantined %d children, %d by deferred storage", label, stats.quarantinedTasks, storageQuarantined)
	}
	born := uint64(forked + threadsOK)
	if strict {
		// Every allowed Strict child was evaluated exactly once; every exit
		// 77 is a fail-closed refusal that never reached evaluation.
		if uint64(exits[0]) != evaluated {
			fail("%s: %d children allowed but %d evaluated: unexpected Strict denial", label, exits[0], evaluated)
		}
		if uint64(exits[77]) != evalRefused+storageQuarantined {
			fail("%s: %d Strict exits 77, want %d evaluation WORK refusals + %d deferred storage quarantines",
				label, exits[77], evalRefused, storageQuarantined)
		}
		// A Strict source refusal or failed constructor refuses the birth;
		// a failed birth that reached cgroup_can_fork (EAGAIN) was
		// constructed and its unobserved receipt retired by task_free.
		if born+eagain != constructOK {
			fail("%s: %d Strict births (%d forks + %d threads) + %d failed births (EAGAIN) for %d constructed TASKs",
				label, born, forked, threadsOK, eagain, constructOK)
		}
		if retired[0] != eagain {
			fail("%s: %d Strict failed births (EAGAIN) but %d receipts retired by task_free", label, eagain, retired[0])
		}
		if got := uint64(forkRefused[int(unix.EPERM)]+threadsFailed) + failedEPERM; got != constructFailures+sourceRefusals+missingTarget {
			fail("%s: %d EPERM fork refusals + %d thread failures + %d failed births (EPERM), want %d failed constructors + %d source refusals + %d missing targets",
				label, forkRefused[int(unix.EPERM)], threadsFailed, failedEPERM, constructFailures, sourceRefusals, missingTarget)
		}
	} else {
		// Audit never refuses (checked above): a source refusal or failed
		// constructor leaves an unconstructed, unevaluated birth, and a
		// refused evaluation WORK an unevaluated child.
		// Every Audit failed birth reaches cgroup_can_fork (EAGAIN). The
		// constructed ones are exactly those whose unobserved receipt
		// task_free retired; the rest are unconstructed failed births.
		unconstructed := constructFailures + sourceRefusals + missingTarget
		if born+eagain < constructOK || born+eagain-constructOK != unconstructed {
			fail("%s: %d Audit births (%d forks + %d threads) + %d failed births, %d constructed, want %d unconstructed",
				label, born, forked, threadsOK, eagain, constructOK, unconstructed)
		}
		unconstructedFailed := eagain - min(retired[0], eagain)
		quarantined := evalRefused + storageQuarantined
		if evaluated > uint64(exits[0]) || deadTasks > born+eagain || unconstructedFailed > unconstructed {
			fail("%s: Audit evaluated %d of %d children, returned %d DEAD TASKs for %d births + %d failed births (%d unconstructed of %d)",
				label, evaluated, exits[0], deadTasks, born, eagain, unconstructedFailed, unconstructed)
		} else if unevaluated := uint64(exits[0]) - evaluated; (threadsPerRound == 0 && unevaluated != unconstructed-unconstructedFailed+quarantined) ||
			unevaluated > unconstructed-unconstructedFailed+quarantined {
			fail("%s: %d Audit children unevaluated, want %d unconstructed births - %d unconstructed failed births + %d evaluation refusals + %d deferred storage quarantines (%d threads/round)",
				label, unevaluated, unconstructed, unconstructedFailed, evalRefused, storageQuarantined, threadsPerRound)
		}
	}
	if v.rules == 1 && matches-beforeMatches != rawEvaluations {
		fail("%s: %d evaluations but %d euid-0 rule matches", label, rawEvaluations, matches-beforeMatches)
	}
	if windows := v.windows() - beforeWindows; windows != rawEvaluations*uint64((v.rules+15)/16-1) {
		fail("%s: rule windows %d for %d evaluations of %d rules", label, windows, rawEvaluations, v.rules)
	}
	// Only an evaluated child has a terminal: a quarantined child's receipt
	// was retired by its exact handoff (handoffFailed == 0 above), so no
	// fallback WORK is charged or refused for it.
	// Exactly one resumed commit per evaluated receipt, whoever wins it.
	// Without the contender no late completion exists; with it, a loser
	// either charged a transient WORK (counted in the WORK formula above) or
	// was refused before any charge.
	afterOutcomes := v.terminalOutcomes()
	wantOutcomes := [4]uint64{evaluated, 0, 0, 0}
	if opts.contender {
		wantOutcomes[2], wantOutcomes[3] = outcomeDelta[2], outcomeDelta[3]
	}
	for i := range afterOutcomes {
		delta := afterOutcomes[i] - beforeOutcomes[i]
		if delta != wantOutcomes[i] {
			fail("%s: terminal outcome deltas %v -> %v, want %v", label, beforeOutcomes, afterOutcomes, wantOutcomes)
			break
		}
	}
	if opts.contender {
		// Contender calls are exactly the witness attempts; its commits are
		// a subset of the one commit per receipt; nothing is left inside.
		if contender.err != nil {
			fail("%s: contender: %v", label, contender.err)
		}
		if race[0] != uint64(contender.calls) || race[1] > evaluated || race[1] > outcomeDelta[0] ||
			afterRace[2] != 0 || afterRace[5] != 0 {
			fail("%s: race witness attempts=%d commits=%d inflight=%d auth_inflight=%d for %d contender calls and %d evaluated receipts",
				label, race[0], race[1], afterRace[2], afterRace[5], contender.calls, evaluated)
		}
	} else if raceWitness != nil && race[0] != 0 {
		fail("%s: %d contender attempts without a contender", label, race[0])
	}
	for i := range afterOutcomes {
		v.outcomes[i] += afterOutcomes[i] - beforeOutcomes[i]
	}
	// Decision 3 witness: refusal and unevaluated rates at this quota,
	// concurrency and reaper latency.
	pct := func(n, d uint64) float64 {
		if d == 0 {
			return 0
		}
		return 100 * float64(n) / float64(d)
	}
	unconstructedBirths := constructFailures + sourceRefusals + missingTarget
	if strict {
		refusals := uint64(refused+threadsFailed) + uint64(exits[77])
		v.t.Logf("%s: Strict rates: births refused %.1f%% (%d/%d), evaluation WORK refused %.1f%% (%d/%d), total fail-closed refusals %.1f%% (%d/%d)",
			label, pct(uint64(refused+threadsFailed), attempts), refused+threadsFailed, attempts,
			pct(evalRefused, evalEntered), evalRefused, evalEntered, pct(refusals, attempts), refusals, attempts)
	} else {
		unevaluated := uint64(exits[0]) - min(evaluated, uint64(exits[0]))
		v.t.Logf("%s: Audit rates: births unconstructed %.1f%% (%d/%d), evaluation WORK refused %.1f%% (%d/%d), children unevaluated %.1f%% (%d/%d)",
			label, pct(unconstructedBirths, attempts), unconstructedBirths, attempts,
			pct(evalRefused, evalEntered), evalRefused, evalEntered, pct(unevaluated, uint64(exits[0])), unevaluated, exits[0])
	}
	// The product-visible witness must count exactly the fail-closed
	// outcomes the test-only witnesses saw, class by class.
	afterRates := v.counters(label, rateWitness, v.rateCells(label, rateWitness))
	afterExclusions := v.counters(label, exclusionWitness, 3)
	var exclusions [3]uint64
	for i := range exclusions {
		exclusions[i] = afterExclusions[i] - beforeExclusions[i]
	}
	var rateBefore, rateAfter [FailClosedRateClasses]uint64
	copy(rateBefore[:], beforeRates)
	copy(rateAfter[:], afterRates)
	retryExhausted := afterRates[FailClosedRateWorkRetry] - beforeRates[FailClosedRateWorkRetry]
	rates, rateErr := FailClosedRate(rateBefore, rateAfter, attempts, 0)
	if rateErr != nil {
		fail("%s: fail-closed rate witness: %v", label, rateErr)
	}
	// classesExact: every witness class has an independent test-only
	// expected value and equals it (the over-capacity burst gate's
	// "every refusal exactly counted").
	classesExact := false
	if rateWitness != nil {
		// The eval-WORK and storage classes have an independent expected
		// value only with their test-only witness; without it the slot
		// prints "na" and is skipped, never derived from the value under
		// test.
		// The G019 M0 classes have an exact expected value only with
		// their test-only witness; the reserved gap class must stay 0.
		want := [FailClosedRateClasses]uint64{
			out[4], sourceRefusals, missingTarget,
			evalRefused + evalChargedFailed, storageQuarantined, out[2] + out[3] + out[5] + out[6],
			exclusions[0], exclusions[1], exclusions[2], 0,
		}
		known := [FailClosedRateClasses]bool{
			true, true, true,
			evalWitness != nil, storageWitness != nil, true,
			exclusionWitness != nil, exclusionWitness != nil, exclusionWitness != nil, true,
		}
		wantText := make([]string, FailClosedRateClasses)
		match := true
		for i := range want {
			wantText[i] = "na"
			if known[i] {
				wantText[i] = strconv.FormatUint(want[i], 10)
				match = match && rates.Failures[i] == want[i]
			}
		}
		if !match {
			fail("%s: fail-closed rate witness %v, want [LIMIT source missing-target eval-WORK storage construct qualify pending open-parent gap] %v",
				label, rates.Failures, wantText)
		}
		classesExact = match && rateErr == nil && !slices.Contains(known[:], false)
		// Retry-bound exhaustions are refusals already counted as a source
		// or evaluation refusal, or a refused terminal fallback.
		if retryExhausted > rates.Failures[1]+rates.Failures[3]+outcomeDelta[3] {
			fail("%s: %d WORK retry-bound exhaustions exceed %d source + %d evaluation refusals + %d refused fallbacks",
				label, retryExhausted, rates.Failures[1], rates.Failures[3], outcomeDelta[3])
		}
		if rates.Degraded != (rates.Total != 0) {
			fail("%s: fail-closed rate verdict %+v: degraded must follow any nonzero witness delta", label, rates)
		}
	}
	// One machine-greppable line per run for the requalification rate
	// table. refused: Strict births refused, Audit births unconstructed (per
	// attempt). unevaluated: forked children never evaluated (per fork
	// attempt). eval_refused: evaluation WORK refused per entry (na without
	// the witness). witness: the fail-closed rate witness deltas (na without
	// the candidate) and its degraded verdict at threshold 0.
	forkAttempts := uint64(forked + refused)
	refusedBirths := uint64(refused + threadsFailed)
	if !strict {
		refusedBirths = unconstructedBirths
	}
	evalRate, witness := "na", "na"
	if evalWitness != nil {
		evalRate = fmt.Sprintf("%.1f%%", pct(evalRefused, evalEntered))
	}
	if rateWitness != nil {
		witness = fmt.Sprintf("%d/%d/%d/%d/%d/%d/%d/%d/%d/%d retry_exhausted=%d degraded=%v", rates.Failures[0], rates.Failures[1],
			rates.Failures[2], rates.Failures[3], rates.Failures[4], rates.Failures[5], rates.Failures[6], rates.Failures[7],
			rates.Failures[8], rates.Failures[9], retryExhausted, rates.Degraded)
	}
	// fail_closed: every fail-closed outcome (Strict: refused births + exit
	// 77; Audit: unconstructed births + quarantined readers). rate:
	// target/achieved births/sec (b2b: back to back). task_high/work_high:
	// sampled used high-water marks / quota. reap_lat: reaper first saw
	// DEAD -> TASK credit returned; reap_bound: previous pass start -> TASK
	// credit returned (upper bound on final free -> return); p50/p99/max.
	failClosed := refusedBirths + uint64(exits[77])
	if !strict {
		failClosed = unconstructedBirths + evalRefused + storageQuarantined
	}
	target := "b2b"
	if opts.birthRate > 0 {
		target = strconv.Itoa(opts.birthRate)
	}
	quantiles := func(d []time.Duration) string {
		if len(d) == 0 {
			return "na"
		}
		slices.Sort(d)
		return fmt.Sprintf("%s/%s/%s", d[len(d)/2], d[min(len(d)-1, len(d)*99/100)], d[len(d)-1])
	}
	v.t.Logf("RATE quota=%d/%d streams=%d threads=%d exhaust=%v class=%d refused=%.1f%% unevaluated=%.1f%% eval_refused=%s reaper_tick=%s attempts=%d births=%d evaluated=%d witness=%s rate=%s/%.1f fail_closed=%d task_high=%d/%d work_high=%d/%d reap_lat=%s reap_bound=%s",
		v.taskQuota, v.workQuota, streams, threadsPerRound, opts.exhaust, v.class,
		pct(refusedBirths, attempts), pct(forkAttempts-min(evaluated, forkAttempts), forkAttempts), evalRate,
		opts.reaperTick, attempts, forkAttempts, evaluated, witness, target, achieved, failClosed,
		taskHigh, v.taskQuota, workHigh, v.workQuota, quantiles(stats.reapLat), quantiles(stats.reapBound))
	// Burst capacity of this object's binding (G019 "gate at capacity"):
	// computed from the WORK quota, never pinned to one profile.
	capacity := int(ConcurrentBirthCapacity(v.workQuota, syncWitness != nil))
	// G019 burst gate (user decision): 8 burst streams are zero-gated (3
	// and 8 are both gated at 0; 32 stays the measured over-capacity run),
	// so an 8-stream burst on an object whose WORK quota gives a capacity
	// below 8 fails instead of being silently measured as over capacity.
	if opts.burst && syncWitness != nil && streams == 8 && capacity < 8 {
		fail("%s: burst gate FAILED: WORK quota %d gives capacity %d < the 8 zero-gated streams (the product profile is 128/32)", label, v.workQuota, capacity)
	}
	// Refusal attribution for the burst lines: the round period (send span
	// per round, back to back) next to the slowest reap, and the exact WORK
	// high-water when the object has its witness.
	roundPeriod := sendSpan / time.Duration(max(rounds, 1))
	workPeak := "na"
	if highWater != nil {
		var peak [2]uint64
		if err := highWater.Lookup(workAccount, &peak); err != nil {
			fail("%s: WORK high-water[%d]: %v", label, workAccount, err)
		} else {
			workPeak = fmt.Sprintf("%d/%d", peak[0], v.workQuota)
			if peak[1] != 0 || peak[0] > uint64(v.workQuota) {
				fail("%s: WORK high-water %d/%d lost %d raises: not exact", label, peak[0], v.workQuota, peak[1])
			}
		}
	}
	attribution := fmt.Sprintf("round=%s reap_max=%s work_peak=%s", roundPeriod, productStats.MaxLatency, workPeak)
	// Synchronous WORK return (option C): every settled WORK ends in
	// exactly one outcome; any pending, fault or stuck is a slow path that
	// waits for the reaper (Degraded) and fails the run. contended (the
	// reaper held the visit claim) is benign and printed for attribution.
	if syncWitness != nil {
		d := syncDelta
		settled := d[workSyncSettledBirth] + d[workSyncSettledExec] + d[workSyncSettledDeath]
		attribution += fmt.Sprintf(" sync=settled:%d/%d/%d,returned:%d,contended:%d,stale:%d,pending:%d,fault:%d,stuck:%d reaper-claim-held=%d",
			d[workSyncSettledBirth], d[workSyncSettledExec], d[workSyncSettledDeath], d[workSyncReturned],
			d[workSyncClaimLost], d[workSyncStale], d[workSyncPending], d[workSyncFault], d[workSyncStuck], productStats.ClaimHeld)
		if d[workSyncPending]+d[workSyncFault]+d[workSyncStuck] != 0 {
			fail("%s: synchronous WORK return slow path: %s", label, attribution)
		}
		if d[workSyncReturned]+d[workSyncClaimLost]+d[workSyncStale] != settled {
			fail("%s: synchronous WORK return outcomes do not add up to the %d settled WORKs: %s", label, settled, attribution)
		}
		// Every constructed child settles its birth WORK in the fork and
		// every completed exec its evaluation WORK at the terminal (the
		// zero gate below makes these exact for a refusal-free burst).
		if opts.burst && streams <= capacity && (d[workSyncSettledBirth] != constructOK || d[workSyncSettledExec] != outcomeDelta[0]) {
			fail("%s: synchronous WORK return settled birth %d exec %d, want %d constructed births and %d completed execs: %s",
				label, d[workSyncSettledBirth], d[workSyncSettledExec], constructOK, outcomeDelta[0], attribution)
		}
		// Tight WORK bound: the retained parent WORKs, the birth WORK of
		// the fork in flight, one WORK per racing child and one per thread.
		if highWater != nil && opts.burst && streams <= capacity {
			var peak [2]uint64
			if err := highWater.Lookup(workAccount, &peak); err == nil &&
				peak[0] > uint64(len(v.parentWorks)+1+streams+threadsPerRound) {
				fail("%s: WORK peak %d above retained %d + 1 + %d streams + %d threads with the synchronous return: %s",
					label, peak[0], len(v.parentWorks), streams, threadsPerRound, attribution)
			}
		}
	}
	// G019 lead decision (b): without the synchronous WORK return no static
	// capacity holds under reap latency (ConcurrentBirthCapacity(W, false)
	// is advisory, test only), so a non-sync burst is measured like an
	// over-capacity one: every refusal counted in its class, never
	// zero-gated. The product requires the synchronous return.
	measuredOnly := syncWitness == nil
	mode := fmt.Sprintf("over capacity streams=%d > capacity=%d", streams, capacity)
	if measuredOnly && streams <= capacity {
		mode = fmt.Sprintf("non-sync measured (advisory capacity %d, not zero-gated) streams=%d", capacity, streams)
	}
	if opts.requireZeroFailClosed && opts.burst && (streams > capacity || measuredOnly) {
		// Over capacity or non-sync: refusals are measured, never hidden.
		// Same per-run witness delta as the RATE line; the pass line prints
		// only the gate's own values.
		gate, gateErr := burstOverCapacityGate(beforeRates, afterRates, attempts, forkAttempts, evaluated, failClosed, strict, classesExact)
		if gateErr == nil && opts.expectRefusals && gate.Rates.Total == 0 {
			gateErr = fmt.Errorf("designed to overflow the WORK quota but no refusal was counted")
		}
		if gateErr != nil {
			fail("%s: burst gate FAILED: %s quota=%d/%d %s over %d births: %v",
				label, mode, v.taskQuota, v.workQuota, attribution, forkAttempts, gateErr)
		} else {
			v.t.Logf("%s: burst gate: %s quota=%d/%d %s witness fail_closed=%d %v (%.2f%% of %d attempts) degraded=%v unevaluated=%d retry_exhausted=%d over %d births (%d evaluated), every refusal counted in its class; reap latency %s; %s",
				label, mode, v.taskQuota, v.workQuota, attribution, gate.Rates.Total, gate.Rates.Failures, 100*gate.Rates.Rate, attempts,
				gate.Rates.Degraded, gate.Unevaluated, gate.RetryExhausted, forkAttempts, evaluated, quantiles(stats.reapLat), productStats)
		}
	} else if opts.requireZeroFailClosed {
		// Same per-run witness delta as the RATE line. The pass lines
		// print only on a pass and only the gate's own values: a failed
		// gate must never also log "fail_closed=0".
		gate, gateErr := zeroFailClosedGate(beforeRates, afterRates, attempts, forkAttempts, evaluated, uint64(refused), failClosed)
		if gateErr != nil {
			fail("%s: steady-state gate FAILED over %d births: %v", label, forkAttempts, gateErr)
			if opts.burst {
				fail("%s: burst gate FAILED: streams=%d capacity=%d quota=%d/%d %s over %d births: %v",
					label, streams, capacity, v.taskQuota, v.workQuota, attribution, forkAttempts, gateErr)
			}
		} else {
			v.t.Logf("%s: steady-state gate: witness fail_closed=%d unevaluated=%d over %d births (%d evaluated)",
				label, gate.Rates.Total, gate.Unevaluated, forkAttempts, evaluated)
			if opts.burst {
				v.t.Logf("%s: burst gate: streams=%d capacity=%d quota=%d/%d %s witness fail_closed=%d unevaluated=%d over %d births; reap latency %s; %s",
					label, streams, capacity, v.taskQuota, v.workQuota, attribution, gate.Rates.Total, gate.Unevaluated, forkAttempts, quantiles(stats.reapLat), productStats)
			}
		}
	}
	// G019 burst gate (credit at exit): the TASK credit must return at
	// exit, so the burst never fills the quota, wakeups (not the fallback
	// sweep) return it, and the tombstones never overflow.
	if opts.burst {
		if taskHigh >= v.taskQuota {
			fail("%s: burst gate FAILED: TASK high-water %d reached the quota %d", label, taskHigh, v.taskQuota)
		}
		if productStats.SweepReaps*10 > productStats.EventReaps {
			fail("%s: burst gate FAILED: %d sweep reaps for %d event reaps, want event reaps >= 10x sweep reaps",
				label, productStats.SweepReaps, productStats.EventReaps)
		}
		if exitWitness != nil {
			capacity := uint64(v.c.Maps["se_exit_tombstones"].MaxEntries())
			// No refused insert, no stale tombstone, no faulted settlement
			// and the high-water below the Degraded threshold.
			if exit.SlowPath != exit.Delta[ExitCreditDirPending]+exit.Delta[ExitCreditUnsettled] || exit.Faults != 0 || exit.HighWater {
				fail("%s: burst gate FAILED: tombstones %s (capacity %d), want no refused insert, no fault and high-water below %d%%",
					label, exit, capacity, ExitCreditHighWaterPercent)
			}
		}
	}
	for slot, cookie := range v.parentWorks {
		if v.charge("se_opaque_work_charges", slot) != cookie {
			fail("%s: parent retained WORK slot %d was reaped", label, slot)
		}
	}
	var key, value uint64
	keys := v.c.Maps["se_opaque_keys"].Iterate()
	for keys.Next(&key, &value) {
		if key != v.parent {
			fail("%s: child TASK %#x survived quiescence", label, key)
		}
	}
	if keys.Err() != nil {
		fail("%s: %v", label, keys.Err())
	}
	var receipt [64]byte
	receipts := v.c.Maps["se_exec_terminal_receipts"].Iterate()
	for receipts.Next(&key, &receipt) {
		if key != v.parent {
			fail("%s: child terminal receipt %#x (phase %d) survived quiescence", label, key,
				binary.LittleEndian.Uint32(receipt[opaqueReceiptPhaseOffset:]))
		}
	}
	if receipts.Err() != nil {
		fail("%s: %v", label, receipts.Err())
	}
	if failed {
		v.dump(label)
		v.t.FailNow()
	}
	v.parentQualified(label)
	v.t.Logf("%s: %d Strict fail-closed exits (77) and %d refused forks under transient WORK exhaustion; %d Audit unevaluated children; every child TASK/WORK refunded exactly",
		label, exits[77], forkRefused[int(unix.EPERM)], uint64(exits[0])-min(evaluated, uint64(exits[0])))
}

// counters reads n uint64 cells of a test-only witness ARRAY; a nil map (an
// object built without that witness) reads as zeros.
// failClosedInject (G019) drives one deterministic fail-closed injector over
// births racing children, 3 per round, each round reaped before the next:
//   - pending (FORKR): every Nth exact success terminal is skipped, so the
//     REGISTERED receipt stays pending and the same task's next exec (the
//     helper's "reexec" of /bin/true) meets it: rate [7], exclusion [1];
//   - open-parent (FORKG): every Nth grandchild birth target fails to open
//     its parent TASK (the helper's own births are no edge): rate [8],
//     exclusion [2]; the TASK-less grandchild's exec then fails closed;
//   - qualify (FORKN): every Nth successful first-exec qualification at
//     bprm_check is a fault: rate [6], exclusion [0].
//
// The rate class and exact witness deltas must equal the injected count.
// Strict refuses exactly the injected children's exec (77), Audit runs them
// unevaluated (0). Every TASK/WORK credit returns, and no child terminal
// receipt survives final free.
func (v *opaqueVerdictRun) failClosedInject(kind string, every, births int) {
	v.t.Helper()
	label := "inject-" + kind
	type injector struct {
		selector, rate, exclusion int
		command                   string
	}
	inj, ok := map[string]injector{
		"pending":     {0, 7, 1, "FORKR:%d\n"},
		"open-parent": {1, 8, 2, "FORKG:%d\n"},
		"qualify":     {2, 6, 0, "FORKN:%d:0\n"},
	}[kind]
	selectorMap, countsMap := v.c.Maps["opaque_real_fc_inject_selector"], v.c.Maps["opaque_real_fc_inject_counts"]
	rateWitness, exclusionWitness := v.c.Maps["opaque_real_fail_closed_rates"], v.c.Maps["opaque_real_exec_exclusions"]
	receipts := v.c.Maps["se_exec_terminal_receipts"]
	if !ok || selectorMap == nil || countsMap == nil || rateWitness == nil || exclusionWitness == nil || receipts == nil {
		v.t.Fatalf("%s: needs an object built with ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_DIAGNOSTIC", label)
	}
	strict := v.class == 2
	baseTasks, baseWorks := v.accounts(label)
	beforeRates := v.counters(label, rateWitness, v.rateCells(label, rateWitness))
	beforeExclusions := v.counters(label, exclusionWitness, 3)
	beforeCounts := v.counters(label, countsMap, 6)
	// Mirrors struct opaque_real_fc_inject_selector.
	type selector struct {
		Every      [3]uint32
		Reserved   uint32
		SkipParent uint64
	}
	set := func(n int) {
		value := selector{SkipParent: v.parent}
		value.Every[inj.selector] = uint32(n)
		if err := selectorMap.Update(uint32(0), &value, ebpf.UpdateAny); err != nil {
			v.t.Fatalf("%s: selector: %v", label, err)
		}
	}
	set(every)
	defer set(0)
	flagsOffset, flagsSize := opaqueSourceField(v.t, v.taskType, []string{"flags"})
	stats := &opaqueReaperStats{
		workStarted: map[uint32]uint64{}, taskStarted: map[uint32]uint64{},
		taskAborted: map[uint32]bool{}, deadSeen: map[uint32][2]time.Time{},
	}
	settled := func() bool {
		for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			if err := v.reapPass(stats, flagsOffset, flagsSize); err != nil {
				v.t.Fatalf("%s: reaper: %v", label, err)
			}
			if tasks, works := v.accounts(label); tasks == baseTasks && works == baseWorks {
				return true
			}
		}
		return false
	}
	exits := map[int]int{}
	for sent := 0; sent < births; {
		k := min(3, births-sent)
		if _, err := fmt.Fprintf(v.stdin, inj.command, k); err != nil {
			v.t.Fatal(err)
		}
		for range k {
			line, err := v.stdout.ReadString('\n')
			if err != nil {
				v.t.Fatalf("%s: %v stderr=%q", label, err, v.stderr.String())
			}
			var pid, code int
			if n, _ := fmt.Sscanf(line, "FORKED:%d:%d\n", &pid, &code); n != 2 || pid <= 0 {
				v.t.Fatalf("%s: line=%q (a refused fork is not an injected fault)", label, line)
			}
			exits[code]++
		}
		if kind == "qualify" {
			// FORKN:<k>:0 ends each round with THREADED:0:0.
			if line, err := v.stdout.ReadString('\n'); err != nil || line != "THREADED:0:0\n" {
				v.t.Fatalf("%s: line=%q err=%v", label, line, err)
			}
		}
		sent += k
		if !settled() {
			tasks, works := v.accounts(label)
			v.leaks(label)
			v.t.Fatalf("%s: TASK %d WORK %d after %d births, want baseline %d/%d: an injected fault leaked a credit",
				label, tasks, works, sent, baseTasks, baseWorks)
		}
	}
	set(0)
	afterRates := v.counters(label, rateWitness, v.rateCells(label, rateWitness))
	afterExclusions := v.counters(label, exclusionWitness, 3)
	afterCounts := v.counters(label, countsMap, 6)
	edges := afterCounts[inj.selector] - beforeCounts[inj.selector]
	injected := afterCounts[3+inj.selector] - beforeCounts[3+inj.selector]
	rateDeltas := make([]uint64, len(afterRates))
	for i := range afterRates {
		rateDeltas[i] = afterRates[i] - beforeRates[i]
	}
	exclusionDelta := afterExclusions[inj.exclusion] - beforeExclusions[inj.exclusion]
	n := uint64(every)
	v.t.Logf("%s: INJECT every %d: %d edges, %d injected; rate deltas %v, exclusion[%d] +%d; exits %v; %d births; TASK/WORK back to %d/%d",
		label, every, edges, injected, rateDeltas, inj.exclusion, exclusionDelta, exits, births, baseTasks, baseWorks)
	fail := v.t.Errorf
	// The selector fires on exactly every Nth edge counted while enabled.
	if injected == 0 || injected != (beforeCounts[inj.selector]+edges)/n-beforeCounts[inj.selector]/n {
		fail("%s: %d injected for %d edges every %d", label, injected, edges, every)
	}
	if rateDeltas[inj.rate] != injected {
		fail("%s: fail-closed rate [%d] +%d, want exactly %d injected", label, inj.rate, rateDeltas[inj.rate], injected)
	}
	if exclusionDelta != injected {
		fail("%s: exec exclusion witness [%d] +%d, want exactly %d injected", label, inj.exclusion, exclusionDelta, injected)
	}
	if strict {
		if uint64(exits[77]) != injected || exits[0]+exits[77] != births {
			fail("%s: Strict exits %v, want %d refused (77) and the rest 0", label, exits, injected)
		}
	} else if exits[0] != births {
		fail("%s: Audit exits %v, want all %d nonblocking (0)", label, exits, births)
	}
	// Final free retires each exact child receipt (a pending one included).
	var key uint64
	var value []byte
	for it := receipts.Iterate(); it.Next(&key, &value); {
		if key != v.parent {
			fail("%s: terminal receipt of %#x survived final free", label, key)
		}
	}
	v.t.Logf("%s: every TASK/WORK credit refunded after %d injected faults", label, injected)
}

// rateCells is the fail-closed rate witness size of this object:
// FailClosedRateCounters (13: WORK retry, ENTRY, ADMISSION) with the product
// publisher, FailClosedRateLegacyCounters (11: WORK retry) without; anything
// else is fatal (FailClosedRateCells).
func (v *opaqueVerdictRun) rateCells(label string, m *ebpf.Map) int {
	v.t.Helper()
	if m == nil {
		return FailClosedRateCounters
	}
	n, err := FailClosedRateCells(m.MaxEntries())
	if err != nil {
		v.t.Fatalf("%s: %v", label, err)
	}
	return n
}

// interpStats reads the interpreter continuation witness
// (InterpContinuationStatsMap); an object without it fails the test.
func (v *opaqueVerdictRun) interpStats(label string) []uint64 {
	v.t.Helper()
	m := v.c.Maps[InterpContinuationStatsMap]
	if m == nil || m.MaxEntries() != InterpContinuationStats {
		v.t.Fatalf("%s: object lacks the %d-cell %s", label, InterpContinuationStats, InterpContinuationStatsMap)
	}
	return v.counters(label, m, InterpContinuationStats)
}

func (v *opaqueVerdictRun) counters(label string, m *ebpf.Map, n int) []uint64 {
	v.t.Helper()
	out := make([]uint64, n)
	if m == nil {
		return out
	}
	for i := range out {
		if err := m.Lookup(uint32(i), &out[i]); err != nil {
			v.t.Fatalf("%s: witness %d: %v", label, i, err)
		}
	}
	return out
}

// syncReturn reports whether the object returns WORK credit synchronously at
// settle (G019 option C, opaque_real_work_sync present). There a DONE WORK is
// returned by the settling program itself: it is no longer charged when the
// harness settles a round, its payload is already zeroed, and the harness
// asserts the settlement through the witness instead.
func (v *opaqueVerdictRun) syncReturn() bool {
	return v.c.Maps[WorkSyncWitnessMap] != nil
}

// syncSettled is the synchronous WORK return witness delta since before
// (from v.counters on WorkSyncWitnessMap): the WORKs settled at birth and at
// the exec terminal, and the ones returned. Every settled WORK must end in
// exactly one outcome, and no slow path (pending, fault, stuck) is allowed.
// Zeros without the witness.
func (v *opaqueVerdictRun) syncSettled(label string, before []uint64) (birth, exec, returned uint64) {
	v.t.Helper()
	if !v.syncReturn() {
		return 0, 0, 0
	}
	after := v.counters(label, v.c.Maps[WorkSyncWitnessMap], workSyncCounters)
	var d [workSyncCounters]uint64
	for i := range d {
		d[i] = after[i] - before[i]
	}
	settled := d[workSyncSettledBirth] + d[workSyncSettledExec] + d[workSyncSettledDeath]
	if d[workSyncPending]+d[workSyncFault]+d[workSyncStuck] != 0 ||
		d[workSyncReturned]+d[workSyncClaimLost]+d[workSyncStale] != settled {
		v.t.Fatalf("%s: synchronous WORK return witness delta %v: want no pending/fault/stuck and every settled WORK in exactly one outcome", label, d)
	}
	return d[workSyncSettledBirth], d[workSyncSettledExec], d[workSyncReturned]
}

// workDecisionWitness is the test-only decision witness of the synchronous
// WORK return (ENFORCE_EXEC_POOL_OPAQUE_WORK_DECISION_WITNESS_DIAGNOSTIC):
// the evaluation decision snapshotted right before the return zeroes the
// payload. Value: count, cookie (u64), deny, mode (u32).
const workDecisionWitness = "opaque_real_work_decision"

// decisionReset clears the decision witness before a harness step.
func (v *opaqueVerdictRun) decisionReset(label string) {
	v.t.Helper()
	if m := v.c.Maps[workDecisionWitness]; m != nil {
		if err := m.Update(uint32(0), [3]uint64{}, ebpf.UpdateExist); err != nil {
			v.t.Fatalf("%s: reset %s: %v", label, workDecisionWitness, err)
		}
	}
}

// decisionFromWitness sets lastDeny (deny*10+mode) from the decision
// witness on objects with the synchronous WORK return, exactly as the
// harness's payload read before a reap does on the others: the last WORK
// that carried a decision wins, and none leaves it -1. A synchronous-return
// object without the witness fails: its decision check would be blind.
func (v *opaqueVerdictRun) decisionFromWitness(label string) {
	v.t.Helper()
	if !v.syncReturn() {
		return
	}
	m := v.c.Maps[workDecisionWitness]
	if m == nil {
		v.t.Fatalf("%s: synchronous-return object lacks %s (build with ENFORCE_EXEC_POOL_OPAQUE_WORK_DECISION_WITNESS_DIAGNOSTIC): the decision check would be blind", label, workDecisionWitness)
	}
	raw, err := m.LookupBytes(uint32(0))
	if err != nil || len(raw) < 24 {
		v.t.Fatalf("%s: %s: %v", label, workDecisionWitness, err)
	}
	if binary.LittleEndian.Uint64(raw[0:8]) != 0 {
		v.lastDeny = int(binary.LittleEndian.Uint32(raw[16:20]))*10 + int(binary.LittleEndian.Uint32(raw[20:24]))
	}
}

// exitCounters reads the credit-at-exit witness (zeros without it).
func (v *opaqueVerdictRun) exitCounters(label string) []uint64 {
	v.t.Helper()
	return v.counters(label, v.c.Maps["opaque_real_exit_credit"], ExitCreditCounters)
}

// exitCapacity is se_exit_tombstones' max_entries (0 without credit at exit).
func (v *opaqueVerdictRun) exitCapacity() uint64 {
	if m := v.c.Maps["se_exit_tombstones"]; m != nil {
		return uint64(m.MaxEntries())
	}
	return 0
}

func (v *opaqueVerdictRun) exitArray(raw []uint64) (out [ExitCreditCounters]uint64) {
	copy(out[:], raw)
	return out
}

// waitExitDrained waits (30 s) until every tombstone inserted since before
// was consumed: every settled or pending exit of the window freed, and Live
// no higher than before (tombstones held before the window may be consumed
// in it, so Live can end below its earlier value), and, with a product
// reaper, until it read every TASK FREED wakeup emitted since (no drops).
func (v *opaqueVerdictRun) waitExitDrained(label string, before []uint64, product *Reaper) {
	v.t.Helper()
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		now := v.exitCounters(label)
		own := (now[ExitCreditSettled] - before[ExitCreditSettled]) + (now[ExitCreditDirPending] - before[ExitCreditDirPending])
		drained := now[ExitCreditLive] <= before[ExitCreditLive] && now[ExitCreditFreed]-before[ExitCreditFreed] >= own
		if drained && product != nil {
			s, err := product.Stats()
			drained = err == nil && (s.Drops != 0 || s.Freed >= now[ExitCreditFreed]-before[ExitCreditFreed])
		}
		if drained {
			return
		}
		if time.Now().After(deadline) {
			v.t.Logf("%s: exit tombstones not drained in 30s: live %d (was %d), freed %d", label,
				now[ExitCreditLive], before[ExitCreditLive], now[ExitCreditFreed]-before[ExitCreditFreed])
			return
		}
	}
}

// exitTombstones lists the tombstones by stage and checks their shape.
func (v *opaqueVerdictRun) exitTombstones(label string) map[uint32]int {
	v.t.Helper()
	var key uint64
	var raw [opaqueExitTombSize]byte
	stages := map[uint32]int{}
	entries := v.c.Maps["se_exit_tombstones"].Iterate()
	for entries.Next(&key, &raw) {
		stage := binary.LittleEndian.Uint32(raw[opaqueExitTombStage:])
		if key == 0 || binary.LittleEndian.Uint64(raw[0:8]) == 0 || binary.LittleEndian.Uint64(raw[8:16]) == 0 ||
			binary.LittleEndian.Uint64(raw[16:24]) == 0 ||
			binary.LittleEndian.Uint32(raw[opaqueExitTombSlot:]) >= v.spec.Maps["se_opaque_charges"].MaxEntries ||
			binary.LittleEndian.Uint32(raw[opaqueExitTombAccount:]) >= v.spec.Maps["opaque_real_exit_accounts"].MaxEntries {
			v.t.Fatalf("%s: malformed tombstone %#x stage %d: %x", label, key, stage, raw)
		}
		stages[stage]++
	}
	if err := entries.Err(); err != nil {
		v.t.Fatalf("%s: tombstones: %v", label, err)
	}
	return stages
}

// Tombstone stages (REAL_OWNER_EXIT_*) and the struct
// real_owner_exit_tombstone wire: cookie, locator, start (u64), then slot,
// stage, flags, account (u32).
const (
	opaqueExitReserved    = 1
	opaqueExitSettled     = 2
	opaqueExitDirPending  = 3
	opaqueExitFreePending = 4
	opaqueExitRetiring    = 5
	opaqueExitFreedStage  = 6

	opaqueExitTombSize    = 40
	opaqueExitTombSlot    = 24
	opaqueExitTombStage   = 28
	opaqueExitTombFlags   = 32
	opaqueExitTombAccount = 36
)

// freeDelay is the G019 credit-at-exit free-delay injector (userspace, no
// RCU hacking): the helper forks n children one after another (ZOMBIE:n);
// each execs, is evaluated and exits but is never reaped, so its task_free
// cannot run while it is a zombie. The credit of every child whose
// tombstone was inserted and whose exit settlement completed must return
// at exit: with n above the TASK quota, n births without a refusal prove
// it. With the BPF exit injector armed (dirEvery, mode; see the
// IG_OPAQUE_REAL_VERDICT_INJECT_EXIT_MODE comment) every Kth exit
// withdrawal stops before stage 1, after stage 1 or after stage 2
// (DIR_PENDING, the directory state the free-time resume must enter from is
// checked per tombstone), or every Kth exit settles nothing (UNSETTLED or
// UNSETTLED_FAULT: the task_free fallback settles it). Births beyond the
// binding's tombstone share (an object built with
// SE_TEST_EXIT_TOMBSTONE_ENTRIES) overflow to the task_free fallback. Each
// slow path is counted exactly and reported Degraded unless benign
// (UNSETTLED). UNZOMBIE then reaps them: every tombstone drains through
// task_free (TASK FREED), every pending withdrawal resumes there and every
// overflowed or unsettled child is settled by the fallback; nothing is
// quarantined. A product reaper sweep of a DIR_PENDING charge (its exit
// lease held) is PENDING at every injected stage, never a reap fault. With
// disarm (IG_OPAQUE_REAL_VERDICT_EXIT_GATE_DISARM) the
// image gate is disarmed after every child exited and before UNZOMBIE, so
// every free runs with the gate off: each must still consume its own
// tombstone (Live drains while the gate is off, nothing falls back), then
// the gate is re-armed.
func (v *opaqueVerdictRun) freeDelay(n, dirEvery, mode int, disarm bool) {
	v.t.Helper()
	label := fmt.Sprintf("free-delay %d", n)
	if disarm {
		label += " (gate disarmed before the reap)"
	}
	tombs, accounts := v.c.Maps["se_exit_tombstones"], v.c.Maps["opaque_real_exit_accounts"]
	inject, injectCounts := v.c.Maps["opaque_real_exit_inject_every"], v.c.Maps["opaque_real_exit_inject_counts"]
	if tombs == nil || accounts == nil || v.c.Maps["opaque_real_exit_credit"] == nil {
		v.t.Fatalf("%s: needs an object built with ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE", label)
	}
	if dirEvery > 0 && (inject == nil || injectCounts == nil) {
		v.t.Fatalf("%s: the exit injector needs ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_DIAGNOSTIC", label)
	}
	capacity := uint64(tombs.MaxEntries())
	share := capacity / uint64(accounts.MaxEntries())
	inserted := min(uint64(n), share)
	// Without overflow the run must prove early credit: more births than
	// the TASK quota while every child is a zombie, injected or not.
	if inserted == uint64(n) && n <= int(v.taskQuota) {
		v.t.Fatalf("%s: needs more births than the TASK quota %d (or an overflowing tombstone share %d)", label, v.taskQuota, share)
	}
	if disarm && inserted != uint64(n) {
		v.t.Fatalf("%s: a disarmed gate runs no fallback: needs every birth inserted (share %d < %d)", label, share, n)
	}
	gateMap := v.c.Maps["opaque_real_owner_child_gate"]
	setGate := func(armed uint32) {
		v.t.Helper()
		if err := gateMap.Update(uint32(0), armed, ebpf.UpdateAny); err != nil {
			v.t.Fatalf("%s: image gate %d: %v", label, armed, err)
		}
	}
	if disarm {
		defer setGate(1)
	}
	if left := v.childTasks(label); len(left) != 0 {
		v.t.Fatalf("%s: %d child TASKs still charged before the injector", label, len(left))
	}
	// No tombstone of an earlier phase may still await its free: the
	// capacity and stale counts below must be this phase's alone.
	for deadline := time.Now().Add(30 * time.Second); v.exitCounters(label)[ExitCreditLive] != 0; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			v.t.Fatalf("%s: %d tombstones of earlier phases never freed", label, v.exitCounters(label)[ExitCreditLive])
		}
	}
	setInject := func(k, m int) {
		if inject != nil {
			if err := inject.Update(uint32(1), uint32(m), ebpf.UpdateAny); err != nil {
				v.t.Fatalf("%s: exit injector mode: %v", label, err)
			}
			if err := inject.Update(uint32(0), uint32(k), ebpf.UpdateAny); err != nil {
				v.t.Fatalf("%s: exit injector: %v", label, err)
			}
		}
	}
	setInject(dirEvery, mode)
	defer setInject(0, 0)
	beforeInject := v.counters(label, injectCounts, 2)
	before := v.exitArray(v.exitCounters(label))
	baseTasks, baseWorks := v.accounts(label)
	beforeEvals, _ := v.progress()
	flagsOffset, flagsSize := opaqueSourceField(v.t, v.taskType, []string{"flags"})
	stats := &opaqueReaperStats{
		workStarted: map[uint32]uint64{}, taskStarted: map[uint32]uint64{},
		taskAborted: map[uint32]bool{}, deadSeen: map[uint32][2]time.Time{},
	}
	product, err := NewReaper(v.c, ReaperConfig{Hooks: v.productReaperHooks(stats, flagsOffset, flagsSize)})
	if err != nil {
		v.t.Fatalf("%s: product reaper: %v", label, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	if err := product.Start(ctx); err != nil {
		cancel()
		v.t.Fatalf("%s: product reaper: %v", label, err)
	}
	stopped := false
	stop := func() error {
		if stopped {
			return nil
		}
		stopped = true
		cancel()
		return product.Wait()
	}
	defer func() { _ = stop() }()

	if _, err := fmt.Fprintf(v.stdin, "ZOMBIE:%d\n", n); err != nil {
		v.t.Fatal(err)
	}
	exits, refused := map[int]int{}, map[int]int{}
	for i := 0; i < n; i++ {
		line, err := v.stdout.ReadString('\n')
		var pid, code int
		if err != nil {
			v.t.Fatalf("%s: %v stderr=%q", label, err, v.stderr.String())
		}
		if k, _ := fmt.Sscanf(line, "FORKED:%d:%d\n", &pid, &code); k != 2 {
			v.t.Fatalf("%s: line=%q", label, line)
		}
		if pid < 0 {
			refused[code]++
		} else {
			exits[code]++
		}
	}
	// While every child is a zombie, only the slow-path children (refused
	// withdrawal or insert, unsettled exit) may still hold a TASK credit.
	var mid ExitCreditVerdict
	var tasks, works uint32
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if mid, err = ExitCredit(before, v.exitArray(v.exitCounters(label)), capacity); err != nil {
			v.t.Fatalf("%s: %v", label, err)
		}
		tasks, works = v.accounts(label)
		if uint64(tasks) == uint64(baseTasks)+mid.SlowPath {
			break
		}
		if time.Now().After(deadline) {
			// A product reaper that stopped on a reap fault returns no
			// credit at all: report its error with the count.
			v.t.Fatalf("%s: TASK used %d with %d zombies, want baseline %d + %d slow-path (%s); product reaper: %v",
				label, tasks, n, baseTasks, mid.SlowPath, mid, stop())
		}
	}
	// The product reaper's sweep visits every DIR_PENDING charge while its
	// exit lease is held: DEAD at PUBLISHED, WITHDRAW_CLAIM or
	// WITHDRAWN_ZERO. Each visit must be PENDING; a fault stops the reaper
	// (no further sweep completes) and every later credit with it.
	if dirEvery > 0 && mode <= 3 {
		s0, err := product.Stats()
		if err != nil {
			v.t.Fatalf("%s: product reaper stats: %v", label, err)
		}
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
			s, err := product.Stats()
			if err == nil && s.Sweeps >= s0.Sweeps+2 {
				break
			}
			if time.Now().After(deadline) {
				v.t.Fatalf("%s: product reaper completed %d sweeps over the DIR_PENDING charges in 5s, want 2: %v",
					label, s.Sweeps-s0.Sweeps, stop())
			}
		}
		if tasks, _ = v.accounts(label); uint64(tasks) != uint64(baseTasks)+mid.SlowPath {
			v.t.Fatalf("%s: TASK used %d after the sweeps, want baseline %d + %d slow-path", label, tasks, baseTasks, mid.SlowPath)
		}
	}
	d := mid.Delta
	afterInject := v.counters(label, injectCounts, 2)
	injected, edges := afterInject[1]-beforeInject[1], afterInject[0]-beforeInject[0]
	evals, _ := v.progress()
	failed := false
	fail := func(format string, args ...any) {
		failed = true
		v.t.Errorf(format, args...)
	}
	// Expected outcome of every inserted exit by injector mode.
	var wantPending, wantUnsettled, wantUnsettledFault uint64
	switch {
	case dirEvery == 0:
	case mode <= 3:
		wantPending = injected
	case mode == 4:
		wantUnsettled = injected
	default:
		wantUnsettledFault = injected
	}
	unsettled := wantUnsettled + wantUnsettledFault
	if len(refused) != 0 || exits[0] != n || evals-beforeEvals != uint64(n) {
		fail("%s: exits %v refusals %v evaluated %d, want %d children allowed and evaluated", label, exits, refused, evals-beforeEvals, n)
	}
	if d[ExitCreditInserted] != inserted || d[ExitCreditAccountOverflow] != uint64(n)-inserted ||
		d[ExitCreditOverflow]+d[ExitCreditBusy]+d[ExitCreditBlocked]+d[ExitCreditStale] != 0 ||
		d[ExitCreditUnsettled] != wantUnsettled || d[ExitCreditUnsettledFault] != wantUnsettledFault ||
		d[ExitCreditDirPending] != wantPending || d[ExitCreditSettled] != inserted-wantPending-unsettled {
		fail("%s: %s, want %d inserted (share %d of %d), %d binding overflow, %d dir-pending, %d+%d unsettled, the rest settled",
			label, mid, inserted, share, capacity, uint64(n)-inserted, wantPending, wantUnsettled, wantUnsettledFault)
	}
	if d[ExitCreditFreed] != 0 || d[ExitCreditFallbackFree] != 0 || d[ExitCreditDirResumed]+d[ExitCreditDirFaulted] != 0 {
		fail("%s: %s with every child a zombie, want no free", label, mid)
	}
	stages := v.exitTombstones(label)
	if d[ExitCreditLive] != inserted-unsettled || d[ExitCreditHighWater] < inserted-unsettled || d[ExitCreditHighWater] > share ||
		stages[opaqueExitSettled] != int(d[ExitCreditSettled]) || stages[opaqueExitDirPending] != int(d[ExitCreditDirPending]) ||
		len(stages) > 2 {
		fail("%s: %s tombstones by stage %v, want %d live: %d SETTLED, %d DIR_PENDING", label, mid, stages,
			inserted-unsettled, d[ExitCreditSettled], d[ExitCreditDirPending])
	}
	if held := v.exitAccountsHeld(label); held != d[ExitCreditLive] {
		fail("%s: binding tombstone gauges hold %d, want %d live", label, held, d[ExitCreditLive])
	}
	// Every inserted exit reached the injected edge (record_death for the
	// unsettled modes, the withdrawal otherwise: no receipt stayed at a
	// child's key), so with the injector armed each one is an edge.
	if every := uint64(dirEvery); (every > 0 && (edges != inserted || injected != afterInject[0]/every-beforeInject[0]/every || injected == 0)) ||
		(every == 0 && injected+edges != 0) {
		fail("%s: %d injected over %d edges every %d mode %d (inserted %d)", label, injected, edges, dirEvery, mode, inserted)
	}
	if dirEvery > 0 && mode <= 3 {
		v.exitPendingDirectory(label, fail, []uint64{1: opaqueDirectoryPublished, 2: opaqueDirectoryWithdrawClaim, 3: opaqueDirectoryWithdrawnZero}[mode])
	}
	if want := d[ExitCreditAccountOverflow]+d[ExitCreditDirPending]+d[ExitCreditUnsettledFault] != 0; mid.Degraded != want {
		fail("%s: verdict %s: degraded must follow overflow, refused withdrawals and faulted settlements (want %v)", label, mid, want)
	}
	proof := "na"
	if n > int(v.taskQuota) {
		proof = fmt.Sprintf("%d births > TASK quota %d with every child a zombie (%d slow path)", n, v.taskQuota, mid.SlowPath)
	}
	v.t.Logf("%s: zombies: TASK used %d (baseline %d) WORK %d (baseline %d); credit at exit: %s; %s", label, tasks, baseTasks, works, baseWorks, proof, mid)

	if disarm {
		setGate(0)
	}
	if _, err := io.WriteString(v.stdin, "UNZOMBIE\n"); err != nil {
		v.t.Fatal(err)
	}
	if line, err := v.stdout.ReadString('\n'); err != nil || line != fmt.Sprintf("UNZOMBIED:%d\n", n) {
		v.t.Fatalf("%s: line=%q err=%v stderr=%q", label, line, err, v.stderr.String())
	}
	freed := inserted - unsettled
	var final ExitCreditVerdict
	for deadline := time.Now().Add(30 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if final, err = ExitCredit(before, v.exitArray(v.exitCounters(label)), capacity); err != nil {
			v.t.Fatalf("%s: %v", label, err)
		}
		tasks, works = v.accounts(label)
		s, serr := product.Stats()
		if serr == nil && final.Delta[ExitCreditLive] == 0 && tasks == baseTasks && works == baseWorks &&
			s.Freed >= final.Delta[ExitCreditFreed] && final.Delta[ExitCreditFreed] >= freed {
			break
		}
		if time.Now().After(deadline) {
			fail("%s: after reaping the zombies: TASK %d WORK %d (baseline %d/%d), %s, reaper freed %d",
				label, tasks, works, baseTasks, baseWorks, final, s.Freed)
			break
		}
	}
	if disarm {
		// Every free above ran with the gate off: it was never re-armed.
		var armed uint32
		if err := gateMap.Lookup(uint32(0), &armed); err != nil || armed != 0 {
			fail("%s: image gate %d (err %v) after the frees, want 0 throughout", label, armed, err)
		}
		setGate(1)
	}
	if err := stop(); err != nil {
		fail("%s: product reaper: %v", label, err)
	}
	productStats, err := product.Stats()
	if err != nil {
		fail("%s: product reaper stats: %v", label, err)
	}
	if productStats.Faulted != 0 {
		fail("%s: product reaper quarantined %d faulted charges: %v", label, productStats.Faulted, product.Faults())
	}
	d = final.Delta
	if err := final.Quiescent(); err != nil {
		fail("%s: %v (%s)", label, err, final)
	}
	if d[ExitCreditFreed] != freed || d[ExitCreditFallbackFree] != uint64(n)-freed ||
		d[ExitCreditDirResumed] != d[ExitCreditDirPending] || d[ExitCreditDirFaulted] != 0 || d[ExitCreditReaperRetired] != 0 {
		fail("%s: %s, want %d freed, %d fallback settlements, every pending withdrawal resumed at free", label, final, freed, uint64(n)-freed)
	}
	if held := v.exitAccountsHeld(label); held != 0 {
		fail("%s: binding tombstone gauges hold %d after every free", label, held)
	}
	deadTasks := uint64(stats.tasks - stats.abortedTasks)
	if final.DeadSettlements() != uint64(n) || deadTasks != uint64(n) || stats.abortedTasks != 0 || stats.quarantinedTasks != 0 {
		fail("%s: reaper returned %d DEAD (%d aborted, %d quarantined) for %d settlements of %d children",
			label, deadTasks, stats.abortedTasks, stats.quarantinedTasks, final.DeadSettlements(), n)
	}
	// The reaper also reads wakeups still queued from before the window
	// (no reader then): at most every FREED counted before it.
	if backlog := before[ExitCreditFreed]; productStats.Drops != 0 || productStats.Freed < d[ExitCreditFreed] ||
		productStats.Freed-d[ExitCreditFreed] > backlog {
		fail("%s: product reaper %s, want %d TASK FREED wakeups of the window + at most %d emitted before it, and no drops",
			label, productStats, d[ExitCreditFreed], backlog)
	}
	var key, value uint64
	keys := v.c.Maps["se_opaque_keys"].Iterate()
	for keys.Next(&key, &value) {
		if key != v.parent {
			fail("%s: child TASK %#x survived its free", label, key)
		}
	}
	var receipt [64]byte
	receipts := v.c.Maps["se_exec_terminal_receipts"].Iterate()
	for receipts.Next(&key, &receipt) {
		if key != v.parent {
			fail("%s: child terminal receipt %#x survived its free", label, key)
		}
	}
	if keys.Err() != nil || receipts.Err() != nil {
		fail("%s: %v %v", label, keys.Err(), receipts.Err())
	}
	if failed {
		v.dump(label)
		v.t.FailNow()
	}
	v.parentQualified(label)
	v.t.Logf("EXIT free-delay n=%d disarm=%v capacity=%d share=%d dir_every=%d mode=%d inserted=%d account_overflow=%d dir_pending=%d unsettled=%d/%d injected=%d freed=%d fallback=%d high_water=%d degraded=%v; %s; product reaper: %s",
		n, disarm, capacity, share, dirEvery, mode, inserted, d[ExitCreditAccountOverflow], d[ExitCreditDirPending], d[ExitCreditUnsettled],
		d[ExitCreditUnsettledFault], injected, d[ExitCreditFreed], d[ExitCreditFallbackFree], d[ExitCreditHighWater], final.Degraded, proof, productStats)
}

// exitAccountsHeld sums the per-binding tombstone gauges.
func (v *opaqueVerdictRun) exitAccountsHeld(label string) uint64 {
	v.t.Helper()
	m := v.c.Maps["opaque_real_exit_accounts"]
	var held uint64
	for _, n := range v.counters(label, m, int(m.MaxEntries())) {
		held += n
	}
	return held
}

// exitPendingDirectory checks that every DIR_PENDING tombstone's charge is
// DEAD, its exit lease still held, at the directory state the injector
// stopped at (PUBLISHED, WITHDRAW_CLAIM or WITHDRAWN_ZERO) and, past stage
// 1, claimed by its own locator: the state the free-time resume enters.
func (v *opaqueVerdictRun) exitPendingDirectory(label string, fail func(string, ...any), want uint64) {
	v.t.Helper()
	var key uint64
	var raw [opaqueExitTombSize]byte
	entries := v.c.Maps["se_exit_tombstones"].Iterate()
	pending := 0
	for entries.Next(&key, &raw) {
		if binary.LittleEndian.Uint32(raw[opaqueExitTombStage:]) != opaqueExitDirPending {
			continue
		}
		pending++
		slot, locator := binary.LittleEndian.Uint32(raw[opaqueExitTombSlot:]), binary.LittleEndian.Uint64(raw[8:16])
		meta, err := v.c.Maps["se_opaque_meta"].LookupBytes(slot)
		if err != nil {
			v.t.Fatalf("%s: TASK meta %d: %v", label, slot, err)
		}
		state, owner := v.field(v.metaType, meta, "directory_state"), v.field(v.metaType, meta, "exclusive_owner")
		if v.field(v.metaType, meta, "phase") != opaqueTaskPhaseDead || v.field(v.metaType, meta, "active_leases") != 1 ||
			state != want || (want != opaqueDirectoryPublished && owner != locator) {
			fail("%s: DIR_PENDING tombstone %#x slot %d: phase=%d leases=%d directory_state=%d owner=%#x, want DEAD, its lease held, state %d owned by %#x",
				label, key, slot, v.field(v.metaType, meta, "phase"), v.field(v.metaType, meta, "active_leases"), state, owner, want, locator)
		}
	}
	if err := entries.Err(); err != nil || pending == 0 {
		fail("%s: DIR_PENDING tombstones: %d (err %v), want at least one", label, pending, err)
	}
}

// birthOutcomes reads the test-only birth accounting witness (see
// opaque_birth_outcomes in the candidate object).
func (v *opaqueVerdictRun) birthOutcomes(label string) [8]uint64 {
	v.t.Helper()
	m := v.c.Maps["opaque_birth_outcomes"]
	if m == nil {
		v.t.Fatalf("%s: verdict object lacks the opaque_birth_outcomes witness", label)
	}
	var out [8]uint64
	for i := range out {
		if err := m.Lookup(uint32(i), &out[i]); err != nil {
			v.t.Fatalf("%s: opaque_birth_outcomes[%d]: %v", label, i, err)
		}
	}
	return out
}

// leaks logs every charged TASK slot of the parent's account (charge,
// se_ol_meta and se_opaque_keys membership) and every non-parent WORK
// charge, after the account failed to return to its baseline.
func (v *opaqueVerdictRun) leaks(label string) {
	v.t.Helper()
	var chargeType *btf.Struct
	if err := v.spec.Types.TypeByName("se_oc_charge", &chargeType); err != nil {
		v.t.Errorf("%s: %v", label, err)
		return
	}
	keyed := map[uint64]uint64{} // locator -> physical key
	var key, value uint64
	keys := v.c.Maps["se_opaque_keys"].Iterate()
	for keys.Next(&key, &value) {
		keyed[value] = key
	}
	if keys.Err() != nil {
		v.t.Logf("%s: se_opaque_keys: %v", label, keys.Err())
	}
	account := v.parentSlot() / v.taskQuota
	for slot := account * v.taskQuota; slot < (account+1)*v.taskQuota; slot++ {
		raw, err := v.c.Maps["se_opaque_charges"].LookupBytes(slot)
		if err != nil {
			v.t.Logf("%s: TASK charge %d: %v", label, slot, err)
			continue
		}
		cookie := v.field(chargeType, raw, "cookie")
		if cookie == 0 {
			continue
		}
		meta, err := v.c.Maps["se_opaque_meta"].LookupBytes(slot)
		if err != nil {
			v.t.Logf("%s: TASK meta %d: %v", label, slot, err)
			continue
		}
		locator := v.field(v.metaType, meta, "locator")
		physical, inKeys := keyed[locator]
		v.t.Logf("%s: TASK slot %d parent=%v charge cookie=%d state=%d; meta phase=%d cookie=%d locator=%#x active_leases=%d exclusive=%d directory_state=%d cleanup_done=%#x cleanup_error=%d; se_opaque_keys holds=%v (%#x)",
			label, slot, slot == v.parentSlot(), cookie, v.field(chargeType, raw, "state"),
			v.field(v.metaType, meta, "phase"), v.field(v.metaType, meta, "cookie"), locator,
			v.field(v.metaType, meta, "active_leases"), v.field(v.metaType, meta, "exclusive"),
			v.field(v.metaType, meta, "directory_state"), v.field(v.metaType, meta, "cleanup_done"),
			v.field(v.metaType, meta, "cleanup_error"), inKeys, physical)
	}
	for slot := account * v.workQuota; slot < (account+1)*v.workQuota; slot++ {
		raw, err := v.c.Maps["se_opaque_work_charges"].LookupBytes(slot)
		if err != nil || len(raw) < 8 {
			continue
		}
		cookie := binary.LittleEndian.Uint64(raw[:8])
		if cookie == 0 || v.parentWorks[slot] == cookie {
			continue
		}
		meta, _ := v.c.Maps["se_opaque_work_meta"].LookupBytes(slot)
		phase := uint32(0)
		if len(meta) >= 8 {
			phase = binary.LittleEndian.Uint32(meta[4:8])
		}
		v.t.Logf("%s: WORK slot %d charge cookie=%d meta phase=%d", label, slot, cookie, phase)
	}
}

// dump logs the diagnostic witnesses after an unexpected outcome.
func (v *opaqueVerdictRun) dump(label string) {
	v.t.Helper()
	var p struct {
		StageBegin, RuleEval, Matched, ObservedUID int32
		RuleEvalCount, MatchedCount                uint64
	}
	_ = v.c.Maps["opaque_real_owner_rule_progress"].Lookup(uint32(0), &p)
	v.t.Logf("%s: rule progress %+v", label, p)
	if raw, err := v.c.Maps["se_exec_capsule_stats"].LookupBytes(uint32(0)); err == nil && len(raw) == 8*opaqueCapStats {
		var stats [opaqueCapStats]uint64
		for i := range stats {
			stats[i] = binary.LittleEndian.Uint64(raw[8*i:])
		}
		v.t.Logf("%s: capsule stats %v", label, stats)
	}
	slot := uint32(v.parentLocator & ((1 << 14) - 1))
	if raw, err := v.c.Maps["se_opaque_payload"].LookupBytes(slot); err == nil {
		v.t.Logf("%s: parent flags=%d reader.owned=%d exec.owned=%d", label,
			v.field(v.taskType, raw, "flags"), v.field(v.taskType, raw, "reader", "owned"),
			v.field(v.taskType, raw, "exec", "owned"))
	}
	var receipt [64]byte
	err := v.c.Maps["se_exec_terminal_receipts"].Lookup(v.parent, &receipt)
	v.t.Logf("%s: parent receipt present=%v", label, err == nil)
	if raw, err := v.c.Maps["opaque_real_owner_policy_witness"].LookupBytes(uint32(0)); err == nil {
		v.t.Logf("%s: policy witness %x", label, raw)
	}
}

func (v *opaqueVerdictRun) capsuleBalanced() {
	v.t.Helper()
	raw, err := v.c.Maps["se_exec_capsule_stats"].LookupBytes(uint32(0))
	if err != nil || len(raw) != 8*opaqueCapStats {
		v.t.Fatalf("capsule stats: len=%d err=%v", len(raw), err)
	}
	var stats [opaqueCapStats]uint64
	for i := range stats {
		stats[i] = binary.LittleEndian.Uint64(raw[8*i:])
	}
	v.t.Logf("capsule stats begin=%d frozen=%d pinned=%d original_claim=%d terminal=%d foreign=%d success=%d release_fault=%d fault=%d pin_failed=%d death_retired=%d",
		stats[0], stats[3], stats[5], stats[7], stats[8], stats[9], stats[10], stats[12], stats[13], stats[6], stats[14])
	if stats[12] != 0 || stats[13] != 0 || stats[6] != 0 {
		v.t.Fatal("capsule faults recorded")
	}
	for slot := uint32(0); slot < uint32(v.spec.Maps["se_routes"].MaxEntries); slot++ {
		route, err := v.c.Maps["se_routes"].LookupBytes(slot)
		if err != nil || len(route) != 104 {
			v.t.Fatalf("route %d: len=%d err=%v", slot, len(route), err)
		}
		if early, pins, latch := binary.LittleEndian.Uint32(route[64:]), binary.LittleEndian.Uint32(route[96:]),
			binary.LittleEndian.Uint32(route[100:]); early|pins|latch != 0 {
			v.t.Fatalf("route %d unbalanced: early=%d pins=%d unresolved=%d", slot, early, pins, latch)
		}
	}
}

// reuseRace (IG_OPAQUE_REAL_VERDICT_REUSE_RACE=1, G025 batch F) drives the
// physical-reuse collision deterministically. On one pinned CPU (SLUB per-CPU
// freelists are LIFO) a predecessor P is born and dies without exec; after
// its final free the directory entry must already be DELETED with no key.
// One exact reaper visit then emulates a reaper in the middle of P's
// withdrawal: without the fix it claims (WITHDRAW_CLAIM) and the newborn at
// P's address loses to it (CONTENDED, refused); with it, it only wipes the
// archive. Children are forked until one reuses P's address (each child that
// does not becomes the next predecessor, so the freelist head is always the
// latest dead TASK), at most opaqueReuseAttempts. The colliding child must
// construct with a newer cookie, unquarantined; every TASK cookie is
// returned exactly once; no constructor is STALE/CONTENDED and no
// replacement-failure site fires; the account returns to its baseline.
// Then the fallback: a reader hold taken while LIVE makes the final-free
// withdrawal refuse, and the reaper path completes exactly once after it.
const opaqueReuseAttempts = 4096

func (v *opaqueVerdictRun) reuseRace(cpu int, exitStale bool) {
	v.t.Helper()
	label := "physical reuse race"
	if left := v.childTasks(label); len(left) != 0 {
		v.t.Fatalf("%s: %d child TASKs still charged before the race", label, len(left))
	}
	replaceWitness := v.c.Maps["opaque_real_replace_failures"]
	beforeReplace := v.counters(label, replaceWitness, 4)
	beforeBirths := v.birthOutcomes(label)
	baseTasks, baseWorks := v.accounts(label)
	v.pin(label, cpu)
	births := 0
	fork := func() opaqueChildTask {
		v.t.Helper()
		before := map[uint32]bool{}
		for _, c := range v.childTasks(label) {
			before[c.slot] = true
		}
		if _, err := io.WriteString(v.stdin, "FORKE\n"); err != nil {
			v.t.Fatal(err)
		}
		line, err := v.stdout.ReadString('\n')
		var pid, code int
		if n, _ := fmt.Sscanf(line, "FORKED:%d:%d\n", &pid, &code); err != nil || n != 2 || pid <= 0 || code != 0 {
			v.t.Fatalf("%s: birth %d refused or failed: line=%q err=%v (a constructor that lost to a DEAD predecessor is refused) stderr=%q",
				label, births+1, line, err, v.stderr.String())
		}
		births++
		var born []opaqueChildTask
		for _, c := range v.childTasks(label) {
			if !before[c.slot] {
				born = append(born, c)
			}
		}
		if len(born) != 1 {
			v.t.Fatalf("%s: birth %d (pid %d) charged %d new TASKs, want exactly 1", label, births, pid, len(born))
		}
		return born[0]
	}
	midWithdrawal := func(c opaqueChildTask) {
		v.t.Helper()
		if code, err := v.reapStep("task", c.slot, c.cookie); err != nil || code != 1 {
			v.t.Fatalf("%s: one reaper visit of TASK %#x cookie %d: code=%d err=%v, want PROGRESS", label, c.physical, c.cookie, code, err)
		}
	}
	retire := func(c opaqueChildTask) {
		v.t.Helper()
		v.settleRound(label, -1)
		v.reapOnce(label, c)
	}
	prev := fork()
	v.finalFree(label, prev)
	midWithdrawal(prev)
	reuses, attempts := 0, 0
	for reuses == 0 && attempts < opaqueReuseAttempts {
		attempts++
		c := fork()
		v.finalFree(label, c)
		flags, cookie, settled := v.task(c.physical, c.locator)
		if flags&2 != 0 || !settled || cookie != c.cookie {
			v.t.Fatalf("%s: TASK %#x flags=%d settled=%v cookie=%d (charge %d), want unquarantined and settled",
				label, c.physical, flags, settled, cookie, c.cookie)
		}
		if c.physical == prev.physical {
			if c.cookie <= prev.cookie || c.slot == prev.slot {
				v.t.Fatalf("%s: reuse of %#x kept a stale identity: cookie %d slot %d after cookie %d slot %d",
					label, c.physical, c.cookie, c.slot, prev.cookie, prev.slot)
			}
			reuses++
			v.reuses++
			v.t.Logf("%s: attempt %d: TASK %#x reused by cookie %d (slot %d) while its predecessor cookie %d (slot %d) was unreaped",
				label, attempts, c.physical, c.cookie, c.slot, prev.cookie, prev.slot)
		}
		retire(prev)
		prev = c
		midWithdrawal(prev)
	}
	retire(prev)
	if reuses == 0 {
		v.t.Fatalf("%s: no physical reuse in %d births pinned to CPU %d (set IG_OPAQUE_REAL_VERDICT_REUSE_CPU to an idle CPU)",
			label, attempts, cpu)
	}
	afterBirths := v.birthOutcomes(label)
	var outcomes [8]uint64
	for i := range outcomes {
		outcomes[i] = afterBirths[i] - beforeBirths[i]
	}
	if want := [8]uint64{1: uint64(births)}; outcomes != want {
		v.t.Fatalf("%s: birth outcomes %v for %d births, want every constructor OK (%v)", label, outcomes, births, want)
	}
	afterReplace := v.counters(label, replaceWitness, 4)
	for i := range afterReplace {
		if afterReplace[i] != beforeReplace[i] {
			v.t.Fatalf("%s: replacement failures %v -> %v, want none", label, beforeReplace, afterReplace)
		}
	}
	if tasks, works := v.accounts(label); tasks != baseTasks || works != baseWorks {
		v.t.Fatalf("%s: account TASK %d WORK %d after exact refunds, want baseline %d/%d", label, tasks, works, baseTasks, baseWorks)
	}
	v.t.Logf("%s: %d births on CPU %d, reuse after %d attempts; every constructor OK, every TASK cookie returned once, replacement failures 0",
		label, births, cpu, attempts)
	v.reuseFallback(label, fork)
	if exitStale {
		v.exitStale(label, fork, retire, opaqueExitInjectSkipDelete)
		v.exitStale(label, fork, retire, opaqueExitInjectSkipFree)
		v.exitStalePending(label, fork, retire, cpu)
	}
	v.pin(label, -1)
	v.parentQualified(label)
}

// reuseFallback: a reader hold on a LIVE child makes its final-free
// withdrawal refuse; the state stays PUBLISHED and the reaper completes the
// withdrawal exactly once after the hold is released.
func (v *opaqueVerdictRun) reuseFallback(label string, fork func() opaqueChildTask) {
	v.t.Helper()
	label += ": reader-hold fallback"
	baseTasks, baseWorks := v.accounts(label)
	// Credit at exit: the exit refuses its withdrawal under the hold
	// (DIR_PENDING, lease kept), the free-time resume refuses again and
	// releases the lease (FREE_PENDING), and the reaper retries the
	// withdrawal and retires the tombstone at its first visit.
	exitCredit := v.c.Maps["opaque_real_exit_credit"] != nil
	exitBefore := v.exitArray(v.exitCounters(label))
	exitDelta := func(want map[int]uint64) ExitCreditVerdict {
		v.t.Helper()
		var got ExitCreditVerdict
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			var err error
			if got, err = ExitCredit(exitBefore, v.exitArray(v.exitCounters(label)), v.exitCapacity()); err != nil {
				v.t.Fatalf("%s: %v", label, err)
			}
			exact := true
			for i, n := range want {
				exact = exact && got.Delta[i] == n
			}
			if exact {
				return got
			}
			if time.Now().After(deadline) {
				v.t.Fatalf("%s: exit credit %s, want %v", label, got, want)
			}
		}
	}
	if _, err := io.WriteString(v.stdin, "SPAWN\n"); err != nil {
		v.t.Fatal(err)
	}
	if line, err := v.stdout.ReadString('\n'); err != nil || !strings.HasPrefix(line, "SPAWNED:") {
		v.t.Fatalf("%s: line=%q err=%v stderr=%q", label, line, err, v.stderr.String())
	}
	children := v.childTasks(label)
	if len(children) != 1 {
		v.t.Fatalf("%s: %d child TASKs, want the one spawned", label, len(children))
	}
	f := children[0]
	hold := func(release uint32) {
		v.t.Helper()
		request := struct {
			Physical, Cookie uint64
			Slot, Release    uint32
		}{f.physical, f.cookie, f.slot, release}
		if err := v.c.Maps["opaque_real_reuse_hold_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
			v.t.Fatal(err)
		}
		if code, _, err := v.c.Programs["opaque_real_reuse_hold"].Test(make([]byte, 64)); err != nil || code != 0 {
			v.t.Fatalf("%s: hold (release=%d) on TASK %#x: code=%d err=%v", label, release, f.physical, code, err)
		}
	}
	meta := func() []byte {
		v.t.Helper()
		raw, err := v.c.Maps["se_opaque_meta"].LookupBytes(f.slot)
		if err != nil {
			v.t.Fatal(err)
		}
		return raw
	}
	hold(0)
	if raw := meta(); v.field(v.metaType, raw, "phase") != 1 || v.field(v.metaType, raw, "reader_holds") != 1 {
		v.t.Fatalf("%s: hold on LIVE TASK: phase=%d reader_holds=%d", label,
			v.field(v.metaType, raw, "phase"), v.field(v.metaType, raw, "reader_holds"))
	}
	if _, err := io.WriteString(v.stdin, "REAP\n"); err != nil {
		v.t.Fatal(err)
	}
	if line, err := v.stdout.ReadString('\n'); err != nil || line != "REAPED:1\n" {
		v.t.Fatalf("%s: line=%q err=%v stderr=%q", label, line, err, v.stderr.String())
	}
	raw := v.waitFinalFree(label, f)
	var value uint64
	if v.field(v.metaType, raw, "directory_state") != opaqueDirectoryPublished ||
		v.field(v.metaType, raw, "cleanup_done")&opaqueCleanupDirDone != 0 ||
		v.field(v.metaType, raw, "exclusive") != 0 || v.field(v.metaType, raw, "exclusive_owner") != 0 ||
		v.field(v.metaType, raw, "reader_holds") != 1 ||
		v.c.Maps["se_opaque_keys"].Lookup(f.physical, &value) != nil || value != f.locator {
		v.t.Fatalf("%s: refused final-free withdrawal changed state: directory_state=%d cleanup_done=%#x exclusive=%d reader_holds=%d key=%#x, want PUBLISHED untouched",
			label, v.field(v.metaType, raw, "directory_state"), v.field(v.metaType, raw, "cleanup_done"),
			v.field(v.metaType, raw, "exclusive"), v.field(v.metaType, raw, "reader_holds"), value)
	}
	if exitCredit {
		var tomb [opaqueExitTombSize]byte
		if err := v.c.Maps["se_exit_tombstones"].Lookup(f.physical, &tomb); err != nil ||
			binary.LittleEndian.Uint32(tomb[opaqueExitTombStage:]) != opaqueExitFreePending ||
			binary.LittleEndian.Uint64(tomb[0:8]) != f.cookie || binary.LittleEndian.Uint64(tomb[8:16]) != f.locator ||
			binary.LittleEndian.Uint32(tomb[opaqueExitTombSlot:]) != f.slot {
			v.t.Fatalf("%s: tombstone of TASK %#x after its free: %x err=%v, want FREE_PENDING with cookie %d slot %d",
				label, f.physical, tomb, err, f.cookie, f.slot)
		}
		exitDelta(map[int]uint64{
			ExitCreditInserted: 1, ExitCreditSettled: 0, ExitCreditDirPending: 1, ExitCreditDirResumed: 0,
			ExitCreditDirFaulted: 1, ExitCreditFreed: 1, ExitCreditReaperRetired: 0, ExitCreditTombFault: 0,
		})
	}
	// The same hold also blocks the reaper's claim.
	if !exitCredit {
		if code, err := v.reapStep("task", f.slot, f.cookie); err != nil || code != 3 {
			v.t.Fatalf("%s: reaper visit under the hold: code=%d err=%v, want PENDING", label, code, err)
		}
	} else {
		// Concurrent product reaps of the one FREE_PENDING charge race for
		// its retirement: exactly one visit wins the FREE_PENDING ->
		// RETIRING CAS and deletes the tombstone (one REAPER_RETIRED, one
		// LIVE and binding-gauge decrement, no failed delete); a visit that
		// read FREE_PENDING and lost the CAS counts RETIRE_LOST; every visit
		// ends PENDING (the claim refused under the hold), none faults.
		const racers = 8
		codes, errs := make([]uint32, racers), make([]error, racers)
		start := make(chan struct{})
		var wg sync.WaitGroup
		for i := range racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				codes[i], errs[i] = v.productReap(ReapTask, f.slot, f.cookie)
			}()
		}
		close(start)
		wg.Wait()
		for i := range racers {
			if errs[i] != nil || codes[i] != 3 {
				v.t.Fatalf("%s: concurrent reaper visit %d of %d under the hold: code=%d err=%v, want PENDING", label, i, racers, codes[i], errs[i])
			}
		}
		var tomb [opaqueExitTombSize]byte
		if err := v.c.Maps["se_exit_tombstones"].Lookup(f.physical, &tomb); !errors.Is(err, ebpf.ErrKeyNotExist) {
			v.t.Fatalf("%s: FREE_PENDING tombstone survived %d concurrent reaper visits: %v", label, racers, err)
		}
		got := exitDelta(map[int]uint64{
			ExitCreditReaperRetired: 1, ExitCreditLive: exitBefore[ExitCreditLive], ExitCreditTombFault: 0, ExitCreditLeaseFault: 0,
		})
		if lost := got.Delta[ExitCreditRetireLost]; lost > racers-1 {
			v.t.Fatalf("%s: %d lost retirement CASes for %d racing visits, want at most %d", label, lost, racers, racers-1)
		}
		if held := v.exitAccountsHeld(label); held != got.Delta[ExitCreditLive] {
			v.t.Fatalf("%s: binding tombstone gauges hold %d after the racing retirement, want %d live", label, held, got.Delta[ExitCreditLive])
		}
		v.t.Logf("%s: %d concurrent reaper visits of FREE_PENDING cookie %d: 1 retired, %d lost the CAS, all PENDING",
			label, racers, f.cookie, got.Delta[ExitCreditRetireLost])
	}
	hold(1)
	v.settleRound(label, -1)
	if exitCredit {
		v.singleReaperReap(label, f)
	} else {
		v.reapOnce(label, f)
	}
	if err := v.c.Maps["se_opaque_keys"].Lookup(f.physical, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		v.t.Fatalf("%s: directory key survived the reaper withdrawal: %v", label, err)
	}
	if tasks, works := v.accounts(label); tasks != baseTasks || works != baseWorks {
		v.t.Fatalf("%s: account TASK %d WORK %d after exact refunds, want baseline %d/%d", label, tasks, works, baseTasks, baseWorks)
	}
	if exitCredit {
		// FREE_PENDING with address reuse: the reaper retired the
		// tombstone and withdrew the key, so the next birth on this CPU
		// reuses the address (SLUB per-CPU LIFO) and its exit must settle
		// normally: one more SETTLED, nothing blocked or stale.
		c := fork()
		if c.physical != f.physical {
			v.t.Fatalf("%s: birth after the FREE_PENDING retirement did not reuse %#x (got %#x); set IG_OPAQUE_REAL_VERDICT_REUSE_CPU to an idle CPU",
				label, f.physical, c.physical)
		}
		v.finalFree(label, c)
		exitDelta(map[int]uint64{
			ExitCreditInserted: 2, ExitCreditSettled: 1, ExitCreditFreed: 2,
			ExitCreditStale: 0, ExitCreditBlocked: 0, ExitCreditTombFault: 0, ExitCreditLive: exitBefore[ExitCreditLive],
		})
		v.settleRound(label, -1)
		v.reapOnce(label, c)
		if err := exitDelta(nil).Quiescent(); err != nil {
			v.t.Fatalf("%s: %v", label, err)
		}
		v.t.Logf("%s: address %#x reused by cookie %d after the FREE_PENDING retirement; settled at exit", label, c.physical, c.cookie)
	}
	v.t.Logf("%s: final-free withdrawal refused under the hold; reaper withdrew and returned TASK cookie %d exactly once", label, f.cookie)
}

// REAL_OWNER_EXIT_INJECT_* one-shot free faults, and the test-only
// tombstone flags of PENDING_SKIP_FREE.
const (
	opaqueExitInjectSkipDelete      = 6
	opaqueExitInjectSkipFree        = 7
	opaqueExitInjectPendingSkipFree = 8
	opaqueExitFlagSkipFree          = 2
	opaqueExitFlagFreeSkipped       = 4
)

// exitStale (IG_OPAQUE_REAL_VERDICT_EXIT_STALE=1, with the reuse race and
// the exit injector) plants one stale tombstone and checks that the
// address's next lifetime is not fooled by it. The injector makes the next
// free of a SETTLED tombstone skip its delete (SKIP_DELETE: FREED left, as a
// failed delete) or its whole consumption (SKIP_FREE: SETTLED left, as a
// missed task_free). The planted child is reaped normally; the next birth
// on the pinned CPU reuses its address, and its exit must find the earlier
// tombstone by its start_time mismatch, finish it (STALE; a SETTLED one is
// counted FREED then), insert its own and settle at exit: exactly one
// STALE, nothing BLOCKED, every relation exact and Live back.
func (v *opaqueVerdictRun) exitStale(label string, fork func() opaqueChildTask, retire func(opaqueChildTask), mode int) {
	v.t.Helper()
	label = fmt.Sprintf("%s: stale tombstone (inject %d)", label, mode)
	inject, counts := v.c.Maps["opaque_real_exit_inject_every"], v.c.Maps["opaque_real_exit_inject_counts"]
	if left := v.childTasks(label); len(left) != 0 {
		v.t.Fatalf("%s: %d child TASKs still charged", label, len(left))
	}
	before := v.exitArray(v.exitCounters(label))
	beforeInject := v.counters(label, counts, 2)
	arm := func(budget uint64, m int) {
		v.t.Helper()
		if err := inject.Update(uint32(1), uint32(m), ebpf.UpdateAny); err != nil {
			v.t.Fatal(err)
		}
		if err := inject.Update(uint32(0), uint32(budget), ebpf.UpdateAny); err != nil {
			v.t.Fatal(err)
		}
	}
	// A cumulative budget: exactly one more injection.
	arm(beforeInject[1]+1, mode)
	defer arm(0, 0)
	c := fork()
	want := uint32(opaqueExitFreedStage)
	if mode == opaqueExitInjectSkipFree {
		want = opaqueExitSettled
	}
	var tomb [opaqueExitTombSize]byte
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		injected := v.counters(label, counts, 2)[1] - beforeInject[1]
		err := v.c.Maps["se_exit_tombstones"].Lookup(c.physical, &tomb)
		if injected == 1 && err == nil && binary.LittleEndian.Uint32(tomb[opaqueExitTombStage:]) == want &&
			binary.LittleEndian.Uint64(tomb[0:8]) == c.cookie {
			break
		}
		if time.Now().After(deadline) {
			v.t.Fatalf("%s: injected %d, tombstone of %#x: %x err=%v, want stage %d with cookie %d", label, injected, c.physical, tomb, err, want, c.cookie)
		}
	}
	arm(0, 0)
	retire(c)
	d := fork()
	if d.physical != c.physical {
		v.t.Fatalf("%s: next birth did not reuse %#x (got %#x); set IG_OPAQUE_REAL_VERDICT_REUSE_CPU to an idle CPU", label, c.physical, d.physical)
	}
	v.finalFree(label, d)
	retire(d)
	if err := v.c.Maps["se_exit_tombstones"].Lookup(c.physical, &tomb); !errors.Is(err, ebpf.ErrKeyNotExist) {
		v.t.Fatalf("%s: tombstone at the reused address survived: %x err=%v", label, tomb, err)
	}
	var got ExitCreditVerdict
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		var err error
		if got, err = ExitCredit(before, v.exitArray(v.exitCounters(label)), v.exitCapacity()); err != nil {
			v.t.Fatalf("%s: %v", label, err)
		}
		dd := got.Delta
		if dd[ExitCreditStale] == 1 && dd[ExitCreditInserted] == 2 && dd[ExitCreditSettled] == 2 && dd[ExitCreditFreed] == 2 &&
			dd[ExitCreditBlocked]+dd[ExitCreditTombFault]+dd[ExitCreditFallbackFree] == 0 && dd[ExitCreditLive] == before[ExitCreditLive] &&
			got.Quiescent() == nil {
			break
		}
		if time.Now().After(deadline) {
			v.t.Fatalf("%s: %s, want 1 stale, 2 inserted, settled and freed, nothing blocked, quiescent (%v)", label, got, got.Quiescent())
		}
	}
	if !got.Degraded {
		v.t.Fatalf("%s: a stale tombstone must be reported Degraded: %s", label, got)
	}
	v.t.Logf("%s: TASK %#x reused by cookie %d after cookie %d left a stale tombstone; %s", label, d.physical, d.cookie, c.cookie, got)
}

// productReap runs one product reap command (opaque_real_reap, the node
// Reaper's backend) with its own context: safe to run concurrently.
func (v *opaqueVerdictRun) productReap(kind ReapKind, slot uint32, cookie uint64) (uint32, error) {
	command := make([]byte, 16)
	binary.LittleEndian.PutUint64(command[0:8], cookie)
	binary.LittleEndian.PutUint32(command[8:12], slot)
	binary.LittleEndian.PutUint32(command[12:16], uint32(kind))
	return v.c.Programs["opaque_real_reap"].Run(&ebpf.RunOptions{Context: command})
}

// exitStalePending (IG_OPAQUE_REAL_VERDICT_EXIT_STALE=1): the injector's
// PENDING_SKIP_FREE budget makes the next exit refuse its withdrawal before
// stage 1 (DIR_PENDING, its death lease held) and that task's free skip the
// whole consumption, as a missed task_free: the address is freed with the
// lease held and the key PUBLISHED. A product reap visit of that charge is
// PENDING (never a fault). A birth from the gated cgroup at that address is
// refused (a replacement needs the predecessor's lease released), so the
// next lifetime there is an uncharged task spawned by this test process on
// the pinned CPU: its exit finds the stale DIR_PENDING (STALE), releases
// the lease without resuming the withdrawal (DIR_FAULTED, FREED, TASK_DEAD;
// the tombstone FREE_PENDING) and its own insert is BLOCKED. The reaper
// then retires the tombstone (REAPER_RETIRED), withdraws the key and returns
// the credit exactly once: every relation exact, Live back, Degraded.
func (v *opaqueVerdictRun) exitStalePending(label string, fork func() opaqueChildTask, retire func(opaqueChildTask), cpu int) {
	v.t.Helper()
	label = fmt.Sprintf("%s: stale DIR_PENDING (inject %d)", label, opaqueExitInjectPendingSkipFree)
	inject, counts, tombs := v.c.Maps["opaque_real_exit_inject_every"], v.c.Maps["opaque_real_exit_inject_counts"], v.c.Maps["se_exit_tombstones"]
	if left := v.childTasks(label); len(left) != 0 {
		v.t.Fatalf("%s: %d child TASKs still charged", label, len(left))
	}
	before := v.exitArray(v.exitCounters(label))
	beforeInject := v.counters(label, counts, 2)
	arm := func(budget uint64, m int) {
		v.t.Helper()
		if err := inject.Update(uint32(1), uint32(m), ebpf.UpdateAny); err != nil {
			v.t.Fatal(err)
		}
		if err := inject.Update(uint32(0), uint32(budget), ebpf.UpdateAny); err != nil {
			v.t.Fatal(err)
		}
	}
	arm(beforeInject[1]+1, opaqueExitInjectPendingSkipFree)
	defer arm(0, 0)
	c := fork()
	var tomb [opaqueExitTombSize]byte
	stage := func() (uint32, uint32, error) {
		err := tombs.Lookup(c.physical, &tomb)
		return binary.LittleEndian.Uint32(tomb[opaqueExitTombStage:]), binary.LittleEndian.Uint32(tomb[opaqueExitTombFlags:]), err
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		injected := v.counters(label, counts, 2)[1] - beforeInject[1]
		st, flags, err := stage()
		if injected == 1 && err == nil && st == opaqueExitDirPending && binary.LittleEndian.Uint64(tomb[0:8]) == c.cookie &&
			flags&(opaqueExitFlagSkipFree|opaqueExitFlagFreeSkipped) == opaqueExitFlagSkipFree|opaqueExitFlagFreeSkipped {
			break
		}
		if time.Now().After(deadline) {
			v.t.Fatalf("%s: injected %d, tombstone of %#x: %x err=%v, want DIR_PENDING with cookie %d and its free skipped",
				label, injected, c.physical, tomb, err, c.cookie)
		}
	}
	arm(0, 0)
	meta, err := v.c.Maps["se_opaque_meta"].LookupBytes(c.slot)
	var value uint64
	if err != nil || v.field(v.metaType, meta, "phase") != opaqueTaskPhaseDead || v.field(v.metaType, meta, "active_leases") != 1 ||
		v.field(v.metaType, meta, "directory_state") != opaqueDirectoryPublished ||
		v.c.Maps["se_opaque_keys"].Lookup(c.physical, &value) != nil || value != c.locator {
		v.t.Fatalf("%s: TASK %#x after its skipped free: phase=%d leases=%d directory_state=%d key=%#x err=%v, want DEAD, lease held, PUBLISHED %#x",
			label, c.physical, v.field(v.metaType, meta, "phase"), v.field(v.metaType, meta, "active_leases"),
			v.field(v.metaType, meta, "directory_state"), value, err, c.locator)
	}
	// The held lease excludes the reaper: PENDING, never a fault.
	if code, err := v.productReap(ReapTask, c.slot, c.cookie); err != nil || code != 3 {
		v.t.Fatalf("%s: product reap of the leased DEAD charge: code=%d err=%v, want PENDING", label, code, err)
	}
	// Next lifetime: uncharged tasks of this process on the pinned CPU
	// until one is born at the freed address (any task there would do).
	attempts := 0
	for v.exitCounters(label)[ExitCreditStale] == before[ExitCreditStale] {
		if attempts == opaqueReuseAttempts {
			v.t.Fatalf("%s: no task reused %#x in %d uncharged births on CPU %d (set IG_OPAQUE_REAL_VERDICT_REUSE_CPU to an idle CPU)",
				label, c.physical, attempts, cpu)
		}
		attempts++
		v.spawnUncharged(label, cpu)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		st, _, err := stage()
		meta, merr := v.c.Maps["se_opaque_meta"].LookupBytes(c.slot)
		if err == nil && merr == nil && st == opaqueExitFreePending && binary.LittleEndian.Uint64(tomb[0:8]) == c.cookie &&
			v.field(v.metaType, meta, "active_leases") == 0 && v.field(v.metaType, meta, "phase") == opaqueTaskPhaseDead {
			break
		}
		if time.Now().After(deadline) {
			v.t.Fatalf("%s: tombstone of %#x after the stale finish: %x err=%v, want FREE_PENDING with cookie %d and its lease released",
				label, c.physical, tomb, err, c.cookie)
		}
	}
	delta := func(want map[int]uint64) ExitCreditVerdict {
		v.t.Helper()
		var got ExitCreditVerdict
		for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
			if got, err = ExitCredit(before, v.exitArray(v.exitCounters(label)), v.exitCapacity()); err != nil {
				v.t.Fatalf("%s: %v", label, err)
			}
			exact := true
			for i, n := range want {
				exact = exact && got.Delta[i] == n
			}
			if exact {
				return got
			}
			if time.Now().After(deadline) {
				v.t.Fatalf("%s: exit credit %s, want %v", label, got, want)
			}
		}
	}
	// BLOCKED: the successor's own insert, plus any other task born at the
	// address before the reaper retires the FREE_PENDING tombstone.
	if got := delta(map[int]uint64{
		ExitCreditInserted: 1, ExitCreditSettled: 0, ExitCreditDirPending: 1, ExitCreditStale: 1, ExitCreditDirResumed: 0,
		ExitCreditDirFaulted: 1, ExitCreditFreed: 1, ExitCreditReaperRetired: 0,
		ExitCreditTombFault: 0, ExitCreditLeaseFault: 0, ExitCreditFallbackFree: 0,
	}); got.Delta[ExitCreditBlocked] == 0 {
		v.t.Fatalf("%s: %s, want the successor's insert BLOCKED", label, got)
	}
	retire(c)
	if err := tombs.Lookup(c.physical, &tomb); !errors.Is(err, ebpf.ErrKeyNotExist) {
		v.t.Fatalf("%s: FREE_PENDING tombstone survived the reaper: %x err=%v", label, tomb, err)
	}
	if err := v.c.Maps["se_opaque_keys"].Lookup(c.physical, &value); !errors.Is(err, ebpf.ErrKeyNotExist) {
		v.t.Fatalf("%s: directory key %#x survived the reaper withdrawal: %v", label, c.physical, err)
	}
	got := delta(map[int]uint64{ExitCreditReaperRetired: 1, ExitCreditLive: before[ExitCreditLive], ExitCreditStale: 1, ExitCreditInserted: 1})
	if err := got.Quiescent(); err != nil || !got.Degraded {
		v.t.Fatalf("%s: %s: quiescent=%v degraded=%v, want quiescent and Degraded", label, got, err, got.Degraded)
	}
	if held := v.exitAccountsHeld(label); held != got.Delta[ExitCreditLive] {
		v.t.Fatalf("%s: binding tombstone gauges hold %d, want %d live", label, held, got.Delta[ExitCreditLive])
	}
	v.t.Logf("%s: TASK %#x cookie %d: free skipped with its lease held; an uncharged lifetime at the address (attempt %d) finished it; %s",
		label, c.physical, c.cookie, attempts, got)
}

// spawnUncharged runs /bin/true from this test process (outside the gated
// cgroup: never charged) on one OS thread pinned to cpu, so its task_struct
// comes from that CPU's slab. The thread is never unlocked: it exits with
// the goroutine, so its affinity never reaches the runtime's thread pool.
func (v *opaqueVerdictRun) spawnUncharged(label string, cpu int) {
	v.t.Helper()
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		var set unix.CPUSet
		set.Set(cpu)
		if err := unix.SchedSetaffinity(0, &set); err != nil {
			done <- err
			return
		}
		done <- exec.Command("/bin/true").Run()
	}()
	if err := <-done; err != nil {
		v.t.Fatalf("%s: uncharged birth on CPU %d: %v", label, cpu, err)
	}
}

// singleReaperReap returns one exact TASK credit through the product
// Reaper, the only supported shape (exactly one Reaper per collection: the
// directory delete stage is not safe under two concurrent visits; racing
// visits are exercised only on the PRE_VISIT retirement CAS, under the
// reader hold above). While it runs, a second Reaper over the same
// collection is refused (ErrReaperActive). The Reaper skips every charge
// but this one, returns it with no fault, and a later visit of the returned
// cookie is PENDING (product command) and refused (diagnostic reap).
func (v *opaqueVerdictRun) singleReaperReap(label string, c opaqueChildTask) {
	v.t.Helper()
	returned := make(chan ReapRecord, 1)
	r, err := NewReaper(v.c, ReaperConfig{Sweep: 5 * time.Millisecond, Hooks: ReaperHooks{
		Skip: func(kind ReapKind, slot uint32, cookie uint64) bool {
			return kind != ReapTask || slot != c.slot || cookie != c.cookie
		},
		Returned: func(rec ReapRecord) {
			select {
			case returned <- rec:
			default:
			}
		},
	}})
	if err != nil {
		v.t.Fatalf("%s: product reaper: %v", label, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx); err != nil {
		v.t.Fatalf("%s: product reaper start: %v", label, err)
	}
	if second, err := NewReaper(v.c, ReaperConfig{}); !errors.Is(err, ErrReaperActive) {
		if second != nil {
			_ = second.backend.close()
		}
		v.t.Fatalf("%s: second Reaper over the same collection: %v, want ErrReaperActive", label, err)
	}
	select {
	case rec := <-returned:
		if rec.Kind != ReapTask || rec.Slot != c.slot || rec.Cookie != c.cookie {
			v.t.Fatalf("%s: reaper returned %+v, want TASK slot %d cookie %d", label, rec, c.slot, c.cookie)
		}
	case <-time.After(5 * time.Second):
		s, _ := r.Stats()
		v.t.Fatalf("%s: TASK cookie %d not returned by the single reaper in 5s: %s %v", label, c.cookie, s, r.Faults())
	}
	cancel()
	if err := r.Wait(); err != nil {
		v.t.Fatalf("%s: product reaper: %v", label, err)
	}
	if s, err := r.Stats(); err != nil || s.Faulted != 0 || s.Tasks != 1 {
		v.t.Fatalf("%s: product reaper stats %s err %v, want 1 TASK and no fault", label, s, err)
	}
	if cookie := v.charge("se_opaque_charges", c.slot); cookie == c.cookie {
		v.t.Fatalf("%s: TASK slot %d still carries cookie %d after its return", label, c.slot, c.cookie)
	}
	if code, err := v.productReap(ReapTask, c.slot, c.cookie); err != nil || code != 3 {
		v.t.Fatalf("%s: product reap of the returned cookie %d: code=%d err=%v, want PENDING", label, c.cookie, code, err)
	}
	if code, err := v.reapStep("task", c.slot, c.cookie); err != nil || code != 4 {
		v.t.Fatalf("%s: second reap of TASK cookie %d: code=%d err=%v, want the refused stale cookie (4)", label, c.cookie, code, err)
	}
	v.t.Logf("%s: single product reaper returned TASK cookie %d; a second Reaper was refused", label, c.cookie)
}

// reapOnce returns the exact TASK credit, then checks a second visit for the
// same cookie is refused (the charge no longer carries it).
func (v *opaqueVerdictRun) reapOnce(label string, c opaqueChildTask) {
	v.t.Helper()
	v.reap("task", c.slot, c.cookie)
	if code, err := v.reapStep("task", c.slot, c.cookie); err != nil || code != 4 {
		v.t.Fatalf("%s: second reap of TASK cookie %d: code=%d err=%v, want the refused stale cookie (4)", label, c.cookie, code, err)
	}
}

// pin pins the helper parent (and its later children) to cpu; -1 restores.
func (v *opaqueVerdictRun) pin(label string, cpu int) {
	v.t.Helper()
	if _, err := fmt.Fprintf(v.stdin, "PIN:%d\n", cpu); err != nil {
		v.t.Fatal(err)
	}
	if line, err := v.stdout.ReadString('\n'); err != nil || line != fmt.Sprintf("PINNED:%d:0\n", cpu) {
		v.t.Fatalf("%s: pin to CPU %d: line=%q err=%v", label, cpu, line, err)
	}
}
