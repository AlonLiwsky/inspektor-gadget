// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestExitCreditVerdict(t *testing.T) {
	var before, after [ExitCreditCounters]uint64
	before[ExitCreditHighWater] = 9
	after = before
	// 10 exits settled, 2 pending (both resumed), 1 unsettled (benign) and
	// 1 unsettled with a fault; all freed.
	after[ExitCreditInserted] += 14
	after[ExitCreditSettled] += 10
	after[ExitCreditDirPending] += 2
	after[ExitCreditDirResumed] += 2
	after[ExitCreditUnsettled]++
	after[ExitCreditUnsettledFault]++
	after[ExitCreditFreed] += 12
	after[ExitCreditFallbackFree] += 4
	after[ExitCreditHighWater] = 11
	v, err := ExitCredit(before, after, 8192)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Quiescent(); err != nil {
		t.Fatalf("quiescent window: %v (%s)", err, v)
	}
	if v.SlowPath != 4 || v.Faults != 1 || !v.Degraded || v.HighWater || v.DeadSettlements() != 16 || v.Delta[ExitCreditHighWater] != 11 {
		t.Fatalf("verdict %s, dead settlements %d", v, v.DeadSettlements())
	}
	if !strings.Contains(v.String(), "dir-pending=2") || !strings.Contains(v.String(), "unsettled-fault=1") {
		t.Fatalf("string %q", v.String())
	}

	// A clean window: every exit settled, nothing slow, not degraded.
	clean := before
	clean[ExitCreditInserted] += 4
	clean[ExitCreditSettled] += 4
	clean[ExitCreditFreed] += 4
	if v, health, err := ExitCreditCheck(before, clean, nil, 8192); err != nil || health != ExitCreditHealthy || v.Degraded || v.Quiescent() != nil {
		t.Fatalf("clean window: %s %v err=%v quiescent=%v", v, health, err, v.Quiescent())
	}

	// A benign CONTENDED exit takes the slow path but is not Degraded; its
	// faulted twin is.
	benign := clean
	benign[ExitCreditInserted]++
	benign[ExitCreditUnsettled]++
	benign[ExitCreditFallbackFree]++
	if v, health, err := ExitCreditCheck(before, benign, nil, 8192); err != nil || health != ExitCreditHealthy || v.SlowPath != 1 || v.Quiescent() != nil {
		t.Fatalf("benign unsettled window: %s %v err=%v", v, health, err)
	}
	faulted := clean
	faulted[ExitCreditInserted]++
	faulted[ExitCreditUnsettledFault]++
	faulted[ExitCreditFallbackFree]++
	if v, health, err := ExitCreditCheck(before, faulted, nil, 8192); err != nil || health != ExitCreditDegraded || v.Faults != 1 || v.SlowPath != 1 {
		t.Fatalf("faulted unsettled window: %s %v err=%v", v, health, err)
	}

	// Every refused insert takes the slow path: counted, Degraded, never an
	// error.
	for _, i := range []int{ExitCreditOverflow, ExitCreditAccountOverflow, ExitCreditBusy, ExitCreditBlocked} {
		refused := clean
		refused[i] += 12
		refused[ExitCreditFallbackFree] += 12
		if v, health, err := ExitCreditCheck(before, refused, nil, 8192); err != nil || health != ExitCreditDegraded || v.SlowPath != 12 ||
			v.Quiescent() != nil || v.DeadSettlements() != 16 {
			t.Fatalf("refused (%s) window: %s %v err=%v", exitCreditNames[i], v, health, err)
		}
	}
	// A stale tombstone is the trace of an earlier fault: Degraded.
	stale := clean
	stale[ExitCreditStale]++
	if v, health, _ := ExitCreditCheck(before, stale, nil, 8192); health != ExitCreditDegraded || v.Faults != 1 {
		t.Fatalf("stale window: %s %v", v, health)
	}
	// A lost retirement CAS is benign.
	lost := clean
	lost[ExitCreditRetireLost]++
	if v, health, _ := ExitCreditCheck(before, lost, nil, 8192); health != ExitCreditHealthy || v.Quiescent() != nil {
		t.Fatalf("retire-lost window: %s %v", v, health)
	}

	// High-water: 75% of the map is Degraded before any insert overflows.
	high := clean
	high[ExitCreditHighWater] = 6144
	if v, health, _ := ExitCreditCheck(before, high, nil, 8192); health != ExitCreditDegraded || !v.HighWater {
		t.Fatalf("high-water 6144/8192: %s %v", v, health)
	}
	high[ExitCreditHighWater] = 6143
	if v, health, _ := ExitCreditCheck(before, high, nil, 8192); health != ExitCreditHealthy || v.HighWater {
		t.Fatalf("high-water 6143/8192: %s %v", v, health)
	}
	// The gauge is lifetime-monotonic: a peak reached before the window
	// does not degrade it (before = after = 6144, Live low)...
	peaked := clean
	peaked[ExitCreditHighWater] = 6144
	peakedBefore := before
	peakedBefore[ExitCreditHighWater] = 6144
	if v, health, _ := ExitCreditCheck(peakedBefore, peaked, nil, 8192); health != ExitCreditHealthy || v.HighWater || v.Degraded {
		t.Fatalf("high-water 6144 reached before the window: %s %v", v, health)
	}
	// ...but a Live gauge at the threshold now does, and so does a rise
	// within the window from an earlier peak below it.
	full := peaked
	full[ExitCreditLive] = 6144
	if v, health, _ := ExitCreditCheck(peakedBefore, full, nil, 8192); health != ExitCreditDegraded || !v.HighWater {
		t.Fatalf("live 6144/8192: %s %v", v, health)
	}
	rose := peaked
	rose[ExitCreditHighWater] = 6145
	if v, health, _ := ExitCreditCheck(peakedBefore, rose, nil, 8192); health != ExitCreditDegraded || !v.HighWater {
		t.Fatalf("high-water 6144 -> 6145: %s %v", v, health)
	}
	// A repeat peak below the lifetime HighWater: only the crossing count
	// sees it, and it degrades its window.
	repeat := peaked
	repeat[ExitCreditHighCrossed]++
	if v, health, _ := ExitCreditCheck(peakedBefore, repeat, nil, 8192); health != ExitCreditDegraded || !v.HighWater || v.Faults != 0 {
		t.Fatalf("repeat high-water crossing: %s %v", v, health)
	}
	// A held lease no tombstone accounts for, still held a second later:
	// a fault, never quiescent.
	stuck := clean
	stuck[ExitCreditHeldStuck]++
	if v, health, _ := ExitCreditCheck(before, stuck, nil, 8192); health != ExitCreditDegraded || v.Faults != 1 || v.Quiescent() == nil {
		t.Fatalf("held-stuck window: %s %v quiescent=%v", v, health, v.Quiescent())
	}
	// A lease left held is a fault, never quiescent.
	leased := clean
	leased[ExitCreditLeaseFault]++
	if v, health, _ := ExitCreditCheck(before, leased, nil, 8192); health != ExitCreditDegraded || v.Faults != 1 || v.Quiescent() == nil {
		t.Fatalf("lease-fault window: %s %v quiescent=%v", v, health, v.Quiescent())
	}

	// Unreadable, unknown capacity and reset counters are Unknown, never
	// clean.
	if _, health, err := ExitCreditCheck(before, clean, errors.New("EPERM"), 8192); health != ExitCreditUnknown || err == nil {
		t.Fatalf("unreadable witness: %v err=%v", health, err)
	}
	if _, health, err := ExitCreditCheck(before, clean, nil, 0); health != ExitCreditUnknown || err == nil {
		t.Fatalf("unknown capacity: %v err=%v", health, err)
	}
	if _, health, err := ExitCreditCheck(clean, before, nil, 8192); health != ExitCreditUnknown || err == nil {
		t.Fatalf("counters moved backwards: %v err=%v", health, err)
	}
	if ExitCreditUnknown.String() != "unknown" || ExitCreditHealthy.String() != "healthy" || ExitCreditDegraded.String() != "degraded" {
		t.Fatal("health names")
	}

	// A faulted resume is quiescent only once the reaper retired it.
	pending := clean
	pending[ExitCreditInserted]++
	pending[ExitCreditDirPending]++
	pending[ExitCreditDirFaulted]++
	pending[ExitCreditFreed]++
	pending[ExitCreditLive]++
	v, err = ExitCredit(before, pending, 8192)
	if err != nil || !v.Degraded || v.Faults != 1 {
		t.Fatalf("faulted window: %s err=%v", v, err)
	}
	if err := v.Quiescent(); err == nil {
		t.Fatalf("unretired faulted tombstone passed quiescence: %s", v)
	}
	pending[ExitCreditReaperRetired]++
	pending[ExitCreditLive]--
	if v, _ := ExitCredit(before, pending, 8192); v.Quiescent() != nil {
		t.Fatalf("retired faulted tombstone: %v", v.Quiescent())
	}

	// With nothing held before the window every relation is exact.
	for name, mutate := range map[string]func(*[ExitCreditCounters]uint64){
		"freed short":     func(a *[ExitCreditCounters]uint64) { a[ExitCreditFreed]-- },
		"freed extra":     func(a *[ExitCreditCounters]uint64) { a[ExitCreditFreed]++ },
		"live leak":       func(a *[ExitCreditCounters]uint64) { a[ExitCreditLive]++ },
		"unresumed":       func(a *[ExitCreditCounters]uint64) { a[ExitCreditDirResumed]-- },
		"extra resume":    func(a *[ExitCreditCounters]uint64) { a[ExitCreditDirResumed]++ },
		"uncounted":       func(a *[ExitCreditCounters]uint64) { a[ExitCreditInserted]++ },
		"tomb fault":      func(a *[ExitCreditCounters]uint64) { a[ExitCreditTombFault]++ },
		"lease fault":     func(a *[ExitCreditCounters]uint64) { a[ExitCreditLeaseFault]++ },
		"extra retire":    func(a *[ExitCreditCounters]uint64) { a[ExitCreditReaperRetired]++ },
		"unsettled extra": func(a *[ExitCreditCounters]uint64) { a[ExitCreditUnsettledFault]++ },
	} {
		bad := after
		mutate(&bad)
		if v, err := ExitCredit(before, bad, 8192); err != nil || v.Quiescent() == nil {
			t.Errorf("%s: quiescence accepted %s (err=%v)", name, v, err)
		}
	}

	// Tombstones held before the window (exits before it, freed in it) may
	// be consumed in it: up to LiveBefore extra frees, resumes and
	// retirements, and Live may drop, but never more than LiveBefore.
	carried := before
	carried[ExitCreditLive] = 6
	window := carried
	window[ExitCreditInserted] += 630
	window[ExitCreditSettled] += 630
	window[ExitCreditFreed] += 636
	window[ExitCreditLive] = 0
	v, err = ExitCredit(carried, window, 8192)
	if err != nil || v.Quiescent() != nil {
		t.Fatalf("carried window: %s err=%v quiescent=%v", v, err, v.Quiescent())
	}
	for name, mutate := range map[string]func(*[ExitCreditCounters]uint64){
		"freed beyond carry": func(a *[ExitCreditCounters]uint64) { a[ExitCreditFreed]++ },
		"freed short":        func(a *[ExitCreditCounters]uint64) { a[ExitCreditFreed] -= 7 },
		"live above carry":   func(a *[ExitCreditCounters]uint64) { a[ExitCreditLive] = 7 },
		"retired beyond":     func(a *[ExitCreditCounters]uint64) { a[ExitCreditReaperRetired] += 7 },
	} {
		bad := window
		mutate(&bad)
		if v, err := ExitCredit(carried, bad, 8192); err != nil || v.Quiescent() == nil {
			t.Errorf("carried %s: quiescence accepted %s (err=%v)", name, v, err)
		}
	}

	backwards := before
	backwards[ExitCreditFreed] = 1
	if _, err := ExitCredit(backwards, before, 8192); err == nil {
		t.Fatal("a counter moving backwards gave a verdict")
	}
	backwards = before
	backwards[ExitCreditHighWater] = 10
	if _, err := ExitCredit(backwards, before, 8192); err == nil {
		t.Fatal("high-water moving backwards gave a verdict")
	}
	// The Live gauge may go down.
	down := carried
	down[ExitCreditLive] = 0
	if _, err := ExitCredit(carried, down, 8192); err != nil {
		t.Fatalf("live gauge down: %v", err)
	}
}

// TestExitCreditBPFSource pins the witness layout, the tombstone stages and
// TASK FREED to the BPF source, and the fail-closed shape of the exit
// program: the tombstone is inserted before se_of_record_death, task_free
// skips its fallback only for a consumed tombstone, and the whole feature,
// its test-only override and injector stay compile-guarded.
func TestExitCreditBPFSource(t *testing.T) {
	raw, err := os.ReadFile("bpf/opaque_real_owner_child_candidate.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	squashed := squashSpace(source)
	names := map[int]string{
		ExitCreditInserted: "INSERTED", ExitCreditLive: "LIVE", ExitCreditHighWater: "HIGH_WATER",
		ExitCreditOverflow: "OVERFLOW", ExitCreditStale: "STALE", ExitCreditSettled: "SETTLED_COUNT",
		ExitCreditDirPending: "DIR_PENDING_COUNT", ExitCreditDirResumed: "DIR_RESUMED",
		ExitCreditDirFaulted: "DIR_FAULTED", ExitCreditFallbackFree: "FALLBACK_FREE", ExitCreditFreed: "FREED",
		ExitCreditReaperRetired: "REAPER_RETIRED", ExitCreditUnsettled: "UNSETTLED",
		ExitCreditTombFault: "TOMB_FAULT", ExitCreditUnsettledFault: "UNSETTLED_FAULT", ExitCreditBusy: "BUSY",
		ExitCreditBlocked: "BLOCKED", ExitCreditAccountOverflow: "ACCOUNT_OVERFLOW", ExitCreditRetireLost: "RETIRE_LOST",
		ExitCreditLeaseFault: "LEASE_FAULT", ExitCreditHeldStuck: "HELD_STUCK", ExitCreditHighCrossed: "HIGH_CROSSED",
		ExitCreditCounters: "COUNTERS",
	}
	if len(names) != ExitCreditCounters+1 {
		t.Fatalf("%d pinned names for %d counters", len(names), ExitCreditCounters)
	}
	for index, name := range names {
		define := fmt.Sprintf("#define REAL_OWNER_EXIT_%s %d\n", name, index)
		if !strings.Contains(source, define) {
			t.Errorf("candidate source lacks %q", strings.TrimSpace(define))
		}
	}
	for _, pin := range []string{
		fmt.Sprintf("#define REAL_OWNER_REAP_TASK_FREED %d\n", ReapEventTaskFreed),
		"#define REAL_OWNER_EXIT_RESERVED 1\n",
		"#define REAL_OWNER_EXIT_SETTLED 2\n",
		"#define REAL_OWNER_EXIT_DIR_PENDING 3\n",
		"#define REAL_OWNER_EXIT_FREE_PENDING 4\n",
		"#define REAL_OWNER_EXIT_RETIRING 5\n",
		"#define REAL_OWNER_EXIT_FREED_STAGE 6\n",
		// The tombstone wire read by the attached test (opaqueExitTomb*).
		"struct real_owner_exit_tombstone {\n\t__u64 cookie, locator, start;\n\t__u32 slot, stage, flags, account;\n};\n" +
			"_Static_assert(sizeof(struct real_owner_exit_tombstone) == 40,",
		// S4: an equal per-binding share, never empty.
		"#define SE_EXIT_TOMBSTONE_ACCOUNT \\\n\t(SE_EXIT_TOMBSTONE_ENTRIES / SE_PROFILE_BINDINGS)\n" +
			"_Static_assert(SE_EXIT_TOMBSTONE_ACCOUNT >= 1,",
		"if (__sync_add_and_fetch(held, 1) > SE_EXIT_TOMBSTONE_ACCOUNT) {\n\t\t__sync_fetch_and_add(held, -1);\n" +
			"\t\treal_owner_exit_count(REAL_OWNER_EXIT_ACCOUNT_OVERFLOW);",
		// S1: the stale-lifetime check (start_time, then the published
		// directory value), at exit and at free.
		"if (real_owner_exit_tomb_insert(key, physical->start_time,",
		// At exit every tombstone at the key is an earlier lifetime's; at
		// free, start_time and the published directory value decide.
		"if (!old || !real_owner_exit_tomb_stale(key, old, physical))",
		"int foreign = tomb->start != physical->start_time;",
		"foreign = value && value != tomb->locator;",
		"if (foreign) {\n\t\t(void)real_owner_exit_tomb_stale(key, tomb, physical);\n\t\treturn 0;\n\t}",
		// A held DEAD lease (PENDING in se_or_task_visit) is witnessed:
		// accounted only by this charge's own DIR_PENDING/FREE_PENDING
		// tombstone, otherwise counted HELD_STUCK once it persists.
		"#define SE_OR_TASK_HELD(slot, cookie, locator, leases) \\\n\treal_owner_exit_held_watch((slot), (cookie), (locator), (leases))",
		"(tomb->stage == REAL_OWNER_EXIT_DIR_PENDING ||\n\t\t     tomb->stage == REAL_OWNER_EXIT_FREE_PENDING)) {\n\t\t\treal_owner_exit_held_clear(slot, cookie);",
		"if (watch->counted || now - watch->since < REAL_OWNER_EXIT_HELD_STUCK_NS)\n\t\treturn;\n" +
			"\tif (__sync_val_compare_and_swap(&watch->counted, 0, 1) == 0)\n\t\treal_owner_exit_count(REAL_OWNER_EXIT_HELD_STUCK);",
		// The tombstone retirement runs only lease-free (the visit's check).
		"real_owner_exit_tomb_reap(__u32 slot, __u64 cookie, __u64 locator)\n{\n\treal_owner_exit_held_clear(slot, cookie);",
		// The high-water mark is ExitCreditHighWaterPercent of the map, and
		// each upward crossing is counted once.
		fmt.Sprintf("#define REAL_OWNER_EXIT_HIGH_MARK \\\n\t((SE_EXIT_TOMBSTONE_ENTRIES * %dULL + 99) / 100)", ExitCreditHighWaterPercent),
		"if (n == REAL_OWNER_EXIT_HIGH_MARK)\n\t\treal_owner_exit_count(REAL_OWNER_EXIT_HIGH_CROSSED);",
		// A lease the free cannot rebuild or release is counted apart.
		"if (!exact || se_of_release(&lease, physical) != SE_OL_OK)\n\t\treal_owner_exit_count(REAL_OWNER_EXIT_LEASE_FAULT);",
		// N2: -EEXIST, -EBUSY and a full map are counted apart.
		"real_owner_exit_count(err == -17 ? REAL_OWNER_EXIT_BLOCKED :\n\t\t\t\t      err == -16 ? REAL_OWNER_EXIT_BUSY :\n\t\t\t\t\t\t   REAL_OWNER_EXIT_OVERFLOW);",
		// S2: UNSETTLED split by se_of_record_death's code.
		"real_owner_exit_count(death == SE_OL_CONTENDED ?\n\t\t\t\t\t      REAL_OWNER_EXIT_UNSETTLED :\n\t\t\t\t\t      REAL_OWNER_EXIT_UNSETTLED_FAULT);",
		// S3: only the FREE_PENDING -> RETIRING CAS winner deletes.
		"if (__sync_val_compare_and_swap(&tomb->stage,\n\t\t\t\t\tREAL_OWNER_EXIT_FREE_PENDING,\n\t\t\t\t\tREAL_OWNER_EXIT_RETIRING) !=\n\t    REAL_OWNER_EXIT_FREE_PENDING) {",
		// S1: a disarmed gate still consumes the tombstone (no fallback).
		"if (!real_owner_image_configured()) {\n#ifdef ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE\n" +
			"\t\t/* Consume a tombstone the armed exit left: a gate disarmed\n\t\t * between exit and free must not strand it. No fallback runs,\n" +
			"\t\t * as before credit at exit. */\n\t\t(void)real_owner_exit_free(physical);\n#endif\n\t\treturn 0;\n\t}",
		// Without the injector the exit calls the production helpers.
		"#else\n#define SE_FC_EXIT_WITHDRAW(lease, physical) \\\n\tse_of_withdraw_directory((lease), (physical))\n" +
			"#define SE_FC_EXIT_RECORD_DEATH(physical, lease) \\\n\tse_of_record_death((physical), (lease))\n#endif\n",
		// S5: the free-time resume reuses the withdrawal's own stages.
		"if (directory == SE_OL_WITHDRAW_CLAIM) {\n\t\tint advanced =\n\t\t\tse_of_withdraw_advance(meta, archive, cookie, locator);\n" +
			"\t\tif (advanced != SE_OL_OK)\n\t\t\treturn advanced;\n\t}\n\treturn se_of_withdraw_delete(meta, archive, cookie);",
		// A: the birth receipt is retired at exit, not counted as failed.
		"#ifdef SE_REAL_OWNER_BIRTH_QUALIFY\n\t/* Retire this task's birth receipt at exit, charged or not:",
		"\t(void)bpf_map_delete_elem(&opaque_birth_receipts, &key);\n#endif\n\t/* An uncharged task carries nothing: one directory lookup. */",
		// Guards: the feature needs the product reap events; the test-only
		// tombstone override needs the disposable bootstrap and a bound.
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE\n" +
			"#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE\n" +
			"#error \"credit at exit requires the product reap events\"\n#endif\n",
		"#ifdef SE_TEST_EXIT_TOMBSTONE_ENTRIES\n" +
			"#ifndef ENFORCE_EXEC_POOL_OPAQUE_REAL_LIVE_BOOTSTRAP_DIAGNOSTIC\n" +
			"#error \"shrunken exit tombstones require the disposable bootstrap\"\n#endif\n",
		"#if SE_TEST_EXIT_TOMBSTONE_ENTRIES < 1 || \\\n" +
			"    SE_TEST_EXIT_TOMBSTONE_ENTRIES > 32 * SE_PROFILE_TASKS\n" +
			"#error \"exit tombstone override must be 1..32*SE_PROFILE_TASKS\"\n#endif\n",
		// U1: the table is its own profile parameter (default 32 x TASKS,
		// an exact multiple of the bindings).
		"#ifndef SE_PROFILE_EXIT_TOMBSTONES\n#define SE_PROFILE_EXIT_TOMBSTONES (32 * SE_PROFILE_TASKS)\n#endif\n" +
			"_Static_assert(SE_PROFILE_EXIT_TOMBSTONES >= SE_PROFILE_BINDINGS &&\n" +
			"\t\t       SE_PROFILE_EXIT_TOMBSTONES % SE_PROFILE_BINDINGS == 0 &&\n",
		"#define SE_EXIT_TOMBSTONE_ENTRIES SE_PROFILE_EXIT_TOMBSTONES",
		// The injector exists only with both the feature and the injectors,
		// never in the product diagnostic twin.
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_DIAGNOSTIC) && \\\n" +
			"\t!defined(SE_PRODUCT_DIAGNOSTIC_TWIN)\n#define SE_FC_EXIT_INJECTOR 1\n#endif\n",
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE\n#ifdef SE_FC_EXIT_INJECTOR\n",
		// task_free: the fallback is skipped only for a consumed tombstone.
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE\n" +
			"\tif (real_owner_exit_free(physical))\n\t\treturn 0;\n#endif\n",
	} {
		if !strings.Contains(squashed, squashSpace(pin)) {
			t.Errorf("candidate source lacks %q", pin)
		}
	}
	// Fail-closed by ordering: in the exit program, an uncharged task
	// returns, then the tombstone insert precedes the DEAD transition and
	// the TASK_DEAD wakeup follows a completed settlement only.
	start := strings.Index(source, "SEC(\"tp_btf/sched_process_exit\")")
	if start < 0 {
		t.Fatal("candidate source lacks the exit program")
	}
	end := strings.Index(source[start:], "\n}\n")
	if end < 0 {
		t.Fatal("exit program has no end")
	}
	body := squashSpace(source[start : start+end])
	last := -1
	for _, step := range []string{
		"bpf_map_delete_elem(&opaque_birth_receipts,&key);",
		"const__u64*published=SE_OL_LOOKUP(&key);if(!published)return0;",
		"__u64value=se_ol_load_scalar(published);if(!value)return0;",
		"if(real_owner_exit_tomb_insert(key,physical->start_time,charged/SE_OC_QUOTA,physical))return0;",
		"intdeath=SE_FC_EXIT_RECORD_DEATH(physical,&lease);",
		"tomb->cookie=lease.cookie;tomb->locator=lease.locator;tomb->slot=lease.slot;",
		"tomb->flags=flags;",
		"SE_FC_EXIT_WITHDRAW(&lease,physical)==SE_OL_OK&&se_of_release(&lease,physical)==SE_OL_OK;",
		"if(settled)SE_REAP_EVENT(TASK_DEAD,",
	} {
		at := strings.Index(body, step)
		if at <= last {
			t.Fatalf("exit program step %q missing or out of order (at %d, previous %d)", step, at, last)
		}
		last = at
	}
	// The whole exit program and the tombstone map are compiled only with
	// the feature: each follows its guard's #ifdef with no #endif between.
	for _, anchor := range []string{
		"SEC(\"tp_btf/sched_process_exit\")", "} se_exit_tombstones SEC(\".maps\");", "} opaque_real_exit_accounts SEC(\".maps\");",
		"} se_exit_held_watch SEC(\".maps\");", "#define SE_OR_TASK_HELD(",
	} {
		at := strings.Index(source, anchor)
		guard := strings.LastIndex(source[:at], "#ifdef ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE\n")
		if at < 0 || guard < 0 || strings.Count(source[guard:at], "#if") != strings.Count(source[guard:at], "#endif")+1 {
			t.Errorf("%s is not inside the ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE guard", anchor)
		}
	}
}
