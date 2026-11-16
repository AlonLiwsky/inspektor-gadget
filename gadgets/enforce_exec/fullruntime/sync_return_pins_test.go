// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWorkSyncReturnSourcePins pins the synchronous WORK return at settle
// (G019 option C, ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE):
//   - the flag needs the reap events and credit at exit;
//   - zero once: with the flag the charge-time payload zero is skipped
//     (SE_OWK_INIT_PAYLOAD_ZERO 0) and the header-is-zero check at charge
//     stays as the verifier of the return-time zero (reaper stage 3, which
//     every path to META_FREE passes);
//   - the settle encoding carries the WORK slot + 1 in the high half of R0
//     (no stack in the 512-byte chains);
//   - every settle site calls the synchronous return at its program's top
//     level, after the settling call returned;
//   - the visit claim: tried once, released at exactly one site, no return
//     between claim and release, and every exit other than returned or
//     claim-lost emits a recovery WORK_DONE;
//   - the reap command visits a WORK only under the claim (TASK keeps the
//     single-reaper rule) and answers SE_OWK_CLAIM_HELD otherwise;
//   - the witness cells match work_sync.go.
func TestWorkSyncReturnSourcePins(t *testing.T) {
	raw, err := os.ReadFile("bpf/opaque_real_owner_child_candidate.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	squashed := squashSpace(source)
	for _, pin := range []string{
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE\n" +
			"#if !defined(ENFORCE_EXEC_POOL_OPAQUE_REAP_EVENTS_CANDIDATE) || \\\n" +
			"\t!defined(ENFORCE_EXEC_POOL_OPAQUE_EXIT_CREDIT_CANDIDATE)\n" +
			"#error \"synchronous WORK return requires the reap events and credit at exit\"\n#endif\n" +
			"#define SE_OWK_INIT_PAYLOAD_ZERO(slot) 0\n",
		"#define SE_SETTLE_PACK(result, slot1) \\\n\t((__s64)(((__u64)(slot1) << 32) | (__u32)(result)))\n" +
			"#define SE_SETTLE_RESULT(value) ((int)(value))\n#define SE_SETTLE_SLOT(value) ((__u32)((__u64)(value) >> 32))\n",
		// Without the flag the settling calls still run.
		"#define SE_WORK_SYNC_RETURN(settled, site) ((void)(settled))",
		"#define SE_SETTLE_SLOT(value) (value)",
		// The birth WORK: packed only after an exact DONE.
		"if (se_owk_semantic_done(&semantic, &work) != SE_OL_OK) {\n\t\tse_owk_fault_ticket(&ticket);\n" +
			"\t\treal_owner_child_fault_open_parent(&parent);\n\t}\n" +
			"#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE\n",
		"else\n\t\tresult = SE_SETTLE_PACK(result, ticket.work_slot + 1);\n#endif\n",
		// The evaluation WORK: packed only when closed (exactly DONE).
		"return SE_SETTLE_PACK(ok ? 0 : -1, closed ? ticket.work_slot + 1 : 0);",
		// Top-level synchronous return at every settle site.
		"SE_WORK_SYNC_RETURN(SE_SETTLE_SLOT(result),\n\t\t\t    REAL_OWNER_WORK_SYNC_SETTLED_BIRTH);",
		"if (real_owner_failure_fexit_publish(key, (__u64)bprm))\n\t\tSE_WORK_SYNC_RETURN(\n" +
			"\t\t\tSE_SETTLE_SLOT(real_owner_work_completion_shape(key)),\n\t\t\tREAL_OWNER_WORK_SYNC_SETTLED_EXEC);",
		"/* The callee may delete the receipt; do not use its pointer again. */\n\t\tSE_WORK_SYNC_RETURN(\n" +
			"\t\t\tSE_SETTLE_SLOT(real_owner_work_completion_shape(key)),\n\t\t\tREAL_OWNER_WORK_SYNC_SETTLED_EXEC);",
		// The reap command's WORK step runs under the claim.
		"return slot < SE_OWK_WORKS ? SE_OWK_REAP_CLAIMED(slot, cookie) :\n\t\t\t\t\t     255;",
		"#define SE_OWK_REAP_CLAIMED(slot, cookie) se_owk_reap_step((slot), (cookie))",
		"__u64 held = __sync_val_compare_and_swap(&claim->claim, 0, cookie);",
		"claim->seen = 0;\n\tint result = se_owk_reap_step(slot, cookie);\n" +
			"\t(void)__sync_val_compare_and_swap(&claim->claim, cookie, 0);\n\treturn result;",
		"#define SE_OWK_CLAIM_HELD 6\n",
		// The test-only decision witness: never in a product object, only
		// with the synchronous return, snapshotted under the claim right
		// before the stages (and so before stage 3's payload zero).
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_DECISION_WITNESS_DIAGNOSTIC\n#ifdef SE_PRODUCT_NO_TEST_RUN\n" +
			"#error \"the WORK decision witness is diagnostic only\"\n#endif\n",
		"#if defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_DECISION_WITNESS_DIAGNOSTIC) && \\\n" +
			"\t!defined(ENFORCE_EXEC_POOL_OPAQUE_WORK_SYNC_RETURN_CANDIDATE)\n" +
			"#error \"the WORK decision witness requires the synchronous WORK return\"\n#endif\n",
		"/* Before stage 3 zeroes the payload (test-only witness). */\n\tSE_WORK_DECISION_SNAPSHOT(slot, cookie);\n" +
			"\tstruct real_owner_work_sync_ctx ctx = {",
		"#else\n#define SE_WORK_DECISION_SNAPSHOT(slot, cookie) ((void)0)\n#endif\n",
	} {
		if strings.Count(squashed, squashSpace(pin)) != 1 {
			t.Errorf("synchronous WORK return pin missing or changed:\n%s", pin)
		}
	}
	// Both death sites (exit, task_free fallback) return at top level.
	if n := strings.Count(squashed, squashSpace("SE_WORK_SYNC_RETURN(real_owner_child_work_death(&lease),\n"+
		"\t\t\t    REAL_OWNER_WORK_SYNC_SETTLED_DEATH);")); n != 2 {
		t.Errorf("%d top-level death-site synchronous returns, want 2 (exit, task_free fallback)", n)
	}
	// The synchronous return: one claim, one release, nothing returns in
	// between, the claim is tried once, and every exit after the release
	// other than RETURNED emits a recovery WORK_DONE.
	start := strings.Index(source, "static __attribute__((noinline)) void real_owner_work_sync_return(")
	if start < 0 {
		t.Fatal("real_owner_work_sync_return not found")
	}
	end := strings.Index(source[start:], "\n}\n")
	body := source[start : start+end]
	claim := "if (__sync_val_compare_and_swap(&claim->claim, 0, cookie)) {"
	release := "(void)__sync_val_compare_and_swap(&claim->claim, cookie, 0);"
	if strings.Count(body, claim) != 1 || strings.Count(body, release) != 1 {
		t.Fatalf("synchronous return: %d claims, %d releases, want 1/1", strings.Count(body, claim), strings.Count(body, release))
	}
	held := body[strings.Index(body, claim):strings.Index(body, release)]
	held = held[strings.Index(held, "}")+1:] // after the claim-lost branch
	if strings.Contains(held, "return") {
		t.Error("synchronous return: a return between the claim and its release strands the claim")
	}
	after := body[strings.Index(body, release):]
	if !strings.Contains(squashSpace(after), squashSpace("if (ctx.result == SE_OWK_RETURNED) {\n\t\treal_owner_work_sync_count(REAL_OWNER_WORK_SYNC_RETURNED);\n\t\treturn;\n\t}")) ||
		!strings.HasSuffix(squashSpace(after), squashSpace("SE_REAP_EVENT(WORK_DONE, slot, cookie);")) {
		t.Error("synchronous return: an exit other than RETURNED must emit a recovery WORK_DONE")
	}
	if !strings.Contains(squashSpace(body), squashSpace("real_owner_work_sync_count(REAL_OWNER_WORK_SYNC_STALE);\n\t\tif (cookie)\n\t\t\tSE_REAP_EVENT(WORK_DONE, slot, cookie);\n\t\treturn;")) {
		t.Error("synchronous return: a stale settle must emit a recovery WORK_DONE")
	}
	// Witness cells.
	for name, cell := range map[string]int{
		"SETTLED_BIRTH": workSyncSettledBirth, "SETTLED_EXEC": workSyncSettledExec,
		"SETTLED_DEATH": workSyncSettledDeath, "RETURNED": workSyncReturned,
		"CLAIM_LOST": workSyncClaimLost, "STALE": workSyncStale, "PENDING": workSyncPending,
		"FAULT": workSyncFault, "STUCK": workSyncStuck, "COUNTERS": workSyncCounters,
	} {
		if define := fmt.Sprintf("#define REAL_OWNER_WORK_SYNC_%s %d\n", name, cell); !strings.Contains(source, define) {
			t.Errorf("candidate source lacks %q", strings.TrimSpace(define))
		}
	}
	// Zero once: the charge-time zero is a hook defaulting to the payload
	// zero, and the header-is-zero check after it is unconditional.
	raw, err = os.ReadFile("../full/shared_pool_opaque_work_candidate.h")
	if err != nil {
		t.Fatal(err)
	}
	work := squashSpace(string(raw))
	for _, pin := range []string{
		"#ifndef SE_OWK_INIT_PAYLOAD_ZERO\n#define SE_OWK_INIT_PAYLOAD_ZERO(slot) SE_OWK_PAYLOAD_ZERO(slot)\n#endif\n",
		"if (!task_exact || !work_exact ||\n\t    SE_OWK_INIT_PAYLOAD_ZERO(ticket->work_slot)) {",
		"work->invocation_sequence && !payload->scope &&\n\t\t     !payload->cookie && !payload->sequence && !payload->slot &&\n\t\t     !payload->reserved;",
	} {
		if strings.Count(work, squashSpace(pin)) != 1 {
			t.Errorf("zero-once pin missing or changed:\n%s", pin)
		}
	}
	// Reuse-aware reserve and reap (chain10 6.12 s6 faults): with returns
	// within microseconds of settling, a slot can be returned and recharged
	// between a racing caller's snapshot and its next step. An older
	// cookie at reserve is CONTENDED (retry), and a visit of an
	// already-returned cookie whose slot was recharged is STALE: never
	// CORRUPT or an account fault. Unconditional since chain15 (the same
	// reserve race faulted a non-sync object with the reaper returning):
	// correct for any returner.
	for _, pin := range []string{
		"result = SE_OL_LIMIT;\n\t} else if (charge->state == SE_OWK_FREE && !charge->cookie &&\n" +
			"\t\t   !charge->scope && !charge->owner_locator &&\n\t\t   !charge->owner_cookie && !charge->incarnation &&\n" +
			"\t\t   !charge->owner_slot && !charge->reserved &&\n\t\t   charge->last_returned > cookie &&\n" +
			"\t\t   charge->last_returned < SE_OWK_COOKIE_LIMIT) {",
		"result = SE_OL_CONTENDED;\n\t} else if (charge->state != SE_OWK_FREE || charge->cookie ||",
	} {
		if strings.Count(work, squashSpace(pin)) != 1 {
			t.Errorf("reuse-aware reserve pin missing or changed:\n%s", pin)
		}
	}
	if !strings.Contains(squashed, squashSpace("#define SE_OWK_INIT_PAYLOAD_ZERO(slot) 0")) {
		t.Error("the synchronous return must zero once")
	}
	if strings.Contains(work, "SE_OWK_REUSE_AWARE") || strings.Contains(squashed, "SE_OWK_REUSE_AWARE") {
		t.Error("the reuse-aware reserve and reap are unconditional; no SE_OWK_REUSE_AWARE switch")
	}
	// Test-only WORK account fault-site witness (chain15): every site that
	// faults a WORK account names itself; the default expands to nothing,
	// and the witness never builds into a product object.
	for _, pin := range []string{
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_WORK_FAULT_SITE_DIAGNOSTIC\n#ifdef SE_PRODUCT_NO_TEST_RUN\n" +
			"#error \"the WORK fault-site witness is diagnostic only\"\n#endif\n" +
			"#define SE_OWK_FAULT_SITE(site) (account->fault |= 1U << (site))\n" +
			"#define SE_OWK_FAULT_SITE_CLEAN(site) (account->fault = 1U | 1U << (site))\n#endif",
	} {
		if !strings.Contains(squashed, squashSpace(pin)) {
			t.Errorf("fault-site witness pin missing:\n%s", pin)
		}
	}
	if !strings.Contains(work, squashSpace("#ifndef SE_OWK_FAULT_SITE\n#define SE_OWK_FAULT_SITE(site) \\\n\tdo {                    \\\n\t} while (0)\n#endif")) {
		t.Error("the fault-site witness must expand to nothing by default")
	}
	// Every path to META_FREE passes the payload-zero stage (cleanup_done
	// == 3 is OWNER_RELEASED | PAYLOAD_ZEROED) in the reaper sequence.
	raw, err = os.ReadFile("../full/shared_pool_opaque_work_reap_candidate.h")
	if err != nil {
		t.Fatal(err)
	}
	reap := squashSpace(string(raw))
	if pin := "bpf_spin_lock(&account->lock);\n\t\tint reused = (charge->cookie > expected_cookie &&\n" +
		"\t\t\t      charge->state != SE_OWK_FREE) ||\n\t\t\t     (charge->state == SE_OWK_FREE && !charge->cookie &&\n" +
		"\t\t\t      charge->last_returned > expected_cookie);\n\t\tbpf_spin_unlock(&account->lock);\n" +
		"\t\treturn reused ? SE_OWK_STALE : SE_OWK_CORRUPT;"; strings.Count(reap, squashSpace(pin)) != 1 || strings.Contains(reap, "SE_OWK_REUSE_AWARE") {
		t.Errorf("reuse-aware reap pin missing or changed:\n%s", pin)
	}
	// Each of the nine account-fault sites names itself exactly once (site
	// 5 is the CLEAN store, site 9 is se_owk_fault_exact in the reap
	// header), and the work header still has its eight account faults.
	for n := 1; n <= 9; n++ {
		plain := strings.Count(work+reap, fmt.Sprintf("SE_OWK_FAULT_SITE(%d);", n))
		clean := strings.Count(work+reap, fmt.Sprintf("SE_OWK_FAULT_SITE_CLEAN(%d);", n))
		if want := map[bool]int{true: 1, false: 0}[n == 5]; plain+clean != 1 || clean != want {
			t.Errorf("fault site %d: %d plain, %d CLEAN (want exactly one, CLEAN only for 5)", n, plain, clean)
		}
	}
	if faults := strings.Count(work, "account->fault=1;"); faults != 8 {
		t.Errorf("WORK account faults in the work header: %d, want 8 (each named by a site)", faults)
	}
	for _, pin := range []string{
		"enum { SE_OWK_OWNER_RELEASED = 1, SE_OWK_PAYLOAD_ZEROED = 2 };",
		"int exact = work->phase == SE_OWK_REFUND_PENDING &&\n\t\t\t\t    !work->active_leases &&\n\t\t\t\t    !work->owner_ref_held &&\n\t\t\t\t    work->cleanup_done == 3 &&",
		"if (exact) {\n\t\t\t\twork->phase = SE_OWK_META_FREE;",
	} {
		if strings.Count(reap, squashSpace(pin)) != 1 {
			t.Errorf("reaper META_FREE-after-zero pin missing or changed:\n%s", pin)
		}
	}
	// The reaper's stage 6 is the only META_FREE writer in every header.
	headers, err := filepath.Glob("../full/*.h")
	if err != nil {
		t.Fatal(err)
	}
	writers := 0
	for _, header := range headers {
		raw, err := os.ReadFile(header)
		if err != nil {
			t.Fatal(err)
		}
		writers += strings.Count(squashSpace(string(raw)), squashSpace("phase = SE_OWK_META_FREE"))
	}
	if writers != 1 || strings.Count(reap, squashSpace("work->phase = SE_OWK_META_FREE;")) != 1 {
		t.Errorf("%d META_FREE writers, want exactly the reaper's stage 6 (after the payload zero)", writers)
	}
}
