// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// Repeated actual child execs retain a qualified parent, unlike the one-shot
// parent test whose deliberately quarantined Audit history cannot seed forks.
// Bootstrap birth/qualify remain attached for this isolated diagnostic only.
func runOpaqueRealPolicyBridgeChildChurn(t *testing.T, collection *ebpf.Collection,
	stdin io.Writer, reader *bufio.Reader, cmd *exec.Cmd, parent, parentLocator uint64,
	cgroup uint64, stderr *bytes.Buffer, births int, pendingABA bool,
) {
	t.Helper()
	parentCharge, err := collection.Maps["se_opaque_charges"].LookupBytes(uint32(0))
	if err != nil || len(parentCharge) < 8 {
		t.Fatalf("parent TASK charge: raw=%x err=%v", parentCharge, err)
	}
	parentCookie := binary.LittleEndian.Uint64(parentCharge[:8])
	if parentCookie == 0 {
		t.Fatal("qualified parent lacks exact TASK cookie")
	}
	seen := make(map[uint64]struct{ cookie, locator uint64 })
	reuses := 0
	var preparedCount uint64
	var lastTaskCookie, lastWorkCookie uint64
	for iteration := 0; iteration < births; iteration++ {
		if _, err := stdin.Write([]byte("FORK\n")); err != nil {
			t.Fatalf("child %d request: %v", iteration, err)
		}
		forked, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(forked, "FORKED:") ||
			!strings.HasSuffix(forked, ":0\n") {
			t.Fatalf("child %d exec: line=%q err=%v stderr=%q",
				iteration, forked, err, stderr.String())
		}
		var child, locator uint64
		keys := collection.Maps["se_opaque_keys"].Iterate()
		for keys.Next(&child, &locator) {
			if child != parent {
				break
			}
		}
		if keys.Err() != nil || child == 0 || child == parent ||
			locator == 0 {
			t.Fatalf("child %d exact TASK missing: physical=%#x locator=%#x err=%v",
				iteration, child, locator, keys.Err())
		}
		var extra, extraLocator uint64
		for keys.Next(&extra, &extraLocator) {
			if extra != parent && extra != child {
				t.Fatalf("child %d found unexpected TASK %#x/%#x", iteration, extra, extraLocator)
			}
		}
		if keys.Err() != nil {
			t.Fatal(keys.Err())
		}
		childCharge, err := collection.Maps["se_opaque_charges"].LookupBytes(uint32(1))
		if err != nil || len(childCharge) < 8 {
			t.Fatalf("child %d TASK charge: raw=%x err=%v", iteration, childCharge, err)
		}
		cookie := binary.LittleEndian.Uint64(childCharge[:8])
		if cookie <= lastTaskCookie {
			t.Fatalf("child %d TASK cookie did not advance: previous=%d current=%d",
				iteration, lastTaskCookie, cookie)
		}
		lastTaskCookie = cookie
		prior, reused := seen[child]
		if reused {
			reuses++
			if cookie <= prior.cookie || locator == prior.locator {
				t.Fatalf("child %d ABA reused stale identity: physical=%#x old=%d/%#x new=%d/%#x",
					iteration, child, prior.cookie, prior.locator, cookie, locator)
			}
			stale := struct {
				Cookie        uint64
				Slot, Enabled uint32
			}{prior.cookie, 1, 1}
			if err := collection.Maps["opaque_real_live_task_reap_request"].Update(
				uint32(0), stale, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			if code, _, err := collection.Programs["opaque_real_live_reap_task"].Test(
				make([]byte, 64)); err != nil || code != 4 {
				t.Fatalf("child %d stale TASK cookie accepted: code=%d err=%v", iteration, code, err)
			}
			var currentLocator uint64
			if err := collection.Maps["se_opaque_keys"].Lookup(child, &currentLocator); err != nil ||
				currentLocator != locator {
				t.Fatalf("child %d stale TASK reap touched successor: got=%#x want=%#x err=%v",
					iteration, currentLocator, locator, err)
			}
			if raw, err := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0)); err != nil || len(raw) < 12 || binary.LittleEndian.Uint32(raw[4:8]) != 2 ||
				binary.LittleEndian.Uint32(raw[8:12]) != 0 {
				t.Fatalf("child %d stale TASK reap changed/faulted successor account: raw=%x err=%v",
					iteration, raw, err)
			}
		}
		seen[child] = struct{ cookie, locator uint64 }{cookie, locator}
		var workCookie uint64
		returned := false
		if !pendingABA || !reused {
			preparedCount++
			var witness realPolicyBridgeWitness
			if err := collection.Maps["opaque_real_owner_policy_witness"].Lookup(uint32(0), &witness); err != nil ||
				witness.Prepared != preparedCount ||
				witness.Physical != child || witness.Cookie != cookie ||
				witness.Invocation == 0 {
				t.Fatalf("child %d real-map bridge did not prepare exact policy: %+v err=%v",
					iteration, witness, err)
			}
			if progressMap := collection.Maps["opaque_real_owner_rule_progress"]; progressMap != nil {
				var progress struct {
					StageBegin, RuleEval, Matched, ObservedUID int32
					RuleEvalCount, MatchedCount                uint64
				}
				if err := progressMap.Lookup(uint32(0), &progress); err != nil ||
					progress.StageBegin != 1 || progress.RuleEval != 1 ||
					progress.Matched != 1 || progress.ObservedUID != 0 ||
					progress.RuleEvalCount != preparedCount ||
					progress.MatchedCount != preparedCount {
					t.Fatalf("child %d actual UID rule count: %+v prepared=%d err=%v",
						iteration, progress, preparedCount, err)
				}
			}
			var receipt [64]byte
			if err := collection.Maps["se_exec_terminal_receipts"].Lookup(child, &receipt); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("child %d retained terminal receipt: raw=%x err=%v", iteration, receipt, err)
			}
			payload, err := collection.Maps["se_opaque_payload"].LookupBytes(uint32(1))
			if err != nil || len(payload) < 8 ||
				binary.LittleEndian.Uint32(payload[4:8])&2 == 0 {
				t.Fatalf("child %d missing conservative Audit quarantine: raw=%x err=%v",
					iteration, payload[:min(len(payload), 8)], err)
			}
			workCharge, err := collection.Maps["se_opaque_work_charges"].LookupBytes(uint32(0))
			if err != nil || len(workCharge) < 8 {
				t.Fatalf("child %d WORK charge: raw=%x err=%v", iteration, workCharge, err)
			}
			workCookie = binary.LittleEndian.Uint64(workCharge[:8])
			if workCookie <= lastWorkCookie {
				t.Fatalf("child %d WORK cookie did not advance: previous=%d current=%d",
					iteration, lastWorkCookie, workCookie)
			}
			if lastWorkCookie != 0 {
				stale := struct {
					Cookie        uint64
					Slot, Enabled uint32
				}{lastWorkCookie, 0, 1}
				if err := collection.Maps["opaque_real_live_work_reap_request"].Update(
					uint32(0), stale, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				if code, _, err := collection.Programs["opaque_real_live_reap_work"].Test(
					make([]byte, 64)); err != nil || code != 3 {
					t.Fatalf("child %d stale WORK cookie accepted: code=%d err=%v", iteration, code, err)
				}
				current, err := collection.Maps["se_opaque_work_charges"].LookupBytes(uint32(0))
				if err != nil || len(current) < 8 || binary.LittleEndian.Uint64(current[:8]) != workCookie {
					t.Fatalf("child %d stale WORK reap touched successor charge: raw=%x err=%v",
						iteration, current, err)
				}
				if raw, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0)); err != nil || len(raw) < 12 || binary.LittleEndian.Uint32(raw[4:8]) != 1 ||
					binary.LittleEndian.Uint32(raw[8:12]) != 0 {
					t.Fatalf("child %d stale WORK reap changed/faulted successor account: raw=%x err=%v",
						iteration, raw, err)
				}
			}
			lastWorkCookie = workCookie
			workRequest := struct {
				Cookie        uint64
				Slot, Enabled uint32
			}{workCookie, 0, 1}
			if err := collection.Maps["opaque_real_live_work_reap_request"].Update(
				uint32(0), workRequest, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			returned = false
			for step := 0; step < 10; step++ {
				code, _, err := collection.Programs["opaque_real_live_reap_work"].Test(make([]byte, 64))
				if err != nil || code > 1 {
					t.Fatalf("child %d WORK reaper step %d: code=%d err=%v", iteration, step, code, err)
				}
				if code == 1 {
					returned = true
					break
				}
			}
			if !returned {
				t.Fatalf("child %d WORK credit not returned", iteration)
			}
		} else {
			var witness realPolicyBridgeWitness
			if err := collection.Maps["opaque_real_owner_policy_witness"].Lookup(uint32(0), &witness); err != nil ||
				witness.Prepared != preparedCount {
				t.Fatalf("child %d stale receipt unexpectedly prepared policy: %+v err=%v", iteration, witness, err)
			}
			var history struct{ Physical, StaleCookie, StaleLocator, Cgroup uint64 }
			if err := collection.Maps["opaque_real_pending_history"].Lookup(child, &history); err != nil ||
				history.Physical != child || history.StaleCookie != prior.cookie ||
				history.StaleLocator != prior.locator || history.Cgroup != cgroup {
				t.Fatalf("child %d predecessor history differs from observed identity: prior=%+v history=%+v err=%v",
					iteration, prior, history, err)
			}
			var receipt [64]byte
			if err := collection.Maps["se_exec_terminal_receipts"].Lookup(child, &receipt); err != nil ||
				binary.LittleEndian.Uint64(receipt[:8]) != child ||
				binary.LittleEndian.Uint64(receipt[16:24]) != prior.cookie ||
				binary.LittleEndian.Uint64(receipt[24:32]) != prior.locator ||
				binary.LittleEndian.Uint32(receipt[56:60]) != 1 {
				t.Fatalf("child %d did not retain exact predecessor receipt: prior=%+v current=%d/%#x receipt_cookie=%d receipt_locator=%#x phase=%d raw=%x err=%v",
					iteration, prior, cookie, locator,
					binary.LittleEndian.Uint64(receipt[16:24]),
					binary.LittleEndian.Uint64(receipt[24:32]),
					binary.LittleEndian.Uint32(receipt[56:60]), receipt, err)
			}
			payload, err := collection.Maps["se_opaque_payload"].LookupBytes(uint32(1))
			if err != nil || len(payload) < 8 || binary.LittleEndian.Uint32(payload[4:8])&2 == 0 {
				t.Fatalf("child %d stale receipt retained trusted successor: raw=%x err=%v", iteration, payload[:min(len(payload), 8)], err)
			}
			if raw, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0)); err != nil ||
				len(raw) < 8 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
				t.Fatalf("child %d stale receipt charged WORK: raw=%x err=%v", iteration, raw, err)
			}
			selector := struct{ Physical, StaleCookie, StaleLocator, Cgroup uint64 }{
				child, prior.cookie, prior.locator, cgroup,
			}
			if err := collection.Maps["opaque_real_pending_selector"].Update(uint32(0), selector, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			if code, _, err := collection.Programs["opaque_real_pending_receipt_cleanup"].Test(make([]byte, 64)); err != nil || code != 0 {
				t.Fatalf("child %d stale receipt cleanup: code=%d err=%v", iteration, code, err)
			}
			if err := collection.Maps["opaque_real_pending_selector"].Update(uint32(0),
				struct{ Physical, StaleCookie, StaleLocator, Cgroup uint64 }{}, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			if err := collection.Maps["se_exec_terminal_receipts"].Lookup(child, &receipt); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("child %d stale receipt remains after exact test cleanup: raw=%x err=%v", iteration, receipt, err)
			}
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			meta, err := collection.Maps["se_opaque_meta"].LookupBytes(uint32(1))
			if err != nil || len(meta) != 128 {
				t.Fatalf("child %d TASK metadata: len=%d err=%v", iteration, len(meta), err)
			}
			if binary.LittleEndian.Uint32(meta[4:8]) == 2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("child %d task_free did not publish DEAD: meta=%x", iteration, meta)
			}
			time.Sleep(20 * time.Millisecond)
		}
		taskRequest := struct {
			Cookie        uint64
			Slot, Enabled uint32
		}{cookie, 1, 1}
		if err := collection.Maps["opaque_real_live_task_reap_request"].Update(
			uint32(0), taskRequest, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		returned = false
		for step := 0; step < 20; step++ {
			code, _, err := collection.Programs["opaque_real_live_reap_task"].Test(make([]byte, 64))
			if err != nil || code > 4 || code == 4 {
				t.Fatalf("child %d TASK reaper step %d: code=%d err=%v", iteration, step, code, err)
			}
			if code == 2 {
				returned = true
				break
			}
		}
		if !returned {
			t.Fatalf("child %d TASK credit not returned", iteration)
		}
		if err := collection.Maps["se_opaque_keys"].Lookup(child, &locator); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("child %d key retained after refund: locator=%#x err=%v", iteration, locator, err)
		}
		if raw, err := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0)); err != nil || len(raw) < 12 || binary.LittleEndian.Uint32(raw[4:8]) != 1 ||
			binary.LittleEndian.Uint32(raw[8:12]) != 0 {
			t.Fatalf("child %d left TASK charge/fault: raw=%x err=%v", iteration, raw, err)
		}
		if raw, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0)); err != nil || len(raw) < 8 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
			t.Fatalf("child %d left WORK charge: raw=%x err=%v", iteration, raw, err)
		}
		if pendingABA {
			history := struct{ Physical, StaleCookie, StaleLocator, Cgroup uint64 }{
				child, cookie, seen[child].locator, cgroup,
			}
			if err := collection.Maps["opaque_real_pending_history"].Update(child, history, ebpf.UpdateAny); err != nil {
				t.Fatalf("child %d predecessor history: %v", iteration, err)
			}
		}
		if iteration == 0 || iteration == births-1 || (iteration+1)%512 == 0 {
			t.Logf("staged Audit child churn %d/%d: task_cookie=%d work_cookie=%d reused_physical=%d",
				iteration+1, births, cookie, workCookie, reuses)
		}
	}
	if (pendingABA || os.Getenv("IG_OPAQUE_REAL_LIVE_REQUIRE_ABA") == "1") && reuses == 0 {
		t.Fatalf("no physical address reuse observed among %d child births", births)
	}
	if _, err := stdin.Write([]byte("DONE\n")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("qualified parent exit: %v stderr=%q", err, stderr.String())
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		meta, err := collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
		if err != nil || len(meta) != 128 {
			t.Fatalf("parent TASK metadata: len=%d err=%v", len(meta), err)
		}
		if binary.LittleEndian.Uint32(meta[4:8]) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("parent task_free did not publish DEAD: meta=%x", meta)
		}
		time.Sleep(20 * time.Millisecond)
	}
	parentRequest := struct {
		Cookie        uint64
		Slot, Enabled uint32
	}{parentCookie, 0, 1}
	if err := collection.Maps["opaque_real_live_task_reap_request"].Update(
		uint32(0), parentRequest, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	returned := false
	for step := 0; step < 20; step++ {
		code, _, err := collection.Programs["opaque_real_live_reap_task"].Test(make([]byte, 64))
		if err != nil || code > 4 || code == 4 {
			t.Fatalf("parent TASK reaper step %d: code=%d err=%v", step, code, err)
		}
		if code == 2 {
			returned = true
			break
		}
	}
	if !returned {
		t.Fatal("qualified parent TASK credit not returned")
	}
	if raw, err := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0)); err != nil || len(raw) < 8 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
		t.Fatalf("final TASK account not empty: raw=%x err=%v", raw, err)
	}
	if err := collection.Maps["se_opaque_keys"].Lookup(parent, &parentLocator); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("parent key retained after refund: locator=%#x err=%v", parentLocator, err)
	}
	t.Logf("staged real-map Audit child churn: births=%d reused_physical=%d final_task_cookie=%d final_work_cookie=%d",
		births, reuses, lastTaskCookie, lastWorkCookie)
}
