// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// Called only by the opt-in isolated-cgroup attached diagnostic. The policy
// seed and witness are BPF-only test authority, never product publication.
type realPolicyBridgeWitness struct {
	Prepared, Physical, Cookie, Invocation uint64
}

func runOpaqueRealPolicyBridgeAttached(t *testing.T, collection *ebpf.Collection,
	stdin io.Writer, cmd *exec.Cmd, physical, locator uint64, stderr *bytes.Buffer,
	expectPrepared, expectWork, expectRuleMissing, expectUIDMatch bool,
) {
	t.Helper()
	var witness realPolicyBridgeWitness
	if progressMap := collection.Maps["opaque_real_owner_rule_progress"]; progressMap != nil {
		var progress struct {
			StageBegin, RuleEval, Matched, ObservedUID int32
			RuleEvalCount, MatchedCount                uint64
		}
		if err := progressMap.Lookup(uint32(0), &progress); err != nil {
			t.Fatalf("read rule progress: %v", err)
		}
		t.Logf("diagnostic rule progress: stage_begin=%d rule_eval=%d matched=%d observed_uid=%d",
			progress.StageBegin, progress.RuleEval, progress.Matched, progress.ObservedUID)
		if expectPrepared && (progress.StageBegin != 1 || progress.RuleEval != 1) {
			t.Fatalf("staged rule target did not complete its exact window: %+v", progress)
		}
		if expectRuleMissing && (progress.StageBegin != 1 || progress.RuleEval != 0) {
			t.Fatalf("missing rule target did not exercise stage fallback: %+v", progress)
		}
		if expectPrepared {
			want := int32(0)
			if expectUIDMatch {
				want = 1
			}
			wantMatches := uint64(want)
			if progress.ObservedUID != 0 || progress.Matched != want ||
				progress.RuleEvalCount != 1 || progress.MatchedCount != wantMatches {
				t.Fatalf("observed UID predicate mismatch: got=%+v want_matched=%d", progress, want)
			}
		}
	}
	if err := collection.Maps["opaque_real_owner_policy_witness"].Lookup(uint32(0), &witness); err != nil ||
		(expectPrepared && (witness.Prepared != 1 || witness.Physical != physical ||
			witness.Cookie == 0 || witness.Invocation == 0)) ||
		(!expectPrepared && witness != (realPolicyBridgeWitness{})) {
		t.Fatalf("actual staged real-map preparation not witnessed: %+v err=%v", witness, err)
	}
	var receipt [64]byte
	if err := collection.Maps["se_exec_terminal_receipts"].Lookup(physical, &receipt); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("target did not retire the exact Audit receipt: raw=%x err=%v", receipt, err)
	}
	payload, err := collection.Maps["se_opaque_payload"].LookupBytes(uint32(0))
	if err != nil || len(payload) < 8 || binary.LittleEndian.Uint32(payload[4:8])&2 == 0 {
		t.Fatalf("unproven Audit policy path retained trusted TASK: flags=%#x err=%v",
			payload[:min(len(payload), 8)], err)
	}
	meta, err := collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
	if err != nil || len(meta) < 28 || binary.LittleEndian.Uint32(meta[24:28]) != 0 {
		t.Fatalf("Audit reader hold not closed: raw=%x err=%v", meta, err)
	}
	taskCharge, err := collection.Maps["se_opaque_charges"].LookupBytes(uint32(0))
	if err != nil || len(taskCharge) < 8 {
		t.Fatalf("staged TASK charge: raw=%x err=%v", taskCharge, err)
	}
	taskCookie := binary.LittleEndian.Uint64(taskCharge[:8])
	if taskCookie == 0 || expectPrepared && taskCookie != witness.Cookie {
		t.Fatalf("staged TASK cookie mismatch: charge=%d witness=%d", taskCookie, witness.Cookie)
	}
	returned := false
	if expectWork {
		workCharge, err := collection.Maps["se_opaque_work_charges"].LookupBytes(uint32(0))
		if err != nil || len(workCharge) < 8 {
			t.Fatalf("prepared WORK charge missing: raw=%x err=%v", workCharge, err)
		}
		workCookie := binary.LittleEndian.Uint64(workCharge[:8])
		if workCookie == 0 {
			t.Fatal("prepared WORK lost its exact reaper identity")
		}
		workRequest := struct {
			Cookie        uint64
			Slot, Enabled uint32
		}{workCookie, 0, 1}
		if err := collection.Maps["opaque_real_live_work_reap_request"].Update(
			uint32(0), workRequest, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		returned = false
		for i := 0; i < 10; i++ {
			code, _, err := collection.Programs["opaque_real_live_reap_work"].Test(make([]byte, 64))
			if err != nil || code > 1 {
				t.Fatalf("staged WORK reap step %d: code=%d err=%v", i, code, err)
			}
			if code == 1 {
				returned = true
				break
			}
		}
		if !returned {
			t.Fatal("staged WORK credit not returned")
		}
		if raw, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0)); err != nil || len(raw) < 8 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
			t.Fatalf("staged WORK account not empty: raw=%x err=%v", raw, err)
		}
	} else if raw, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0)); err != nil || len(raw) < 8 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
		t.Fatalf("missing target unexpectedly charged WORK: raw=%x err=%v", raw, err)
	}
	if _, err := stdin.Write([]byte("DONE\n")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("tracked Audit parent exit: %v stderr=%q", err, stderr.String())
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		meta, err = collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
		if err != nil || len(meta) != 128 {
			t.Fatalf("dead TASK metadata: len=%d err=%v", len(meta), err)
		}
		if binary.LittleEndian.Uint32(meta[4:8]) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("staged task_free did not publish DEAD: meta=%x", meta)
		}
		time.Sleep(20 * time.Millisecond)
	}
	taskRequest := struct {
		Cookie        uint64
		Slot, Enabled uint32
	}{taskCookie, 0, 1}
	if err := collection.Maps["opaque_real_live_task_reap_request"].Update(
		uint32(0), taskRequest, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	returned = false
	for i := 0; i < 20; i++ {
		code, _, err := collection.Programs["opaque_real_live_reap_task"].Test(make([]byte, 64))
		if err != nil || code > 4 || code == 4 {
			t.Fatalf("staged TASK reap visit %d: code=%d err=%v", i, code, err)
		}
		if code == 2 {
			returned = true
			break
		}
	}
	if !returned {
		t.Fatal("staged TASK credit not returned")
	}
	if raw, err := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0)); err != nil || len(raw) < 8 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
		t.Fatalf("staged TASK account not empty: raw=%x err=%v", raw, err)
	}
	if err := collection.Maps["se_opaque_keys"].Lookup(physical, &locator); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("staged TASK key retained after refund: locator=%#x err=%v", locator, err)
	}
	t.Logf("staged real-map Audit preparation=%v, quarantine and exact WORK/TASK refund: physical=%#x cookie=%d invocation=%d",
		expectPrepared, physical, taskCookie, witness.Invocation)
}
