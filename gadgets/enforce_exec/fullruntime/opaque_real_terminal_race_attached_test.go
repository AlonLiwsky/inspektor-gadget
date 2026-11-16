// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os/exec"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

// A test-only tail-call target leaves the exact reader to the real success
// producer. Concurrent TC test-runs then contend for that same receipt. The
// witness distinguishes actual overlapping entries from mere goroutine launch;
// a batch runner must require observed overlap before calling it race proof.
func runOpaqueRealTerminalRaceAttached(t *testing.T, collection *ebpf.Collection,
	stdin io.Writer, cmd *exec.Cmd, physical, locator uint64, stderr *bytes.Buffer,
	producerFailure bool,
) {
	t.Helper()
	expectedPhase := uint32(2)
	if producerFailure {
		expectedPhase = 3
	}
	var receipt struct {
		Physical, Bprm, Cookie, Locator, Invocation, Scope, Generation uint64
		Phase, Reserved                                                uint32
	}
	if err := collection.Maps["se_exec_terminal_receipts"].Lookup(physical, &receipt); err != nil ||
		receipt.Physical != physical || receipt.Bprm == 0 || receipt.Cookie == 0 ||
		receipt.Locator != locator || receipt.Invocation == 0 ||
		receipt.Scope != 10 || receipt.Generation != 1 || receipt.Phase != expectedPhase || receipt.Reserved != 0 {
		t.Fatalf("real terminal phase %d not retained: %+v err=%v", expectedPhase, receipt, err)
	}
	taskCookie := receipt.Cookie
	if err := collection.Maps["opaque_real_owner_work_completion_selector"].Update(
		uint32(0), physical, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["opaque_real_owner_work_completion_gate"].Update(
		uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"opaque_real_owner_work_completion_selector",
		"opaque_real_owner_work_completion_gate",
	} {
		if err := collection.Maps[name].Freeze(); err != nil {
			t.Fatal(err)
		}
	}
	const competitors = 64
	start := make(chan struct{})
	failures := make(chan error, competitors)
	var wg sync.WaitGroup
	var ready sync.WaitGroup
	ready.Add(competitors)
	for i := 0; i < competitors; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ready.Done()
			<-start
			code, _, err := collection.Programs["opaque_real_owner_terminal_race_complete"].Test(make([]byte, 64))
			if err == nil && code != 0 {
				err = errors.New("race entrypoint returned nonzero")
			}
			failures <- err
		}()
	}
	ready.Wait()
	close(start)
	wg.Wait()
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatalf("concurrent terminal test-run: %v", err)
		}
	}
	var witness struct {
		Attempts, Commits, Inflight, Overlap     uint64
		Authenticated, AuthInflight, AuthOverlap uint64
	}
	if err := collection.Maps["opaque_real_terminal_race_witness"].Lookup(uint32(0), &witness); err != nil ||
		witness.Attempts != competitors || witness.Commits != 1 || witness.Inflight != 0 ||
		witness.Authenticated == 0 || witness.AuthInflight != 0 {
		t.Fatalf("terminal race lacked single commit: %+v err=%v", witness, err)
	}
	if err := collection.Maps["se_exec_terminal_receipts"].Lookup(physical, &receipt); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("terminal race retained receipt: %+v err=%v", receipt, err)
	}
	meta, err := collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
	if err != nil || len(meta) < 28 || binary.LittleEndian.Uint32(meta[24:28]) != 0 {
		t.Fatalf("terminal race retained reader hold: raw=%x err=%v", meta, err)
	}
	// Competing readers may allocate distinct WORK slots before one wins
	// completion. Every charged contender must become exactly reclaimable.
	chargedWorks := 0
	for slot := uint32(0); slot < 16; slot++ {
		workCharge, err := collection.Maps["se_opaque_work_charges"].LookupBytes(slot)
		if err != nil || len(workCharge) < 8 {
			t.Fatalf("terminal race WORK slot %d charge: raw=%x err=%v", slot, workCharge, err)
		}
		workCookie := binary.LittleEndian.Uint64(workCharge[:8])
		if workCookie == 0 {
			continue
		}
		chargedWorks++
		workRequest := struct {
			Cookie        uint64
			Slot, Enabled uint32
		}{workCookie, slot, 1}
		if err := collection.Maps["opaque_real_live_work_reap_request"].Update(
			uint32(0), workRequest, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		returned := false
		for step := 0; step < 10; step++ {
			code, _, err := collection.Programs["opaque_real_live_reap_work"].Test(make([]byte, 64))
			if err != nil || code > 1 {
				meta, _ := collection.Maps["se_opaque_work_meta"].LookupBytes(slot)
				t.Fatalf("terminal race WORK slot %d cookie %d reap step %d: code=%d err=%v meta=%x", slot, workCookie, step, code, err, meta)
			}
			if code == 1 {
				returned = true
				break
			}
		}
		if !returned {
			t.Fatalf("terminal race WORK slot %d cookie %d credit not returned", slot, workCookie)
		}
	}
	if chargedWorks == 0 {
		t.Fatal("terminal race committed without a charged WORK")
	}
	if raw, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0)); err != nil ||
		len(raw) < 8 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
		t.Fatalf("terminal race WORK charge retained after %d exact reaps: raw=%x err=%v", chargedWorks, raw, err)
	}
	if _, err := stdin.Write([]byte("DONE\n")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("terminal race parent exit: %v stderr=%q", err, stderr.String())
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		meta, err = collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
		if err != nil || len(meta) != 128 {
			t.Fatalf("dead TASK metadata: raw=%x err=%v", meta, err)
		}
		if binary.LittleEndian.Uint32(meta[4:8]) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("terminal race TASK did not reach DEAD: meta=%x", meta)
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
	returned := false
	for step := 0; step < 20; step++ {
		code, _, err := collection.Programs["opaque_real_live_reap_task"].Test(make([]byte, 64))
		if err != nil || code > 4 || code == 4 {
			t.Fatalf("terminal race TASK reap step %d: code=%d err=%v", step, code, err)
		}
		if code == 2 {
			returned = true
			break
		}
	}
	if !returned {
		t.Fatal("terminal race TASK credit not returned")
	}
	if raw, err := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0)); err != nil ||
		len(raw) < 8 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
		t.Fatalf("terminal race TASK charge retained: raw=%x err=%v", raw, err)
	}
	if err := collection.Maps["se_opaque_keys"].Lookup(physical, &locator); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("terminal race TASK key retained: locator=%#x err=%v", locator, err)
	}
	t.Logf("same real terminal contested by %d calls with %d entry overlaps, %d authenticated contenders and %d after-auth overlaps, exactly %d commit, %d WORK charges and TASK refunded",
		witness.Attempts, witness.Overlap, witness.Authenticated, witness.AuthOverlap,
		witness.Commits, chargedWorks)
}
