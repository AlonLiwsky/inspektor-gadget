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
	"github.com/cilium/ebpf/btf"
)

// Synthetic Audit/retained-target diagnostic only. This proves source-owned
// success settlement, not product Ready, policy evaluation, or role transitions.
// An object without ENFORCE_EXEC_POOL_OPAQUE_SUCCESS_SOURCE_COMPLETION_DIAGNOSTIC
// cannot pass: its success receipt remains pending without TC completion.
func runOpaqueRealSuccessSourceCompletionAttached(t *testing.T, collection *ebpf.Collection,
	spec *ebpf.CollectionSpec, stdin io.Writer, cmd *exec.Cmd, physical, locator uint64, stderr *bytes.Buffer,
) {
	t.Helper()
	for _, name := range []string{"opaque_real_owner_work_completion_probe", "opaque_real_owner_work_retry_probe", "opaque_real_owner_terminal_race_complete"} {
		if collection.Programs[name] != nil {
			t.Fatalf("controller completion program unexpectedly loaded: %s", name)
		}
	}
	var receipt [64]byte
	if err := collection.Maps["se_exec_terminal_receipts"].Lookup(physical, &receipt); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("success source did not retire receipt before DONE: raw=%x err=%v", receipt, err)
	}
	var liveLocator uint64
	if err := collection.Maps["se_opaque_keys"].Lookup(physical, &liveLocator); err != nil || liveLocator != locator {
		t.Fatalf("live physical TASK lost exact locator: got=%#x want=%#x err=%v", liveLocator, locator, err)
	}
	meta, err := collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
	if err != nil || len(meta) != 128 || binary.LittleEndian.Uint32(meta[4:8]) != 1 || binary.LittleEndian.Uint32(meta[24:28]) != 0 {
		t.Fatalf("source must settle reader while TASK remains LIVE before DONE: raw=%x err=%v", meta, err)
	}
	payload, err := collection.Maps["se_opaque_payload"].LookupBytes(uint32(0))
	if err != nil {
		t.Fatal(err)
	}
	var taskType *btf.Struct
	if err := spec.Types.TypeByName("se_task_state", &taskType); err != nil {
		t.Fatal(err)
	}
	for _, path := range [][]string{{"reader", "owned"}, {"exec", "owned"}, {"reader_invocation"}} {
		offset, size := opaqueSourceField(t, taskType, path)
		if offset+size > len(payload) {
			t.Fatalf("TASK field %v outside payload", path)
		}
		for _, value := range payload[offset : offset+size] {
			if value != 0 {
				t.Fatalf("success retained TASK %v before DONE: raw=%x", path, payload[offset:offset+size])
			}
		}
	}
	taskCharge, err := collection.Maps["se_opaque_charges"].LookupBytes(uint32(0))
	if err != nil || len(taskCharge) < 8 {
		t.Fatalf("TASK charge: raw=%x err=%v", taskCharge, err)
	}
	taskCookie := binary.LittleEndian.Uint64(taskCharge[:8])
	if taskCookie == 0 {
		t.Fatal("live TASK lost exact cleanup cookie")
	}
	if _, err := stdin.Write([]byte("DONE\n")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("source completion parent exit: %v stderr=%q", err, stderr.String())
	}
	// Only exact diagnostic reapers run after DONE; no completion test-run.
	chargedWorks := 0
	for slot := uint32(0); slot < 16; slot++ {
		workCharge, err := collection.Maps["se_opaque_work_charges"].LookupBytes(slot)
		if err != nil || len(workCharge) < 8 {
			t.Fatalf("source completion WORK slot %d charge: raw=%x err=%v", slot, workCharge, err)
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
				t.Fatalf("source completion WORK slot %d cookie %d reap step %d: code=%d err=%v meta=%x", slot, workCookie, step, code, err, meta)
			}
			if code == 1 {
				returned = true
				break
			}
		}
		if !returned {
			t.Fatalf("source completion WORK slot %d cookie %d credit not returned", slot, workCookie)
		}
	}
	if chargedWorks == 0 {
		t.Fatal("source completion committed without a charged WORK")
	}
	if raw, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0)); err != nil ||
		len(raw) < 8 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
		t.Fatalf("source completion WORK charge retained after %d exact reaps: raw=%x err=%v", chargedWorks, raw, err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		meta, err := collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
		if err != nil || len(meta) != 128 {
			t.Fatalf("dead TASK metadata: raw=%x err=%v", meta, err)
		}
		if binary.LittleEndian.Uint32(meta[4:8]) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("source completion TASK did not reach DEAD: meta=%x", meta)
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
			t.Fatalf("source completion TASK reap step %d: code=%d err=%v", step, code, err)
		}
		if code == 2 {
			returned = true
			break
		}
	}
	if !returned {
		t.Fatal("source completion TASK credit not returned")
	}
	if raw, err := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0)); err != nil ||
		len(raw) < 8 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
		t.Fatalf("source completion TASK charge retained: raw=%x err=%v", raw, err)
	}
	if err := collection.Maps["se_opaque_keys"].Lookup(physical, &locator); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("source completion TASK key retained: locator=%#x err=%v", locator, err)
	}
	t.Log("real sched_process_exec settled receipt, exec and reader before DONE; zero TC completion calls; exact WORK/TASK refunds; synthetic Audit only, no product Ready or roles")
}

// Derive semantic field locations from this object's BTF, not guessed wire offsets.
func opaqueSourceField(t *testing.T, root *btf.Struct, path []string) (int, int) {
	t.Helper()
	var current btf.Type = root
	offset := 0
	for _, name := range path {
		structure, ok := btf.UnderlyingType(current).(*btf.Struct)
		if !ok {
			t.Fatalf("non-struct in TASK field %v", path)
		}
		found := false
		for _, member := range structure.Members {
			if member.Name == name {
				if member.BitfieldSize != 0 || member.Offset%8 != 0 {
					t.Fatalf("unaligned TASK field %v", path)
				}
				offset += int(member.Offset / 8)
				current = member.Type
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing TASK field %v", path)
		}
	}
	size, err := btf.Sizeof(current)
	if err != nil {
		t.Fatal(err)
	}
	return offset, size
}

func TestOpaqueSourceFieldNestedOwnership(t *testing.T) {
	u32 := &btf.Int{Name: "u32", Size: 4}
	reader := &btf.Struct{Name: "reader", Size: 48, Members: []btf.Member{{Name: "owned", Type: u32, Offset: 40 * 8}}}
	task := &btf.Struct{Name: "task", Size: 128, Members: []btf.Member{{Name: "reader", Type: reader, Offset: 48 * 8}}}
	offset, size := opaqueSourceField(t, task, []string{"reader", "owned"})
	if offset != 88 || size != 4 {
		t.Fatalf("ownership field: offset=%d size=%d, want 88/4", offset, size)
	}
}
