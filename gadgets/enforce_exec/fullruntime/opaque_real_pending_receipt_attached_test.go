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

	"github.com/cilium/ebpf"
)

// The test-only LSM injector installs a deliberately mismatched terminal
// before the real source runs. This is pending-terminal refusal, not yet a
// physically reused TASK/ABA or simultaneous-terminal-race proof.
func runOpaqueRealPendingReceiptAttached(t *testing.T, collection *ebpf.Collection,
	stdin io.Writer, cmd *exec.Cmd, physical, locator uint64, stderr *bytes.Buffer,
) {
	t.Helper()
	var receipt [64]byte
	charge, err := collection.Maps["se_opaque_charges"].LookupBytes(uint32(0))
	if err != nil || len(charge) < 8 {
		t.Fatalf("live TASK charge: raw=%x err=%v", charge, err)
	}
	currentCookie := binary.LittleEndian.Uint64(charge[:8])
	if err := collection.Maps["se_exec_terminal_receipts"].Lookup(physical, &receipt); err != nil ||
		binary.LittleEndian.Uint64(receipt[:8]) != physical ||
		binary.LittleEndian.Uint64(receipt[16:24]) != currentCookie+1 ||
		binary.LittleEndian.Uint64(receipt[24:32]) != locator+1 ||
		binary.LittleEndian.Uint32(receipt[56:60]) != 1 {
		t.Fatalf("injected stale terminal was overwritten: raw=%x err=%v", receipt, err)
	}
	payload, err := collection.Maps["se_opaque_payload"].LookupBytes(uint32(0))
	if err != nil || len(payload) < 8 || binary.LittleEndian.Uint32(payload[4:8])&2 == 0 {
		t.Fatalf("pending exec retained trusted TASK: flags=%x err=%v", payload[:min(len(payload), 8)], err)
	}
	meta, err := collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
	if err != nil || len(meta) < 28 || binary.LittleEndian.Uint32(meta[24:28]) != 0 {
		t.Fatalf("pending exec retained reader: raw=%x err=%v", meta, err)
	}
	if raw, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0)); err != nil ||
		len(raw) < 8 || binary.LittleEndian.Uint32(raw[4:8]) != 0 {
		t.Fatalf("pending exec charged WORK: raw=%x err=%v", raw, err)
	}
	if code, _, err := collection.Programs["opaque_real_pending_receipt_cleanup"].Test(
		make([]byte, 64)); err != nil || code != 0 {
		t.Fatalf("exact test-only stale receipt cleanup: code=%d err=%v", code, err)
	}
	if err := collection.Maps["se_exec_terminal_receipts"].Lookup(physical, &receipt); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("stale test-only receipt remains: raw=%x err=%v", receipt, err)
	}
	// G019 gap 4: an injected receipt at a first admission is pending, never
	// an interpreter continuation (no continued pass, no refusal reason).
	if stats := collection.Maps[InterpContinuationStatsMap]; stats != nil {
		for i := uint32(0); i < InterpContinuationStats; i++ {
			var n uint64
			if err := stats.Lookup(i, &n); err != nil || n != 0 {
				t.Fatalf("pending receipt reached the interpreter continuation: cell %d = %d err=%v", i, n, err)
			}
		}
	}
	t.Logf("mismatched pending terminal refused and TASK quarantined: physical=%#x live_cookie=%d stale_cookie=%d",
		physical, currentCookie, currentCookie+1)
	// Existing missing-target helper checks no policy witness/WORK charge and
	// exact TASK refund after the quarantined Audit parent exits.
	runOpaqueRealPolicyBridgeAttached(t, collection, stdin, cmd, physical,
		locator, stderr, false, false, false, false)
}
