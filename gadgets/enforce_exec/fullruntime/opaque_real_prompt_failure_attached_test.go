// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os/exec"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// Synthetic Audit only: require settlement while the failed-exec parent is
// idle, not on its next exec/fork. No meaningful role grants or Ready claim.
func runOpaqueRealPromptFailureAttached(t *testing.T, collection *ebpf.Collection,
	spec *ebpf.CollectionSpec, stdin io.Writer, stdout *bufio.Reader, cmd *exec.Cmd,
	physical, locator uint64, stderr *bytes.Buffer,
) {
	t.Helper()
	for _, name := range []string{"opaque_real_owner_work_completion_probe", "opaque_real_owner_work_retry_probe", "opaque_real_owner_terminal_race_complete"} {
		if collection.Programs[name] != nil {
			t.Fatalf("controller completion program unexpectedly loaded: %s", name)
		}
	}
	var receipt [64]byte
	if err := collection.Maps["se_exec_terminal_receipts"].Lookup(physical, &receipt); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("prompt failure must retire receipt before next exec/fork: raw=%x err=%v", receipt, err)
	}
	var liveLocator uint64
	if err := collection.Maps["se_opaque_keys"].Lookup(physical, &liveLocator); err != nil || liveLocator != locator {
		t.Fatalf("idle failed-exec TASK lost exact locator: got=%#x want=%#x err=%v", liveLocator, locator, err)
	}
	meta, err := collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
	if err != nil || len(meta) != 128 || binary.LittleEndian.Uint32(meta[4:8]) != 1 || binary.LittleEndian.Uint32(meta[24:28]) != 0 {
		t.Fatalf("idle failed-exec TASK must be LIVE with no reader hold: raw=%x err=%v", meta, err)
	}
	var metaType *btf.Struct
	if err := spec.Types.TypeByName("se_ol_meta", &metaType); err != nil {
		t.Fatal(err)
	}
	leaseOffset, leaseSize := opaqueSourceField(t, metaType, []string{"active_leases"})
	assertNoLease := func() {
		t.Helper()
		metadata, err := collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
		if err != nil || leaseSize != 4 || leaseOffset+leaseSize > len(metadata) {
			t.Fatalf("exact TASK lease field unavailable: offset=%d size=%d err=%v", leaseOffset, leaseSize, err)
		}
		if leases := binary.LittleEndian.Uint32(metadata[leaseOffset : leaseOffset+leaseSize]); leases != 0 {
			t.Fatalf("idle TASK retained %d active lexical leases after receipt retirement", leases)
		}
	}
	assertNoLease()
	var taskType *btf.Struct
	if err := spec.Types.TypeByName("se_task_state", &taskType); err != nil {
		t.Fatal(err)
	}
	field := func(path ...string) []byte {
		t.Helper()
		payload, err := collection.Maps["se_opaque_payload"].LookupBytes(uint32(0))
		if err != nil {
			t.Fatal(err)
		}
		offset, size := opaqueSourceField(t, taskType, path)
		if offset+size > len(payload) {
			t.Fatalf("TASK field %v outside payload", path)
		}
		return payload[offset : offset+size]
	}
	for _, path := range [][]string{{"reader", "owned"}, {"exec", "owned"}, {"reader_invocation"}} {
		for _, value := range field(path...) {
			if value != 0 {
				t.Fatalf("idle failed-exec TASK retained ownership %v", path)
			}
		}
	}
	if flags := binary.LittleEndian.Uint32(field("flags")); flags != 5 {
		t.Fatalf("prompt failure quarantined qualified TASK: flags=%#x", flags)
	}
	cookie := binary.LittleEndian.Uint64(field("physical_cookie"))
	invocation := binary.LittleEndian.Uint64(field("next_invocation"))
	if cookie == 0 || invocation == 0 || invocation == ^uint64(0) {
		t.Fatalf("prompt failure lacks exact completed invocation: cookie=%d invocation=%d", cookie, invocation)
	}
	account, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
	if err != nil || len(account) < 8 || binary.LittleEndian.Uint32(account[4:8]) != 1 {
		t.Fatalf("prompt failure must leave exactly one charged completion WORK for exact reap: raw=%x err=%v", account, err)
	}
	// These assertions run after the outer syscall returned too: its kretprobe
	// must not recreate a receipt or completion after the fexit retired it.
	if _, err := stdin.Write([]byte("EXEC\n")); err != nil {
		t.Fatal(err)
	}
	if line, err := stdout.ReadString('\n'); err != nil || line != "AFTER\n" {
		t.Fatalf("successful exec after prompt failure: line=%q err=%v stderr=%q", line, err, stderr.String())
	}
	if flags := binary.LittleEndian.Uint32(field("flags")); flags != 5 {
		t.Fatalf("success after prompt failure quarantined TASK: flags=%#x", flags)
	}
	if next := binary.LittleEndian.Uint64(field("next_invocation")); next != invocation+1 {
		t.Fatalf("success must allocate exactly one new invocation: got=%d want=%d", next, invocation+1)
	}
	if next := binary.LittleEndian.Uint64(field("physical_cookie")); next != cookie {
		t.Fatalf("success replaced original TASK cookie: got=%d want=%d", next, cookie)
	}
	assertNoLease()
	account, err = collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
	if err != nil || len(account) < 8 || binary.LittleEndian.Uint32(account[4:8]) != 2 {
		t.Fatalf("two terminals must leave exactly two completion WORK charges, no duplicate: raw=%x err=%v", account, err)
	}
	runOpaqueRealSuccessSourceCompletionAttached(t, collection, spec, stdin, cmd, physical, locator, stderr)
	t.Log("real ENOEXEC settled before next exec/fork while parent idle; later success and exact refunds; no controller completion, synthetic Audit only")
}
