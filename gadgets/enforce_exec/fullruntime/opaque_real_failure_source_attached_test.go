// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"os/exec"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// This synthetic Audit diagnostic proves a failed exec cannot strand its
// reader across a later successful exec. It does not prove policy evaluation,
// role grants, fork draining, strict enforcement, or product readiness.
func runOpaqueRealFailureSourceDrainAttached(t *testing.T, collection *ebpf.Collection,
	spec *ebpf.CollectionSpec, stdin io.Writer, stdout *bufio.Reader, cmd *exec.Cmd,
	physical, locator uint64, stderr *bytes.Buffer,
) {
	t.Helper()
	for _, name := range []string{"opaque_real_owner_work_completion_probe", "opaque_real_owner_work_retry_probe", "opaque_real_owner_terminal_race_complete"} {
		if collection.Programs[name] != nil {
			t.Fatalf("controller completion program unexpectedly loaded: %s", name)
		}
	}
	var receipt struct {
		Physical, Bprm, Cookie, Locator, Invocation, Scope, Generation uint64
		Phase, Reserved                                                uint32
	}
	if err := collection.Maps["se_exec_terminal_receipts"].Lookup(physical, &receipt); err != nil ||
		receipt.Physical != physical || receipt.Bprm == 0 || receipt.Cookie == 0 ||
		receipt.Locator != locator || receipt.Invocation == 0 || receipt.Scope != 10 ||
		receipt.Generation != 1 || receipt.Phase != 3 || receipt.Reserved != 0 {
		t.Fatalf("failed exec did not retain exact FAILURE receipt: %+v err=%v", receipt, err)
	}
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
	if flags := binary.LittleEndian.Uint32(field("flags")); flags != 5 {
		t.Fatalf("failed exec quarantined qualified parent before retry: flags=%#x", flags)
	}
	if invocation := binary.LittleEndian.Uint64(field("next_invocation")); invocation != receipt.Invocation {
		t.Fatalf("failure receipt does not match last allocated invocation: got=%d receipt=%d", invocation, receipt.Invocation)
	}
	// The parent survived ENOEXEC and is still reading commands. No TC
	// completion calls are available: only the next real LSM entry can drain.
	if _, err := stdin.Write([]byte("EXEC\n")); err != nil {
		t.Fatal(err)
	}
	if line, err := stdout.ReadString('\n'); err != nil || line != "AFTER\n" {
		t.Fatalf("allowed exec after failure: line=%q err=%v stderr=%q", line, err, stderr.String())
	}
	if flags := binary.LittleEndian.Uint32(field("flags")); flags != 5 {
		t.Fatalf("failure-to-success retry quarantined parent: flags=%#x", flags)
	}
	if invocation := binary.LittleEndian.Uint64(field("next_invocation")); invocation != receipt.Invocation+1 {
		t.Fatalf("next exec did not allocate one fresh invocation after failure: got=%d want=%d", invocation, receipt.Invocation+1)
	}
	if cookie := binary.LittleEndian.Uint64(field("physical_cookie")); cookie != receipt.Cookie {
		t.Fatalf("retry replaced physical TASK identity: got=%d want=%d", cookie, receipt.Cookie)
	}
	// Reuse the stronger success-source assertions and exact post-DONE reapers.
	// They require no terminal receipt, no reader/exec ownership, a still-LIVE
	// exact TASK, charged WORK, and complete WORK/TASK refunds.
	runOpaqueRealSuccessSourceCompletionAttached(t, collection, spec, stdin, cmd, physical, locator, stderr)
	t.Log("real ENOEXEC followed by successful exec drained FAILURE without controller completion or quarantine; synthetic Audit only")
}
