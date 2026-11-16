// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

// These immutable diagnostic identities prevent a normal object from being
// mistaken for an injected close/release-result fault. They are not admissions
// for a product image or a production kernel.
var opaqueBirthNegativeObjects = map[string]string{
	"stale-cookie": "f7a3426354fce7e4152f9ee478ec29b5d7f46ea0accae4eb8a963cf07fe5862f",
	"moved-scope":  "f7a3426354fce7e4152f9ee478ec29b5d7f46ea0accae4eb8a963cf07fe5862f",
	"prior-denial": "f7a3426354fce7e4152f9ee478ec29b5d7f46ea0accae4eb8a963cf07fe5862f",
	"missing-hook": "f7a3426354fce7e4152f9ee478ec29b5d7f46ea0accae4eb8a963cf07fe5862f",
	"close":        "cb14637bf9798fee4ab335fde9cd6cad45738916adbfac7efc7717caf9a887d7",
	"release":      "e559dc1ceb97eabb0da5390d0ced55ecb97ccb76c8ff8ef01225ffa3e54586eb",
}

func validateOpaqueBirthNegativeObject(t *testing.T, path, scenario string) {
	t.Helper()
	want, ok := opaqueBirthNegativeObjects[scenario]
	if !ok {
		t.Fatalf("unknown audit-only birth negative scenario %q", scenario)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(raw)); got != want {
		t.Fatalf("wrong %s diagnostic object: got=%s want=%s", scenario, got, want)
	}
}

func opaqueBirthNegativeState(scenario string, flags, state uint64) error {
	if flags == 5 {
		return fmt.Errorf("uncertain child remains usable QUALIFIED: flags=%d", flags)
	}
	switch scenario {
	case "missing-hook":
		if state != 1 {
			return fmt.Errorf("missing successful-fork observation must remain state1, got %d", state)
		}
	case "moved-scope", "prior-denial":
		if flags != 4 || state != 2 {
			return fmt.Errorf("unobserved first use must remain LIVE-only/state2: flags=%d state=%d", flags, state)
		}
	case "stale-cookie":
		if state != 4 {
			return fmt.Errorf("stale-cookie transition must remain faulted state4, got %d", state)
		}
	case "close", "release":
		if flags&2 == 0 || state != 4 {
			return fmt.Errorf("posttransition fault must quarantine exact TASK and retain state4: flags=%d state=%d", flags, state)
		}
	default:
		return fmt.Errorf("unknown scenario %q", scenario)
	}
	return nil
}

func TestOpaqueBirthNegativeState(t *testing.T) {
	for _, tc := range []struct {
		name, scenario string
		flags, state   uint64
		valid          bool
	}{
		{"missing observation stays unqualified", "missing-hook", 4, 1, true},
		{"missing observation cannot qualify", "missing-hook", 5, 1, false},
		{"missing observation cannot certify", "missing-hook", 4, 3, false},
		{"close fault quarantines", "close", 7, 4, true},
		{"release fault quarantines", "release", 7, 4, true},
		{"fault cannot leave healthy qualification", "close", 5, 4, false},
		{"fault must retain marker", "release", 7, 3, false},
		{"unknown rejected", "strict", 7, 4, false},
		{"moved scope never qualifies", "moved-scope", 4, 2, true},
		{"moved scope cannot certify", "moved-scope", 5, 3, false},
		{"prior denial keeps first use untouched", "prior-denial", 4, 2, true},
		{"prior denial cannot consume first use", "prior-denial", 4, 4, false},
		{"stale cookie remains faulted", "stale-cookie", 6, 4, true},
		{"stale cookie cannot certify", "stale-cookie", 4, 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := opaqueBirthNegativeState(tc.scenario, tc.flags, tc.state); (err == nil) != tc.valid {
				t.Fatalf("valid=%v err=%v", tc.valid, err)
			}
		})
	}
}

// Audit-only: the retained target intentionally denies every Strict exec, so
// this fixture cannot establish causal Strict denial. Fault injection occurs
// after actual cleanup; it does not prove recovery from leaked lexical leases.
func runOpaqueBirthNegativeAttached(t *testing.T, c *ebpf.Collection, spec *ebpf.CollectionSpec,
	attach func(string) link.Link, stdin io.Writer, stdout *bufio.Reader, cmd *exec.Cmd,
	parent uint64, stderr *bytes.Buffer, scenario, cgroup string, prior link.Link,
) {
	t.Helper()
	for _, name := range []string{"opaque_real_owner_work_completion_probe", "opaque_real_owner_work_retry_probe", "opaque_real_owner_terminal_race_complete", "opaque_real_owner_birth_signal0_diagnostic"} {
		if c.Programs[name] != nil {
			t.Fatalf("forbidden synthetic authority loaded: %s", name)
		}
	}
	if err := c.Maps["opaque_birth_receipt_zero"].Freeze(); err != nil {
		t.Fatal(err)
	}
	if scenario != "missing-hook" {
		birth, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: "sched_process_fork", Program: c.Programs["opaque_real_owner_successful_birth_candidate"]})
		if err != nil {
			t.Fatal(err)
		}
		defer birth.Close()
	}
	cleanup, err := link.Kprobe("free_task", c.Programs["opaque_real_owner_birth_free_task_candidate"], nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup.Close()
	if err := c.Maps["opaque_real_owner_child_targets"].Update(uint32(0), c.Programs["opaque_real_owner_child_target_candidate"], ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := c.Maps["opaque_real_owner_child_targets"].Freeze(); err != nil {
		t.Fatal(err)
	}
	attach("opaque_real_owner_child_source_candidate")
	var taskType, receiptType *btf.Struct
	if err := spec.Types.TypeByName("se_task_state", &taskType); err != nil {
		t.Fatal(err)
	}
	if err := spec.Types.TypeByName("opaque_birth_receipt", &receiptType); err != nil {
		t.Fatal(err)
	}
	field := func(root *btf.Struct, raw []byte, path ...string) uint64 {
		t.Helper()
		off, size := opaqueSourceField(t, root, path)
		if off+size > len(raw) {
			t.Fatalf("field %v outside map bytes", path)
		}
		switch size {
		case 4:
			return uint64(binary.LittleEndian.Uint32(raw[off : off+size]))
		case 8:
			return binary.LittleEndian.Uint64(raw[off : off+size])
		default:
			t.Fatalf("unexpected field width %d", size)
		}
		return 0
	}
	exchange := func(command string) string {
		t.Helper()
		if _, err := io.WriteString(stdin, command+"\n"); err != nil {
			t.Fatal(err)
		}
		line, err := stdout.ReadString('\n')
		if err != nil {
			t.Fatalf("%s: %v stderr=%q", command, err, stderr.String())
		}
		return strings.TrimSuffix(line, "\n")
	}
	before := exchange("FORK")
	if !strings.HasPrefix(before, "BEFORE:") {
		t.Fatalf("child must stop before exec: %q", before)
	}
	pid, err := strconv.Atoi(strings.TrimPrefix(before, "BEFORE:"))
	if err != nil || pid <= 0 {
		t.Fatalf("bad child identity %q", before)
	}
	var physical, locator, key, value uint64
	iter := c.Maps["se_opaque_keys"].Iterate()
	for iter.Next(&key, &value) {
		if key != parent {
			if physical != 0 {
				t.Fatal("unexpected extra TASK")
			}
			physical, locator = key, value
		}
	}
	if iter.Err() != nil || physical == 0 {
		t.Fatalf("missing exact child TASK: %v", iter.Err())
	}
	slot := uint32(locator & ((1 << 14) - 1))
	receipt, err := c.Maps["opaque_birth_receipts"].LookupBytes(physical)
	if err != nil || receipt == nil {
		t.Fatalf("missing child birth receipt: %v", err)
	}
	wantBefore := uint64(2)
	if scenario == "missing-hook" {
		wantBefore = 1
	}
	if field(receiptType, receipt, "state") != wantBefore || field(receiptType, receipt, "child") != physical || field(receiptType, receipt, "child_locator") != locator {
		t.Fatal("child birth receipt not exact before exec")
	}
	cookie := field(receiptType, receipt, "child_cookie")
	if cookie == 0 {
		t.Fatal("missing child cookie")
	}

	receiptCookie := cookie
	if scenario == "stale-cookie" {
		if cookie == ^uint64(0) {
			t.Fatal("cannot construct distinct stale cookie")
		}
		receiptCookie++
		offset, size := opaqueSourceField(t, receiptType, []string{"child_cookie"})
		if size != 8 {
			t.Fatal("invalid cookie ABI")
		}
		mapSpec := spec.Maps["opaque_birth_receipts"]
		if mapSpec == nil || mapSpec.Type != ebpf.Hash || mapSpec.KeySize != 8 || mapSpec.ValueSize != 88 || mapSpec.Flags != unix.BPF_F_RDONLY {
			t.Fatal("stale injection requires exact user-readonly receipt ELF map")
		}
		injectOpaqueBirthStaleCookie(t, c.Maps["opaque_birth_receipts"], physical, receiptCookie, offset)
	}
	var restore func()
	if scenario == "moved-scope" {
		restore = moveOpaqueBirthChild(t, cgroup, pid)
		defer restore()
	}
	if (scenario == "prior-denial") != (prior != nil) {
		t.Fatal("incomplete independent prior-denial setup")
	}
	for attempt := 0; attempt < 2; attempt++ {
		want := fmt.Sprintf("EXEC-OK:%d", pid)
		if scenario == "prior-denial" {
			want = fmt.Sprintf("EXEC-ERR:%d:%d", pid, unix.EACCES)
		}
		if line := exchange("EXEC"); line != want {
			t.Fatalf("wrong same-PID exec result on attempt%d: got=%q want=%q", attempt, line, want)
		}
		task, err := c.Maps["se_opaque_payload"].LookupBytes(slot)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err = c.Maps["opaque_birth_receipts"].LookupBytes(physical)
		if err != nil || receipt == nil {
			t.Fatalf("lost live fault receipt: %v", err)
		}
		if field(taskType, task, "physical_cookie") != cookie || field(receiptType, receipt, "child_cookie") != receiptCookie || field(receiptType, receipt, "child_locator") != locator {
			t.Fatal("fault inspection changed exact TASK generation")
		}
		if err := opaqueBirthNegativeState(scenario, field(taskType, task, "flags"), field(receiptType, receipt, "state")); err != nil {
			t.Fatal(err)
		}
		for _, path := range [][]string{{"reader", "owned"}, {"exec", "owned"}, {"reader_invocation"}} {
			if field(taskType, task, path...) != 0 {
				t.Fatalf("Audit fault retained ownership %v", path)
			}
		}
	}

	if restore != nil {
		restore()
	}
	if prior != nil {
		if err := prior.Close(); err != nil {
			t.Fatal(err)
		}
		if line := exchange("EXEC"); line != fmt.Sprintf("EXEC-OK:%d", pid) {
			t.Fatalf("removing independent denial did not restore same-PID exec: %q", line)
		}
		task, err := c.Maps["se_opaque_payload"].LookupBytes(slot)
		if err != nil {
			t.Fatal(err)
		}
		receipt, err = c.Maps["opaque_birth_receipts"].LookupBytes(physical)
		if err != nil || receipt == nil {
			t.Fatalf("missing successful retry receipt: %v", err)
		}
		if field(taskType, task, "flags") != 5 || field(taskType, task, "physical_cookie") != cookie || field(taskType, task, "next_invocation") != 1 || field(receiptType, receipt, "state") != 3 {
			t.Fatal("same-PID retry did not qualify exactly once after prior denial removal")
		}
		for _, path := range [][]string{{"reader", "owned"}, {"exec", "owned"}, {"reader_invocation"}} {
			if field(taskType, task, path...) != 0 {
				t.Fatalf("successful retry retained %v", path)
			}
		}
	}
	if line := exchange("DONE"); line != fmt.Sprintf("REAPED:%d:0", pid) {
		t.Fatalf("child did not exit cleanly: %q", line)
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		receipt, err := c.Maps["opaque_birth_receipts"].LookupBytes(physical)
		if err != nil {
			t.Fatal(err)
		}
		if receipt == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("birth receipt survived final-free")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := io.WriteString(stdin, "DONE\n"); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("parent exit: %v stderr=%q", err, stderr.String())
	}
	t.Logf("%s: real child repeated exec matched Audit/prior-denial contract; exact untrusted TASK/receipt state and final-free receipt cleanup; no Strict or leaked-lease recovery claim", scenario)
}
