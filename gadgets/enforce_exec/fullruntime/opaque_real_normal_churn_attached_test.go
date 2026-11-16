// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

// Only kernel-observed successful births may qualify ordinary descendants.
// In particular, never select the signal-0 diagnostic qualification helper.
func selectOpaqueNormalChurnBirthPrograms(spec *ebpf.CollectionSpec, selected map[string]*ebpf.ProgramSpec) error {
	if spec.Maps["opaque_birth_receipts"] == nil || spec.Maps["opaque_birth_receipt_zero"] == nil {
		return errors.New("normal churn requires the guarded successful-birth receipt object")
	}
	for _, want := range []struct {
		name, section string
		kind          ebpf.ProgramType
	}{
		{"opaque_real_owner_successful_birth_candidate", "raw_tp/sched_process_fork", ebpf.RawTracepoint},
		{"opaque_real_owner_birth_free_task_candidate", "kprobe/free_task", ebpf.Kprobe},
	} {
		program := spec.Programs[want.name]
		if program == nil || program.Type != want.kind || program.SectionName != want.section || program.Flags != 0 {
			return fmt.Errorf("normal churn requires exact non-sleepable birth source %s (%s)", want.name, want.section)
		}
		selected[want.name] = program
	}
	if selected["opaque_real_owner_birth_signal0_diagnostic"] != nil {
		return errors.New("normal churn must not load synthetic signal-0 qualification")
	}
	return nil
}

// Synthetic admission/retained Audit target only. Unlike quarantine churn, the
// parent has already execed and every real child must remain qualified. Bootstrap
// birth/qualify links are closed; only the real child source may construct it.
func runOpaqueRealNormalChurnAttached(t *testing.T, c *ebpf.Collection, spec *ebpf.CollectionSpec,
	attach func(string) link.Link, stdin io.Writer, stdout *bufio.Reader, cmd *exec.Cmd,
	parent, parentLocator uint64, stderr *bytes.Buffer, births int,
) {
	t.Helper()
	for _, name := range []string{"opaque_real_owner_work_completion_probe", "opaque_real_owner_work_retry_probe", "opaque_real_owner_terminal_race_complete"} {
		if c.Programs[name] != nil {
			t.Fatalf("controller completion unexpectedly loaded: %s", name)
		}
	}
	if c.Programs["opaque_real_owner_birth_signal0_diagnostic"] != nil {
		t.Fatal("synthetic signal-0 qualification unexpectedly loaded")
	}
	if err := c.Maps["opaque_birth_receipt_zero"].Freeze(); err != nil {
		t.Fatalf("freeze birth receipt zero template: %v", err)
	}
	birthLink, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name: "sched_process_fork", Program: c.Programs["opaque_real_owner_successful_birth_candidate"],
	})
	if err != nil {
		t.Fatalf("attach source-owned successful birth: %v", err)
	}
	defer birthLink.Close()
	freeLink, err := link.Kprobe("free_task", c.Programs["opaque_real_owner_birth_free_task_candidate"], nil)
	if err != nil {
		t.Fatalf("attach source-owned birth receipt cleanup: %v", err)
	}
	defer freeLink.Close()
	var taskType, metaType *btf.Struct
	if err := spec.Types.TypeByName("se_task_state", &taskType); err != nil {
		t.Fatal(err)
	}
	if err := spec.Types.TypeByName("se_ol_meta", &metaType); err != nil {
		t.Fatal(err)
	}
	field := func(root *btf.Struct, raw []byte, path ...string) uint64 {
		t.Helper()
		offset, size := opaqueSourceField(t, root, path)
		if offset+size > len(raw) {
			t.Fatalf("field %v outside map value", path)
		}
		switch size {
		case 4:
			return uint64(binary.LittleEndian.Uint32(raw[offset : offset+size]))
		case 8:
			return binary.LittleEndian.Uint64(raw[offset : offset+size])
		default:
			t.Fatalf("unexpected scalar width %d", size)
		}
		return 0
	}
	account := func(name string, want uint32) {
		t.Helper()
		raw, err := c.Maps[name].LookupBytes(uint32(0))
		if err != nil || len(raw) < 12 || binary.LittleEndian.Uint32(raw[4:8]) != want || binary.LittleEndian.Uint32(raw[8:12]) != 0 {
			t.Fatalf("%s charge/fault: raw=%x want=%d err=%v", name, raw, want, err)
		}
	}
	healthy := func(label string, physical, locator uint64, phase uint32) uint64 {
		t.Helper()
		slot := uint32(locator & ((1 << 14) - 1))
		raw, err := c.Maps["se_opaque_payload"].LookupBytes(slot)
		if err != nil {
			t.Fatalf("%s: TASK physical=%#x locator=%#x slot=%d payload lookup: %v", label, physical, locator, slot, err)
		}
		if field(taskType, raw, "flags") != 5 || field(taskType, raw, "next_invocation") != 1 {
			t.Fatalf("%s: TASK physical=%#x locator=%#x slot=%d must be qualified after exactly one exec: flags=%d invocations=%d", label, physical, locator, slot, field(taskType, raw, "flags"), field(taskType, raw, "next_invocation"))
		}
		for _, p := range [][]string{{"reader", "owned"}, {"exec", "owned"}, {"reader_invocation"}} {
			if field(taskType, raw, p...) != 0 {
				t.Fatalf("%s: TASK physical=%#x locator=%#x retains %v", label, physical, locator, p)
			}
		}
		meta, err := c.Maps["se_opaque_meta"].LookupBytes(slot)
		if err != nil || len(meta) != 128 || binary.LittleEndian.Uint32(meta[4:8]) != phase || field(metaType, meta, "active_leases") != 0 || binary.LittleEndian.Uint32(meta[24:28]) != 0 {
			t.Fatalf("%s: TASK physical=%#x locator=%#x expected_phase=%d phase/lease/reader not settled: meta=%x err=%v", label, physical, locator, phase, meta, err)
		}
		var receipt [64]byte
		if err := c.Maps["se_exec_terminal_receipts"].Lookup(physical, &receipt); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("%s: TASK physical=%#x locator=%#x retained terminal: %x err=%v", label, physical, locator, receipt, err)
		}
		return field(taskType, raw, "physical_cookie")
	}
	charge := func(name string, slot uint32) uint64 {
		t.Helper()
		raw, err := c.Maps[name].LookupBytes(slot)
		if err != nil || len(raw) < 8 {
			t.Fatalf("%s slot %d: raw=%x err=%v", name, slot, raw, err)
		}
		return binary.LittleEndian.Uint64(raw[:8])
	}
	reap := func(kind string, slot uint32, cookie uint64, stale bool) {
		t.Helper()
		request := struct {
			Cookie        uint64
			Slot, Enabled uint32
		}{cookie, slot, 1}
		if err := c.Maps["opaque_real_live_"+kind+"_reap_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		for step := 0; step < 20; step++ {
			code, _, err := c.Programs["opaque_real_live_reap_"+kind].Test(make([]byte, 64))
			if err != nil {
				t.Fatal(err)
			}
			if stale {
				want := uint32(3)
				if kind == "task" {
					want = 4
				}
				if code != want {
					t.Fatalf("stale %s cookie accepted: got=%d want=%d", kind, code, want)
				}
				return
			}
			if kind == "work" && code == 1 || kind == "task" && code == 2 {
				return
			}
			if kind == "work" && code > 1 || kind == "task" && code >= 4 {
				t.Fatalf("exact %s reap rejected: slot=%d cookie=%d code=%d", kind, slot, cookie, code)
			}
		}
		t.Fatalf("exact %s credit not returned", kind)
	}
	parentCookie := healthy("parent after initial exec", parent, parentLocator, 1)
	t.Logf("parent after initial exec qualified and settled: physical=%#x locator=%#x cookie=%d", parent, parentLocator, parentCookie)
	account("se_opaque_accounts", 1)
	account("se_opaque_work_accounts", 1)
	// Preserve the parent's one completed WORK for final cleanup; all later
	// completed fork/exec WORKs are reaped between births under the fixed quota.
	retained := map[uint32]uint64{}
	for slot := uint32(0); slot < spec.Maps["se_opaque_work_charges"].MaxEntries; slot++ {
		if cookie := charge("se_opaque_work_charges", slot); cookie != 0 {
			retained[slot] = cookie
		}
	}
	if len(retained) != 1 {
		t.Fatalf("parent exec must leave exactly one completed WORK, got %d", len(retained))
	}
	if err := c.Maps["opaque_real_owner_child_targets"].Update(uint32(0), c.Programs["opaque_real_owner_child_target_candidate"], ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := c.Maps["opaque_real_owner_child_targets"].Freeze(); err != nil {
		t.Fatal(err)
	}
	attach("opaque_real_owner_child_source_candidate")
	type identity struct{ cookie, locator uint64 }
	seen := map[uint64]identity{}
	previousWorks := map[uint32]uint64{}
	reuses := 0
	for iteration := 0; iteration <= births; iteration++ {
		command, descendants := "FORK\n", 1
		if iteration == births {
			command, descendants = "GRAND\n", 2
			t.Log("checking fork by an exec-qualified child and its grandchild")
		}
		if _, err := stdin.Write([]byte(command)); err != nil {
			t.Fatal(err)
		}
		line, err := stdout.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "FORKED:") || !strings.HasSuffix(line, ":0\n") {
			t.Fatalf("child %d fork/exec: line=%q err=%v stderr=%q", iteration, line, err, stderr.String())
		}
		type descendant struct{ physical, locator, cookie uint64 }
		var children []descendant
		var key, value uint64
		keys := c.Maps["se_opaque_keys"].Iterate()
		for keys.Next(&key, &value) {
			if key != parent {
				children = append(children, descendant{physical: key, locator: value})
			}
		}
		if keys.Err() != nil || len(children) != descendants {
			t.Fatalf("round %d expected %d descendant TASKs, got %d: err=%v", iteration, descendants, len(children), keys.Err())
		}
		for i := range children {
			child, locator := children[i].physical, children[i].locator
			slot := uint32(locator & ((1 << 14) - 1))
			deadline := time.Now().Add(10 * time.Second)
			for {
				meta, err := c.Maps["se_opaque_meta"].LookupBytes(slot)
				if err != nil {
					t.Fatal(err)
				}
				if len(meta) == 128 && binary.LittleEndian.Uint32(meta[4:8]) == 2 {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("round %d descendant %#x final-free not observed: %x", iteration, child, meta)
				}
				time.Sleep(20 * time.Millisecond)
			}
			cookie := healthy(fmt.Sprintf("round %d descendant after exec/final-free", iteration), child, locator, 2)
			// LookupBytes represents a missing key as (nil, nil), unlike Lookup.
			if receipt, err := c.Maps["opaque_birth_receipts"].LookupBytes(child); err != nil || receipt != nil {
				t.Fatalf("round %d descendant %#x birth receipt survived final-free: receipt=%x err=%v", iteration, child, receipt, err)
			}
			if cookie == 0 || charge("se_opaque_charges", slot) != cookie {
				t.Fatal("descendant lost exact TASK charge")
			}
			children[i].cookie = cookie
			if old, ok := seen[child]; ok {
				reuses++
				if cookie <= old.cookie || locator == old.locator {
					t.Fatal("physical TASK reuse retained stale identity")
				}
				reap("task", slot, old.cookie, true)
				var got uint64
				if err := c.Maps["se_opaque_keys"].Lookup(child, &got); err != nil || got != locator {
					t.Fatal("stale TASK reaper touched successor")
				}
			}
			seen[child] = identity{cookie, locator}
		}
		account("se_opaque_accounts", uint32(1+descendants))
		account("se_opaque_work_accounts", uint32(1+2*descendants))
		works := 0
		for ws := uint32(0); ws < spec.Maps["se_opaque_work_charges"].MaxEntries; ws++ {
			wc := charge("se_opaque_work_charges", ws)
			if saved, ok := retained[ws]; ok {
				if wc != saved {
					t.Fatal("parent WORK changed during child churn")
				}
				continue
			}
			if wc == 0 {
				continue
			}
			works++
			if old := previousWorks[ws]; old != 0 {
				if wc <= old {
					t.Fatal("WORK cookie did not advance")
				}
				reap("work", ws, old, true)
				if charge("se_opaque_work_charges", ws) != wc {
					t.Fatal("stale WORK reaper changed successor")
				}
			}
			previousWorks[ws] = wc
			reap("work", ws, wc, false)
		}
		if works != 2*descendants {
			t.Fatalf("round %d needs %d fork and exec completion WORKs, got %d", iteration, 2*descendants, works)
		}
		account("se_opaque_work_accounts", 1)
		for _, child := range children {
			slot := uint32(child.locator & ((1 << 14) - 1))
			reap("task", slot, child.cookie, false)
			var got uint64
			if err := c.Maps["se_opaque_keys"].Lookup(child.physical, &got); !errors.Is(err, ebpf.ErrKeyNotExist) {
				t.Fatalf("descendant key retained after refund: %v", err)
			}
		}
		account("se_opaque_accounts", 1)
		if healthy(fmt.Sprintf("parent after child %d refund", iteration), parent, parentLocator, 1) != parentCookie {
			t.Fatal("parent identity changed")
		}
		if iteration < births && (iteration == 0 || (iteration+1)%512 == 0 || iteration == births-1) {
			t.Logf("normal post-exec churn %d/%d: physical reuses=%d", iteration+1, births, reuses)
		}
	}
	if births > 4096 && reuses == 0 {
		t.Fatal("4097 births did not demonstrate physical address reuse; ABA proof missing")
	}
	runOpaqueRealSuccessSourceCompletionAttached(t, c, spec, stdin, cmd, parent, parentLocator, stderr)
	t.Logf("%d ordinary post-exec child births plus child/grandchild proof, no quarantine, %d physical reuses, exact TASK/WORK refunds; synthetic Audit only", births, reuses)
}
