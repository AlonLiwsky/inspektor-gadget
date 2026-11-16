// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Only parents and binding are synthetic. The eight-parent race, credits,
// final-free callbacks and reapers use the real opaque candidate/maps.
func runOpaqueRealConcurrentBoundary(t *testing.T, c *ebpf.Collection,
	attachLSM func(string) link.Link, birth, qualify link.Link,
	ctx context.Context, cgroup, helper string,
	postPublishFault, postPublishTaskCloseFault, untrackedStrict bool,
	untrackedHelper string, initialTask bool, initialHelper string,
) {
	t.Helper()
	type parent struct {
		cmd    *exec.Cmd
		in     io.WriteCloser
		out    *bufio.Reader
		stderr bytes.Buffer
		slot   uint32
		cookie uint64
		live   int
	}
	var parents [8]*parent
	defer func() {
		for _, p := range parents {
			if p != nil && p.cmd.ProcessState == nil {
				_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
				_ = p.cmd.Wait()
			}
		}
	}()
	charges := func(name string, n uint32) map[uint32]uint64 {
		t.Helper()
		m := make(map[uint32]uint64)
		for s := uint32(0); s < n; s++ {
			raw, err := c.Maps[name].LookupBytes(s)
			if err != nil || len(raw) < 8 {
				t.Fatalf("%s[%d]: %x %v", name, s, raw, err)
			}
			if cookie := binary.LittleEndian.Uint64(raw[:8]); cookie != 0 {
				m[s] = cookie
			}
		}
		return m
	}
	account := func(tasks, works int) {
		t.Helper()
		for _, want := range []struct {
			name string
			used int
		}{{"se_opaque_accounts", tasks}, {"se_opaque_work_accounts", works}} {
			raw, err := c.Maps[want.name].LookupBytes(uint32(0))
			if err != nil || len(raw) < 12 || binary.LittleEndian.Uint32(raw[4:8]) != uint32(want.used) || binary.LittleEndian.Uint32(raw[8:12]) != 0 {
				t.Fatalf("%s used=%d fault=0: raw=%x err=%v", want.name, want.used, raw, err)
			}
		}
		raw, err := c.Maps["se_routes"].LookupBytes(uint32(0))
		if err != nil || len(raw) < 68 || binary.LittleEndian.Uint32(raw[64:68]) != 0 {
			t.Fatalf("route claim: %x %v", raw, err)
		}
	}
	oneNew := func(before, after map[uint32]uint64) (uint32, uint64) {
		t.Helper()
		if len(after) != len(before)+1 {
			t.Fatalf("one new TASK expected: before=%v after=%v", before, after)
		}
		for slot, cookie := range before {
			if after[slot] != cookie {
				t.Fatalf("TASK[%d] changed %d -> %d", slot, cookie, after[slot])
			}
		}
		for slot, cookie := range after {
			if _, ok := before[slot]; !ok {
				return slot, cookie
			}
		}
		t.Fatal("new TASK missing")
		return 0, 0
	}
	command := func(p *parent, word string) (string, error) {
		if _, err := p.in.Write([]byte(word + "\n")); err != nil {
			return "", err
		}
		return p.out.ReadString('\n')
	}
	spawn := func(p *parent) (bool, error) {
		line, err := command(p, "SPAWN")
		if err != nil {
			return false, err
		}
		if strings.HasPrefix(line, "SPAWNED:") {
			if _, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "SPAWNED:"))); err != nil {
				return false, err
			}
			p.live++
			return true, nil
		}
		if line == "SPAWNFAIL:1\n" {
			return false, nil
		}
		return false, fmt.Errorf("unexpected spawn response %q", line)
	}
	reapWork := func(slot uint32, cookie uint64) {
		t.Helper()
		request := struct {
			Cookie        uint64
			Slot, Enabled uint32
		}{cookie, slot, 1}
		if err := c.Maps["opaque_real_live_work_reap_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 12; i++ {
			code, _, err := c.Programs["opaque_real_live_reap_work"].Test(make([]byte, 64))
			if err != nil || code > 1 {
				t.Fatalf("WORK[%d]/%d reap: code=%d err=%v", slot, cookie, code, err)
			}
			if code == 1 {
				return
			}
		}
		t.Fatalf("WORK[%d]/%d not returned", slot, cookie)
	}
	reapAllWork := func() {
		t.Helper()
		for slot, cookie := range charges("se_opaque_work_charges", 8) {
			reapWork(slot, cookie)
		}
		if m := charges("se_opaque_work_charges", 8); len(m) != 0 {
			t.Fatalf("WORK retained: %v", m)
		}
	}
	waitDead := func(slot uint32) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			raw, err := c.Maps["se_opaque_meta"].LookupBytes(slot)
			if err != nil || len(raw) != 128 {
				t.Fatalf("TASK[%d] meta: %x %v", slot, raw, err)
			}
			if binary.LittleEndian.Uint32(raw[4:8]) == 2 {
				if binary.LittleEndian.Uint32(raw[84:88]) != 0 {
					t.Fatalf("TASK[%d] cleanup fault: %x", slot, raw)
				}
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("TASK[%d] not DEAD: %x", slot, raw)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	reapTask := func(slot uint32, cookie uint64) {
		t.Helper()
		request := struct {
			Cookie        uint64
			Slot, Enabled uint32
		}{cookie, slot, 1}
		if err := c.Maps["opaque_real_live_task_reap_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 24; i++ {
			code, _, err := c.Programs["opaque_real_live_reap_task"].Test(make([]byte, 64))
			if err != nil || code == 4 || code > 4 {
				t.Fatalf("TASK[%d]/%d reap: code=%d err=%v", slot, cookie, code, err)
			}
			if code == 2 {
				return
			}
		}
		t.Fatalf("TASK[%d]/%d not returned", slot, cookie)
	}

	seen := make(map[uint32]uint64)
	for i := range parents {
		p := &parent{}
		cmd := exec.CommandContext(ctx, "/bin/bash", "-c",
			"echo $$ > \"$1/cgroup.procs\" || exit 97; \"$2\" <&0 & child=$!; wait \"$child\"",
			"ig15-real-live-launcher", cgroup, helper)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		var err error
		p.in, err = cmd.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		out, err := cmd.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		p.out = bufio.NewReader(out)
		cmd.Stderr = &p.stderr
		p.cmd = cmd
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		parents[i] = p
		if line, err := p.out.ReadString('\n'); err != nil || line != "READY\n" {
			t.Fatalf("parent %d qualification: line=%q err=%v stderr=%q", i, line, err, p.stderr.String())
		}
		after := charges("se_opaque_charges", 64)
		p.slot, p.cookie = oneNew(seen, after)
		seen = after
	}
	account(8, 0)
	if err := birth.Close(); err != nil {
		t.Fatal(err)
	}
	if err := qualify.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Maps["opaque_real_owner_child_targets"].Update(uint32(0), c.Programs["opaque_real_owner_child_target_candidate"], ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := c.Maps["opaque_real_owner_child_targets"].Freeze(); err != nil {
		t.Fatal(err)
	}
	attachLSM("opaque_real_owner_child_source_candidate")
	if untrackedStrict {
		probe := exec.CommandContext(ctx, untrackedHelper, cgroup)
		output, err := probe.CombinedOutput()
		if err != nil || string(output) != "EPERM_SURVIVED\n" {
			t.Fatalf("untracked strict parent was not recoverably denied: output=%q err=%v", output, err)
		}
		if after := charges("se_opaque_charges", 64); len(after) != len(seen) {
			t.Fatalf("untracked parent created a TASK charge: before=%v after=%v", seen, after)
		}
		account(8, 0)
		t.Log("untracked strict parent retained after policy-originated EPERM; no child charge")
		return
	}
	if initialTask {
		probe := exec.CommandContext(ctx, initialHelper, cgroup)
		input, err := probe.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		output, err := probe.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		probe.Stderr = &stderr
		if err := probe.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if probe.ProcessState == nil {
				_ = probe.Process.Kill()
				_ = probe.Wait()
			}
		}()
		reader := bufio.NewReader(output)
		if line, err := reader.ReadString('\n'); err != nil || line != "READY\n" {
			t.Fatalf("initial helper readiness: %q %v stderr=%q", line, err, stderr.String())
		}
		var stat syscall.Stat_t
		if err := syscall.Stat(cgroup, &stat); err != nil || stat.Ino == 0 {
			t.Fatalf("initial helper cgroup inode: %v", err)
		}
		request := struct {
			Cgroup, Scope uint64
			TID, Enabled  uint32
		}{stat.Ino, 10, uint32(probe.Process.Pid), 1}
		if err := c.Maps["opaque_initial_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if err := c.Maps["opaque_initial_request"].Freeze(); err != nil {
			t.Fatal(err)
		}
		attachLSM("opaque_real_owner_initial_task_diagnostic")
		if _, err := input.Write([]byte{'G'}); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		if err != nil || line != "ROOT_FORK_OK\n" {
			t.Fatalf("initial current-task constructor: line=%q err=%v stderr=%q", line, err, stderr.String())
		}
		if err := probe.Wait(); err != nil {
			t.Fatalf("initial helper exit: %v stderr=%q", err, stderr.String())
		}
		var consumed uint32
		if err := c.Maps["opaque_initial_consumed"].Lookup(uint32(0), &consumed); err != nil || consumed != 1 {
			t.Fatalf("initial request not exactly once consumed: %d %v", consumed, err)
		}
		after := charges("se_opaque_charges", 64)
		if len(after) != len(seen)+2 {
			t.Fatalf("initial TASK and child charges missing: before=%v after=%v", seen, after)
		}
		for slot, cookie := range seen {
			if after[slot] != cookie {
				t.Fatalf("initial enrollment changed prior TASK[%d]: %d -> %d", slot, cookie, after[slot])
			}
		}
		reapAllWork()
		for slot, cookie := range after {
			if _, old := seen[slot]; old {
				continue
			}
			waitDead(slot)
			reapTask(slot, cookie)
		}
		account(8, 0)
		if final := charges("se_opaque_charges", 64); len(final) != len(seen) {
			t.Fatalf("initial TASK/child charges not returned: before=%v final=%v", seen, final)
		}
		t.Log("test-only current-task enrollment, strict child fork and exact TASK/WORK refunds succeeded; native authority remains unproved")
		return
	}
	if postPublishFault || postPublishTaskCloseFault {
		ok, err := spawn(parents[0])
		if err != nil || !ok {
			t.Fatalf("published strict child denied after close fault: ok=%t err=%v", ok, err)
		}
		if after := charges("se_opaque_charges", 64); len(after) != 9 {
			t.Fatalf("published child charge missing: %+v", after)
		}
		meta, err := c.Maps["se_opaque_meta"].LookupBytes(parents[0].slot)
		if err != nil || len(meta) != 128 || binary.LittleEndian.Uint32(meta[84:88]) != 1 {
			t.Fatalf("parent TASK did not retain structural cleanup fault: raw=%x err=%v", meta, err)
		}
		workAccount, err := c.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
		if err != nil || len(workAccount) < 12 || binary.LittleEndian.Uint32(workAccount[4:8]) != 1 {
			t.Fatalf("WORK credit was not retained: raw=%x err=%v", workAccount, err)
		}
		if postPublishFault {
			if binary.LittleEndian.Uint32(workAccount[8:12]) != 1 {
				t.Fatalf("WORK close fault was not held: raw=%x", workAccount)
			}
		} else if binary.LittleEndian.Uint32(workAccount[8:12]) != 0 ||
			binary.LittleEndian.Uint32(meta[28:32]) == 0 {
			t.Fatalf("TASK close fault lost its lease or faulted unrelated WORK: meta=%x work=%x", meta, workAccount)
		}
		t.Log("strict child published; exact parent cleanup fault and charge retained")
		return
	}
	for i := 0; i < 55; i++ {
		ok, err := spawn(parents[i%len(parents)])
		if err != nil || !ok {
			t.Fatalf("fill child %d: ok=%t err=%v", i, ok, err)
		}
		after := charges("se_opaque_charges", 64)
		_, _ = oneNew(seen, after)
		seen = after
		reapAllWork()
		account(9+i, 0)
	}
	account(63, 0)
	var outcomes [8]struct {
		ok  bool
		err error
	}
	var wg sync.WaitGroup
	for i, p := range parents {
		wg.Add(1)
		go func(i int, p *parent) { defer wg.Done(); outcomes[i].ok, outcomes[i].err = spawn(p) }(i, p)
	}
	wg.Wait()
	successes := 0
	for i, v := range outcomes {
		if v.err != nil {
			t.Fatalf("concurrent parent %d: %v", i, v.err)
		}
		if v.ok {
			successes++
		}
	}
	if successes > 1 {
		t.Fatalf("TASK quota oversubscribed: %d racing successes", successes)
	}
	after := charges("se_opaque_charges", 64)
	if len(after) != 63+successes {
		t.Fatalf("racing TASK leaked: successes=%d charges=%d", successes, len(after))
	}
	for slot, cookie := range seen {
		if after[slot] != cookie {
			t.Fatalf("TASK[%d] changed %d -> %d", slot, cookie, after[slot])
		}
	}
	seen = after
	account(63+successes, len(charges("se_opaque_work_charges", 8)))
	reapAllWork()
	account(63+successes, 0)
	if successes == 0 {
		ok, err := spawn(parents[0])
		if err != nil || !ok {
			t.Fatalf("single retry must fill remaining credit: ok=%t err=%v", ok, err)
		}
		after = charges("se_opaque_charges", 64)
		_, _ = oneNew(seen, after)
		seen = after
		reapAllWork()
	}
	account(64, 0)
	if ok, err := spawn(parents[0]); err != nil || ok {
		t.Fatalf("full TASK must deny: ok=%t err=%v", ok, err)
	}
	reapAllWork()
	account(64, 0)
	t.Logf("eight-parent boundary race: successes=%d, TASK never exceeded 64", successes)
	for i, p := range parents {
		line, err := command(p, "REAP")
		if err != nil || line != "REAPED:"+strconv.Itoa(p.live)+"\n" {
			t.Fatalf("parent %d reap %d: %q %v", i, p.live, line, err)
		}
	}
	for slot, cookie := range seen {
		isParent := false
		for _, p := range parents {
			if p.slot == slot && p.cookie == cookie {
				isParent = true
				break
			}
		}
		if !isParent {
			waitDead(slot)
			reapTask(slot, cookie)
		}
	}
	account(8, 0)
	for i, p := range parents {
		if _, err := p.in.Write([]byte("DONE\n")); err != nil {
			t.Fatal(err)
		}
		if err := p.cmd.Wait(); err != nil {
			t.Fatalf("parent %d exit: %v stderr=%q", i, err, p.stderr.String())
		}
		waitDead(p.slot)
		reapTask(p.slot, p.cookie)
	}
	account(0, 0)
	iter := c.Maps["se_opaque_keys"].Iterate()
	var key, value uint64
	if iter.Next(&key, &value) || iter.Err() != nil {
		t.Fatalf("TASK key retained: %#x %#x %v", key, value, iter.Err())
	}
	t.Log("concurrent TASK boundary, exact child/parent refund and empty key map")
}
