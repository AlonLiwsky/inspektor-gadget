// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// Invoked only by the opt-in, isolated real-map attached test. The parent and
// strict snapshot are synthetic; source/target, quota, final-free and reaper
// transitions are the actual opaque candidate. No exec verdict is tested.
func runOpaqueRealCreditExhaustion(t *testing.T, collection *ebpf.Collection,
	attachLSM func(string) link.Link, stdin io.Writer, reader *bufio.Reader,
	cmd *exec.Cmd, parentPhysical uint64, workExhaust bool,
) {
	t.Helper()
	if err := collection.Maps["opaque_real_owner_child_targets"].Update(uint32(0),
		collection.Programs["opaque_real_owner_child_target_candidate"], ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["opaque_real_owner_child_targets"].Freeze(); err != nil {
		t.Fatal(err)
	}
	attachLSM("opaque_real_owner_child_source_candidate")

	readCookie := func(mapName string, slot uint32) uint64 {
		t.Helper()
		raw, err := collection.Maps[mapName].LookupBytes(slot)
		if err != nil || len(raw) < 8 {
			t.Fatalf("%s[%d] cookie: raw=%x err=%v", mapName, slot, raw, err)
		}
		return binary.LittleEndian.Uint64(raw[:8])
	}
	checkAccounts := func(tasks, works uint32) {
		t.Helper()
		task, err := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0))
		if err != nil || len(task) < 12 ||
			binary.LittleEndian.Uint32(task[4:8]) != tasks ||
			binary.LittleEndian.Uint32(task[8:12]) != 0 {
			t.Fatalf("TASK account: want used=%d raw=%x err=%v", tasks, task, err)
		}
		work, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
		if err != nil || len(work) < 12 ||
			binary.LittleEndian.Uint32(work[4:8]) != works ||
			binary.LittleEndian.Uint32(work[8:12]) != 0 {
			t.Fatalf("WORK account: want used=%d raw=%x err=%v", works, work, err)
		}
		route, err := collection.Maps["se_routes"].LookupBytes(uint32(0))
		if err != nil || len(route) < 68 ||
			binary.LittleEndian.Uint32(route[64:68]) != 0 {
			t.Fatalf("original route claim retained: raw=%x err=%v", route, err)
		}
	}
	reapWork := func(slot uint32, cookie uint64) {
		t.Helper()
		if cookie == 0 {
			t.Fatal("WORK lost its charged cookie before reaper")
		}
		request := struct {
			Cookie        uint64
			Slot, Enabled uint32
		}{cookie, slot, 1}
		if err := collection.Maps["opaque_real_live_work_reap_request"].Update(
			uint32(0), request, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		for step := 0; step < 10; step++ {
			code, _, err := collection.Programs["opaque_real_live_reap_work"].Test(make([]byte, 64))
			if err != nil || code > 1 {
				t.Fatalf("WORK[%d] reap cookie=%d step=%d code=%d err=%v", slot, cookie, step, code, err)
			}
			if code == 1 {
				return
			}
		}
		t.Fatalf("WORK[%d] cookie=%d did not return its exact credit", slot, cookie)
	}
	waitDead := func(slot uint32) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for {
			meta, err := collection.Maps["se_opaque_meta"].LookupBytes(slot)
			if err != nil || len(meta) != 128 {
				t.Fatalf("TASK[%d] death metadata: raw=%x err=%v", slot, meta, err)
			}
			if binary.LittleEndian.Uint32(meta[4:8]) == 2 {
				if binary.LittleEndian.Uint32(meta[84:88]) != 0 {
					t.Fatalf("TASK[%d] final-free cleanup error: raw=%x", slot, meta)
				}
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("TASK[%d] task_free did not publish DEAD: raw=%x", slot, meta)
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
		if err := collection.Maps["opaque_real_live_task_reap_request"].Update(
			uint32(0), request, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		for step := 0; step < 20; step++ {
			code, _, err := collection.Programs["opaque_real_live_reap_task"].Test(make([]byte, 64))
			if err != nil || code == 4 || code > 4 {
				t.Fatalf("TASK[%d] reap cookie=%d step=%d code=%d err=%v", slot, cookie, step, code, err)
			}
			if code == 2 {
				return
			}
		}
		t.Fatalf("TASK[%d] cookie=%d did not return its exact credit", slot, cookie)
	}
	requestSpawn := func(wantSuccess bool) {
		t.Helper()
		if _, err := stdin.Write([]byte("SPAWN\n")); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		if err != nil || (wantSuccess && !strings.HasPrefix(line, "SPAWNED:")) ||
			(!wantSuccess && line != "SPAWNFAIL:1\n") {
			t.Fatalf("strict fork wantSuccess=%t: line=%q err=%v", wantSuccess, line, err)
		}
	}
	requestReap := func(count int) {
		t.Helper()
		if _, err := stdin.Write([]byte("REAP\n")); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		if err != nil || line != "REAPED:"+strconv.Itoa(count)+"\n" {
			t.Fatalf("tracked children reap count=%d: line=%q err=%v", count, line, err)
		}
	}

	parentCookie := readCookie("se_opaque_charges", 0)
	if parentCookie == 0 {
		t.Fatal("synthetic strict parent is not charged")
	}
	if workExhaust {
		var childCookies [9]uint64
		var workCookies [8]uint64
		for i := 0; i < 8; i++ {
			requestSpawn(true)
			childCookies[i] = readCookie("se_opaque_charges", uint32(i+1))
			workCookies[i] = readCookie("se_opaque_work_charges", uint32(i))
			if childCookies[i] <= parentCookie || workCookies[i] == 0 ||
				(i > 0 && (childCookies[i] <= childCookies[i-1] ||
					workCookies[i] <= workCookies[i-1])) {
				t.Fatalf("WORK quota child %d nonmonotonic TASK/WORK cookies: task=%d work=%d", i, childCookies[i], workCookies[i])
			}
			checkAccounts(uint32(i+2), uint32(i+1))
		}
		requestSpawn(false) // WORK 8/8, TASK only 9/64.
		checkAccounts(9, 8)
		for i, cookie := range workCookies {
			if got := readCookie("se_opaque_work_charges", uint32(i)); got != cookie {
				t.Fatalf("denied fork changed WORK[%d] cookie: before=%d after=%d", i, cookie, got)
			}
		}
		t.Log("strict WORK quota 8/8 denied 9th child fork EPERM without TASK or WORK charge")
		reapWork(0, workCookies[0])
		checkAccounts(9, 7)
		requestSpawn(true)
		childCookies[8] = readCookie("se_opaque_charges", 9)
		newCookie := readCookie("se_opaque_work_charges", 0)
		if childCookies[8] <= childCookies[7] || newCookie <= workCookies[7] {
			t.Fatalf("post-exhaustion TASK/WORK did not recycle with new cookies: task=%d work=%d", childCookies[8], newCookie)
		}
		stale := struct {
			Cookie        uint64
			Slot, Enabled uint32
		}{workCookies[0], 0, 1}
		if err := collection.Maps["opaque_real_live_work_reap_request"].Update(
			uint32(0), stale, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if code, _, err := collection.Programs["opaque_real_live_reap_work"].Test(make([]byte, 64)); err != nil || code != 3 {
			t.Fatalf("stale WORK[0] cookie touched recycled owner: code=%d err=%v", code, err)
		}
		checkAccounts(10, 8)
		for i := 0; i < 8; i++ {
			cookie := workCookies[i]
			if i == 0 {
				cookie = newCookie
			}
			reapWork(uint32(i), cookie)
			checkAccounts(10, uint32(7-i))
		}
		requestReap(9)
		for i, cookie := range childCookies {
			waitDead(uint32(i + 1))
			reapTask(uint32(i+1), cookie)
		}
		checkAccounts(1, 0)
		t.Log("real-map strict WORK quota: EPERM at 8/8, exact refund and stale-cookie rejection after reuse")
	} else {
		var childCookies [63]uint64
		var lastWorkCookie uint64
		for i := 0; i < 63; i++ {
			requestSpawn(true)
			childCookies[i] = readCookie("se_opaque_charges", uint32(i+1))
			if childCookies[i] <= parentCookie ||
				(i > 0 && childCookies[i] <= childCookies[i-1]) {
				t.Fatalf("child %d TASK cookie not monotonic: %d", i, childCookies[i])
			}
			workCookie := readCookie("se_opaque_work_charges", 0)
			if workCookie <= lastWorkCookie {
				t.Fatalf("child %d WORK cookie not monotonic: %d after %d", i, workCookie, lastWorkCookie)
			}
			lastWorkCookie = workCookie
			reapWork(0, workCookie)
			checkAccounts(uint32(i+2), 0)
			if i == 0 || i == 31 || i == 62 {
				t.Logf("strict live TASK occupancy %d/64: child_cookie=%d work_cookie=%d", i+2, childCookies[i], workCookie)
			}
		}
		requestSpawn(false) // 64 TASK credits are occupied; LSM must return EPERM.
		workCookie := readCookie("se_opaque_work_charges", 0)
		if workCookie <= lastWorkCookie {
			t.Fatalf("failed fork WORK cookie did not advance: %d after %d", workCookie, lastWorkCookie)
		}
		reapWork(0, workCookie)
		checkAccounts(64, 0)
		t.Logf("strict 65th TASK allocation denied EPERM with full healthy account; failed WORK cookie=%d returned", workCookie)

		requestReap(63)
		for i, cookie := range childCookies {
			waitDead(uint32(i + 1))
			reapTask(uint32(i+1), cookie)
		}
		checkAccounts(1, 0)
		requestSpawn(true)
		recoveredCookie := readCookie("se_opaque_charges", 1)
		if recoveredCookie <= childCookies[0] {
			t.Fatalf("post-exhaustion TASK slot did not recycle: previous=%d new=%d", childCookies[0], recoveredCookie)
		}
		workCookie = readCookie("se_opaque_work_charges", 0)
		reapWork(0, workCookie)
		checkAccounts(2, 0)
		requestReap(1)
		waitDead(1)
		reapTask(1, recoveredCookie)
		checkAccounts(1, 0)
		t.Logf("real-map strict TASK quota: 63 live children, 65th fork EPERM, exact recovery and final zero credits")
	}
	if _, err := stdin.Write([]byte("DONE\n")); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("strict parent exit: %v", err)
	}
	waitDead(0)
	reapTask(0, parentCookie)
	checkAccounts(0, 0)
	var locator uint64
	if err := collection.Maps["se_opaque_keys"].Lookup(parentPhysical, &locator); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("strict parent key retained after refund: locator=%#x err=%v", locator, err)
	}
	t.Log("real-map strict quota diagnostic: parent exit and TASK/WORK final zero credits")
}
