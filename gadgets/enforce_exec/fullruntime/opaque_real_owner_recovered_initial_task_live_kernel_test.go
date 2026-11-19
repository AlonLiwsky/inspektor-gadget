// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// This opt-in test connects the real recovered S/G/A authorization to the
// candidate's actual opaque TASK constructor. Its route and policy seed are
// synthetic; its BindingLease is a fixture, not a trusted runtime owner. It
// does not prove product Ready or source-certified initial completion.
type recoveredReapRequestWire struct {
	ABI, Operation                                 uint32
	NodeIncarnation, AdminGeneration, ReapSequence uint64
	TaskBudget, WorkBudget                         uint32
	ExpectedEpoch, Reserved0, Reserved1            uint64
}

// This fixture supplies real proc/cgroup/namespace pins to the production
// physical-pin preparation path. Its Check is test authority only; a selected
// owner still needs its trusted runtime's BindingLease implementation.
type recoveredLiveTestLease struct {
	proc, cgroup, mount, hostMount *os.File
	pid                            uint32
	cgroupID                       uint64
	start                          string
}

func (l *recoveredLiveTestLease) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if l == nil || l.proc == nil || l.cgroup == nil || l.mount == nil || l.hostMount == nil {
		return fmt.Errorf("incomplete recovered live test lease")
	}
	start, err := readPinnedInitStart(l.proc, l.pid)
	if err != nil {
		return err
	}
	if start != l.start {
		return fmt.Errorf("recovered live test init identity changed")
	}
	return checkBindingScope(l.proc, l, l.cgroupID)
}

func (l *recoveredLiveTestLease) InitProc() *os.File           { return l.proc }
func (l *recoveredLiveTestLease) Cgroup() *os.File             { return l.cgroup }
func (l *recoveredLiveTestLease) MountNamespace() *os.File     { return l.mount }
func (l *recoveredLiveTestLease) HostMountNamespace() *os.File { return l.hostMount }
func (l *recoveredLiveTestLease) Close() error {
	if l == nil {
		return nil
	}
	var result error
	for _, f := range []**os.File{&l.proc, &l.cgroup, &l.mount, &l.hostMount} {
		if *f != nil {
			result = errors.Join(result, (*f).Close())
			*f = nil
		}
	}
	return result
}

func runRecoveredReaperStep(t *testing.T, collection *ebpf.Collection,
	input io.Writer, output *bufio.Reader, step uint64,
) uint32 {
	t.Helper()
	wire := recoveredReapRequestWire{1, 1, 11, 1, step, 32, 16, step - 1, 0, 0}
	if err := collection.Maps["se_pool_reap_request"].Update(uint32(0), wire, ebpf.UpdateAny); err != nil {
		t.Fatalf("reap request step %d: %v", step, err)
	}
	if _, err := input.Write([]byte{'P'}); err != nil {
		t.Fatalf("physical admin reaper step %d: %v", step, err)
	}
	line, err := output.ReadString('\n')
	if err != nil || line != "REAP_STEP\n" {
		t.Fatalf("physical admin reaper step %d: %q %v", step, line, err)
	}
	receipt, err := collection.Maps["se_pool_reap_receipt"].LookupBytes(uint32(0))
	if err != nil || len(receipt) != 128 ||
		binary.LittleEndian.Uint32(receipt[0:4]) != 1 ||
		binary.LittleEndian.Uint32(receipt[4:8]) != 0 ||
		binary.LittleEndian.Uint64(receipt[8:16]) != 11 ||
		binary.LittleEndian.Uint64(receipt[16:24]) != 1 ||
		binary.LittleEndian.Uint64(receipt[24:32]) != step ||
		binary.LittleEndian.Uint64(receipt[32:40]) != step-1 ||
		binary.LittleEndian.Uint64(receipt[40:48]) != step ||
		binary.LittleEndian.Uint32(receipt[64:68]) != 32 ||
		binary.LittleEndian.Uint32(receipt[68:72]) != 16 ||
		binary.LittleEndian.Uint32(receipt[72:76]) > 32 ||
		binary.LittleEndian.Uint32(receipt[88:92]) != 0 ||
		binary.LittleEndian.Uint32(receipt[92:96]) != 0 ||
		binary.LittleEndian.Uint32(receipt[112:116])&1 == 0 {
		t.Fatalf("recovered-admin reaper step %d invalid receipt: raw=%x err=%v", step, receipt, err)
	}
	control, err := collection.Maps["se_pool_reap_control"].LookupBytes(uint32(0))
	if err != nil || len(control) != 64 || binary.LittleEndian.Uint32(control[4:8]) != 0 ||
		binary.LittleEndian.Uint64(control[32:40]) != step {
		t.Fatalf("recovered-admin reaper step %d left control busy: raw=%x err=%v", step, control, err)
	}
	reclaimed := binary.LittleEndian.Uint32(receipt[72:76])
	if step <= 4 || step%512 == 0 {
		t.Logf("reaper step=%d task_before=%d reclaimed=%d pending=%d", step,
			binary.LittleEndian.Uint32(receipt[48:52]), reclaimed,
			binary.LittleEndian.Uint32(receipt[80:84]))
	}
	return reclaimed
}

func runRecoveredTaskQuotaExhaustion(t *testing.T, collection *ebpf.Collection,
	targetInput io.Writer, targetOutput *bufio.Reader, adminInput io.Writer,
	adminOutput *bufio.Reader, nextStep *uint64, rootCookie uint64,
) {
	t.Helper()
	accountUsed := func(name string) uint32 {
		t.Helper()
		raw, err := collection.Maps[name].LookupBytes(uint32(0))
		if err != nil || len(raw) < 12 || binary.LittleEndian.Uint32(raw[8:12]) != 0 {
			t.Fatalf("%s unhealthy account: raw=%x err=%v", name, raw, err)
		}
		return binary.LittleEndian.Uint32(raw[4:8])
	}
	checkClaims := func() {
		t.Helper()
		raw, err := collection.Maps["se_routes"].LookupBytes(uint32(0))
		if err != nil || len(raw) < 68 || binary.LittleEndian.Uint32(raw[64:68]) != 0 {
			t.Fatalf("strict route retained an early claim: raw=%x err=%v", raw, err)
		}
	}
	drainWork := func() {
		t.Helper()
		for attempt := 0; accountUsed("se_opaque_work_accounts") != 0 && attempt < 128; attempt++ {
			if returned := runRecoveredReaperStep(t, collection, adminInput, adminOutput, *nextStep); returned != 0 {
				t.Fatalf("reaper returned live TASK while draining WORK: %d", returned)
			}
			*nextStep++
		}
		if used := accountUsed("se_opaque_work_accounts"); used != 0 {
			t.Fatalf("bounded physical reaper did not return WORK credit: used=%d", used)
		}
	}
	waitDead := func(slot uint32) {
		t.Helper()
		deadline := time.Now().Add(20 * time.Second)
		for {
			meta, err := collection.Maps["se_opaque_meta"].LookupBytes(slot)
			if err != nil || len(meta) < 8 {
				t.Fatalf("TASK[%d] death metadata: raw=%x err=%v", slot, meta, err)
			}
			if binary.LittleEndian.Uint32(meta[4:8]) == 2 {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("TASK[%d] missed source-owned task_free: meta=%x", slot, meta)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	request := func(command byte) string {
		t.Helper()
		if _, err := targetInput.Write([]byte{command}); err != nil {
			t.Fatal(err)
		}
		line, err := targetOutput.ReadString('\n')
		if err != nil {
			t.Fatalf("target command %q: %v", command, err)
		}
		return line
	}
	var firstCookie, lastCookie, lastWorkCookie uint64
	for i := 0; i < 63; i++ {
		line := request('H')
		if !strings.HasPrefix(line, "HELD:") {
			t.Fatalf("held child %d not admitted: %q", i, line)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "HELD:")))
		if err != nil || pid <= 0 {
			t.Fatalf("held child %d PID: %q %v", i, line, err)
		}
		charge, err := collection.Maps["se_opaque_charges"].LookupBytes(uint32(i + 1))
		if err != nil || len(charge) < 32 {
			t.Fatalf("held child %d charge: raw=%x err=%v", i, charge, err)
		}
		cookie := binary.LittleEndian.Uint64(charge[:8])
		if receiptMap := collection.Maps["opaque_birth_receipts"]; receiptMap != nil {
			locator := binary.LittleEndian.Uint64(charge[24:32])
			var physical, mappedLocator, childPhysical uint64
			keys := collection.Maps["se_opaque_keys"].Iterate()
			for keys.Next(&physical, &mappedLocator) {
				if mappedLocator == locator {
					childPhysical = physical
					break
				}
			}
			if err := keys.Err(); err != nil || childPhysical == 0 {
				t.Fatalf("held child %d physical receipt key: locator=%#x err=%v", i, locator, err)
			}
			receipt, err := receiptMap.LookupBytes(childPhysical)
			if err != nil || len(receipt) != 88 ||
				binary.LittleEndian.Uint64(receipt[0:8]) != childPhysical ||
				binary.LittleEndian.Uint64(receipt[8:16]) != cookie ||
				binary.LittleEndian.Uint64(receipt[16:24]) != locator ||
				binary.LittleEndian.Uint64(receipt[24:32]) == 0 ||
				binary.LittleEndian.Uint64(receipt[24:32]) == childPhysical ||
				binary.LittleEndian.Uint64(receipt[32:40]) != rootCookie ||
				binary.LittleEndian.Uint64(receipt[40:48]) != 10 ||
				binary.LittleEndian.Uint64(receipt[48:56]) == 0 ||
				binary.LittleEndian.Uint64(receipt[56:64]) == 0 ||
				binary.LittleEndian.Uint32(receipt[76:80]) != 2 ||
				binary.LittleEndian.Uint32(receipt[80:84]) != 4 {
				observation := uint32(0)
				if len(receipt) >= 84 {
					observation = binary.LittleEndian.Uint32(receipt[80:84])
				}
				t.Fatalf("held child %d incorrect original-claim birth receipt: observation=%d raw=%x err=%v", i, observation, receipt, err)
			}
			payload, err := collection.Maps["se_opaque_payload"].LookupBytes(uint32(i + 1))
			if err != nil || len(payload) < 8 || binary.LittleEndian.Uint32(payload[4:8]) != 4 {
				t.Fatalf("held child %d was qualified by tracing without LSM authentication: flags=%x err=%v", i, payload, err)
			}
			if i == 0 {
				fd, err := unix.PidfdOpen(pid, 0)
				if errors.Is(err, unix.ENOSYS) {
					// Stock Rocky 4.18 accepts a held proc directory FD
					// in pidfd_send_signal; this is only a test trigger.
					fd, err = unix.Open(filepath.Join("/proc", strconv.Itoa(pid)),
						unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
				}
				if err != nil {
					t.Fatalf("held child pidfd: %v", err)
				}
				err = unix.PidfdSendSignal(fd, 0, nil, 0)
				_ = unix.Close(fd)
				if err != nil {
					t.Fatalf("held child physical signal-0 qualifier: %v", err)
				}
				receipt, err = receiptMap.LookupBytes(childPhysical)
				payload, payloadErr := collection.Maps["se_opaque_payload"].LookupBytes(uint32(i + 1))
				if err != nil || payloadErr != nil || len(receipt) != 88 || len(payload) < 8 ||
					binary.LittleEndian.Uint32(receipt[76:80]) != 3 ||
					binary.LittleEndian.Uint32(payload[4:8]) != 5 {
					t.Fatalf("held child signal-0 did not authenticate birth: receipt=%x/%v payload=%x/%v",
						receipt, err, payload, payloadErr)
				}
			}
		}
		work, err := collection.Maps["se_opaque_work_charges"].LookupBytes(uint32(0))
		if err != nil || len(work) < 8 {
			t.Fatalf("held child %d WORK charge: raw=%x err=%v", i, work, err)
		}
		workCookie := binary.LittleEndian.Uint64(work[:8])
		if cookie <= rootCookie || cookie <= lastCookie || workCookie <= lastWorkCookie {
			t.Fatalf("held child %d TASK/WORK identity did not advance: task=%d prior=%d work=%d prior=%d", i, cookie, lastCookie, workCookie, lastWorkCookie)
		}
		if i == 0 {
			firstCookie = cookie
		}
		lastCookie, lastWorkCookie = cookie, workCookie
		drainWork()
		if used := accountUsed("se_opaque_accounts"); used != uint32(i+2) {
			t.Fatalf("held child %d did not retain TASK credit: used=%d", i, used)
		}
		checkClaims()
	}
	if line := request('H'); line != "DENIED:1\n" {
		t.Fatalf("65th strict TASK allocation did not return EPERM: %q", line)
	}
	if receiptMap := collection.Maps["opaque_birth_receipts"]; receiptMap != nil {
		deadline := time.Now().Add(20 * time.Second)
		for {
			var key uint64
			var receipt [88]byte
			entries := receiptMap.Iterate()
			count := 0
			for entries.Next(&key, &receipt) {
				count++
			}
			if err := entries.Err(); err != nil {
				t.Fatalf("failed-fork birth receipt scan: %v", err)
			}
			if count == 63 {
				break /* only the 63 successful held children remain */
			}
			if count < 63 || time.Now().After(deadline) {
				t.Fatalf("denied fork retained or lost a birth receipt: count=%d want=63", count)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	if used := accountUsed("se_opaque_accounts"); used != 64 {
		t.Fatalf("denied fork changed full TASK account: used=%d", used)
	}
	deniedWork, err := collection.Maps["se_opaque_work_charges"].LookupBytes(uint32(0))
	if err != nil || len(deniedWork) < 8 ||
		binary.LittleEndian.Uint64(deniedWork[:8]) <= lastWorkCookie ||
		accountUsed("se_opaque_work_accounts") != 1 {
		t.Fatalf("denied TASK did not retain one exact failed-fork WORK credit: raw=%x prior=%d err=%v", deniedWork, lastWorkCookie, err)
	}
	deniedWorkCookie := binary.LittleEndian.Uint64(deniedWork[:8])
	drainWork()
	deniedWork, err = collection.Maps["se_opaque_work_charges"].LookupBytes(uint32(0))
	if err != nil || len(deniedWork) < 16 ||
		binary.LittleEndian.Uint64(deniedWork[:8]) != 0 ||
		binary.LittleEndian.Uint64(deniedWork[8:16]) != deniedWorkCookie {
		t.Fatalf("failed-fork WORK credit was not exactly returned: raw=%x cookie=%d err=%v", deniedWork, deniedWorkCookie, err)
	}
	checkClaims()
	t.Logf("recovered strict TASK quota: 63 held children plus root, 65th fork EPERM, TASK used=64 WORK used=0 failed-WORK-cookie=%d returned", deniedWorkCookie)
	if line := request('R'); line != "REAPED:63\n" {
		t.Fatalf("held children did not exit exactly: %q", line)
	}
	for slot := uint32(1); slot <= 63; slot++ {
		waitDead(slot)
	}
	if receiptMap := collection.Maps["opaque_birth_receipts"]; receiptMap != nil {
		var key uint64
		var receipt [88]byte
		entries := receiptMap.Iterate()
		if entries.Next(&key, &receipt) || entries.Err() != nil {
			t.Fatalf("physical task_free retained birth receipt: key=%#x receipt=%x err=%v", key, receipt, entries.Err())
		}
	}
	returned := uint32(0)
	for attempt := 0; accountUsed("se_opaque_accounts") != 1 && attempt < 192; attempt++ {
		returned += runRecoveredReaperStep(t, collection, adminInput, adminOutput, *nextStep)
		*nextStep++
	}
	if used := accountUsed("se_opaque_accounts"); used != 1 || returned != 63 {
		t.Fatalf("physical admin did not refund all held TASKs: used=%d returned=%d", used, returned)
	}
	if used := accountUsed("se_opaque_work_accounts"); used != 0 {
		t.Fatalf("held children left WORK credit: used=%d", used)
	}
	if line := request('F'); !strings.HasPrefix(line, "FORKED:") {
		t.Fatalf("post-exhaustion fork did not recover: %q", line)
	}
	charge, err := collection.Maps["se_opaque_charges"].LookupBytes(uint32(1))
	if err != nil || len(charge) < 8 || binary.LittleEndian.Uint64(charge[:8]) <= lastCookie || firstCookie == 0 {
		t.Fatalf("post-exhaustion slot was not safely recycled: raw=%x last=%d err=%v", charge, lastCookie, err)
	}
	waitDead(1)
	returned = 0
	for attempt := 0; accountUsed("se_opaque_accounts") != 1 && attempt < 192; attempt++ {
		returned += runRecoveredReaperStep(t, collection, adminInput, adminOutput, *nextStep)
		*nextStep++
	}
	if used := accountUsed("se_opaque_accounts"); used != 1 || returned != 1 ||
		accountUsed("se_opaque_work_accounts") != 0 {
		t.Fatalf("post-exhaustion child did not refund exactly: TASK used=%d returned=%d", used, returned)
	}
	checkClaims()
	t.Logf("recovered TASK quota safely recycled slot 1 after EPERM; new cookie=%d", binary.LittleEndian.Uint64(charge[:8]))

	// Keep each completed fork's WORK credit outstanding. A full WORK
	// account must deny a ninth fork before reserving any new TASK credit.
	previousTaskCookie := binary.LittleEndian.Uint64(charge[:8])
	previousWorkCookie := deniedWorkCookie
	var workCookies [8]uint64
	for i := range workCookies {
		if line := request('H'); !strings.HasPrefix(line, "HELD:") {
			t.Fatalf("WORK quota child %d not admitted: %q", i, line)
		}
		taskCharge, err := collection.Maps["se_opaque_charges"].LookupBytes(uint32(i + 1))
		workCharge, workErr := collection.Maps["se_opaque_work_charges"].LookupBytes(uint32(i))
		if err != nil || workErr != nil || len(taskCharge) < 8 || len(workCharge) < 16 {
			t.Fatalf("WORK quota child %d charge: TASK=%x/%v WORK=%x/%v", i, taskCharge, err, workCharge, workErr)
		}
		taskCookie := binary.LittleEndian.Uint64(taskCharge[:8])
		workCookie := binary.LittleEndian.Uint64(workCharge[:8])
		if taskCookie <= previousTaskCookie || workCookie <= previousWorkCookie {
			t.Fatalf("WORK quota child %d nonmonotonic charge: TASK=%d prior=%d WORK=%d prior=%d",
				i, taskCookie, previousTaskCookie, workCookie, previousWorkCookie)
		}
		previousTaskCookie, previousWorkCookie = taskCookie, workCookie
		workCookies[i] = workCookie
		if tasks, works := accountUsed("se_opaque_accounts"), accountUsed("se_opaque_work_accounts"); tasks != uint32(i+2) || works != uint32(i+1) {
			t.Fatalf("WORK quota child %d incorrect occupancy: TASK=%d WORK=%d", i, tasks, works)
		}
		checkClaims()
	}
	if line := request('H'); line != "DENIED:1\n" ||
		accountUsed("se_opaque_accounts") != 9 ||
		accountUsed("se_opaque_work_accounts") != 8 {
		t.Fatalf("full WORK account did not deny ninth fork without TASK charge: %q", line)
	}
	for slot, cookie := range workCookies {
		workCharge, err := collection.Maps["se_opaque_work_charges"].LookupBytes(uint32(slot))
		if err != nil || len(workCharge) < 8 || binary.LittleEndian.Uint64(workCharge[:8]) != cookie {
			t.Fatalf("denied WORK fork changed occupied slot %d: raw=%x cookie=%d err=%v", slot, workCharge, cookie, err)
		}
	}
	drainWork()
	for slot, cookie := range workCookies {
		workCharge, err := collection.Maps["se_opaque_work_charges"].LookupBytes(uint32(slot))
		if err != nil || len(workCharge) < 16 || binary.LittleEndian.Uint64(workCharge[:8]) != 0 ||
			binary.LittleEndian.Uint64(workCharge[8:16]) != cookie {
			t.Fatalf("WORK quota slot %d was not exactly refunded: raw=%x cookie=%d err=%v", slot, workCharge, cookie, err)
		}
	}
	if line := request('H'); !strings.HasPrefix(line, "HELD:") {
		t.Fatalf("WORK quota did not recover after physical refund: %q", line)
	}
	taskCharge, err := collection.Maps["se_opaque_charges"].LookupBytes(uint32(9))
	workCharge, workErr := collection.Maps["se_opaque_work_charges"].LookupBytes(uint32(0))
	if err != nil || workErr != nil || len(taskCharge) < 8 || len(workCharge) < 8 ||
		binary.LittleEndian.Uint64(taskCharge[:8]) <= previousTaskCookie ||
		binary.LittleEndian.Uint64(workCharge[:8]) <= previousWorkCookie {
		t.Fatalf("recycled WORK/TASK charge not newer: TASK=%x/%v WORK=%x/%v", taskCharge, err, workCharge, workErr)
	}
	drainWork()
	if line := request('R'); line != "REAPED:9\n" {
		t.Fatalf("WORK quota children were not all reaped: %q", line)
	}
	for slot := uint32(1); slot <= 9; slot++ {
		waitDead(slot)
	}
	returned = 0
	for attempt := 0; accountUsed("se_opaque_accounts") != 1 && attempt < 192; attempt++ {
		returned += runRecoveredReaperStep(t, collection, adminInput, adminOutput, *nextStep)
		*nextStep++
	}
	if tasks, works := accountUsed("se_opaque_accounts"), accountUsed("se_opaque_work_accounts"); tasks != 1 || works != 0 || returned != 9 {
		t.Fatalf("WORK quota children were not exactly refunded: TASK=%d WORK=%d TASK-returns=%d", tasks, works, returned)
	}
	checkClaims()
	t.Logf("recovered WORK quota: 8/8 occupied, ninth fork EPERM without TASK charge, eight exact WORK refunds, post-refund fork admitted, nine TASK credits returned")
}

func runRecoveredFirstFork(t *testing.T, collection *ebpf.Collection,
	targetInput io.Writer, targetOutput *bufio.Reader, adminInput io.Writer,
	adminOutput *bufio.Reader, nextStep *uint64, rootCookie uint64, parentCount int,
) {
	t.Helper()
	if parentCount < 1 || parentCount > 8 {
		t.Fatalf("invalid first-fork parent count %d", parentCount)
	}
	request := func(command byte) string {
		t.Helper()
		if _, err := targetInput.Write([]byte{command}); err != nil {
			t.Fatal(err)
		}
		line, err := targetOutput.ReadString('\n')
		if err != nil {
			t.Fatalf("first-fork command %q: %v", command, err)
		}
		return line
	}
	type derivedParent struct {
		physical, cookie, locator uint64
		slot                      uint32
	}
	parents := make([]derivedParent, 0, parentCount)
	receiptMap := collection.Maps["opaque_birth_receipts"]
	if receiptMap == nil {
		t.Fatal("first-fork qualification requires exact birth receipts")
	}
	lastParentCookie := rootCookie
	for i := 0; i < parentCount; i++ {
		line := request('Q')
		if !strings.HasPrefix(line, "QUALIFIED_PARENT:") {
			t.Fatalf("derived child %d did not start: %q", i, line)
		}
		pid, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "QUALIFIED_PARENT:")))
		if err != nil || pid <= 0 {
			t.Fatalf("derived child %d PID: %q %v", i, line, err)
		}
		slot := uint32(i + 1)
		charge, err := collection.Maps["se_opaque_charges"].LookupBytes(slot)
		if err != nil || len(charge) < 32 {
			t.Fatalf("derived child %d charge: %x %v", i, charge, err)
		}
		childCookie := binary.LittleEndian.Uint64(charge[:8])
		childLocator := binary.LittleEndian.Uint64(charge[24:32])
		if childCookie <= lastParentCookie || childLocator == 0 {
			t.Fatalf("derived child %d identity: cookie=%d locator=%#x previous=%d",
				i, childCookie, childLocator, lastParentCookie)
		}
		var physical, mappedLocator, childPhysical uint64
		keys := collection.Maps["se_opaque_keys"].Iterate()
		for keys.Next(&physical, &mappedLocator) {
			if mappedLocator == childLocator {
				childPhysical = physical
				break
			}
		}
		if err := keys.Err(); err != nil || childPhysical == 0 {
			t.Fatalf("derived child %d physical key: %#x %v", i, childPhysical, err)
		}
		receipt, err := receiptMap.LookupBytes(childPhysical)
		payload, payloadErr := collection.Maps["se_opaque_payload"].LookupBytes(slot)
		if err != nil || payloadErr != nil || len(receipt) != 88 || len(payload) < 8 ||
			binary.LittleEndian.Uint64(receipt[8:16]) != childCookie ||
			binary.LittleEndian.Uint64(receipt[16:24]) != childLocator ||
			binary.LittleEndian.Uint64(receipt[32:40]) != rootCookie ||
			binary.LittleEndian.Uint32(receipt[76:80]) != 2 ||
			binary.LittleEndian.Uint32(payload[4:8]) != 4 {
			t.Fatalf("derived child %d was not marker-only: receipt=%x/%v payload=%x/%v",
				i, receipt, err, payload, payloadErr)
		}
		parents = append(parents, derivedParent{childPhysical, childCookie, childLocator, slot})
		lastParentCookie = childCookie
	}
	if parentCount > 1 {
		// Creating the held parents consumed one WORK credit each. Reclaim
		// only those completed setup WORKs before the simultaneous first forks,
		// or the burst would merely test the intentional eight-WORK limit.
		workMap := collection.Maps["se_opaque_work_accounts"]
		work, err := workMap.LookupBytes(uint32(0))
		if err != nil || len(work) < 8 || binary.LittleEndian.Uint32(work[4:8]) != uint32(parentCount) {
			t.Fatalf("first-fork setup WORK occupancy: %x %v", work, err)
		}
		settled := false
		for attempt := 0; attempt < 128; attempt++ {
			if reclaimed := runRecoveredReaperStep(t, collection, adminInput, adminOutput, *nextStep); reclaimed != 0 {
				t.Fatalf("live first-fork parent was reclaimed during setup: %d", reclaimed)
			}
			*nextStep++
			work, err = workMap.LookupBytes(uint32(0))
			if err != nil || len(work) < 12 || binary.LittleEndian.Uint32(work[8:12]) != 0 {
				t.Fatalf("first-fork setup WORK account fault: %x %v", work, err)
			}
			if binary.LittleEndian.Uint32(work[4:8]) == 0 {
				settled = true
				break
			}
		}
		if !settled {
			t.Fatalf("first-fork setup WORK credits did not return: %x", work)
		}
	}
	if line := request('B'); line != fmt.Sprintf("BURST:%d:0\n", parentCount) {
		t.Fatalf("derived children's concurrent first forks did not all qualify: %q", line)
	}
	for i, parent := range parents {
		receipt, err := receiptMap.LookupBytes(parent.physical)
		payload, payloadErr := collection.Maps["se_opaque_payload"].LookupBytes(parent.slot)
		if err != nil || payloadErr != nil || len(receipt) != 88 || len(payload) < 8 ||
			binary.LittleEndian.Uint64(receipt[8:16]) != parent.cookie ||
			binary.LittleEndian.Uint64(receipt[16:24]) != parent.locator ||
			binary.LittleEndian.Uint32(receipt[76:80]) != 3 ||
			binary.LittleEndian.Uint32(payload[4:8]) != 5 {
			t.Fatalf("derived parent %d lacked qualified first fork: receipt=%x/%v payload=%x/%v",
				i, receipt, err, payload, payloadErr)
		}
	}
	for slot := uint32(parentCount + 1); slot <= uint32(2*parentCount); slot++ {
		grandchild, err := collection.Maps["se_opaque_charges"].LookupBytes(slot)
		if err != nil || len(grandchild) < 32 ||
			binary.LittleEndian.Uint64(grandchild[:8]) <= lastParentCookie ||
			binary.LittleEndian.Uint64(grandchild[24:32]) == 0 {
			t.Fatalf("concurrent first-fork grandchild slot %d: charge=%x err=%v", slot, grandchild, err)
		}
	}
	if line := request('R'); line != fmt.Sprintf("REAPED:%d\n", parentCount) {
		t.Fatalf("derived child was not reaped: %q", line)
	}
	for slot := uint32(1); slot <= uint32(2*parentCount); slot++ {
		deadline := time.Now().Add(20 * time.Second)
		for {
			meta, err := collection.Maps["se_opaque_meta"].LookupBytes(slot)
			if err != nil || len(meta) < 8 {
				t.Fatalf("first-fork TASK[%d] death: %x %v", slot, meta, err)
			}
			if binary.LittleEndian.Uint32(meta[4:8]) == 2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("first-fork TASK[%d] lacked task_free: %x", slot, meta)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	returned := uint32(0)
	for attempt := 0; attempt < 192; attempt++ {
		returned += runRecoveredReaperStep(t, collection, adminInput, adminOutput, *nextStep)
		*nextStep++
		account, err := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0))
		work, workErr := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
		if err != nil || workErr != nil || len(account) < 12 || len(work) < 12 ||
			binary.LittleEndian.Uint32(account[8:12]) != 0 ||
			binary.LittleEndian.Uint32(work[8:12]) != 0 {
			t.Fatalf("first-fork account fault: TASK=%x/%v WORK=%x/%v", account, err, work, workErr)
		}
		if binary.LittleEndian.Uint32(account[4:8]) == 1 &&
			binary.LittleEndian.Uint32(work[4:8]) == 0 {
			if returned != uint32(2*parentCount) {
				t.Fatalf("first-fork TASK refunds=%d want=%d", returned, 2*parentCount)
			}
			t.Logf("derived first forks: %d marker-only children became QUALIFIED in task_alloc, %d grandchildren charged, %d TASK and WORK credits returned",
				parentCount, parentCount, 2*parentCount)
			return
		}
	}
	account, _ := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0))
	work, _ := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
	var details strings.Builder
	for slot := uint32(1); slot <= uint32(2*parentCount); slot++ {
		meta, _ := collection.Maps["se_opaque_meta"].LookupBytes(slot)
		charge, _ := collection.Maps["se_opaque_charges"].LookupBytes(slot)
		payload, _ := collection.Maps["se_opaque_payload"].LookupBytes(slot)
		archive, _ := collection.Maps["se_opaque_archive"].LookupBytes(slot)
		fmt.Fprintf(&details, " slot%d:meta=%x charge=%x flags=", slot, meta, charge)
		if len(payload) >= 8 {
			fmt.Fprintf(&details, "%d", binary.LittleEndian.Uint32(payload[4:8]))
		} else {
			fmt.Fprintf(&details, "short:%x", payload)
		}
		fmt.Fprintf(&details, " archive=%x", archive)
	}
	t.Fatalf("first-fork charges did not return after bounded physical scans: TASK returned=%d account=%x WORK=%x%s",
		returned, account, work, details.String())
}

// A verifier-isolation object can stop after the child's real TASK charge and
// source abort, before any directory publication. A denied security_task_alloc
// does not invoke security_task_free for that child; physical admin reaping
// must return the exact unpublished charge instead.
func runRecoveredAbortedBirths(t *testing.T, collection *ebpf.Collection,
	targetInput io.Writer, targetOutput *bufio.Reader, adminInput io.Writer,
	adminOutput *bufio.Reader, nextStep *uint64, rootCookie uint64, count int,
) {
	t.Helper()
	request := func(command byte) string {
		t.Helper()
		if _, err := targetInput.Write([]byte{command}); err != nil {
			t.Fatal(err)
		}
		line, err := targetOutput.ReadString('\n')
		if err != nil {
			t.Fatalf("aborted-birth command %q: %v", command, err)
		}
		return line
	}
	accountUsed := func(name string) uint32 {
		t.Helper()
		account, err := collection.Maps[name].LookupBytes(uint32(0))
		if err != nil || len(account) < 12 || binary.LittleEndian.Uint32(account[8:12]) != 0 {
			t.Fatalf("aborted-birth account %s: %x %v", name, account, err)
		}
		return binary.LittleEndian.Uint32(account[4:8])
	}
	lastCookie := rootCookie
	for i := 0; i < count; i++ {
		if line := request('H'); line != "DENIED:1\n" {
			t.Fatalf("aborted child %d was not denied before birth: %q", i, line)
		}
		charge, err := collection.Maps["se_opaque_charges"].LookupBytes(uint32(1))
		meta, metaErr := collection.Maps["se_opaque_meta"].LookupBytes(uint32(1))
		if err != nil || metaErr != nil || len(charge) < 32 || len(meta) < 8 ||
			binary.LittleEndian.Uint64(charge[:8]) <= lastCookie ||
			binary.LittleEndian.Uint32(meta[4:8]) != 6 ||
			accountUsed("se_opaque_accounts") != 2 {
			t.Fatalf("aborted child %d lacks retained unpublished TASK: charge=%x/%v meta=%x/%v previous=%d",
				i, charge, err, meta, metaErr, lastCookie)
		}
		lastCookie = binary.LittleEndian.Uint64(charge[:8])
		keys := collection.Maps["se_opaque_keys"].Iterate()
		var physical, locator uint64
		if !keys.Next(&physical, &locator) || physical == 0 ||
			keys.Next(&physical, &locator) || keys.Err() != nil {
			t.Fatalf("aborted child %d published a directory entry: first=%#x/%#x err=%v",
				i, physical, locator, keys.Err())
		}
		returned := uint32(0)
		settled := false
		for attempt := 0; attempt < 192; attempt++ {
			returned += runRecoveredReaperStep(t, collection, adminInput, adminOutput, *nextStep)
			*nextStep++
			if accountUsed("se_opaque_accounts") == 1 &&
				accountUsed("se_opaque_work_accounts") == 0 {
				settled = true
				break
			}
		}
		if !settled || returned != 1 {
			t.Fatalf("aborted child %d did not return exact TASK/WORK credit: settled=%t returned=%d",
				i, settled, returned)
		}
		if (i+1)%512 == 0 {
			t.Logf("aborted births=%d TASK-cookie=%d physical scan epochs=%d", i+1, lastCookie, *nextStep-1)
		}
	}
	if receiptMap := collection.Maps["opaque_birth_receipts"]; receiptMap != nil {
		deadline := time.Now().Add(20 * time.Second)
		for {
			var key uint64
			var receipt [88]byte
			entries := receiptMap.Iterate()
			if !entries.Next(&key, &receipt) && entries.Err() == nil {
				break
			}
			if entries.Err() != nil || time.Now().After(deadline) {
				t.Fatalf("denied births retained receipt: key=%#x receipt=%x err=%v",
					key, receipt, entries.Err())
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	t.Logf("aborted births complete: denied=%d TASK-cookie=%d physical scan epochs=%d, original root retained",
		count, lastCookie, *nextStep-1)
}

func TestOpaqueRecoveredInitialTaskLive(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_RECOVERED_INITIAL_TASK_OBJECT")
	cgroup := os.Getenv("IG_OPAQUE_RECOVERED_INITIAL_TASK_CGROUP")
	targetBinary := os.Getenv("IG_OPAQUE_RECOVERED_INITIAL_TASK_HELPER")
	topologyBinary := os.Getenv("IG_OPAQUE_RECOVERED_INITIAL_TASK_TOPOLOGY")
	reaperTransport := os.Getenv("IG_OPAQUE_RECOVERED_INITIAL_TASK_REAPER_TRANSPORT") == "1"
	swapNegative := os.Getenv("IG_OPAQUE_RECOVERED_INITIAL_TASK_DETHREAD_NEGATIVE") == "1"
	exitNegative := os.Getenv("IG_OPAQUE_RECOVERED_INITIAL_TASK_EXIT_NEGATIVE") == "1"
	exhaust := os.Getenv("IG_OPAQUE_RECOVERED_INITIAL_TASK_EXHAUST") == "1"
	firstForkCount := 0
	if raw := os.Getenv("IG_OPAQUE_RECOVERED_INITIAL_TASK_CHILD_FIRST_FORK"); raw != "" {
		var err error
		firstForkCount, err = strconv.Atoi(raw)
		if err != nil || firstForkCount < 1 || firstForkCount > 8 {
			t.Fatalf("invalid recovered first-fork parent count %q", raw)
		}
	}
	firstFork := firstForkCount > 0
	abortCount := 0
	if raw := os.Getenv("IG_OPAQUE_RECOVERED_INITIAL_TASK_CHILD_ABORT"); raw != "" {
		var err error
		abortCount, err = strconv.Atoi(raw)
		if err != nil || abortCount < 1 || abortCount > 4097 {
			t.Fatalf("invalid recovered aborted-birth count %q", raw)
		}
	}
	churnCount := 0
	if raw := os.Getenv("IG_OPAQUE_RECOVERED_INITIAL_TASK_CHILD_CHURN"); raw != "" {
		var err error
		churnCount, err = strconv.Atoi(raw)
		if err != nil || churnCount < 1 || churnCount > 4097 || !reaperTransport {
			t.Fatalf("invalid recovered child churn count %q", raw)
		}
	}
	if (swapNegative || exitNegative) && (reaperTransport || churnCount != 0 || exhaust || swapNegative && exitNegative) {
		t.Fatal("physical-swap/exit negative must not select reaper, child churn or each other")
	}
	if exhaust && (!reaperTransport || churnCount != 0) {
		t.Fatal("recovered TASK exhaustion requires the physical reaper and no child churn")
	}
	if firstFork && (!reaperTransport || exhaust || churnCount != 0 || swapNegative || exitNegative) {
		t.Fatal("recovered first-fork proof requires only the physical reaper")
	}
	if abortCount > 0 && (!reaperTransport || exhaust || churnCount != 0 || firstFork || swapNegative || exitNegative) {
		t.Fatal("recovered aborted-birth proof requires only the physical reaper")
	}
	if object == "" || cgroup == "" || targetBinary == "" || topologyBinary == "" {
		t.Skip("set recovered initial TASK object, isolated cgroup, target and topology helpers")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 ||
		!filepath.IsAbs(targetBinary) || !filepath.IsAbs(topologyBinary) ||
		!strings.HasPrefix(filepath.Base(cgroup), "ig15-g005-recovered-initial-") {
		t.Fatal("requires root, amd64/Linux, dedicated cgroup and absolute static helpers")
	}
	var cgstat unix.Stat_t
	if err := unix.Stat(cgroup, &cgstat); err != nil || cgstat.Ino == 0 {
		t.Fatalf("isolated cgroup stat: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	timeout := 70 * time.Second
	if churnCount > 1 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()
	target := exec.CommandContext(ctx, targetBinary, cgroup)
	target.Env = append(os.Environ(), "IG_TEST_ISOLATE_MOUNT_NS=1")
	if swapNegative {
		// The alternate physical leader already exists before strict hooks
		// attach; creating a new thread after capture is correctly denied.
		target.Env = append(target.Env, "IG_TEST_PRECREATE_SWAP_THREAD=1")
	}
	input, err := target.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := target.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var targetErr bytes.Buffer
	target.Stderr = &targetErr
	if err := target.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if target.ProcessState == nil {
			_ = target.Process.Kill()
			_ = target.Wait()
		}
	}()
	reader := bufio.NewReader(output)
	if line, err := reader.ReadString('\n'); err != nil || line != "READY\n" {
		t.Fatalf("target readiness: %q %v stderr=%q", line, err, targetErr.String())
	}
	if _, err := input.Write([]byte{'M'}); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "IN_CGROUP\n" {
		t.Fatalf("target cgroup: %q %v stderr=%q", line, err, targetErr.String())
	}
	procPath := filepath.Join("/proc", strconv.Itoa(target.Process.Pid))
	paths := []string{procPath, cgroup, filepath.Join(procPath, "ns/mnt"), "/proc/self/ns/mnt"}
	var borrowed [4]*os.File
	for i, path := range paths {
		borrowed[i], err = os.Open(path)
		if err != nil {
			for _, f := range borrowed {
				if f != nil {
					_ = f.Close()
				}
			}
			t.Fatalf("borrow recovered live pin %s: %v", path, err)
		}
	}
	lease := &recoveredLiveTestLease{
		proc: borrowed[0], cgroup: borrowed[1],
		mount: borrowed[2], hostMount: borrowed[3], pid: uint32(target.Process.Pid),
		cgroupID: cgstat.Ino,
	}
	lease.start, err = readPinnedInitStart(lease.proc, lease.pid)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	pins, err := prepareSharedPhysicalPins(ctx,
		SharedBindingConfig{CgroupID: cgstat.Ino, InitHostPID: lease.pid}, lease)
	if err != nil {
		if pins != nil {
			_ = pins.Close()
		} else {
			_ = lease.Close()
		}
		t.Fatalf("recovered live physical pin preparation: %v", err)
	}
	defer func() {
		if err := pins.Close(); err != nil {
			t.Error(err)
		}
	}()
	if pins.InitProc().Fd() == lease.InitProc().Fd() {
		t.Fatal("physical pin preparation did not duplicate borrowed init proc")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	selected := map[string]*ebpf.ProgramSpec{}
	for _, name := range []string{
		"opaque_real_live_bootstrap_control",
		"opaque_real_owner_child_source_candidate",
		"opaque_real_owner_child_final_free_candidate",
		"opaque_real_owner_recovered_initial_task_diagnostic",
		"se_rm_guardian", "se_rm_administrator",
	} {
		if spec.Programs[name] == nil {
			t.Fatalf("missing candidate program %s", name)
		}
		selected[name] = spec.Programs[name]
	}
	reaperPrograms := []string{"opaque_real_live_reap_task"}
	if reaperTransport {
		reaperPrograms = []string{"se_pool_reaper_entry", "se_pool_reaper_chunk"}
	}
	if churnCount > 0 || exhaust || firstFork || abortCount > 0 {
		reaperPrograms = append(reaperPrograms, "opaque_real_owner_child_target_candidate")
	}
	for _, name := range reaperPrograms {
		if spec.Programs[name] == nil {
			t.Fatalf("missing reaper program %s", name)
		}
		selected[name] = spec.Programs[name]
	}
	if spec.Maps["opaque_birth_receipts"] != nil {
		for _, name := range []string{
			"opaque_real_owner_successful_birth_candidate",
			"opaque_real_owner_birth_free_task_candidate",
			"opaque_real_owner_birth_signal0_diagnostic",
		} {
			if spec.Programs[name] == nil {
				t.Fatalf("birth receipt map lacks source %s", name)
			}
			selected[name] = spec.Programs[name]
		}
	}
	spec.Programs = selected
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("recovered initial TASK verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	if os.Getenv("IG_OPAQUE_RECOVERED_INITIAL_TASK_LOAD_ONLY") == "1" {
		t.Log("recovered candidate collection verifier-loaded; no LSM links attached")
		return
	}
	config := struct {
		Incarnation, Nonce uint64
		ABI, Scenario      uint32
		CloneFlags         uint64
	}{11, 13, 2, 0, 0x8011}
	if err := collection.Maps["se_rm_configuration"].Update(uint32(0), config, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["se_rm_configuration"].Freeze(); err != nil {
		t.Fatal(err)
	}
	gate := struct {
		Cgroup, Scope           uint64
		Enabled, ExecutionClass uint32
	}{cgstat.Ino, 10, 1, 2}
	if err := collection.Maps["opaque_real_live_bootstrap_gate"].Update(uint32(0), gate, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["opaque_real_owner_child_gate"].Update(uint32(0), uint32(1), ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	request := struct {
		NodeCookie, AdminGeneration, Cgroup, Scope uint64
		TargetTGID, Enabled                        uint32
	}{11, 1, cgstat.Ino, 10, uint32(target.Process.Pid), 1}
	if err := collection.Maps["opaque_recovered_initial_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"opaque_real_live_bootstrap_gate", "opaque_real_owner_child_gate",
		"opaque_recovered_initial_request", "se_opaque_payload_zero", "se_opaque_work_zero",
	} {
		if err := collection.Maps[name].Freeze(); err != nil {
			t.Fatalf("freeze %s: %v", name, err)
		}
	}
	if zero := collection.Maps["opaque_birth_receipt_zero"]; zero != nil {
		if err := zero.Freeze(); err != nil {
			t.Fatalf("freeze birth receipt zero template: %v", err)
		}
	}
	code, _, err := collection.Programs["opaque_real_live_bootstrap_control"].Test(make([]byte, 64))
	if err != nil || code != 0 {
		t.Fatalf("synthetic route seed: code=%d err=%v", code, err)
	}
	reapWire := recoveredReapRequestWire{1, 1, 11, 1, 1, 32, 16, 0, 0, 0}
	if reaperTransport {
		if churnCount > 0 || exhaust || firstFork || abortCount > 0 {
			if err := collection.Maps["opaque_real_owner_child_targets"].Update(uint32(0),
				collection.Programs["opaque_real_owner_child_target_candidate"], ebpf.UpdateAny); err != nil {
				t.Fatalf("install child constructor target: %v", err)
			}
		}
		chain := collection.Maps["se_pool_reap_chain"]
		if err := chain.Update(uint32(0), collection.Programs["se_pool_reaper_chunk"], ebpf.UpdateAny); err != nil {
			t.Fatalf("install exact reaper chunk: %v", err)
		}
		var installed *ebpf.Program
		if err := chain.Lookup(uint32(0), &installed); err != nil || installed == nil {
			t.Fatalf("read back reaper chunk: %v", err)
		}
		installedInfo, err := installed.Info()
		_ = installed.Close()
		if err != nil {
			t.Fatal(err)
		}
		originalInfo, err := collection.Programs["se_pool_reaper_chunk"].Info()
		if err != nil {
			t.Fatal(err)
		}
		installedID, installedOK := installedInfo.ID()
		originalID, originalOK := originalInfo.ID()
		if !installedOK || !originalOK || installedID == 0 || installedID != originalID {
			t.Fatalf("reaper chunk identity mismatch: installed=%d original=%d", installedID, originalID)
		}
		if err := collection.Maps["se_pool_reap_request"].Update(uint32(0), reapWire, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		// A copied request is never authority; the test process is not A.
		if _, _, err := collection.Programs["se_pool_reaper_entry"].Test(make([]byte, 64)); err != nil {
			t.Fatalf("wrong-sender reaper TEST_RUN: %v", err)
		}
		control, err := collection.Maps["se_pool_reap_control"].LookupBytes(uint32(0))
		if err != nil || len(control) != 64 || binary.LittleEndian.Uint64(control[24:32]) != 0 ||
			binary.LittleEndian.Uint32(control[4:8]) != 0 {
			t.Fatalf("wrong-sender reaper reserved control: raw=%x err=%v", control, err)
		}
	}
	var links []link.Link
	defer func() {
		for i := len(links) - 1; i >= 0; i-- {
			_ = links[i].Close()
		}
	}()
	for _, name := range []string{
		"opaque_real_owner_child_source_candidate",
		"opaque_real_owner_child_final_free_candidate", "opaque_real_owner_recovered_initial_task_diagnostic",
	} {
		attached, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs[name]})
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		links = append(links, attached)
	}
	if program := collection.Programs["opaque_real_owner_successful_birth_candidate"]; program != nil {
		attached, err := link.AttachRawTracepoint(link.RawTracepointOptions{
			Name: "sched_process_fork", Program: program,
		})
		if err != nil {
			t.Fatalf("attach successful-birth diagnostic: %v", err)
		}
		links = append(links, attached)
	}
	if program := collection.Programs["opaque_real_owner_birth_free_task_candidate"]; program != nil {
		attached, err := link.Kprobe("free_task", program, nil)
		if err != nil {
			t.Fatalf("attach failed-fork receipt cleanup: %v", err)
		}
		links = append(links, attached)
	}
	if program := collection.Programs["opaque_real_owner_birth_signal0_diagnostic"]; program != nil {
		attached, err := link.AttachLSM(link.LSMOptions{Program: program})
		if err != nil {
			t.Fatalf("attach physical signal-0 birth consumer: %v", err)
		}
		links = append(links, attached)
	}
	descriptors := []int{
		collection.Programs["se_rm_guardian"].FD(),
		collection.Programs["se_rm_administrator"].FD(),
		collection.Maps["se_rm_guardian_request"].FD(),
		collection.Maps["se_rm_admin_request"].FD(),
		collection.Maps["se_rm_control"].FD(),
		collection.Maps["se_rm_guardian_receipt"].FD(),
		collection.Maps["se_rm_admin_receipt"].FD(),
		int(pins.InitProc().Fd()),
		collection.Maps["opaque_recovered_initial_consumed"].FD(),
	}
	if reaperTransport {
		descriptors = append(descriptors, collection.Programs["se_pool_reaper_entry"].FD())
	}
	var files []*os.File
	for i, fd := range descriptors {
		dup, err := unix.Dup(fd)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, os.NewFile(uintptr(dup), fmt.Sprintf("recovery-fd-%d", i)))
	}
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	topologyMode := "live"
	if reaperTransport {
		topologyMode = "live-reap"
	}
	if churnCount > 0 || exhaust || firstFork || abortCount > 0 {
		topologyMode = "live-churn"
	}
	if swapNegative {
		topologyMode = "live-swap"
	}
	if exitNegative {
		topologyMode = "live-exit"
	}
	live := exec.CommandContext(ctx, topologyBinary, topologyMode)
	live.ExtraFiles = files
	var result []byte
	var topologyInput io.WriteCloser
	var topologyOutput *bufio.Reader
	var topologyErr bytes.Buffer
	guardianPGID := 0
	if reaperTransport || swapNegative || exitNegative {
		stdin, err := live.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := live.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		topologyInput = stdin
		defer topologyInput.Close()
		topologyOutput = bufio.NewReader(stdout)
		live.Stderr = &topologyErr
		if err := live.Start(); err != nil {
			t.Fatal(err)
		}
		defer func() {
			if live.ProcessState == nil {
				if guardianPGID > 0 {
					_ = syscall.Kill(-guardianPGID, syscall.SIGKILL)
				}
				_ = live.Process.Kill()
				_ = live.Wait()
			}
		}()
		line, err := topologyOutput.ReadString('\n')
		result = []byte(line)
		readyLine := "ENROLLED %d\n"
		if swapNegative || exitNegative {
			readyLine = "CAPTURED %d\n"
		}
		parsed, parseErr := fmt.Sscanf(line, readyLine, &guardianPGID)
		if err != nil || parseErr != nil || parsed != 1 || guardianPGID <= 0 {
			t.Fatalf("recovered topology enrollment: %q read=%v parse=%v stderr=%q", line, err, parseErr, topologyErr.String())
		}
	} else {
		result, err = live.CombinedOutput()
		if err != nil || !strings.Contains(string(result), "topology PASS mode=live") {
			var stage, consumed uint32
			_ = collection.Maps["opaque_recovered_initial_stage"].Lookup(uint32(0), &stage)
			_ = collection.Maps["opaque_recovered_initial_consumed"].Lookup(uint32(0), &consumed)
			t.Fatalf("recovered initial TASK: %v stage=%d consumed=%d\n%s", err, stage, consumed, result)
		}
	}
	if exitNegative {
		var witnessed uint64
		if err := collection.Maps["opaque_recovered_initial_physical"].Lookup(uint32(0), &witnessed); err != nil || witnessed <= 1 {
			t.Fatalf("physical exit capture did not precede target death: witness=%#x err=%v", witnessed, err)
		}
		if _, err := input.Write([]byte{'X'}); err != nil {
			t.Fatal(err)
		}
		if err := target.Wait(); err != nil {
			t.Fatalf("pre-enrollment target exit: %v stderr=%q", err, targetErr.String())
		}
		deadline := time.Now().Add(20 * time.Second)
		for {
			if err := collection.Maps["opaque_recovered_initial_physical"].Lookup(uint32(0), &witnessed); err != nil {
				t.Fatal(err)
			}
			if witnessed == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("exited physical TASK was not tombstoned: witness=%#x", witnessed)
			}
			time.Sleep(20 * time.Millisecond)
		}
		if _, err := topologyInput.Write([]byte{'S'}); err != nil {
			t.Fatal(err)
		}
		line, err := topologyOutput.ReadString('\n')
		if err != nil || line != "EXIT_DENIED\n" {
			t.Fatalf("exited physical TASK was not refused: %q %v stderr=%q", line, err, topologyErr.String())
		}
		var stage, consumed uint32
		_ = collection.Maps["opaque_recovered_initial_stage"].Lookup(uint32(0), &stage)
		_ = collection.Maps["opaque_recovered_initial_consumed"].Lookup(uint32(0), &consumed)
		if stage != 1 || consumed != 0 {
			t.Fatalf("physical exit consumed or enrolled root: stage=%d consumed=%d", stage, consumed)
		}
		keys := collection.Maps["se_opaque_keys"].Iterate()
		var physical, locator uint64
		if keys.Next(&physical, &locator) || keys.Err() != nil {
			t.Fatalf("physical exit left enrolled TASK: physical=%#x locator=%#x err=%v", physical, locator, keys.Err())
		}
		account, err := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0))
		if err != nil || len(account) < 12 || binary.LittleEndian.Uint32(account[4:8]) != 0 ||
			binary.LittleEndian.Uint32(account[8:12]) != 0 {
			t.Fatalf("physical exit retained TASK charge/fault: raw=%x err=%v", account, err)
		}
		line, err = topologyOutput.ReadString('\n')
		if err != nil || !strings.Contains(line, "topology PASS mode=live-exit") {
			t.Fatalf("physical exit topology: %q %v stderr=%q", line, err, topologyErr.String())
		}
		if err := live.Wait(); err != nil {
			t.Fatalf("physical exit topology process: %v stderr=%q", err, topologyErr.String())
		}
		t.Log("pre-enrollment physical exit tombstoned witness and denied second signal without a TASK charge")
		return
	}
	if swapNegative {
		var witnessed uint64
		if err := collection.Maps["opaque_recovered_initial_physical"].Lookup(uint32(0), &witnessed); err != nil || witnessed <= 1 {
			t.Fatalf("physical capture did not precede swap: witness=%#x err=%v", witnessed, err)
		}
		originalPhysical := witnessed
		if _, err := input.Write([]byte{'T'}); err != nil {
			t.Fatal(err)
		}
		if line, err := reader.ReadString('\n'); err != nil || line != "SWAPPED\n" {
			t.Fatalf("de_thread of pinned init: %q %v stderr=%q", line, err, targetErr.String())
		}
		// Proc PID/starttime and mount/cgroup pins survive de_thread; they
		// cannot by themselves certify that the physical TASK is unchanged.
		if err := pins.Check(ctx); err != nil {
			t.Fatalf("retained proc/group pins changed unexpectedly after de_thread: %v", err)
		}
		deadline := time.Now().Add(20 * time.Second)
		for {
			if err := collection.Maps["opaque_recovered_initial_physical"].Lookup(uint32(0), &witnessed); err != nil {
				t.Fatal(err)
			}
			if witnessed == 1 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("old physical TASK was not source-tombstoned: witness=%#x", witnessed)
			}
			time.Sleep(20 * time.Millisecond)
		}
		if _, err := topologyInput.Write([]byte{'S'}); err != nil {
			t.Fatal(err)
		}
		line, err := topologyOutput.ReadString('\n')
		if err != nil || line != "SWAP_DENIED\n" {
			t.Fatalf("replacement physical TASK was not refused: %q %v stderr=%q", line, err, topologyErr.String())
		}
		var stage, consumed uint32
		_ = collection.Maps["opaque_recovered_initial_stage"].Lookup(uint32(0), &stage)
		_ = collection.Maps["opaque_recovered_initial_consumed"].Lookup(uint32(0), &consumed)
		if stage != 1 || consumed != 0 {
			t.Fatalf("physical swap consumed or enrolled root: stage=%d consumed=%d", stage, consumed)
		}
		keys := collection.Maps["se_opaque_keys"].Iterate()
		var physical, locator uint64
		if keys.Next(&physical, &locator) || keys.Err() != nil {
			t.Fatalf("physical swap left an enrolled TASK: physical=%#x locator=%#x err=%v", physical, locator, keys.Err())
		}
		if _, err := input.Write([]byte{'X'}); err != nil {
			t.Fatal(err)
		}
		if err := target.Wait(); err != nil {
			t.Fatalf("swapped target exit: %v stderr=%q", err, targetErr.String())
		}
		line, err = topologyOutput.ReadString('\n')
		if err != nil || !strings.Contains(line, "topology PASS mode=live-swap") {
			t.Fatalf("physical swap topology: %q %v stderr=%q", line, err, topologyErr.String())
		}
		if err := live.Wait(); err != nil {
			t.Fatalf("physical swap topology process: %v stderr=%q", err, topologyErr.String())
		}
		t.Logf("pinned-proc de_thread negative: original physical %#x tombstoned, replacement refused without TASK charge", originalPhysical)
		return
	}
	var stage, consumed uint32
	if err := collection.Maps["opaque_recovered_initial_stage"].Lookup(uint32(0), &stage); err != nil || stage != 4 {
		t.Fatalf("initial TASK not qualified: stage=%d err=%v output=%s", stage, err, result)
	}
	if err := collection.Maps["opaque_recovered_initial_consumed"].Lookup(uint32(0), &consumed); err != nil || consumed != 1 {
		t.Fatalf("initial TASK not one-shot: consumed=%d err=%v", consumed, err)
	}
	keys := collection.Maps["se_opaque_keys"].Iterate()
	var physical, locator uint64
	if !keys.Next(&physical, &locator) || keys.Err() != nil || physical == 0 || locator == 0 ||
		keys.Next(&physical, &locator) {
		t.Fatalf("expected one opaque TASK: physical=%#x locator=%#x err=%v", physical, locator, keys.Err())
	}
	var witnessed uint64
	if err := collection.Maps["opaque_recovered_initial_physical"].Lookup(uint32(0), &witnessed); err != nil || witnessed != physical {
		t.Fatalf("initial TASK not bound to physical capture: witness=%#x TASK=%#x err=%v", witnessed, physical, err)
	}
	var payload [1280]byte
	if err := collection.Maps["se_opaque_payload"].Lookup(uint32(0), &payload); err != nil ||
		binary.LittleEndian.Uint32(payload[4:8]) != 5 ||
		binary.LittleEndian.Uint64(payload[16:24]) != 10 {
		t.Fatalf("initial TASK not qualified in opaque payload: flags=%d scope=%d err=%v",
			binary.LittleEndian.Uint32(payload[4:8]), binary.LittleEndian.Uint64(payload[16:24]), err)
	}
	charge, err := collection.Maps["se_opaque_charges"].LookupBytes(uint32(0))
	if err != nil || len(charge) < 8 || binary.LittleEndian.Uint64(charge[:8]) == 0 {
		t.Fatalf("initial TASK charge: raw=%x err=%v", charge, err)
	}
	cookie := binary.LittleEndian.Uint64(charge[:8])
	nextReapStep := uint64(1)
	if exhaust {
		runRecoveredTaskQuotaExhaustion(t, collection, input, reader,
			topologyInput, topologyOutput, &nextReapStep, cookie)
	}
	if firstFork {
		runRecoveredFirstFork(t, collection, input, reader,
			topologyInput, topologyOutput, &nextReapStep, cookie, firstForkCount)
	}
	if abortCount > 0 {
		runRecoveredAbortedBirths(t, collection, input, reader,
			topologyInput, topologyOutput, &nextReapStep, cookie, abortCount)
	}
	seenChildren := make(map[uint64]struct{ cookie, locator uint64 })
	var lastChildCookie uint64
	addressReuse := 0
	for iteration := 0; iteration < churnCount; iteration++ {
		if _, err := input.Write([]byte{'F'}); err != nil {
			t.Fatalf("child %d fork request: %v", iteration, err)
		}
		line, err := reader.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, "FORKED:") {
			t.Fatalf("child %d fork/wait: %q %v stderr=%q", iteration, line, err, targetErr.String())
		}
		var child, childLocator uint64
		keys := collection.Maps["se_opaque_keys"].Iterate()
		for keys.Next(&child, &childLocator) {
			if child != physical {
				break
			}
		}
		if keys.Err() != nil || child == 0 || child == physical || childLocator == 0 {
			t.Fatalf("child %d missing charged TASK: physical=%#x locator=%#x err=%v", iteration, child, childLocator, keys.Err())
		}
		childCharge, err := collection.Maps["se_opaque_charges"].LookupBytes(uint32(1))
		if err != nil || len(childCharge) < 8 {
			t.Fatalf("child %d TASK charge: raw=%x err=%v", iteration, childCharge, err)
		}
		childCookie := binary.LittleEndian.Uint64(childCharge[:8])
		if childCookie <= lastChildCookie || childCookie <= cookie {
			t.Fatalf("child %d TASK cookie did not advance: previous=%d current=%d root=%d",
				iteration, lastChildCookie, childCookie, cookie)
		}
		if previous, reused := seenChildren[child]; reused {
			addressReuse++
			if childCookie <= previous.cookie || childLocator == previous.locator {
				t.Fatalf("child %d reused physical address without new identity: physical=%#x old=%d/%#x new=%d/%#x",
					iteration, child, previous.cookie, previous.locator, childCookie, childLocator)
			}
		}
		seenChildren[child] = struct{ cookie, locator uint64 }{childCookie, childLocator}
		lastChildCookie = childCookie
		account, err := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0))
		if err != nil || len(account) < 12 || binary.LittleEndian.Uint32(account[4:8]) != 2 ||
			binary.LittleEndian.Uint32(account[8:12]) != 0 {
			t.Fatalf("child %d did not hold exactly two healthy TASK credits: raw=%x err=%v", iteration, account, err)
		}
		// waitpid reaps the PID, but task_free may follow an RCU grace period.
		// Scanning a still-LIVE charge cannot recover it and must not be
		// mistaken for a reaper failure.
		deathDeadline := time.Now().Add(20 * time.Second)
		for {
			meta, metaErr := collection.Maps["se_opaque_meta"].LookupBytes(uint32(1))
			if metaErr != nil || len(meta) < 8 {
				t.Fatalf("child %d metadata after waitpid: raw=%x err=%v", iteration, meta, metaErr)
			}
			phase := binary.LittleEndian.Uint32(meta[4:8])
			if phase == 2 { // exact task_free, not a failed/aborted birth
				break
			}
			if phase != 1 && phase != 3 && phase != 4 {
				t.Fatalf("child %d did not reach source-owned DEAD: phase=%d meta=%x", iteration, phase, meta)
			}
			if time.Now().After(deathDeadline) {
				t.Fatalf("child %d task_free did not complete within 20s: meta=%x", iteration, meta)
			}
			time.Sleep(20 * time.Millisecond)
		}
		if receiptMap := collection.Maps["opaque_birth_receipts"]; receiptMap != nil {
			var key uint64
			var receipt [88]byte
			entries := receiptMap.Iterate()
			if entries.Next(&key, &receipt) || entries.Err() != nil {
				t.Fatalf("child %d physical death retained birth receipt: key=%#x receipt=%x err=%v",
					iteration, key, receipt, entries.Err())
			}
		}
		returned := false
		for attempt := 0; attempt < 192; attempt++ {
			if runRecoveredReaperStep(t, collection, topologyInput, topologyOutput, nextReapStep) == 1 {
				returned = true
				nextReapStep++
				break
			}
			nextReapStep++
		}
		if !returned {
			meta, _ := collection.Maps["se_opaque_meta"].LookupBytes(uint32(1))
			charge, _ := collection.Maps["se_opaque_charges"].LookupBytes(uint32(1))
			account, _ := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0))
			workMeta, _ := collection.Maps["se_opaque_work_meta"].LookupBytes(uint32(0))
			archive, _ := collection.Maps["se_opaque_archive"].LookupBytes(uint32(1))
			var currentLocator uint64
			keyErr := collection.Maps["se_opaque_keys"].Lookup(child, &currentLocator)
			var advance []byte
			if observation := collection.Maps["se_ow_advance_observation"]; observation != nil {
				advance, _ = observation.LookupBytes(uint32(0))
			}
			t.Fatalf("child %d credit not returned after bounded recovered-admin scans: physical=%#x expected_locator=%#x current_locator=%#x key_err=%v archive=%x meta=%x charge=%x account=%x workMeta=%x advance=%x", iteration, child, childLocator, currentLocator, keyErr, archive, meta, charge, account, workMeta, advance)
		}
		if err := collection.Maps["se_opaque_keys"].Lookup(child, &childLocator); !errors.Is(err, ebpf.ErrKeyNotExist) {
			t.Fatalf("child %d key retained after refund: locator=%#x err=%v", iteration, childLocator, err)
		}
		account, err = collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0))
		if err != nil || len(account) < 12 || binary.LittleEndian.Uint32(account[4:8]) != 1 ||
			binary.LittleEndian.Uint32(account[8:12]) != 0 {
			t.Fatalf("child %d failed to restore one healthy parent TASK credit: raw=%x err=%v", iteration, account, err)
		}
		workAccount, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
		if err != nil || len(workAccount) < 12 || binary.LittleEndian.Uint32(workAccount[4:8]) != 0 ||
			binary.LittleEndian.Uint32(workAccount[8:12]) != 0 {
			t.Fatalf("child %d left WORK credit or fault: raw=%x err=%v", iteration, workAccount, err)
		}
		if (iteration+1)%512 == 0 {
			t.Logf("recovered child churn: births=%d TASK-cookie=%d address-reuse=%d scan-epochs=%d",
				iteration+1, childCookie, addressReuse, nextReapStep-1)
		}
	}
	if churnCount == 4097 && addressReuse == 0 {
		t.Fatal("4097-birth run did not exercise physical address reuse")
	}
	if churnCount > 0 {
		t.Logf("recovered child churn complete: births=%d TASK-cookie=%d address-reuse=%d scan-epochs=%d",
			churnCount, lastChildCookie, addressReuse, nextReapStep-1)
	}
	if err := pins.Check(ctx); err != nil {
		t.Fatalf("retained physical binding pins changed before root retirement: %v", err)
	}
	if _, err := input.Write([]byte{'X'}); err != nil {
		t.Fatal(err)
	}
	if err := target.Wait(); err != nil {
		t.Fatalf("target exit: %v stderr=%q", err, targetErr.String())
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		meta, err := collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
		if err != nil || len(meta) < 8 {
			t.Fatalf("initial TASK metadata after exit: raw=%x err=%v", meta, err)
		}
		if binary.LittleEndian.Uint32(meta[4:8]) == 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("task_free did not publish DEAD: raw=%x", meta)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := collection.Maps["opaque_recovered_initial_physical"].Lookup(uint32(0), &witnessed); err != nil || witnessed != 1 {
		t.Fatalf("task_free did not tombstone physical capture: witness=%#x err=%v", witnessed, err)
	}
	if reaperTransport {
		if topologyMode == "live-reap" {
			if _, err := topologyInput.Write([]byte{'D'}); err != nil {
				t.Fatalf("release physical admin to reap: %v", err)
			}
		}
		returned := false
		for attempt := 0; attempt < 192; attempt++ {
			step := nextReapStep
			nextReapStep++
			if runRecoveredReaperStep(t, collection, topologyInput, topologyOutput, step) == 1 {
				returned = true
				t.Logf("physical recovered admin returned root TASK credit at scan epoch %d", step)
				break
			}
		}
		if !returned {
			meta, _ := collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
			charge, _ := collection.Maps["se_opaque_charges"].LookupBytes(uint32(0))
			account, _ := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0))
			t.Fatalf("recovered-admin bounded scans did not return root TASK credit: meta=%x charge=%x account=%x", meta, charge, account)
		}
		if _, err := topologyInput.Write([]byte{'X'}); err != nil {
			t.Fatalf("stop physical reaper: %v", err)
		}
		line, err := topologyOutput.ReadString('\n')
		result = append(result, line...)
		if err != nil || !strings.Contains(line, "topology PASS mode="+topologyMode) {
			t.Fatalf("physical admin reaper topology: %q %v stderr=%q", line, err, topologyErr.String())
		}
		if err := live.Wait(); err != nil {
			t.Fatalf("physical admin reaper process: %v stderr=%q", err, topologyErr.String())
		}
	} else {
		// The TC reaper remains a disposable transport, not product authority.
		reapRequest := struct {
			Cookie        uint64
			Slot, Enabled uint32
		}{cookie, 0, 1}
		if err := collection.Maps["opaque_real_live_task_reap_request"].Update(
			uint32(0), reapRequest, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		returned := false
		for i := 0; i < 20; i++ {
			code, _, err := collection.Programs["opaque_real_live_reap_task"].Test(make([]byte, 64))
			if err != nil || code == 4 || code > 4 {
				t.Fatalf("initial TASK reap visit %d: code=%d err=%v", i, code, err)
			}
			if code == 2 {
				returned = true
				break
			}
		}
		if !returned {
			t.Fatal("initial TASK credit was not returned")
		}
	}
	if err := collection.Maps["se_opaque_keys"].Lookup(physical, &locator); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("initial TASK key retained after refund: locator=%#x err=%v", locator, err)
	}
	account, err := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0))
	if err != nil || len(account) < 16 || binary.LittleEndian.Uint32(account[4:8]) != 0 ||
		binary.LittleEndian.Uint32(account[8:12]) != 0 {
		t.Fatalf("initial TASK account not clean after refund: raw=%x err=%v", account, err)
	}
	t.Logf("recovered admin enrolled and reaped one qualified opaque TASK; %s", strings.TrimSpace(string(result)))
}
