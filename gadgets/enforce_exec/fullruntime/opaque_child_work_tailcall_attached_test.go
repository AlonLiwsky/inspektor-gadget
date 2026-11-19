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

// This opt-in diagnostic requires an isolated cgroup. It seeds and
// synthetically qualifies a parent before switching from seed to handoff.
// The result cannot qualify product eligibility or policy enforcement.
func TestOpaqueChildWorkTailcallAttached(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_CHILD_WORK_TAILCALL_OBJECT")
	cgroup := os.Getenv("IG_OPAQUE_CHILD_WORK_TAILCALL_CGROUP")
	if object == "" || cgroup == "" {
		t.Skip("set child-WORK object and disposable cgroup2 path")
	}
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(cgroup), "ig15-g005-childwork-") {
		t.Fatal("root and dedicated ig15-g005-childwork-* cgroup required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(cgroup, &stat); err != nil || stat.Ino == 0 {
		t.Fatalf("isolated cgroup stat: %v", err)
	}
	procs, err := os.ReadFile(filepath.Join(cgroup, "cgroup.procs"))
	if err != nil || bytes.Contains(append([]byte{'\n'}, procs...),
		[]byte("\n"+strconv.Itoa(os.Getpid())+"\n")) {
		t.Fatalf("controller must be outside isolated cgroup: %v", err)
	}
	churn := 0
	if raw := os.Getenv("IG_OPAQUE_CHILD_WORK_TAILCALL_CHURN"); raw != "" {
		churn, err = strconv.Atoi(raw)
		if err != nil || churn < 2 || churn > 10001 {
			t.Fatalf("invalid charged handoff churn count %q", raw)
		}
	}
	exhaust := os.Getenv("IG_OPAQUE_CHILD_WORK_TAILCALL_EXHAUST") == "1"
	reuse := os.Getenv("IG_OPAQUE_CHILD_WORK_TAILCALL_REUSE") == "1"
	if (exhaust && churn != 0) || (reuse && (exhaust || churn != 0)) {
		t.Fatal("churn, exhaustion and key-reuse diagnostics are mutually exclusive")
	}
	cases := []struct {
		name string
		mode int
	}{
		{"populated-target", 0},
		{"missing-target", 1},
		{"route-lost", 2},
		{"abort-after-publish", 3},
	}
	if churn != 0 {
		cases = []struct {
			name string
			mode int
		}{{"charged-churn", 4}}
	} else if exhaust {
		cases = []struct {
			name string
			mode int
		}{{"charged-exhaustion", 5}}
	} else if reuse {
		cases = []struct {
			name string
			mode int
		}{{"charged-key-reuse", 6}}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runOpaqueChildWorkTailcallAttached(t, object, cgroup, stat.Ino, tc.mode, churn)
		})
	}
}

func runOpaqueChildWorkTailcallAttached(t *testing.T, object, cgroup string, cgroupID uint64, mode, churn int) {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	const seed = "opaque_lifecycle_task_alloc"
	const qualify = "opaque_lifecycle_child_work_qualify_probe"
	const source = "opaque_lifecycle_child_work_handoff_probe"
	const target = "opaque_lifecycle_child_work_target_probe"
	const free = "opaque_lifecycle_task_free"
	const workReap = "opaque_lifecycle_work_reap"
	const taskReap = "opaque_lifecycle_reap"
	selected := map[string]*ebpf.ProgramSpec{}
	for _, name := range []string{seed, qualify, source, target, free, workReap, taskReap} {
		if spec.Programs[name] == nil {
			t.Fatalf("missing diagnostic %s", name)
		}
		selected[name] = spec.Programs[name]
	}
	spec.Programs = selected
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("charged handoff verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	gate := collection.Maps["opaque_lifecycle_gate"]
	targets := collection.Maps["opaque_lifecycle_child_work_targets"]
	counts := collection.Maps["opaque_lifecycle_child_work_counts"]
	fault := collection.Maps["opaque_lifecycle_child_work_fault"]
	if gate == nil || targets == nil || counts == nil || counts.ValueSize() != 32 ||
		fault == nil || fault.ValueSize() != 4 ||
		targets.Type() != ebpf.ProgramArray || targets.MaxEntries() != 1 {
		t.Fatal("missing diagnostic gate, target, or counters")
	}
	gateValue := struct {
		CgroupID, Scope      uint64
		Incarnation, Enabled uint32
	}{cgroupID, 10, 1, 1}
	if err := gate.Update(uint32(0), gateValue, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if mode != 1 {
		if err := targets.Update(uint32(0), collection.Programs[target], ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	if mode == 2 || mode == 3 {
		if err := fault.Update(uint32(0), uint32(mode-1), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []*ebpf.Map{
		gate, targets, fault, collection.Maps["writer_probe_gate"],
		collection.Maps["se_opaque_payload_zero"], collection.Maps["se_opaque_work_zero"],
	} {
		if m == nil {
			t.Fatal("missing frozen diagnostic prerequisite")
		}
		if err := m.Freeze(); err != nil {
			t.Fatal(err)
		}
	}
	qualifyLink, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs[qualify]})
	if err != nil {
		t.Fatal(err)
	}
	defer qualifyLink.Close()
	freeLink, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs[free]})
	if err != nil {
		t.Fatal(err)
	}
	defer freeLink.Close()
	seedLink, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs[seed]})
	if err != nil {
		t.Fatal(err)
	}
	defer seedLink.Close()

	timeout := 15 * time.Second
	if churn != 0 || mode == 5 || mode == 6 {
		timeout = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// Launcher enters the cgroup, forks a tracked parent, and waits.
	// READY is emitted only after the tracked parent's exec/qualification.
	parentScript := "echo READY; read -r go; /bin/true; rc=$?; echo STATUS:$rc; exit \"$rc\""
	parentHelper := ""
	if churn != 0 {
		parentScript = fmt.Sprintf("echo READY; for ((i=0;i<%d;i++)); do read -r go || exit 98; /bin/true || exit 99; echo STEP:$i; done; read -r done || exit 98; exit 0", churn)
	} else if mode == 5 || mode == 6 {
		parentHelper = os.Getenv("IG_OPAQUE_CHILD_WORK_TAILCALL_PARENT_HELPER")
		if !filepath.IsAbs(parentHelper) {
			t.Fatal("exhaustion/key-reuse diagnostic requires an absolute parent-helper path")
		}
		parentScript = "echo READY; exec \"$1\""
		if mode == 6 {
			parentScript += " immediate"
		}
	}
	cmd := exec.CommandContext(ctx, "/bin/bash", "-c",
		"echo $$ > \"$1/cgroup.procs\" || exit 97; /bin/bash -c \"$2\" ig15-child-work-parent \"$3\"; rc=$?; echo LAUNCH_STATUS:$rc; exit \"$rc\"",
		"ig15-child-work-launcher", cgroup, parentScript, parentHelper)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	// Context cancellation must also reap the launcher child, which inherits
	// stdout and would otherwise keep ReadString blocked after launcher death.
	stopKill := context.AfterFunc(ctx, func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	})
	defer stopKill()
	defer func() {
		if cmd.ProcessState == nil {
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			_ = cmd.Wait()
		}
	}()
	reader := bufio.NewReader(stdout)
	ready, err := reader.ReadString('\n')
	if err != nil || ready != "READY\n" {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		t.Fatalf("tracked parent not ready: line=%q err=%v stderr=%q", ready, err, stderr.String())
	}
	if err := seedLink.Close(); err != nil {
		t.Fatal(err)
	}
	payloads := collection.Maps["se_opaque_payload"]
	qualified := 0
	var occupied []string
	for slot := uint32(0); slot < payloads.MaxEntries(); slot++ {
		value, err := payloads.LookupBytes(slot)
		if err != nil || len(value) != 1280 {
			t.Fatalf("TASK payload %d: len=%d err=%v", slot, len(value), err)
		}
		if binary.LittleEndian.Uint32(value[4:8]) == 5 &&
			binary.LittleEndian.Uint64(value[16:24]) == 10 &&
			binary.LittleEndian.Uint64(value[48:56]) != 0 {
			qualified++
		}
		if binary.LittleEndian.Uint64(value[8:16]) != 0 {
			occupied = append(occupied, strconv.FormatUint(uint64(slot), 10)+
				":"+strconv.FormatUint(uint64(binary.LittleEndian.Uint32(value[4:8])), 10)+
				":"+strconv.FormatUint(binary.LittleEndian.Uint64(value[48:56]), 10))
		}
	}
	if qualified != 1 {
		births, _ := collection.Maps["opaque_lifecycle_counters"].LookupBytes(uint32(0))
		route, _ := collection.Maps["writer_probe_route"].LookupBytes(uint32(0))
		t.Fatalf("expected one synthetically qualified parent, got %d occupied=%v births=%x route=%x stderr=%q",
			qualified, occupied, births, route, stderr.String())
	}
	sourceLink, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs[source]})
	if err != nil {
		t.Fatal(err)
	}
	defer sourceLink.Close()
	if churn != 0 {
		runOpaqueChildWorkChurn(t, collection, counts, cmd, stdin, reader,
			ctx, stopKill, &stderr, churn)
		return
	}
	if mode == 5 {
		runOpaqueChildWorkExhaustion(t, collection, counts, cmd, stdin,
			reader, ctx, stopKill, &stderr)
		return
	}
	if mode == 6 {
		runOpaqueChildWorkReuse(t, collection, counts, cmd, stdin,
			reader, ctx, stopKill, &stderr)
		return
	}
	if _, err := io.WriteString(stdin, "GO\n"); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	output, readErr := io.ReadAll(reader)
	waitErr := cmd.Wait()
	stopKill()
	if readErr != nil || ctx.Err() != nil ||
		(mode == 0 && waitErr != nil) || (mode != 0 && waitErr == nil) {
		t.Fatalf("charged child result: mode=%d read=%v wait=%v context=%v output=%q stderr=%q",
			mode, readErr, waitErr, ctx.Err(), output, stderr.String())
	}
	raw, err := counts.LookupBytes(uint32(0))
	if err != nil || len(raw) != 32 {
		t.Fatalf("handoff counters: len=%d err=%v", len(raw), err)
	}
	sourceCount := binary.LittleEndian.Uint64(raw[0:8])
	targetCount := binary.LittleEndian.Uint64(raw[8:16])
	acceptedCount := binary.LittleEndian.Uint64(raw[16:24])
	fallbackCount := binary.LittleEndian.Uint64(raw[24:32])
	if sourceCount != 1 || (mode == 0 && (targetCount != 1 || acceptedCount != 1 || fallbackCount != 0)) ||
		(mode == 1 && (targetCount != 0 || acceptedCount != 0 || fallbackCount != 1)) ||
		((mode == 2 || mode == 3) && (targetCount != 1 || acceptedCount != 0 || fallbackCount != 0)) {
		t.Fatalf("charged handoff did not reach expected edge: source=%d target=%d accepted=%d fallback=%d output=%q stderr=%q",
			sourceCount, targetCount, acceptedCount, fallbackCount, output, stderr.String())
	}
	t.Logf("charged diagnostic handoff: source=%d target=%d accepted=%d fallback=%d",
		sourceCount, targetCount, acceptedCount, fallbackCount)
	wantTasks := 2
	if mode == 1 || mode == 2 {
		wantTasks = 1
	}
	wantDeaths := 1
	if mode == 0 {
		wantDeaths = 2
	}
	reapOpaqueChildWorkDiagnostic(t, collection, wantDeaths, wantTasks, 0, 1)
	if mode == 2 {
		route, err := collection.Maps["writer_probe_route"].LookupBytes(uint32(0))
		if err != nil || len(route) != 88 ||
			binary.LittleEndian.Uint32(route[60:64]) != 3 { // WITHDRAWN
			t.Fatalf("route loss was not applied: route=%x err=%v", route, err)
		}
	}
}

func runOpaqueChildWorkChurn(t *testing.T, collection *ebpf.Collection, counts *ebpf.Map,
	cmd *exec.Cmd, stdin io.WriteCloser, reader *bufio.Reader, ctx context.Context,
	stopKill func() bool, stderr *bytes.Buffer, births int,
) {
	t.Helper()
	for i := 0; i < births; i++ {
		if _, err := io.WriteString(stdin, "GO\n"); err != nil {
			t.Fatalf("charged churn command %d: %v", i, err)
		}
		line, err := reader.ReadString('\n')
		if err != nil || line != fmt.Sprintf("STEP:%d\n", i) {
			t.Fatalf("charged churn step %d: line=%q err=%v stderr=%q", i, line, err, stderr.String())
		}
		raw, err := counts.LookupBytes(uint32(0))
		if err != nil || len(raw) != 32 ||
			binary.LittleEndian.Uint64(raw[0:8]) != uint64(i+1) ||
			binary.LittleEndian.Uint64(raw[8:16]) != uint64(i+1) ||
			binary.LittleEndian.Uint64(raw[16:24]) != uint64(i+1) ||
			binary.LittleEndian.Uint64(raw[24:32]) != 0 {
			t.Fatalf("charged churn verdict %d: counts=%x err=%v", i, raw, err)
		}
		reapOpaqueChildWorkDiagnostic(t, collection, i+1, 1, 1, 1)
	}
	if _, err := io.WriteString(stdin, "DONE\n"); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	output, readErr := io.ReadAll(reader)
	waitErr := cmd.Wait()
	stopKill()
	if readErr != nil || waitErr != nil || ctx.Err() != nil {
		t.Fatalf("charged churn parent exit: read=%v wait=%v context=%v output=%q stderr=%q",
			readErr, waitErr, ctx.Err(), output, stderr.String())
	}
	reapOpaqueChildWorkDiagnostic(t, collection, births+1, 1, 0, 0)
	t.Logf("charged TASK/WORK handoff churn: births=%d accepted=%d, all credits returned", births, births)
}

// Fill the WORK account without reaping, require a recoverable denial at its
// exact quota, then refund and prove that the same parent can admit again.
// This is a diagnostic accounting test, not an enforcement-policy test.
func runOpaqueChildWorkExhaustion(t *testing.T, collection *ebpf.Collection, counts *ebpf.Map,
	cmd *exec.Cmd, stdin io.WriteCloser, reader *bufio.Reader, ctx context.Context,
	stopKill func() bool, stderr *bytes.Buffer,
) {
	t.Helper()
	const workQuota = 32
	releaseChildren := func(want int) {
		t.Helper()
		if _, err := io.WriteString(stdin, "REAP\n"); err != nil {
			t.Fatal(err)
		}
		line, err := reader.ReadString('\n')
		if err != nil || line != fmt.Sprintf("REAPED:%d\n", want) {
			t.Fatalf("charged exhaustion child release: want=%d line=%q err=%v stderr=%q",
				want, line, err, stderr.String())
		}
	}
	for i := 0; i < workQuota+2; i++ {
		if _, err := io.WriteString(stdin, "GO\n"); err != nil {
			t.Fatalf("charged exhaustion command %d: %v", i, err)
		}
		line, err := reader.ReadString('\n')
		var step, code, errnoValue int
		parsed, parseErr := fmt.Sscanf(line, "STEP:%d:%d:%d\n", &step, &code, &errnoValue)
		if err != nil || parseErr != nil || parsed != 3 || step != i {
			t.Fatalf("charged exhaustion step %d: line=%q err=%v stderr=%q", i, line, err, stderr.String())
		}
		if (i == workQuota && (code != 1 || errnoValue != int(unix.EPERM))) ||
			(i != workQuota && (code != 0 || errnoValue != 0)) {
			work, workErr := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
			task, taskErr := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0))
			route, routeErr := collection.Maps["writer_probe_route"].LookupBytes(uint32(0))
			verdicts, countErr := counts.LookupBytes(uint32(0))
			lifecycle := opaqueLifecycleCounters(t, collection)
			childMeta, childMetaErr := collection.Maps["se_opaque_meta"].LookupBytes(uint32(i + 1))
			childCharge, childChargeErr := collection.Maps["se_opaque_charges"].LookupBytes(uint32(i + 1))
			workMeta, workMetaErr := collection.Maps["se_opaque_work_meta"].LookupBytes(uint32(i))
			workCharge, workChargeErr := collection.Maps["se_opaque_work_charges"].LookupBytes(uint32(i))
			parentMeta, parentMetaErr := collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
			archive, archiveErr := collection.Maps["se_opaque_archive"].LookupBytes(uint32(i + 1))
			keyValue := uint64(0)
			if len(archive) == 8 {
				keyValue = binary.LittleEndian.Uint64(archive)
			}
			locator, locatorErr := collection.Maps["se_opaque_keys"].LookupBytes(keyValue)
			archives := make([]string, 0, i+2)
			for slot := 0; slot <= i+1; slot++ {
				value, lookupErr := collection.Maps["se_opaque_archive"].LookupBytes(uint32(slot))
				archives = append(archives, fmt.Sprintf("%d:%x:%v", slot, value, lookupErr))
			}
			t.Fatalf("charged exhaustion step %d: code=%d errno=%d want EPERM denial=%t stderr=%q WORK=%x TASK=%x route=%x verdicts=%x lifecycle=%x childMeta=%x childCharge=%x workMeta=%x workCharge=%x parentMeta=%x archive=%x locator=%x archives=%v map_errors=%v/%v/%v/%v/%v/%v/%v/%v/%v/%v/%v",
				i, code, errnoValue, i == workQuota, stderr.String(), work, task, route,
				verdicts, lifecycle, childMeta, childCharge, workMeta, workCharge, parentMeta,
				archive, locator, archives,
				workErr, taskErr, routeErr, countErr, childMetaErr, childChargeErr,
				workMetaErr, workChargeErr, parentMetaErr, archiveErr, locatorErr)
		}
		wantAccepted := uint64(i + 1)
		if i >= workQuota {
			wantAccepted = uint64(i)
		}
		raw, err := counts.LookupBytes(uint32(0))
		if err != nil || len(raw) != 32 ||
			binary.LittleEndian.Uint64(raw[0:8]) != wantAccepted ||
			binary.LittleEndian.Uint64(raw[8:16]) != wantAccepted ||
			binary.LittleEndian.Uint64(raw[16:24]) != wantAccepted ||
			binary.LittleEndian.Uint64(raw[24:32]) != 0 {
			t.Fatalf("charged exhaustion verdict %d: counts=%x err=%v", i, raw, err)
		}
		if i == workQuota-1 {
			work, workErr := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
			task, taskErr := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0))
			if workErr != nil || taskErr != nil || len(work) != 40 || len(task) != 40 ||
				binary.LittleEndian.Uint32(work[4:8]) != workQuota ||
				binary.LittleEndian.Uint32(work[8:12]) != 0 ||
				binary.LittleEndian.Uint64(work[32:40]) != (uint64(1)<<workQuota)-1 ||
				binary.LittleEndian.Uint32(task[4:8]) != workQuota+1 ||
				binary.LittleEndian.Uint32(task[8:12]) != 0 {
				t.Fatalf("charged exhaustion quota not reached: WORK=%x err=%v TASK=%x err=%v",
					work, workErr, task, taskErr)
			}
		}
		if i == workQuota {
			// A failed reservation must not fault the account or leak a claim.
			work, workErr := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
			task, taskErr := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0))
			route, routeErr := collection.Maps["writer_probe_route"].LookupBytes(uint32(0))
			if workErr != nil || taskErr != nil || routeErr != nil ||
				len(work) != 40 || len(task) != 40 || len(route) != 88 ||
				binary.LittleEndian.Uint32(work[4:8]) != workQuota ||
				binary.LittleEndian.Uint32(work[8:12]) != 0 ||
				binary.LittleEndian.Uint32(task[4:8]) != workQuota+1 ||
				binary.LittleEndian.Uint32(task[8:12]) != 0 ||
				binary.LittleEndian.Uint32(route[64:68]) != 0 {
				t.Fatalf("failed reservation changed account/claim: WORK=%x TASK=%x route=%x errs=%v/%v/%v",
					work, task, route, workErr, taskErr, routeErr)
			}
			releaseChildren(workQuota)
			reapOpaqueChildWorkDiagnostic(t, collection, workQuota, workQuota, 1, workQuota)
		}
		if i == workQuota+1 {
			releaseChildren(1)
			reapOpaqueChildWorkDiagnostic(t, collection, workQuota+1, 1, 1, 1)
		}
	}
	if _, err := io.WriteString(stdin, "DONE\n"); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	output, readErr := io.ReadAll(reader)
	waitErr := cmd.Wait()
	stopKill()
	if readErr != nil || waitErr != nil || ctx.Err() != nil {
		t.Fatalf("charged exhaustion parent exit: read=%v wait=%v context=%v output=%q stderr=%q",
			readErr, waitErr, ctx.Err(), output, stderr.String())
	}
	reapOpaqueChildWorkDiagnostic(t, collection, workQuota+2, 1, 0, 0)
	t.Log("charged WORK account exhaustion denied without fault; exact refund restored admission")
}

// Ordinary short-lived children can reuse a physical task address before the
// old charged directory is reaped. The replacement path must transfer that
// exact old DEAD key to the new charged constructor, never accept by address.
func runOpaqueChildWorkReuse(t *testing.T, collection *ebpf.Collection, counts *ebpf.Map,
	cmd *exec.Cmd, stdin io.WriteCloser, reader *bufio.Reader, ctx context.Context,
	stopKill func() bool, stderr *bytes.Buffer,
) {
	t.Helper()
	const births = 32
	for i := 0; i < births; i++ {
		if _, err := io.WriteString(stdin, "GO\n"); err != nil {
			t.Fatalf("charged key-reuse command %d: %v", i, err)
		}
		line, err := reader.ReadString('\n')
		var step, code, errnoValue int
		parsed, parseErr := fmt.Sscanf(line, "STEP:%d:%d:%d\n", &step, &code, &errnoValue)
		raw, countErr := counts.LookupBytes(uint32(0))
		if err != nil || parseErr != nil || parsed != 3 || step != i ||
			code != 0 || errnoValue != 0 || countErr != nil || len(raw) != 32 ||
			binary.LittleEndian.Uint64(raw[0:8]) != uint64(i+1) ||
			binary.LittleEndian.Uint64(raw[8:16]) != uint64(i+1) ||
			binary.LittleEndian.Uint64(raw[16:24]) != uint64(i+1) ||
			binary.LittleEndian.Uint64(raw[24:32]) != 0 {
			work, _ := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
			task, _ := collection.Maps["se_opaque_accounts"].LookupBytes(uint32(0))
			t.Fatalf("charged key-reuse birth %d: line=%q read=%v parse=%v counts=%x countErr=%v WORK=%x TASK=%x stderr=%q",
				i, line, err, parseErr, raw, countErr, work, task, stderr.String())
		}
	}
	replaced := 0
	for slot := uint32(1); slot <= births; slot++ {
		meta, err := collection.Maps["se_opaque_meta"].LookupBytes(slot)
		if err != nil || len(meta) != 128 {
			t.Fatalf("charged key-reuse TASK %d metadata: len=%d err=%v", slot, len(meta), err)
		}
		if binary.LittleEndian.Uint32(meta[40:44]) == 7 { // DELETED before any reaper ran
			replaced++
		}
	}
	if os.Getenv("IG_OPAQUE_CHILD_WORK_TAILCALL_REUSE_REQUIRE") == "1" && replaced == 0 {
		t.Fatal("no same-key replacement was observed on the required kernel")
	}
	reapOpaqueChildWorkDiagnostic(t, collection, births, births, 1, births)
	if _, err := io.WriteString(stdin, "DONE\n"); err != nil {
		t.Fatal(err)
	}
	_ = stdin.Close()
	output, readErr := io.ReadAll(reader)
	waitErr := cmd.Wait()
	stopKill()
	if readErr != nil || waitErr != nil || ctx.Err() != nil {
		t.Fatalf("charged key-reuse parent exit: read=%v wait=%v context=%v output=%q stderr=%q",
			readErr, waitErr, ctx.Err(), output, stderr.String())
	}
	reapOpaqueChildWorkDiagnostic(t, collection, births+1, 1, 0, 0)
	t.Logf("charged key-reuse births=%d exact same-key replacements=%d; all credits returned",
		births, replaced)
}

// Use the fixture's exact slot/cookie reapers, WORK first. A successful
// callback that merely returned zero but stranded a credit must fail here.
func reapOpaqueChildWorkDiagnostic(t *testing.T, collection *ebpf.Collection,
	wantDeaths, wantTasks, remainTasks, wantWork int,
) {
	t.Helper()
	requestMap := collection.Maps["opaque_lifecycle_request"]
	workCharges := collection.Maps["se_opaque_work_charges"]
	taskCharges := collection.Maps["se_opaque_charges"]
	if requestMap == nil || workCharges == nil || taskCharges == nil {
		t.Fatal("missing charged-reaper maps")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		counters := opaqueLifecycleCounters(t, collection)
		if binary.LittleEndian.Uint64(counters[8:16]) >= uint64(wantDeaths) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("task_free did not observe expected tracked tasks: want=%d counters=%x",
				wantDeaths, counters)
		}
		time.Sleep(10 * time.Millisecond)
	}
	workReturned := 0
	for slot := uint32(0); slot < workCharges.MaxEntries(); slot++ {
		charge, err := workCharges.LookupBytes(slot)
		if err != nil || len(charge) < 56 {
			t.Fatalf("WORK charge %d: len=%d err=%v", slot, len(charge), err)
		}
		cookie := binary.LittleEndian.Uint64(charge[0:8])
		if cookie == 0 {
			continue
		}
		meta, err := collection.Maps["se_opaque_work_meta"].LookupBytes(slot)
		if err != nil || len(meta) != 80 ||
			binary.LittleEndian.Uint32(meta[4:8]) != 4 { // DONE
			t.Fatalf("WORK %d was not source-closed: meta=%x err=%v", slot, meta, err)
		}
		request := struct {
			Cookie         uint64
			Slot, Reserved uint32
		}{cookie, slot, 0}
		if err := requestMap.Update(uint32(0), request, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		for step := 0; step < 12; step++ {
			if _, err := collection.Programs["opaque_lifecycle_work_reap"].Run(
				&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
				t.Fatal(err)
			}
			charge, err = workCharges.LookupBytes(slot)
			if err != nil || len(charge) < 56 {
				t.Fatalf("WORK recheck %d: len=%d err=%v", slot, len(charge), err)
			}
			if binary.LittleEndian.Uint64(charge[0:8]) == 0 {
				workReturned++
				break
			}
		}
		if binary.LittleEndian.Uint64(charge[0:8]) != 0 {
			t.Fatalf("WORK %d credit stranded: charge=%x", slot, charge)
		}
	}
	if workReturned != wantWork {
		t.Fatalf("expected %d WORK credits returned, got %d", wantWork, workReturned)
	}
	taskReturned := 0
	liveTasks := 0
	for slot := uint32(0); slot < taskCharges.MaxEntries(); slot++ {
		charge, err := taskCharges.LookupBytes(slot)
		if err != nil || len(charge) < 40 {
			t.Fatalf("TASK charge %d: len=%d err=%v", slot, len(charge), err)
		}
		cookie := binary.LittleEndian.Uint64(charge[0:8])
		if cookie == 0 {
			continue
		}
		meta, err := collection.Maps["se_opaque_meta"].LookupBytes(slot)
		if err != nil || len(meta) != 128 {
			t.Fatalf("TASK metadata %d: len=%d err=%v", slot, len(meta), err)
		}
		if binary.LittleEndian.Uint32(meta[4:8]) == 1 { // LIVE parent
			liveTasks++
			continue
		}
		request := struct {
			Cookie         uint64
			Slot, Reserved uint32
		}{cookie, slot, 0}
		if err := requestMap.Update(uint32(0), request, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		for step := 0; step < 16; step++ {
			if _, err := collection.Programs["opaque_lifecycle_reap"].Run(
				&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
				t.Fatal(err)
			}
			charge, err = taskCharges.LookupBytes(slot)
			if err != nil || len(charge) < 40 {
				t.Fatalf("TASK recheck %d: len=%d err=%v", slot, len(charge), err)
			}
			if binary.LittleEndian.Uint64(charge[0:8]) == 0 {
				taskReturned++
				break
			}
		}
		if binary.LittleEndian.Uint64(charge[0:8]) != 0 {
			meta, _ := collection.Maps["se_opaque_meta"].LookupBytes(slot)
			t.Fatalf("TASK %d credit stranded: charge=%x meta=%x", slot, charge, meta)
		}
	}
	if taskReturned != wantTasks {
		t.Fatalf("TASK returns=%d want=%d", taskReturned, wantTasks)
	}
	if liveTasks != remainTasks {
		t.Fatalf("live TASKs=%d want=%d", liveTasks, remainTasks)
	}
	for _, name := range []string{"se_opaque_accounts", "se_opaque_work_accounts"} {
		account, err := collection.Maps[name].LookupBytes(uint32(0))
		wantUsed := uint32(0)
		if name == "se_opaque_accounts" {
			wantUsed = uint32(remainTasks)
		}
		if err != nil || len(account) < 40 ||
			binary.LittleEndian.Uint32(account[4:8]) != wantUsed ||
			binary.LittleEndian.Uint32(account[8:12]) != 0 ||
			(binary.LittleEndian.Uint64(account[32:40]) == 0) != (wantUsed == 0) {
			t.Fatalf("%s not fully refunded: %x err=%v", name, account, err)
		}
	}
	route, err := collection.Maps["writer_probe_route"].LookupBytes(uint32(0))
	if err != nil || len(route) != 88 ||
		binary.LittleEndian.Uint32(route[64:68]) != 0 {
		t.Fatalf("route retains early claim: %x err=%v", route, err)
	}
	if remainTasks == 0 || wantDeaths == 1 || wantDeaths%512 == 0 {
		t.Logf("charged diagnostic credits returned: WORK=%d TASK=%d live=%d route_claims=0",
			workReturned, taskReturned, liveTasks)
	}
}
