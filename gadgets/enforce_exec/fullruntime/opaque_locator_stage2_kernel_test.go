// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// An opt-in isolated experiment. The two objects use different phase-specific
// evaluator resolvers and share *all* maps. The program is always denying;
// this test proves lifecycle transfer only, never a production verdict.
func TestOpaqueStage2AttachedTailcallAndFallback(t *testing.T) {
	sourceObject := os.Getenv("IG_OPAQUE_STAGE2_SOURCE_OBJECT")
	evaluatorObject := os.Getenv("IG_OPAQUE_STAGE2_EVAL_OBJECT")
	cgroup := os.Getenv("IG_OPAQUE_STAGE2_CGROUP")
	if sourceObject == "" || evaluatorObject == "" || cgroup == "" {
		t.Skip("set both stage-2 objects and an isolated cgroup2 path")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(cgroup, &stat); err != nil || stat.Ino == 0 {
		t.Fatalf("isolated cgroup: %v", err)
	}
	procs, err := os.ReadFile(cgroup + "/cgroup.procs")
	if err != nil || strings.Contains("\n"+string(procs), "\n"+strconv.Itoa(os.Getpid())+"\n") {
		t.Fatalf("controller must stay outside isolated cgroup: %v", err)
	}
	births := 1
	if raw := os.Getenv("IG_OPAQUE_STAGE2_BIRTHS"); raw != "" {
		births, err = strconv.Atoi(raw)
		if err != nil || births < 1 || births > 5000 {
			t.Fatalf("invalid isolated birth count %q", raw)
		}
	}
	if os.Getenv("IG_OPAQUE_STAGE2_COMMIT_FAULT_DIAG") == "1" {
		t.Run("failed-commit-rollback", func(t *testing.T) {
			testOpaqueStage2AttachedCase(t, sourceObject, evaluatorObject, cgroup, stat.Ino, false, births)
		})
		return
	}
	for _, fallback := range []bool{false, true} {
		name := "target"
		if fallback {
			name = "missing-target-fallback"
		}
		t.Run(name, func(t *testing.T) {
			testOpaqueStage2AttachedCase(t, sourceObject, evaluatorObject, cgroup, stat.Ino, fallback, births)
		})
	}
}

func stage2LoadOnly(t *testing.T, object string, names ...string) *ebpf.CollectionSpec {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	selected := make(map[string]*ebpf.ProgramSpec, len(names))
	for _, name := range names {
		program := spec.Programs[name]
		if program == nil {
			t.Fatalf("%s lacks %s", object, name)
		}
		selected[name] = program
	}
	spec.Programs = selected
	return spec
}

func stage2LoadCollection(t *testing.T, spec *ebpf.CollectionSpec, replacements map[string]*ebpf.Map) *ebpf.Collection {
	t.Helper()
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs:        ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
		MapReplacements: replacements,
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("stage-2 verifier: %+v", verifier)
		}
		t.Fatal(err)
	}
	t.Cleanup(collection.Close)
	return collection
}

func stage2PopulatePolicy(t *testing.T, maps map[string]*ebpf.Map, scope uint64, productObjectShape bool) {
	t.Helper()
	blobs, object, snapshot := maps["opaque_lifecycle_policy_blobs"],
		maps["opaque_lifecycle_policy_object"], maps["opaque_lifecycle_policy_snapshot"]
	if blobs == nil || object == nil || snapshot == nil ||
		blobs.MaxEntries() != 11 || blobs.ValueSize() != 288 ||
		object.ValueSize() != 80 || snapshot.ValueSize() != 784 {
		t.Fatal("invalid synthetic policy map geometry")
	}
	for key := uint32(0); key < 11; key++ {
		value := make([]byte, 288)
		switch key {
		case 0:
			binary.LittleEndian.PutUint32(value[8:12], 1)
			binary.LittleEndian.PutUint32(value[12:16], 9)
			binary.LittleEndian.PutUint32(value[16:20], 1)
		case 1:
			binary.LittleEndian.PutUint64(value[0:8], 1)
			binary.LittleEndian.PutUint64(value[8:16], 1)
			binary.LittleEndian.PutUint32(value[20:24], 2)
		case 9:
			binary.LittleEndian.PutUint32(value[4:8], 2)
			for _, offset := range []int{12, 16, 20} {
				binary.LittleEndian.PutUint32(value[offset:offset+4], ^uint32(0))
			}
		}
		if err := blobs.Update(key, value, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	objectValue := make([]byte, 80)
	binary.LittleEndian.PutUint64(objectValue[8:16], 1)
	binary.LittleEndian.PutUint32(objectValue[48:52], 2)
	binary.LittleEndian.PutUint32(objectValue[52:56], 11)
	binary.LittleEndian.PutUint32(objectValue[60:64], 1)
	if productObjectShape {
		if object.Flags() != unix.BPF_F_RDONLY {
			t.Fatalf("object lacks userspace write barrier: flags=%#x", object.Flags())
		}
	} else {
		if object.Flags() != 0 {
			t.Fatalf("legacy synthetic object flags=%#x", object.Flags())
		}
		if err := object.Update(uint32(0), objectValue, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	snapshotValue := make([]byte, 784)
	binary.LittleEndian.PutUint64(snapshotValue[0:8], scope)
	binary.LittleEndian.PutUint64(snapshotValue[8:16], 1)
	binary.LittleEndian.PutUint64(snapshotValue[24:32], 1)
	binary.LittleEndian.PutUint32(snapshotValue[32:36], 3)
	binary.LittleEndian.PutUint32(snapshotValue[36:40], 1)
	binary.LittleEndian.PutUint32(snapshotValue[40:44], 1)
	const ticket = 56
	binary.LittleEndian.PutUint64(snapshotValue[ticket:ticket+8], scope)
	binary.LittleEndian.PutUint64(snapshotValue[ticket+8:ticket+16], 1)
	binary.LittleEndian.PutUint64(snapshotValue[ticket+16:ticket+24], 1)
	binary.LittleEndian.PutUint32(snapshotValue[ticket+32:ticket+36], 1)
	const metadata = 376
	binary.LittleEndian.PutUint64(snapshotValue[metadata:metadata+8], 1)
	binary.LittleEndian.PutUint64(snapshotValue[metadata+64:metadata+72], 1)
	binary.LittleEndian.PutUint32(snapshotValue[metadata+144:metadata+148], 1)
	snapshotValue[metadata+148] = '/'
	if err := snapshot.Update(uint32(0), snapshotValue, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for name, m := range map[string]*ebpf.Map{"blobs": blobs, "object": object, "snapshot": snapshot} {
		if productObjectShape && name == "object" {
			continue
		}
		if err := m.Freeze(); err != nil {
			if name == "object" && os.Getenv("IG_OPAQUE_STAGE2_UNFROZEN_OBJECT_DIAG") == "1" &&
				err.Error() == "can't freeze map: operation not supported" {
				t.Log("diagnostic only: object with spinlock could not freeze on this kernel; controller owns all FDs")
				continue
			}
			t.Fatalf("freeze synthetic %s: %v", name, err)
		}
	}
}

func stage2SeedReadOnlyObject(t *testing.T, source *ebpf.Collection, cgroup string) {
	t.Helper()
	seed := source.Programs["opaque_lifecycle_seed_policy_object"]
	if seed == nil {
		t.Fatal("missing isolated BPF object seeder")
	}
	attached, err := link.AttachLSM(link.LSMOptions{Program: seed})
	if err != nil {
		t.Fatalf("attach BPF object seeder: %v", err)
	}
	child := exec.Command("/bin/bash", "-c",
		`echo $$ > "$1/cgroup.procs"; exec /bin/true`, "stage2-object-seed", cgroup)
	out, runErr := child.CombinedOutput()
	closeErr := attached.Close()
	if runErr != nil || closeErr != nil {
		t.Fatalf("BPF object seed child=%v output=%s detach=%v", runErr, out, closeErr)
	}
	object := source.Maps["opaque_lifecycle_policy_object"]
	value, err := object.LookupBytes(uint32(0))
	if err != nil || len(value) != 80 ||
		binary.LittleEndian.Uint64(value[8:16]) != 1 ||
		binary.LittleEndian.Uint32(value[48:52]) != 2 ||
		binary.LittleEndian.Uint32(value[52:56]) != 11 ||
		binary.LittleEndian.Uint32(value[60:64]) != 1 {
		t.Fatalf("BPF object seed not exact: value=%x err=%v", value, err)
	}
	writeErr := object.Update(uint32(0), make([]byte, 80), ebpf.UpdateAny)
	if writeErr == nil {
		t.Fatal("userspace unexpectedly wrote BPF_F_RDONLY object")
	}
	remaining, err := object.LookupBytes(uint32(0))
	if err != nil || !bytes.Equal(remaining, value) {
		t.Fatalf("rejected syscall write changed BPF object: before=%x after=%x err=%v", value, remaining, err)
	}
	t.Logf("BPF initialized userspace-read-only policy object; syscall write rejected: %v", writeErr)
}

func testOpaqueStage2AttachedCase(t *testing.T, sourceObject, evaluatorObject, cgroup string, cgroupID uint64, fallback bool, births int) {
	t.Helper()
	productObjectShape := os.Getenv("IG_OPAQUE_STAGE2_PRODUCT_OBJECT_TRUST_DIAG") == "1"
	sourceNames := []string{
		"opaque_lifecycle_task_alloc", "opaque_lifecycle_task_free",
		"opaque_lifecycle_exec", "opaque_lifecycle_work_reap", "opaque_lifecycle_reap",
	}
	if productObjectShape {
		sourceNames = append(sourceNames, "opaque_lifecycle_seed_policy_object")
	}
	sourceSpec := stage2LoadOnly(t, sourceObject, sourceNames...)
	source := stage2LoadCollection(t, sourceSpec, nil)
	evaluatorSpec := stage2LoadOnly(t, evaluatorObject,
		"opaque_lifecycle_suspended_eval_reader_diagnostic",
		"opaque_lifecycle_suspended_stage2_diagnostic")
	replacements := make(map[string]*ebpf.Map, len(evaluatorSpec.Maps))
	for name := range evaluatorSpec.Maps {
		m := source.Maps[name]
		if m == nil {
			t.Fatalf("source lacks shared map %s", name)
		}
		replacements[name] = m
	}
	evaluator := stage2LoadCollection(t, evaluatorSpec, replacements)
	for name, sourceMap := range replacements {
		sourceInfo, sourceErr := sourceMap.Info()
		evaluatorInfo, evaluatorErr := evaluator.Maps[name].Info()
		if sourceErr != nil || evaluatorErr != nil {
			t.Fatalf("shared map %s info: source=%v evaluator=%v", name, sourceErr, evaluatorErr)
		}
		sourceID, sourceOK := sourceInfo.ID()
		evaluatorID, evaluatorOK := evaluatorInfo.ID()
		if !sourceOK || !evaluatorOK || sourceID != evaluatorID {
			t.Fatalf("map %s was not shared: source=%d/%v evaluator=%d/%v",
				name, sourceID, sourceOK, evaluatorID, evaluatorOK)
		}
	}
	const scope = uint64(10)
	stage2PopulatePolicy(t, source.Maps, scope, productObjectShape)
	gate := struct {
		CgroupID, Scope      uint64
		Incarnation, Enabled uint32
	}{cgroupID, scope, 1, 1}
	if err := source.Maps["opaque_lifecycle_gate"].Update(uint32(0), gate, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if productObjectShape {
		stage2SeedReadOnlyObject(t, source, cgroup)
	}
	entryTargets := source.Maps["opaque_lifecycle_tail_targets"]
	stage2Targets := source.Maps["opaque_lifecycle_suspended_diag_target"]
	if entryTargets == nil || stage2Targets == nil ||
		entryTargets.Type() != ebpf.ProgramArray || stage2Targets.Type() != ebpf.ProgramArray {
		t.Fatal("missing isolated program arrays")
	}
	if err := entryTargets.Update(uint32(0), evaluator.Programs["opaque_lifecycle_suspended_eval_reader_diagnostic"], ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	stage1Info, err := evaluator.Programs["opaque_lifecycle_suspended_eval_reader_diagnostic"].Info()
	if err != nil {
		t.Fatal(err)
	}
	stage1ID, ok := stage1Info.ID()
	if !ok {
		t.Fatal("stage-1 target has no program ID")
	}
	var storedStage1 uint32
	if err := entryTargets.Lookup(uint32(0), &storedStage1); err != nil || storedStage1 != uint32(stage1ID) {
		t.Fatalf("wrong stage-1 target ID: got=%d want=%d err=%v", storedStage1, stage1ID, err)
	}
	if !fallback {
		if err := stage2Targets.Update(uint32(0), evaluator.Programs["opaque_lifecycle_suspended_stage2_diagnostic"], ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		stage2Info, err := evaluator.Programs["opaque_lifecycle_suspended_stage2_diagnostic"].Info()
		if err != nil {
			t.Fatal(err)
		}
		stage2ID, ok := stage2Info.ID()
		if !ok {
			t.Fatal("stage-2 target has no program ID")
		}
		var storedStage2 uint32
		if err := stage2Targets.Lookup(uint32(0), &storedStage2); err != nil || storedStage2 != uint32(stage2ID) {
			t.Fatalf("wrong stage-2 target ID: got=%d want=%d err=%v", storedStage2, stage2ID, err)
		}
	} else {
		var absent uint32
		if err := stage2Targets.Lookup(uint32(0), &absent); err == nil {
			t.Fatalf("missing-target case unexpectedly has target ID %d", absent)
		}
	}
	for _, name := range []string{
		"opaque_lifecycle_gate", "opaque_lifecycle_tail_targets",
		"opaque_lifecycle_suspended_diag_target", "writer_probe_gate",
		"se_opaque_payload_zero", "se_opaque_work_zero",
	} {
		if err := source.Maps[name].Freeze(); err != nil {
			t.Fatalf("freeze %s: %v", name, err)
		}
	}
	for _, name := range []string{"opaque_lifecycle_task_free", "opaque_lifecycle_exec", "opaque_lifecycle_task_alloc"} {
		attached, err := link.AttachLSM(link.LSMOptions{Program: source.Programs[name]})
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		t.Cleanup(func() { _ = attached.Close() })
	}
	for birth := 1; birth <= births; birth++ {
		child := exec.Command("/bin/bash", "-c",
			`echo $$ > "$1/cgroup.procs"; /bin/true; rc=$?; exit "$rc"`,
			"stage2-fixture-child", cgroup)
		if out, err := child.CombinedOutput(); err == nil {
			t.Fatalf("diagnostic must deny exec; output=%s", out)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			counters := opaqueLifecycleCounters(t, source)
			if binary.LittleEndian.Uint64(counters[0:8]) == uint64(birth) &&
				binary.LittleEndian.Uint64(counters[8:16]) == uint64(birth) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no attached birth/death: %x", counters)
			}
			time.Sleep(10 * time.Millisecond)
		}
		counters := opaqueLifecycleCounters(t, source)
		if len(counters) < 176 {
			t.Fatalf("missing diagnostic counters: %x", counters)
		}
		stage2Count, fallbackCount := uint64(birth), uint64(0)
		if fallback {
			stage2Count, fallbackCount = 0, uint64(birth)
		}
		if os.Getenv("IG_OPAQUE_STAGE2_COMMIT_FAULT_DIAG") == "1" {
			stage2Count, fallbackCount = 0, 0
		}
		for offset, want := range map[int]uint64{
			16: 0, 48: uint64(birth), 72: uint64(birth), 80: 0, 104: uint64(birth), 112: 0,
			120: uint64(birth), 136: 0, 152: uint64(birth), 160: stage2Count, 168: fallbackCount,
		} {
			if got := binary.LittleEndian.Uint64(counters[offset : offset+8]); got != want {
				t.Fatalf("counter offset %d: got=%d want=%d all=%x", offset, got, want, counters)
			}
		}
		workCharge, err := source.Maps["se_opaque_work_charges"].LookupBytes(uint32(0))
		if err != nil || len(workCharge) < 8 {
			t.Fatalf("WORK charge: %v", err)
		}
		workCookie := binary.LittleEndian.Uint64(workCharge[0:8])
		if workCookie == 0 {
			t.Fatal("WORK charge vanished before reaping")
		}
		workMeta, err := source.Maps["se_opaque_work_meta"].LookupBytes(uint32(0))
		if err != nil || len(workMeta) != 80 ||
			binary.LittleEndian.Uint32(workMeta[4:8]) != 4 ||
			binary.LittleEndian.Uint32(workMeta[72:76]) != 0 ||
			binary.LittleEndian.Uint32(workMeta[76:80]) != 0 {
			t.Fatalf("WORK not DONE after terminal closure: meta=%x err=%v", workMeta, err)
		}
		request := struct {
			Cookie         uint64
			Slot, Reserved uint32
		}{workCookie, 0, 0}
		if err := source.Maps["opaque_lifecycle_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		for step := 0; step < 10; step++ {
			if _, err := source.Programs["opaque_lifecycle_work_reap"].Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
				t.Fatal(err)
			}
			workCharge, err = source.Maps["se_opaque_work_charges"].LookupBytes(uint32(0))
			if err != nil {
				t.Fatal(err)
			}
			if binary.LittleEndian.Uint64(workCharge[0:8]) == 0 {
				break
			}
		}
		if binary.LittleEndian.Uint64(workCharge[0:8]) != 0 {
			t.Fatalf("WORK credit did not return: %x", workCharge)
		}
		taskCharge, err := source.Maps["se_opaque_charges"].LookupBytes(uint32(0))
		if err != nil || len(taskCharge) < 8 {
			t.Fatalf("TASK charge: %v", err)
		}
		taskCookie := binary.LittleEndian.Uint64(taskCharge[0:8])
		if taskCookie == 0 {
			t.Fatal("TASK charge vanished before reaping")
		}
		request.Cookie = taskCookie
		if err := source.Maps["opaque_lifecycle_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		for step := 0; step < 12; step++ {
			if _, err := source.Programs["opaque_lifecycle_reap"].Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
				t.Fatal(err)
			}
			taskCharge, err = source.Maps["se_opaque_charges"].LookupBytes(uint32(0))
			if err != nil {
				t.Fatal(err)
			}
			if binary.LittleEndian.Uint64(taskCharge[0:8]) == 0 {
				break
			}
		}
		if binary.LittleEndian.Uint64(taskCharge[0:8]) != 0 {
			t.Fatalf("TASK credit did not return: %x", taskCharge)
		}
		for _, name := range []string{"se_opaque_work_accounts", "se_opaque_accounts"} {
			account, err := source.Maps[name].LookupBytes(uint32(0))
			if err != nil || len(account) < 40 ||
				binary.LittleEndian.Uint32(account[4:8]) != 0 ||
				binary.LittleEndian.Uint32(account[8:12]) != 0 ||
				binary.LittleEndian.Uint64(account[32:40]) != 0 {
				t.Fatalf("%s did not drain without fault: account=%x err=%v", name, account, err)
			}
		}
	}
	if os.Getenv("IG_OPAQUE_STAGE2_COMMIT_FAULT_DIAG") == "1" {
		t.Logf("attached failed-commit rollback: stage-2=0, fallback=0, WORK/TASK credits returned across %d births", births)
	} else if fallback {
		t.Logf("attached stage-2: target=0 fallback=%d, WORK/TASK credits returned", births)
	} else {
		t.Logf("attached stage-2: target=%d fallback=0, WORK/TASK credits returned", births)
	}
}
