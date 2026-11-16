// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Load-only preflight for the isolated attached-lifecycle fixture. This does
// not arm a gate, attach a hook, exercise a callback, or prove G005 churn.
func TestOpaqueLocatorLifecycleFixtureKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_LIFECYCLE_FIXTURE_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_LIFECYCLE_FIXTURE_OBJECT for load-only preflight")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required for BPF verifier load")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	programOnly := os.Getenv("IG_OPAQUE_LIFECYCLE_PROGRAM_ONLY")
	if programOnly != "" {
		program := spec.Programs[programOnly]
		if program == nil {
			t.Fatalf("missing diagnostic program %s", programOnly)
		}
		spec.Programs = map[string]*ebpf.ProgramSpec{programOnly: program}
	}
	if programOnly == "" {
		for _, name := range []string{
			"opaque_lifecycle_task_alloc", "opaque_lifecycle_task_free",
			"opaque_lifecycle_reap",
		} {
			if spec.Programs[name] == nil {
				t.Fatalf("missing lifecycle entry %s", name)
			}
		}
	}
	for _, name := range []string{"opaque_lifecycle_gate", "opaque_lifecycle_request"} {
		m := spec.Maps[name]
		if m == nil || m.Type != ebpf.Array || m.MaxEntries != 1 ||
			m.Flags != unix.BPF_F_RDONLY_PROG {
			t.Fatalf("invalid frozen-source fixture map %s", name)
		}
	}
	programOptions := ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024}
	if os.Getenv("IG_OPAQUE_LIFECYCLE_LOAD_STATS_ONLY") == "1" {
		programOptions.LogLevel = ebpf.LogLevelStats
		programOptions.LogSizeStart = 16 * 1024 * 1024
	}
	if os.Getenv("IG_OPAQUE_LIFECYCLE_LOAD_INSN_DIAGNOSTIC") == "1" {
		programOptions.LogLevel = ebpf.LogLevelInstruction | ebpf.LogLevelStats
		programOptions.LogSizeStart = 16 * 1024 * 1024
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: programOptions,
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("lifecycle fixture verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	if programOnly != "" {
		program := collection.Programs[programOnly]
		if program == nil {
			t.Fatalf("diagnostic program %s was not loaded", programOnly)
		}
		t.Logf("diagnostic program verifier stats: %s", program.VerifierLog)
		return
	}
	var gate [24]byte
	if err := collection.Maps["opaque_lifecycle_gate"].Lookup(uint32(0), &gate); err != nil || gate != ([24]byte{}) {
		t.Fatalf("lifecycle fixture must load unarmed: err=%v", err)
	}
	t.Log("opaque lifecycle fixture loaded with gate zero; no attachment")
}

// The typed fixture must contain a real exec producer, not merely an abort
// branch whose transaction is permanently empty. This is a source/object
// inventory check; the attached test below proves that it actually runs.
func TestOpaqueLocatorLifecycleExecProgramSpec(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_LIFECYCLE_FIXTURE_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_LIFECYCLE_FIXTURE_OBJECT for fixture inventory")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Programs["opaque_lifecycle_exec"] == nil {
		t.Fatal("typed opaque TASK fixture has no attached exec transaction producer")
	}
	if route := spec.Maps["writer_probe_route"]; route == nil ||
		route.Type != ebpf.Array || route.MaxEntries != 2 ||
		route.ValueSize != 88 || route.Flags != unix.BPF_F_RDONLY {
		t.Fatalf("fixture must retain its fixed original-route owner: %+v", route)
	}
	for name, size := range map[string]uint32{
		"se_opaque_payload":      1280,
		"se_opaque_work_payload": 19456,
	} {
		if m := spec.Maps[name]; m == nil || m.ValueSize != size {
			t.Fatalf("%s ABI value size must be %d", name, size)
		}
	}
}

func TestOpaqueLocatorLifecycleWorkProgramSpec(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_LIFECYCLE_FIXTURE_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_LIFECYCLE_FIXTURE_OBJECT for WORK fixture inventory")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Programs["opaque_lifecycle_work_reap"] == nil {
		t.Fatal("typed opaque WORK fixture has no WORK-first reaper")
	}
}

// This opt-in test requires an isolated disposable cgroup2 supplied by its
// supervisor, while the Go controller remains outside it. The typed variant
// has an actual exec/WORK source; the controller returns WORK before TASK.
// Synthetic metadata cannot qualify selected policy enforcement by itself.
func TestOpaqueLocatorLifecycleFixtureKernelRun(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_LIFECYCLE_FIXTURE_OBJECT")
	cgroup := os.Getenv("IG_OPAQUE_LIFECYCLE_CGROUP")
	if object == "" || cgroup == "" {
		t.Skip("set fixture object and isolated cgroup2 path")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(cgroup, &stat); err != nil || stat.Ino == 0 {
		t.Fatalf("isolated cgroup stat: %v", err)
	}
	procs, err := os.ReadFile(cgroup + "/cgroup.procs")
	if err != nil || bytes.Contains(append([]byte{'\n'}, procs...),
		[]byte("\n"+strconv.Itoa(os.Getpid())+"\n")) {
		t.Fatalf("fixture controller must remain outside isolated cgroup: %v", err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("lifecycle fixture verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	gate := struct {
		CgroupID, Scope      uint64
		Incarnation, Enabled uint32
	}{stat.Ino, 10, 1, 1}
	expectStage := os.Getenv("IG_OPAQUE_LIFECYCLE_EXPECT_STAGE") == "1"
	if blobs := collection.Maps["opaque_lifecycle_policy_blobs"]; blobs != nil {
		object := collection.Maps["opaque_lifecycle_policy_object"]
		snapshot := collection.Maps["opaque_lifecycle_policy_snapshot"]
		if object == nil || snapshot == nil ||
			object.Type() != ebpf.Array || object.MaxEntries() != 1 ||
			object.ValueSize() != 80 || object.Flags() != 0 ||
			snapshot.Type() != ebpf.Array || snapshot.MaxEntries() != 1 ||
			snapshot.ValueSize() != 784 || snapshot.Flags()&unix.BPF_F_RDONLY_PROG == 0 {
			t.Fatal("invalid synthetic policy object/snapshot maps")
		}
		wantEntries := uint32(10)
		if expectStage {
			wantEntries = 11
		}
		if blobs.Type() != ebpf.Array || blobs.MaxEntries() != wantEntries ||
			blobs.ValueSize() != 288 || blobs.Flags()&unix.BPF_F_RDONLY_PROG == 0 {
			t.Fatal("invalid synthetic policy-preparation source map")
		}
		header := make([]byte, 288)
		binary.LittleEndian.PutUint32(header[8:12], 1)  // policies
		binary.LittleEndian.PutUint32(header[12:16], 9) // rule_base
		if expectStage {
			binary.LittleEndian.PutUint32(header[16:20], 1) // one rule
		}
		policy := make([]byte, 288)
		binary.LittleEndian.PutUint64(policy[0:8], 1)   // uid
		binary.LittleEndian.PutUint64(policy[8:16], 1)  // root_role
		binary.LittleEndian.PutUint32(policy[20:24], 2) // enforce mode
		rule := make([]byte, 288)
		binary.LittleEndian.PutUint32(rule[4:8], 2) // enforce allow
		for _, offset := range []int{12, 16, 20} {
			binary.LittleEndian.PutUint32(rule[offset:offset+4], ^uint32(0))
		}
		for key := uint32(0); key < wantEntries; key++ {
			value := make([]byte, 288)
			if key == 0 {
				value = header
			} else if key == 1 {
				value = policy
			} else if expectStage && key == 9 {
				value = rule
			}
			if err := blobs.Update(key, value, ebpf.UpdateAny); err != nil {
				t.Fatalf("populate synthetic policy blob %d: %v", key, err)
			}
		}
		objectValue := make([]byte, 80)
		binary.LittleEndian.PutUint64(objectValue[8:16], 1)            // generation
		binary.LittleEndian.PutUint32(objectValue[48:52], 2)           // READY
		binary.LittleEndian.PutUint32(objectValue[52:56], wantEntries) // length
		binary.LittleEndian.PutUint32(objectValue[60:64], 1)           // held pin
		if err := object.Update(uint32(0), objectValue, ebpf.UpdateAny); err != nil {
			t.Fatalf("populate synthetic object: %v", err)
		}
		snapshotValue := make([]byte, 784)
		binary.LittleEndian.PutUint64(snapshotValue[0:8], gate.Scope)
		binary.LittleEndian.PutUint64(snapshotValue[8:16], 1)  // serial
		binary.LittleEndian.PutUint64(snapshotValue[24:32], 1) // generation
		binary.LittleEndian.PutUint32(snapshotValue[32:36], 3) // ACTIVE
		binary.LittleEndian.PutUint32(snapshotValue[36:40], 1) // count
		binary.LittleEndian.PutUint32(snapshotValue[40:44], 1) // claim
		const ticket = 56
		binary.LittleEndian.PutUint64(snapshotValue[ticket:ticket+8], gate.Scope)
		binary.LittleEndian.PutUint64(snapshotValue[ticket+8:ticket+16], 1)
		binary.LittleEndian.PutUint64(snapshotValue[ticket+16:ticket+24], 1)
		binary.LittleEndian.PutUint32(snapshotValue[ticket+32:ticket+36], 1) // HELD
		const metadata = 376
		binary.LittleEndian.PutUint64(snapshotValue[metadata:metadata+8], 1)     // root epoch
		binary.LittleEndian.PutUint64(snapshotValue[metadata+64:metadata+72], 1) // uid
		binary.LittleEndian.PutUint32(snapshotValue[metadata+144:metadata+148], 1)
		snapshotValue[metadata+148] = '/'
		if err := snapshot.Update(uint32(0), snapshotValue, ebpf.UpdateAny); err != nil {
			t.Fatalf("populate synthetic snapshot: %v", err)
		}
		for name, source := range map[string]*ebpf.Map{
			"blobs": blobs, "object": object, "snapshot": snapshot,
		} {
			if err := source.Freeze(); err != nil {
				t.Fatalf("freeze synthetic policy %s: %v", name, err)
			}
		}
	} else if os.Getenv("IG_OPAQUE_LIFECYCLE_EXPECT_EVAL") == "1" {
		t.Fatal("typed WORK evaluator fixture lacks its policy source")
	}
	if err := collection.Maps["opaque_lifecycle_gate"].Update(uint32(0), gate, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	expectTailcall := os.Getenv("IG_OPAQUE_LIFECYCLE_EXPECT_TAILCALL") == "1"
	expectFallback := os.Getenv("IG_OPAQUE_LIFECYCLE_EXPECT_TAILCALL_FALLBACK") == "1"
	if expectStage && !expectTailcall {
		t.Fatal("staged evaluator fixture requires the exact tail-call successor")
	}
	if expectTailcall && expectFallback {
		t.Fatal("choose one tail-call fixture outcome")
	}
	if expectTailcall || expectFallback {
		targets := collection.Maps["opaque_lifecycle_tail_targets"]
		stage := collection.Programs["opaque_lifecycle_exec_stage"]
		if targets == nil || stage == nil || targets.Type() != ebpf.ProgramArray ||
			targets.MaxEntries() != 1 || targets.Flags() != 0 {
			t.Fatal("missing one-slot tail-call stage and program array")
		}
		if expectTailcall {
			info, err := stage.Info()
			if err != nil {
				t.Fatal(err)
			}
			stageID, ok := info.ID()
			if !ok {
				t.Fatal("tail-call stage has no program ID")
			}
			if err := targets.Update(uint32(0), stage, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			var got uint32
			if err := targets.Lookup(uint32(0), &got); err != nil || got != uint32(stageID) {
				t.Fatalf("tail-call stage ID mismatch: got=%d want=%d err=%v", got, stageID, err)
			}
		}
		if err := targets.Freeze(); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{
		"opaque_lifecycle_gate", "writer_probe_gate",
		"se_opaque_payload_zero", "se_opaque_work_zero",
	} {
		if err := collection.Maps[name].Freeze(); err != nil {
			t.Fatalf("freeze %s: %v", name, err)
		}
	}
	free, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs["opaque_lifecycle_task_free"]})
	if err != nil {
		t.Fatal(err)
	}
	defer free.Close()
	var execLink link.Link
	if program := collection.Programs["opaque_lifecycle_exec"]; program != nil {
		execLink, err = link.AttachLSM(link.LSMOptions{Program: program})
		if err != nil {
			t.Fatal(err)
		}
		defer execLink.Close()
	} else if os.Getenv("IG_OPAQUE_LIFECYCLE_EXPECT_EXEC") == "1" {
		t.Fatal("typed lifecycle fixture is missing its exec source")
	}
	workReaper := collection.Programs["opaque_lifecycle_work_reap"]
	if workReaper == nil && os.Getenv("IG_OPAQUE_LIFECYCLE_EXPECT_WORK") == "1" {
		t.Fatal("typed WORK fixture is missing its WORK-first reaper")
	}
	alloc, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs["opaque_lifecycle_task_alloc"]})
	if err != nil {
		t.Fatal(err)
	}
	defer alloc.Close()
	if os.Getenv("IG_OPAQUE_LIFECYCLE_SATURATE") == "1" {
		if workReaper != nil {
			t.Fatal("TASK-only saturation runner does not qualify a live WORK source")
		}
		testOpaqueLifecycleSaturation(t, collection, cgroup)
		return
	}
	wantBirths := 1
	if raw := os.Getenv("IG_OPAQUE_LIFECYCLE_BIRTHS"); raw != "" {
		wantBirths, err = strconv.Atoi(raw)
		if err != nil || wantBirths < 1 || wantBirths > 10001 {
			t.Fatalf("invalid fixture birth count %q", raw)
		}
	}
	var counters []byte
	var reclaimed uint64
	var workReturned uint64
	threadHelper := os.Getenv("IG_OPAQUE_LIFECYCLE_THREAD_HELPER")
	for i := 0; i < wantBirths; i++ {
		// The shell is born outside the gate, moves itself into the isolated
		// cgroup, then either forks one process or execs a helper that creates
		// and joins one pthread. The Go controller never consumes a credit.
		var child *exec.Cmd
		if threadHelper == "" {
			child = exec.Command("/bin/bash", "-c",
				`echo $$ > "$1/cgroup.procs"; /bin/true; rc=$?; exit "$rc"`,
				"opaque-fixture-child", cgroup)
		} else {
			child = exec.Command("/bin/bash", "-c",
				`echo $$ > "$1/cgroup.procs"; exec "$2"`,
				"opaque-fixture-thread", cgroup, threadHelper)
		}
		if out, err := child.CombinedOutput(); (expectFallback && err == nil) || (!expectFallback && err != nil) {
			t.Fatalf("fixture child %d: fallback=%v err=%v output=%s", i, expectFallback, err, out)
		}
		deadline := time.Now().Add(5 * time.Second)
		for {
			counters = opaqueLifecycleCounters(t, collection)
			if binary.LittleEndian.Uint64(counters[0:8]) >= uint64(i+1) &&
				binary.LittleEndian.Uint64(counters[8:16]) >= uint64(i+1) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("no attached birth/death at child %d: %x", i, counters)
			}
			time.Sleep(10 * time.Millisecond)
		}
		before := reclaimed
		if workReaper != nil {
			beforeWork := workReturned
			for slot := uint32(0); slot < spec.Maps["se_opaque_work_charges"].MaxEntries; slot++ {
				charge, err := collection.Maps["se_opaque_work_charges"].LookupBytes(slot)
				if err != nil || len(charge) < 56 {
					t.Fatalf("WORK charge %d: len=%d err=%v", slot, len(charge), err)
				}
				cookie := binary.LittleEndian.Uint64(charge[0:8])
				if cookie == 0 {
					continue
				}
				payload, err := collection.Maps["se_opaque_work_payload"].LookupBytes(slot)
				if err != nil || len(payload) < 48 ||
					binary.LittleEndian.Uint64(payload[40:48]) != gate.Scope {
					meta, _ := collection.Maps["se_opaque_work_meta"].LookupBytes(slot)
					account, _ := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
					t.Fatalf("WORK %d lacks the source-written typed semantic: len=%d err=%v payload_prefix=%x charge=%x meta=%x account=%x counters=%x",
						slot, len(payload), err, payload[:min(len(payload), 48)], charge, meta, account, opaqueLifecycleCounters(t, collection))
				}
				if os.Getenv("IG_OPAQUE_LIFECYCLE_EXPECT_DEATH_CONTINUATION") == "1" ||
					expectTailcall || expectFallback {
					meta, err := collection.Maps["se_opaque_work_meta"].LookupBytes(slot)
					if err != nil || len(meta) != 80 ||
						binary.LittleEndian.Uint32(meta[4:8]) != 4 || // DONE
						binary.LittleEndian.Uint32(meta[64:68]) != 1 || // owner ref
						binary.LittleEndian.Uint32(meta[72:76]) != 0 { // stage reset
						t.Fatalf("WORK %d was not closed by task_free: meta=%x err=%v", slot, meta, err)
					}
				}
				if os.Getenv("IG_OPAQUE_LIFECYCLE_EXPECT_CATALOGUE") == "1" {
					// The typed 19,184-byte invocation is followed by the
					// 272-byte scoped cache. Check the callback's published
					// result before the WORK-first reaper zeroes its payload.
					const cache = 19184
					if len(payload) != cache+272 ||
						binary.LittleEndian.Uint64(payload[cache:cache+8]) != gate.Scope ||
						binary.LittleEndian.Uint64(payload[cache+8:cache+16]) != 1 ||
						binary.LittleEndian.Uint64(payload[cache+16:cache+24]) != 1 ||
						binary.LittleEndian.Uint64(payload[cache+24:cache+32]) != 1 ||
						!bytes.Equal(payload[cache+32:], make([]byte, 240)) {
						t.Fatalf("WORK %d lacks callback-classified scoped catalogue: cache=%x", slot, payload[min(len(payload), cache):])
					}
				}
				if expectStage {
					const decision = 3176 + 9216 + 2248
					const cursor = 3176 + 11904
					if len(payload) != 19456 ||
						binary.LittleEndian.Uint32(payload[decision+4:decision+8]) != 2 ||
						binary.LittleEndian.Uint64(payload[decision+8:decision+16])&1 == 0 ||
						binary.LittleEndian.Uint64(payload[cursor:cursor+8]) != 1 ||
						binary.LittleEndian.Uint32(payload[cursor+16:cursor+20]) != 1 ||
						binary.LittleEndian.Uint32(payload[cursor+20:cursor+24]) != 3 {
						t.Fatalf("WORK %d lost staged evaluator result: decision=%x cursor=%x", slot,
							payload[decision:decision+32], payload[cursor:cursor+56])
					}
				}
				request := struct {
					Cookie         uint64
					Slot, Reserved uint32
				}{cookie, slot, 0}
				if err := collection.Maps["opaque_lifecycle_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
					t.Fatal(err)
				}
				for step := 0; step < 10; step++ {
					if _, err := workReaper.Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
						t.Fatal(err)
					}
					charge, err = collection.Maps["se_opaque_work_charges"].LookupBytes(slot)
					if err != nil || len(charge) < 56 {
						t.Fatalf("WORK charge recheck %d: len=%d err=%v", slot, len(charge), err)
					}
					if binary.LittleEndian.Uint64(charge[0:8]) == 0 {
						workReturned++
						break
					}
				}
				if binary.LittleEndian.Uint64(charge[0:8]) != 0 {
					t.Fatalf("WORK %d credit did not return: %x", slot, charge)
				}
			}
			if workReturned == beforeWork {
				t.Fatalf("no source-owned WORK returned at child %d: counters=%x", i, counters)
			}
		}
		for slot := uint32(0); slot < 64; slot++ {
			var charge [40]byte
			if err := collection.Maps["se_opaque_charges"].Lookup(slot, &charge); err != nil {
				t.Fatal(err)
			}
			cookie := binary.LittleEndian.Uint64(charge[0:8])
			if cookie == 0 {
				continue
			}
			var meta [128]byte
			if err := collection.Maps["se_opaque_meta"].Lookup(slot, &meta); err != nil {
				t.Fatal(err)
			}
			phase := binary.LittleEndian.Uint32(meta[4:8])
			if phase != 2 && phase != 6 {
				continue // live fixture runner threads are not reapable
			}
			request := struct {
				Cookie         uint64
				Slot, Reserved uint32
			}{cookie, slot, 0}
			if err := collection.Maps["opaque_lifecycle_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
				t.Fatal(err)
			}
			for step := 0; step < 12; step++ {
				if _, err := collection.Programs["opaque_lifecycle_reap"].Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
					t.Fatal(err)
				}
				if err := collection.Maps["se_opaque_charges"].Lookup(slot, &charge); err != nil {
					t.Fatal(err)
				}
				if binary.LittleEndian.Uint64(charge[0:8]) == 0 {
					reclaimed++
					break
				}
			}
		}
		if reclaimed == before {
			t.Fatalf("no exited opaque TASK reaped at child %d: counters=%x", i, counters)
		}
		if i%512 == 0 || i+1 == wantBirths {
			var account [40]byte
			if err := collection.Maps["se_opaque_accounts"].Lookup(uint32(0), &account); err != nil {
				t.Fatal(err)
			}
			if fault := binary.LittleEndian.Uint32(account[8:12]); fault != 0 {
				t.Fatalf("opaque account fault at child %d: %x", i, account)
			}
		}
	}
	counters = opaqueLifecycleCounters(t, collection)
	var finalAccount [40]byte
	if err := collection.Maps["se_opaque_accounts"].Lookup(uint32(0), &finalAccount); err != nil {
		t.Fatal(err)
	}
	if births, deaths, denied := binary.LittleEndian.Uint64(counters[0:8]),
		binary.LittleEndian.Uint64(counters[8:16]), binary.LittleEndian.Uint64(counters[16:24]); births != uint64(wantBirths) || deaths != births || denied != 0 ||
		reclaimed != births || binary.LittleEndian.Uint32(finalAccount[4:8]) != 0 ||
		binary.LittleEndian.Uint64(finalAccount[32:40]) != 0 {
		t.Fatalf("incomplete opaque churn: want=%d reclaimed=%d counters=%x account=%x",
			wantBirths, reclaimed, counters, finalAccount)
	}
	// Every charged TASK birth must have held an exact route claim through its
	// commit, and every callback must have returned that claim. A leaked early
	// claim would prevent route withdrawal/recycle even after all credits return.
	route, err := collection.Maps["writer_probe_route"].LookupBytes(uint32(0))
	if err != nil || len(route) != 88 ||
		binary.LittleEndian.Uint32(route[4:8]) != gate.Incarnation ||
		binary.LittleEndian.Uint64(route[16:24]) != gate.Scope ||
		binary.LittleEndian.Uint64(route[40:48]) != uint64(wantBirths) ||
		binary.LittleEndian.Uint32(route[60:64]) != 2 || // ACTIVE
		binary.LittleEndian.Uint32(route[64:68]) != 0 || // early claims
		binary.LittleEndian.Uint32(route[72:76]) != 0 || // no legacy TASK counter
		binary.LittleEndian.Uint32(route[76:80]) != 0 { // no legacy WORK counter
		t.Fatalf("opaque route claim lifecycle incomplete: route=%x err=%v", route, err)
	}
	if execLink != nil {
		if len(counters) < 72 ||
			binary.LittleEndian.Uint64(counters[48:56]) != uint64(wantBirths) ||
			binary.LittleEndian.Uint64(counters[56:64]) != uint64(wantBirths) ||
			binary.LittleEndian.Uint64(counters[64:72]) != 0 {
			t.Fatalf("source-owned exec transactions not reserved and aborted exactly once per TASK: %x", counters)
		}
		t.Logf("source-owned exec reservations=%d aborts=%d faults=0",
			binary.LittleEndian.Uint64(counters[48:56]),
			binary.LittleEndian.Uint64(counters[56:64]))
	}
	if workReaper != nil {
		workAccount, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
		if err != nil || len(workAccount) != 40 {
			t.Fatalf("WORK account: len=%d err=%v", len(workAccount), err)
		}
		if len(counters) < 104 ||
			binary.LittleEndian.Uint64(counters[72:80]) < uint64(wantBirths) ||
			binary.LittleEndian.Uint64(counters[72:80]) != workReturned ||
			binary.LittleEndian.Uint64(counters[80:88]) != 0 ||
			binary.LittleEndian.Uint32(workAccount[4:8]) != 0 ||
			binary.LittleEndian.Uint32(workAccount[8:12]) != 0 ||
			binary.LittleEndian.Uint64(workAccount[32:40]) != 0 {
			t.Fatalf("WORK lifetime incomplete: returned=%d counters=%x account=%x", workReturned, counters, workAccount)
		}
		t.Logf("source-owned typed WORK done=%d returned=%d faults=0",
			binary.LittleEndian.Uint64(counters[72:80]), workReturned)
	}
	if os.Getenv("IG_OPAQUE_LIFECYCLE_EXPECT_DEATH_CONTINUATION") == "1" {
		if len(counters) < 120 ||
			binary.LittleEndian.Uint64(counters[104:112]) != uint64(wantBirths) ||
			binary.LittleEndian.Uint64(counters[112:120]) != uint64(wantBirths) {
			t.Fatalf("incomplete suspended/death transitions: want=%d counters=%x", wantBirths, counters)
		}
		t.Logf("suspended WORK=%d task_free closure=%d",
			binary.LittleEndian.Uint64(counters[104:112]),
			binary.LittleEndian.Uint64(counters[112:120]))
	}
	if expectTailcall {
		if len(counters) < 152 ||
			binary.LittleEndian.Uint64(counters[104:112]) != uint64(wantBirths) || // suspended
			binary.LittleEndian.Uint64(counters[112:120]) != 0 || // no death closure
			binary.LittleEndian.Uint64(counters[120:128]) != uint64(wantBirths) || // entry
			binary.LittleEndian.Uint64(counters[128:136]) != uint64(wantBirths) || // stage
			binary.LittleEndian.Uint64(counters[136:144]) != 0 || // fallback
			binary.LittleEndian.Uint64(counters[144:152]) != uint64(wantBirths) { // done
			t.Fatalf("incomplete tail-call WORK handoff: want=%d counters=%x", wantBirths, counters)
		}
		t.Logf("tail-call WORK handoff=%d stage=%d fallback=0",
			binary.LittleEndian.Uint64(counters[120:128]),
			binary.LittleEndian.Uint64(counters[128:136]))
	}
	if expectFallback {
		if len(counters) < 152 ||
			binary.LittleEndian.Uint64(counters[104:112]) != uint64(wantBirths) ||
			binary.LittleEndian.Uint64(counters[112:120]) != 0 ||
			binary.LittleEndian.Uint64(counters[120:128]) != uint64(wantBirths) ||
			binary.LittleEndian.Uint64(counters[128:136]) != 0 ||
			binary.LittleEndian.Uint64(counters[136:144]) != uint64(wantBirths) ||
			binary.LittleEndian.Uint64(counters[144:152]) != 0 {
			t.Fatalf("missing-stage fallback did not deny and close WORK: want=%d counters=%x", wantBirths, counters)
		}
		t.Logf("missing-stage denied and closed WORK=%d", wantBirths)
	}
	t.Logf("attached opaque TASK births=%d deaths=%d returns=%d denied=0; no policy enforcement",
		binary.LittleEndian.Uint64(counters[0:8]), binary.LittleEndian.Uint64(counters[8:16]), reclaimed)
}

func opaqueLifecycleCounters(t *testing.T, collection *ebpf.Collection) []byte {
	t.Helper()
	counters, err := collection.Maps["opaque_lifecycle_counters"].LookupBytes(uint32(0))
	if err != nil || len(counters) < 48 {
		t.Fatalf("opaque lifecycle counters: len=%d err=%v", len(counters), err)
	}
	return counters
}

func testOpaqueLifecycleSaturation(t *testing.T, collection *ebpf.Collection, cgroup string) {
	t.Helper()
	held := make([]*exec.Cmd, 0, 64)
	killHeld := func() {
		for _, child := range held {
			_ = syscall.Kill(-child.Process.Pid, syscall.SIGTERM)
		}
		for _, child := range held {
			_ = child.Wait()
		}
		held = nil
	}
	defer killHeld()
	var account [40]byte
	for i := 0; i < 64; i++ {
		child := exec.Command("/bin/bash", "-c",
			`echo $$ > "$1/cgroup.procs"; /bin/sleep 120 & wait`,
			"opaque-held-child", cgroup)
		child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		held = append(held, child)
		deadline := time.Now().Add(5 * time.Second)
		for {
			if err := collection.Maps["se_opaque_accounts"].Lookup(uint32(0), &account); err != nil {
				t.Fatal(err)
			}
			if binary.LittleEndian.Uint32(account[4:8]) == uint32(i+1) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("held child %d never charged: account=%x", i, account)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	if binary.LittleEndian.Uint64(account[32:40]) != ^uint64(0) ||
		binary.LittleEndian.Uint32(account[8:12]) != 0 {
		t.Fatalf("full quota is not exactly 64 healthy credits: %x", account)
	}
	retryHelper := os.Getenv("IG_OPAQUE_LIFECYCLE_RETRY_HELPER")
	if retryHelper == "" {
		t.Fatal("same-parent EPERM proof requires a static C retry helper")
	}
	// Keep this exact C parent alive inside the gated cgroup across the
	// failed clone and the later successful retry. A C helper handles EPERM
	// without Bash's fatal-fork behavior; pipes require no extra TASK birth.
	controlRead, controlWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	statusRead, statusWrite, err := os.Pipe()
	if err != nil {
		controlRead.Close()
		controlWrite.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	retryParent := exec.CommandContext(ctx, retryHelper, cgroup)
	retryParent.ExtraFiles = []*os.File{controlRead, statusWrite}
	var retryStderr bytes.Buffer
	retryParent.Stderr = &retryStderr
	if err := retryParent.Start(); err != nil {
		controlRead.Close()
		controlWrite.Close()
		statusRead.Close()
		statusWrite.Close()
		t.Fatal(err)
	}
	controlRead.Close()
	statusWrite.Close()
	retryDone := false
	defer func() {
		controlWrite.Close()
		statusRead.Close()
		if !retryDone {
			_ = retryParent.Process.Kill()
			_ = retryParent.Wait()
		}
	}()
	status := bufio.NewReader(statusRead)
	first, err := status.ReadString('\n')
	if err != nil || first != "EPERM\n" {
		waitErr := retryParent.Wait()
		retryDone = true
		t.Fatalf("full quota must deny surviving parent: status=%q read=%v wait=%v stderr=%s",
			first, err, waitErr, retryStderr.String())
	}
	procs, err := os.ReadFile(cgroup + "/cgroup.procs")
	if err != nil || !bytes.Contains(append([]byte{'\n'}, procs...),
		[]byte("\n"+strconv.Itoa(retryParent.Process.Pid)+"\n")) {
		t.Fatalf("original denied parent did not survive in scope: pid=%d err=%v",
			retryParent.Process.Pid, err)
	}
	counters := opaqueLifecycleCounters(t, collection)
	if binary.LittleEndian.Uint64(counters[0:8]) != 64 ||
		binary.LittleEndian.Uint64(counters[16:24]) == 0 {
		t.Fatalf("full-quota denial changed TASK charge: %x", counters)
	}
	killHeld()
	deadline := time.Now().Add(5 * time.Second)
	for {
		counters = opaqueLifecycleCounters(t, collection)
		if binary.LittleEndian.Uint64(counters[8:16]) == 64 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("held children did not all die: %x", counters)
		}
		time.Sleep(10 * time.Millisecond)
	}
	var returned uint64
	for slot := uint32(0); slot < 64; slot++ {
		var charge [40]byte
		if err := collection.Maps["se_opaque_charges"].Lookup(slot, &charge); err != nil {
			t.Fatal(err)
		}
		cookie := binary.LittleEndian.Uint64(charge[0:8])
		if cookie == 0 {
			t.Fatalf("full quota slot %d lost charge before reaping", slot)
		}
		request := struct {
			Cookie         uint64
			Slot, Reserved uint32
		}{cookie, slot, 0}
		if err := collection.Maps["opaque_lifecycle_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		for step := 0; step < 12; step++ {
			if _, err := collection.Programs["opaque_lifecycle_reap"].Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
				t.Fatal(err)
			}
			if err := collection.Maps["se_opaque_charges"].Lookup(slot, &charge); err != nil {
				t.Fatal(err)
			}
			if binary.LittleEndian.Uint64(charge[0:8]) == 0 {
				returned++
				break
			}
		}
	}
	if err := collection.Maps["se_opaque_accounts"].Lookup(uint32(0), &account); err != nil {
		t.Fatal(err)
	}
	if returned != 64 || binary.LittleEndian.Uint32(account[4:8]) != 0 ||
		binary.LittleEndian.Uint64(account[32:40]) != 0 ||
		binary.LittleEndian.Uint32(account[8:12]) != 0 {
		t.Fatalf("full-quota cleanup did not drain exactly: returns=%d account=%x", returned, account)
	}
	if _, err := controlWrite.Write([]byte{'R'}); err != nil {
		t.Fatalf("resume original denied parent: %v", err)
	}
	second, err := status.ReadString('\n')
	if err != nil || second != "OK\n" {
		t.Fatalf("same parent could not retry after EPERM: status=%q err=%v",
			second, err)
	}
	if err := retryParent.Wait(); err != nil {
		t.Fatalf("surviving parent did not exit successfully: %v stderr=%s",
			err, retryStderr.String())
	}
	retryDone = true
	deadline = time.Now().Add(5 * time.Second)
	for {
		counters = opaqueLifecycleCounters(t, collection)
		if binary.LittleEndian.Uint64(counters[0:8]) == 65 &&
			binary.LittleEndian.Uint64(counters[8:16]) == 65 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("post-EPERM child was not tracked: %x", counters)
		}
		time.Sleep(10 * time.Millisecond)
	}
	var lastCharge [40]byte
	if err := collection.Maps["se_opaque_charges"].Lookup(uint32(0), &lastCharge); err != nil {
		t.Fatal(err)
	}
	lastCookie := binary.LittleEndian.Uint64(lastCharge[0:8])
	if lastCookie == 0 {
		t.Fatal("post-EPERM child has no exact charge")
	}
	request := struct {
		Cookie         uint64
		Slot, Reserved uint32
	}{lastCookie, 0, 0}
	if err := collection.Maps["opaque_lifecycle_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 12 && binary.LittleEndian.Uint64(lastCharge[0:8]) != 0; step++ {
		if _, err := collection.Programs["opaque_lifecycle_reap"].Run(&ebpf.RunOptions{Data: make([]byte, 64)}); err != nil {
			t.Fatal(err)
		}
		if err := collection.Maps["se_opaque_charges"].Lookup(uint32(0), &lastCharge); err != nil {
			t.Fatal(err)
		}
	}
	if binary.LittleEndian.Uint64(lastCharge[0:8]) != 0 {
		t.Fatal("post-EPERM child credit was not returned")
	}
	if err := collection.Maps["se_opaque_accounts"].Lookup(uint32(0), &account); err != nil {
		t.Fatal(err)
	}
	if binary.LittleEndian.Uint32(account[4:8]) != 0 ||
		binary.LittleEndian.Uint64(account[32:40]) != 0 ||
		binary.LittleEndian.Uint32(account[8:12]) != 0 ||
		binary.LittleEndian.Uint64(counters[16:24]) != 1 {
		t.Fatalf("same-parent retry left credit/fault or extra denial: counters=%x account=%x",
			counters, account)
	}
	t.Log("full 64-credit quota denied with EPERM; same parent survived, retried after release, and all 65 credits returned")
}
