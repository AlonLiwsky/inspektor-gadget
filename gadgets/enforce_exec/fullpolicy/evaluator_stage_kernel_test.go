// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestStageCandidateKernel exercises the isolated, unattached continuation
// fixture. It does not prove publication, WORK authentication, or enforcement.
func TestStageCandidateKernel(t *testing.T) {
	object := os.Getenv("IG_FULL_STAGE_OBJECT")
	if object == "" {
		t.Skip("set IG_FULL_STAGE_OBJECT on a disposable root BPF host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	programOptions := ebpf.ProgramOptions{LogSizeStart: 16 * 1024 * 1024}
	if os.Getenv("IG_FULL_STAGE_STATS") == "1" {
		programOptions.LogLevel = ebpf.LogLevelStats
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: programOptions})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	blobs := collection.Maps["stage_blobs"]
	facts := collection.Maps["stage_facts"]
	scratch := collection.Maps["stage_scratch"]
	cursor := collection.Maps["stage_cursor"]
	program := collection.Programs["evaluator_stage_probe"]
	if program == nil {
		program = collection.Programs["evaluator_stage_scalar_probe"]
	}
	if program != nil && os.Getenv("IG_FULL_STAGE_STATS") == "1" {
		t.Logf("advance verifier stats: %s", program.VerifierLog)
	}
	begin := collection.Programs["evaluator_stage_begin_probe"]
	finish := collection.Programs["evaluator_stage_finish_probe"]
	if (begin == nil) != (finish == nil) {
		t.Fatal("incomplete staged lifecycle fixture")
	}
	if blobs == nil || facts == nil || scratch == nil || cursor == nil || program == nil ||
		blobs.ValueSize() != 288 || facts.ValueSize() != 9216 || scratch.ValueSize() != 2688 || cursor.ValueSize() != 56 {
		t.Fatal("stage fixture ABI mismatch")
	}
	for _, scenario := range []struct {
		count     int
		lastMatch bool
	}{
		{17, false}, {17, true}, {256, false}, {256, true},
	} {
		t.Run(fmt.Sprintf("rules_%d_last_match_%t", scenario.count, scenario.lastMatch), func(t *testing.T) {
			count := scenario.count
			rules := make([]Rule, count)
			for i := range rules {
				path := fmt.Sprintf("/unmatched/%03d", i)
				if scenario.lastMatch && i == count-1 {
					path = "/safe"
				}
				rules[i] = Rule{
					Name: fmt.Sprintf("rule-%03d", i), Action: Deny,
					Target: Target{Path: []string{path}},
				}
			}
			policies := []Policy{{ID: "stage", Revision: "1", Mode: Enforce, Rules: rules}}
			compiled, err := CompileKernel(policies, 1, "stage-container")
			if err != nil {
				t.Fatal(err)
			}
			for i, entry := range compiled.Entries {
				if err := blobs.Put(uint32(i), entry); err != nil {
					t.Fatal(err)
				}
			}
			input := evaluatorFactBytes(t, compiled, policies, Facts{ActorPath: "/actor", TargetPath: "/safe"})
			if err := facts.Put(uint32(0), input); err != nil {
				t.Fatal(err)
			}
			if err := scratch.Put(uint32(0), make([]byte, scratch.ValueSize())); err != nil {
				t.Fatal(err)
			}
			state := make([]byte, cursor.ValueSize())
			if begin == nil {
				// The earlier advance-only fixture has no begin program.
				binary.LittleEndian.PutUint64(state[0:8], 1)
				binary.LittleEndian.PutUint32(state[8:12], 1)
				binary.LittleEndian.PutUint32(state[12:16], uint32(count))
				binary.LittleEndian.PutUint32(state[20:24], 1)
				binary.LittleEndian.PutUint32(state[28:32], 1)
				binary.LittleEndian.PutUint32(state[32:36], 1)
			}
			if err := cursor.Put(uint32(0), state); err != nil {
				t.Fatal(err)
			}
			if begin != nil {
				result, _, err := begin.Test(make([]byte, 64))
				if err != nil || result != 1 {
					t.Fatalf("begin result=%d error=%v", result, err)
				}
				result, _, err = begin.Test(make([]byte, 64))
				if err != nil || result != 0 {
					t.Fatalf("begin replay result=%d error=%v", result, err)
				}
				result, _, err = finish.Test(make([]byte, 64))
				if err != nil || result != 0 {
					t.Fatalf("premature finish result=%d error=%v", result, err)
				}
			}
			for step := 1; step <= (count+15)/16; step++ {
				result, _, err := program.Test(make([]byte, 64))
				if err != nil || result != 1 {
					t.Fatalf("step %d result=%d error=%v", step, result, err)
				}
				got, err := cursor.LookupBytes(uint32(0))
				if err != nil {
					t.Fatal(err)
				}
				wantNext := step * 16
				if wantNext > count {
					wantNext = count
				}
				if next := binary.LittleEndian.Uint32(got[16:20]); next != uint32(wantNext) {
					t.Fatalf("step %d advanced to %d, want %d", step, next, wantNext)
				}
				wantState := uint32(1)
				if wantNext == count {
					wantState = 2 // READY
				}
				if state := binary.LittleEndian.Uint32(got[20:24]); state != wantState {
					t.Fatalf("step %d state=%d, want %d", step, state, wantState)
				}
			}
			output, err := scratch.LookupBytes(uint32(0))
			if err != nil {
				t.Fatal(err)
			}
			decision := output[2248:]
			matched := binary.LittleEndian.Uint64(decision[8+(count-1)/64*8 : 16+(count-1)/64*8])
			lastBit := uint64(1) << uint((count-1)%64)
			if got := matched&lastBit != 0; got != scenario.lastMatch {
				t.Fatalf("last-rule match bit=%t, want %t", got, scenario.lastMatch)
			}
			if got := binary.LittleEndian.Uint32(decision[0:4]) != 0; got != scenario.lastMatch {
				t.Fatalf("deny=%t, want %t", got, scenario.lastMatch)
			}
			if finish != nil {
				result, _, err := finish.Test(make([]byte, 64))
				if err != nil || result != 1 {
					t.Fatalf("finish result=%d error=%v", result, err)
				}
				final, err := scratch.LookupBytes(uint32(0))
				if err != nil {
					t.Fatal(err)
				}
				wantMode := uint32(1)
				if scenario.lastMatch {
					wantMode = 2
				}
				if mode := binary.LittleEndian.Uint32(final[2252:2256]); mode != wantMode {
					t.Fatalf("final mode=%d, want %d", mode, wantMode)
				}
				result, _, err = finish.Test(make([]byte, 64))
				if err != nil || result != 0 {
					t.Fatalf("finish replay result=%d error=%v", result, err)
				}
				if count == 17 && !scenario.lastMatch {
					if err := cursor.Put(uint32(0), make([]byte, cursor.ValueSize())); err != nil {
						t.Fatal(err)
					}
					if err := scratch.Put(uint32(0), make([]byte, scratch.ValueSize())); err != nil {
						t.Fatal(err)
					}
					result, _, err := begin.Test(make([]byte, 64))
					if err != nil || result != 1 {
						t.Fatalf("second begin result=%d error=%v", result, err)
					}
					header := mustDecode[KernelHeader](t, compiled, 0)
					header.Generation++
					changed, err := encode(header)
					if err != nil {
						t.Fatal(err)
					}
					if err := blobs.Put(uint32(0), changed); err != nil {
						t.Fatal(err)
					}
					result, _, err = program.Test(make([]byte, 64))
					if err != nil || result != 0 {
						t.Fatalf("stale generation result=%d error=%v", result, err)
					}
					output, err := scratch.LookupBytes(uint32(0))
					if err != nil {
						t.Fatal(err)
					}
					if fault := binary.LittleEndian.Uint32(output[2248+104 : 2248+108]); fault != 1 {
						t.Fatalf("stale generation fault=%d, want FE_INVALID", fault)
					}
				}
			}
		})
	}
	if begin == nil {
		return
	}
	t.Run("reference-parity", func(t *testing.T) {
		runEvaluatorParity(t, func(t *testing.T, compiled *KernelProgram, input evaluatorFacts) []uint64 {
			t.Helper()
			for i, entry := range compiled.Entries {
				if err := blobs.Put(uint32(i), entry); err != nil {
					t.Fatal(err)
				}
			}
			if err := facts.Put(uint32(0), input); err != nil {
				t.Fatal(err)
			}
			if err := scratch.Put(uint32(0), bytes.Repeat([]byte{0xa5}, int(scratch.ValueSize()))); err != nil {
				t.Fatal(err)
			}
			if err := cursor.Put(uint32(0), make([]byte, cursor.ValueSize())); err != nil {
				t.Fatal(err)
			}
			result, _, err := begin.Test(make([]byte, 64))
			if err != nil || result > 1 {
				t.Fatalf("begin result=%d error=%v", result, err)
			}
			if result == 1 {
				for step := 0; step < 16; step++ {
					state, err := cursor.LookupBytes(uint32(0))
					if err != nil {
						t.Fatal(err)
					}
					if binary.LittleEndian.Uint32(state[20:24]) != 1 { // ACTIVE
						break
					}
					result, _, err = program.Test(make([]byte, 64))
					if err != nil || result > 1 {
						t.Fatalf("advance %d result=%d error=%v", step, result, err)
					}
				}
				state, err := cursor.LookupBytes(uint32(0))
				if err != nil {
					t.Fatal(err)
				}
				if binary.LittleEndian.Uint32(state[20:24]) != 2 { // READY
					t.Fatalf("stage did not finish after 16 windows: %x", state)
				}
				result, _, err = finish.Test(make([]byte, 64))
				if err != nil || result > 1 {
					t.Fatalf("finish result=%d error=%v", result, err)
				}
			}
			output, err := scratch.LookupBytes(uint32(0))
			if err != nil {
				t.Fatal(err)
			}
			decision := output[2248:2360]
			values := make([]uint64, 16)
			if result == 0 {
				values[0] = ^uint64(0)
			}
			values[1] = uint64(binary.LittleEndian.Uint32(decision[0:4]))
			values[2] = uint64(binary.LittleEndian.Uint32(decision[4:8]))
			values[3] = uint64(binary.LittleEndian.Uint32(decision[104:108]))
			for i := 0; i < 12; i++ {
				values[4+i] = binary.LittleEndian.Uint64(decision[8+i*8 : 16+i*8])
			}
			return values
		})
	})
}
