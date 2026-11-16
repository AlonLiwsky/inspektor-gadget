// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestEvaluatorKernel proves the fact-driven semantics with BPF_PROG_TEST_RUN.
// It explicitly selects development evaluator semantics; ordinary owner builds stay ABI2.
// It does not attach to any hook and does not prove authoritative fact acquisition.
func TestEvaluatorKernel(t *testing.T) {
	if os.Getenv("IG_FULL_EVALUATOR_KERNEL_TEST") != "1" {
		t.Skip("set IG_FULL_EVALUATOR_KERNEL_TEST=1 on a disposable root BPF host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("requires disposable root BPF host")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	object := os.Getenv("IG_FULL_EVALUATOR_BPF_OBJECT")
	if object == "" {
		source := os.Getenv("IG_FULL_EVALUATOR_BPF_SOURCE")
		if source == "" {
			source = "testdata/evaluator_runner.c"
		}
		object = filepath.Join(t.TempDir(), "evaluator.bpf.o")
		if output, err := exec.Command("clang", "-target", "bpf", "-DENFORCE_EXEC_ABI3_DEVELOPMENT=1", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-c", source, "-o", object).CombinedOutput(); err != nil {
			t.Fatalf("compile evaluator BPF: %v\n%s", err, output)
		}
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 16 * 1024 * 1024}})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("complete verifier log:\n%+v", verifier)
		}
		t.Fatalf("evaluator BPF verifier/load failed: %v", err)
	}
	defer collection.Close()
	blobs, inputs, scratch := collection.Maps["blobs"], collection.Maps["input_map"], collection.Maps["scratch_map"]
	program := collection.Programs["evaluator"]
	if blobs == nil || inputs == nil || scratch == nil || program == nil {
		t.Fatal("missing evaluator maps/program")
	}
	if blobs.Flags()&(1<<7) == 0 {
		t.Fatal("blob map must forbid BPF writes")
	}
	if blobs.Type() != ebpf.Hash || blobs.MaxEntries() != MaxKernelEntries || blobs.ValueSize() != KernelBlobSize || inputs.ValueSize() != 9216 || scratch.ValueSize() != 2688 {
		t.Fatal("unexpected evaluator map ABI")
	}
	if output, err := exec.Command("uname", "-a").CombinedOutput(); err == nil {
		t.Logf("kernel: %s", output)
	}
	t.Log("evaluator verifier accepted; BPF_PROG_TEST_RUN only, no attachment")
	runEvaluatorParity(t, func(t *testing.T, p *KernelProgram, facts evaluatorFacts) []uint64 {
		t.Helper()
		for i, entry := range p.Entries {
			if err := blobs.Put(uint32(i), entry); err != nil {
				t.Fatal(err)
			}
		}
		if err := inputs.Put(uint32(0), facts); err != nil {
			t.Fatal(err)
		}
		poison := bytes.Repeat([]byte{0xa5}, int(scratch.ValueSize()))
		if err := scratch.Put(uint32(0), poison); err != nil {
			t.Fatal(err)
		}
		var first []uint64
		for attempt := 0; attempt < 2; attempt++ {
			result, _, err := program.Test(make([]byte, 64))
			if err != nil {
				t.Fatal(err)
			}
			if result > 1 {
				t.Fatalf("invalid evaluator result %d", result)
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
			if attempt == 0 {
				first = values
			} else {
				for i, v := range first {
					if values[i] != v {
						t.Fatalf("reused scratch differs: %v then %v", first, values)
					}
				}
			}
		}
		return first
	})
	t.Run("frozen-program", func(t *testing.T) {
		beforeResult, _, err := program.Test(make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		before, err := scratch.LookupBytes(uint32(0))
		if err != nil {
			t.Fatal(err)
		}
		if err := blobs.Freeze(); err != nil {
			t.Fatal(err)
		}
		if err := blobs.Put(uint32(0), Blob{}); !errors.Is(err, syscall.EPERM) {
			t.Fatalf("frozen blob write: %v", err)
		}
		result, _, err := program.Test(make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		if result != beforeResult {
			t.Fatalf("freeze changed evaluator result: before=%d after=%d", beforeResult, result)
		}
		after, err := scratch.LookupBytes(uint32(0))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before[2248:2360], after[2248:2360]) {
			t.Fatal("freeze changed evaluator decision")
		}
	})
}
