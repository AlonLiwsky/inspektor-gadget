// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

type matcherKernelInput struct {
	PatternKey, Length uint32
	Bytes              [256]byte
}

type matcherScalarKernelInput struct {
	PatternKey, Length, Slot, Reserved uint32
	Cookie                             uint64
	Bytes                              [256]byte
}

// The explicit scalar-context matcher uses a typed stack token as its fifth
// global-function argument. This opt-in test loads and test-runs it without
// attachment; it does not qualify selected exec enforcement or kernel matrix.
func TestScalarGlobalMatcherKernel(t *testing.T) {
	object := os.Getenv("IG_FULL_MATCHER_SCALAR_OBJECT")
	if object == "" {
		t.Skip("set IG_FULL_MATCHER_SCALAR_OBJECT to the compiled scalar matcher fixture on a BPF-capable host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required for scalar matcher TEST_RUN")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 16 * 1024 * 1024}})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("complete scalar matcher verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	blobs, inputs, program := collection.Maps["blobs"], collection.Maps["input_map"], collection.Programs["matcher_scalar"]
	if blobs == nil || inputs == nil || program == nil || blobs.MaxEntries() != 2*MaxKernelEntries || blobs.ValueSize() != KernelBlobSize || inputs.ValueSize() != 280 {
		t.Fatal("scalar matcher loaded ABI mismatch")
	}
	var keys [2]uint32
	for slot, pattern := range []string{"/a", "/b"} {
		compiled, key := compileMatcherPattern(t, pattern)
		keys[slot] = key
		for i, blob := range compiled.Entries {
			if err := blobs.Put(uint32(slot*MaxKernelEntries+i), blob); err != nil {
				t.Fatal(err)
			}
		}
	}
	run := func(slot uint32, cookie uint64, path string) int {
		t.Helper()
		input := matcherScalarKernelInput{PatternKey: keys[slot], Length: uint32(len(path)), Slot: slot, Cookie: cookie}
		copy(input.Bytes[:], path)
		if err := inputs.Put(uint32(0), input); err != nil {
			t.Fatal(err)
		}
		result, _, err := program.Test(make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		if result > 2 {
			t.Fatalf("invalid scalar matcher result %d", result)
		}
		return int(result) - 1
	}
	if run(0, 101, "/a") != 1 || run(0, 101, "/b") != 0 ||
		run(1, 102, "/b") != 1 || run(1, 102, "/a") != 0 ||
		run(0, 102, "/a") != -1 {
		t.Fatal("scalar WORK token did not isolate matcher blobs")
	}
	longPath := "/" + strings.Repeat("a", 254)
	longProgram, longKey := compileMatcherPattern(t, longPath)
	keys[0] = longKey
	for i, blob := range longProgram.Entries {
		if err := blobs.Put(uint32(i), blob); err != nil {
			t.Fatal(err)
		}
	}
	if run(0, 101, longPath) != 1 || run(0, 101, longPath+"a") != -1 ||
		run(1, 102, "/b") != 1 {
		t.Fatal("long scalar matcher changed bounds or crossed WORK slots")
	}
}

// TestMatcherKernel verifies the matcher with BPF_PROG_TEST_RUN only. Nothing is
// attached, and this is not proof of pre-exec fact acquisition or enforcement.
func TestMatcherKernel(t *testing.T) {
	if os.Getenv("IG_FULL_MATCHER_KERNEL_TEST") != "1" {
		t.Skip("set IG_FULL_MATCHER_KERNEL_TEST=1 on a disposable root BPF host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required on disposable BPF test host")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	source := os.Getenv("IG_FULL_MATCHER_BPF_SOURCE")
	if source == "" {
		source = "bpf/matcher_test.bpf.c"
	}
	object := os.Getenv("IG_FULL_MATCHER_BPF_OBJECT")
	if object == "" {
		object = filepath.Join(t.TempDir(), "matcher.bpf.o")
		if output, err := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-c", source, "-o", object).CombinedOutput(); err != nil {
			t.Fatalf("compile BPF matcher: %v\n%s", err, output)
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
		t.Fatalf("matcher BPF verifier/load failed: %v", err)
	}
	defer collection.Close()
	blobs := collection.Maps["blobs"]
	inputs := collection.Maps["input_map"]
	program := collection.Programs["matcher"]
	if blobs == nil || inputs == nil || program == nil {
		t.Fatal("missing matcher maps/program")
	}
	if blobs.Type() != ebpf.Hash || blobs.MaxEntries() != MaxKernelEntries || blobs.ValueSize() != KernelBlobSize || inputs.ValueSize() != 264 {
		t.Fatal("unexpected kernel ABI")
	}
	if output, err := exec.Command("uname", "-a").CombinedOutput(); err == nil {
		t.Logf("kernel: %s", output)
	}
	t.Log("matcher verifier accepted; BPF_PROG_TEST_RUN only, no attachment")
	publish := func(t *testing.T, entries []Blob) {
		t.Helper()
		for i, entry := range entries {
			if err := blobs.Put(uint32(i), entry); err != nil {
				t.Fatal(err)
			}
		}
	}
	run := func(t *testing.T, key uint32, data []byte) int {
		t.Helper()
		input := matcherKernelInput{PatternKey: key, Length: uint32(len(data))}
		copy(input.Bytes[:], data)
		if err := inputs.Put(uint32(0), input); err != nil {
			t.Fatal(err)
		}
		// A nonempty packet is required by the socket-filter test-run interface even
		// though the matcher obtains its input exclusively from its explicit map.
		result, _, err := program.Test(make([]byte, 64))
		if err != nil {
			t.Fatal(err)
		}
		if result > 2 {
			t.Fatalf("invalid matcher result %d", result)
		}
		return int(result) - 1
	}
	patterns := []string{"/**", "/usr/*", "/a?/x", "/[a-cx-z]", "/[^a-c]", "/[\\d]", "/工具/**", "/file\\*", "/line?", "/*a*a*a*a*a*", "/**/**/**", "/😀?", "/[α-ω]", "/" + strings.Repeat("a", 254)}
	observations := []string{"", "/", "/usr/tool", "/usr/tool/sub", "/ab/x", "/a/x", "/b", "/z", "/d", "/5", "/工具/甲", "/file*", "/file1", "/line\n", "prefix/usr/tool", "/aaaaa", "/aaaaab", "/😀é", "/λ", "/x/y/z", "/" + strings.Repeat("a", 254)}
	for _, pattern := range patterns {
		t.Run(pattern, func(t *testing.T) {
			candidate, key := compileMatcherPattern(t, pattern)
			publish(t, candidate.Entries)
			oracle, err := glob(pattern)
			if err != nil {
				t.Fatal(err)
			}
			for _, input := range observations {
				expected := 0
				if oracle.MatchString(input) {
					expected = 1
				}
				if actual := run(t, key, []byte(input)); actual != expected {
					t.Errorf("%q got%d want%d", input, actual, expected)
				}
			}
		})
	}
	t.Run("invalid-input", func(t *testing.T) {
		candidate, key := compileMatcherPattern(t, "/**")
		publish(t, candidate.Entries)
		invalid := [][]byte{{'/', 0}, {'/', 0x80}, {'/', 0xc0, 0xaf}, {'/', 0xc2}, {'/', 0xe2, 0x82}, {'/', 0xed, 0xa0, 0x80}, {'/', 0xf4, 0x90, 0x80, 0x80}, []byte("/" + strings.Repeat("a", 255))}
		for _, input := range invalid {
			if got := run(t, key, input); got != -1 {
				t.Errorf("invalid input%x got%d", input, got)
			}
		}
	})
	t.Run("state-bounds-and-cycles", func(t *testing.T) {
		entries := make([]Blob, 2+MaxRegexStates)
		entries[1], err = encode(KernelPattern{CodeBase: 2, Count: MaxRegexStates})
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < MaxRegexStates-1; i++ {
			entries[i+2], err = encode(KernelInstruction{Op: KernelNop, Out: uint32(i + 1)})
			if err != nil {
				t.Fatal(err)
			}
		}
		entries[len(entries)-1], err = encode(KernelInstruction{Op: KernelMatch})
		if err != nil {
			t.Fatal(err)
		}
		publish(t, entries)
		if got := run(t, 1, nil); got != 1 {
			t.Fatal("512-state closure failed", got)
		}
		entries[1], err = encode(KernelPattern{CodeBase: 2, Count: MaxRegexStates + 1})
		if err != nil {
			t.Fatal(err)
		}
		publish(t, entries)
		if got := run(t, 1, nil); got != -1 {
			t.Fatal("513-state program accepted", got)
		}
		entries[1], err = encode(KernelPattern{CodeBase: 2, Count: 2})
		if err != nil {
			t.Fatal(err)
		}
		entries[2], err = encode(KernelInstruction{Op: KernelAlt, Out: 0, Arg: 1})
		if err != nil {
			t.Fatal(err)
		}
		entries[3], err = encode(KernelInstruction{Op: KernelMatch})
		if err != nil {
			t.Fatal(err)
		}
		publish(t, entries)
		if got := run(t, 1, nil); got != 1 {
			t.Fatal("epsilon cycle did not terminate", got)
		}
		if got := run(t, 1, []byte("not-empty")); got != 0 {
			t.Fatal("substring match accepted", got)
		}
	})
}
