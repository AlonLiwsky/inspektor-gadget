// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// This is only a load check of the disposable current-task enrollment cut.
// Its PID request is synthetic, not a trusted runtime witness, and loading
// disarmed cannot prove callback execution or initial TASK lifecycle safety.
func TestOpaqueInitialTaskDiagnosticKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_INITIAL_TASK_DIAGNOSTIC_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_INITIAL_TASK_DIAGNOSTIC_OBJECT")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	request := spec.Maps["opaque_initial_request"]
	consumed := spec.Maps["opaque_initial_consumed"]
	if request == nil || request.Type != ebpf.Array || request.KeySize != 4 ||
		request.ValueSize != 24 || request.MaxEntries != 1 ||
		request.Flags != unix.BPF_F_RDONLY_PROG ||
		consumed == nil || consumed.Type != ebpf.Array ||
		consumed.KeySize != 4 || consumed.ValueSize != 4 ||
		consumed.MaxEntries != 1 || consumed.Flags != unix.BPF_F_RDONLY {
		t.Fatalf("invalid disposable initial-task maps: request=%+v consumed=%+v", request, consumed)
	}
	selected := map[string]*ebpf.ProgramSpec{}
	for name, kind := range map[string]ebpf.ProgramType{
		"opaque_real_live_bootstrap_control":        ebpf.SchedCLS,
		"opaque_real_owner_initial_task_diagnostic": ebpf.LSM,
	} {
		program := spec.Programs[name]
		if program == nil || program.Type != kind {
			t.Fatalf("missing typed diagnostic %s: %+v", name, program)
		}
		selected[name] = program
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for disarmed verifier load")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec.Programs = selected
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("initial-task diagnostic verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	var gotRequest [24]byte
	if err := collection.Maps["opaque_initial_request"].Lookup(uint32(0), &gotRequest); err != nil ||
		gotRequest != ([24]byte{}) {
		t.Fatalf("request loaded armed: %x %v", gotRequest, err)
	}
	var used uint32
	if err := collection.Maps["opaque_initial_consumed"].Lookup(uint32(0), &used); err != nil || used != 0 {
		t.Fatalf("request loaded consumed: %d %v", used, err)
	}
}
