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

// Disarmed verifier load only. Live authorization, TASK publication, and
// reclamation require a separate attached S/G/A process-topology test.
func TestOpaqueRecoveredInitialTaskDiagnosticKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_RECOVERED_INITIAL_TASK_DIAGNOSTIC_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_RECOVERED_INITIAL_TASK_DIAGNOSTIC_OBJECT")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	request := spec.Maps["opaque_recovered_initial_request"]
	consumed := spec.Maps["opaque_recovered_initial_consumed"]
	stage := spec.Maps["opaque_recovered_initial_stage"]
	if request == nil || request.Type != ebpf.Array || request.KeySize != 4 ||
		request.ValueSize != 40 || request.MaxEntries != 1 ||
		request.Flags != unix.BPF_F_RDONLY_PROG ||
		consumed == nil || consumed.Type != ebpf.Array || consumed.KeySize != 4 ||
		consumed.ValueSize != 4 || consumed.MaxEntries != 1 ||
		consumed.Flags != unix.BPF_F_RDONLY ||
		stage == nil || stage.Type != ebpf.Array || stage.KeySize != 4 ||
		stage.ValueSize != 4 || stage.MaxEntries != 1 ||
		stage.Flags != unix.BPF_F_RDONLY {
		t.Fatalf("invalid recovered initial TASK maps: request=%+v consumed=%+v stage=%+v", request, consumed, stage)
	}
	name := "opaque_real_owner_recovered_initial_task_diagnostic"
	program := spec.Programs[name]
	if program == nil || program.Type != ebpf.LSM {
		t.Fatalf("missing typed recovered initial TASK program: %+v", program)
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for disarmed verifier load")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{name: program}
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
	var gotRequest [40]byte
	if err := collection.Maps["opaque_recovered_initial_request"].Lookup(uint32(0), &gotRequest); err != nil ||
		gotRequest != ([40]byte{}) {
		t.Fatalf("request loaded armed: %x %v", gotRequest, err)
	}
	for _, name := range []string{"opaque_recovered_initial_consumed", "opaque_recovered_initial_stage"} {
		var value uint32
		if err := collection.Maps[name].Lookup(uint32(0), &value); err != nil || value != 0 {
			t.Fatalf("%s loaded nonzero: %d %v", name, value, err)
		}
	}
}
