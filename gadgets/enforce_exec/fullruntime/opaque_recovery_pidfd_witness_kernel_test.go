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

// Verifies the complete disarmed recovered-control/witness cohort loads. It
// does not prove REGISTER/ARM/CAPTURE/READY/COMMIT, an authorized callback, or
// safe initial TASK publication; those require an actual S/G/A integration.
func TestRecoveryPidfdWitnessKernelLoad(t *testing.T) {
	object := os.Getenv("IG_RECOVERY_PIDFD_WITNESS_OBJECT")
	if object == "" {
		t.Skip("set IG_RECOVERY_PIDFD_WITNESS_OBJECT")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Maps) != 11 || len(spec.Programs) != 5 {
		t.Fatalf("unexpected diagnostic cohort: maps=%d programs=%d", len(spec.Maps), len(spec.Programs))
	}
	for name, want := range map[string]struct {
		value, flags uint32
	}{
		"se_rm_configuration":        {32, unix.BPF_F_RDONLY_PROG},
		"se_rm_guardian_request":     {64, unix.BPF_F_RDONLY_PROG},
		"se_rm_admin_request":        {40, unix.BPF_F_RDONLY_PROG},
		"se_rm_control":              {192, unix.BPF_F_RDONLY},
		"se_rm_guardian_receipt":     {96, unix.BPF_F_RDONLY},
		"se_rm_admin_receipt":        {96, unix.BPF_F_RDONLY},
		"recovery_pidfd_request":     {32, unix.BPF_F_RDONLY_PROG},
		"recovery_pidfd_consumed":    {4, unix.BPF_F_RDONLY},
		"recovery_pidfd_result":      {32, unix.BPF_F_RDONLY},
		"recovery_alloc_observation": {48, unix.BPF_F_RDONLY},
		"recovery_alloc_count":       {4, unix.BPF_F_RDONLY},
	} {
		m := spec.Maps[name]
		maxEntries := uint32(1)
		if name == "recovery_alloc_observation" {
			maxEntries = 32
		}
		if m == nil || m.Type != ebpf.Array || m.KeySize != 4 ||
			m.ValueSize != want.value || m.MaxEntries != maxEntries ||
			m.Flags != want.flags {
			t.Fatalf("invalid diagnostic map %s: %+v", name, m)
		}
	}
	for name, target := range map[string]string{
		"recovery_pidfd_task_alloc": "task_alloc",
		"recovery_pidfd_task_free":  "task_free",
		"recovery_pidfd_task_kill":  "task_kill",
	} {
		p := spec.Programs[name]
		if p == nil || p.Type != ebpf.LSM || p.AttachTo != target {
			t.Fatalf("invalid diagnostic LSM %s: %+v", name, p)
		}
	}
	for _, name := range []string{"se_rm_guardian", "se_rm_administrator"} {
		p := spec.Programs[name]
		if p == nil || p.Type != ebpf.SchedCLS {
			t.Fatalf("missing recovered endpoint %s: %+v", name, p)
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for disarmed kernel load")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("recovered pidfd verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	var request [32]byte
	if err := collection.Maps["recovery_pidfd_request"].Lookup(uint32(0), &request); err != nil || request != ([32]byte{}) {
		t.Fatalf("witness request loaded armed: %x %v", request, err)
	}
	var consumed uint32
	if err := collection.Maps["recovery_pidfd_consumed"].Lookup(uint32(0), &consumed); err != nil || consumed != 0 {
		t.Fatalf("witness loaded consumed: %d %v", consumed, err)
	}
}
