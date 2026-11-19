// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Source-shape prerequisite only: the recovered opaque TASK hooks must be
// inert when their real shared-node configuration is absent. No synthetic
// bootstrap or test-only gate may be present. This does not authorize host
// admission, native activation, exec enforcement, or Ready.
func TestOpaqueRealNativeConfigGateKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_NATIVE_CONFIG_GATE_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_NATIVE_CONFIG_GATE_OBJECT for isolated native-config candidate")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{
		"opaque_real_owner_child_gate", "opaque_real_live_bootstrap_gate",
		"opaque_real_owner_policy_witness", "se_tasks", "se_invocations",
		"se_zero_tasks", "se_zero_invocations", "se_task_sequences", "se_admin",
	} {
		if spec.Maps[name] != nil {
			t.Fatalf("native-config candidate retained forbidden map %s", name)
		}
	}
	for name := range spec.Maps {
		if strings.HasPrefix(name, "opaque_real_live_") {
			t.Fatalf("native-config candidate retained bootstrap map %s", name)
		}
	}
	configuration := spec.Maps["se_configuration"]
	if configuration == nil || configuration.Type != ebpf.Array ||
		configuration.KeySize != 4 || configuration.ValueSize != 56 ||
		configuration.MaxEntries != 1 || configuration.Flags != unix.BPF_F_RDONLY_PROG {
		t.Fatalf("invalid native configuration map: %+v", configuration)
	}
	names := []string{
		"opaque_real_owner_child_source_candidate",
		"opaque_real_owner_child_target_candidate",
		"opaque_real_owner_child_final_free_candidate",
	}
	selected := make(map[string]*ebpf.ProgramSpec, len(names))
	for _, name := range names {
		program := spec.Programs[name]
		if program == nil || program.Type != ebpf.LSM {
			t.Fatalf("missing native-config TASK hook %s: %+v", name, program)
		}
		selected[name] = program
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for isolated verifier/attach check")
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
			t.Logf("native-config TASK verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	config, err := collection.Maps["se_configuration"].LookupBytes(uint32(0))
	if err != nil || len(config) != 56 {
		t.Fatalf("zero native configuration: len=%d err=%v", len(config), err)
	}
	for _, b := range config {
		if b != 0 {
			t.Fatal("native configuration unexpectedly armed")
		}
	}
	if err := collection.Maps["se_configuration"].Freeze(); err != nil {
		t.Fatal(err)
	}
	free, err := link.AttachLSM(link.LSMOptions{
		Program: collection.Programs["opaque_real_owner_child_final_free_candidate"],
	})
	if err != nil {
		t.Fatal(err)
	}
	defer free.Close()
	alloc, err := link.AttachLSM(link.LSMOptions{
		Program: collection.Programs["opaque_real_owner_child_source_candidate"],
	})
	if err != nil {
		t.Fatal(err)
	}
	defer alloc.Close()
	if err := exec.Command("/bin/true").Run(); err != nil {
		t.Fatalf("unconfigured hooks disrupted ordinary child: %v", err)
	}
	accounts := collection.Maps["se_opaque_accounts"]
	if accounts == nil {
		t.Fatal("missing opaque TASK account")
	}
	for slot := uint32(0); slot < 2; slot++ {
		raw, err := accounts.LookupBytes(slot)
		if err != nil || len(raw) < 12 ||
			binary.LittleEndian.Uint32(raw[4:8]) != 0 ||
			binary.LittleEndian.Uint32(raw[8:12]) != 0 {
			t.Fatalf("unconfigured TASK account %d mutated: raw=%x err=%v", slot, raw, err)
		}
	}
	var physical, locator uint64
	iter := collection.Maps["se_opaque_keys"].Iterate()
	if iter.Next(&physical, &locator) || iter.Err() != nil {
		t.Fatalf("unconfigured hooks published TASK key: physical=%#x locator=%#x err=%v", physical, locator, iter.Err())
	}
}

// A load-only source-composition gate. It proves neither policy enforcement
// nor native readiness; the diagnostic gate must remain zero and no link is
// attached. In particular, this cannot substitute for admitted-kernel churn.
func TestOpaqueRealOwnerChildCandidateKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_REAL_CHILD_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_REAL_CHILD_OBJECT to the compiled candidate")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	source := spec.Programs["opaque_real_owner_child_source_candidate"]
	target := spec.Programs["opaque_real_owner_child_target_candidate"]
	finalFree := spec.Programs["opaque_real_owner_child_final_free_candidate"]
	for name, program := range map[string]*ebpf.ProgramSpec{
		"source": source, "target": target,
	} {
		if program == nil || program.Type != ebpf.LSM || program.AttachTo != "task_alloc" {
			t.Fatalf("missing typed %s callback: %+v", name, program)
		}
	}
	if finalFree == nil || finalFree.Type != ebpf.LSM || finalFree.AttachTo != "task_free" {
		t.Fatalf("missing typed final-free callback: %+v", finalFree)
	}
	gate := spec.Maps["opaque_real_owner_child_gate"]
	if gate == nil || gate.Type != ebpf.Array || gate.KeySize != 4 ||
		gate.ValueSize != 4 || gate.MaxEntries != 1 ||
		gate.Flags != unix.BPF_F_RDONLY_PROG {
		t.Fatalf("invalid default-inert gate: %+v", gate)
	}
	for _, forbidden := range []string{
		"se_tasks", "se_invocations",
		"writer_probe_route", "writer_probe_snapshots",
		"opaque_lifecycle_policy_object", "opaque_lifecycle_gate",
	} {
		if spec.Maps[forbidden] != nil {
			t.Fatalf("mixed or synthetic owner map %s", forbidden)
		}
	}
	targets := spec.Maps["opaque_real_owner_child_targets"]
	if targets == nil || targets.Type != ebpf.ProgramArray ||
		targets.KeySize != 4 || targets.ValueSize != 4 || targets.MaxEntries != 1 {
		t.Fatalf("invalid isolated continuation target map: %+v", targets)
	}
	if len(spec.Maps) != 30 {
		t.Fatalf("expected 14 opaque, 14 real-control and two diagnostic maps; got %d", len(spec.Maps))
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for load-only verifier check")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{
		"opaque_real_owner_child_source_candidate":     source,
		"opaque_real_owner_child_target_candidate":     target,
		"opaque_real_owner_child_final_free_candidate": finalFree,
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("child candidate verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	var armed uint32
	if err := collection.Maps["opaque_real_owner_child_gate"].Lookup(uint32(0), &armed); err != nil || armed != 0 {
		t.Fatalf("child candidate gate must load disarmed: armed=%d err=%v", armed, err)
	}
	t.Log("real-route child source, target and final-free loaded without attachment")
}

// The recovered-control variant must load its complete authorization cohort,
// not make TASK_STORAGE disappear in a one-off collection loader. This is
// still a disarmed, unattached source-composition test, not Ready proof.
func TestOpaqueRealOwnerChildRecoveredCandidateKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_REAL_CHILD_RECOVERY_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_REAL_CHILD_RECOVERY_OBJECT to the recovered candidate")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Maps) != 40 || spec.Maps["se_admin"] != nil || len(spec.Programs) != 9 {
		t.Fatalf("unexpected recovered cohort: maps=%d programs=%d admin=%v",
			len(spec.Maps), len(spec.Programs), spec.Maps["se_admin"])
	}
	for _, name := range []string{
		"se_rm_configuration", "se_rm_guardian_request",
		"se_rm_admin_request", "se_rm_control", "se_rm_guardian_receipt",
		"se_rm_admin_receipt",
	} {
		if spec.Maps[name] == nil {
			t.Fatalf("missing recovered authorization map %s", name)
		}
	}
	for name, want := range map[string]struct {
		valueSize uint32
		flags     uint32
	}{
		"se_pool_reap_request": {64, unix.BPF_F_RDONLY_PROG},
		"se_pool_reap_control": {64, unix.BPF_F_RDONLY},
		"se_pool_reap_receipt": {128, unix.BPF_F_RDONLY},
	} {
		m := spec.Maps[name]
		if m == nil || m.Type != ebpf.Array || m.KeySize != 4 ||
			m.ValueSize != want.valueSize || m.MaxEntries != 1 ||
			m.Flags != want.flags {
			t.Fatalf("invalid recovered reaper wire map %s: %+v", name, m)
		}
	}
	stage := spec.Maps["se_pool_reap_stage"]
	if stage == nil || stage.Type != ebpf.Array || stage.KeySize != 4 ||
		stage.MaxEntries != 1 || stage.Flags != unix.BPF_F_RDONLY {
		t.Fatalf("invalid recovered reaper stage: %+v", stage)
	}
	chain := spec.Maps["se_pool_reap_chain"]
	if chain == nil || chain.Type != ebpf.ProgramArray || chain.KeySize != 4 ||
		chain.ValueSize != 4 || chain.MaxEntries != 1 {
		t.Fatalf("invalid recovered reaper chain: %+v", chain)
	}
	for name, target := range map[string]string{
		"opaque_real_owner_child_source_candidate":     "task_alloc",
		"opaque_real_owner_child_target_candidate":     "task_alloc",
		"opaque_real_owner_child_final_free_candidate": "task_free",
	} {
		program := spec.Programs[name]
		if program == nil || program.Type != ebpf.LSM || program.AttachTo != target {
			t.Fatalf("invalid recovered callback %s: %+v", name, program)
		}
	}
	for _, name := range []string{
		"se_rm_guardian", "se_rm_administrator", "se_command",
		"se_pool_reaper_entry", "se_pool_reaper_chunk",
	} {
		if program := spec.Programs[name]; program == nil || program.Type != ebpf.SchedCLS {
			t.Fatalf("invalid TEST_RUN-only recovered endpoint %s: %+v", name, program)
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for complete collection load")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("recovered candidate verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	var armed uint32
	if err := collection.Maps["opaque_real_owner_child_gate"].Lookup(uint32(0), &armed); err != nil || armed != 0 {
		t.Fatalf("recovered candidate must load disarmed: armed=%d err=%v", armed, err)
	}
	var controlBefore, controlAfter [64]byte
	var receiptBefore, receiptAfter [128]byte
	if err := collection.Maps["se_pool_reap_control"].Lookup(uint32(0), &controlBefore); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["se_pool_reap_receipt"].Lookup(uint32(0), &receiptBefore); err != nil {
		t.Fatal(err)
	}
	if _, _, err := collection.Programs["se_pool_reaper_entry"].Test(make([]byte, 64)); err != nil {
		t.Fatalf("unconfigured reaper TEST_RUN: %v", err)
	}
	if err := collection.Maps["se_pool_reap_control"].Lookup(uint32(0), &controlAfter); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["se_pool_reap_receipt"].Lookup(uint32(0), &receiptAfter); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(controlBefore[:], controlAfter[:]) ||
		!bytes.Equal(receiptBefore[:], receiptAfter[:]) {
		t.Fatal("unconfigured reaper must not reserve BUSY or publish a receipt")
	}
	t.Log("complete recovered-control and real-map child collection loaded without attachment")
}

// The optional diagnostic callback must make the reader begin/finish path
// verifier-visible. This disarmed load does not prove attached exec behavior
// or authorize selecting the probe as an enforcement image.
func TestOpaqueRealOwnerReaderBeginProbeKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_REAL_READER_PROBE_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_REAL_READER_PROBE_OBJECT to the probe object")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	probe := spec.Programs["opaque_real_owner_reader_begin_probe"]
	if probe == nil || probe.Type != ebpf.LSM || probe.AttachTo != "bprm_check_security" {
		t.Fatalf("missing diagnostic bprm callback: %+v", probe)
	}
	if len(spec.Maps) != 40 || len(spec.Programs) != 10 {
		t.Fatalf("unexpected probe cohort: maps=%d programs=%d", len(spec.Maps), len(spec.Programs))
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for verifier load")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{
		"opaque_real_owner_reader_begin_probe": probe,
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("reader probe verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	var armed uint32
	if err := collection.Maps["opaque_real_owner_child_gate"].Lookup(uint32(0), &armed); err != nil || armed != 0 {
		t.Fatalf("diagnostic gate must load disarmed: armed=%d err=%v", armed, err)
	}
}

// Load both sides of the optional reader-success diagnostic on one kernel.
// The gate stays zero and neither hook is linked: failed-exec termination and
// initial trusted TASK bootstrap are not yet part of this variant.
func TestOpaqueRealOwnerReaderSuccessProbeKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_REAL_READER_SUCCESS_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_REAL_READER_SUCCESS_OBJECT to the probe object")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	begin := spec.Programs["opaque_real_owner_reader_begin_probe"]
	success := spec.Programs["opaque_real_owner_reader_success_probe"]
	reaperEntry := spec.Programs["se_pool_reaper_entry"]
	reaperChunk := spec.Programs["se_pool_reaper_chunk"]
	if begin == nil || begin.Type != ebpf.LSM || begin.AttachTo != "bprm_check_security" ||
		success == nil || success.Type != ebpf.Tracing || success.AttachTo != "sched_process_exec" ||
		reaperEntry == nil || reaperEntry.Type != ebpf.SchedCLS ||
		reaperChunk == nil || reaperChunk.Type != ebpf.SchedCLS ||
		len(spec.Maps) != 41 || len(spec.Programs) != 11 {
		t.Fatalf("unexpected reader-success cohort: maps=%d programs=%d begin=%+v success=%+v reaper=%+v/%+v",
			len(spec.Maps), len(spec.Programs), begin, success, reaperEntry, reaperChunk)
	}
	mailbox := spec.Maps["se_exec_terminal_receipts"]
	if mailbox == nil || mailbox.Type != ebpf.Hash || mailbox.KeySize != 8 ||
		mailbox.ValueSize != 64 || mailbox.MaxEntries != 128 ||
		mailbox.Flags != unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY {
		t.Fatalf("invalid plain terminal receipt mailbox: %+v", mailbox)
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for verifier load")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{
		"opaque_real_owner_reader_begin_probe":   begin,
		"opaque_real_owner_reader_success_probe": success,
		"se_pool_reaper_entry":                   reaperEntry,
		"se_pool_reaper_chunk":                   reaperChunk,
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("reader-success verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	var armed uint32
	if err := collection.Maps["opaque_real_owner_child_gate"].Lookup(uint32(0), &armed); err != nil || armed != 0 {
		t.Fatalf("reader-success gate must load disarmed: armed=%d err=%v", armed, err)
	}
}

// The default-inert TC diagnostic makes receipt-authenticated normal
// charged-WORK completion verifier-reachable. It is not attached or selected.
func TestOpaqueRealOwnerPreparedWorkCompletionProbeKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_PREPARED_WORK_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_PREPARED_WORK_OBJECT to the opt-in probe object")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	probe := spec.Programs["opaque_real_owner_work_completion_probe"]
	retry := spec.Programs["opaque_real_owner_work_retry_probe"]
	begin := spec.Programs["opaque_real_owner_reader_begin_probe"]
	success := spec.Programs["opaque_real_owner_reader_success_probe"]
	if probe == nil || probe.Type != ebpf.SchedCLS ||
		retry == nil || retry.Type != ebpf.SchedCLS ||
		begin == nil || begin.Type != ebpf.LSM || begin.AttachTo != "bprm_check_security" ||
		success == nil || success.Type != ebpf.Tracing || success.AttachTo != "sched_process_exec" ||
		len(spec.Maps) != 43 || len(spec.Programs) != 13 {
		t.Fatalf("unexpected prepared-WORK diagnostic cohort: maps=%d programs=%d probe=%+v retry=%+v begin=%+v success=%+v",
			len(spec.Maps), len(spec.Programs), probe, retry, begin, success)
	}
	gate := spec.Maps["opaque_real_owner_work_completion_gate"]
	if gate == nil || gate.Type != ebpf.Array || gate.KeySize != 4 ||
		gate.ValueSize != 4 || gate.MaxEntries != 1 ||
		gate.Flags != unix.BPF_F_RDONLY_PROG {
		t.Fatalf("invalid prepared-WORK gate: %+v", gate)
	}
	selector := spec.Maps["opaque_real_owner_work_completion_selector"]
	if selector == nil || selector.Type != ebpf.Array ||
		selector.KeySize != 4 || selector.ValueSize != 8 ||
		selector.MaxEntries != 1 || selector.Flags != unix.BPF_F_RDONLY_PROG {
		t.Fatalf("invalid prepared-WORK selector: %+v", selector)
	}
	receipts := spec.Maps["se_exec_terminal_receipts"]
	if receipts == nil || receipts.Type != ebpf.Hash ||
		receipts.KeySize != 8 || receipts.ValueSize != 64 ||
		receipts.MaxEntries != 128 ||
		receipts.Flags != unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY {
		t.Fatalf("invalid BPF-only terminal receipts: %+v", receipts)
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for verifier load")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{
		"opaque_real_owner_work_completion_probe": probe,
		"opaque_real_owner_work_retry_probe":      retry,
		"opaque_real_owner_reader_begin_probe":    begin,
		"opaque_real_owner_reader_success_probe":  success,
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("prepared-WORK verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	var armed uint32
	if err := collection.Maps["opaque_real_owner_work_completion_gate"].Lookup(uint32(0), &armed); err != nil || armed != 0 {
		t.Fatalf("prepared-WORK gate must load disarmed: armed=%d err=%v", armed, err)
	}
	if _, _, err := collection.Programs["opaque_real_owner_work_completion_probe"].Test(make([]byte, 64)); err != nil {
		t.Fatalf("disarmed prepared-WORK TEST_RUN: %v", err)
	}
	if _, _, err := collection.Programs["opaque_real_owner_work_retry_probe"].Test(make([]byte, 64)); err != nil {
		t.Fatalf("disarmed postcommit retry TEST_RUN: %v", err)
	}
	var selected uint64
	if err := collection.Maps["opaque_real_owner_work_completion_selector"].Lookup(uint32(0), &selected); err != nil || selected != 0 {
		t.Fatalf("prepared-WORK selector must load empty: selected=%d err=%v", selected, err)
	}
}

// The exact-build outer-return variant must load the real source-owned
// receipt, charged-WORK consumer and both BPF-only frame maps together. It
// remains disarmed and unattached; loading is not live terminal proof.
func TestOpaqueRealOwnerFinalFailureProbeKernelLoad(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_FINAL_FAILURE_OBJECT")
	if object == "" {
		t.Skip("set IG_OPAQUE_FINAL_FAILURE_OBJECT to the opt-in probe object")
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.Maps) != 45 || len(spec.Programs) != 17 {
		t.Fatalf("unexpected final-failure cohort: maps=%d programs=%d",
			len(spec.Maps), len(spec.Programs))
	}
	for name, size := range map[string]uint32{
		"se_failure_outer_frames":   64,
		"se_failure_handler_frames": 16,
	} {
		m := spec.Maps[name]
		if m == nil || m.Type != ebpf.Hash || m.KeySize != 8 ||
			m.ValueSize != size || m.MaxEntries != 128 ||
			m.Flags != unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY {
			t.Fatalf("invalid BPF-only failure frame %s: %+v", name, m)
		}
	}
	selected := map[string]*ebpf.ProgramSpec{}
	for _, name := range []string{
		"opaque_real_owner_reader_begin_probe",
		"opaque_real_owner_reader_success_probe",
		"opaque_real_owner_work_completion_probe",
		"opaque_real_owner_work_retry_probe",
		"opaque_real_owner_failure_outer_enter",
		"opaque_real_owner_failure_handler_enter",
		"opaque_real_owner_failure_handler_exit",
		"opaque_real_owner_failure_outer_exit",
	} {
		p := spec.Programs[name]
		if p == nil {
			t.Fatalf("missing final-failure program %s", name)
		}
		selected[name] = p
	}
	for _, name := range []string{
		"opaque_real_owner_failure_outer_enter",
		"opaque_real_owner_failure_handler_enter",
		"opaque_real_owner_failure_handler_exit",
		"opaque_real_owner_failure_outer_exit",
	} {
		if selected[name].Type != ebpf.Kprobe {
			t.Fatalf("non-kprobe final-failure program %s: %+v", name, selected[name])
		}
	}
	if os.Geteuid() != 0 {
		t.Skip("root required for verifier load")
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
			t.Logf("final-failure verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	var gate uint32
	if err := collection.Maps["opaque_real_owner_child_gate"].Lookup(uint32(0), &gate); err != nil || gate != 0 {
		t.Fatalf("final-failure source must load disarmed: gate=%d err=%v", gate, err)
	}
	if err := collection.Maps["opaque_real_owner_work_completion_gate"].Lookup(uint32(0), &gate); err != nil || gate != 0 {
		t.Fatalf("final-failure consumer must load disarmed: gate=%d err=%v", gate, err)
	}
	for _, name := range []string{
		"opaque_real_owner_work_completion_probe",
		"opaque_real_owner_work_retry_probe",
	} {
		if _, _, err := collection.Programs[name].Test(make([]byte, 64)); err != nil {
			t.Fatalf("disarmed %s TEST_RUN: %v", name, err)
		}
	}
}
