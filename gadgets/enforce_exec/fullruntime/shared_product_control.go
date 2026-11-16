// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedProductCommands are the product publisher's authenticated syscall
// commands (G019 M4 design sections 3, 4.0 and 13). Each one checks that the
// calling thread's se_admin task storage holds the node nonce.
var sharedProductCommands = []string{
	"opaque_real_policy_stage",
	"opaque_real_route_publish",
	"opaque_real_route_withdraw",
	"opaque_real_route_recycle",
	// G019 gap 3: drop a RETIRING record once its holders are gone.
	"opaque_real_route_drop_retired",
	// G020: the image index commands (BEGIN/KEYS/SEAL/ABORT/DELETE/
	// RECLAIM/INSPECT, bpf/opaque_real_owner_product_image.h).
	sharedImageCommand,
	"opaque_real_adopt_verify",
	"opaque_real_adopt_task",
	"opaque_real_adopt_finish",
	"opaque_real_adopt_quarantine",
}

// sharedProductRouteAnchorBytes is the product se_route_anchor: the 104-byte
// anchor plus the adopting and adopting_faults words (M4 B1) and the two
// per-record holder mirrors (G019 gap 3, struct se_route_rec, 32 B each).
const sharedProductRouteAnchorBytes = 176

// sharedProductAdminGeometry is the exact shape of the two authority maps the
// product control writes and freezes. The product image has no se_commands,
// se_receipts or se_command (they belong to the protocol control).
var sharedProductAdminGeometry = map[string]operators.NativeMapResource{
	"se_configuration": {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 56, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG},
	"se_admin":         {Type: uint32(ebpf.TaskStorage), KeySize: 4, ValueSize: 8, Flags: unix.BPF_F_NO_PREALLOC},
	// struct opaque_real_cmd_receipt {node_cookie, sequence}: the last
	// sequence the node consumed (bpf/opaque_real_owner_product_publisher.h).
	"opaque_real_cmd_receipt": {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 16, MaxEntries: 1, Flags: unix.BPF_F_RDONLY},
}

// sharedProductMapGeometry is the exact geometry of the maps the product
// publisher reads or that size its commands (review M-4): the per-binding
// adoption state, the adopted set (one entry per TASK), the 12-cell
// fail-closed witness and its attempts, the policy objects and arena cells
// the stager writes, and the verdict event ring.
func sharedProductMapGeometry(p SharedProfile) (map[string]operators.NativeMapResource, error) {
	admission, err := p.Validate()
	if err != nil {
		return nil, err
	}
	if admission.PolicyObjects > math.MaxUint32 || admission.ArenaCells > math.MaxUint32 || p.Tasks > math.MaxUint32 {
		return nil, fmt.Errorf("shared product geometry exceeds uint32")
	}
	array := func(size, count uint32) operators.NativeMapResource {
		return operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: size, MaxEntries: count, Flags: unix.BPF_F_RDONLY}
	}
	return map[string]operators.NativeMapResource{
		"opaque_real_adopt_state": array(sharedProductAdoptStateBytes, uint32(p.Bindings)),
		// struct opaque_real_adopted_key {task; slot, reserved} -> {cookie, locator}.
		"opaque_real_adopted":           {Type: uint32(ebpf.Hash), KeySize: 16, ValueSize: 16, MaxEntries: uint32(p.Tasks), Flags: unix.BPF_F_RDONLY},
		"opaque_real_attempts":          array(8, FailClosedRateAttempts),
		"opaque_real_fail_closed_rates": array(8, FailClosedRateCounters),
		// G019 gap 4 (review H1): the interpreter continuation's
		// continued passes (depth 1..5) and refusal reasons.
		InterpContinuationStatsMap: array(8, InterpContinuationStats),
		// G019 gaps 1 and 2: the birth-park witness.
		BirthParkStatsMap: array(8, BirthParkStats),
		// G020: the per-pass fact witness (full/shared_pass_facts.h).
		FactStatsMap: array(8, FactStats),
		// struct er_work, the adoption's per-CPU role scratch (BTF: 536 B).
		"opaque_real_adopt_roles": {Type: uint32(ebpf.PerCPUArray), KeySize: 4, ValueSize: 536, MaxEntries: 1},
		"se_objects":              array(sharedProductObjectBytes, uint32(admission.PolicyObjects)),
		"se_arena":                array(fullpolicy.KernelBlobSize, uint32(admission.ArenaCells)),
		// G020: the image index (sharedProductImageGeometry).
		sharedImageKeysMap:     {Type: uint32(ebpf.Hash), KeySize: 24, ValueSize: 1, MaxEntries: uint32(p.Images), Flags: unix.BPF_F_RDONLY},
		sharedImageBindingsMap: array(sharedImageBindingBytes, uint32(p.Bindings)),
		sharedImageWitnessMap:  {Type: uint32(ebpf.PerCPUArray), KeySize: 4, ValueSize: sharedImageWitnessBytes, MaxEntries: 1, Flags: unix.BPF_F_RDONLY},
		// The KEYS/DELETE loop state (struct real_owner_image_loop), kept
		// off the BPF stack.
		sharedImageScratchMap: {Type: uint32(ebpf.PerCPUArray), KeySize: 4, ValueSize: sharedImageScratchBytes, MaxEntries: 1, Flags: unix.BPF_F_RDONLY},
		// G020: the node-wide verdict event ring (SharedProfile.VerdictRing).
		SharedVerdictRingMap: {Type: uint32(ebpf.RingBuf), MaxEntries: uint32(p.verdictRing())},
	}, nil
}

// sharedProductHeaderBytes is struct opaque_real_cmd_header
// {node_cookie, nonce, sequence}, the prefix of every product request.
const sharedProductHeaderBytes = 24

// validateSharedProductControl is the product control's admission: the
// TASK/WORK/exit geometry of the profile (validateSharedCandidateGeometry),
// the exact authority maps, the per-binding route and binding maps, and every
// product command as an enabled, unattached syscall program. Nothing is
// adapted; any difference refuses.
// sharedProductTailCalls are the product object's tail-call slots, each with
// its exact target: the birth constructor (task_alloc), the ten exec
// verdict graph stages, and (G019 gap 4) the two static-class interpreter
// continuation entries. The eBPF operator installs them at load, before any
// hook attaches (metadata tail_calls, NativeResources.TailCalls), and freezes
// the arrays. Without them the hooks never reach a verdict (G019 chain14).
var sharedProductTailCalls = []operators.NativeTailCall{
	{Map: "opaque_real_owner_child_targets", Index: 0, Program: "opaque_real_owner_child_target_candidate"},
	{Map: "opaque_real_prepare_strict", Index: 0, Program: "opaque_real_owner_prepare_strict"},
	{Map: "opaque_real_prepare_audit", Index: 0, Program: "opaque_real_owner_prepare_audit"},
	{Map: "opaque_real_stage_strict", Index: 0, Program: "opaque_real_owner_stage_strict"},
	{Map: "opaque_real_stage_audit", Index: 0, Program: "opaque_real_owner_stage_audit"},
	{Map: "opaque_real_rule_strict", Index: 0, Program: "opaque_real_owner_rule_strict"},
	{Map: "opaque_real_rule_audit", Index: 0, Program: "opaque_real_owner_rule_audit"},
	{Map: "opaque_real_policy_strict", Index: 0, Program: "opaque_real_owner_policy_strict"},
	{Map: "opaque_real_policy_audit", Index: 0, Program: "opaque_real_owner_policy_audit"},
	{Map: "opaque_real_finish_strict", Index: 0, Program: "opaque_real_owner_finish_strict"},
	{Map: "opaque_real_finish_audit", Index: 0, Program: "opaque_real_owner_finish_audit"},
	{Map: "opaque_real_continue_strict", Index: 0, Program: "opaque_real_owner_continue_strict"},
	{Map: "opaque_real_continue_audit", Index: 0, Program: "opaque_real_owner_continue_audit"},
}

// InterpContinuationStatsMap is the product object's interpreter
// continuation witness (G019 gap 4, review H1;
// ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE): one u64 per cell,
// RDONLY to userspace. Cells InterpContinuedDepth1..+4 count interpreter
// passes continued at exec_binprm depth 1..5; the others count each refusal
// reason, every one of which is also a FailClosedRateGap.
const (
	InterpContinuationStatsMap = "opaque_real_interp_stats"
	InterpContinuationStats    = 12
)

// Cells of InterpContinuationStatsMap (full/shared_exec_interp_continuation.h).
const (
	InterpContinuedDepth1 = iota // + depth - 1, depth 1..5
	_
	_
	_
	_
	InterpRefusedFrame     // receipt/failure-frame tuple, or claim release
	InterpRefusedClassify  // TASK open, reader not CONTINUE
	InterpRefusedRecover   // reader recovery or pinned snapshot
	InterpRefusedResume    // no exact suspended terminal WORK of the class
	InterpRefusedGraphMiss // continue or prepare tail call returned
	InterpRefusedDepth     // a pass beyond exec_binprm depth 5
	InterpRefusedRebind    // WORK reset, view, token, suspend or TASK close
)

// sharedProductCapsuleMaps are the exec-capsule store's maps and their
// value sizes (struct se_exec_capsule, struct se_exec_marker). The store is
// per-task kernel storage (user decision, G019 chain16): every task of the
// node has its own slot, so no tgid can fall outside it. An ARRAY store
// (the earlier pid_max-sized design, built with max_entries 1) degrades every
// exec whose tgid it cannot hold (se_cap_degrade: Strict denied, Audit
// allowed) and is never admitted.
// G019 gap 1: the birth park (struct se_birth_park) is per-task storage too.
var sharedProductCapsuleMaps = map[string]uint32{"se_exec_capsules": 104, "se_exec_markers": 16, sharedBirthParkMap: sharedBirthParkBytes}

// validateSharedProductCapsules requires each exec-capsule map to be
// BPF_MAP_TYPE_TASK_STORAGE of its exact value size.
func validateSharedProductCapsules(r *operators.NativeResources) error {
	for name, valueSize := range sharedProductCapsuleMaps {
		want := operators.NativeMapResource{Type: uint32(ebpf.TaskStorage), KeySize: 4, ValueSize: valueSize, Flags: unix.BPF_F_NO_PREALLOC}
		if m, ok := r.Maps[name]; !ok || m != want {
			return fmt.Errorf("product exec-capsule map %s is %+v, requires per-task storage %+v (an array store degrades every exec it cannot hold)", name, m, want)
		}
	}
	return nil
}

// sharedProductWorkSync is the synchronous WORK return witness
// (WorkSyncWitnessMap) every product object carries. G019 lead decision (b):
// the product object requires the synchronous return (#error in the source
// under SE_PRODUCT_NO_TEST_RUN), so its burst capacity is
// ConcurrentBirthCapacity(W, true); the non-sync branch is test-only.
var sharedProductWorkSync = operators.NativeMapResource{
	Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8, MaxEntries: workSyncCounters, Flags: unix.BPF_F_RDONLY,
}

// validateSharedProductWorkSync refuses a product object without the
// synchronous WORK return witness, or with another shape.
func validateSharedProductWorkSync(r *operators.NativeResources) error {
	if m, ok := r.Maps[WorkSyncWitnessMap]; !ok || m != sharedProductWorkSync {
		return fmt.Errorf("product object map %s is %+v, requires the synchronous WORK return witness %+v", WorkSyncWitnessMap, m, sharedProductWorkSync)
	}
	return nil
}

// sharedProductTestGateMaps may never exist in a product-publisher object:
// its hooks are armed only by the authenticated configuration
// (ENFORCE_EXEC_POOL_OPAQUE_NATIVE_CONFIG_GATE_CANDIDATE: se_profile_matches
// on se_configuration), never by a userspace-writable test gate.
var sharedProductTestGateMaps = []string{"opaque_real_owner_child_gate"}

// validateSharedProductNoTestGate refuses a product-publisher object that
// carries a test gate map (sharedProductTestGateMaps).
func validateSharedProductNoTestGate(r *operators.NativeResources) error {
	for _, name := range sharedProductTestGateMaps {
		if _, present := r.Maps[name]; present {
			return fmt.Errorf("product publisher object carries the test gate %s (requires the configuration gate)", name)
		}
	}
	return nil
}

// validateSharedProductTailCalls requires the declared tail calls to be
// exactly sharedProductTailCalls, every slot of every program array of the
// object declared (none left empty, none extra), and each target an
// existing, never-attached program.
func validateSharedProductTailCalls(r *operators.NativeResources) error {
	want := map[operators.NativeTailCall]bool{}
	for _, c := range sharedProductTailCalls {
		want[c] = true
	}
	got := map[operators.NativeTailCall]bool{}
	for _, c := range r.TailCalls {
		if got[c] {
			return fmt.Errorf("tail call %s[%d] declared twice", c.Map, c.Index)
		}
		got[c] = true
		if !want[c] {
			return fmt.Errorf("unreviewed tail call %s[%d] = %s", c.Map, c.Index, c.Program)
		}
	}
	slots := map[string]uint32{}
	for _, c := range sharedProductTailCalls {
		if !got[c] {
			return fmt.Errorf("tail call %s[%d] = %s not installed", c.Map, c.Index, c.Program)
		}
		m, ok := r.Maps[c.Map]
		if !ok || m.Type != uint32(ebpf.ProgramArray) || m.KeySize != 4 || m.ValueSize != 4 {
			return fmt.Errorf("tail call map %s is %+v, requires a program array", c.Map, m)
		}
		p, ok := r.Programs[c.Program]
		if !ok || p.Target != sharedProgramDisabled {
			return fmt.Errorf("tail call target %s missing or attached", c.Program)
		}
		slots[c.Map]++
	}
	for name, m := range r.Maps {
		if m.Type != uint32(ebpf.ProgramArray) {
			continue
		}
		if slots[name] != m.MaxEntries {
			return fmt.Errorf("program array %s has %d slots, %d installed", name, m.MaxEntries, slots[name])
		}
	}
	return nil
}

func validateSharedProductControl(p SharedProfile, r *operators.NativeResources) error {
	if err := validateSharedCandidateGeometry(p, r); err != nil {
		return err
	}
	// Revision is make-before-break (productCommander.revise stages into a
	// FREE object before the old one is released): with every binding
	// published, one policy object must still be free. The product source
	// asserts the same at compile time.
	admission, err := p.Validate()
	if err != nil {
		return err
	}
	// G020: the image index holds up to sharedImageLayersMax lower-layer
	// roots per binding, every binding's quota reserved in the node pool
	// (se_image_keys max_entries = Images = Bindings x 128, preallocated).
	if p.PerBinding.Images != sharedImageLayersMax || p.Images != p.Bindings*sharedImageLayersMax {
		return fmt.Errorf("shared product profile has %d image cells (%d per binding): the image index requires %d per binding and Images = Bindings x %d", p.Images, p.PerBinding.Images, sharedImageLayersMax, sharedImageLayersMax)
	}
	if admission.PolicyObjects <= p.Bindings {
		return fmt.Errorf("shared product profile has %d policy objects for %d bindings: revision needs at least one spare object (policy objects > bindings)", admission.PolicyObjects, p.Bindings)
	}
	if err := validateSharedProductNoTestGate(r); err != nil {
		return err
	}
	if err := validateSharedProductTailCalls(r); err != nil {
		return err
	}
	if err := validateSharedProductCapsules(r); err != nil {
		return err
	}
	if err := validateSharedProductWorkSync(r); err != nil {
		return err
	}
	for name, want := range sharedProductAdminGeometry {
		if got, ok := r.Maps[name]; !ok || got != want {
			return fmt.Errorf("shared product map %s is %+v, requires %+v", name, got, want)
		}
	}
	product, err := sharedProductMapGeometry(p)
	if err != nil {
		return err
	}
	for name, want := range product {
		if got, ok := r.Maps[name]; !ok || got != want {
			return fmt.Errorf("shared product map %s is %+v, requires %+v", name, got, want)
		}
	}
	bindings := uint32(p.Bindings)
	for name, valueSize := range map[string]uint32{"se_routes": sharedProductRouteAnchorBytes, "se_bindings": 0, "se_route_index": 8} {
		got, ok := r.Maps[name]
		if !ok || got.MaxEntries != bindings || (valueSize != 0 && got.ValueSize != valueSize) {
			return fmt.Errorf("shared product map %s is %+v, requires %d entries", name, got, bindings)
		}
	}
	for _, name := range sharedProductCommands {
		cmd, ok := r.Programs[name]
		if !ok || cmd.Type != uint32(ebpf.Syscall) || cmd.Target != "" {
			return fmt.Errorf("shared product command %s missing, disabled or attached", name)
		}
	}
	return nil
}

// sharedProductConfigMap is the se_configuration surface the product control
// uses: an initial-zero check, then the admin install's Put and Freeze.
type sharedProductConfigMap interface {
	sharedAdminMap
	Lookup(key, valueOut interface{}) error
}

// sharedCommandProgram runs one syscall command with a request context.
type sharedCommandProgram interface {
	Run(*ebpf.RunOptions) (uint32, error)
}

// sharedProductControl is the node's single product admin: one locked OS
// thread whose se_admin task storage holds the node nonce. Every product
// command runs on that thread.
type sharedProductControl struct {
	config   sharedNodeWire
	thread   *controlThread
	programs map[string]sharedCommandProgram
	// installed: the admin thread and the frozen configuration are in
	// place, so the configuration gate armed the hooks. Publication is
	// refused before it (BPF also refuses unless se_profile_matches).
	installed bool
	// sequence is the last sequence issued; owned by admin-thread jobs. BPF
	// consumes a sequence only when it authenticates the request, and
	// requires each one to exceed the last consumed, so gaps are harmless
	// and a sequence is never reused.
	sequence uint64
}

// newSharedProductControl validates the admitted product image, refuses an
// already-initialized configuration, then installs the admin thread
// (installSharedAdmin: se_admin and se_configuration written and frozen).
// The returned control is retained on error so the caller can close it.
func newSharedProductControl(ctx context.Context, p SharedProfile, manifest *operators.NativeResources, admin sharedAdminMap, configuration sharedProductConfigMap, programs map[string]sharedCommandProgram) (*sharedProductControl, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateSharedProductControl(p, manifest); err != nil {
		return nil, err
	}
	for _, name := range sharedProductCommands {
		if programs[name] == nil {
			return nil, fmt.Errorf("shared product command %s was not published", name)
		}
	}
	admission, err := p.Validate()
	if err != nil {
		return nil, err
	}
	if admin == nil || configuration == nil {
		return nil, fmt.Errorf("shared admin maps unavailable")
	}
	var old sharedNodeWire
	if err := configuration.Lookup(uint32(0), &old); err != nil {
		return nil, err
	}
	if old != (sharedNodeWire{}) {
		return nil, fmt.Errorf("shared product configuration was already initialized")
	}
	cookie, err := sharedRandomIdentity()
	if err != nil {
		return nil, err
	}
	nonce, err := sharedRandomIdentity()
	if err != nil {
		return nil, err
	}
	c := &sharedProductControl{
		config:   sharedNodeWire{NodeCookie: cookie, Nonce: nonce, ABI: OwnerDevelopmentABI, ProfileVersion: SharedProfileVersion, Bindings: uint32(p.Bindings), Objects: uint32(admission.PolicyObjects), Cells: uint32(admission.ArenaCells)},
		programs: programs,
	}
	for i, count := range p.PolicySlots {
		c.config.Slots[i] = uint32(count)
	}
	c.thread, err = installSharedAdmin(admin, configuration, c.config)
	if err != nil {
		return c, err
	}
	if err := ctx.Err(); err != nil {
		return c, err
	}
	// se_configuration is written and frozen: the configuration gate
	// (se_profile_matches) now arms the object's hooks.
	c.installed = true
	return c, nil
}

// run executes one product command on the admin thread and returns its code.
// The request is the command body; run prefixes the authenticated header
// with the next sequence. An accepted call is always joined, even after ctx
// is canceled.
func (c *sharedProductControl) run(ctx context.Context, name string, body []byte) (uint32, error) {
	if c == nil || c.thread == nil {
		return 0, ErrSharedNativeUnavailable
	}
	program := c.programs[name]
	if program == nil {
		return 0, fmt.Errorf("shared product command %s unavailable", name)
	}
	var code uint32
	err := c.thread.do(ctx, func() error {
		if c.sequence >= ^uint64(0)-1 {
			return fmt.Errorf("shared product command sequence exhausted")
		}
		c.sequence++
		request := sharedProductRequest(c.config, c.sequence, body)
		var err error
		code, err = program.Run(&ebpf.RunOptions{Context: request})
		return err
	})
	return code, err
}

// sharedProductRequest encodes struct opaque_real_cmd_header followed by the
// command body (little-endian, the BPF layout).
func sharedProductRequest(config sharedNodeWire, sequence uint64, body []byte) []byte {
	request := make([]byte, sharedProductHeaderBytes+len(body))
	binary.LittleEndian.PutUint64(request[0:8], config.NodeCookie)
	binary.LittleEndian.PutUint64(request[8:16], config.Nonce)
	binary.LittleEndian.PutUint64(request[16:24], sequence)
	copy(request[sharedProductHeaderBytes:], body)
	return request
}

// close stops the admin thread. Its frozen se_admin entry dies with the
// thread; the collection still owns the maps.
func (c *sharedProductControl) close() error {
	if c == nil || c.thread == nil {
		return nil
	}
	return c.thread.close()
}
