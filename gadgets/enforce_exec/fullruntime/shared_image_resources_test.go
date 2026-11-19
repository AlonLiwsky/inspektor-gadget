// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func TestSharedPoolReaperTransportInventory(t *testing.T) {
	p := sharedTestProfile()
	p.Tasks, p.Scratch = 16384, 256
	p.PerBinding.Tasks, p.PerBinding.Scratch = 8192, 128
	base, baseUsage, err := sharedPoolGeometry(p)
	if err != nil {
		t.Fatal(err)
	}
	mapsWant, programsWant := sharedPoolReaperTransportGeometry()
	r := &operators.NativeResources{Maps: maps.Clone(base), Programs: maps.Clone(programsWant)}
	for name, shape := range mapsWant {
		r.Maps[name] = shape
	}
	usage, err := validateSharedPoolImageResources(p, r)
	if err != nil || usage.MapValueBytes != baseUsage.MapValueBytes+148 {
		t.Fatalf("candidate transport inventory rejected: usage=%+v err=%v", usage, err)
	}
	for name := range mapsWant {
		broken := &operators.NativeResources{Maps: maps.Clone(r.Maps), Programs: maps.Clone(r.Programs)}
		delete(broken.Maps, name)
		if _, err := validateSharedPoolImageResources(p, broken); err == nil {
			t.Fatalf("missing transport map %s accepted", name)
		}
		broken.Maps[name] = r.Maps[name]
		shape := broken.Maps[name]
		shape.Flags ^= 1
		broken.Maps[name] = shape
		if _, err := validateSharedPoolImageResources(p, broken); err == nil {
			t.Fatalf("wrong transport map flags for %s accepted", name)
		}
	}
	for name := range programsWant {
		broken := &operators.NativeResources{Maps: maps.Clone(r.Maps), Programs: maps.Clone(r.Programs)}
		delete(broken.Programs, name)
		if _, err := validateSharedPoolImageResources(p, broken); err == nil {
			t.Fatalf("missing transport program %s accepted", name)
		}
		broken.Programs[name] = r.Programs[name]
		shape := broken.Programs[name]
		shape.Target = "ingress"
		broken.Programs[name] = shape
		if _, err := validateSharedPoolImageResources(p, broken); err == nil {
			t.Fatalf("attached transport program %s accepted", name)
		}
	}
	unknown := &operators.NativeResources{Maps: maps.Clone(r.Maps), Programs: maps.Clone(r.Programs)}
	unknown.Programs["se_pool_reaper_unreviewed"] = operators.NativeProgramResource{Type: uint32(ebpf.SchedCLS), Instructions: 1}
	if _, err := validateSharedPoolImageResources(p, unknown); err == nil {
		t.Fatal("unreviewed transport program accepted")
	}
	node, err := NewNodeEnforcer(SharedNodeConfig{Profile: p, ABI3Development: true, Image: "test:pool-reaper-candidate"})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.admitSharedResources(r); !errors.Is(err, ErrSharedNativeUnavailable) || node.host.admitted != nil {
		t.Fatalf("source-shape proof bypassed product availability gate: %v", err)
	}
}

func TestSharedOpaqueTaskGeometryAndNotReadyBoundary(t *testing.T) {
	p := sharedTestProfile()
	p.Tasks, p.PerBinding.Tasks = 128, 64
	want, usage, err := sharedOpaqueTaskGeometry(p)
	if err != nil || len(want) != 8 || usage.MapValueBytes != 188768 {
		t.Fatalf("opaque B2/T128 geometry drift: maps=%d usage=%+v err=%v", len(want), usage, err)
	}
	r := &operators.NativeResources{Maps: maps.Clone(want)}
	if got, err := validateSharedOpaqueTaskResources(p, r); err != nil || got != usage {
		t.Fatalf("exact opaque TASK maps rejected: %+v %v", got, err)
	}
	for name := range want {
		broken := &operators.NativeResources{Maps: maps.Clone(want)}
		delete(broken.Maps, name)
		if _, err := validateSharedOpaqueTaskResources(p, broken); err == nil {
			t.Fatalf("missing opaque TASK map %s accepted", name)
		}
		broken.Maps[name] = want[name]
		shape := broken.Maps[name]
		shape.ValueSize++
		broken.Maps[name] = shape
		if _, err := validateSharedOpaqueTaskResources(p, broken); err == nil {
			t.Fatalf("wrong opaque TASK ABI for %s accepted", name)
		}
	}
	for _, legacy := range []string{"se_tasks", "se_invocations", "se_pool_task_meta", "se_pool_work_meta"} {
		broken := &operators.NativeResources{Maps: maps.Clone(want)}
		broken.Maps[legacy] = operators.NativeMapResource{}
		if _, err := validateSharedOpaqueTaskResources(p, broken); err == nil {
			t.Fatalf("mixed opaque/legacy map %s accepted", legacy)
		}
	}
	broken := &operators.NativeResources{Maps: maps.Clone(want)}
	broken.Maps["se_opaque_unreviewed"] = operators.NativeMapResource{}
	if _, err := validateSharedOpaqueTaskResources(p, broken); err == nil {
		t.Fatal("unreviewed opaque TASK map accepted")
	}
	node, err := NewNodeEnforcer(SharedNodeConfig{Profile: p, ABI3Development: true, Image: "test:opaque-task"})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.admitSharedResources(r); !errors.Is(err, ErrSharedNativeUnavailable) || node.host.admitted != nil {
		t.Fatalf("opaque geometry bypassed native NotReady gate: %v", err)
	}
	p.Tasks = 129 // Cannot leave a slot outside the original binding partition.
	if _, _, err := sharedOpaqueTaskGeometry(p); err == nil {
		t.Fatal("unowned opaque TASK remainder accepted")
	}
	p.Tasks, p.PerBinding.Tasks = 16386, 8193
	if _, _, err := sharedOpaqueTaskGeometry(p); err == nil {
		t.Fatal("opaque TASK locator exceeded its 14-bit slot bound")
	}
}

// G025: the qualified opaque candidate quota profiles (TASK/WORK per
// binding, two bindings): 128/16 is the approved default, 64/8 and 256/32
// stay selectable. Each must be an accepted exact owner cohort.
func TestSharedOpaqueOwnerGeometryAcceptsQualifiedQuotaProfiles(t *testing.T) {
	for _, q := range []struct{ tasks, scratch uint64 }{{128, 16}, {64, 8}, {256, 32}} {
		p := sharedTestProfile()
		p.PerBinding.Tasks, p.PerBinding.Scratch = q.tasks, q.scratch
		p.Tasks, p.Scratch = p.Bindings*q.tasks, p.Bindings*q.scratch
		want, usage, err := sharedOpaqueOwnerGeometry(p)
		if err != nil || len(want) != 14 {
			t.Fatalf("quota profile %d/%d rejected: maps=%d err=%v", q.tasks, q.scratch, len(want), err)
		}
		r := &operators.NativeResources{Maps: maps.Clone(want)}
		if got, err := validateSharedOpaqueOwnerResources(p, r); err != nil || got != usage {
			t.Fatalf("quota profile %d/%d owner cohort rejected: %+v %v", q.tasks, q.scratch, got, err)
		}
		if want["se_opaque_charges"].MaxEntries != uint32(2*q.tasks) ||
			want["se_opaque_work_charges"].MaxEntries != uint32(2*q.scratch) {
			t.Fatalf("quota profile %d/%d charge geometry %+v", q.tasks, q.scratch, want)
		}
	}
}

func TestSharedOpaqueOwnerGeometryRequiresTaskAndWorkTogether(t *testing.T) {
	p := sharedTestProfile()
	p.Tasks, p.PerBinding.Tasks = 128, 64
	want, usage, err := sharedOpaqueOwnerGeometry(p)
	if err != nil || len(want) != 14 || usage.MapValueBytes != 2716096 {
		t.Fatalf("combined owner geometry: maps=%d usage=%+v err=%v", len(want), usage, err)
	}
	r := &operators.NativeResources{Maps: maps.Clone(want)}
	if got, err := validateSharedOpaqueOwnerResources(p, r); err != nil || got != usage {
		t.Fatalf("exact owner cohort rejected: %+v %v", got, err)
	}
	for name := range want {
		broken := &operators.NativeResources{Maps: maps.Clone(want)}
		delete(broken.Maps, name)
		if _, err := validateSharedOpaqueOwnerResources(p, broken); err == nil {
			t.Fatalf("missing TASK/WORK map %s accepted", name)
		}
		broken.Maps[name] = want[name]
		shape := broken.Maps[name]
		shape.Flags ^= 1
		broken.Maps[name] = shape
		if _, err := validateSharedOpaqueOwnerResources(p, broken); err == nil {
			t.Fatalf("wrong TASK/WORK map flags for %s accepted", name)
		}
	}
	for _, legacy := range []string{
		"se_tasks", "se_invocations", "se_pool_task_meta", "se_pool_work_meta",
		"se_opaque_unreviewed", "opaque_real_owner_child_gate",
		"opaque_real_live_bootstrap_gate", "opaque_lifecycle_policy_object",
		"opaque_real_owner_policy_witness",
		"opaque_real_pending_selector",
		"opaque_real_pending_history",
		"opaque_real_terminal_race_witness",
		"opaque_lifecycle_policy_snapshot", "opaque_lifecycle_policy_blobs",
		"opaque_real_owner_work_completion_gate",
		"opaque_real_owner_work_completion_selector",
	} {
		broken := &operators.NativeResources{Maps: maps.Clone(want)}
		broken.Maps[legacy] = operators.NativeMapResource{}
		if _, err := validateSharedOpaqueOwnerResources(p, broken); err == nil {
			t.Fatalf("mixed owner map %s accepted", legacy)
		}
	}
	for _, name := range []string{"opaque_future_bootstrap", "opaque_unreviewed_policy_gate"} {
		broken := &operators.NativeResources{Maps: maps.Clone(want)}
		broken.Maps[name] = operators.NativeMapResource{}
		if _, err := validateSharedOpaqueOwnerResources(p, broken); err == nil {
			t.Fatalf("new diagnostic map %s accepted", name)
		}
		broken = &operators.NativeResources{Maps: maps.Clone(want), Programs: map[string]operators.NativeProgramResource{
			name: {Type: uint32(ebpf.LSM), Instructions: 1},
		}}
		if _, err := validateSharedOpaqueOwnerResources(p, broken); err == nil {
			t.Fatalf("new diagnostic program %s accepted", name)
		}
	}
	good := p
	p.PerBinding.Scratch = 65
	if _, _, err := sharedOpaqueOwnerGeometry(p); err == nil {
		t.Fatal("WORK account with more than 64 bits accepted")
	}
	p.PerBinding.Scratch = 63
	if _, _, err := sharedOpaqueOwnerGeometry(p); err == nil {
		t.Fatal("unpartitioned WORK credit accepted")
	}
	// WORK quota: a power of two of 1..64 credits per binding (the verdict
	// source's static assert refuses any other quota; it bounds its own to 32).
	for quota := uint64(1); quota <= 65; quota++ {
		q := good
		q.PerBinding.Scratch, q.Scratch = quota, q.Bindings*quota
		_, _, err := sharedOpaqueOwnerGeometry(q)
		if want := quota <= 64 && quota&(quota-1) == 0; (err == nil) != want {
			t.Fatalf("WORK quota %d per binding: accepted=%v, want %v (%v)", quota, err == nil, want, err)
		}
	}
	node, err := NewNodeEnforcer(SharedNodeConfig{Profile: good, ABI3Development: true, Image: "test:opaque-owner"})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.admitSharedResources(r); !errors.Is(err, ErrSharedNativeUnavailable) || node.host.admitted != nil {
		t.Fatalf("combined source shape bypassed native NotReady gate: %v", err)
	}
}

func TestSharedOpaqueOwnerReaperTransportGeometryAndNotReady(t *testing.T) {
	p := sharedTestProfile()
	p.Tasks, p.PerBinding.Tasks = 128, 64
	p.Scratch, p.PerBinding.Scratch = 16, 8
	base, baseUsage, err := sharedOpaqueOwnerGeometry(p)
	if err != nil {
		t.Fatal(err)
	}
	transportMaps, transportPrograms := sharedOpaqueReaperTransportGeometry()
	r := &operators.NativeResources{Maps: maps.Clone(base), Programs: maps.Clone(transportPrograms)}
	for name, shape := range transportMaps {
		r.Maps[name] = shape
	}
	usage, err := validateSharedOpaqueOwnerResources(p, r)
	if err != nil || usage.MapValueBytes != baseUsage.MapValueBytes+404 {
		t.Fatalf("exact opaque reaper transport rejected: usage=%+v err=%v", usage, err)
	}
	for name := range transportMaps {
		broken := &operators.NativeResources{Maps: maps.Clone(r.Maps), Programs: maps.Clone(r.Programs)}
		delete(broken.Maps, name)
		if _, err := validateSharedOpaqueOwnerResources(p, broken); err == nil {
			t.Fatalf("partial opaque reaper transport missing %s accepted", name)
		}
		shape := r.Maps[name]
		shape.Flags ^= 1
		broken.Maps[name] = shape
		if _, err := validateSharedOpaqueOwnerResources(p, broken); err == nil {
			t.Fatalf("mutated opaque reaper transport %s accepted", name)
		}
	}
	for name := range transportPrograms {
		broken := &operators.NativeResources{Maps: maps.Clone(r.Maps), Programs: maps.Clone(r.Programs)}
		delete(broken.Programs, name)
		if _, err := validateSharedOpaqueOwnerResources(p, broken); err == nil {
			t.Fatalf("partial opaque reaper transport missing program %s accepted", name)
		}
		shape := r.Programs[name]
		shape.Target = "ingress"
		broken.Programs[name] = shape
		if _, err := validateSharedOpaqueOwnerResources(p, broken); err == nil {
			t.Fatalf("attached opaque reaper transport %s accepted", name)
		}
	}
	for _, unknown := range []string{"se_pool_task_meta", "se_pool_reaper_unreviewed"} {
		broken := &operators.NativeResources{Maps: maps.Clone(r.Maps), Programs: maps.Clone(r.Programs)}
		if unknown == "se_pool_task_meta" {
			broken.Maps[unknown] = operators.NativeMapResource{}
		} else {
			broken.Programs[unknown] = operators.NativeProgramResource{Type: uint32(ebpf.SchedCLS), Instructions: 1}
		}
		if _, err := validateSharedOpaqueOwnerResources(p, broken); err == nil {
			t.Fatalf("unreviewed flat-pool/transport resource %s accepted", unknown)
		}
	}
	node, err := NewNodeEnforcer(SharedNodeConfig{Profile: p, ABI3Development: true, Image: "test:opaque-reaper"})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.admitSharedResources(r); !errors.Is(err, ErrSharedNativeUnavailable) || node.host.admitted != nil {
		t.Fatalf("exact opaque reaper geometry bypassed native NotReady gate: %v", err)
	}
}

func TestSharedPoolReaperTransportCompiledInventory(t *testing.T) {
	path := os.Getenv("IG_SHARED_POOL_REAPER_OBJECT")
	if path == "" {
		t.Skip("set IG_SHARED_POOL_REAPER_OBJECT to a compiled repository transport candidate")
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	mapsWant, programsWant := sharedPoolReaperTransportGeometry()
	for name, want := range mapsWant {
		m := spec.Maps[name]
		if m == nil || (operators.NativeMapResource{Type: uint32(m.Type), KeySize: m.KeySize, ValueSize: m.ValueSize, MaxEntries: m.MaxEntries, Flags: m.Flags}) != want {
			t.Fatalf("compiled transport map %s differs from host ABI", name)
		}
	}
	for name, want := range programsWant {
		prog := spec.Programs[name]
		if prog == nil || uint32(prog.Type) != want.Type || prog.AttachTo != "" || prog.SectionName != "tc" || prog.Instructions.Size() == 0 {
			t.Fatalf("compiled transport program %s differs from unattached TEST_RUN ABI", name)
		}
	}
}

func TestSharedPoolGeometryAndAdmissionBoundary(t *testing.T) {
	p := sharedTestProfile()
	p.Tasks, p.Scratch = 16384, 256
	p.PerBinding.Tasks, p.PerBinding.Scratch = 8192, 128
	shape, usage, err := sharedPoolGeometry(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(shape) != 13 || usage.Directories != 4096 ||
		usage.BitmapBytes != 1056 || usage.MapValueBytes != 30231120 {
		t.Fatalf("reviewed B2 profile drift: %+v maps=%d", usage, len(shape))
	}
	for _, name := range []string{
		"se_pool_task_meta", "se_pool_task_payload", "se_pool_work_meta",
		"se_pool_work_payload", "se_pool_charges", "se_pool_directory",
		"se_pool_bitmaps", "se_pool_sequence", "se_pool_reap_control",
		"se_pool_reap_receipt",
	} {
		if shape[name].Flags != unix.BPF_F_RDONLY {
			t.Fatalf("kernel-owned pool map %s is not userspace-readonly", name)
		}
	}
	for _, name := range []string{"se_pool_task_zero", "se_pool_work_zero", "se_pool_reap_request"} {
		if shape[name].Flags != unix.BPF_F_RDONLY_PROG {
			t.Fatalf("pool input/template map %s lost program-readonly flag", name)
		}
	}
	resource := &operators.NativeResources{Maps: maps.Clone(shape)}
	if _, err := validateSharedPoolImageResources(p, resource); err != nil {
		t.Fatal(err)
	}
	for name := range shape {
		t.Run(name, func(t *testing.T) {
			missing := &operators.NativeResources{Maps: maps.Clone(shape)}
			delete(missing.Maps, name)
			if _, err := validateSharedPoolImageResources(p, missing); err == nil {
				t.Fatal("incomplete fixed-pool geometry accepted")
			}
			malformed := &operators.NativeResources{Maps: maps.Clone(shape)}
			value := malformed.Maps[name]
			value.ValueSize++
			malformed.Maps[name] = value
			if _, err := validateSharedPoolImageResources(p, malformed); err == nil {
				t.Fatal("incompatible fixed-pool map accepted")
			}
		})
	}
	legacy := &operators.NativeResources{Maps: maps.Clone(shape)}
	legacy.Maps["se_tasks"] = operators.NativeMapResource{}
	if _, err := validateSharedPoolImageResources(p, legacy); err == nil {
		t.Fatal("dual task ownership accepted")
	}
	node, err := NewNodeEnforcer(SharedNodeConfig{Profile: p, ABI3Development: true, Image: "test:fixed-pool"})
	if err != nil {
		t.Fatal(err)
	}
	if err := node.admitSharedResources(resource); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("incomplete product migration did not hit the availability gate: %v", err)
	}
	if node.host.admitted != nil {
		t.Fatal("rejected pool image retained")
	}
}

func TestSharedPoolPartitionsAllowUnavailableRemainder(t *testing.T) {
	p := sharedTestProfile()
	p.PerBinding.Tasks = 8192 // Stay inside the kernel's 128-word scan bound.
	p.PerBinding.Tasks--
	if _, _, err := sharedPoolGeometry(p); err != nil {
		t.Fatalf("reviewed unavailable remainder refused: %v", err)
	}
	p.PerBinding.Tasks = p.Tasks
	if _, _, err := sharedPoolGeometry(p); err == nil {
		t.Fatal("overcommitted task pool accepted")
	}
}

func TestSharedPoolTaskQuotaMatchesKernelScanBound(t *testing.T) {
	p := sharedTestProfile()
	p.PerBinding.Tasks = 8193
	p.Tasks = p.Bindings * p.PerBinding.Tasks
	if _, err := p.Validate(); err != nil {
		t.Fatalf("logical profile should remain valid: %v", err)
	}
	if _, _, err := sharedPoolGeometry(p); err == nil {
		t.Fatal("host admitted a task bitmap larger than the kernel's 128-word scan bound")
	}
	p.PerBinding.Tasks = 8192
	if _, _, err := sharedPoolGeometry(p); err != nil {
		t.Fatalf("exact kernel scan boundary refused: %v", err)
	}
}

func sharedImageFixture(t *testing.T) (SharedProfile, *operators.NativeResources) {
	t.Helper()
	p, r := sharedResourcesFixture()
	p.Images = 65536
	p.TelemetryBytes = 262144
	extra, programs := sharedImageGeometry(p)
	for n, v := range extra {
		r.Maps[n] = v
	}
	r.Programs = programs
	for n, v := range r.Programs {
		v.Instructions = 17
		r.Programs[n] = v
	}
	return p, r
}

func TestSharedImageInventory(t *testing.T) {
	p, r := sharedImageFixture(t)
	u, err := validateSharedImageResources(p, r)
	if err != nil {
		t.Fatal(err)
	}
	if !u.PendingEnforcementQualification || u.MapPayloadBytes == 0 || u.ProgramInstructions != 9*17 {
		t.Fatalf("incomplete accounting: %+v", u)
	}
	for name := range r.Maps {
		t.Run(name, func(t *testing.T) {
			p, r := sharedImageFixture(t)
			delete(r.Maps, name)
			if _, err := validateSharedImageResources(p, r); err == nil {
				t.Fatal("missing map accepted")
			}
		})
	}
	for name := range r.Programs {
		t.Run(name, func(t *testing.T) {
			p, r := sharedImageFixture(t)
			v := r.Programs[name]
			v.Target = "foreign"
			r.Programs[name] = v
			if _, err := validateSharedImageResources(p, r); err == nil {
				t.Fatal("foreign hook accepted")
			}
		})
	}
}

func TestSharedImageCannotAdmitUnqualifiedFacts(t *testing.T) {
	p, r := sharedImageFixture(t)
	n, err := NewNodeEnforcer(SharedNodeConfig{Profile: p, ABI3Development: true, Image: "test:shared"})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.admitSharedResources(r); err == nil {
		t.Fatal("unqualified inode facts silently admitted")
	}
	if n.host.admitted != nil {
		t.Fatal("refused image retained as admitted")
	}
}

// Build-only opt-in: this inspects an ELF and never loads a BPF program/map.
func TestSharedImageCompiledInventory(t *testing.T) {
	path := os.Getenv("IG_SHARED_IMAGE_OBJECT")
	if path == "" {
		t.Skip("set IG_SHARED_IMAGE_OBJECT to the explicit 2-binding build-only artifact")
	}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatal(err)
	}
	p := sharedTestProfile()
	p.PolicySlots = [4]uint64{2, 0, 0, 0}
	p.Tasks = 128
	p.PerBinding.Tasks = 64
	p.Scratch = 32
	p.PerBinding.Scratch = 16
	p.AcceptedUIDs = 32
	p.PerBinding.AcceptedUIDs = 16
	p.Images = 65536
	p.TelemetryBytes = 262144
	r := &operators.NativeResources{Maps: map[string]operators.NativeMapResource{}, Programs: map[string]operators.NativeProgramResource{}}
	for name, m := range spec.Maps {
		r.Maps[name] = operators.NativeMapResource{Type: uint32(m.Type), KeySize: m.KeySize, ValueSize: m.ValueSize, MaxEntries: m.MaxEntries, Flags: m.Flags}
	}
	for name, p := range spec.Programs {
		r.Programs[name] = operators.NativeProgramResource{Type: uint32(p.Type), Target: p.AttachTo, Instructions: p.Instructions.Size() / 8}
	}
	u, err := validateSharedImageResources(p, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Maps) != 27 || len(r.Programs) != 9 || !u.PendingEnforcementQualification {
		t.Fatalf("unexpected actual manifest: maps%d programs%d usage%+v", len(r.Maps), len(r.Programs), u)
	}
	t.Logf("actual ELF: %d maps, %d programs, %d encoded instruction words; fixed inode pools remain unqualified/unadmitted", len(r.Maps), len(r.Programs), u.ProgramInstructions)
}

// TestSharedProductAdmissionRefusesTwinMaps (security review M-2): the
// publication fault injector and the fail-closed injector maps are refused
// by name on the product path, before any allowlist; the tagged
// qualification path still admits the twin.
func TestSharedProductAdmissionRefusesTwinMaps(t *testing.T) {
	twin := sharedProductManifest(sharedCandidateQualificationProfile())
	twin.Maps["opaque_real_publish_fault"] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 4, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG}
	n, err := NewNodeEnforcer(sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := n.admitSharedResources(twin); err == nil || !strings.Contains(err.Error(), "opaque_real_publish_fault") {
		t.Fatalf("product admission of the twin: %v, want a refusal naming the injector", err)
	}
	if _, err := validateSharedOpaqueOwnerResources(sharedCandidateQualificationProfile(), twin); err == nil || !strings.Contains(err.Error(), "diagnostic-twin map opaque_real_publish_fault") {
		t.Fatalf("owner validator: %v, want the named refusal first", err)
	}
	// The twin's fail-closed (and stale-resume) injector maps are refused by name too, each
	// alone on an otherwise clean product manifest.
	injectors := map[string]operators.NativeMapResource{
		"opaque_real_fc_inject_selector":   {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 24, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG},
		"opaque_real_fc_inject_counts":     {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8, MaxEntries: 6, Flags: unix.BPF_F_RDONLY},
		"opaque_real_fc_pending_marked":    {Type: uint32(ebpf.LRUHash), KeySize: 16, ValueSize: 4, MaxEntries: 4096, Flags: unix.BPF_F_RDONLY},
		"opaque_real_fc_inject_ext":        {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 24, MaxEntries: 1, Flags: unix.BPF_F_RDONLY_PROG},
		"opaque_real_fc_inject_ext_counts": {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8, MaxEntries: 10, Flags: unix.BPF_F_RDONLY},
		"opaque_real_interp_stale_resume":  {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8, MaxEntries: 1},
		// G020 H2: the verdict-event suspension-fault injector.
		"opaque_real_verdict_suspend_fault": {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8, MaxEntries: 1},
		// G020: the per-pass fact witness ring (struct real_owner_pass_witness).
		"opaque_real_fact_witness": {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 832, MaxEntries: 17},
	}
	if len(injectors) != len(sharedProductForbiddenMaps)-1 {
		t.Fatalf("forbidden maps %v, injector cases %d", sharedProductForbiddenMaps, len(injectors))
	}
	for name, m := range injectors {
		if !slices.Contains(sharedProductForbiddenMaps, name) {
			t.Errorf("%s is not in sharedProductForbiddenMaps", name)
		}
		r := sharedProductManifest(sharedCandidateQualificationProfile())
		r.Maps[name] = m
		if err := n.admitSharedResources(r); err == nil || !strings.Contains(err.Error(), name) {
			t.Errorf("product admission with %s: %v, want a refusal naming it", name, err)
		}
		if _, err := validateSharedOpaqueOwnerResources(sharedCandidateQualificationProfile(), r); err == nil || !strings.Contains(err.Error(), "diagnostic-twin map "+name) {
			t.Errorf("owner validator with %s: %v, want the named refusal first", name, err)
		}
	}
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: twin}
	qual := host.qualification(nil)
	qual.newProductPublisher = func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
		return newSharedFakePublisher(), nil // admission is under test, not the borrow
	}
	q, err := StartNode(WithSharedNodeQualification(t.Context(), qual), sharedQualifiedConfig())
	if err != nil {
		t.Fatalf("qualified path refused the twin: %v", err)
	}
	if err := q.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}
