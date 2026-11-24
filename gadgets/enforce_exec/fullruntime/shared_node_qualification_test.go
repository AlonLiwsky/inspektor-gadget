// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/common/rootbarrier"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
)

const (
	sharedCandidateGadgetYAML           = "candidate/gadget.yaml"
	sharedCandidateDiagnosticGadgetYAML = "candidate/gadget.diagnostic.yaml"
)

// sharedCandidateQualificationProfile is the geometry candidate/gadget.yaml
// declares: the product q(128,32) object (g19pkg128), 2 bindings x 128 TASK /
// 32 WORK, with the product revision headroom (sharedProductPolicySlots) and
// burst-sized tombstone table (which equals the legacy 32 x TASKS default at
// this quota). G019 burst gate (user decision: 8 burst streams zero-gated):
// ConcurrentBirthCapacity(W, sync) = (W-1)/2 must be >= 8, so W >= 17, and
// the WORK quota must be a power of two (the verdict source refuses any
// other: se_owk_begin's frame), so W = 32 (capacity 15) is the smallest
// product WORK quota; 16 gave 7.
func sharedCandidateQualificationProfile() SharedProfile {
	p := sharedProductProfileFor(128, 32)
	p.ExitTombstones = sharedProductExitTombstones
	return p
}

// sharedProductPolicySlots are the policy objects of every product object
// (-DSE_PROFILE_SLOTS_256=4 in compile-pkg.sh, G020 carryover D3): 2 x
// Bindings, the PoC default. Revision is make-before-break (it stages into a
// FREE object before the old one is released), so the admission floor stays
// Bindings + 1 (objects > bindings); 2 x Bindings also keeps one binding's
// long-held RETIRING record from starving the other binding's revision. The
// diagnostic twins (compile.sh) keep two (sharedCandidateProfileFor).
var sharedProductPolicySlots = [4]uint64{4, 0, 0, 0}

// sharedProductProfileFor is the profile of a product q(task, work) object:
// the twin geometry of sharedCandidateProfileFor with the product policy
// objects.
func sharedProductProfileFor(task, work uint64) SharedProfile {
	p := sharedCandidateProfileFor(task, work)
	p.PolicySlots = sharedProductPolicySlots
	// G020: the image index holds 128 lower-layer roots per binding
	// (-DSE_PROFILE_IMAGES=256 -DSE_PROFILE_IMAGE_QUOTA=128 in the product
	// builds; the twins keep 2/1).
	p.Images, p.PerBinding.Images = p.Bindings*sharedImageLayersMax, sharedImageLayersMax
	return p
}

// sharedProductProfileNamed is the product profile of the object of
// profile name (64, 128, 256 or 512: the g19pkg<name> row of
// sharedProductProfiles, in pin order) with the burst-sized tombstone
// table, and its index in sharedProductProfiles.
func sharedProductProfileNamed(name string) (SharedProfile, int, bool) {
	for i, q := range sharedProductProfiles {
		if q.Name == "g19pkg"+name {
			p := sharedProductProfileFor(q.Task, q.Work)
			p.ExitTombstones = sharedProductExitTombstones
			return p, i, true
		}
	}
	return SharedProfile{}, 0, false
}

// TestSharedProductProfileNamedMatchesImageProfile: the profile the product
// attached tests and the layout builder use has the same geometry
// annotations as the published product image's (sharedProductImageProfile).
func TestSharedProductProfileNamedMatchesImageProfile(t *testing.T) {
	for _, q := range sharedProductProfiles {
		name := strings.TrimPrefix(q.Name, "g19pkg")
		got, _, ok := sharedProductProfileNamed(name)
		if !ok {
			t.Fatalf("profile %s not found", name)
		}
		if g, w := sharedGeometryAnnotations(got), sharedGeometryAnnotations(sharedProductImageProfile(q.Task, q.Work)); !maps.Equal(g, w) {
			t.Errorf("profile %s geometry %v, the product image's %v", name, g, w)
		}
	}
	if _, _, ok := sharedProductProfileNamed("g19pkg64"); ok {
		t.Error("a full object name was accepted as a profile name")
	}
}

// sharedProductExitTombstones is the burst-sized tombstone table of every
// product object (-DSE_PROFILE_EXIT_TOMBSTONES=8192 in build-g19pkg.sh): the
// measured live-tombstone peak in the G019 burst/steady/churn runs is 824
// node-wide (an older build held ~4.3k), far below the 75% high mark (6144).
const sharedProductExitTombstones = 8192

// sharedCandidateProfileFor is the profile of a q(task, work) object: per
// binding task TASK and work WORK credits, two bindings.
func sharedCandidateProfileFor(task, work uint64) SharedProfile {
	p := sharedTestProfile()
	p.Tasks, p.PerBinding.Tasks = 2*task, task
	p.Scratch, p.PerBinding.Scratch = 2*work, work
	// The twin objects' compile-time profile (compile.sh, build-g19pkg.sh):
	// two 256-cell policy objects (product objects: sharedProductProfileFor),
	// 8 accepted UIDs, 2/1 inode facts and images
	// (G019 U1: a small binding count; target sizing is deferred). The
	// product control writes these into se_configuration, which BPF
	// requires to equal its compile-time profile (se_profile_matches).
	p.PolicySlots = [4]uint64{2, 0, 0, 0}
	p.AcceptedUIDs, p.PerBinding.AcceptedUIDs = 8, 4
	p.InodeFacts, p.PerBinding.InodeFacts = 2, 1
	p.Images, p.PerBinding.Images = 2, 1
	return p
}

// sharedCandidateObjectProfiles are the qualified object geometries
// (build-g19pkg.sh q(64,8), q(128,16), q(128,32) (the product g19pkg128,
// G019 burst gate), q(256,32), q(512,16)): the twin
// policy objects with the legacy default tombstone table (qualification
// objects) and with the product burst-sized one (product-source twins), and
// the product policy objects with the burst-sized table (product objects);
// duplicates (twin q(128,16): both 8192) are removed.
func sharedCandidateObjectProfiles() []SharedProfile {
	var out []SharedProfile
	seen := map[[4]uint64]bool{}
	for _, q := range [][2]uint64{{64, 8}, {128, 16}, {128, 32}, {256, 32}, {512, 16}} {
		twin, twinProduct, product := sharedCandidateProfileFor(q[0], q[1]), sharedCandidateProfileFor(q[0], q[1]), sharedProductProfileFor(q[0], q[1])
		twinProduct.ExitTombstones = sharedProductExitTombstones
		product.ExitTombstones = sharedProductExitTombstones
		for _, p := range []SharedProfile{twin, twinProduct, product} {
			key := [4]uint64{q[0], q[1], p.exitTombstones(), p.PolicySlots[0]}
			if !seen[key] {
				seen[key] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// mergedSharedCandidateMetadataFor is the candidate image's gadget.yaml: the
// product metadata merged with the packaged attach declaration and, for a
// diagnostic twin (live bootstrap, TC programs), both diagnostic overlays.
func mergedSharedCandidateMetadataFor(t *testing.T, diagnostic bool) *viper.Viper {
	t.Helper()
	paths := []string{sharedCandidateGadgetYAML, candidatePackaging}
	if diagnostic {
		paths = append(paths, sharedCandidateDiagnosticGadgetYAML, candidateDiagnosticPackaging)
	}
	return loadCandidateMetadata(t, paths...)
}

// packagingForObject applies sharedPackagingForObject to merged metadata
// for one object; a refusal fails the test.
func packagingForObject(t *testing.T, merged *viper.Viper, spec *ebpf.CollectionSpec, path string) *viper.Viper {
	t.Helper()
	out, err := sharedPackagingForObject(merged, sharedObjectShapeOf(spec))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out
}

// candidateProbeLinks pins the non-trampoline links the qualified loader
// attaches besides the trampoline attach set: TestOpaqueRealPolicyVerdictAttached
// (4 failure-frame kprobes, the reader success tp_btf, the credit-at-exit
// sched_process_exit tp_btf) and attachChildSource (raw_tp
// sched_process_fork, kprobe free_task). They take no trampoline slot.
var candidateProbeLinks = map[string]string{
	// D1 (LSM-only prototype): tracepoints only, no kprobe.
	"opaque_real_owner_child_exit_candidate":       "tp_btf/sched_process_exit",
	"real_owner_capsule_terminal":                  "tp_btf/sys_exit",
	"opaque_real_owner_successful_birth_candidate": "raw_tp/sched_process_fork",
	"d1_witness_exec":                              "tp_btf/sched_process_exec",
	"d1_witness_fork":                              "tp_btf/sched_process_fork",
}

// sharedMergedTailCalls reads the merged metadata's tail_calls the way the
// eBPF operator does (NativeResources.TailCalls).
func sharedMergedTailCalls(t *testing.T, merged *viper.Viper) []operators.NativeTailCall {
	t.Helper()
	var calls []operators.NativeTailCall
	if err := merged.UnmarshalKey("tail_calls", &calls); err != nil {
		t.Fatal(err)
	}
	return calls
}

func TestSharedCandidateMergedMetadataDeclaration(t *testing.T) {
	merged := mergedSharedCandidateMetadataFor(t, false)
	for _, diagnostic := range []bool{false, true} {
		if got := sharedMergedTailCalls(t, mergedSharedCandidateMetadataFor(t, diagnostic)); !reflect.DeepEqual(got, sharedProductTailCalls) {
			t.Fatalf("merged tail_calls (diagnostic %v) %+v, pinned %+v", diagnostic, got, sharedProductTailCalls)
		}
	}
	if fmt.Sprint(sharedCandidateProbeSet) != fmt.Sprint(candidateProbeLinks) {
		t.Fatalf("product probe set %v, pinned %v", sharedCandidateProbeSet, candidateProbeLinks)
	}
	if fmt.Sprint(sharedCandidateAttachSet) != fmt.Sprint(candidateAttachSet) {
		t.Fatalf("product attach set %v, pinned %v", sharedCandidateAttachSet, candidateAttachSet)
	}
	perHook := map[string]int{}
	for _, target := range sharedCandidateAttachSet {
		perHook[target]++
	}
	if fmt.Sprint(perHook) != fmt.Sprint(candidateAttachPerHook) || len(sharedCandidateAttachSet) != 15 {
		t.Fatalf("product attach set per hook %v, pinned %v", perHook, candidateAttachPerHook)
	}
	disabled := candidateDisabled(merged)
	for name := range candidateDisabled(loadCandidatePackaging(t)) {
		if !disabled[name] {
			t.Errorf("merged metadata lost packaged disable of %s", name)
		}
	}
	for name := range sharedCandidateAttachSet {
		if disabled[name] {
			t.Errorf("merged metadata disables attach-set program %s", name)
		}
	}
	for name := range sharedCandidateProbeSet {
		if disabled[name] {
			t.Errorf("merged metadata disables qualified probe %s", name)
		}
	}
	if !disabled["se_command"] {
		t.Error("product metadata leaves the protocol command se_command enabled")
	}
	diagnostic := candidateDisabled(mergedSharedCandidateMetadataFor(t, true))
	for name := range sharedCandidateCommandSet {
		if merged.IsSet("programs."+name) || disabled[name] || diagnostic[name] {
			t.Errorf("metadata declares or disables the pinned command %s", name)
		}
	}
	for name := range disabled {
		if !diagnostic[name] {
			t.Errorf("diagnostic metadata lost the product disable of %s", name)
		}
	}
	for name := range diagnostic {
		if sharedCandidateAttached(name) {
			t.Errorf("diagnostic metadata disables attach-set program %s", name)
		}
	}
	for key, want := range sharedGeometryAnnotations(sharedCandidateQualificationProfile()) {
		if got := merged.GetString(key); got != want {
			t.Errorf("%s = %q, want %q", key, got, want)
		}
	}
	if merged.GetString("annotations.enforce-exec-owner-abi") != "3" || !merged.GetBool("annotations.enforce-exec-owner-development") ||
		merged.GetString("annotations.enforce-exec-shared-profile") != "1" || merged.GetBool("annotations.enforce-exec") ||
		merged.GetBool("annotations.enforce-exec-full") || merged.GetString("annotations.enforce-exec-shared-recovery") != "" {
		t.Fatal("merged metadata does not select the shared ABI3 development image")
	}
}

// sharedCandidateManifest mirrors the eBPF operator's manifest: Target is the
// metadata attach target, gadget_program_disabled for disabled programs.
func sharedCandidateManifest(spec *ebpf.CollectionSpec, disabled map[string]bool) *operators.NativeResources {
	r := &operators.NativeResources{Maps: map[string]operators.NativeMapResource{}, Programs: map[string]operators.NativeProgramResource{}}
	// D1: the kernel witness map is required at startup.
	r.Maps[sharedKernelWitnessMap] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: sharedKernelWitnessCellSize, MaxEntries: sharedKernelWitnessCells}
	for name, m := range spec.Maps {
		r.Maps[name] = operators.NativeMapResource{Type: uint32(m.Type), KeySize: m.KeySize, ValueSize: m.ValueSize, MaxEntries: m.MaxEntries, Flags: m.Flags}
	}
	for name, p := range spec.Programs {
		target := p.AttachTo
		if disabled[name] {
			target = sharedProgramDisabled
		}
		r.Programs[name] = operators.NativeProgramResource{Type: uint32(p.Type), Target: target}
	}
	return r
}

// TestSharedCandidateMergedMetadataObjects pins that the merged metadata leaves
// exactly the qualified loader's steady state enabled in each real candidate
// object: the 8 trampoline links (task_free 2) plus the 8 pinned
// kprobe/raw_tp/tp_btf links, the one pinned syscall command, every other
// program disabled, and that qualification admission accepts that manifest.
// IG_ENFORCE_EXEC_PRODUCT_OBJECTS take the product metadata and must also be
// TC-free, recovery-free and pool-reaper-free; IG_ENFORCE_EXEC_CANDIDATE_OBJECTS
// (diagnostic twins) take the diagnostic merge; a diagnostic disable must
// name a program of at least one of them (twins differ in their TEST_RUN
// programs), a product disable a program of every product object.
func TestSharedCandidateMergedMetadataObjects(t *testing.T) {
	product, diagnostic := os.Getenv("IG_ENFORCE_EXEC_PRODUCT_OBJECTS"), os.Getenv("IG_ENFORCE_EXEC_CANDIDATE_OBJECTS")
	if product == "" && diagnostic == "" {
		t.Skip("set IG_ENFORCE_EXEC_PRODUCT_OBJECTS and/or IG_ENFORCE_EXEC_CANDIDATE_OBJECTS=/path/<object>.bpf.o[,...] for the merged attach set")
	}
	diagnosticPrograms := map[string]bool{}
	for _, object := range candidateObjectPaths(product, diagnostic) {
		path := object.path
		spec, err := ebpf.LoadCollectionSpec(path)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		// G019 gap 4: a frozen non-product object without the interpreter
		// continuation takes the merge without exactly its entries.
		merged := packagingForObject(t, mergedSharedCandidateMetadataFor(t, object.diagnostic), spec, path)
		disabled := candidateDisabled(merged)
		trampolines, probes, commands := map[string]string{}, map[string]string{}, map[string]ebpf.ProgramType{}
		for name, p := range spec.Programs {
			if !object.diagnostic && (p.Type == ebpf.SchedCLS || strings.HasPrefix(name, "se_rm_") || strings.HasPrefix(name, sharedPoolReaperProgramPrefix)) {
				t.Errorf("%s: product object has %s (%s)", path, name, p.SectionName)
			}
			if disabled[name] {
				continue
			}
			switch target := nativeattach.TrampolineTarget(p); {
			case target != "":
				trampolines[name] = target
			case p.Type == ebpf.Syscall:
				commands[name] = p.Type
			default:
				probes[name] = p.SectionName
			}
		}
		if !object.diagnostic {
			for name := range spec.Maps {
				if strings.HasPrefix(name, "se_rm_") || strings.HasPrefix(name, "se_pool_reap") {
					t.Errorf("%s: product object has map %s", path, name)
				}
			}
		}
		pinned, err := sharedCandidateCommandsOf(sharedCandidateManifest(spec, nil).Programs)
		if err != nil {
			t.Errorf("%s: %v", path, err)
		}
		if fmt.Sprint(commands) != fmt.Sprint(pinned) {
			t.Errorf("%s: enabled commands %v, pinned %v", path, commands, pinned)
		}
		if fmt.Sprint(trampolines) != fmt.Sprint(sharedCandidateAttachSet) {
			t.Errorf("%s: enabled trampolines %v, pinned %v", path, trampolines, sharedCandidateAttachSet)
		}
		if fmt.Sprint(probes) != fmt.Sprint(candidateProbeLinks) {
			t.Errorf("%s: enabled non-trampoline links %v, pinned %v", path, probes, candidateProbeLinks)
		}
		for name := range disabled {
			switch {
			case object.diagnostic:
				diagnosticPrograms[name] = diagnosticPrograms[name] || spec.Programs[name] != nil
			case spec.Programs[name] == nil:
				t.Errorf("%s: disabled %s is not a program of the object (stale metadata)", path, name)
			}
		}
		manifest := sharedCandidateManifest(spec, disabled)
		manifest.TailCalls = sharedMergedTailCalls(t, merged)
		// Every declared tail call names a program array and a disabled
		// target of this object (the operator installs it before attach).
		for _, c := range manifest.TailCalls {
			m, p := spec.Maps[c.Map], spec.Programs[c.Program]
			if m == nil || m.Type != ebpf.ProgramArray || c.Index >= m.MaxEntries || p == nil || !disabled[c.Program] {
				t.Errorf("%s: tail call %s[%d] = %s does not fit the object", path, c.Map, c.Index, c.Program)
			}
		}
		if err := validateSharedCandidateAttachSet(manifest); err != nil {
			t.Errorf("%s: %v", path, err)
		}
		// Exactly one qualified geometry matches the loaded map sizes.
		var matched []string
		var profile SharedProfile
		for _, p := range sharedCandidateObjectProfiles() {
			// The geometry admission does not size the policy objects (the
			// product control does): match them on se_objects too, so a
			// product object (3) and a twin (2) never both match.
			admission, err := p.Validate()
			if err != nil {
				t.Fatal(err)
			}
			if validateSharedCandidateGeometry(p, manifest) == nil && manifest.Maps["se_objects"].MaxEntries == uint32(admission.PolicyObjects) {
				matched = append(matched, fmt.Sprintf("%d/%d tombstones %d policy objects %d", p.PerBinding.Tasks, p.PerBinding.Scratch, p.exitTombstones(), admission.PolicyObjects))
				profile = p
			}
		}
		if len(matched) != 1 {
			t.Errorf("%s: geometry matches profiles %v, want exactly one", path, matched)
		}
		// A product-publisher object must also pass the product control's
		// exact admission under that profile (policy objects, arena, adopt
		// state, admin maps: the profile se_profile_matches requires), unless
		// it is a recovery twin, which the product publisher refuses.
		if len(matched) == 1 && sharedHasProductCommands(manifest) {
			_, recovery := manifest.Maps["se_rm_control"]
			switch err := validateSharedProductControl(profile, manifest); {
			case recovery:
				t.Logf("%s: recovery twin: no product admin control (%v)", path, err)
			case err != nil:
				t.Errorf("%s: product control admission under profile %s: %v", path, matched[0], err)
			}
		}
		// A product (untagged or not opted-in) node refuses the same image.
		n, err := NewNodeEnforcer(sharedQualifiedConfig())
		if err != nil {
			t.Fatal(err)
		}
		if err := n.admitSharedResources(manifest); err == nil || n.host.admitted != nil {
			t.Errorf("%s: product node admitted the candidate image", path)
		} else {
			t.Logf("%s: product node refuses: %v", path, err)
		}
	}
	for name, present := range diagnosticPrograms {
		if !present {
			t.Errorf("diagnostic disable %s is not a program of any diagnostic object (stale metadata)", name)
		}
	}
}

func sharedEnableQualification(t *testing.T) {
	t.Helper()
	old, oldNS := sharedQualificationBuild, sharedNamespaceCheck
	sharedQualificationBuild = true
	// Host tests may run in a container: the agent namespace precondition
	// (design 13.8) has its own test.
	sharedNamespaceCheck = func() error { return nil }
	t.Cleanup(func() { sharedQualificationBuild, sharedNamespaceCheck = old, oldNS })
}

func sharedCandidateFakeManifest() *operators.NativeResources {
	r := sharedCandidateFakeManifestWithoutCommands()
	for name, typ := range sharedCandidateCommandSet {
		r.Programs[name] = operators.NativeProgramResource{Type: uint32(typ)}
	}
	return r
}

func sharedCandidateFakeManifestWithoutCommands() *operators.NativeResources {
	r := &operators.NativeResources{Maps: map[string]operators.NativeMapResource{}, Programs: map[string]operators.NativeProgramResource{}}
	// D1: the kernel witness map is required at startup.
	r.Maps[sharedKernelWitnessMap] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: sharedKernelWitnessCellSize, MaxEntries: sharedKernelWitnessCells}
	for name, target := range sharedCandidateAttachSet {
		r.Programs[name] = operators.NativeProgramResource{Type: uint32(ebpf.LSM), Target: target}
	}
	for name, section := range sharedCandidateProbeSet {
		kind, target, _ := strings.Cut(section, "/")
		typ := ebpf.Kprobe
		switch kind {
		case "raw_tp":
			typ = ebpf.RawTracepoint
		case "tp_btf":
			typ = ebpf.Tracing
		}
		r.Programs[name] = operators.NativeProgramResource{Type: uint32(typ), Target: target}
	}
	r.Programs["opaque_real_owner_policy_strict"] = operators.NativeProgramResource{Type: uint32(ebpf.LSM), Target: sharedProgramDisabled}
	geometry, _, err := sharedOpaqueOwnerGeometry(sharedCandidateQualificationProfile())
	if err != nil {
		panic(err)
	}
	maps.Copy(r.Maps, geometry)
	maps.Copy(r.Maps, sharedExitCreditGeometry(sharedCandidateQualificationProfile()))
	r.Maps[sharedCapsuleStatsMap] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8 * SharedCapsuleCounters, MaxEntries: 1}
	// The root barrier (every D1 object): its denial and fault counters and
	// its self-test probe (gadgets/common/root_barrier.h).
	r.Maps[rootbarrier.CountersMap] = operators.NativeMapResource{Type: uint32(ebpf.PerCPUArray), KeySize: 4, ValueSize: 8, MaxEntries: 11}
	r.Maps[rootbarrier.FaultsMap] = operators.NativeMapResource{Type: uint32(ebpf.PerCPUArray), KeySize: 4, ValueSize: 8, MaxEntries: 2}
	r.Maps[rootbarrier.ProbeMap] = operators.NativeMapResource{Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 40, MaxEntries: 1}
	// The executable-mapping gate's fault counter (full/shared_exec_map.h).
	r.Maps[sharedExecMapFaultsMap] = operators.NativeMapResource{Type: uint32(ebpf.PerCPUArray), KeySize: 4, ValueSize: 8, MaxEntries: 2}
	return r
}

// sharedFakeNativeHost stands in for the host manager plus eBPF operator: one
// gadget context, final admission, the native transaction and its receipts.
type sharedFakeNativeHost struct {
	runs, stops   int
	attached      map[string]bool
	refuse        error
	manifest      *operators.NativeResources
	gc            *gadgetcontext.GadgetContext
	removedLinkID uint32
	// reaper is the last product reaper built (over reapBackend), reaperErr
	// refuses building one.
	reaper      *Reaper
	reapBackend *fakeReapBackend
	reaperErr   error
	// exit is the fake credit-at-exit witness: counters, a read error and
	// the number of reads.
	exitMu     sync.Mutex
	exit       [ExitCreditCounters]uint64
	exitErr    error
	exitReads  int
	exitBorrow error
	// capsule is the fake exec-capsule witness, like exit.
	capsule       [SharedCapsuleCounters]uint64
	capsuleErr    error
	capsuleReads  int
	capsuleBorrow error
	// birthPark is the fake birth-park witness (read under exitMu).
	birthPark    [BirthParkStats]uint64
	birthParkErr error
	facts        [FactStats]uint64
	factsErr     error
	// verdict is the fake verdict counters (G020 emitter, read under exitMu).
	verdict KernelEventCounters
	// failClosed* is the fake fail-closed rate witness (read under exitMu).
	failClosedRates    [FailClosedRateCounters]uint64
	failClosedAttempts [FailClosedRateAttempts]uint64
	failClosedErr      error
	// The root barrier seams (verifyRootBarrier, rootBarrierFaults).
	rootBarrierErr      error
	rootBarrierVerified int
	barrierFaults       uint64
	barrierFaultsErr    error
	// The executable-mapping gate seams (verifyExecMap, execMapFaults).
	execMapErr       error
	execMapVerified  int
	execMapFaultsN   uint64
	execMapFaultsErr error
	failClosedCells  int
	// block, when set, makes the witness borrow close entered and wait for
	// block to close.
	block, entered chan struct{}
	// readyChecked is set once the operator Readiness gate passed.
	readyChecked atomic.Bool
}

// exitCredit stands in for borrowSharedExitCredit.
func (h *sharedFakeNativeHost) exitCredit(operators.GadgetContext) (sharedExitCreditRead, error) {
	if h.block != nil {
		close(h.entered)
		<-h.block
	}
	if h.exitBorrow != nil {
		return nil, h.exitBorrow
	}
	return func() ([ExitCreditCounters]uint64, error) {
		h.exitMu.Lock()
		defer h.exitMu.Unlock()
		h.exitReads++
		return h.exit, h.exitErr
	}, nil
}

// capsuleStats stands in for borrowSharedCapsuleStats (under exitMu).
func (h *sharedFakeNativeHost) capsuleStats(operators.GadgetContext) (sharedCapsuleStatsRead, error) {
	if h.capsuleBorrow != nil {
		return nil, h.capsuleBorrow
	}
	return func() ([SharedCapsuleCounters]uint64, error) {
		h.exitMu.Lock()
		defer h.exitMu.Unlock()
		h.capsuleReads++
		return h.capsule, h.capsuleErr
	}, nil
}

// birthParkStats stands in for borrowSharedBirthParkStats (under exitMu).
func (h *sharedFakeNativeHost) birthParkStats(operators.GadgetContext) (sharedBirthParkStatsRead, error) {
	return func() ([BirthParkStats]uint64, error) {
		h.exitMu.Lock()
		defer h.exitMu.Unlock()
		return h.birthPark, h.birthParkErr
	}, nil
}

// factStats stands in for borrowSharedFactStats (under exitMu).
func (h *sharedFakeNativeHost) factStats(operators.GadgetContext) (sharedFactStatsRead, error) {
	return func() ([FactStats]uint64, error) {
		h.exitMu.Lock()
		defer h.exitMu.Unlock()
		return h.facts, h.factsErr
	}, nil
}

// verdictCounters stands in for borrowSharedVerdictCounters (under exitMu).
func (h *sharedFakeNativeHost) verdictCounters(operators.GadgetContext) (sharedVerdictCountersRead, func() error, error) {
	return func() (KernelEventCounters, error) {
		h.exitMu.Lock()
		defer h.exitMu.Unlock()
		return h.verdict, nil
	}, func() error { return nil }, nil
}

// setFacts changes the fake fact witness under its lock.
func (h *sharedFakeNativeHost) setFacts(f func(*[FactStats]uint64, *error)) {
	h.exitMu.Lock()
	defer h.exitMu.Unlock()
	f(&h.facts, &h.factsErr)
}

// setBirthPark changes the fake birth-park witness under its lock.
func (h *sharedFakeNativeHost) setBirthPark(f func(*[BirthParkStats]uint64, *error)) {
	h.exitMu.Lock()
	defer h.exitMu.Unlock()
	f(&h.birthPark, &h.birthParkErr)
}

// failClosed stands in for borrowSharedFailClosed (under exitMu).
func (h *sharedFakeNativeHost) failClosed(_ operators.GadgetContext, cells int) (sharedFailClosedRead, error) {
	h.failClosedCells = cells
	return func() ([FailClosedRateCounters]uint64, [FailClosedRateAttempts]uint64, error) {
		h.exitMu.Lock()
		defer h.exitMu.Unlock()
		return h.failClosedRates, h.failClosedAttempts, h.failClosedErr
	}, nil
}

// verifyRootBarrier stands in for verifySharedRootBarrier: it records the
// receipts it saw and returns rootBarrierErr.
func (h *sharedFakeNativeHost) verifyRootBarrier(_ operators.GadgetContext, receipts map[string]*operators.NativeAttachment) error {
	h.exitMu.Lock()
	defer h.exitMu.Unlock()
	h.rootBarrierVerified = len(receipts)
	return h.rootBarrierErr
}

// rootBarrierFaults stands in for borrowSharedRootBarrierFaults (under
// exitMu).
func (h *sharedFakeNativeHost) rootBarrierFaults(operators.GadgetContext) (sharedRootBarrierFaultRead, error) {
	return func() (uint64, error) {
		h.exitMu.Lock()
		defer h.exitMu.Unlock()
		return h.barrierFaults, h.barrierFaultsErr
	}, nil
}

// verifyExecMap stands in for verifySharedExecMap: it counts its calls and
// returns execMapErr.
func (h *sharedFakeNativeHost) verifyExecMap(operators.GadgetContext) error {
	h.exitMu.Lock()
	defer h.exitMu.Unlock()
	h.execMapVerified++
	return h.execMapErr
}

// execMapFaults stands in for borrowSharedExecMapFaults (under exitMu).
func (h *sharedFakeNativeHost) execMapFaults(operators.GadgetContext) (sharedRootBarrierFaultRead, error) {
	return func() (uint64, error) {
		h.exitMu.Lock()
		defer h.exitMu.Unlock()
		return h.execMapFaultsN, h.execMapFaultsErr
	}, nil
}

// setFailClosed changes the fake fail-closed witness under its lock.
func (h *sharedFakeNativeHost) setFailClosed(f func(*[FailClosedRateCounters]uint64, *[FailClosedRateAttempts]uint64, *error)) {
	h.exitMu.Lock()
	defer h.exitMu.Unlock()
	f(&h.failClosedRates, &h.failClosedAttempts, &h.failClosedErr)
}

// setCapsule changes the fake capsule witness under its lock.
func (h *sharedFakeNativeHost) setCapsule(f func(*[SharedCapsuleCounters]uint64, *error)) {
	h.exitMu.Lock()
	defer h.exitMu.Unlock()
	f(&h.capsule, &h.capsuleErr)
}

// setExit changes the fake witness under its lock.
func (h *sharedFakeNativeHost) setExit(f func(*[ExitCreditCounters]uint64, *error)) {
	h.exitMu.Lock()
	defer h.exitMu.Unlock()
	f(&h.exit, &h.exitErr)
}

// newReaper stands in for borrowSharedCandidateReaper.
func (h *sharedFakeNativeHost) newReaper(_ operators.GadgetContext, config ReaperConfig) (*Reaper, error) {
	if h.reaperErr != nil {
		return nil, h.reaperErr
	}
	h.reapBackend = newFakeReapBackend()
	config.Sweep = time.Hour
	h.reaper = newReaper(h.reapBackend, config)
	return h.reaper, nil
}

// qualification is the test seam over this host.
func (h *sharedFakeNativeHost) qualification(publisher func(operators.GadgetContext) (SharedRoutePublisher, error)) SharedNodeQualification {
	return SharedNodeQualification{Run: h.run, Publisher: publisher, newReaper: h.newReaper, exitCredit: h.exitCredit, capsuleStats: h.capsuleStats, birthParkStats: h.birthParkStats, factStats: h.factStats, failClosed: h.failClosed, verdictCounters: h.verdictCounters, rootBarrier: h.verifyRootBarrier, rootBarrierFaults: h.rootBarrierFaults, execMap: h.verifyExecMap, execMapFaults: h.execMapFaults}
}

func (h *sharedFakeNativeHost) run(ctx context.Context, opt gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
	h.runs++
	done := make(chan error, 1)
	gc := gadgetcontext.New(ctx, "local/shared-candidate:abi3-development", opt)
	h.gc = gc
	value, _ := gc.GetVar(sharedNodeKey)
	node := value.(*NodeEnforcer)
	stop := func(context.Context) error {
		h.stops++
		node.mu.Lock()
		claimed := node.host.claimed
		node.mu.Unlock()
		var err error
		if claimed {
			err = node.Close(gc)
		}
		clear(h.attached) // manager detach closes every link
		return err
	}
	validate, _ := gc.GetVar(operators.NativeResourceValidatorKey)
	if err := validate.(func(*operators.NativeResources) error)(h.manifest); err != nil {
		done <- err
		return stop, done, nil
	}
	gc.SetVar(operators.NativeResourcesKey, h.manifest)
	if h.refuse != nil {
		// All-or-nothing: a refused transaction leaves nothing attached.
		done <- h.refuse
		return stop, done, nil
	}
	h.attached = map[string]bool{}
	id := uint32(0)
	for name, p := range h.manifest.Programs {
		if p.Target == sharedProgramDisabled || p.Type == uint32(ebpf.Syscall) {
			continue // the operator never attaches a syscall command
		}
		id++
		h.attached[name] = true
		linkID, target := id, p.Target
		gc.SetVar(operators.NativeAttachmentPrefix+name, &operators.NativeAttachment{
			Type: p.Type, LinkID: linkID, ProgramID: linkID + 100, Target: target,
			Check: func() error {
				if !h.attached[name] || h.removedLinkID == linkID {
					return &nativeattach.ErrNotReady{Name: name, Target: target, LinkID: linkID, Err: syscall.ENOENT}
				}
				return nil
			},
		})
	}
	node.mu.Lock()
	node.host.claimed, node.host.context = true, gc
	node.mu.Unlock()
	go func() {
		if err := node.Start(gc); err != nil {
			done <- err
			return
		}
		// As the gadget context: operator Readiness right after Start; a
		// failure ends the gadget run.
		if ready, ok := sharedOperatorInstance(node).(operators.Readiness); ok {
			if err := ready.Ready(gc); err != nil {
				done <- err
				return
			}
		}
		h.readyChecked.Store(true)
	}()
	return stop, done, nil
}

func sharedQualifiedConfig() SharedNodeConfig {
	return SharedNodeConfig{Profile: sharedCandidateQualificationProfile(), ABI3Development: true, Image: "local/shared-candidate:abi3-development"}
}

func TestSharedStartNodeProductDefaultUnavailable(t *testing.T) {
	old := sharedQualificationBuild
	sharedQualificationBuild = false // a product build, even under the tag
	t.Cleanup(func() { sharedQualificationBuild = old })
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	// No build tag: the explicit opt-in is ignored and nothing is loaded.
	ctx := WithSharedNodeQualification(t.Context(), host.qualification(nil))
	if _, err := StartNode(ctx, sharedQualifiedConfig()); !errors.Is(err, ErrSharedNativeUnavailable) || host.runs != 0 {
		t.Fatalf("product StartNode: err=%v runs=%d", err, host.runs)
	}
	sharedEnableQualification(t)
	if _, err := StartNode(t.Context(), sharedQualifiedConfig()); !errors.Is(err, ErrSharedNativeUnavailable) || host.runs != 0 {
		t.Fatalf("qualification build without opt-in: err=%v runs=%d", err, host.runs)
	}
	// A product node (no qualification) still refuses the candidate manifest.
	n, err := NewNodeEnforcer(sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	if err := n.admitSharedResources(sharedCandidateFakeManifest()); err == nil {
		t.Fatal("product node admitted the candidate manifest")
	}
}

func TestSharedStartNodeQualifiedLoadsOneCollection(t *testing.T) {
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	ctx := WithSharedNodeQualification(t.Context(), host.qualification(nil))
	n, err := StartNode(ctx, sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	if host.runs != 1 || len(host.attached) != 20 || len(n.host.live.receipts) != 20 { // S1: + the tp_btf/sched_process_fork witness, - the merged failure terminal; + the 7 root barrier links; + the 2 mapping gate links
		t.Fatalf("runs=%d attached=%d receipts=%d", host.runs, len(host.attached), len(n.host.live.receipts))
	}
	if n.host.live.reaper == nil || n.host.live.reaper.reaper != host.reaper {
		t.Fatal("live node runs no product reaper")
	}
	waitReaper(t, "first sweep", func() bool { s, _ := host.reaper.Stats(); return s.Sweeps >= 1 })
	if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("live node Ready: %v", err)
	}
	installSharedPinTest(n)
	lease := func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }
	a, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 11, InitHostPID: 1, Acquire: lease})
	if err != nil {
		t.Fatal(err)
	}
	b, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 12, InitHostPID: 1, Acquire: lease})
	if err != nil {
		t.Fatal(err)
	}
	sa, sb := a.Inspect(), b.Inspect()
	if sa.Fault != nil || sb.Fault != nil || !sa.Attached || !sa.RouteReserved || !sb.RouteReserved || sa.RouteSlot == sb.RouteSlot || sa.Ready || sb.Ready {
		t.Fatalf("live inspect: a=%+v b=%+v", sa, sb)
	}
	if n.host.scopeSlots[sa.RouteSlot] != a.account || n.host.scopeSlots[sb.RouteSlot] != b.account {
		t.Fatal("bindings do not own their route slots of the one collection")
	}
	if _, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 13, InitHostPID: 1, Acquire: lease}); err == nil {
		t.Fatal("third binding exceeded the profile's route slots")
	}
	// An external link removal is a typed NotReady naming the hook.
	host.removedLinkID = n.host.live.receipts["opaque_real_owner_reader_begin_probe"].LinkID
	var notReady *nativeattach.ErrNotReady
	if s := a.Inspect(); !errors.As(s.Fault, &notReady) || notReady.Target != "bpf_lsm_bprm_check_security" || s.Attached {
		t.Fatalf("removed link inspect: %+v", s)
	}
	if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) || !errors.As(err, &notReady) {
		t.Fatalf("removed link Ready: %v", err)
	}
	host.removedLinkID = 0
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
	if host.stops != 1 || len(host.attached) != 0 || len(n.scopes) != 0 || n.host.scopeSlots[0] != nil || n.host.scopeSlots[1] != nil {
		t.Fatalf("cleanup: stops=%d attached=%d scopes=%d slots=%v", host.stops, len(host.attached), len(n.scopes), n.host.scopeSlots)
	}
	select {
	case <-n.host.live.reaper.waited: // StopNode joined the reaper
	default:
		t.Fatal("product reaper still running after StopNode")
	}
	if n.host.live.reaper.err != nil {
		t.Fatalf("product reaper: %v", n.host.live.reaper.err)
	}
	if s := a.Inspect(); !errors.Is(s.Fault, ErrSharedNativeUnavailable) {
		t.Fatalf("stopped node inspect: %+v", s)
	}
}

func TestSharedStartNodeQualifiedCapacityRefusal(t *testing.T) {
	sharedEnableQualification(t)
	refusal := &nativeattach.ErrAttachCapacity{Target: "bprm_execve", Err: syscall.E2BIG}
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest(), refuse: refusal}
	// StartNode retries the whole host start outside the lifecycle lock:
	// every refused attempt is torn down before the next one.
	q := host.qualification(nil)
	q.attachRetry = &nativeattach.Retry{Initial: time.Millisecond, Max: time.Millisecond, MaxAttempts: 3, Budget: time.Second}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), q), sharedQualifiedConfig())
	var capacity *nativeattach.ErrAttachCapacity
	if n != nil || !errors.As(err, &capacity) || capacity.Target != "bprm_execve" || !errors.Is(err, ErrSharedNodeNotReady) {
		t.Fatalf("capacity refusal: node=%v err=%v", n, err)
	}
	if host.runs != 3 || host.stops != 3 || len(host.attached) != 0 {
		t.Fatalf("refusal left state: runs=%d stops=%d attached=%d", host.runs, host.stops, len(host.attached))
	}
}

func TestSharedStartNodeQualifiedRejectsOutsideAttachSet(t *testing.T) {
	sharedEnableQualification(t)
	manifest := sharedCandidateFakeManifest()
	extra := maps.Clone(manifest.Programs)
	extra["opaque_real_owner_policy_seed_diagnostic"] = operators.NativeProgramResource{Type: uint32(ebpf.SchedCLS), Target: "tc"}
	manifest.Programs = extra
	host := &sharedFakeNativeHost{manifest: manifest}
	ctx := WithSharedNodeQualification(t.Context(), host.qualification(nil))
	if n, err := StartNode(ctx, sharedQualifiedConfig()); n != nil || err == nil || !strings.Contains(err.Error(), "outside the pinned attach set") {
		t.Fatalf("extra program admitted: node=%v err=%v", n, err)
	}
	if host.stops != 1 || len(host.attached) != 0 {
		t.Fatalf("refusal left state: stops=%d attached=%d", host.stops, len(host.attached))
	}
}

func TestSharedCandidateAdmitsReapCommand(t *testing.T) {
	if err := validateSharedCandidateAttachSet(sharedCandidateFakeManifest()); err != nil {
		t.Fatal(err)
	}
}

func TestSharedCandidateRefusesReapCommandShapes(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(map[string]operators.NativeProgramResource)
		want string
	}{
		{"missing", func(p map[string]operators.NativeProgramResource) { delete(p, "opaque_real_reap") }, "command opaque_real_reap missing"},
		{"attached", func(p map[string]operators.NativeProgramResource) {
			p["opaque_real_reap"] = operators.NativeProgramResource{Type: uint32(ebpf.Syscall), Target: "x"}
		}, "command opaque_real_reap missing"},
		{"disabled", func(p map[string]operators.NativeProgramResource) {
			p["opaque_real_reap"] = operators.NativeProgramResource{Type: uint32(ebpf.Syscall), Target: sharedProgramDisabled}
		}, "command opaque_real_reap missing"},
		{"not a syscall program", func(p map[string]operators.NativeProgramResource) {
			p["opaque_real_reap"] = operators.NativeProgramResource{Type: uint32(ebpf.SchedCLS)}
		}, "command opaque_real_reap missing"},
		{"enabled se_command", func(p map[string]operators.NativeProgramResource) {
			p["se_command"] = operators.NativeProgramResource{Type: uint32(ebpf.Syscall)}
		}, "se_command is outside the pinned attach set"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := sharedCandidateFakeManifest()
			tc.edit(manifest.Programs)
			if err := validateSharedCandidateAttachSet(manifest); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("admission: %v, want %q", err, tc.want)
			}
		})
	}
	if err := validateSharedCandidateAttachSet(sharedCandidateFakeManifestWithoutCommands()); err == nil {
		t.Fatal("manifest without the reap command admitted")
	}
}

// TestSharedStartNodeQualifiedReaperRefusalFailsClosed: without its product
// reaper the node does not start, and the attached collection is torn down.
func TestSharedStartNodeQualifiedReaperRefusalFailsClosed(t *testing.T) {
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest(), reaperErr: errors.New("no reap handles")}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(nil)), sharedQualifiedConfig())
	if n != nil || err == nil || !strings.Contains(err.Error(), "product reaper unavailable") {
		t.Fatalf("node started without its reaper: node=%v err=%v", n, err)
	}
	if host.stops != 1 || len(host.attached) != 0 {
		t.Fatalf("refusal left state: stops=%d attached=%d", host.stops, len(host.attached))
	}
}

// TestSharedStartNodeQualifiedPublisherRefusalStartsNoReaper: the route
// publisher (for a product object, the admin control) is installed before
// the reaper (design 12, G1 review), so a refused publisher starts no
// reaper; the refused startup tears the collection down. (A refused reaper
// closing the publisher: TestSharedNodeProductPublisherLifecycle.)
func TestSharedStartNodeQualifiedPublisherRefusalStartsNoReaper(t *testing.T) {
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	refuse := func(operators.GadgetContext) (SharedRoutePublisher, error) { return nil, errors.New("no publisher") }
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(refuse)), sharedQualifiedConfig())
	if n != nil || err == nil || !strings.Contains(err.Error(), "route publisher unavailable") {
		t.Fatalf("publisher refusal: node=%v err=%v", n, err)
	}
	if host.reaper != nil {
		t.Fatal("reaper built before the publisher")
	}
	if host.stops != 1 || len(host.attached) != 0 {
		t.Fatalf("refusal left state: stops=%d attached=%d", host.stops, len(host.attached))
	}
}

// TestSharedStartNodeQualifiedReaperQuarantineDegrades: a reap fault
// quarantines one charge (the reaper keeps running); Ready and Inspect report
// the node degraded, never Ready.
func TestSharedStartNodeQualifiedReaperQuarantineDegrades(t *testing.T) {
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(nil)), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	a, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 11, InitHostPID: 1, Acquire: func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	waitReaper(t, "first sweep", func() bool { s, _ := host.reaper.Stats(); return s.Sweeps >= 1 })
	host.reapBackend.set(ReapWork, 1, fakeReapCharge{cookie: 4, metaCookie: 4, phase: ReapWorkPhaseDone, code: reapWorkFault})
	host.reapBackend.events <- reapEvent{cookie: 4, slot: 1, kind: ReapEventWorkDone}
	waitReaper(t, "quarantine", func() bool { return n.host.live.reaper.faulted.Load() == 1 })
	if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "quarantined 1 charge") {
		t.Fatalf("degraded Ready: %v", err)
	}
	if s := a.Inspect(); s.Fault == nil || !strings.Contains(s.Fault.Error(), "node degraded") || s.Attached || s.Ready {
		t.Fatalf("degraded Inspect: %+v", s)
	}
	select {
	case <-n.host.live.reaper.waited:
		t.Fatalf("a quarantined charge stopped the reaper: %v", n.host.live.reaper.err)
	default:
	}
	if err := n.StopNode(t.Context()); err == nil || !strings.Contains(err.Error(), "quarantined 1 charge") {
		t.Fatalf("StopNode: %v, want the quarantine reported", err)
	}
	if host.stops != 1 || len(host.attached) != 0 || !n.host.released {
		t.Fatalf("teardown blocked: stops=%d attached=%d released=%v", host.stops, len(host.attached), n.host.released)
	}
}

// TestSharedStartNodeQualifiedReaperFaultDegrades: a reaper that stops on an
// infrastructure error (a malformed wakeup) is surfaced by Ready and Inspect
// (the node stays unavailable, never Ready), never blocks teardown, and is
// reported by StopNode after it.
func TestSharedStartNodeQualifiedReaperFaultDegrades(t *testing.T) {
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(nil)), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	a, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 11, InitHostPID: 1, Acquire: func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) || strings.Contains(err.Error(), "reaper") {
		t.Fatalf("healthy Ready: %v", err)
	}
	waitReaper(t, "first sweep", func() bool { s, _ := host.reaper.Stats(); return s.Sweeps >= 1 })
	host.reapBackend.events <- reapEvent{cookie: 4, slot: 8, kind: ReapEventTaskDead} // malformed: faults
	<-n.host.live.reaper.waited
	if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "node degraded") {
		t.Fatalf("degraded Ready: %v", err)
	}
	if s := a.Inspect(); s.Fault == nil || !strings.Contains(s.Fault.Error(), "node degraded") || s.Attached || s.Ready {
		t.Fatalf("degraded Inspect: %+v", s)
	}
	err = n.StopNode(t.Context())
	if err == nil || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("StopNode: %v, want the reaper fault", err)
	}
	if host.stops != 1 || len(host.attached) != 0 || len(n.scopes) != 0 || !n.host.released {
		t.Fatalf("teardown blocked: stops=%d attached=%d scopes=%d released=%v", host.stops, len(host.attached), len(n.scopes), n.host.released)
	}
}

// TestSharedBorrowedReaperRefusesMissingHandles: the product reaper borrows
// exactly the published command and reap maps; any missing one fails.
func TestSharedBorrowedReaperRefusesMissingHandles(t *testing.T) {
	gc := gadgetcontext.New(t.Context(), "local/shared-candidate:abi3-development")
	if _, err := borrowSharedCandidateReaper(gc, ReaperConfig{}); err == nil || !strings.Contains(err.Error(), "opaque_real_reap was not published") {
		t.Fatalf("no command: %v", err)
	}
	borrow := func(gc operators.GadgetContext) (*Reaper, error) {
		return borrowSharedCandidateReaper(gc, ReaperConfig{})
	}
	gc.SetVar(operators.ProgramPrefix+"opaque_real_reap", new(ebpf.Program))
	if _, err := borrow(gc); err == nil || !strings.Contains(err.Error(), "manifest unavailable") {
		t.Fatalf("no manifest: %v", err)
	}
	gc.SetVar(operators.NativeResourcesKey, &operators.NativeResources{Maps: map[string]operators.NativeMapResource{"opaque_real_reap_events": {}}})
	if _, err := borrow(gc); err == nil || !strings.Contains(err.Error(), "object has no map") {
		t.Fatalf("no maps: %v", err)
	}
}

func TestSharedCandidateRefusesMissingExitCreditWitness(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(map[string]operators.NativeMapResource)
	}{
		{"missing witness", func(m map[string]operators.NativeMapResource) { delete(m, "opaque_real_exit_credit") }},
		{"short witness", func(m map[string]operators.NativeMapResource) {
			w := m["opaque_real_exit_credit"]
			w.MaxEntries = ExitCreditCounters - 1
			m["opaque_real_exit_credit"] = w
		}},
		{"witness not an array", func(m map[string]operators.NativeMapResource) {
			w := m["opaque_real_exit_credit"]
			w.Type = uint32(ebpf.Hash)
			m["opaque_real_exit_credit"] = w
		}},
		{"missing tombstones", func(m map[string]operators.NativeMapResource) { delete(m, "se_exit_tombstones") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := sharedCandidateFakeManifest()
			tc.edit(manifest.Maps)
			if err := validateSharedCandidateAttachSet(manifest); err == nil {
				t.Fatal("admitted without its credit-at-exit witness")
			}
		})
	}
}

// TestSharedStartNodeQualifiedExitCreditUnavailableFailsClosed: a node whose
// credit-at-exit witness cannot be borrowed or read at start does not start.
func TestSharedStartNodeQualifiedExitCreditUnavailableFailsClosed(t *testing.T) {
	sharedEnableQualification(t)
	for _, tc := range []struct {
		name string
		host *sharedFakeNativeHost
		want string
	}{
		{"not published", &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest(), exitBorrow: errors.New("no map")}, "witness unavailable"},
		{"unreadable", &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest(), exitErr: errors.New("EPERM")}, "witness unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := StartNode(WithSharedNodeQualification(t.Context(), tc.host.qualification(nil)), sharedQualifiedConfig())
			if n != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("node started without its witness: node=%v err=%v", n, err)
			}
			if tc.host.stops != 1 || len(tc.host.attached) != 0 || tc.host.reaper != nil {
				t.Fatalf("refusal left state: stops=%d attached=%d reaper=%v", tc.host.stops, len(tc.host.attached), tc.host.reaper != nil)
			}
		})
	}
}

// TestSharedStartNodeQualifiedExitCreditDegrades: a credit-at-exit fault the
// reaper never sees (a lease that cannot be rebuilt, a held lease stuck on a
// DEAD charge) or an unreadable witness makes the node degraded, sticky:
// Ready carries it (never Ready), Inspect reports Fault and not Attached,
// StopNode tears down and reports it. Benign counts stay healthy.
func TestSharedStartNodeQualifiedExitCreditDegrades(t *testing.T) {
	sharedEnableQualification(t)
	for _, tc := range []struct {
		name string
		set  func(*[ExitCreditCounters]uint64, *error)
		want string
	}{
		{"lease fault", func(c *[ExitCreditCounters]uint64, _ *error) { c[ExitCreditLeaseFault]++ }, "lease-fault=1"},
		{"held stuck", func(c *[ExitCreditCounters]uint64, _ *error) { c[ExitCreditHeldStuck] += 2 }, "held-stuck=2"},
		{"account overflow", func(c *[ExitCreditCounters]uint64, _ *error) { c[ExitCreditAccountOverflow]++ }, "account-overflow=1"},
		{"unreadable", func(_ *[ExitCreditCounters]uint64, err *error) { *err = errors.New("map gone") }, "credit at exit unknown"},
		{"counter moved backwards", func(c *[ExitCreditCounters]uint64, _ *error) { c[ExitCreditInserted] = 0 }, "moved backwards"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
			host.exit[ExitCreditInserted] = 5 // activity before the node started
			n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(nil)), sharedQualifiedConfig())
			if err != nil {
				t.Fatal(err)
			}
			installSharedPinTest(n)
			a, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 11, InitHostPID: 1, Acquire: func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }})
			if err != nil {
				t.Fatal(err)
			}
			host.setExit(func(c *[ExitCreditCounters]uint64, _ *error) {
				c[ExitCreditInserted] += 3
				c[ExitCreditSettled] += 3
				c[ExitCreditUnsettled]++ // CONTENDED: benign
			})
			if s := a.Inspect(); s.Fault != nil || !s.Attached {
				t.Fatalf("healthy Inspect: %+v", s)
			}
			if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) || strings.Contains(err.Error(), "credit at exit") {
				t.Fatalf("healthy Ready: %v", err)
			}
			host.setExit(tc.set)
			if s := a.Inspect(); s.Fault == nil || !strings.Contains(s.Fault.Error(), tc.want) || s.Attached || s.Ready {
				t.Fatalf("degraded Inspect: %+v", s)
			}
			// Sticky: a later clean witness does not clear it.
			host.setExit(func(c *[ExitCreditCounters]uint64, err *error) {
				*c, *err = [ExitCreditCounters]uint64{ExitCreditInserted: 9, ExitCreditSettled: 9}, nil
			})
			if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "node degraded") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("degraded Ready: %v", err)
			}
			if err := n.StopNode(t.Context()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("StopNode: %v, want the credit-at-exit fault", err)
			}
			if host.stops != 1 || len(host.attached) != 0 || !n.host.released {
				t.Fatalf("teardown blocked: stops=%d attached=%d released=%v", host.stops, len(host.attached), n.host.released)
			}
		})
	}
}

// TestSharedStopNodeReadsExitCreditBeforeClose: the final witness reading is
// taken before the collection closes and never after it.
func TestSharedStopNodeReadsExitCreditBeforeClose(t *testing.T) {
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(nil)), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	host.setExit(func(c *[ExitCreditCounters]uint64, _ *error) { c[ExitCreditTombFault]++ })
	if err := n.StopNode(t.Context()); err == nil || !strings.Contains(err.Error(), "tomb-fault=1") {
		t.Fatalf("StopNode missed the fault of the final window: %v", err)
	}
	host.exitMu.Lock()
	reads := host.exitReads
	host.exitMu.Unlock()
	if err := n.liveHealthFault(); err == nil {
		t.Fatal("sticky fault lost after StopNode")
	}
	host.exitMu.Lock()
	defer host.exitMu.Unlock()
	if host.exitReads != reads {
		t.Fatal("witness read after the collection closed")
	}
}

func TestSharedCandidateRefusesGeometryMismatch(t *testing.T) {
	manifest := sharedCandidateFakeManifest()
	if err := validateSharedCandidateGeometry(sharedCandidateQualificationProfile(), manifest); err != nil {
		t.Fatal(err)
	}
	// The pre-fix metadata declared the per-binding quota as the node total.
	old := sharedTestProfile()
	old.Tasks, old.PerBinding.Tasks, old.Scratch, old.PerBinding.Scratch = 128, 64, 16, 8
	for name, p := range map[string]SharedProfile{
		"node total as per-binding":         old,
		"256/32 profile on a 128/16 object": sharedCandidateProfileFor(256, 32),
		"64/8 profile on a 128/16 object":   sharedCandidateProfileFor(64, 8),
	} {
		if err := validateSharedCandidateGeometry(p, manifest); err == nil || !strings.Contains(err.Error(), "requires") {
			t.Errorf("%s admitted: %v", name, err)
		}
	}
	short := sharedCandidateFakeManifest()
	charges := short.Maps["se_opaque_charges"]
	charges.MaxEntries--
	short.Maps["se_opaque_charges"] = charges
	if err := validateSharedCandidateGeometry(sharedCandidateQualificationProfile(), short); err == nil {
		t.Error("short charge map admitted")
	}
	delete(short.Maps, "se_opaque_work_charges")
	if err := validateSharedCandidateGeometry(sharedCandidateQualificationProfile(), short); err == nil {
		t.Error("missing WORK charge map admitted")
	}
	// Through StartNode: the mismatched image is refused at admission and
	// nothing is attached.
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	config := sharedQualifiedConfig()
	config.Profile = sharedCandidateProfileFor(256, 32)
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(nil)), config)
	if n != nil || err == nil || !strings.Contains(err.Error(), "requires") || len(host.attached) != 0 {
		t.Fatalf("mismatched geometry started: node=%v err=%v attached=%d", n, err, len(host.attached))
	}
}

// TestSharedBindRefusalReasons: each refusal names its own reason and stays
// fail-closed (no binding, no scope, no preparation left).
func TestSharedBindRefusalReasons(t *testing.T) {
	lease := func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }
	for _, tc := range []struct {
		name string
		set  func(*NodeEnforcer)
		want string
	}{
		{"closed", func(n *NodeEnforcer) { n.closed = true }, "node closed"},
		{"released", func(n *NodeEnforcer) { n.host.released = true }, "node resources released"},
		{"collection closed", func(n *NodeEnforcer) { n.collectionClosed = true }, "node collection closed"},
		{"stopping", func(n *NodeEnforcer) { n.closing = true }, "node stopping"},
		{"duplicate cgroup", func(n *NodeEnforcer) { n.bindings[11] = &BindingSession{} }, "cgroup 11 already has a binding"},
		{"preparations full", func(n *NodeEnforcer) {
			n.preparations = map[*BindingSession]struct{}{{}: {}, {}: {}}
		}, "2 binding preparations in flight (profile allows 2 bindings)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := NewNodeEnforcer(sharedQualifiedConfig())
			if err != nil {
				t.Fatal(err)
			}
			installSharedPinTest(n)
			tc.set(n)
			s, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 11, InitHostPID: 1, Acquire: lease})
			if s != nil || err == nil || !strings.Contains(err.Error(), tc.want) || !strings.HasPrefix(err.Error(), "shared binding unavailable: ") {
				t.Fatalf("Bind: session=%v err=%v, want %q", s, err, tc.want)
			}
			if len(n.scopes) != 0 {
				t.Fatalf("refused Bind left scopes %v", n.scopes)
			}
		})
	}
}

// TestSharedQualifiedStartupOverlayUnavailable: an unavailable overlay layout
// (G020 ruling: Degraded, FromImage refused) never fails qualified startup;
// the node's Ready reports it.
func TestSharedQualifiedStartupOverlayUnavailable(t *testing.T) {
	sharedEnableQualification(t)
	oldRead, oldLoad := overlayLayoutReader, overlayModuleLoader
	t.Cleanup(func() {
		overlayLayoutReader, overlayModuleLoader = oldRead, oldLoad
		sharedOverlayLayoutFailure.Store(nil)
	})
	overlayLayoutReader = func() (uint32, error) { return 0, fmt.Errorf("overlay module BTF: %w", os.ErrNotExist) }
	overlayModuleLoader = func() error { return fmt.Errorf("autoload refused") }
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(nil)), sharedQualifiedConfig())
	if err != nil {
		t.Fatalf("StartNode with the overlay layout unavailable: %v", err)
	}
	if err := (sharedQualifiedOperator{n}).Ready(host.gc); err != nil {
		t.Fatalf("startup readiness with the overlay layout unavailable: %v", err)
	}
	if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(fmt.Sprint(err), "FromImage policies refused") {
		t.Fatalf("Ready: %v, want the overlay Degraded reason", err)
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}

// TestSharedQualifiedOperatorStartupReadiness: the qualified operator instance
// keeps the host gadget running once the live candidate is healthy (the
// gadget context stops a gadget whose operator Readiness fails), while the
// node's enforcement Ready stays unavailable; a broken receipt fails it.
func TestSharedQualifiedOperatorStartupReadiness(t *testing.T) {
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(nil)), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	op := sharedQualifiedOperator{n}
	var readiness operators.Readiness = op
	if err := readiness.Ready(host.gc); err != nil {
		t.Fatalf("startup readiness: %v", err)
	}
	if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) {
		t.Fatalf("enforcement Ready: %v", err)
	}
	host.removedLinkID = n.host.live.receipts["opaque_real_owner_child_exit_candidate"].LinkID
	var notReady *nativeattach.ErrNotReady
	if err := readiness.Ready(host.gc); !errors.As(err, &notReady) {
		t.Fatalf("startup readiness with a removed link: %v", err)
	}
	if err := readiness.Ready(nil); err == nil {
		t.Fatal("startup readiness for a foreign context")
	}
	host.removedLinkID = 0
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := readiness.Ready(host.gc); err == nil {
		t.Fatal("startup readiness after StopNode")
	}
}

// TestSharedInstantiateSelectsOperatorReadiness: only a qualified node in a
// qualification build or a product node in a product build gets startup
// readiness; every other shared node is the NodeEnforcer itself, whose
// operator Ready never succeeds.
func TestSharedInstantiateSelectsOperatorReadiness(t *testing.T) {
	old := sharedQualificationBuild
	t.Cleanup(func() { sharedQualificationBuild = old })
	for _, tc := range []struct {
		build, qualified, product, want bool
	}{
		{false, false, false, false},
		{false, true, false, false},
		{true, false, false, false},
		{true, true, false, true},
		{false, false, true, true},
		{true, false, true, false},
	} {
		sharedQualificationBuild = tc.build
		n, err := NewNodeEnforcer(sharedQualifiedConfig())
		if err != nil {
			t.Fatal(err)
		}
		n.host.qualified, n.host.product = tc.qualified, tc.product
		instance := sharedOperatorInstance(n)
		if _, ok := instance.(sharedQualifiedOperator); ok != tc.want {
			t.Fatalf("build=%v qualified=%v product=%v: live operator %v", tc.build, tc.qualified, tc.product, ok)
		}
		if !tc.want {
			if r, ok := instance.(operators.Readiness); !ok || r.Ready(nil) == nil {
				t.Fatalf("build=%v qualified=%v product=%v: operator readiness must fail", tc.build, tc.qualified, tc.product)
			}
		}
	}
}

// TestSharedStartNodeCanceledDuringStartupJoinsTeardown: StartNode canceled
// while startLiveCandidate is still running keeps the host teardown, which
// StopNode joins even when the candidate is installed afterwards.
func TestSharedStartNodeCanceledDuringStartupJoinsTeardown(t *testing.T) {
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest(), block: make(chan struct{}), entered: make(chan struct{})}
	ctx, cancel := context.WithCancel(t.Context())
	type result struct {
		n   *NodeEnforcer
		err error
	}
	out := make(chan result, 1)
	go func() {
		n, err := StartNode(WithSharedNodeQualification(ctx, host.qualification(nil)), sharedQualifiedConfig())
		out <- result{n, err}
	}()
	<-host.entered // startup is blocked in the witness borrow
	cancel()
	// Let startLiveCandidate finish (and install the candidate) while
	// StartNode is already tearing down.
	time.Sleep(10 * time.Millisecond)
	close(host.block)
	r := <-out
	if r.n != nil || !errors.Is(r.err, context.Canceled) {
		t.Fatalf("canceled StartNode: node=%v err=%v", r.n, r.err)
	}
	if host.stops != 1 || len(host.attached) != 0 {
		t.Fatalf("teardown not joined: stops=%d attached=%d", host.stops, len(host.attached))
	}
	if host.reaper != nil {
		if err := host.reaper.Wait(); err != nil {
			t.Fatalf("reaper after canceled startup: %v", err)
		}
	}
}

// TestSharedStartNodeWaitsForReadinessGate: StartNode succeeds only after the
// operator Readiness gate passed; a gate failure is a StartNode error and
// the gadget is torn down.
func TestSharedStartNodeWaitsForReadinessGate(t *testing.T) {
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(nil)), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	if !waitBool(&host.readyChecked) {
		t.Fatal("StartNode returned before the readiness gate passed")
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The gate fails on a degraded witness read: StartNode fails, teardown joins.
	host = &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	host.exit[ExitCreditInserted] = 1
	failing := host.qualification(nil)
	borrow := failing.exitCredit
	failing.exitCredit = func(gc operators.GadgetContext) (sharedExitCreditRead, error) {
		read, err := borrow(gc)
		if err != nil {
			return nil, err
		}
		reads := 0
		return func() ([ExitCreditCounters]uint64, error) {
			c, err := read()
			if reads++; reads > 1 {
				c[ExitCreditLeaseFault]++ // after the baseline
			}
			return c, err
		}, nil
	}
	n, err = StartNode(WithSharedNodeQualification(t.Context(), failing), sharedQualifiedConfig())
	if n != nil || err == nil || !strings.Contains(err.Error(), "lease-fault=1") {
		t.Fatalf("degraded startup: node=%v err=%v", n, err)
	}
	if host.stops != 1 || len(host.attached) != 0 || host.readyChecked.Load() {
		t.Fatalf("failed gate left state: stops=%d attached=%d ready=%v", host.stops, len(host.attached), host.readyChecked.Load())
	}
}

// waitBool waits briefly for b (the fake gadget sets it right after the gate).
func waitBool(b *atomic.Bool) bool {
	for range 200 {
		if b.Load() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// TestSharedStoppedHealthIsNeverHealthy: once health monitoring stopped (the
// gadget is stopping), Inspect and Ready report it although every hook and
// the witness still look healthy.
func TestSharedStoppedHealthIsNeverHealthy(t *testing.T) {
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(nil)), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	installSharedPinTest(n)
	a, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 11, InitHostPID: 1, Acquire: func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }})
	if err != nil {
		t.Fatal(err)
	}
	n.stopLiveHealth()
	if s := a.Inspect(); s.Fault == nil || !strings.Contains(s.Fault.Error(), "health monitoring stopped") || s.Attached {
		t.Fatalf("Inspect after health stopped: %+v", s)
	}
	if err := n.Ready(host.gc); !strings.Contains(fmt.Sprint(err), "health monitoring stopped") {
		t.Fatalf("Ready after health stopped: %v", err)
	}
	if err := (sharedQualifiedOperator{n}).Ready(host.gc); err == nil {
		t.Fatal("startup readiness after health stopped")
	}
	if err := n.StopNode(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestSharedCandidateRefusesExitGeometryMismatch(t *testing.T) {
	p := sharedCandidateQualificationProfile()
	for name, edit := range map[string]func(map[string]operators.NativeMapResource){
		"reduced tombstones (SE_TEST_EXIT_TOMBSTONE_ENTRIES)": func(m map[string]operators.NativeMapResource) {
			t := m["se_exit_tombstones"]
			t.MaxEntries = 4
			m["se_exit_tombstones"] = t
		},
		"tombstones not a hash": func(m map[string]operators.NativeMapResource) {
			t := m["se_exit_tombstones"]
			t.Type = uint32(ebpf.Array)
			m["se_exit_tombstones"] = t
		},
		"accounts per binding": func(m map[string]operators.NativeMapResource) {
			a := m["opaque_real_exit_accounts"]
			a.MaxEntries = 3
			m["opaque_real_exit_accounts"] = a
		},
		"missing accounts": func(m map[string]operators.NativeMapResource) { delete(m, "opaque_real_exit_accounts") },
	} {
		manifest := sharedCandidateFakeManifest()
		edit(manifest.Maps)
		if err := validateSharedCandidateGeometry(p, manifest); err == nil {
			t.Errorf("%s admitted", name)
		}
	}
}

// TestSharedProfileExitTombstones: the tombstone table is burst-sized and
// decoupled from TASKS; zero keeps the legacy 32 x TASKS only for the
// pre-existing qualification objects. The BPF static assert's bounds hold.
func TestSharedProfileExitTombstones(t *testing.T) {
	legacy := sharedCandidateProfileFor(256, 32)
	if legacy.exitTombstones() != 32*512 {
		t.Fatalf("legacy default %d", legacy.exitTombstones())
	}
	product := sharedCandidateProfileFor(512, 16)
	product.ExitTombstones = sharedProductExitTombstones
	if _, err := product.Validate(); err != nil || product.exitTombstones() != 8192 {
		t.Fatalf("product 512/16: %v %d", err, product.exitTombstones())
	}
	if got := sharedExitCreditGeometry(product)["se_exit_tombstones"].MaxEntries; got != 8192 {
		t.Fatalf("geometry pins %d tombstones, want 8192", got)
	}
	if sharedGeometryAnnotations(product)["annotations.enforce-exec-shared-exit-tombstones"] != "8192" {
		t.Fatal("geometry annotation missing exit-tombstones")
	}
	for name, tombstones := range map[string]uint64{"not a multiple of bindings": 8191, "above 1<<20": 1<<20 + 2} {
		p := product
		p.ExitTombstones = tombstones
		if _, err := p.Validate(); err == nil {
			t.Errorf("%s admitted", name)
		}
	}
	// A 512/16 object built with the legacy table is refused by the product
	// profile (and the other way round): never adapted.
	manifest := sharedCandidateFakeManifest()
	maps.Copy(manifest.Maps, sharedExitCreditGeometry(product))
	big := sharedCandidateProfileFor(512, 16)
	geometry, _, err := sharedOpaqueOwnerGeometry(big)
	if err != nil {
		t.Fatal(err)
	}
	maps.Copy(manifest.Maps, geometry)
	if err := validateSharedCandidateGeometry(product, manifest); err != nil {
		t.Fatalf("product 512/16 manifest: %v", err)
	}
	if err := validateSharedCandidateGeometry(big, manifest); err == nil {
		t.Error("legacy 32 x TASKS profile admitted the 8192-tombstone object")
	}
}

// TestSharedCandidateProductCommands (G2): a candidate object carries either
// no product publisher command or all 8, each an unattached syscall command;
// a partial set, an attached one or a non-syscall one is refused.
func TestSharedCandidateProductCommands(t *testing.T) {
	r := sharedCandidateFakeManifest()
	if err := validateSharedCandidateAttachSet(r); err != nil {
		t.Fatalf("object without the product publisher: %v", err)
	}
	for _, name := range sharedProductCommands {
		r.Programs[name] = operators.NativeProgramResource{Type: uint32(ebpf.Syscall)}
	}
	if err := validateSharedCandidateAttachSet(r); err != nil {
		t.Fatalf("object with the product publisher: %v", err)
	}
	for name, edit := range map[string]func(*operators.NativeResources){
		"partial set": func(r *operators.NativeResources) { delete(r.Programs, "opaque_real_adopt_finish") },
		"attached": func(r *operators.NativeResources) {
			r.Programs["opaque_real_route_publish"] = operators.NativeProgramResource{Type: uint32(ebpf.Syscall), Target: "x"}
		},
		"not a syscall": func(r *operators.NativeResources) {
			r.Programs["opaque_real_route_recycle"] = operators.NativeProgramResource{Type: uint32(ebpf.Kprobe)}
		},
		"disabled": func(r *operators.NativeResources) {
			r.Programs["opaque_real_policy_stage"] = operators.NativeProgramResource{Type: uint32(ebpf.Syscall), Target: sharedProgramDisabled}
		},
	} {
		bad := sharedCandidateFakeManifest()
		maps.Copy(bad.Programs, r.Programs)
		edit(bad)
		if err := validateSharedCandidateAttachSet(bad); err == nil {
			t.Errorf("%s: admitted", name)
		}
	}
}

// TestSharedCandidateRefusesMalformedCapsuleWitness: the exec-capsule witness
// (se_exec_capsule_stats, one ARRAY entry of SharedCapsuleCounters u64) is a
// node health input; admission refuses a manifest without it or of another
// shape (the pre-DEATH_RETIRED 14-counter build included).
func TestSharedCandidateRefusesMalformedCapsuleWitness(t *testing.T) {
	if err := validateSharedCandidateAttachSet(sharedCandidateFakeManifest()); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*operators.NativeMapResource) bool
	}{
		{"missing", func(*operators.NativeMapResource) bool { return false }},
		{"14 counters", func(m *operators.NativeMapResource) bool { m.ValueSize = 8 * 14; return true }},
		{"two entries", func(m *operators.NativeMapResource) bool { m.MaxEntries = 2; return true }},
		{"per-cpu", func(m *operators.NativeMapResource) bool { m.Type = uint32(ebpf.PerCPUArray); return true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest := sharedCandidateFakeManifest()
			m := manifest.Maps[sharedCapsuleStatsMap]
			if tc.edit(&m) {
				manifest.Maps[sharedCapsuleStatsMap] = m
			} else {
				delete(manifest.Maps, sharedCapsuleStatsMap)
			}
			if err := validateSharedCandidateAttachSet(manifest); err == nil || !strings.Contains(err.Error(), sharedCapsuleStatsMap) {
				t.Fatalf("admitted a malformed capsule witness: %v", err)
			}
		})
	}
}

// TestSharedStartNodeQualifiedCapsuleWitnessUnavailableFailsClosed: a node
// whose exec-capsule witness cannot be borrowed or read at start does not
// start, and leaves nothing attached.
func TestSharedStartNodeQualifiedCapsuleWitnessUnavailableFailsClosed(t *testing.T) {
	sharedEnableQualification(t)
	for _, tc := range []struct {
		name string
		host *sharedFakeNativeHost
		want string
	}{
		{"not published", &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest(), capsuleBorrow: errors.New("no map")}, "exec-capsule witness unavailable"},
		{"unreadable", &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest(), capsuleErr: errors.New("EPERM")}, "exec-capsule witness unreadable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			n, err := StartNode(WithSharedNodeQualification(t.Context(), tc.host.qualification(nil)), sharedQualifiedConfig())
			if n != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("node started without its capsule witness: node=%v err=%v", n, err)
			}
			if tc.host.stops != 1 || len(tc.host.attached) != 0 || tc.host.reaper != nil {
				t.Fatalf("refusal left state: stops=%d attached=%d reaper=%v", tc.host.stops, len(tc.host.attached), tc.host.reaper != nil)
			}
		})
	}
}

// TestSharedCapsuleHealth: the exec-capsule witness is reported over the
// window since node start. Degraded admissions (FAULT) are counters only; a
// death retire (DEATH_RETIRED, a missed exec terminal) is Degraded for
// FailClosedRateDegradedWindow after it was observed, then clears (review
// L2); a release fault (a route pin that cannot be released) makes the node
// degraded, sticky: Ready, Inspect, CapsuleHealth and StopNode carry it and
// teardown still completes. An unreadable or backwards witness is Unknown,
// also sticky.
func TestSharedCapsuleHealth(t *testing.T) {
	sharedEnableQualification(t)
	for _, tc := range []struct {
		name string
		set  func(*[SharedCapsuleCounters]uint64, *error)
		want string
	}{
		{"release fault", func(c *[SharedCapsuleCounters]uint64, _ *error) { c[SharedCapsuleReleaseFault]++ }, "release-fault=1 (fault=2 death-retired=3)"},
		{"unreadable", func(_ *[SharedCapsuleCounters]uint64, err *error) { *err = errors.New("map gone") }, "exec-capsule witness unknown"},
		{"counter moved backwards", func(c *[SharedCapsuleCounters]uint64, _ *error) { c[0] = 0 }, "moved backwards"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
			// Activity before the node started is outside the window.
			host.capsule[0], host.capsule[SharedCapsuleReleaseFault], host.capsule[SharedCapsuleFault] = 7, 4, 1
			n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(nil)), sharedQualifiedConfig())
			if err != nil {
				t.Fatal(err)
			}
			installSharedPinTest(n)
			var clock sharedTestClock
			n.mu.Lock()
			n.host.live.capsule.clock = clock.now
			n.mu.Unlock()
			a, err := n.Bind(t.Context(), SharedBindingConfig{CgroupID: 11, InitHostPID: 1, Acquire: func(context.Context) (BindingLease, error) { return &sharedTestLease{}, nil }})
			if err != nil {
				t.Fatal(err)
			}
			host.setCapsule(func(c *[SharedCapsuleCounters]uint64, _ *error) {
				c[0] += 5
				c[SharedCapsuleFault] += 2
				c[SharedCapsuleDeathRetired] += 3
			})
			// Death retires: Degraded within the window, not sticky.
			if got, err := n.CapsuleHealth(); err == nil || !strings.Contains(err.Error(), "death-retired=3") || got != (SharedCapsuleHealth{Faults: 2, DeathRetired: 3}) {
				t.Fatalf("death-retired CapsuleHealth %+v, %v, want Degraded", got, err)
			}
			if s := a.Inspect(); s.Fault == nil || !strings.Contains(s.Fault.Error(), "missed exec terminal") {
				t.Fatalf("death-retired Inspect: %+v", s)
			}
			clock.advance(FailClosedRateDegradedWindow - time.Second)
			if _, err := n.CapsuleHealth(); err == nil {
				t.Fatal("death retire cleared inside the window")
			}
			clock.advance(time.Second)
			if got, err := n.CapsuleHealth(); err != nil || got != (SharedCapsuleHealth{Faults: 2, DeathRetired: 3}) {
				t.Fatalf("healthy CapsuleHealth %+v, %v", got, err)
			}
			if s := a.Inspect(); s.Fault != nil || !s.Attached {
				t.Fatalf("healthy Inspect: %+v", s)
			}
			if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) || strings.Contains(err.Error(), "exec-capsule") {
				t.Fatalf("healthy Ready: %v", err)
			}
			host.setCapsule(tc.set)
			if s := a.Inspect(); s.Fault == nil || !strings.Contains(s.Fault.Error(), tc.want) || s.Attached || s.Ready {
				t.Fatalf("degraded Inspect: %+v", s)
			}
			// Sticky: a later clean witness does not clear it.
			host.setCapsule(func(c *[SharedCapsuleCounters]uint64, err *error) {
				*c, *err = [SharedCapsuleCounters]uint64{0: 20, SharedCapsuleReleaseFault: 4, SharedCapsuleFault: 1}, nil
			})
			if _, err := n.CapsuleHealth(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("degraded CapsuleHealth: %v", err)
			}
			if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) || !strings.Contains(err.Error(), "node degraded") || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("degraded Ready: %v", err)
			}
			if err := n.StopNode(t.Context()); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("StopNode: %v, want the capsule fault", err)
			}
			if host.stops != 1 || len(host.attached) != 0 || !n.host.released {
				t.Fatalf("teardown blocked: stops=%d attached=%d released=%v", host.stops, len(host.attached), n.host.released)
			}
		})
	}
}

// TestSharedStopNodeReadsCapsuleWitnessBeforeClose: the final capsule witness
// reading is taken before the collection closes and never after it.
func TestSharedStopNodeReadsCapsuleWitnessBeforeClose(t *testing.T) {
	sharedEnableQualification(t)
	host := &sharedFakeNativeHost{manifest: sharedCandidateFakeManifest()}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), host.qualification(nil)), sharedQualifiedConfig())
	if err != nil {
		t.Fatal(err)
	}
	host.setCapsule(func(c *[SharedCapsuleCounters]uint64, _ *error) { c[SharedCapsuleReleaseFault]++ })
	if err := n.StopNode(t.Context()); err == nil || !strings.Contains(err.Error(), "release-fault=1") {
		t.Fatalf("StopNode missed the release fault of the final window: %v", err)
	}
	host.exitMu.Lock()
	reads := host.capsuleReads
	host.exitMu.Unlock()
	if err := n.liveHealthFault(); err == nil {
		t.Fatal("sticky capsule fault lost after StopNode")
	}
	host.exitMu.Lock()
	defer host.exitMu.Unlock()
	if host.capsuleReads != reads {
		t.Fatal("capsule witness read after the collection closed")
	}
}

// sharedTestClock is a manually advanced clock.
type sharedTestClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *sharedTestClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.t.IsZero() {
		c.t = time.Unix(1_000_000, 0)
	}
	return c.t
}

func (c *sharedTestClock) advance(d time.Duration) {
	c.now()
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// TestSharedLiveCapsuleDeathRetiredWindow (review L2): each new death retire
// restarts the Degraded window; a quiet window clears it; a release fault
// stays sticky regardless.
func TestSharedLiveCapsuleDeathRetiredWindow(t *testing.T) {
	var clock sharedTestClock
	var counters [SharedCapsuleCounters]uint64
	c := &sharedLiveCapsule{read: func() ([SharedCapsuleCounters]uint64, error) { return counters, nil }, clock: clock.now}
	if err := c.check(); err != nil {
		t.Fatalf("quiet witness: %v", err)
	}
	counters[SharedCapsuleDeathRetired] = 1
	if err := c.check(); err == nil || !strings.Contains(err.Error(), "death-retired=1") {
		t.Fatalf("first retire: %v", err)
	}
	clock.advance(FailClosedRateDegradedWindow / 2)
	counters[SharedCapsuleDeathRetired] = 2
	if err := c.check(); err == nil {
		t.Fatal("second retire not Degraded")
	}
	clock.advance(FailClosedRateDegradedWindow / 2)
	if err := c.check(); err == nil || !strings.Contains(err.Error(), "death-retired=2") {
		t.Fatalf("window restarted by the second retire: %v", err)
	}
	clock.advance(FailClosedRateDegradedWindow / 2)
	if err := c.check(); err != nil {
		t.Fatalf("quiet window: %v", err)
	}
	counters[SharedCapsuleReleaseFault] = 1
	if err := c.check(); err == nil || !strings.Contains(err.Error(), "release-fault=1") {
		t.Fatalf("release fault: %v", err)
	}
	clock.advance(10 * FailClosedRateDegradedWindow)
	if err := c.check(); err == nil || !strings.Contains(err.Error(), "release-fault=1") {
		t.Fatalf("release fault not sticky: %v", err)
	}
}
