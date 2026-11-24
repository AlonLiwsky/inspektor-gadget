// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
)

const sharedNodeKey = "enforce-exec/native-shared-node"

// sharedNodeAttachRetry is the shared node's explicit, bounded native attach
// retry: a capacity refusal (*nativeattach.ErrAttachCapacity) is
// retried at most 8 times, and no wait starts that would end past 30 s from
// the first attempt (so the bound is about 30 s plus the final attempt).
// Then StartNode returns the last refusal wrapped in ErrSharedNodeNotReady.
//
// StartNode runs it around the host's whole start (startLiveSharedNode), never
// inside the gadget's Start: each refused attempt has already returned from
// the host's StartGadget, so the manager's lifecycle lock is released and the
// attempt's gadget fully torn down before a backoff wait begins. A stop,
// replace or start on that manager (for example the one that frees the
// trampoline links) runs during the wait, and nothing of the refused attempt
// stays attached, so exhaustion fails closed.
func sharedNodeAttachRetry() nativeattach.Retry {
	return nativeattach.Retry{
		Initial:     500 * time.Millisecond,
		Max:         5 * time.Second,
		MaxAttempts: 8,
		Budget:      30 * time.Second,
	}
}

// sharedNodeRetryBounded refuses a StartNode retry without an attempt bound
// or a time budget.
func sharedNodeRetryBounded(retry nativeattach.Retry) error {
	if retry.MaxAttempts <= 0 || retry.Budget <= 0 {
		return fmt.Errorf("shared node requires a bounded native attach retry, got %+v", retry)
	}
	return nil
}

// sharedNodeAttachFailFast is the admission rule: the effective
// NativeAttachRetryKey must be false, so a capacity refusal fails the
// gadget's Start at once and no backoff wait runs under the manager's
// lifecycle lock. StartNode retries outside it (sharedNodeAttachRetry).
func sharedNodeAttachFailFast(gc operators.GadgetContext) error {
	value, ok := gc.GetVar(operators.NativeAttachRetryKey)
	if v, isBool := value.(bool); !ok || !isBool || v {
		return fmt.Errorf("shared node requires a fail-fast native attach (no retry inside Start), got %T %+v", value, value)
	}
	return nil
}

type sharedBorrowedFD interface{ FD() int }

type sharedHostState struct {
	// overlayFailure is the node's "overlay layout unavailable" reason from
	// this node's constants computation (nil: the layout is set).
	overlayFailure atomic.Pointer[error]
	sharedProtocolHostOwnership
	borrowed                                 []sharedBorrowedFD
	context                                  operators.GadgetContext
	admitted                                 *operators.NativeResources
	resources                                sharedControlResources
	control                                  *sharedControl
	claimed, operatorClosed, released, ready bool
	commandsJoined                           bool
	startAttempted                           bool
	// qualified is set only by startQualifiedSharedNode (qualification build
	// plus explicit opt-in). It admits the candidate attach set, nothing else.
	qualified bool
	// product is set only by startProductSharedNode (product build, pinned
	// kernel, WithSharedNodeHost): the live path with the exact product
	// manifest and the product Ready semantics.
	product bool
	live    *sharedLiveCandidate
	// started receives the qualified startup result once: Start's error, or
	// the operator Readiness result (sharedQualifiedOperator.Ready), which
	// the gadget context evaluates right before it publishes the gadget as
	// running.
	started chan error
	// stopGadget tears down the host gadget (the manager detach), set as
	// soon as SharedNodeQualification.Run returns it. It lives outside the
	// live candidate, which startLiveCandidate installs concurrently.
	stopGadget    func(context.Context) error
	gadgetStopped bool
	// newPublisher is the qualification route publisher factory
	// (SharedNodeQualification.Publisher); nil keeps Publish unavailable.
	newPublisher func(operators.GadgetContext) (SharedRoutePublisher, error)
	// newReaper builds the product reaper over the started host gadget
	// context; nil selects borrowSharedCandidateReaper. Tests only override it.
	newReaper func(operators.GadgetContext, ReaperConfig) (*Reaper, error)
	// exitCredit borrows the credit-at-exit witness reader; nil selects
	// borrowSharedExitCredit. Tests only override it.
	exitCredit func(operators.GadgetContext) (sharedExitCreditRead, error)
	// capsuleStats borrows the exec-capsule witness reader; nil selects
	// borrowSharedCapsuleStats. Tests only override it.
	capsuleStats func(operators.GadgetContext) (sharedCapsuleStatsRead, error)
	// birthParkStats borrows the birth-park witness reader (product
	// objects); nil selects borrowSharedBirthParkStats. Tests only.
	birthParkStats func(operators.GadgetContext) (sharedBirthParkStatsRead, error)
	// imageSource replaces the image index's containerd source (tests).
	imageSource sharedImageLayerSource
	// factStats borrows the per-pass fact witness reader (objects with the
	// G020 facts); nil selects borrowSharedFactStats. Tests only.
	factStats func(operators.GadgetContext) (sharedFactStatsRead, error)
	// failClosed borrows the fail-closed rate witness reader; nil selects
	// borrowSharedFailClosed. failClosedClock is its clock (nil: time.Now).
	// Tests only override them.
	failClosed      func(operators.GadgetContext, int) (sharedFailClosedRead, error)
	failClosedClock func() time.Time
	// rootBarrier verifies the root barrier of a product node at start;
	// nil selects verifySharedRootBarrier. rootBarrierFaults borrows its
	// fault reader; nil selects borrowSharedRootBarrierFaults. Tests only
	// override them.
	rootBarrier       func(operators.GadgetContext, map[string]*operators.NativeAttachment) error
	rootBarrierFaults func(operators.GadgetContext) (sharedRootBarrierFaultRead, error)
	// execMap replaces the executable-mapping gate's start self-test
	// (verifySharedExecMap), execMapFaults its fault reader
	// (borrowSharedExecMapFaults). Tests only.
	execMap       func(operators.GadgetContext) error
	execMapFaults func(operators.GadgetContext) (sharedRootBarrierFaultRead, error)
	// newProductPublisher replaces borrowSharedProductPublisher (G1).
	// Package tests only.
	newProductPublisher func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error)
	// verdictCounters borrows the verdict counters (objects with the G020
	// emitter); nil selects borrowSharedVerdictCounters. verdictClock is its
	// Degraded window's clock (nil: time.Now). Tests only override them.
	verdictCounters func(operators.GadgetContext) (sharedVerdictCountersRead, func() error, error)
	verdictClock    func() time.Time
	// strictRefused is why Strict publication is refused on this node
	// (design 13.8: the agent is not in the initial pid/time namespaces).
	strictRefused error
}

// liveHost reports whether the node runs the live collection path: a
// qualified node in a qualification build, or a product node in a product
// build (mutual exclusion: never both).
func (h *sharedHostState) liveHost() bool {
	return h != nil && ((h.qualified && sharedQualificationBuild) || (h.product && !sharedQualificationBuild))
}

// sharedLiveCandidate is the one node-wide candidate collection, owned by the
// host gadget. Bindings own route slots (scopeSlots) of it, never a collection.
type sharedLiveCandidate struct {
	receipts  map[string]*operators.NativeAttachment
	publisher SharedRoutePublisher
	reaper    *sharedLiveReaper
	exit      *sharedLiveExitCredit
	capsule   *sharedLiveCapsule
	// birthPark is the birth-park witness (nil: not a product object).
	birthPark *sharedLiveBirthPark
	// facts is the per-pass fact witness (nil: no G020 facts).
	facts *sharedLiveFactStats
	// failClosed polls the fail-closed rate witness (nil: the object has
	// none and is not a product object).
	failClosed *sharedLiveFailClosed
	// witness is the D1 kernel witness (nil: not a D1 object).
	witness *sharedLiveKernelWitness
	// verdict is the verdict event counters (nil: no G020 emitter).
	verdict *sharedLiveVerdict
	// healthStopped is set once stopLiveHealth ran: the reaper and the
	// witness no longer watch the node, so it is never healthy again.
	healthStopped bool
	// The withdraw -> recycle loops (startRecycle), joined before the
	// publisher closes; recycleFault is their sticky refusal.
	recyclers     sync.WaitGroup
	recycleCtx    context.Context
	recycleCancel context.CancelFunc
	recycleFault  error
	// publisherClosed: closeLivePublisher detached the publisher (node
	// teardown); a later withdrawal is recorded pending and counted in
	// teardownPending (TeardownPendingWithdrawals).
	publisherClosed bool
	teardownPending uint64
	// recycleStopped is set (under n.mu) before the loops are joined:
	// startRecycle then refuses, so no Add races the Wait.
	recycleStopped bool
}

// sharedCandidateAttachSet is the pinned steady-state trampoline attach set
// of the shared candidate, D1 (LSM-only prototype): 15 links, all BPF LSM
// hooks: task_free 2 (the product release and the exec capsule's death
// retire), task_alloc 1, bprm_creds_for_exec 1 (the exec frame's begin),
// bprm_check_security 1, bprm_committed_creds 1, the 7 root barrier
// programs (gadgets/common/root_barrier.h; its task_alloc body runs inline in
// the task_alloc source program) and the 2 programs of the executable-mapping
// gate (full/shared_exec_map.h): mmap_file 1, file_mprotect 1. No
// fentry/fexit program is attached.
// Every other program of the image must be disabled by its packaged
// metadata.
var sharedCandidateAttachSet = map[string]string{
	"opaque_real_owner_child_final_free_candidate": "bpf_lsm_task_free",
	"opaque_real_owner_child_source_candidate":     "bpf_lsm_task_alloc",
	"real_owner_capsule_free":                      "bpf_lsm_task_free",
	"real_owner_capsule_begin":                     "bpf_lsm_bprm_creds_for_exec",
	"opaque_real_owner_reader_begin_probe":         "bpf_lsm_bprm_check_security",
	// The success terminal (was tp_btf/sched_process_exec).
	"opaque_real_owner_reader_success_probe": "bpf_lsm_bprm_committed_creds",
	// The root barrier (README, "Root barrier").
	"rb_chroot":     "bpf_lsm_path_chroot",
	"rb_pivotroot":  "bpf_lsm_sb_pivotroot",
	"rb_userns":     "bpf_lsm_userns_create",
	"rb_capable":    "bpf_lsm_capable",
	"rb_sb_mount":   "bpf_lsm_sb_mount",
	"rb_move_mount": "bpf_lsm_move_mount",
	"rb_sb_umount":  "bpf_lsm_sb_umount",
	// The executable-mapping gate (full/shared_exec_map.h).
	sharedExecMapMmap:     "bpf_lsm_mmap_file",
	sharedExecMapMprotect: "bpf_lsm_file_mprotect",
}

// sharedCandidateProbeSet is the pinned non-trampoline part of the steady
// state, D1: stable tracepoints only (no kprobe): the exec frame's two
// terminals on the syscall-exit raw tracepoint (the failure terminal and
// the capsule terminal), the sched_process_fork raw_tp (birth, and the
// kernel witness of lsm/task_alloc), the sched_process_exec tp_btf (ONLY the
// kernel witness of lsm/bprm_committed_creds: the success terminal is that
// LSM hook, in the attach set above) and the credit-at-exit
// sched_process_exit tp_btf
// (nativeattach.Rank: sys_exit before bprm_creds_for_exec; sched_process_exit
// after task_free and, since Stop detaches in exact reverse, detached before
// it). They attach through bpf links and take no trampoline slot. Values are
// the object's section names; none is kernel-specific.
var sharedCandidateProbeSet = map[string]string{
	"opaque_real_owner_child_exit_candidate":       "tp_btf/sched_process_exit",
	"real_owner_capsule_terminal":                  "tp_btf/sys_exit",
	"opaque_real_owner_successful_birth_candidate": "raw_tp/sched_process_fork",
	// The kernel witness of lsm/bprm_committed_creds (review F2) and of
	// lsm/task_alloc (S1 review N1: a typed tp_btf for the child's task
	// storage mark).
	"d1_witness_exec": "tp_btf/sched_process_exec",
	"d1_witness_fork": "tp_btf/sched_process_fork",
}

// sharedCandidateCommandSet is the pinned set of enabled syscall commands:
// the product reaper's opaque_real_reap, which startLiveCandidate borrows and
// TEST_RUNs. A command is never attached and never disabled; every other
// syscall program (se_command) must be disabled by the packaged metadata.
var sharedCandidateCommandSet = map[string]ebpf.ProgramType{
	"opaque_real_reap": ebpf.Syscall,
}

// sharedCandidateCommandsOf is the exact enabled command set of a manifest
// (G2): sharedCandidateCommandSet, plus the 8 product publisher commands
// (sharedProductCommands) when the object carries the product publisher
// (ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE). The product
// commands come all or none; their exact syscall shape is checked by the
// caller, and product publication additionally requires them
// (validateSharedProductControl). A product command present in the object
// but disabled by the metadata is refused (it is in the set, so it must be
// an enabled, unattached syscall), never treated as absent: an object with
// the publisher compiled in always exposes all 8 commands.
func sharedCandidateCommandsOf(programs map[string]operators.NativeProgramResource) (map[string]ebpf.ProgramType, error) {
	out := maps.Clone(sharedCandidateCommandSet)
	present := 0
	for _, name := range sharedProductCommands {
		if _, ok := programs[name]; ok {
			present++
			out[name] = ebpf.Syscall
		}
	}
	if present != 0 && present != len(sharedProductCommands) {
		return nil, fmt.Errorf("shared candidate carries %d of the %d product publisher commands", present, len(sharedProductCommands))
	}
	return out, nil
}

// validateSharedCandidateGeometry requires the loaded TASK/WORK maps to be
// exactly the profile's geometry (sharedOpaqueOwnerGeometry): node TASK and
// WORK slots, per-binding accounts and binding count. A profile that differs
// from the object (for example the per-binding quota declared as the node
// total) is refused, never adapted.
func validateSharedCandidateGeometry(p SharedProfile, resources *operators.NativeResources) error {
	if resources == nil {
		return fmt.Errorf("missing shared candidate manifest")
	}
	want, _, err := sharedOpaqueOwnerGeometry(p)
	if err != nil {
		return fmt.Errorf("shared candidate profile: %w", err)
	}
	if p.exitTombstones() > math.MaxUint32 {
		return fmt.Errorf("shared candidate profile: exit tombstones exceed uint32")
	}
	maps.Copy(want, sharedExitCreditGeometry(p))
	for name, shape := range want {
		if got, ok := resources.Maps[name]; !ok || got != shape {
			return fmt.Errorf("shared candidate map %s is %+v, profile (tasks %d/%d per binding, work %d/%d, bindings %d) requires %+v",
				name, got, p.Tasks, p.PerBinding.Tasks, p.Scratch, p.PerBinding.Scratch, p.Bindings, shape)
		}
	}
	return nil
}

// sharedExitCreditGeometry is the exact credit-at-exit map geometry of
// profile p: the burst-sized node-wide tombstone table
// (SharedProfile.ExitTombstones; struct real_owner_exit_tombstone, 40 bytes),
// one tombstone gauge per binding, and the witness counters. A
// reduced-tombstone test build (SE_TEST_EXIT_TOMBSTONE_ENTRIES) is refused.
func sharedExitCreditGeometry(p SharedProfile) map[string]operators.NativeMapResource {
	return map[string]operators.NativeMapResource{
		"se_exit_tombstones":        {Type: uint32(ebpf.Hash), KeySize: 8, ValueSize: 40, MaxEntries: uint32(p.exitTombstones()), Flags: unix.BPF_F_RDONLY},
		"opaque_real_exit_accounts": {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8, MaxEntries: uint32(p.Bindings), Flags: unix.BPF_F_RDONLY},
		"opaque_real_exit_credit":   {Type: uint32(ebpf.Array), KeySize: 4, ValueSize: 8, MaxEntries: ExitCreditCounters, Flags: unix.BPF_F_RDONLY},
	}
}

// sharedExitCreditCapacity checks the credit-at-exit witness shape
// (opaque_real_exit_credit: an array of ExitCreditCounters u64 counters) and
// returns the tombstone capacity (se_exit_tombstones max_entries).
func sharedExitCreditCapacity(resources *operators.NativeResources) (uint64, error) {
	witness, ok := resources.Maps["opaque_real_exit_credit"]
	if !ok || witness.Type != uint32(ebpf.Array) || witness.KeySize != 4 || witness.ValueSize != 8 || witness.MaxEntries != ExitCreditCounters {
		return 0, fmt.Errorf("shared candidate credit-at-exit witness opaque_real_exit_credit missing or malformed")
	}
	tombstones, ok := resources.Maps["se_exit_tombstones"]
	if !ok || tombstones.MaxEntries == 0 {
		return 0, fmt.Errorf("shared candidate tombstone map se_exit_tombstones missing")
	}
	return uint64(tombstones.MaxEntries), nil
}

func sharedCandidateAttached(name string) bool {
	_, trampoline := sharedCandidateAttachSet[name]
	_, probe := sharedCandidateProbeSet[name]
	return trampoline || probe
}

const sharedProgramDisabled = "gadget_program_disabled"

// validateSharedCandidateAttachSet is qualification-only admission: exactly the
// pinned attach set plus the pinned syscall commands is enabled. It is not the
// product resource validator.
func validateSharedCandidateAttachSet(resources *operators.NativeResources) error {
	if resources == nil {
		return fmt.Errorf("missing shared candidate manifest")
	}
	for _, set := range []map[string]string{sharedCandidateAttachSet, sharedCandidateProbeSet} {
		for name := range set {
			p, ok := resources.Programs[name]
			if !ok || p.Target == "" || p.Target == sharedProgramDisabled {
				return fmt.Errorf("shared candidate attach program %s missing or disabled", name)
			}
		}
	}
	commands, err := sharedCandidateCommandsOf(resources.Programs)
	if err != nil {
		return err
	}
	for name, typ := range commands {
		p, ok := resources.Programs[name]
		if !ok || p.Type != uint32(typ) || p.Target != "" {
			return fmt.Errorf("shared candidate command %s missing, disabled or attached", name)
		}
	}
	// The pinned exit program settles credit at exit; its witness and
	// tombstone map are node health inputs (sharedLiveExitCredit).
	if _, err := sharedExitCreditCapacity(resources); err != nil {
		return err
	}
	// The capsule hooks are pinned; their witness is a node health input
	// (sharedLiveCapsule).
	if err := sharedCapsuleStatsShape(resources); err != nil {
		return err
	}
	for name, p := range resources.Programs {
		if _, command := commands[name]; command {
			continue // exact shape checked above
		}
		if !sharedCandidateAttached(name) && p.Target != sharedProgramDisabled {
			return fmt.Errorf("shared candidate program %s is outside the pinned attach set", name)
		}
	}
	return nil
}

// NewNodeEnforcer constructs a host-owned node handle without starting a gadget
// or allocating kernel resources. The HOST must pass WithNodeEnforcer to its
// existing manager's one StartGadget call, and retain this handle on any error.
func NewNodeEnforcer(config SharedNodeConfig) (*NodeEnforcer, error) {
	if _, err := config.Profile.Validate(); err != nil {
		return nil, err
	}
	if err := validateSharedNodeSelection(config); err != nil {
		return nil, err
	}
	return &NodeEnforcer{config: config, bindings: map[uint64]*BindingSession{}, host: &sharedHostState{}}, nil
}

// WithNodeEnforcer adds native ownership to the existing host gadget context.
// It does not construct an instance manager or a second runtime.
func WithNodeEnforcer(node *NodeEnforcer) gadgetcontext.Option {
	return func(gc *gadgetcontext.GadgetContext) {
		gc.SetVar(sharedNodeKey, node)
		gc.SetVar(operators.NativeOwnerRequiredKey, true)
		// No retry inside Start: Start runs under the manager's lifecycle
		// lock. A capacity refusal fails Start at once (rolled back) and
		// StartNode retries the whole host start outside the lock.
		gc.SetVar(operators.NativeAttachRetryKey, false)
		if node != nil && node.config.RecoveryDevelopment {
			gc.SetVar(operators.NativeRecoveryTestRunKey, true)
		}
		// G020: the image classifier's overlay layout for the running kernel
		// and this load's verdict epoch. Without an epoch no constants are
		// installed: admission then refuses a product object (M8).
		if constants, err := sharedImageOverlayConstants(); err == nil {
			gc.SetVar(operators.NativeConstantsKey, constants)
		}
		if node != nil && node.host != nil {
			if reason := sharedImageOverlayUnavailable(); reason != nil {
				node.host.overlayFailure.Store(&reason)
			} else {
				node.host.overlayFailure.Store(nil)
			}
		}
		gc.SetVar(operators.NativeResourceValidatorKey, func(resources *operators.NativeResources) error {
			if node == nil || node.host == nil {
				return fmt.Errorf("missing host-owned shared node")
			}
			if err := sharedNodeAttachFailFast(gc); err != nil {
				return err
			}
			return node.admitSharedResources(resources)
		})
	}
}

// validateSharedProductConstants (review M8): a product object is admitted
// only with its native constants set (operators.NativeResources.Constants):
// the classifier's se_image_ovl_layout (UNSET off the matrix is a value, a
// missing one is a refusal) and the verdict event's se_verdict_load_epoch.
// The eBPF operator itself keeps skipping absent names for other gadgets.
func validateSharedProductConstants(resources *operators.NativeResources) error {
	// D3: also the probed FMODE_BACKING bit (se_image_fmode_backing; unset is
	// a value that refuses every overlay file, a missing one is a refusal).
	for name, size := range map[string]uint32{sharedImageOverlayLayoutConstant: 4, sharedImageFmodeBackingConstant: 4, sharedVerdictLoadEpochConstant: 8} {
		if got, ok := resources.Constants[name]; !ok || got != size {
			return fmt.Errorf("product object native constant %s not set as a %d-byte constant", name, size)
		}
	}
	return nil
}

func (n *NodeEnforcer) admitSharedResources(resources *operators.NativeResources) (err error) {
	if n.host != nil && n.host.product {
		// Every product refusal is typed (fail closed with the reason).
		defer func() {
			if err != nil && !errors.Is(err, ErrSharedNativeUnavailable) {
				err = fmt.Errorf("shared product image refused: %w: %w", err, ErrSharedNativeUnavailable)
			}
		}()
	}
	// Product admission (every path but the tagged qualification one)
	// refuses diagnostic-twin maps by name before any allowlist.
	if n.host == nil || !n.host.qualified || !sharedQualificationBuild {
		if err := refuseSharedProductForbiddenMaps(resources); err != nil {
			return err
		}
	}
	if n.config.RecoveryDevelopment {
		if err := validateSharedRecoveryImageGeometry(n.config.Profile, resources); err != nil {
			return err
		}
		return fmt.Errorf("recovered native supervisor and link retention are not implemented: %w", ErrSharedNativeUnavailable)
	}
	// Set only by startQualifiedSharedNode in a qualification build, or by
	// startProductSharedNode in a product build.
	live := n.host.liveHost()
	if hasSharedOpaqueTaskMaps(resources) && !live {
		var err error
		if _, hasWork := resources.Maps["se_opaque_work_accounts"]; hasWork {
			_, err = validateSharedOpaqueOwnerResources(n.config.Profile, resources)
		} else {
			_, err = validateSharedOpaqueTaskResources(n.config.Profile, resources)
		}
		if err != nil {
			return err
		}
		return fmt.Errorf("opaque TASK/WORK product hooks and source cleanup are incomplete: %w", ErrSharedNativeUnavailable)
	}
	if live {
		if n.host.product {
			// The exact generated product name sets (no diagnostic,
			// recovery or test resource, every command).
			if err := validateSharedProductManifest(resources); err != nil {
				return err
			}
		}
		// The live candidate validators; the product validators above
		// refuse this image.
		if err := validateSharedCandidateGeometry(n.config.Profile, resources); err != nil {
			return err
		}
		if err := validateSharedCandidateAttachSet(resources); err != nil {
			return err
		}
		// A product-publisher object is admitted only with its exact
		// tail-call slots (pre-load: the operator installs them before
		// attach), so the hooks it arms can reach a verdict, and never with
		// a userspace-writable test gate (its hooks are armed only by the
		// authenticated configuration).
		if n.host.product || sharedHasProductCommands(resources) {
			if err := validateSharedProductNoTestGate(resources); err != nil {
				return err
			}
			if err := validateSharedProductTailCalls(resources); err != nil {
				return err
			}
			if err := validateSharedProductCapsules(resources); err != nil {
				return err
			}
			if err := validateSharedProductWorkSync(resources); err != nil {
				return err
			}
			if err := validateSharedVerdictCounters(resources); err != nil {
				return err
			}
			if err := validateSharedProductConstants(resources); err != nil {
				return err
			}
		}
		n.mu.Lock()
		defer n.mu.Unlock()
		if n.closing || n.closed || n.host.released {
			return fmt.Errorf("shared native admission closed")
		}
		n.host.admitted = sharedAdmittedCopy(resources)
		return nil
	}
	if hasSharedPoolMaps(resources) {
		if _, err := validateSharedPoolImageResources(n.config.Profile, resources); err != nil {
			return err
		}
		return fmt.Errorf("fixed task/work pool product migration is incomplete: %w", ErrSharedNativeUnavailable)
	}
	if resources != nil {
		if _, fullImage := resources.Maps["se_tasks"]; fullImage {
			usage, err := validateSharedImageResources(n.config.Profile, resources)
			if err != nil {
				return err
			}
			if usage.PendingEnforcementQualification {
				return fmt.Errorf("shared image lifetime/qualification proofs remain unavailable: %w", ErrSharedNativeUnavailable)
			}
			return ErrSharedNativeUnavailable // qualification/publication remains unavailable
		}
	}
	if _, err := validateSharedProtocolResources(n.config.Profile, resources); err != nil {
		return err
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.host == nil || n.closing || n.closed || n.host.released {
		return fmt.Errorf("shared native admission closed")
	}
	// Accepted manifests have no nested map templates; shallow value copies are
	// complete independent snapshots. Never retain caller-mutable map registries.
	n.host.admitted = sharedAdmittedCopy(resources)
	return nil
}

// validateSharedProductManifest requires the exact generated product name
// sets (shared_product_manifest.go): every map and program of the product
// object, nothing more, nothing less.
func validateSharedProductManifest(resources *operators.NativeResources) error {
	if resources == nil {
		return fmt.Errorf("missing native resources")
	}
	if got := slices.Sorted(maps.Keys(resources.Maps)); !slices.Equal(got, sharedProductManifestMaps) {
		return fmt.Errorf("map set differs from the product manifest: extra %v, missing %v", sharedSetDiff(got, sharedProductManifestMaps), sharedSetDiff(sharedProductManifestMaps, got))
	}
	if got := slices.Sorted(maps.Keys(resources.Programs)); !slices.Equal(got, sharedProductManifestPrograms) {
		return fmt.Errorf("program set differs from the product manifest: extra %v, missing %v", sharedSetDiff(got, sharedProductManifestPrograms), sharedSetDiff(sharedProductManifestPrograms, got))
	}
	return nil
}

// sharedSetDiff is a minus b, both sorted.
func sharedSetDiff(a, b []string) []string {
	var out []string
	for _, v := range a {
		if _, found := slices.BinarySearch(b, v); !found {
			out = append(out, v)
		}
	}
	return out
}

// admitSharedProductImage admits the product image on the running kernel:
// the product kernel gate (SharedProductKernel, re-run here, at
// instantiation); every probe program's effective target (resources, after
// any attach_to override) is its section's own target; and the loaded eBPF
// object's sha256 (operators.NativeProgramDigestKey) is one of this
// release's product objects (sharedProductObjects), on every kernel alike.
// Every refusal wraps ErrSharedNativeUnavailable.
func admitSharedProductImage(gc operators.GadgetContext, metadata *viper.Viper, resources *operators.NativeResources) error {
	kernel, err := sharedProductKernelCheck()
	if err != nil {
		return err
	}
	refuse := func(cause error) error {
		return fmt.Errorf("shared product image refused on %s: %w: %w", kernel.Release, cause, ErrSharedNativeUnavailable)
	}
	if resources == nil {
		return refuse(fmt.Errorf("missing native resources"))
	}
	// D1: every probe's target is its section's own (tracepoints); no
	// program takes a per-kernel symbol, and the metadata must not carry
	// an attach_to override for any of them.
	for name, section := range sharedCandidateProbeSet {
		_, want, _ := strings.Cut(section, "/")
		if got := metadata.GetString("programs." + name + ".attach_to"); got != "" {
			return refuse(fmt.Errorf("probe %s carries an attach_to override %q", name, got))
		}
		program, ok := resources.Programs[name]
		if !ok || program.Target != want {
			return refuse(fmt.Errorf("probe %s targets %q, want %q", name, program.Target, want))
		}
	}
	value, _ := gc.GetVar(operators.NativeProgramDigestKey)
	digest, _ := value.(string)
	if digest == "" {
		return refuse(fmt.Errorf("eBPF object digest unavailable"))
	}
	if !sharedProductObject(digest) {
		return refuse(fmt.Errorf("eBPF object sha256 %s is not a product object of this release", digest))
	}
	return nil
}

// checkSharedPossibleCPUs refuses a host whose possible CPU count is
// outside 1..64 (the shared maps' hard limit) or above the profile's
// PossibleCPUs: the node does not start (fail closed).
func checkSharedPossibleCPUs(cpus int, profile SharedProfile) error {
	if cpus < 1 || cpus > 64 || uint32(cpus) > profile.PossibleCPUs {
		return fmt.Errorf("actual possible CPUs %d exceed shared profile (limit %d, hard limit 64): %w", cpus, profile.PossibleCPUs, ErrSharedNativeUnavailable)
	}
	return nil
}

func instantiateSharedNode(gc operators.GadgetContext, metadata *viper.Viper, node *NodeEnforcer) (_ operators.DataOperatorInstance, err error) {
	if node == nil || node.host == nil || metadata == nil {
		return nil, fmt.Errorf("shared image requires its host-owned native node")
	}
	if node.host.product {
		// Every product refusal is typed (fail closed with the reason).
		defer func() {
			if err != nil && !errors.Is(err, ErrSharedNativeUnavailable) {
				err = fmt.Errorf("shared product image refused: %w: %w", err, ErrSharedNativeUnavailable)
			}
		}()
	}
	recoveryAnnotation := metadata.GetString("annotations.enforce-exec-shared-recovery")
	if (node.config.RecoveryDevelopment && recoveryAnnotation != "1") || (!node.config.RecoveryDevelopment && recoveryAnnotation != "") || !node.config.ABI3Development || gc.ImageName() != node.config.Image || metadata.GetString("annotations.enforce-exec-owner-abi") != "3" || !metadata.GetBool("annotations.enforce-exec-owner-development") || metadata.GetString("annotations.enforce-exec-shared-profile") != "1" || metadata.GetBool("annotations.enforce-exec") || metadata.GetBool("annotations.enforce-exec-full") {
		return nil, fmt.Errorf("shared image/native capability mismatch")
	}
	if err := admitSharedEventABI(metadata); err != nil {
		return nil, err
	}
	for key, want := range sharedGeometryAnnotations(node.config.Profile) {
		if metadata.GetString(key) != want {
			return nil, fmt.Errorf("shared image geometry mismatch: %s", strings.TrimPrefix(key, "annotations.enforce-exec-shared-"))
		}
	}
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	if err := checkSharedPossibleCPUs(cpus, node.config.Profile); err != nil {
		return nil, err
	}
	value, _ := gc.GetVar(operators.NativeResourcesKey)
	resources, _ := value.(*operators.NativeResources)
	// The product node binds the kernel and the image first (kernel
	// admission, every probe target, the object bytes), before any resource
	// admission.
	if node.host.product {
		if err = admitSharedProductImage(gc, metadata, resources); err != nil {
			return nil, err
		}
	}
	if err = node.admitSharedResources(resources); err != nil {
		return nil, err
	}
	// The qualified candidate (qualification builds only) is admitted on the
	// product gate's checks (the product node was checked above); no other
	// shared node runs a collection.
	if !node.host.product {
		if !node.host.qualified || !sharedQualificationBuild {
			return nil, fmt.Errorf("shared image requires a product or qualification node")
		}
		if err = verifySharedCandidateKernel(); err != nil {
			return nil, err
		}
	}
	node.mu.Lock()
	defer node.mu.Unlock()
	if node.host.claimed || node.host.released || node.closing || node.closed {
		return nil, fmt.Errorf("shared native node already claimed")
	}
	node.host.claimed = true
	node.host.context = gc
	return sharedOperatorInstance(node), nil
}

// sharedOperatorInstance is the operator instance of a claimed shared node:
// sharedQualifiedOperator only for a live node (a qualified node in a
// qualification build, or a product node).
func sharedOperatorInstance(node *NodeEnforcer) operators.DataOperatorInstance {
	if node.host.liveHost() {
		return sharedQualifiedOperator{node}
	}
	return node
}

// sharedQualifiedOperator is the live node's operator instance (qualified
// or product; the name predates the product node). The gadget context stops
// a gadget whose operator Readiness fails right after Start, while
// NodeEnforcer.Ready fails until the node is enforcing (a qualified node
// never is; a product node may be Ready with zero bindings but still fails
// on, e.g., a refused Strict namespace), so the host gadget, and with it the
// live collection, would be torn down before any Bind. Its operator
// readiness is therefore startup readiness only: the live candidate exists
// and every receipt, the product reaper and credit at exit are healthy.
// Enforcement readiness stays NodeEnforcer.Ready.
type sharedQualifiedOperator struct{ *NodeEnforcer }

func (o sharedQualifiedOperator) Ready(gc operators.GadgetContext) error {
	n := o.NodeEnforcer
	n.mu.Lock()
	var err error
	var health sharedLiveHealth
	var product bool
	var strictRefused error
	if n.host == nil || n.host.context != gc || n.host.live == nil || n.closing || n.closed {
		err = fmt.Errorf("shared candidate startup incomplete")
	} else {
		health = n.liveHealthLocked()
		product, strictRefused = n.host.product, n.host.strictRefused
	}
	n.mu.Unlock()
	switch {
	case err != nil:
	case product:
		// Product startup: the NotReady inputs, the Strict namespace and
		// the kernel controls only; Degraded never fails startup.
		err = sharedProductReady(health, strictRefused)
	default:
		err = health.check()
	}
	// StartNode reports success only after this gate, right before the gadget
	// context publishes the gadget as running; a failure ends the gadget.
	n.signalStarted(err)
	return err
}

// signalStarted delivers the qualified startup result to StartNode once.
func (n *NodeEnforcer) signalStarted(err error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.host != nil && n.host.started != nil {
		n.host.started <- err
		n.host.started = nil
	}
}

// sharedGeometryAnnotations is the image metadata a shared image must carry
// for profile p (metadata keys, as read by instantiateSharedNode).
func sharedGeometryAnnotations(p SharedProfile) map[string]string {
	values := map[string]uint64{"images": p.Images, "image-quota": p.PerBinding.Images, "inode-facts": p.InodeFacts, "inode-quota": p.PerBinding.InodeFacts, "tasks": p.Tasks, "scratch": p.Scratch, "accepted-uids": p.AcceptedUIDs, "task-quota": p.PerBinding.Tasks, "scratch-quota": p.PerBinding.Scratch, "bindings": p.Bindings, "exit-tombstones": p.exitTombstones(), "verdict-ring": p.verdictRing(), "slots-256": p.PolicySlots[0], "slots-1024": p.PolicySlots[1], "slots-4096": p.PolicySlots[2], "slots-16384": p.PolicySlots[3]}
	out := make(map[string]string, len(values))
	for key, value := range values {
		out["annotations.enforce-exec-shared-"+key] = strconv.FormatUint(value, 10)
	}
	return out
}

func (*NodeEnforcer) Name() string { return "enforce-exec-shared-node" }

// Start borrows and verifies the actual host-loaded program/map identities,
// then sets up the frozen, physical-thread-qualified command capability.
// Successful protocol startup is NOT complete shared enforcement readiness.
func (n *NodeEnforcer) Start(gc operators.GadgetContext) error {
	n.mu.Lock()
	if gc == nil || n.host == nil || !n.host.claimed || n.host.context != gc || n.host.control != nil || n.host.startAttempted || n.closing || n.closed {
		n.mu.Unlock()
		return fmt.Errorf("invalid shared host startup")
	}
	n.host.startAttempted = true
	ctx, cancel := context.WithCancel(gc.Context())
	done := make(chan struct{})
	n.host.startup = sharedStartupOperation{cancel: cancel, done: done}
	admitted := n.host.admitted
	n.mu.Unlock()
	defer func() { cancel(); n.mu.Lock(); n.host.startup = sharedStartupOperation{}; close(done); n.mu.Unlock() }()
	if n.host.qualified || n.host.product {
		err := n.startLiveCandidate(gc, admitted)
		if err != nil {
			// Success is signalled by the operator Readiness, not here.
			n.signalStarted(err)
		}
		return err
	}
	r, err := sharedControlResourcesFromContext(gc)
	n.mu.Lock()
	n.host.resources = r
	n.host.borrowed = r.borrowedHandles()
	n.mu.Unlock()
	if err != nil {
		return err
	}
	r.manifest = admitted
	n.mu.Lock()
	n.host.resources = r
	n.mu.Unlock()
	// Exact protocol-only capability, not an absence-of-se_tasks heuristic.
	if _, err = validateSharedProtocolResources(n.config.Profile, r.manifest); err != nil {
		return err
	}
	control, err := newSharedControl(ctx, n.config.Profile, r)
	n.mu.Lock()
	n.host.control = control
	n.mu.Unlock()
	if err != nil {
		return err
	}
	// newSharedControl validated actual loaded identities before this allocation.
	// Fixed slots are allocated only after explicit native resource admission.
	slots := make([]*sharedPhysicalScope, n.config.Profile.Bindings)
	objects := newSharedObjectRegistry(n.config.Profile)
	n.mu.Lock()
	n.host.protocol = &sharedProtocolCapability{}
	n.host.scopeSlots = slots
	n.objects = objects
	n.mu.Unlock()
	receipt, err := control.call(ctx, sharedCommandWire{Operation: sharedNodeInspect})
	if err == nil && (receipt.Value != SharedProfileVersion || receipt.Serial != 0 || receipt.Generation != 0) {
		err = fmt.Errorf("shared protocol handshake receipt mismatch")
	}
	n.mu.Lock()
	n.host.handshakeComplete = err == nil
	n.mu.Unlock()
	return err
}

func (n *NodeEnforcer) Ready(gc operators.GadgetContext) error {
	n.mu.Lock()
	if n.host == nil || n.host.context != gc || (n.host.control == nil && n.host.live == nil) || n.closing || n.closed {
		n.mu.Unlock()
		return fmt.Errorf("shared host startup incomplete")
	}
	if n.host.live != nil {
		// Receipt and witness reads run outside n.mu.
		health := n.liveHealthLocked()
		product, strictRefused := n.host.product, n.host.strictRefused
		n.mu.Unlock()
		if product {
			return sharedProductReady(health, strictRefused)
		}
		// A live qualification collection still has no published policy.
		return errors.Join(ErrSharedNativeUnavailable, health.check(), n.adoptionDegraded(), n.revisionDegraded(), n.verdictLossDegraded(), n.overlayDegraded())
	}
	n.mu.Unlock()
	// Routing, union evaluator adaptation, qualified history publication and
	// required attachment receipts are not integrated. Never advertise protection.
	return ErrSharedNativeUnavailable
}

// sharedProductReady is a live product node's Ready (plan Q3, Q6, F2, F5):
// nil, also with zero bindings, unless a NotReady health input fails, Strict
// publication is refused (the agent is outside the initial pid/time
// namespaces) or a kernel control re-read now fails (ftrace off,
// livepatch). Every failure wraps ErrSharedNodeNotReady. Degraded inputs
// never fail it (NodeEnforcer.Degraded).
func sharedProductReady(health sharedLiveHealth, strictRefused error) error {
	notReady, _ := health.checks()
	if strictRefused != nil {
		notReady = append(notReady, fmt.Errorf("strict publication refused: %w", strictRefused))
	}
	if err := checkSharedProductKernelRuntime(sharedProductKernelProbes); err != nil {
		notReady = append(notReady, err)
	}
	if len(notReady) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrSharedNodeNotReady, errors.Join(notReady...))
}

// Degraded joins the live node's Degraded conditions (nil: none): a
// fail-closed Degraded window, the image ledger (G020 ruling), a refused
// adoption, a revision report, verdict loss and the overlay layout. It
// never makes Ready fail. A node that is not live reports startup
// incomplete.
func (n *NodeEnforcer) Degraded(gc operators.GadgetContext) error {
	n.mu.Lock()
	if n.host == nil || n.host.context != gc || n.host.live == nil || n.closing || n.closed {
		n.mu.Unlock()
		return fmt.Errorf("shared host startup incomplete")
	}
	health := n.liveHealthLocked()
	n.mu.Unlock()
	_, degraded := health.checks()
	return errors.Join(append(degraded, n.adoptionDegraded(), n.revisionDegraded(), n.verdictLossDegraded(), n.overlayDegraded())...)
}

// BeforeStop must precede host StopGadget. It joins native commands; it neither
// closes borrowed maps nor claims that manager attachment teardown happened.
func (n *NodeEnforcer) BeforeStop(ctx context.Context) error {
	return n.beforeStopProtocolUsing(ctx, nil)
}

func (n *NodeEnforcer) beforeStopProtocolUsing(ctx context.Context, transport sharedCommandTransport) error {
	n.stopMu.Lock()
	defer n.stopMu.Unlock()
	n.mu.Lock()
	if n.host == nil {
		n.mu.Unlock()
		return fmt.Errorf("not a host-owned shared node")
	}
	if n.host.commandsJoined {
		err := n.host.cleanupErr
		n.mu.Unlock()
		return err
	}
	n.mu.Unlock()
	if err := n.cancelAndJoinPreparations(ctx); err != nil {
		return err
	}
	n.mu.Lock()
	sessions := make([]*BindingSession, 0, len(n.bindings))
	for _, s := range n.bindings {
		sessions = append(sessions, s)
	}
	control := n.host.control
	protocol := n.host.protocol != nil
	n.mu.Unlock()
	for _, s := range sessions {
		if s.account == nil {
			return ErrSharedNativeUnavailable
		}
		s.account.mu.Lock()
		registered := s.account.registration.Sequence != 0 || s.account.native.attempted
		s.account.mu.Unlock()
		if registered && protocol {
			continue
		} // retain until real whole-node destruction
		// Ordinary Remove remains strict for all registered/ambiguous accounts.
		// A live published route is removed at its own last-good generation.
		s.account.mu.Lock()
		generation := s.account.route.state.Generation
		s.account.mu.Unlock()
		if err := s.Remove(ctx, generation); err != nil {
			return err
		}
	}
	var cleanup error
	if protocol {
		cleanup = errors.Join(n.settleProtocolScopes(ctx, control, transport), n.settleSharedObjects(ctx, transport))
	}
	// Unknown outcome is not an unjoined invocation: protocol-only jobs have
	// synchronously returned, and this sole program has no attached consumers.
	// Keep every unresolved record/pin through actual collection destruction.
	err := errors.Join(cleanup, control.close())
	n.mu.Lock()
	n.host.cleanupErr = err
	n.host.commandsJoined = true // close joins even when it returns a sticky thread failure
	n.mu.Unlock()
	return err
}

func (n *NodeEnforcer) Stop(gc operators.GadgetContext) error {
	if gc == nil {
		return fmt.Errorf("missing shared host context")
	}
	// The eBPF operator (lower priority) stops and closes the collection
	// after this operator; the reaper, the recycle loops and the publisher
	// (its pollers and admin thread) must not outlive its programs. The
	// sessions are removed (routes withdrawn) first, while the publisher is
	// alive, then the publisher closes.
	n.stopLiveHealth()
	// Never under the gadget's (possibly already canceled) context: a
	// canceled removal would leave the sessions while the publisher closes,
	// and a later StopNode could no longer withdraw them.
	// Bounded: a removal that cannot finish in time leaves its route
	// latched (withdrawLiveRoute records it pending once the publisher is
	// closed), never a hang.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(gc.Context()), sharedTeardownTimeout)
	defer cancel()
	err := n.BeforeStop(ctx)
	return errors.Join(err, n.closeLivePublisher())
}

func (n *NodeEnforcer) Close(gc operators.GadgetContext) error {
	n.mu.Lock()
	valid := gc != nil && n.host != nil && n.host.context == gc
	n.mu.Unlock()
	if !valid {
		return fmt.Errorf("foreign shared host close")
	}
	n.stopLiveHealth() // also on a startup failure, where Stop never ran
	ctx, cancel := context.WithTimeout(context.WithoutCancel(gc.Context()), sharedTeardownTimeout)
	defer cancel()
	err := n.BeforeStop(ctx)
	err = errors.Join(err, n.closeLivePublisher())
	n.mu.Lock()
	if !n.host.commandsJoined || (len(n.bindings) != 0 && n.host.protocol == nil) {
		n.mu.Unlock()
		if err != nil {
			return err
		}
		return fmt.Errorf("shared cleanup has not joined")
	}
	n.host.operatorClosed = true
	n.closed = true
	n.mu.Unlock()
	return err
}

// ReleaseAfterDetach is called only after HOST manager teardown has joined.
// Known borrowed handles must be closed too. No map-ID absence/RSS proof is
// inferred, and this method never closes a collection owned by that manager.
func (n *NodeEnforcer) ReleaseAfterDetach() error {
	n.mu.Lock()
	if n.host == nil {
		n.mu.Unlock()
		return fmt.Errorf("not a host-owned shared node")
	}
	if n.host.claimed && !n.host.operatorClosed {
		n.mu.Unlock()
		return fmt.Errorf("host shared operator teardown not joined")
	}
	if len(n.preparations) != 0 || n.host.startup.done != nil || (n.objects != nil && n.objects.operation.done != nil) || (len(n.bindings) != 0 && (n.host.protocol == nil || !n.host.commandsJoined || !n.host.operatorClosed)) {
		n.mu.Unlock()
		return fmt.Errorf("shared preparations/sessions have not joined")
	}
	for _, a := range n.scopes {
		if a.native.done != nil {
			n.mu.Unlock()
			return fmt.Errorf("native scope operation not joined")
		}
	}
	// Inspect both the retained partial-start ledger and current resource set.
	// No passing check is inferred from a map/manifest name or collection Close.
	for _, h := range append(n.host.resources.borrowedHandles(), n.host.borrowed...) {
		if h.FD() >= 0 {
			n.mu.Unlock()
			return fmt.Errorf("borrowed shared handles remain live")
		}
	}
	if n.objects != nil {
		// Unresolved records are destroyed with the actual protocol collection,
		// not converted into acknowledged native cleanup receipts.
		clear(n.objects.slots)
		clear(n.objects.records)
		clear(n.objects.scopes)
		n.objects.retainedBytes = 0
		n.objects.destroyed = true
	}
	n.host.released = true
	n.closed = true
	protocol := n.host.protocol != nil
	n.mu.Unlock()
	// Verified detach: the verdict counters' Final snapshot.
	n.finalizeVerdictCounters()
	if protocol {
		n.retireProtocolSessionsAfterDetach()
	}
	// A failed trusted lease Close retains the account for this same retry path.
	return n.releasePhysicalScopes()
}

// startLiveCandidate borrows exactly the pinned attach set's native receipts
// (15 trampoline links, task_free 2, plus the 5 pinned raw_tp/tp_btf links).
// The eBPF operator published them only after the whole transaction attached;
// their Check is the operator's nativeReadinessCheck (link present by ID,
// same program). It then starts the product reaper over the borrowed
// opaque_real_reap command and reap maps; a missing handle fails startup.
// Route slots are allocated here, one per binding.
func (n *NodeEnforcer) startLiveCandidate(gc operators.GadgetContext, admitted *operators.NativeResources) error {
	if admitted == nil {
		return fmt.Errorf("shared candidate was not admitted")
	}
	want := len(sharedCandidateAttachSet) + len(sharedCandidateProbeSet)
	receipts := make(map[string]*operators.NativeAttachment, want)
	for name := range admitted.Programs {
		value, _ := gc.GetVar(operators.NativeAttachmentPrefix + name)
		receipt, _ := value.(*operators.NativeAttachment)
		pinned := sharedCandidateAttached(name)
		if receipt != nil && !pinned {
			return fmt.Errorf("shared candidate attached %s outside the pinned attach set", name)
		}
		if pinned {
			if receipt == nil || receipt.Check == nil || receipt.LinkID == 0 || receipt.ProgramID == 0 {
				return fmt.Errorf("shared candidate receipt for %s unavailable", name)
			}
			receipts[name] = receipt
		}
	}
	if len(receipts) != want {
		return fmt.Errorf("shared candidate has %d of %d attach receipts", len(receipts), want)
	}
	for name, receipt := range receipts {
		if err := receipt.Check(); err != nil {
			return fmt.Errorf("shared candidate receipt %s: %w", name, err)
		}
	}
	// The root barrier of a product node: verified once every link is
	// present, after the kernel gate admitted the kernel
	// (admitSharedProductImage). A failure is NotReady.
	if n.host.product {
		verify := n.host.rootBarrier
		if verify == nil {
			verify = verifySharedRootBarrier
		}
		if err := verify(gc, receipts); err != nil {
			return err
		}
		// The executable-mapping gate's self-test: both em_* programs
		// must refuse a file mapping of a probe thread. It runs before the
		// canary, which cannot prove em_file_mprotect. A failure is NotReady.
		verifyMap := n.host.execMap
		if verifyMap == nil {
			verifyMap = verifySharedExecMap
		}
		if err := verifyMap(gc); err != nil {
			return err
		}
	}
	// D1 objects (the d1_witness map): every attached program must have run
	// before the node is live, then the kernel witness is armed.
	// The map is REQUIRED: an object without it is refused, never run
	// without its canary and witness.
	if m, ok := admitted.Maps[sharedKernelWitnessMap]; !ok || m.Type != uint32(ebpf.Array) || m.KeySize != 4 || m.ValueSize != sharedKernelWitnessCellSize || m.MaxEntries != sharedKernelWitnessCells {
		return fmt.Errorf("shared candidate kernel witness map %s missing or malformed", sharedKernelWitnessMap)
	}
	witness, err := sharedStartKernelWitness(gc, receipts, n.config.FailClosedPollInterval, n.config.CanaryCommand)
	if err != nil {
		return err
	}
	capacity, err := sharedExitCreditCapacity(admitted)
	if err != nil {
		return err
	}
	borrowExit := n.host.exitCredit
	if borrowExit == nil {
		borrowExit = borrowSharedExitCredit
	}
	read, err := borrowExit(gc)
	if err != nil || read == nil {
		return errors.Join(err, fmt.Errorf("shared candidate credit-at-exit witness unavailable"))
	}
	// The window opens here: every later health check compares against it.
	baseline, err := read()
	if err != nil {
		return fmt.Errorf("shared candidate credit-at-exit witness unreadable: %w", err)
	}
	exit := &sharedLiveExitCredit{read: read, capacity: capacity, baseline: baseline}
	if err := sharedCapsuleStatsShape(admitted); err != nil {
		return err
	}
	borrowCapsule := n.host.capsuleStats
	if borrowCapsule == nil {
		borrowCapsule = borrowSharedCapsuleStats
	}
	readCapsule, err := borrowCapsule(gc)
	if err != nil || readCapsule == nil {
		return errors.Join(err, fmt.Errorf("shared candidate exec-capsule witness unavailable"))
	}
	capsuleBaseline, err := readCapsule()
	if err != nil {
		return fmt.Errorf("shared candidate exec-capsule witness unreadable: %w", err)
	}
	capsule := &sharedLiveCapsule{read: readCapsule, baseline: capsuleBaseline}
	birthPark, err := n.newLiveBirthPark(gc, admitted)
	if err != nil {
		return err
	}
	facts, err := n.newLiveFactStats(gc, admitted)
	if err != nil {
		return err
	}
	verdict, err := n.newLiveVerdict(gc, admitted)
	if err != nil {
		return err
	}
	verdictInstalled := false
	defer func() {
		if !verdictInstalled {
			verdict.close()
		}
	}()
	// The fail-closed rate window opens here too; its poller starts only
	// once the candidate is installed (a refused startup leaves none).
	failClosed, err := n.newLiveFailClosed(gc, admitted)
	if err != nil {
		return err
	}
	// The route publisher (for a product object, the node's admin control)
	// is installed before the reaper (design 12): a refused control leaves
	// no reaper to stop.
	var publisher SharedRoutePublisher
	newPublisher := n.host.newPublisher
	if newPublisher == nil && sharedHasProductCommands(admitted) {
		// G1: an object with the product publisher gets the adopting product
		// publisher; a qualification override (SharedNodeQualification.Publisher)
		// still wins.
		newPublisher = func(gc operators.GadgetContext) (SharedRoutePublisher, error) {
			if n.host.newProductPublisher != nil {
				return n.host.newProductPublisher(gc, admitted)
			}
			return n.borrowSharedProductPublisher(gc, admitted)
		}
	}
	closePublisher := func() error {
		if publisher == nil {
			return nil
		}
		return publisher.Close()
	}
	if newPublisher != nil {
		if publisher, err = newPublisher(gc); err != nil || sharedNilPublisher(publisher) {
			if err != nil || publisher != nil {
				// A failed factory owns its partial result; a value that came
				// back with an error is never used (it may be a typed nil).
				publisher = nil
			}
			return errors.Join(err, closePublisher(), fmt.Errorf("shared candidate route publisher unavailable"))
		}
	}
	if r, ok := publisher.(interface{ setOnReleased(func(uint32, uint64)) }); ok {
		r.setOnReleased(n.releasedAdoptionSlot)
	}
	newReaper := n.host.newReaper
	if newReaper == nil {
		newReaper = borrowSharedCandidateReaper
	}
	reaper := &sharedLiveReaper{}
	r, err := newReaper(gc, ReaperConfig{Hooks: ReaperHooks{Fault: reaper.onFault}})
	if err != nil || r == nil {
		return errors.Join(err, fmt.Errorf("shared candidate product reaper unavailable"), closePublisher())
	}
	// The reaper is stopped explicitly (stopLiveHealth), always before the
	// collection closes; it does not end with the gadget context.
	if err := reaper.start(context.WithoutCancel(gc.Context()), r); err != nil {
		return errors.Join(fmt.Errorf("shared candidate product reaper: %w", err), closePublisher())
	}
	n.mu.Lock()
	var refused error
	switch {
	case n.closing || n.closed:
		refused = fmt.Errorf("node stopping")
	case n.host.live != nil:
		refused = fmt.Errorf("shared candidate already live")
	}
	if refused != nil {
		n.mu.Unlock()
		// Outside n.mu: closing the publisher joins its pollers and ends
		// its admin thread.
		return errors.Join(refused, closePublisher(), reaper.stop())
	}
	defer n.mu.Unlock()
	n.host.scopeSlots = make([]*sharedPhysicalScope, n.config.Profile.Bindings)
	n.host.live = &sharedLiveCandidate{receipts: receipts, publisher: publisher, reaper: reaper, exit: exit, capsule: capsule, birthPark: birthPark, facts: facts, failClosed: failClosed, verdict: verdict}
	verdictInstalled = true
	n.host.live.witness = witness
	if witness != nil {
		witness.start() // joined by stopLiveHealth
	}
	if failClosed != nil {
		failClosed.start() // joined by stopLiveHealth
	}
	return nil
}

// borrowSharedCandidateReaper builds the product reaper over handles the
// eBPF operator published in the host gadget context: the opaque_real_reap
// command (operators.ProgramPrefix) and the collection's maps
// (operators.MapPrefix). The operator owns and closes them; the reaper only
// closes its own ringbuf reader. They are deliberately not added to
// host.borrowed, which ReleaseAfterDetach requires closed.
func borrowSharedCandidateReaper(gc operators.GadgetContext, config ReaperConfig) (*Reaper, error) {
	value, _ := gc.GetVar(operators.ProgramPrefix + "opaque_real_reap")
	program, _ := value.(*ebpf.Program)
	if program == nil {
		return nil, fmt.Errorf("shared candidate command opaque_real_reap was not published")
	}
	value, _ = gc.GetVar(operators.NativeResourcesKey)
	resources, _ := value.(*operators.NativeResources)
	if resources == nil {
		return nil, fmt.Errorf("shared candidate manifest unavailable")
	}
	c := &ebpf.Collection{Programs: map[string]*ebpf.Program{"opaque_real_reap": program}, Maps: map[string]*ebpf.Map{}}
	for name := range resources.Maps {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		if m, _ := value.(*ebpf.Map); m != nil {
			c.Maps[name] = m
		}
	}
	// NewReaper refuses a missing reap map or program by name.
	return NewReaper(c, config)
}

// sharedExitCreditRead reads the credit-at-exit witness counters.
type sharedExitCreditRead func() ([ExitCreditCounters]uint64, error)

// borrowSharedExitCredit reads opaque_real_exit_credit through the map handle
// the eBPF operator published (operators.MapPrefix); the operator owns it.
func borrowSharedExitCredit(gc operators.GadgetContext) (sharedExitCreditRead, error) {
	value, _ := gc.GetVar(operators.MapPrefix + "opaque_real_exit_credit")
	m, _ := value.(*ebpf.Map)
	if m == nil {
		return nil, fmt.Errorf("shared candidate map opaque_real_exit_credit was not published")
	}
	return func() ([ExitCreditCounters]uint64, error) {
		var out [ExitCreditCounters]uint64
		for i := range out {
			if err := m.Lookup(uint32(i), &out[i]); err != nil {
				return out, fmt.Errorf("opaque_real_exit_credit[%d]: %w", i, err)
			}
		}
		return out, nil
	}, nil
}

// sharedLiveExitCredit is node health over the credit-at-exit witness: the
// window from node start (baseline) to each check. A lease fault, a stuck
// held lease, a tombstone fault, a stale tombstone, a faulted settlement, a
// refused insert or the high-water mark (ExitCreditCheck: Degraded), or an
// unreadable or inconsistent witness (Unknown) is a sticky fault: those
// slots stay charged fail-closed and the reaper never sees them as faults.
// Busy (-EBUSY bucket) and the high-water mark are sticky Degraded too, by
// design: both mean credit at exit is no longer guaranteed for every exit
// (fail-closed), even if the gauge later drops; only node teardown clears it.
type sharedLiveExitCredit struct {
	read     sharedExitCreditRead
	capacity uint64
	baseline [ExitCreditCounters]uint64
	mu       sync.Mutex
	fault    error // sticky, the first unhealthy window
	closed   bool  // the collection is closing: never read again
}

// check reads the witness (unless closed) and returns the sticky fault.
func (e *sharedLiveExitCredit) check() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fault != nil || e.closed {
		return e.fault
	}
	now, readErr := e.read()
	v, health, err := ExitCreditCheck(e.baseline, now, readErr, e.capacity)
	switch health {
	case ExitCreditHealthy:
		return nil
	case ExitCreditDegraded:
		e.fault = fmt.Errorf("shared candidate credit at exit degraded, node degraded: %s", v)
	default:
		e.fault = fmt.Errorf("shared candidate credit at exit unknown, node degraded: %w", err)
	}
	return e.fault
}

// close takes the final reading before the collection closes.
func (e *sharedLiveExitCredit) close() {
	_ = e.check() // sticky in e.fault, reported by liveHealthFault
	e.mu.Lock()
	e.closed = true
	e.mu.Unlock()
}

// sharedLiveReaper is the running product reaper of the live collection.
type sharedLiveReaper struct {
	reaper *Reaper
	cancel context.CancelFunc
	waited chan struct{}
	err    error // Reaper.Wait's result, valid once waited is closed
	// faulted counts the charges the reaper quarantined (sticky, like
	// ReaperStats.Faulted); lastFault is the latest one. Set by onFault on the
	// reaper goroutine, read without touching BPF.
	faulted   atomic.Uint64
	lastFault atomic.Pointer[ReapFault]
}

// onFault is the reaper's Fault hook: one charge was quarantined and its
// credit stays charged (fail-closed), so the node is degraded.
func (l *sharedLiveReaper) onFault(f ReapFault) {
	l.lastFault.Store(&f)
	l.faulted.Add(1)
}

func (l *sharedLiveReaper) start(ctx context.Context, r *Reaper) error {
	ctx, cancel := context.WithCancel(ctx)
	if err := r.Start(ctx); err != nil {
		cancel()
		return err
	}
	l.reaper, l.cancel, l.waited = r, cancel, make(chan struct{})
	go func() {
		l.err = r.Wait()
		close(l.waited)
	}()
	return nil
}

// stop cancels the reaper and joins its goroutine. Idempotent; it returns the
// reaper's sticky error (nil after a clean stop).
func (l *sharedLiveReaper) stop() error {
	l.cancel()
	<-l.waited
	return l.err
}

// fault is the reaper's sticky degradation: a quarantined charge (its credit
// never returns) or the reaper having stopped on an infrastructure error (no
// credit returns any more). It never makes the node Ready; it only adds
// detail to the live fault.
func (l *sharedLiveReaper) fault() error {
	var result error
	if n := l.faulted.Load(); n > 0 {
		result = fmt.Errorf("shared candidate product reaper quarantined %d charge(s) (last %s), node degraded", n, *l.lastFault.Load())
	}
	select {
	case <-l.waited:
	default:
		return result
	}
	if l.err != nil {
		result = errors.Join(result, fmt.Errorf("shared candidate product reaper stopped, node degraded: %w", l.err))
	}
	return result
}

// stopLiveHealth takes the final credit-at-exit reading and stops and joins
// the live product reaper, if any. It must run before the collection closes
// (a witness read or a TEST_RUN on a closed map or program). A fault never
// blocks teardown; it stays sticky (liveHealthFault).
func (n *NodeEnforcer) stopLiveHealth() {
	n.mu.Lock()
	var reaper *sharedLiveReaper
	var exit *sharedLiveExitCredit
	var capsule *sharedLiveCapsule
	var birthPark *sharedLiveBirthPark
	var facts *sharedLiveFactStats
	var failClosed *sharedLiveFailClosed
	var witness *sharedLiveKernelWitness
	if n.host != nil && n.host.live != nil {
		reaper, exit, capsule, failClosed = n.host.live.reaper, n.host.live.exit, n.host.live.capsule, n.host.live.failClosed
		witness = n.host.live.witness
		birthPark, facts = n.host.live.birthPark, n.host.live.facts
		// From here on the node is never healthy: health is no longer
		// watched although hooks may still be attached.
		n.host.live.healthStopped = true
	}
	n.mu.Unlock()
	if exit != nil {
		exit.close()
	}
	if capsule != nil {
		capsule.close()
	}
	if birthPark != nil {
		birthPark.close()
	}
	if facts != nil {
		facts.close()
	}
	if witness != nil {
		witness.close()
	}
	if failClosed != nil {
		failClosed.close() // joins the poller, then the final reading
	}
	if reaper != nil {
		_ = reaper.stop() // sticky in reaper.err, reported by liveHealthFault
	}
}

// liveHealthFault reports the sticky faults of the live product reaper, of
// credit at exit, of the exec-capsule store and of a gated fail-closed rate
// witness (Unknown only: a refusal rate is reported live, never as a
// teardown failure).
func (n *NodeEnforcer) liveHealthFault() error {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.host == nil || n.host.live == nil {
		return nil
	}
	var result error
	if n.host.live.reaper != nil {
		result = n.host.live.reaper.fault()
	}
	if n.host.live.exit != nil {
		result = errors.Join(result, n.host.live.exit.check())
	}
	if n.host.live.capsule != nil {
		result = errors.Join(result, n.host.live.capsule.check())
	}
	if n.host.live.birthPark != nil {
		result = errors.Join(result, n.host.live.birthPark.check())
	}
	if n.host.live.facts != nil {
		result = errors.Join(result, n.host.live.facts.check())
	}
	if n.host.live.failClosed != nil {
		result = errors.Join(result, n.host.live.failClosed.stickyFault())
	}
	if n.host.live.witness != nil {
		result = errors.Join(result, n.host.live.witness.check())
	}
	return errors.Join(result, n.host.live.recycleFault)
}

// livePublisher returns the live qualification route publisher. Withdrawal
// (publish=false) stays reachable while the node stops, until teardown.
func (n *NodeEnforcer) livePublisher(publish bool) (SharedRoutePublisher, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.host == nil || n.host.live == nil || n.host.live.publisher == nil || n.host.gadgetStopped || n.host.released || n.closed || (publish && n.closing) {
		return nil, ErrSharedNativeUnavailable
	}
	return n.host.live.publisher, nil
}

// checkLiveRoute compares a slot's kernel route tuple with its last-good.
func (n *NodeEnforcer) checkLiveRoute(slot uint32, want SharedRouteState) error {
	publisher, err := n.livePublisher(false)
	if err != nil {
		return err
	}
	have, err := publisher.Route(slot)
	if err != nil {
		return err
	}
	if have != want {
		return fmt.Errorf("route slot %d is %+v, last-good %+v", slot, have, want)
	}
	return nil
}

func (n *NodeEnforcer) checkLiveReceipts() error {
	n.mu.Lock()
	health := n.liveHealthLocked()
	n.mu.Unlock()
	return health.check()
}

// sharedLiveHealth is a snapshot of the live candidate's health inputs, taken
// under n.mu and checked outside it (link lookups and witness map reads).
type sharedLiveHealth struct {
	unavailable, stopped bool
	receipts             []*operators.NativeAttachment
	reaper               *sharedLiveReaper
	exit                 *sharedLiveExitCredit
	capsule              *sharedLiveCapsule
	birthPark            *sharedLiveBirthPark
	facts                *sharedLiveFactStats
	failClosed           *sharedLiveFailClosed
	witness              *sharedLiveKernelWitness
	// image is the product publisher's G020 image index (nil without).
	image sharedImageReporter
}

func (n *NodeEnforcer) liveHealthLocked() sharedLiveHealth {
	if n.host == nil || n.host.live == nil {
		return sharedLiveHealth{unavailable: true}
	}
	live := n.host.live
	h := sharedLiveHealth{stopped: live.healthStopped, reaper: live.reaper, exit: live.exit, capsule: live.capsule, birthPark: live.birthPark, facts: live.facts, failClosed: live.failClosed}
	h.witness = live.witness
	for _, receipt := range live.receipts {
		h.receipts = append(h.receipts, receipt)
	}
	if image, ok := live.publisher.(sharedImageReporter); ok {
		h.image = image
	}
	return h
}

// check joins every health input (qualified Ready and startup readiness).
func (h sharedLiveHealth) check() error {
	if h.unavailable {
		return ErrSharedNativeUnavailable
	}
	notReady, degraded := h.checks()
	return errors.Join(append(notReady, degraded...)...)
}

// checks reads every health input once and routes each failure (unwrapped)
// for the product node: notReady are stopped health, the attach receipts,
// the product reaper, the credit-at-exit, exec-capsule, birth-park and fact
// witnesses and a fail-closed NotReady or Unknown; degraded are a
// fail-closed Degraded window and the image ledger.
func (h sharedLiveHealth) checks() (notReady, degraded []error) {
	if h.unavailable {
		return []error{ErrSharedNativeUnavailable}, nil
	}
	add := func(list *[]error, err error) {
		if err != nil {
			*list = append(*list, err)
		}
	}
	if h.stopped {
		add(&notReady, fmt.Errorf("shared candidate health monitoring stopped (node stopping)"))
	}
	for _, receipt := range h.receipts {
		add(&notReady, receipt.Check())
	}
	if h.reaper != nil {
		add(&notReady, h.reaper.fault())
	}
	if h.exit != nil {
		add(&notReady, h.exit.check())
	}
	if h.capsule != nil {
		add(&notReady, h.capsule.check())
	}
	if h.birthPark != nil {
		add(&notReady, h.birthPark.check())
	}
	if h.facts != nil {
		add(&notReady, h.facts.check())
	}
	if h.witness != nil {
		add(&notReady, h.witness.check())
	}
	if h.failClosed != nil {
		if err := h.failClosed.check(); errors.Is(err, ErrSharedFailClosedNotReady) {
			add(&notReady, err)
		} else {
			add(&degraded, err)
		}
	}
	// G020: any image ledger vs kernel count mismatch, or an UNCERTAIN or
	// failed exact delete, is Degraded (not reversed for the product node).
	if h.image != nil {
		add(&degraded, h.image.imageHealth())
	}
	return notReady, degraded
}

// reserveLiveRoute gives a bound account one route slot of the node
// collection. The account keeps it until node destruction, like its pins.
func (n *NodeEnforcer) reserveLiveRoute(a *sharedPhysicalScope) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.host == nil || n.host.live == nil || a.native.reserved {
		return nil
	}
	for slot, owner := range n.host.scopeSlots {
		if owner == nil {
			a.native.slot, a.native.reserved = uint32(slot), true
			n.host.scopeSlots[slot] = a
			return nil
		}
	}
	return fmt.Errorf("shared route slots exhausted: %w", ErrSharedBindingCapacity)
}

// startQualifiedSharedNode loads the shared candidate collection once per node
// through the host's gadget context. Reached only from a qualification build
// with an explicit WithSharedNodeQualification opt-in.
func startQualifiedSharedNode(ctx context.Context, config SharedNodeConfig, q SharedNodeQualification) (*NodeEnforcer, error) {
	return startLiveSharedNode(ctx, config, q.Run, q, false)
}

// startProductSharedNode loads the shared product collection once per node
// through the host's gadget context, with no seam. Reached only from a
// product build with WithSharedNodeHost, after the kernel gate.
func startProductSharedNode(ctx context.Context, config SharedNodeConfig, h SharedNodeHost) (*NodeEnforcer, error) {
	return startLiveSharedNode(ctx, config, h.Run, SharedNodeQualification{}, true)
}

// startLiveSharedNode is the shared body of the qualified and the product
// start: seams is the qualification seam set (empty for product). It retries
// the whole host start (startLiveSharedNodeOnce) on a capacity refusal with
// the bounded sharedNodeAttachRetry, outside the host manager's lifecycle
// lock: each refused attempt has returned from run's StartGadget and been
// torn down (StopNode joined) before the wait, and every attempt uses a fresh
// NodeEnforcer. ctx cancels a wait at once. A failed teardown ends the retry
// (no further attempt may run beside something possibly still attached).
func startLiveSharedNode(ctx context.Context, config SharedNodeConfig, run func(context.Context, gadgetcontext.Option) (func(context.Context) error, <-chan error, error), seams SharedNodeQualification, product bool) (*NodeEnforcer, error) {
	// Validate the config once before any run; the handle is discarded
	// (every attempt builds its own in startLiveSharedNodeOnce).
	if _, err := NewNodeEnforcer(config); err != nil {
		return nil, err
	}
	retry := sharedNodeAttachRetry()
	if seams.attachRetry != nil {
		retry = *seams.attachRetry
	}
	if err := sharedNodeRetryBounded(retry); err != nil {
		return nil, err
	}
	retry.State = func(err error) {
		// Only a capacity refusal is a NotReady attach state; nil or any
		// other (final) error clears it.
		var capErr *nativeattach.ErrAttachCapacity
		if !errors.As(err, &capErr) {
			err = nil
		}
		if config.AttachState != nil {
			config.AttachState(err)
		}
	}
	var node *NodeEnforcer
	var final error
	err := retry.Run(ctx, func() error {
		n, startErr, stopErr := startLiveSharedNodeOnce(ctx, config, run, seams, product)
		if startErr == nil {
			node = n
			return nil
		}
		if stopErr != nil {
			// Terminal: hide the capacity refusal from the attach retry and
			// mark teardown failure terminal for StartNodeRetrying as well.
			final = errors.Join(startErr, errSharedNodeTeardownFailed)
			if !errors.Is(startErr, stopErr) {
				final = errors.Join(final, stopErr)
			}
			return fmt.Errorf("shared node teardown failed: %w", stopErr)
		}
		return startErr
	})
	if final != nil {
		err = final
		// The retry reports nothing (attempt 1) or clears the state
		// (n>1) for this terminal error: report the refusal it wraps.
		var capErr *nativeattach.ErrAttachCapacity
		if errors.As(final, &capErr) && config.AttachState != nil {
			config.AttachState(capErr)
		}
	}
	if err != nil {
		// A capacity refusal (exhausted or canceled retry) is a NotReady
		// reason.
		var capErr *nativeattach.ErrAttachCapacity
		if errors.As(err, &capErr) && !errors.Is(err, ErrSharedNodeNotReady) {
			err = fmt.Errorf("%w: native attach capacity: %w", ErrSharedNodeNotReady, err)
		}
		return nil, err
	}
	return node, nil
}

// startLiveSharedNodeOnce runs one host start (run: the host's one
// StartGadget call) of a fresh NodeEnforcer. On failure it returns the start
// error and the result of the joined teardown (StopNode).
func startLiveSharedNodeOnce(ctx context.Context, config SharedNodeConfig, run func(context.Context, gadgetcontext.Option) (func(context.Context) error, <-chan error, error), seams SharedNodeQualification, product bool) (*NodeEnforcer, error, error) {
	n, err := NewNodeEnforcer(config)
	if err != nil {
		return nil, err, nil
	}
	q := seams
	started := make(chan error, 1)
	n.host.qualified, n.host.product = !product, product
	n.host.started, n.host.newPublisher, n.host.newReaper, n.host.exitCredit = started, q.Publisher, q.newReaper, q.exitCredit
	n.host.capsuleStats = q.capsuleStats
	n.host.birthParkStats = q.birthParkStats
	n.host.factStats = q.factStats
	n.host.failClosed, n.host.failClosedClock = q.failClosed, q.failClosedClock
	n.host.rootBarrier, n.host.rootBarrierFaults = q.rootBarrier, q.rootBarrierFaults
	n.host.execMap, n.host.execMapFaults = q.execMap, q.execMapFaults
	n.host.newProductPublisher = q.newProductPublisher
	n.host.verdictCounters, n.host.verdictClock = q.verdictCounters, q.verdictClock
	n.host.imageSource = q.imageSource
	n.host.strictRefused = sharedNamespaceCheck()
	stop, done, err := run(ctx, WithNodeEnforcer(n))
	if stop == nil {
		// Nothing to join: the teardown is unknown, so never retry.
		missing := fmt.Errorf("missing shared candidate host teardown")
		return nil, errors.Join(err, missing), missing
	}
	// Recorded before any wait: StopNode always joins the host teardown,
	// whatever startLiveCandidate installs concurrently.
	n.mu.Lock()
	n.host.stopGadget = stop
	n.mu.Unlock()
	if err == nil {
		select {
		case err = <-started:
		case err = <-done:
			err = errors.Join(err, fmt.Errorf("shared candidate gadget ended before startup"))
		case <-ctx.Done():
			err = ctx.Err()
		}
	}
	if err != nil {
		// Typed refusals (nativeattach.ErrAttachCapacity, ErrNotReady) pass
		// through; the transaction already rolled back, and teardown joins.
		return nil, err, n.StopNode(context.WithoutCancel(ctx))
	}
	return n, nil, nil
}

// stopLiveCollection tears the host gadget down once, after BeforeStop.
func (n *NodeEnforcer) stopLiveCollection(ctx context.Context) error {
	n.mu.Lock()
	stop, stopped := n.host.stopGadget, n.host.gadgetStopped
	n.mu.Unlock()
	if stop == nil || stopped {
		return nil
	}
	// The reaper TEST_RUNs a collection program and the witness is a
	// collection map: final reading and join first.
	n.stopLiveHealth()
	// Publisher handles reference the collection; release them first. A
	// publisher fault (a sticky admin-thread failure) never blocks teardown:
	// it is joined to the result.
	closeErr := n.closeLivePublisher()
	if err := stop(ctx); err != nil {
		return errors.Join(err, closeErr)
	}
	n.mu.Lock()
	n.host.gadgetStopped = true
	n.collectionClosed = true
	n.mu.Unlock()
	return closeErr
}

// closeLivePublisher stops the recycle loops, then detaches and closes the
// live route publisher outside n.mu (its Close joins pollers and ends the
// product admin thread). Idempotent: shared by Stop(gc) and StopNode. The
// publisher is detached even when Close fails.
func (n *NodeEnforcer) closeLivePublisher() error {
	n.mu.Lock()
	live := n.host.live
	n.mu.Unlock()
	if live == nil {
		return nil
	}
	n.stopRecycles(live)
	n.mu.Lock()
	publisher := live.publisher
	live.publisher = nil
	live.publisherClosed = true
	n.mu.Unlock()
	if publisher == nil {
		return nil
	}
	return publisher.Close()
}

// sharedTeardownTimeout bounds the session removal of an operator-driven
// teardown (Stop/Close of the host gadget).
const sharedTeardownTimeout = 5 * time.Second

// TeardownPendingWithdrawals counts the removals that reached an already
// closed publisher during node teardown: their routes were not withdrawn
// (they stay last-good or latched, fail-closed) and die with the collection.
func (n *NodeEnforcer) TeardownPendingWithdrawals() uint64 {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.host == nil || n.host.live == nil {
		return 0
	}
	return n.host.live.teardownPending
}

// sharedAdmittedCopy is the node's independent copy of an admitted manifest:
// maps, programs and the tail-call slots (the product control re-validates
// them against this copy at startup).
func sharedAdmittedCopy(r *operators.NativeResources) *operators.NativeResources {
	return &operators.NativeResources{Maps: maps.Clone(r.Maps), Programs: maps.Clone(r.Programs), TailCalls: slices.Clone(r.TailCalls), Constants: maps.Clone(r.Constants)}
}

// overlayDegraded is the node's overlay-layout-unavailable reason as a
// Degraded condition (G020 ruling): reported by Ready only, never part of
// sharedLiveHealth.check, so it never fails qualified startup. Without a
// layout every image fact is UNKNOWN and a FromImage policy is refused at
// publish (productImageIndex.build); every other policy publishes.
func (n *NodeEnforcer) overlayDegraded() error {
	n.mu.Lock()
	h := n.host
	n.mu.Unlock()
	if err := h.overlayUnavailable(); err != nil {
		return fmt.Errorf("image facts Degraded, FromImage policies refused: %w", err)
	}
	return nil
}

// overlayUnavailable is the node's overlay-layout-unavailable reason.
func (h *sharedHostState) overlayUnavailable() error {
	if h == nil {
		return nil
	}
	if p := h.overlayFailure.Load(); p != nil {
		return *p
	}
	return nil
}
