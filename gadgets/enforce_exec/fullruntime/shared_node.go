// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/containerd/containerd/v2/pkg/identifiers"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
)

var ErrSharedNativeUnavailable = errors.New("shared native collection/publication is not implemented")

// ErrSharedNodeNotReady types every reason a live product node's Ready
// fails (errors.Is): a missing or changed attach receipt, the product
// reaper, a witness (credit at exit, exec capsule, birth park, facts), a
// fail-closed NotReady or Unknown, stopped health, a refused Strict
// namespace, or a kernel control (ftrace off, livepatch) re-read at Ready.
var ErrSharedNodeNotReady = errors.New("shared node NotReady")

type SharedNodeConfig struct {
	Profile             SharedProfile
	ABI3Development     bool
	RecoveryDevelopment bool
	Image               string
	// FailClosedPollInterval is how often the live node samples its
	// fail-closed rate witness (0: SharedFailClosedPollInterval; otherwise
	// within [SharedFailClosedPollMin, SharedFailClosedPollMax]).
	FailClosedPollInterval time.Duration
	// RevisionDrainTimeout bounds how long a product revision waits for the
	// slot's RETIRING record to lose its holders (G019 gap 3; 0:
	// DefaultRevisionDrainTimeout; at most MaxRevisionDrainTimeout).
	RevisionDrainTimeout time.Duration
	// ContainerdAddress is the containerd socket the G020 image index
	// resolves a binding's rootfs snapshot from (containerd namespace
	// k8s.io; e.g. /run/containerd/containerd.sock). Empty: no image index
	// (every publication carries none; FromImage policies are not
	// published). ImageProcRoot and ImageHostRoot locate the host PID
	// namespace's procfs and the host mount namespace's root as seen by the
	// agent (empty: "/proc" and "/").
	ContainerdAddress            string
	ImageProcRoot, ImageHostRoot string
	// AttachState, if set, reports the native attach while StartNode is
	// still retrying (NodeEnforcer.Ready is only reachable after StartNode
	// returns): it is called with the *nativeattach.ErrAttachCapacity of
	// every refused attempt (show the node NotReady with it), then once with
	// nil when the refusal no longer applies (started, or another error ended
	// the start, which StartNode returns). When the bounded retry runs out,
	// the last call is the last refusal and StartNode returns it. It is
	// called outside the host manager's lifecycle lock. It must not block.
	AttachState func(error)
	// CanaryCommand, if non-empty, is exec'd as the startup attach canary
	// instead of /proc/self/exe with IG_ENFORCE_EXEC_CANARY=1 (e.g. a
	// fixed static helper or /bin/true).
	CanaryCommand []string
}

func (c SharedNodeConfig) failClosedPollInterval() time.Duration {
	if c.FailClosedPollInterval == 0 {
		return SharedFailClosedPollInterval
	}
	return c.FailClosedPollInterval
}

func validateSharedNodeSelection(config SharedNodeConfig) error {
	if !config.ABI3Development || config.Image == "" {
		return fmt.Errorf("explicit shared development image and trusted opt-in required")
	}
	if d := config.failClosedPollInterval(); d < SharedFailClosedPollMin || d > SharedFailClosedPollMax {
		return fmt.Errorf("fail-closed poll interval %s outside [%s, %s]", d, SharedFailClosedPollMin, SharedFailClosedPollMax)
	}
	if d := config.RevisionDrainTimeout; d < 0 || d > MaxRevisionDrainTimeout {
		return fmt.Errorf("revision drain timeout %s outside [0, %s]", d, MaxRevisionDrainTimeout)
	}
	for name, path := range map[string]string{"containerd address": config.ContainerdAddress, "image proc root": config.ImageProcRoot, "image host root": config.ImageHostRoot} {
		if path != "" && (!filepath.IsAbs(path) || filepath.Clean(path) != path) {
			return fmt.Errorf("%s %q is not an absolute clean path", name, path)
		}
	}
	recoveryImage := strings.HasSuffix(config.Image, ":abi3-recovery-development")
	if recoveryImage != config.RecoveryDevelopment {
		return fmt.Errorf("recovered image and trusted opt-in mismatch")
	}
	return nil
}

type SharedBindingConfig struct {
	CgroupID uint64
	// InitHostPID is supplied by the trusted runtime, never policy metadata.
	InitHostPID uint32
	// ContainerID is the container's containerd container ID (the CRI
	// container ID, containerd namespace k8s.io), supplied by the trusted
	// runtime together with the cgroup and init, never policy metadata. It
	// selects the rootfs snapshot whose lower layers the image index holds
	// (G020 FromImage). Optional: empty means no image index for this
	// binding, so a policy with a FromImage predicate is never published
	// (ErrSharedImageIndexUnavailable). A rebind of the same cgroup must
	// carry the same ID. Bind refuses an ID that is not a containerd
	// identifier (ValidSharedContainerID).
	ContainerID string
	Acquire     func(context.Context) (BindingLease, error)
}

// ValidSharedContainerID reports whether id is a containerd identifier
// (containerd pkg/identifiers.Validate: at most 76 characters,
// alphanumeric runs separated by single '.', '_' or '-'). A CRI container
// ID (64 hex characters) is one.
func ValidSharedContainerID(id string) bool { return identifiers.Validate(id) == nil }

type SharedBindingStatus struct {
	ScopeCookie, CgroupID, Generation uint64
	PreparedID                        uint64
	Ready                             bool
	RootAuthorized                    bool
	Removed                           bool
	// Attached and RouteSlot are reported only by a live qualification node:
	// every candidate receipt is present and this binding owns that route slot
	// of the one node collection. Neither implies Ready or a published policy.
	Attached      bool
	RouteReserved bool
	RouteSlot     uint32
	// RoutePublished: a qualification publisher committed a policy into this
	// route slot (Generation is that route's generation). Component-level
	// only; it never implies Ready. WithdrawPending: Remove retired the
	// session but the kernel route keeps its last-good policy until a real
	// withdrawal exists, and the slot is never reused before node teardown.
	RoutePublished  bool
	WithdrawPending bool
	// Adoption is the slot's refused root-task adoption (Degraded), reported
	// until the slot is recycled; nil otherwise.
	Adoption *SharedAdoptionStatus
	// Revision is the slot's Degraded revision report (G019 gap 3:
	// RevisionDrainTimeout or RevisionObjectStarved, with the RETIRING
	// record's holders); nil otherwise. Never NotReady on its own.
	Revision *SharedRevisionStatus
	// MigrationOutUnenforced labels the accepted G019 residual (gap 5, user
	// decisions D1/U3; design section 10) on every published Strict route:
	// a TASK-carrying task moved out of this cgroup into an unrouted one is
	// no longer enforced there (admission follows the current cgroup; the
	// migration is not relabelled). Admission's refusal of privileged and
	// cgroup-writable pods narrows who can migrate. It is a status label,
	// never a Fault, and it stays set until the gap is closed.
	MigrationOutUnenforced bool
	Fault                  error
}

// Protected reports whether s shows the binding enforced at the generation
// the caller committed (plan Q6/F4; node Ready is separate and also
// required): nil only if the binding is not removed, Fault is nil, every
// receipt is Attached, the route is published and not WithdrawPending, its
// Generation is generation, and no root-task adoption was refused.
func (s SharedBindingStatus) Protected(generation uint64) error {
	var errs []error
	if s.Removed {
		errs = append(errs, fmt.Errorf("binding removed"))
	}
	if s.Fault != nil {
		errs = append(errs, s.Fault)
	}
	if !s.Attached {
		errs = append(errs, fmt.Errorf("binding receipts not attached"))
	}
	if !s.RoutePublished {
		errs = append(errs, fmt.Errorf("binding route not published"))
	}
	if s.WithdrawPending {
		errs = append(errs, fmt.Errorf("binding route withdrawal pending"))
	}
	if generation == 0 || s.Generation != generation {
		errs = append(errs, fmt.Errorf("binding route generation %d, committed %d", s.Generation, generation))
	}
	if s.Adoption != nil {
		errs = append(errs, fmt.Errorf("binding root-task adoption refused: %s", s.Adoption.Reason))
	}
	return errors.Join(errs...)
}

// SharedBindingPolicy is one binding's compiled policy for its route slot.
// Class is the frozen execution class (1 Audit, 2 Strict); Fallback is the
// no-match verdict (0 none, 1 allow, 2 deny); Rules is the rule count.
//
// Source and Container select the product path (G019 M4 decision A, design
// 13.11): the binding's one authored policy, compiled by Publish twice by
// the one compiler: fullpolicy.CompileSharedPolicy gives the staged cells
// (the scope-neutral shared object: no generation, container or epoch;
// root_epoch 0, which BPF requires), and fullpolicy.CompileKernelWithRoleEpochs
// at the route's next generation gives the root epoch (carried in the
// snapshot metadata). Both must agree on the policy UID and root role.
// Class, Fallback and Rules are derived from the shared object.
// Source.RootRole must be authored: the compiler would otherwise default it,
// and the init's role is never guessed. A revision must keep the policy UID
// and root role (terminal refusal otherwise).
type SharedBindingPolicy struct {
	Class, Fallback, Rules, SetRole uint32
	Source                          *fullpolicy.Policy
	Container                       string
	// ExecMap is the binding's executable-mapping gate (off by default).
	ExecMap SharedExecMap
	// program is the compiled Source (set by BindingSession.Publish), the
	// source of the root epoch; object is its scope-neutral shared object
	// (fullpolicy.CompileSharedPolicy: no generation, container or epoch),
	// the cells actually staged. Both come from the one compiler.
	program *fullpolicy.KernelProgram
	object  *fullpolicy.SharedPolicy
}

func (p SharedBindingPolicy) validate() error {
	if err := p.ExecMap.validate(p.Source); err != nil {
		return err
	}
	if p.Source != nil {
		if p.Source.RootRole == "" {
			return fmt.Errorf("shared binding policy %s has no root role", p.Source.ID)
		}
		if p.Container == "" {
			return fmt.Errorf("shared binding policy %s has no container", p.Source.ID)
		}
		return nil
	}
	if p.Class < 1 || p.Class > 2 || p.Fallback > 2 || p.Rules < 1 || p.Rules > 256 {
		return fmt.Errorf("invalid shared binding policy %+v", p)
	}
	return nil
}

// sharedCompiledPolicy is what the product publisher stages and publishes
// from one compiled single-policy program.
type sharedCompiledPolicy struct {
	UID, RootRole, RootEpoch uint64
	Class, Fallback, Rules   uint32
	Entries                  []fullpolicy.Blob
}

// sharedCompiledPolicyOf derives the staged cells and the publication
// facts of one compiled policy. The cells are the shared object's: a shared
// object carries root_epoch 0 (the epoch is the snapshot metadata's,
// root_epochs[0]), and BPF refuses any other. The root epoch comes from the
// role-epoch compilation of the same policy, whose UID and root role must
// equal the object's.
func sharedCompiledPolicyOf(program *fullpolicy.KernelProgram, object *fullpolicy.SharedPolicy) (sharedCompiledPolicy, error) {
	return sharedCompiledPolicyOfCells(program, object.Entries(), object.UID())
}

// sharedCompiledPolicyOfCells is sharedCompiledPolicyOf over the shared
// object's cells and UID.
func sharedCompiledPolicyOfCells(program *fullpolicy.KernelProgram, entries []fullpolicy.Blob, objectUID uint64) (sharedCompiledPolicy, error) {
	if program == nil || len(program.Entries) <= fullpolicy.KernelPolicyBase || len(entries) <= fullpolicy.KernelPolicyBase {
		return sharedCompiledPolicy{}, fmt.Errorf("no compiled shared policy")
	}
	// At least one rule cell (review L4): a policy without rules is refused
	// before anything is staged.
	if len(entries) < fullpolicy.KernelRuleBase+1 {
		return sharedCompiledPolicy{}, fmt.Errorf("compiled shared policy has no rule (%d cells)", len(entries))
	}
	header, err := fullpolicy.Decode[fullpolicy.KernelHeader](entries[0])
	if err != nil {
		return sharedCompiledPolicy{}, err
	}
	policy, err := fullpolicy.Decode[fullpolicy.KernelPolicy](entries[fullpolicy.KernelPolicyBase])
	if err != nil {
		return sharedCompiledPolicy{}, err
	}
	epochs, err := fullpolicy.Decode[fullpolicy.KernelPolicy](program.Entries[fullpolicy.KernelPolicyBase])
	if err != nil {
		return sharedCompiledPolicy{}, err
	}
	if header.PolicyCount != 1 {
		return sharedCompiledPolicy{}, fmt.Errorf("shared binding takes one policy (M4), compiled %d", header.PolicyCount)
	}
	if header.RuleCount == 0 {
		return sharedCompiledPolicy{}, fmt.Errorf("compiled shared policy has no rule")
	}
	if policy.UID == 0 || policy.UID != objectUID || policy.RootRole == 0 || policy.RootEpoch != 0 || policy.Mode < 1 || policy.Mode > 2 {
		return sharedCompiledPolicy{}, fmt.Errorf("compiled shared object uid %d role %d epoch %d mode %d", policy.UID, policy.RootRole, policy.RootEpoch, policy.Mode)
	}
	if epochs.UID != policy.UID || epochs.RootRole != policy.RootRole || epochs.RootEpoch == 0 {
		return sharedCompiledPolicy{}, fmt.Errorf("role-epoch compilation (uid %d role %d epoch %d) does not match the shared object (uid %d role %d)",
			epochs.UID, epochs.RootRole, epochs.RootEpoch, policy.UID, policy.RootRole)
	}
	return sharedCompiledPolicy{
		UID: policy.UID, RootRole: policy.RootRole, RootEpoch: epochs.RootEpoch,
		Class: policy.Mode, Fallback: policy.Default, Rules: header.RuleCount,
		Entries: entries,
	}, nil
}

// compile compiles Source at generation, retaining the binding's activated
// root epochs, and derives Class, Fallback and Rules from the program. A
// predicate the product evaluator cannot produce is refused first
// (ErrSharedPredicateUnsupported, sharedProductFactSupport).
func (p SharedBindingPolicy) compile(generation uint64, activated map[string]uint64) (SharedBindingPolicy, error) {
	if err := admitSharedProductPolicy(p.Source); err != nil {
		return p, err
	}
	program, err := fullpolicy.CompileKernelWithRoleEpochs([]fullpolicy.Policy{*p.Source}, generation, p.Container, activated)
	if err != nil {
		return p, fmt.Errorf("compile shared policy %s: %w", p.Source.ID, err)
	}
	object, err := fullpolicy.CompileSharedPolicy(*p.Source)
	if err != nil {
		return p, fmt.Errorf("compile shared object %s: %w", p.Source.ID, err)
	}
	c, err := sharedCompiledPolicyOf(program, object)
	if err != nil {
		return p, err
	}
	p.program, p.object, p.Class, p.Fallback, p.Rules = program, object, c.Class, c.Fallback, c.Rules
	return p, nil
}

// SharedRouteState is the kernel route tuple of one slot (the binding's
// witness): it changes only through that slot's own publication.
type SharedRouteState struct {
	Cgroup, Scope, Generation, Serial uint64
	Incarnation, Record, Class, Phase uint32
}

// ErrSharedRouteFree is what SharedRoutePublisher.Route returns (wrapped) for
// a slot that holds no route.
var ErrSharedRouteFree = errors.New("shared route slot free")

// ErrSharedBindingWithdrawn reports that the cgroup's route was withdrawn. Withdrawal is
// terminal for that container for the node's lifetime (G019 M4 D5): neither
// Bind nor Publish may reuse its retained physical account.
var ErrSharedBindingWithdrawn = errors.New("shared binding withdrawn")

// ErrSharedBindingCapacity reports that Bind found no free binding: the
// profile's Bindings (2 in every product object) are bound, being
// prepared, or retained until their removed route is recycled. A host shows
// it as the container's NotReady reason; it clears once a binding is
// removed and its slot recycled. Changing the limit needs a new product
// object (new pins).
var ErrSharedBindingCapacity = errors.New("shared binding capacity exhausted")

// ErrSharedRetryableRefusal marks every retryable publisher refusal (a
// command's RETRY result, a stage with no free policy object until a
// retired object's pins drain, ErrSharedRevisionDraining): in-flight claims
// or pins hold what the operation needs; retrying later can succeed.
var ErrSharedRetryableRefusal = errors.New("retryable refusal (in-flight claims or pins)")

// Execution classes of SharedBindingPolicy.Class and SharedRouteState.Class.
const (
	sharedClassAudit  uint32 = 1
	sharedClassStrict uint32 = 2
)

// ErrSharedClassChange reports the refusal of a revision that changes the
// binding's execution class (Audit <-> Strict), terminal for that request
// (G019 gap 6, accepted): a route's class is frozen at its first publication and
// in-flight execs carry it (the frozen-class ADMISSION check), so a class
// change needs a new binding. Withdrawal is terminal for the cgroup (D5),
// so that means a new container (cgroup) bound with the new class. The
// binding keeps its last-good route.
var ErrSharedClassChange = errors.New("execution class change requires a new binding (G019 gap 6)")

// sharedClassName names an execution class for errors.
func sharedClassName(class uint32) string {
	switch class {
	case sharedClassAudit:
		return "Audit"
	case sharedClassStrict:
		return "Strict"
	}
	return fmt.Sprintf("class %d", class)
}

// sharedClassChangeError is the terminal refusal of a class-changing
// revision of slot.
func sharedClassChangeError(slot uint32, from, to uint32) error {
	return fmt.Errorf("revision of route slot %d changes the execution class %s -> %s (terminal; Remove this binding and bind a new container with the new class): %w: %w",
		slot, sharedClassName(from), sharedClassName(to), ErrSharedClassChange, ErrSharedNativeUnavailable)
}

// SharedInitIdentity is the bound init's kernel identity, taken from the
// binding's own pins (never from policy metadata): the init-pid-namespace
// TGID, its start time in clock ticks (/proc/<pid>/stat field 22, exactly as
// pinned; never converted) and its mount namespace inode. A first Strict
// publication adopts exactly this init (G019 M4 design section 4).
type SharedInitIdentity struct {
	TGID       uint32
	StartTicks uint64
	MountNS    uint64
	// ContainerID is the binding's SharedBindingConfig.ContainerID (G020:
	// the image index's rootfs snapshot); empty without one.
	ContainerID string
}

// SharedRoutePublisher is a TEST/QUALIFICATION-ONLY seam: it commits one
// binding's policy into its route slot of the one node collection. Publish
// must be all-or-nothing per slot (a refused or faulted publication keeps
// that slot's last-good route) and must never touch another slot. Withdraw
// returns ErrSharedNativeUnavailable when no kernel withdrawal exists. Route
// returns an error wrapping ErrSharedRouteFree for a slot without a route.
type SharedRoutePublisher interface {
	Publish(ctx context.Context, slot uint32, cgroup uint64, policy SharedBindingPolicy, first bool, init SharedInitIdentity) (SharedRouteState, error)
	Withdraw(ctx context.Context, slot uint32, cgroup uint64) error
	Route(slot uint32) (SharedRouteState, error)
	Close() error
}

// sharedCollection is private: injected ownership tests do not attest hooks,
// immutable arena installation, routing or native publication.
type (
	sharedCollection interface{ Close() error }
	NodeEnforcer     struct {
		mu               sync.Mutex
		stopMu           sync.Mutex
		config           SharedNodeConfig
		collection       sharedCollection
		host             *sharedHostState
		objects          *sharedObjectRegistry
		bindings         map[uint64]*BindingSession
		scopes           map[uint64]*sharedPhysicalScope
		preparations     map[*BindingSession]struct{}
		prepareBinding   func(context.Context, SharedBindingConfig, BindingLease) (*sharedPhysicalPins, error)
		collectionClosed bool
		nextPreparedID   uint64
		// withdrawnCgroups is the compact terminal record (D5): every cgroup
		// whose route was withdrawn on this node, never bound again. A
		// withdrawn account whose slot was recycled is dropped from scopes
		// (freeRecycledSlot) and survives only here: 8 bytes of key per
		// churned container for the node's lifetime (cgroup IDs are 64-bit
		// kernfs IDs, never reused), so neither the binding capacity nor the
		// account memory grows with the churn.
		withdrawnCgroups map[uint64]struct{}
		closing, closed  bool
	}
)

type BindingSession struct {
	mu               sync.Mutex
	node             *NodeEnforcer
	prepared, cgroup uint64
	account          *sharedPhysicalScope
	pending          *sharedPhysicalPins
	removed          bool
	prepareCancel    context.CancelFunc
	prepareDone      chan struct{}
}

// sharedQualificationBuild is true only in binaries built with the
// enforce_exec_shared_qualification tag. Product builds never set it, so the
// candidate StartNode path below is unreachable there.
var sharedQualificationBuild bool

type sharedQualificationKey struct{}

// SharedNodeQualification is a TEST/QUALIFICATION-ONLY seam. It does nothing
// unless the binary carries the enforce_exec_shared_qualification build tag.
// Run must start the shared candidate image once through the host's existing
// manager with opt applied (one StartGadget call) and return without
// waiting for the gadget to finish. stop must tear that gadget down and join
// the manager's detach; done yields the gadget run's result when it ends. It is
// never a product admission path. After a capacity refusal StartNode calls
// Run again (a fresh opt) once stop has returned, as SharedNodeHost.Run; the
// same rules apply: no two concurrent StartNode calls for one gadget ID, and
// stop should be a no-op when its own StartGadget failed.
type SharedNodeQualification struct {
	Run func(ctx context.Context, opt gadgetcontext.Option) (stop func(context.Context) error, done <-chan error, err error)
	// Publisher optionally builds the route publisher over the started host
	// gadget context. Without it BindingSession.Publish stays unavailable.
	Publisher func(gc operators.GadgetContext) (SharedRoutePublisher, error)
	// newReaper replaces the product reaper borrowed from the host gadget
	// context (borrowSharedCandidateReaper). Package tests only.
	newReaper func(gc operators.GadgetContext, config ReaperConfig) (*Reaper, error)
	// exitCredit replaces the credit-at-exit witness borrowed from the host
	// gadget context (borrowSharedExitCredit). Package tests only.
	exitCredit func(gc operators.GadgetContext) (sharedExitCreditRead, error)
	// capsuleStats replaces the exec-capsule witness borrowed from the host
	// gadget context (borrowSharedCapsuleStats). Package tests only.
	capsuleStats func(gc operators.GadgetContext) (sharedCapsuleStatsRead, error)
	// birthParkStats replaces the birth-park witness borrowed from the host
	// gadget context (borrowSharedBirthParkStats). Package tests only.
	birthParkStats func(gc operators.GadgetContext) (sharedBirthParkStatsRead, error)
	// factStats replaces the per-pass fact witness borrowed from the host
	// gadget context (borrowSharedFactStats). Package tests only.
	factStats func(gc operators.GadgetContext) (sharedFactStatsRead, error)
	// failClosed replaces the fail-closed rate witness borrowed from the
	// host gadget context (borrowSharedFailClosed), failClosedClock its
	// clock. Package tests only.
	failClosed      func(gc operators.GadgetContext, cells int) (sharedFailClosedRead, error)
	failClosedClock func() time.Time
	// rootBarrier replaces the product node's root barrier start check
	// (verifySharedRootBarrier), rootBarrierFaults its fault reader
	// (borrowSharedRootBarrierFaults). Package tests only.
	rootBarrier       func(gc operators.GadgetContext, receipts map[string]*operators.NativeAttachment) error
	rootBarrierFaults func(gc operators.GadgetContext) (sharedRootBarrierFaultRead, error)
	// execMap replaces the executable-mapping gate's start self-test
	// (verifySharedExecMap), execMapFaults its fault reader
	// (borrowSharedExecMapFaults). Package tests only.
	execMap       func(gc operators.GadgetContext) error
	execMapFaults func(gc operators.GadgetContext) (sharedRootBarrierFaultRead, error)
	// newProductPublisher replaces the product publisher borrowed from the
	// host gadget context (borrowSharedProductPublisher). Package tests only.
	newProductPublisher func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error)
	// verdictCounters replaces the verdict counters borrowed from the host
	// gadget context (borrowSharedVerdictCounters), verdictClock their
	// Degraded window's clock. Package tests only.
	verdictCounters func(gc operators.GadgetContext) (sharedVerdictCountersRead, func() error, error)
	verdictClock    func() time.Time
	// imageSource replaces the containerd rootfs snapshot source of the
	// image index (the real resolver and host attestation still run).
	// Package tests only: the live image test's own overlay mount.
	imageSource sharedImageLayerSource
	// attachRetry replaces sharedNodeAttachRetry() (nil: the default).
	// Package tests only; it must still be bounded (StartNode checks it).
	attachRetry *nativeattach.Retry
}

// WithSharedNodeQualification selects the qualification-only candidate
// StartNode path; product builds ignore it (only WithSharedNodeHost starts
// a product node there).
func WithSharedNodeQualification(ctx context.Context, q SharedNodeQualification) context.Context {
	return context.WithValue(ctx, sharedQualificationKey{}, q)
}

func sharedQualificationFrom(ctx context.Context) (SharedNodeQualification, bool) {
	q, ok := ctx.Value(sharedQualificationKey{}).(SharedNodeQualification)
	return q, ok && sharedQualificationBuild && q.Run != nil
}

type sharedNodeHostKey struct{}

// SharedNodeHost is the product StartNode host: Run must start the shared
// product image once through the host's existing manager with opt applied
// (one StartGadget call) and return without waiting for the gadget to
// finish; stop must tear that gadget down and join the manager's detach;
// done yields the gadget run's result when it ends. It carries nothing else:
// no publisher override and no test seam.
//
// The gadget's Start never waits for attach capacity (WithNodeEnforcer opts
// out of the in-Start retry): a capacity refusal fails that StartGadget at
// once. StartNode then calls stop, and only after stop returns does it wait
// (bounded, see sharedNodeAttachRetry) and call Run again with a fresh opt.
// So the manager's lifecycle lock is never held across a backoff wait, and
// the host must accept a later Run for the same gadget ID once stop returned
// nil (a failed stop ends StartNode without a further attempt).
//
// The host must not run two StartNode calls for the same gadget ID
// concurrently: stop targets the gadget ID, so a refused attempt's stop could
// tear down the other caller's live gadget. stop should be a no-op (return
// nil) when its own StartGadget failed.
type SharedNodeHost struct {
	Run func(ctx context.Context, opt gadgetcontext.Option) (stop func(context.Context) error, done <-chan error, err error)
}

// WithSharedNodeHost selects the product StartNode path. StartNode then
// admits a kernel that passes the product kernel gate (SharedProductKernel)
// and a product image of this release; anything else is refused with
// ErrSharedNativeUnavailable. A qualification build refuses it.
func WithSharedNodeHost(ctx context.Context, h SharedNodeHost) context.Context {
	return context.WithValue(ctx, sharedNodeHostKey{}, h)
}

func sharedNodeHostFrom(ctx context.Context) (SharedNodeHost, bool) {
	h, ok := ctx.Value(sharedNodeHostKey{}).(SharedNodeHost)
	return h, ok && h.Run != nil
}

// StartNode starts the node-wide shared collection. A qualification build
// with WithSharedNodeQualification loads the shared candidate collection;
// that node never reports Ready. Otherwise WithSharedNodeHost loads the
// product image, only in a product build and only on a kernel the product
// kernel gate admits (SharedProductKernel, checked before the host runs
// anything).
// Without either StartNode refuses with ErrSharedNativeUnavailable.
//
// When config.CanaryCommand is empty, the startup attach canary execs
// /proc/self/exe with IG_ENFORCE_EXEC_CANARY=1, which fullruntime's init()
// handles by exiting 0; importers that do not set CanaryCommand must treat
// IG_ENFORCE_EXEC_CANARY as reserved.
func StartNode(ctx context.Context, config SharedNodeConfig) (*NodeEnforcer, error) {
	if q, ok := sharedQualificationFrom(ctx); ok {
		return startQualifiedSharedNode(ctx, config, q)
	}
	if h, ok := sharedNodeHostFrom(ctx); ok {
		// Mutual exclusion: a qualification binary never reaches the
		// product path.
		if sharedQualificationBuild {
			return nil, fmt.Errorf("shared product node refused: qualification build: %w", ErrSharedNativeUnavailable)
		}
		if _, err := sharedProductKernelCheck(); err != nil {
			return nil, err
		}
		return startProductSharedNode(ctx, config, h)
	}
	return startSharedNode(ctx, config, func(context.Context, SharedNodeConfig, SharedAdmission) (sharedCollection, error) {
		return nil, ErrSharedNativeUnavailable
	})
}

func startSharedNode(ctx context.Context, config SharedNodeConfig, start func(context.Context, SharedNodeConfig, SharedAdmission) (sharedCollection, error)) (*NodeEnforcer, error) {
	admission, err := config.Profile.Validate()
	if err != nil {
		return nil, err
	}
	if err := validateSharedNodeSelection(config); err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	collection, err := start(ctx, config, admission)
	if collection == nil {
		return nil, errors.Join(err, fmt.Errorf("missing shared collection"))
	}
	// Retain partial-start ownership for StopNode; startup errors cannot prove
	// that the collection has already detached and released every resource.
	n := &NodeEnforcer{config: config, collection: collection, bindings: make(map[uint64]*BindingSession)}
	if err = errors.Join(err, ctx.Err()); err != nil {
		n.closing = true
	}
	return n, err
}

// Bind prepares trusted physical inputs only. Kernel root authorization and
// publication are separate unavailable operations; this cannot report Ready.
// A cgroup's physical account (pins, route slot and last route publication)
// is retained until node destruction: binding the same cgroup again after
// Remove inherits that account's route slot and route state, including a
// WithdrawPending last-good route; Inspect reports it as the new session's.
func (n *NodeEnforcer) Bind(ctx context.Context, c SharedBindingConfig) (*BindingSession, error) {
	return n.bindPhysicalScope(ctx, c)
}

// PreparedID is a native reservation identity, never a kernel scope cookie.
func (s *BindingSession) PreparedID() uint64 { return s.prepared }

// ScopeCookie remains zero until real authenticated kernel registration. The
// command sequence, not a competing Go allocator, creates that authority.
func (s *BindingSession) ScopeCookie() uint64 {
	s.account.mu.Lock()
	defer s.account.mu.Unlock()
	if s.account.registration.Operation != sharedBindingOpen || s.account.registration.Status != 0 {
		return 0
	}
	return s.account.registration.Sequence
}

// Inspect reports ErrSharedNativeUnavailable unless the node holds a live
// qualification candidate collection. Then it reports the binding's route slot
// and the live receipt state; Ready stays false because no policy is published.
func (s *BindingSession) Inspect() SharedBindingStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := SharedBindingStatus{PreparedID: s.prepared, ScopeCookie: s.ScopeCookie(), CgroupID: s.cgroup, Removed: s.removed, Fault: ErrSharedNativeUnavailable}
	n := s.node
	n.mu.Lock()
	live := n.host != nil && n.host.live != nil && !n.host.released && !n.closing && !n.closed
	n.mu.Unlock()
	if !live {
		return status
	}
	s.account.mu.Lock()
	status.RouteSlot, status.RouteReserved = s.account.native.slot, s.account.native.reserved
	route := s.account.route
	s.account.mu.Unlock()
	status.RoutePublished, status.WithdrawPending = route.published, route.withdrawPending
	if route.published {
		status.Generation = route.state.Generation
		status.MigrationOutUnenforced = route.state.Class == sharedClassStrict
	}
	switch {
	case s.removed:
		status.Fault = fmt.Errorf("binding removed")
	case !status.RouteReserved:
		status.Fault = fmt.Errorf("binding has no route slot")
	default:
		status.Fault = n.checkLiveReceipts()
	}
	status.Attached = status.Fault == nil
	if status.Fault == nil && route.fault != nil {
		status.Fault = route.fault
	}
	if status.Fault == nil && route.published {
		// The kernel route must still be exactly the last committed tuple.
		status.Fault = n.checkLiveRoute(status.RouteSlot, route.state)
	}
	if publisher, err := n.livePublisher(false); err == nil && status.RouteReserved {
		if r, ok := publisher.(sharedAdoptionReporter); ok {
			if st, reported := r.adoptionStatus(status.RouteSlot); reported && st.Cgroup == s.cgroup {
				status.Adoption = &st
			}
		}
		if r, ok := publisher.(sharedRevisionReporter); ok {
			if st, reported := r.revisionReport(status.RouteSlot); reported {
				status.Revision = &st
			}
		}
	}
	return status
}

// Publish commits policy into this binding's route slot through the
// qualification publisher. The first publication opens the route; later ones
// advance its generation under the same class (a class change needs a new
// route, G019 gap 6). A refused or faulted publication keeps last-good and
// changes no other binding. It never reports Ready. It is Compile and
// PublishCompiled under one hold of the binding's locks (shared_compiled.go),
// so it is never refused as stale.
func (s *BindingSession) Publish(ctx context.Context, policy SharedBindingPolicy) (SharedRouteState, error) {
	if err := policy.validate(); err != nil {
		return SharedRouteState{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	publisher, err := s.publishableLocked(ctx)
	if err != nil {
		return SharedRouteState{}, err
	}
	a := s.account
	a.mu.Lock()
	defer a.mu.Unlock()
	init, err := s.routeInitLocked()
	if err != nil {
		return SharedRouteState{}, err
	}
	compiled, err := s.compileLocked(policy)
	if err != nil {
		return a.route.state, err
	}
	return s.publishCompiledLocked(ctx, publisher, init, compiled.policy)
}

// unconfirmedFirstRoute records a failed first publication of slot: the
// kernel route read back (published when non-zero) with a fault, or the read
// failure as the fault.
func unconfirmedFirstRoute(publisher SharedRoutePublisher, slot uint32, policy SharedBindingPolicy, cause error) sharedLiveRoute {
	have, err := publisher.Route(slot)
	switch {
	case errors.Is(err, ErrSharedRouteFree):
		return sharedLiveRoute{} // nothing was committed
	case err != nil:
		return sharedLiveRoute{fault: fmt.Errorf("route slot %d unknown after a failed first publication (%w): %w", slot, cause, err)}
	case have == (SharedRouteState{}):
		return sharedLiveRoute{fault: fmt.Errorf("route slot %d read back empty without ErrSharedRouteFree after a failed first publication: %w", slot, cause)}
	}
	fault := fmt.Errorf("route slot %d holds %+v from a failed first publication: %w", slot, have, cause)
	route := sharedLiveRoute{published: true, state: have, policy: policy, fault: fault}
	if policy.program != nil {
		// The epoch the request carried, so a later revision of the same
		// policy keeps it.
		c, _ := sharedCompiledPolicyOf(policy.program, policy.object)
		route.epoch = c.RootEpoch
	}
	return route
}

func checkPublishedRoute(last sharedLiveRoute, state SharedRouteState, cgroup uint64, policy SharedBindingPolicy) error {
	switch {
	case state.Cgroup != cgroup || state.Class != policy.Class || state.Generation == 0:
		return fmt.Errorf("published route tuple %+v does not match the binding", state)
	case last.published && (state.Generation <= last.state.Generation || state.Scope != last.state.Scope || state.Incarnation != last.state.Incarnation):
		return fmt.Errorf("published route tuple %+v does not advance %+v", state, last.state)
	}
	return nil
}

// Remove retires the logical session, not its retained physical history account.
// Nonzero generations still require the unavailable authenticated withdrawal.
func (s *BindingSession) Remove(ctx context.Context, expectedGeneration uint64) error {
	return s.removePhysicalSession(ctx, expectedGeneration)
}

func (n *NodeEnforcer) StopNode(ctx context.Context) error {
	if n.host != nil {
		if err := n.BeforeStop(ctx); err != nil {
			return err
		}
		if err := n.stopLiveCollection(ctx); err != nil {
			n.mu.Lock()
			stopped := n.host.gadgetStopped
			n.mu.Unlock()
			if !stopped {
				return err
			}
			// The gadget stopped: a publisher Close fault (a sticky admin
			// thread) never blocks the release; it is reported with it.
			return errors.Join(err, n.ReleaseAfterDetach(), n.liveHealthFault())
		}
		// A reaper or credit-at-exit fault never blocks teardown; it is
		// reported after it.
		return errors.Join(n.ReleaseAfterDetach(), n.liveHealthFault())
	}
	n.stopMu.Lock()
	defer n.stopMu.Unlock()
	if err := n.cancelAndJoinPreparations(ctx); err != nil {
		return err
	}
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return nil
	}
	n.closing = true
	bindings := make([]*BindingSession, 0, len(n.bindings))
	for _, s := range n.bindings {
		bindings = append(bindings, s)
	}
	n.mu.Unlock()
	var result error
	for _, s := range bindings {
		result = errors.Join(result, s.Remove(ctx, 0))
	}
	if result != nil {
		return result
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !n.collectionClosed {
		if err := n.collection.Close(); err != nil {
			return err
		}
		n.mu.Lock()
		n.collectionClosed = true
		n.mu.Unlock()
	}
	if err := n.releasePhysicalScopes(); err != nil {
		return err
	}
	n.mu.Lock()
	n.closed = true
	n.mu.Unlock()
	return nil
}
