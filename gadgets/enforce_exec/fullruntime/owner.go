// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	execruntime "github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/runtime"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const ownerKey = "enforce-exec/native-owner"

var ownerHooks = map[string]struct {
	kind   ebpf.ProgramType
	target string
}{
	"enforce_exec_full":        {ebpf.LSM, "bprm_check_security"},
	"enforce_exec_track_memfd": {ebpf.LSM, "inode_init_security_anon"},
	"eo_task_alloc":            {ebpf.LSM, "task_alloc"},
	"eo_task_newtask":          {ebpf.Tracing, "task_newtask"},
	"eo_copy_process_exit":     {ebpf.Tracing, "copy_process"},
	"eo_sched_exec":            {ebpf.Tracing, "sched_process_exec"},
	"eo_bprm_exit":             {ebpf.Tracing, "bprm_execve"},
	"eo_task_exit":             {ebpf.Tracing, "sched_process_exit"},
	"eo_migrate_enter":         {ebpf.Tracing, "cgroup_migrate"}, "eo_migrate_exit": {ebpf.Tracing, "cgroup_migrate"},
	"eo_reconfigure_enter": {ebpf.Tracing, "cgroup_update_dfl_csses"}, "eo_reconfigure_exit": {ebpf.Tracing, "cgroup_update_dfl_csses"},
	"eo_movement_arm": {ebpf.Tracing, "cgroup_kn_lock_live"},
}

// BindingLease is supplied ONLY by a trusted runtime owner. Acquire transfers
// ownership. It must pin the exact runtime container, init proc allocation,
// cgroup, mount namespace and any image/lower-root evidence for its lifetime.
// Check authenticates runtime ownership and re-attests all pins/root constraints.
// It must reject host/unsupported namespaces and runtime helper ingress, never
// infer exemptions. Policy metadata/annotations are not evidence. InitProc is a
// borrowed proc-directory pin for the exact InitHostPID, not /proc's root directory.
type BindingLease interface {
	Check(context.Context) error
	InitProc() *os.File
	Cgroup() *os.File
	MountNamespace() *os.File
	HostMountNamespace() *os.File
	Close() error
}
type OwnerConfig struct {
	// ABI3Development is trusted native consent for the isolated development image.
	// It is never inferred from policy/image annotations and defaults to false.
	ABI3Development bool
	Program         *fullpolicy.KernelProgram
	CgroupID        uint64
	InitHostPID     uint32
	ControlRoot     string // canonical admin-selected writable cgroup-v2 control path
	Acquire         func(context.Context) (BindingLease, error)
	ImageOrigins    *execruntime.ImageOriginSnapshot
}

func (c OwnerConfig) ownerABI() uint32 {
	if c.ABI3Development {
		return OwnerDevelopmentABI
	}
	return OwnerABI
}

// Owner owns a single, persistent OCI binding. Native callers MUST retain this
// handle on startup failure, drain with BeforeStop BEFORE StopGadget, wait for
// actual manager teardown, then ReleaseAfterDetach. Operator Close cannot prove
// that lower-priority eBPF collection FDs have closed, so it never releases pins
// or the aggregate reservation. Do not copy Owner.
type Owner struct {
	counterMap                                   kernelCounterMap
	counterSnapshot                              KernelEventCounters
	counterErr                                   error
	counterFinal                                 bool
	start                                        string
	pending                                      *fullpolicy.KernelProgram
	mu                                           sync.Mutex
	config                                       OwnerConfig
	reservation                                  *budgetReservation
	context                                      operators.GadgetContext
	lease                                        BindingLease
	proc                                         *os.File
	resources                                    ControlResources
	gates                                        *GateMap
	gate                                         *Gate
	slot                                         *ProgramSlot
	control                                      *OwnerControl
	publisher                                    *Publisher
	tracker                                      *execruntime.FilesystemTracker
	attachments                                  map[string]*operators.NativeAttachment
	current                                      *fullpolicy.KernelProgram
	claimed, prepared, closing, closed, released bool
}

func NewOwner(config OwnerConfig, budget *Budget) (*Owner, error) {
	program := snapshotProgram(config.Program)
	if err := fullpolicy.ValidateKernelProgram(program); err != nil {
		return nil, err
	}
	if config.CgroupID == 0 || config.InitHostPID == 0 || config.InitHostPID > 0x7fffffff || config.Acquire == nil || !filepath.IsAbs(config.ControlRoot) || filepath.Clean(config.ControlRoot) != config.ControlRoot {
		return nil, fmt.Errorf("complete trusted native owner configuration required")
	}
	h, _ := fullpolicy.Decode[fullpolicy.KernelHeader](program.Entries[0])
	for i := uint32(0); i < h.PolicyCount; i++ {
		row, _ := fullpolicy.Decode[fullpolicy.KernelPolicy](program.Entries[fullpolicy.KernelPolicyBase+i])
		if row.RootEpoch != h.Generation {
			return nil, fmt.Errorf("fresh owner requires fresh UID root epochs")
		}
	}
	config.Program = program
	if config.ImageOrigins != nil {
		s := *config.ImageOrigins
		s.Keys = append([]execruntime.ImageOriginKey(nil), s.Keys...)
		config.ImageOrigins = &s
	}
	if err := validateOwnerProgram(program, config.ImageOrigins); err != nil {
		return nil, err
	}
	reservation, err := budget.reserve(config.CgroupID)
	if err != nil {
		return nil, err
	}
	return &Owner{config: config, reservation: reservation, attachments: map[string]*operators.NativeAttachment{}}, nil
}

func WithOwner(owner *Owner) gadgetcontext.Option {
	return func(gc *gadgetcontext.GadgetContext) {
		gc.SetVar(ownerKey, owner)
		gc.SetVar(operators.NativeOwnerRequiredKey, true)
		// The legacy Owner refuses attach capacity at once; it does not use
		// the native default retry.
		gc.SetVar(operators.NativeAttachRetryKey, false)
	}
}

type ownerOperator struct{}

func New() operators.DataOperator                 { return &ownerOperator{} }
func init()                                       { operators.RegisterDataOperator(New()) }
func (*ownerOperator) Name() string               { return "enforce-exec-owner" }
func (*ownerOperator) Priority() int              { return 1 }
func (*ownerOperator) Init(*params.Params) error  { return nil }
func (*ownerOperator) GlobalParams() api.Params   { return nil }
func (*ownerOperator) InstanceParams() api.Params { return nil }
func (*ownerOperator) InstantiateDataOperator(gc operators.GadgetContext, _ api.ParamValues) (operators.DataOperatorInstance, error) {
	value, _ := gc.GetVar("config")
	metadata, ok := value.(*viper.Viper)
	sharedValue, sharedSupplied := gc.GetVar(sharedNodeKey)
	if sharedSupplied || (ok && metadata != nil && metadata.GetString("annotations.enforce-exec-shared-profile") != "") {
		node, _ := sharedValue.(*NodeEnforcer)
		return instantiateSharedNode(gc, metadata, node)
	}
	supplied, _ := gc.GetVar(ownerKey)
	owner, _ := supplied.(*Owner)
	abi := ""
	if ok {
		abi = metadata.GetString("annotations.enforce-exec-owner-abi")
	}
	if abi == "" {
		if owner != nil {
			return nil, fmt.Errorf("native owner requires persistent-owner image ABI")
		}
		return nil, nil
	}
	development := metadata.GetBool("annotations.enforce-exec-owner-development")
	if owner == nil || abi != fmt.Sprint(owner.config.ownerABI()) || development != owner.config.ABI3Development {
		return nil, fmt.Errorf("persistent-owner image requires matching native ABI/development configuration (default ABI%d)", OwnerABI)
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if owner.claimed || owner.released || owner.closing {
		return nil, fmt.Errorf("native owner already used")
	}
	if metadata.GetBool("annotations.enforce-exec") || metadata.GetBool("annotations.enforce-exec-full") {
		return nil, fmt.Errorf("incompatible immutable image capability on persistent owner")
	}
	r, _ := gc.GetVar(operators.NativeResourcesKey)
	manifest, _ := r.(*operators.NativeResources)
	cpus, err := ebpf.PossibleCPU()
	if err != nil {
		return nil, err
	}
	if err = admitOwnerResources(gc, manifest, cpus); err != nil {
		return nil, err
	}
	if err = verifySupportedKernel(); err != nil {
		return nil, err
	}
	owner.claimed = true
	owner.context = gc
	return owner, nil
}
func (*Owner) Name() string { return "enforce-exec-owner" }
func (o *Owner) mapHandle(name string) (*ebpf.Map, error) {
	v, _ := o.context.GetVar(operators.MapPrefix + name)
	m, _ := v.(*ebpf.Map)
	if m == nil || m.FD() < 0 {
		return nil, fmt.Errorf("missing live owner map %s", name)
	}
	return m, nil
}

func (o *Owner) captureAttachments() error {
	for name, expected := range ownerHooks {
		v, _ := o.context.GetVar(operators.NativeAttachmentPrefix + name)
		receipt, _ := v.(*operators.NativeAttachment)
		if receipt == nil || receipt.Type != uint32(expected.kind) || receipt.Target != expected.target || receipt.Check == nil {
			return fmt.Errorf("owner hook %s is not attached", name)
		}
		if err := receipt.Check(); err != nil {
			return fmt.Errorf("owner hook %s: %w", name, err)
		}
		o.attachments[name] = receipt
	}
	return nil
}

func (o *Owner) verify(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if o.lease == nil || o.proc == nil {
		return fmt.Errorf("owner identity pins unavailable")
	}
	if err := o.lease.Check(ctx); err != nil {
		return err
	}
	start, err := readPinnedInitStart(o.proc, o.config.InitHostPID)
	if err != nil {
		return err
	}
	if start != o.start {
		return fmt.Errorf("pinned init identity changed")
	}
	if err = checkBindingScope(o.proc, o.lease, o.config.CgroupID); err != nil {
		return err
	}
	if err = checkKernelControls(); err != nil {
		return err
	}
	for name, receipt := range o.attachments {
		if err := receipt.Check(); err != nil {
			return fmt.Errorf("owner hook %s lost: %w", name, err)
		}
	}
	return nil
}

// Start only PREPARES under a closed gate. No policy commit or admission is
// possible until the native caller invokes Activate after StartGadget succeeds.
func (o *Owner) Start(gc operators.GadgetContext) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if gc == nil || o.context != gc || o.closed || o.closing || o.slot != nil || o.lease != nil {
		return fmt.Errorf("invalid owner startup")
	}
	ctx, cancel := context.WithTimeout(gc.Context(), 5*time.Second)
	defer cancel()
	o.captureCounters() // Telemetry failure must not alter enforcement readiness.
	if err := o.captureAttachments(); err != nil {
		return err
	}
	lease, err := o.config.Acquire(ctx)
	o.lease = lease // retain even a partially acquired error result until teardown
	if err != nil {
		return err
	}
	if lease == nil {
		return fmt.Errorf("runtime returned no binding lease")
	}
	if err = lease.Check(ctx); err != nil {
		return err
	}
	o.proc, err = DuplicateProcPin(lease.InitProc())
	if err != nil {
		return err
	}
	o.start, err = readPinnedInitStart(o.proc, o.config.InitHostPID)
	if err != nil {
		return err
	}
	if err = o.verify(ctx); err != nil {
		return err
	}
	o.resources, err = ControlResourcesFromContext(gc)
	if err != nil {
		return err
	}
	gateMap, err := o.mapHandle("eo_gates")
	if err != nil {
		return err
	}
	o.gates, err = NewGateMap(gateMap)
	if err != nil {
		return err
	}
	index, gate, err := o.gates.Allocate()
	if err != nil {
		return err
	}
	o.gate = gate
	slots, err := o.mapHandle("eo_programs")
	if err != nil {
		return err
	}
	epochs, err := o.mapHandle("eo_epochs")
	if err != nil {
		return err
	}
	o.slot, err = NewProgramSlot(gate, slots, epochs)
	if err != nil {
		return err
	}
	initial, err := o.slot.Begin(ctx, o.config.Program)
	if err != nil {
		return err
	}
	origins, err := o.mapHandle("image_origins")
	if err != nil {
		return err
	}
	ready, err := o.mapHandle("image_ready")
	if err != nil {
		return err
	}
	if err = execruntime.InitializeImageOrigins(origins, ready, o.config.ImageOrigins); err != nil {
		return err
	}
	fsOrigins, err := o.mapHandle("fs_inode_origins")
	if err != nil {
		return err
	}
	fsDiagnostics, err := o.mapHandle("fs_diagnostics")
	if err != nil {
		return err
	}
	o.tracker, err = execruntime.NewFilesystemTracker(fsOrigins, fsDiagnostics)
	if err != nil {
		return err
	}
	if err = o.tracker.Probe(); err != nil {
		return err
	}
	zero, err := o.mapHandle("zero_observation")
	if err != nil {
		return err
	}
	if err = zero.Freeze(); err != nil {
		return err
	}
	var bytes [8]byte
	if _, err = rand.Read(bytes[:]); err != nil {
		return err
	}
	cookie := binary.LittleEndian.Uint64(bytes[:])
	if cookie == 0 {
		return fmt.Errorf("invalid random owner cookie")
	}
	o.control, err = newOwnerControl(ctx, ControlConfig{Cookie: cookie, Cgroup: o.config.CgroupID, InitHostPID: o.config.InitHostPID, TaskLimit: OwnerTaskLimit, GateSlot: index, ABI: o.config.ownerABI()}, o.resources, gate, o.config.ABI3Development)
	if err != nil {
		return err
	}
	if err = o.control.ArmMovement(ctx, o.config.ControlRoot); err != nil {
		return err
	}
	inventory, err := o.control.Call(ctx, ControlCommand{Operation: OwnerInventory})
	if err != nil {
		return err
	}
	rows, err := o.control.Rows(inventory.Count)
	if err != nil {
		return err
	}
	var rootCookie uint64
	for _, row := range rows {
		if row.TID == o.config.InitHostPID && row.TGID == o.config.InitHostPID {
			if rootCookie != 0 {
				return fmt.Errorf("duplicate trusted init inventory")
			}
			rootCookie = row.Cookie
		}
	}
	if rootCookie == 0 {
		return fmt.Errorf("trusted init absent from physical inventory")
	}
	if err = o.verify(ctx); err != nil {
		return err
	}
	if _, err = o.control.Call(ctx, ControlCommand{Operation: OwnerRootAuthorize, RootCookie: rootCookie}); err != nil {
		return err
	}
	if err = o.verify(ctx); err != nil {
		return err
	}
	o.publisher, err = NewPublisher(o.slot, o.control, o.verify, initial)
	if err == nil {
		o.pending = o.config.Program
	}
	return err
}

func (o *Owner) Ready(gc operators.GadgetContext) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.context != gc || o.publisher == nil || o.closing || o.closed {
		return fmt.Errorf("owner startup incomplete")
	}
	ctx, cancel := context.WithTimeout(gc.Context(), 5*time.Second)
	defer cancel()
	if err := o.verify(ctx); err != nil {
		return err
	}
	if err := o.tracker.Check(); err != nil {
		return err
	}
	o.prepared = true
	return nil
}

// Activate is called ONLY after the manager has acknowledged all IG startup.
// Gadget readiness is not sandbox Ready: this explicit second boundary commits
// the prepared first revision and only then reopens authored exec admission.
func (o *Owner) Activate(ctx context.Context) (PublicationResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.prepared || o.closing || o.closed || o.current != nil {
		return PublicationResult{}, fmt.Errorf("owner cannot activate")
	}
	result, err := o.publisher.Resume(ctx)
	o.completeAttempt(result, o.config.Program)
	return result, err
}

func (o *Owner) Update(ctx context.Context, program *fullpolicy.KernelProgram) (PublicationResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.current == nil || o.closing || o.closed {
		return PublicationResult{}, fmt.Errorf("owner is not activated")
	}
	if o.pending != nil {
		return PublicationResult{}, ErrGateBusy
	}
	candidate := snapshotProgram(program)
	if err := validateOwnerProgram(candidate, o.config.ImageOrigins); err != nil {
		return PublicationResult{}, err
	}
	if usesFilesystem(candidate) {
		if err := o.tracker.Check(); err != nil {
			return PublicationResult{}, err
		}
	}
	result, err := o.publisher.Publish(ctx, candidate)
	o.completeAttempt(result, candidate)
	return result, err
}

// AbortPending discards only an uncommitted candidate. Committed publications
// must finish through Resume; their policy and UID root epochs cannot roll back.
func (o *Owner) AbortPending(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.prepared || o.closing || o.closed || o.publisher == nil {
		return fmt.Errorf("owner not running")
	}
	err := o.publisher.Abort(ctx)
	o.publisher.mu.Lock()
	defer o.publisher.mu.Unlock()
	// Abort can consume the update lease while reporting deferred cleanup errors.
	if o.publisher.pending == nil {
		o.pending = nil
	}
	return err
}

func (o *Owner) Resume(ctx context.Context) (PublicationResult, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.prepared || o.closing || o.closed {
		return PublicationResult{}, fmt.Errorf("owner not running")
	}
	if o.pending == nil {
		return PublicationResult{}, fmt.Errorf("no pending owner publication")
	}
	result, err := o.publisher.Resume(ctx)
	o.completeAttempt(result, o.pending)
	return result, err
}

func (o *Owner) completeAttempt(result PublicationResult, candidate *fullpolicy.KernelProgram) {
	if result.Committed {
		o.current = candidate
	}
	o.publisher.mu.Lock()
	defer o.publisher.mu.Unlock()
	if o.publisher.pending != nil {
		o.pending = candidate
	} else {
		o.pending = nil
	}
}

func (o *Owner) Epochs() map[string]uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.slot == nil {
		return nil
	}
	return o.slot.Epochs()
}

func (o *Owner) Check(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.current == nil || o.closing || o.closed {
		return fmt.Errorf("owner is not activated")
	}
	if o.pending != nil {
		return fmt.Errorf("owner publication is not finalized: %w", ErrGateBusy)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	// Finish may have reopened admission and consumed its publication handle
	// before deleting the auxiliary staging reference failed. Same-revision
	// health retries must finish that cleanup rather than silently report Ready.
	// Cleanup refuses any slot update still in flight and never changes the
	// active program, successful epochs or admission state.
	if err := o.slot.Cleanup(); err != nil {
		return fmt.Errorf("owner finalized publication cleanup: %w", err)
	}
	if err := o.verify(ctx); err != nil {
		return err
	}
	if usesFilesystem(o.current) {
		if err := o.tracker.Check(); err != nil {
			return err
		}
	}
	return checkProtection(ctx, o.control, o.gate, o.slot.Generation())
}

// checkProtection is the read-only heartbeat behind Owner.Check. It never
// closes the admission gate and never re-attests: a closed gate denies
// not-yet-owned execs (gate_denials) and fails forks with EAGAIN in the bound
// cgroup in every mode, including Audit, so a same-plan refresh must not close
// it. Live kernel facts that show drift are checked and fail closed, but
// physical cgroup membership is not inventoried: a dormant unverified task in
// the bound cgroup is caught when it execs or forks (quarantine, owner fault,
// NotReady) or at the next publication.
//
// The coarse movement receipt (ValidatedMovementSequence) goes stale on any
// cgroup migration on the node, so a stale receipt is not drift and is not
// renewed here. No admission hook reads it: exec and fork in the bound cgroup
// validate the task's roles on every operation, and an invalid task is denied
// and quarantined, which raises Faults and fails this check. Each publication
// (Activate, Update, Resume) re-validates the physical inventory under a
// drained gate before it commits and again after the swap.
func checkProtection(ctx context.Context, control publicationControl, gate *Gate, generation uint64) error {
	h, err := control.Call(ctx, ControlCommand{Operation: OwnerRootCheck})
	if err != nil {
		return err
	}
	if h.RootMatch != 1 || h.ActiveGeneration != generation || h.Faults != 0 || h.Retired != 0 || h.MovementArmed != 1 || h.MovementFault != 0 || h.MovementSequence&1 != 0 {
		return fmt.Errorf("owner kernel protection is not confirmed")
	}
	// A failed validation, a fault or an invalidated publication receipt clears
	// the readiness generation. Only a new publication restores it.
	if h.ReadyGeneration != generation {
		return fmt.Errorf("owner readiness for generation %d is not attested", generation)
	}
	phase, err := control.Phase()
	if err != nil {
		return err
	}
	if phase.State != OwnerIdle || phase.CommittedGeneration != generation {
		return fmt.Errorf("owner publication phase is not idle")
	}
	faults, err := control.GenerationFault(generation)
	if err != nil {
		return err
	}
	if faults != 0 {
		return fmt.Errorf("active generation observation/semantic fault %#x", faults)
	}
	closed, _, err := gate.State()
	if err != nil {
		return err
	}
	if closed {
		return fmt.Errorf("owner publication is not finalized")
	}
	return nil
}

func (o *Owner) beforeStop(ctx context.Context) error {
	if o.closed {
		return nil
	}
	if o.publisher != nil {
		err := o.publisher.Retire(ctx)
		o.publisher.mu.Lock()
		o.closing = o.publisher.retired
		o.publisher.mu.Unlock()
		return err
	}
	if o.slot != nil {
		if err := o.slot.Retire(ctx); err != nil {
			return err
		}
	} else if o.gate != nil {
		lease, err := o.gate.BeginUpdate(ctx)
		if err != nil {
			return err
		}
		if err = lease.Retire(); err != nil {
			return err
		}
	}
	o.closing = true
	if o.control != nil {
		_, err := o.control.Call(ctx, ControlCommand{Operation: OwnerRetire})
		return err
	}
	return nil
}

// KernelEventCounters counts evaluator events, not every denied exec. Early
// owner/gate/lineage refusals return before verdict emission and are excluded.
// Live per-CPU reads are not atomic across CPUs or keys. Final is set only after
// verified attachment teardown; an error means the counts are incomplete
// (the last successful sample, if any).
type KernelEventCounters struct {
	Submitted         uint64
	Lost              uint64 // failed verdict ring-buffer reservations
	ObservationErrors uint64
	Final             bool
}

type kernelCounterMap interface {
	Lookup(interface{}, interface{}) error
	Close() error
}

func validateCounterMap(info *ebpf.MapInfo) error {
	if info == nil || info.Type != ebpf.PerCPUArray || info.KeySize != 4 || info.ValueSize != 8 || info.MaxEntries != 3 {
		return fmt.Errorf("incompatible full verdict counters map")
	}
	return nil
}

func (o *Owner) captureCounters() {
	if o.counterMap != nil || o.counterFinal {
		return
	}
	m, err := o.mapHandle("counters")
	if err == nil {
		var info *ebpf.MapInfo
		info, err = m.Info()
		if err == nil {
			err = validateCounterMap(info)
		}
		if err == nil {
			var clone *ebpf.Map
			clone, err = m.Clone()
			if err == nil {
				o.counterMap = clone
			}
		}
	}
	o.counterErr = err
}

func (o *Owner) readCounters() (KernelEventCounters, error) {
	if o.counterMap == nil {
		return KernelEventCounters{}, errors.Join(fmt.Errorf("full verdict counters unavailable"), o.counterErr)
	}
	var result KernelEventCounters
	fields := []*uint64{&result.Submitted, &result.Lost, &result.ObservationErrors}
	for key, field := range fields {
		var values []uint64
		if err := o.counterMap.Lookup(uint32(key), &values); err != nil {
			return KernelEventCounters{}, fmt.Errorf("read full verdict counter %d: %w", key, err)
		}
		if len(values) == 0 {
			return KernelEventCounters{}, fmt.Errorf("empty full verdict per-CPU counter %d", key)
		}
		for _, value := range values {
			*field += value
		}
	}
	return result, nil
}

// KernelEventCounters is read-only, including after owner release. It never
// resumes publication, reopens a gate, or acknowledges native health faults.
func (o *Owner) KernelEventCounters() (KernelEventCounters, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.counterFinal {
		return o.counterSnapshot, o.counterErr
	}
	counters, err := o.readCounters()
	if err == nil {
		o.counterSnapshot = counters
	}
	return o.counterSnapshot, err
}

// Called only after ReleaseAfterDetach has verified collection and hook closure.
// A cloned map FD survives manager teardown, so the snapshot includes reserves
// racing retirement. Failed reads remain explicitly unavailable after release.
func (o *Owner) finalizeCounters() {
	if o.counterFinal {
		return
	}
	counters, err := o.readCounters()
	if err == nil {
		o.counterSnapshot = counters
	}
	o.counterErr = err
	o.counterSnapshot.Final = true
	if o.counterMap != nil {
		o.counterErr = errors.Join(o.counterErr, o.counterMap.Close())
		o.counterMap = nil
	}
	o.counterFinal = true
}

// OwnerDiagnostics is a bounded, read-only observation, not a readiness receipt.
// Kernel counters may change between reads; Check remains the health authority.
type OwnerDiagnostics struct {
	Health     ControlHealth
	GateClosed bool
	Admitted   uint64
}

func (o *Owner) Diagnostics() (OwnerDiagnostics, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.control == nil || o.gate == nil || o.closed || o.released {
		return OwnerDiagnostics{}, fmt.Errorf("owner diagnostic resources unavailable")
	}
	health, err := o.control.Health()
	if err != nil {
		return OwnerDiagnostics{}, err
	}
	closed, count, err := o.gate.State()
	return OwnerDiagnostics{Health: health, GateClosed: closed, Admitted: count}, err
}

func (o *Owner) BeforeStop(ctx context.Context) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.beforeStop(ctx)
}

func (o *Owner) PreStop(gc operators.GadgetContext) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(gc.Context()), 5*time.Second)
	defer cancel()
	return o.BeforeStop(ctx)
}
func (o *Owner) Stop(gc operators.GadgetContext) error { return o.PreStop(gc) }
func (o *Owner) Close(gc operators.GadgetContext) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := o.beforeStop(ctx)
	if o.control != nil {
		err = errors.Join(err, o.control.Close())
	}
	o.closing = true
	o.closed = true
	return err // never release pins or borrowed resources here
}

// ReleaseAfterDetach follows a successful manager WaitStopped, not StopGadget's
// cancellation alone. It also checks actual borrowed FDs/receipts are no longer
// live. On failure retain this Owner and retry; never release its identity pins.
func (o *Owner) ReleaseAfterDetach() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.released {
		return nil
	}
	if o.claimed && !o.closed {
		return fmt.Errorf("owner operator has not closed")
	}
	if o.resources.Program != nil && o.resources.Program.FD() >= 0 {
		return fmt.Errorf("owner command still loaded")
	}
	for _, m := range []*ebpf.Map{o.resources.Configuration, o.resources.Tasks, o.resources.TaskIDs, o.resources.Work} {
		if m != nil && m.FD() >= 0 {
			return fmt.Errorf("owner collection still open")
		}
	}
	for name, receipt := range o.attachments {
		if receipt.Check() == nil {
			return fmt.Errorf("owner hook %s still attached", name)
		}
	}
	o.finalizeCounters()
	if o.slot != nil {
		if err := o.slot.CloseAfterDetach(); err != nil {
			return err
		}
	}
	if o.gates != nil {
		if err := o.gates.Close(); err != nil {
			return err
		}
	}
	// Close consumes file/lease ownership even on OS close errors. Never retry a
	// recycled descriptor; the runtime-specific lease follows the same contract.
	var errs []error
	if o.proc != nil {
		errs = append(errs, o.proc.Close())
		o.proc = nil
	}
	if o.lease != nil {
		errs = append(errs, o.lease.Close())
		o.lease = nil
	}
	o.reservation.release()
	o.released = true
	return errors.Join(errs...)
}

func usesFilesystem(p *fullpolicy.KernelProgram) bool {
	h, _ := fullpolicy.Decode[fullpolicy.KernelHeader](p.Entries[0])
	for i := uint32(0); i < h.RuleCount; i++ {
		r, _ := fullpolicy.Decode[fullpolicy.KernelRule](p.Entries[h.RuleBase+i])
		if r.FSType.Count != 0 {
			return true
		}
	}
	return false
}

func validateOwnerProgram(p *fullpolicy.KernelProgram, snapshot *execruntime.ImageOriginSnapshot) error {
	if err := fullpolicy.ValidateKernelProgram(p); err != nil {
		return err
	}
	h, _ := fullpolicy.Decode[fullpolicy.KernelHeader](p.Entries[0])
	for i := uint32(0); i < h.RuleCount; i++ {
		r, _ := fullpolicy.Decode[fullpolicy.KernelRule](p.Entries[h.RuleBase+i])
		if (r.ActorImage != -1 || r.TargetImage != -1) && (snapshot == nil || !snapshot.Complete) {
			return fmt.Errorf("image predicate requires complete lifetime origin lease")
		}
	}
	return execruntime.ValidateImageOriginSnapshot(snapshot)
}

func (o *Owner) Generation() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.slot == nil {
		return 0
	}
	return o.slot.Generation()
}

func (o *Owner) PendingGeneration() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.pending == nil {
		return 0
	}
	h, _ := fullpolicy.Decode[fullpolicy.KernelHeader](o.pending.Entries[0])
	return h.Generation
}
