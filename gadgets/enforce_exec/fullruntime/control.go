// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

const (
	OwnerABI            = 2
	OwnerDevelopmentABI = 3
	OwnerTaskLimit      = 4096
	pidfdThread         = 0x80 // Linux PIDFD_THREAD; older x/sys versions omit the name.
)

const (
	OwnerInventory uint32 = iota + 1
	OwnerRootAuthorize
	OwnerRootCheck
	OwnerBootstrapA
	OwnerBootstrapB
	OwnerValidate
	OwnerPublicationBegin
	OwnerPublicationCommitted
	OwnerBootstrapAbort
	OwnerPhaseClear
	OwnerRetire
	OwnerReattest
	OwnerSessionOpen
	OwnerCandidateBegin
	OwnerCandidateAbort
	OwnerCandidateWrite
	OwnerCandidateSeal
)

type ControlConfig struct {
	Cookie, Cgroup                        uint64
	InitHostPID, TaskLimit, GateSlot, ABI uint32
}
type ControlCommand struct {
	Nonce, Generation, RootCookie uint64
	Operation, NewUIDMask         uint32
}
type ControlHealth struct {
	TaskCredits, WorkCredits, AuthorityVersion, AComplete, ReadyGeneration uint64
	ActiveGeneration, MovementSequence, MovementArmed, MovementFault       uint64
	Faults, PendingBirths, GateDenials, RootCookie                         uint64
	Count, Result, Retired, Busy, RootMatch, Padding                       uint32
}
type ControlPhase struct {
	Busy, AttemptedGeneration, CandidateGeneration uint64
	State, NewUIDMask                              uint32
	CommittedGeneration, ValidatedMovementSequence uint64
}
type ControlRow struct {
	Cookie                       uint64
	TID, TGID, Flags, ValidRoles uint32
}

// DispatchDescriptor is a development-only kernel snapshot, not native write authority.
type DispatchDescriptor struct {
	Generation                                             uint64
	ExecutionClass, ProgramBank, HistoryReserved, Reserved uint32
	PolicyCount, RoleWriterMask                            uint32
}
type (
	CandidateAddition struct{ UID, Epoch uint64 }
	CandidateRecord   struct {
		Attempt, ReceiptSerial, InventoryCount, Writers, WriteSequence uint64
		PassID, PassStartSerial                                        uint64
		Expected                                                       DispatchDescriptor
		State, ProgramBank, HistoryReserved, SealedClass               uint32
		Entries, RequiredKnownMask, AdditionCount, CertifiedKnownMask  uint32
		SealedPolicyCount, SealedRoleWriterMask                        uint32
		Additions                                                      [8]CandidateAddition
	}
)

type DispatchRecord struct {
	Lock, ScopeState                                             uint32
	SessionCookie, Cgroup, Serial, LastAttempt                   uint64
	Active                                                       DispatchDescriptor
	ExecInflight, ForkInflight, IngressInflight, MutationWriters uint64
	AuthorityReaders                                             uint64
	BankReaders                                                  [2]uint64
	IntegrityFault, CoverageUnknown                              uint64
	Candidate                                                    CandidateRecord
}
type CandidateRequest struct {
	SessionCookie, Attempt         uint64
	Entries, Reserved, Index, Bank uint32
}
type CandidateInput struct {
	Request CandidateRequest
	Data    [288]byte
}
type SealWorkspace struct {
	Busy, SessionCookie, Attempt uint64
	Patterns, Instructions       uint32
	Seen                         [256]uint64
}
type ControlResources struct {
	Epochs                                               *ebpf.Map
	SealWork                                             *ebpf.Map
	ProgramBank0, ProgramBank1, Dispatch, CandidateInput *ebpf.Map
	TaskIDs, ZeroTask                                    *ebpf.Map
	GenerationFaults                                     *ebpf.Map
	Configuration, Commands, Health, Phase, Rows         *ebpf.Map
	Admin, Tasks, Work, Anchor, Births                   *ebpf.Map
	Program                                              *ebpf.Program
}

// ControlResourcesFromContext borrows the actual loaded handles. The native
// owner must stop/join all commands before the eBPF operator closes them.
func ControlResourcesFromContext(gc operators.GadgetContext) (ControlResources, error) {
	var r ControlResources
	for name, dst := range map[string]**ebpf.Map{
		"eo_task_ids": &r.TaskIDs, "eo_zero_task": &r.ZeroTask, "eo_generation_faults": &r.GenerationFaults, "eo_configuration": &r.Configuration, "eo_commands": &r.Commands, "eo_health": &r.Health, "eo_phase": &r.Phase, "eo_rows": &r.Rows,
		"eo_admin": &r.Admin, "eo_tasks": &r.Tasks, "eo_work": &r.Work, "eo_anchor": &r.Anchor, "eo_birth_groups": &r.Births,
	} {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		m, ok := value.(*ebpf.Map)
		if !ok || m == nil {
			return r, fmt.Errorf("missing owner map %s", name)
		}
		*dst = m
	}
	// ABI2 has neither map. ABI-selected validation below requires both for ABI3.
	for name, dst := range map[string]**ebpf.Map{
		"eo_epochs": &r.Epochs, "eo_seal_work": &r.SealWork, "eo_dispatch": &r.Dispatch, "eo_candidate_input": &r.CandidateInput,
		"eo_program_bank0": &r.ProgramBank0, "eo_program_bank1": &r.ProgramBank1,
	} {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		*dst, _ = value.(*ebpf.Map)
	}
	value, _ := gc.GetVar(operators.ProgramPrefix + "eo_command")
	r.Program, _ = value.(*ebpf.Program)
	if r.Program == nil {
		return r, fmt.Errorf("missing native owner command program")
	}
	return r, nil
}

func (r ControlResources) validate(abi uint32) error {
	taskSize, workSize := uint32(680), uint32(1096)
	switch abi {
	case OwnerABI:
	case OwnerDevelopmentABI:
		// Transitional Stage A layout, not the complete ADR resource profile.
		taskSize, workSize = 1088, 2648

		for _, row := range []struct {
			name             string
			m                *ebpf.Map
			size, max, flags uint32
		}{
			{"dispatch", r.Dispatch, 400, 1, unix.BPF_F_RDONLY},
			{"candidate input", r.CandidateInput, 320, 1, unix.BPF_F_RDONLY_PROG},
			{"seal workspace", r.SealWork, 2080, 1, unix.BPF_F_RDONLY},
			{"program bank 0", r.ProgramBank0, 296, 16384, unix.BPF_F_RDONLY},
			{"program bank 1", r.ProgramBank1, 296, 16384, unix.BPF_F_RDONLY},
		} {
			if row.m == nil || row.m.FD() < 0 || row.m.Type() != ebpf.Array || row.m.KeySize() != 4 || row.m.ValueSize() != row.size || row.m.MaxEntries() != row.max || row.m.Flags() != row.flags {
				return fmt.Errorf("invalid development owner %s map ABI", row.name)
			}
		}
		if r.Epochs == nil || r.Epochs.FD() < 0 || r.Epochs.Type() != ebpf.Hash || r.Epochs.KeySize() != 8 || r.Epochs.ValueSize() != 8 || r.Epochs.MaxEntries() != 65536 || r.Epochs.Flags() != unix.BPF_F_NO_PREALLOC|unix.BPF_F_RDONLY {
			return fmt.Errorf("invalid development owner accepted catalogue map ABI")
		}

	default:
		return fmt.Errorf("unsupported owner map ABI")
	}
	for _, row := range []struct {
		name                   string
		m                      *ebpf.Map
		kind                   ebpf.MapType
		key, value, max, flags uint32
	}{
		{"generation faults", r.GenerationFaults, ebpf.LRUHash, 8, 8, 64, unix.BPF_F_RDONLY},
		{"config", r.Configuration, ebpf.Array, 4, 32, 1, unix.BPF_F_RDONLY_PROG},
		{"commands", r.Commands, ebpf.Array, 4, 32, 1, unix.BPF_F_RDONLY_PROG},
		{"health", r.Health, ebpf.Array, 4, 128, 1, unix.BPF_F_RDONLY},
		{"phase", r.Phase, ebpf.Array, 4, 48, 1, unix.BPF_F_RDONLY},
		{"rows", r.Rows, ebpf.Array, 4, 24, OwnerTaskLimit, unix.BPF_F_RDONLY},
		{"admin", r.Admin, ebpf.TaskStorage, 4, 8, 0, unix.BPF_F_NO_PREALLOC},
		{"tasks", r.Tasks, ebpf.Hash, 8, taskSize, OwnerTaskLimit, unix.BPF_F_NO_PREALLOC | unix.BPF_F_RDONLY},
		{"task identities", r.TaskIDs, ebpf.TaskStorage, 4, 8, 0, unix.BPF_F_NO_PREALLOC},
		{"zero task", r.ZeroTask, ebpf.Array, 4, taskSize, 1, unix.BPF_F_RDONLY_PROG},
		{"work", r.Work, ebpf.TaskStorage, 4, workSize, 0, unix.BPF_F_NO_PREALLOC},
		{"anchor", r.Anchor, ebpf.Array, 4, 16, 1, unix.BPF_F_WRONLY},
		{"births", r.Births, ebpf.Hash, 8, 8, OwnerTaskLimit, unix.BPF_F_NO_PREALLOC | unix.BPF_F_WRONLY},
	} {
		if row.m == nil || row.m.FD() < 0 || row.m.Type() != row.kind || row.m.KeySize() != row.key || row.m.ValueSize() != row.value || row.m.MaxEntries() != row.max || row.m.Flags() != row.flags {
			return fmt.Errorf("invalid owner %s map ABI", row.name)
		}
	}
	if r.Program == nil || r.Program.FD() < 0 || r.Program.Type() != ebpf.Syscall {
		return fmt.Errorf("owner command must be a loaded syscall program")
	}
	return nil
}

var ErrControlClosed = errors.New("owner command thread closed")

type (
	controlFailure struct{ err error }
	controlJob     struct {
		ctx     context.Context
		run     func() error
		result  chan error
		private bool // scalar-result callers use non-retaining panic recovery
	}
)

type controlThread struct {
	jobs       chan controlJob
	stop, done chan struct{}
	once       sync.Once
	failure    atomic.Pointer[controlFailure]
}

func safeControlCall(fn func() error) (err error, panicked bool) {
	defer func() {
		if value := recover(); value != nil {
			err = fmt.Errorf("owner command panic: %v", value)
			panicked = true
		}
	}()
	return fn(), false
}

// A private panic has a fixed terminal owner and never formats or retains the
// recovered payload. This does not bound allocations made before the panic.
var (
	errPrivateControlPanic     = errors.New("private owner command panic")
	privateControlPanicFailure = &controlFailure{err: errPrivateControlPanic}
)

func safePrivateControlCall(fn func() error) (err error, panicked bool) {
	defer func() {
		if recover() != nil {
			err, panicked = errPrivateControlPanic, true
		}
	}()
	return fn(), false
}

func startControlThread(setup func() error) (*controlThread, error) {
	w := &controlThread{jobs: make(chan controlJob), stop: make(chan struct{}), done: make(chan struct{})}
	ready := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		// Deliberately do NOT UnlockOSThread: the frozen admin nonce belongs to this
		// physical task. Exit destroys the OS thread instead of handing its authority
		// to another goroutine in the Go thread pool.
		defer close(w.done)
		err, _ := safeControlCall(setup)
		if err != nil {
			w.failure.Store(&controlFailure{err})
			ready <- err
			return
		}
		ready <- nil
		for {
			select {
			case <-w.stop:
				return
			case job := <-w.jobs:
				if err := job.ctx.Err(); err != nil {
					job.result <- err
					continue
				}
				isPrivate := job.private
				var err error
				var panicked bool
				if isPrivate {
					err, panicked = safePrivateControlCall(job.run)
					if panicked {
						// Publish terminal state BEFORE the result is observable.
						w.failure.Store(privateControlPanicFailure)
					}
				} else {
					err, panicked = safeControlCall(job.run)
				}
				job.result <- err
				if panicked {
					if !isPrivate {
						w.failure.Store(&controlFailure{err})
					}
					return
				}
			}
		}
	}()
	if err := <-ready; err != nil {
		<-w.done
		return nil, err
	}
	return w, nil
}

func (w *controlThread) unavailable() error {
	if failed := w.failure.Load(); failed != nil {
		return failed.err
	}
	return ErrControlClosed
}

func (w *controlThread) do(ctx context.Context, fn func() error) error {
	err, canceled, accepted := w.doJoined(ctx, fn, false)
	if !accepted {
		return err
	}
	return errors.Join(err, canceled)
}

// doJoined separates execution from rich error presentation. The acceptance bit
// preserves direct pre-submission errors versus joined accepted-call errors.
// Callers must not let cleanup/finish replace this cancellation snapshot.
func (w *controlThread) doJoined(ctx context.Context, fn func() error, private bool) (err, canceled error, accepted bool) {
	if err := ctx.Err(); err != nil {
		return err, nil, false
	}
	job := controlJob{ctx: ctx, run: fn, result: make(chan error, 1), private: private}
	select {
	case <-w.done:
		return w.unavailable(), nil, false
	case <-ctx.Done():
		return ctx.Err(), nil, false
	case <-w.stop:
		return ErrControlClosed, nil, false
	case w.jobs <- job:
	}
	// Once accepted, a bounded kernel call must be JOINED even after cancellation.
	// Returning early would let native rollback/reopen race an unfinished writer.
	err = <-job.result
	return err, ctx.Err(), true
}

func (w *controlThread) close() error {
	w.once.Do(func() { close(w.stop) })
	<-w.done
	if failed := w.failure.Load(); failed != nil {
		return failed.err
	}
	return nil
}

// OwnerControl owns one pinned command thread, not the borrowed maps/program or
// the binding itself. It does not authorize the proc pin, report Ready or manage
// ProgramSlot transactions. The native owner must retain its trusted init proc
// pin and validate it before/after initial root authorization and publication.
type OwnerControl struct {
	resources ControlResources
	config    ControlConfig
	thread    *controlThread
}

func NewOwnerControl(ctx context.Context, cfg ControlConfig, r ControlResources, gate *Gate) (*OwnerControl, error) {
	return newOwnerControl(ctx, cfg, r, gate, false)
}

func newOwnerControl(ctx context.Context, cfg ControlConfig, r ControlResources, gate *Gate, development bool) (*OwnerControl, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if runtime.GOARCH != "amd64" || cfg.ABI != (OwnerConfig{ABI3Development: development}).ownerABI() || cfg.Cookie == 0 || cfg.Cgroup == 0 || cfg.InitHostPID == 0 || cfg.InitHostPID > 0x7fffffff || cfg.TaskLimit == 0 || cfg.TaskLimit > OwnerTaskLimit || cfg.GateSlot >= MaxLifetimeSlots {
		return nil, fmt.Errorf("unsupported or incomplete native owner configuration")
	}
	if gate == nil {
		return nil, fmt.Errorf("owner gate required")
	}
	closed, count, err := gate.State()
	if err != nil {
		return nil, err
	}
	if !closed || count != 0 {
		return nil, fmt.Errorf("owner setup requires its closed/drained publication lease")
	}
	if err = r.validate(cfg.ABI); err != nil {
		return nil, err
	}
	var existing ControlConfig
	if err = r.Configuration.Lookup(uint32(0), &existing); err != nil {
		return nil, err
	}
	if existing != (ControlConfig{}) {
		return nil, fmt.Errorf("owner configuration already initialized")
	}
	// Kernel-owned task and opaque maps are immutable from UAPI BEFORE scope
	// activation. Read-only-UAPI health/rows/phase already prohibit native writes.
	for _, row := range []struct {
		name string
		m    *ebpf.Map
	}{{"task identities", r.TaskIDs}, {"zero task", r.ZeroTask}, {"work", r.Work}, {"anchor", r.Anchor}, {"births", r.Births}} {
		if err = row.m.Freeze(); err != nil {
			return nil, fmt.Errorf("freeze owner %s: %w", row.name, err)
		}
	}
	c := &OwnerControl{resources: r, config: cfg}
	c.thread, err = startControlThread(func() error {
		fd, e := unix.PidfdOpen(unix.Gettid(), pidfdThread)
		if e != nil {
			return fmt.Errorf("owner PIDFD_THREAD: %w", e)
		}
		defer unix.Close(fd)
		if e = r.Admin.Put(uint32(fd), cfg.Cookie); e != nil {
			return e
		}
		if e = r.Admin.Freeze(); e != nil {
			return e
		}
		if e = r.Commands.Put(uint32(0), ControlCommand{Nonce: cfg.Cookie}); e != nil {
			return e
		}
		if e = r.Configuration.Put(uint32(0), cfg); e != nil {
			return e
		}
		return r.Configuration.Freeze()
	})
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, errors.Join(err, c.Close())
	}
	return c, nil
}

func (c *OwnerControl) Health() (ControlHealth, error) {
	var h ControlHealth
	err := c.resources.Health.Lookup(uint32(0), &h)
	return h, err
}

func (c *OwnerControl) Phase() (ControlPhase, error) {
	var p ControlPhase
	err := c.resources.Phase.Lookup(uint32(0), &p)
	return p, err
}

// Call serializes both input and result on the qualified thread. A nonzero
// syscall return is an error even if the shared result still contains an older
// success; unauthorized callers cannot manufacture an acknowledgement.
func (c *OwnerControl) Call(ctx context.Context, command ControlCommand) (ControlHealth, error) {
	var h ControlHealth
	err := c.thread.do(ctx, func() error {
		command.Nonce = c.config.Cookie
		if err := c.resources.Commands.Put(uint32(0), command); err != nil {
			return err
		}
		result, err := c.resources.Program.Run(&ebpf.RunOptions{})
		if err != nil {
			return err
		}
		if result != 0 {
			return fmt.Errorf("owner command %d refused: result %d", command.Operation, result)
		}
		h, err = c.Health()
		if err != nil {
			return err
		}
		if h.Result != 0 {
			return fmt.Errorf("owner command %d incomplete: status %d", command.Operation, h.Result)
		}
		return nil
	})
	return h, err
}

// Dispatch returns one coherent kernel-owned descriptor and receipt snapshot.
// The map is retained by the owner/program; no native code writes this record.
func (c *OwnerControl) Dispatch() (DispatchRecord, error) {
	var record DispatchRecord
	if c.config.ABI != OwnerDevelopmentABI || c.resources.Dispatch == nil {
		return record, fmt.Errorf("development dispatch unavailable")
	}
	err := c.resources.Dispatch.LookupWithFlags(uint32(0), &record, ebpf.LookupLock)
	return record, err
}

func (c *OwnerControl) candidateCommand(operation uint32, input CandidateInput) (ControlCommand, error) {
	if c.config.ABI != OwnerDevelopmentABI || input.Request.SessionCookie != c.config.Cookie || c.config.Cookie == 0 {
		return ControlCommand{}, fmt.Errorf("development candidate scope mismatch")
	}
	switch operation {
	case OwnerSessionOpen, OwnerCandidateBegin, OwnerCandidateAbort, OwnerCandidateWrite, OwnerCandidateSeal:
	default:
		return ControlCommand{}, fmt.Errorf("invalid development candidate operation")
	}
	if input.Request.Reserved != 0 || (operation != OwnerSessionOpen && input.Request.Attempt == 0) {
		return ControlCommand{}, fmt.Errorf("invalid development candidate request")
	}
	return ControlCommand{Nonce: c.config.Cookie, Generation: input.Request.Attempt, Operation: operation}, nil
}

// CandidateCall keeps request, authenticated syscall, and coherent receipt on
// the same qualified admin thread. It never acquires/closes the legacy gate.
// A receipt is returned even on command failure for exact-identity reconciliation;
// callers must not interpret a syscall errno alone as a commit acknowledgement.
func (c *OwnerControl) CandidateCall(ctx context.Context, operation uint32, input CandidateInput) (DispatchRecord, error) {
	var record DispatchRecord
	command, err := c.candidateCommand(operation, input)
	if err != nil {
		return record, err
	}
	err = c.thread.do(ctx, func() error {
		if err := c.resources.CandidateInput.Put(uint32(0), input); err != nil {
			return err
		}
		if err := c.resources.Commands.Put(uint32(0), command); err != nil {
			return err
		}
		result, runErr := c.resources.Program.Run(&ebpf.RunOptions{})
		var receiptErr error
		record, receiptErr = c.Dispatch()
		if runErr != nil {
			return errors.Join(runErr, receiptErr)
		}
		if result != 0 {
			return errors.Join(fmt.Errorf("candidate command %d refused: result %d", operation, result), receiptErr)
		}
		return receiptErr
	})
	return record, err
}

func (c *OwnerControl) Rows(count uint32) ([]ControlRow, error) {
	if count > OwnerTaskLimit {
		return nil, fmt.Errorf("invalid owner inventory count")
	}
	rows := make([]ControlRow, count)
	for i := range rows {
		if err := c.resources.Rows.Lookup(uint32(i), &rows[i]); err != nil {
			return nil, err
		}
		if rows[i].Cookie == 0 || rows[i].TID == 0 || rows[i].TGID == 0 || rows[i].ValidRoles > 8 {
			return nil, fmt.Errorf("invalid owner inventory row")
		}
	}
	return rows, nil
}

// ArmMovement is an intentionally rejected write, not a hierarchy mutation.
// The pinned kernel acquires cgroup_mutex before parsing the negative PID.
// Require BOTH EINVAL and the kernel-generated authorized arm receipt. Never
// substitute a valid PID, create a helper cgroup, or treat an early parse error
// as proof. controlRoot is an administrator-selected writable cgroup-v2 path.
func (c *OwnerControl) ArmMovement(ctx context.Context, controlRoot string) error {
	if !filepath.IsAbs(controlRoot) || filepath.Clean(controlRoot) != controlRoot {
		return fmt.Errorf("canonical control cgroup path required")
	}
	return c.thread.do(ctx, func() error {
		h, err := c.Health()
		if err != nil {
			return err
		}
		if h.MovementArmed != 0 {
			if h.MovementFault != 0 {
				return fmt.Errorf("movement monitor fault")
			}
			return nil
		}
		fd, err := unix.Openat2(unix.AT_FDCWD, controlRoot, &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return err
		}
		defer unix.Close(fd)
		var stat unix.Statfs_t
		if err = unix.Fstatfs(fd, &stat); err != nil {
			return err
		}
		if stat.Type != unix.CGROUP2_SUPER_MAGIC {
			return fmt.Errorf("control path is not cgroup v2")
		}
		file, err := unix.Openat2(fd, "cgroup.procs", &unix.OpenHow{Flags: unix.O_WRONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS})
		if err != nil {
			return err
		}
		defer unix.Close(file)
		n, writeErr := unix.Write(file, []byte("-1\n"))
		if n > 0 || !errors.Is(writeErr, unix.EINVAL) {
			return fmt.Errorf("nonmutating cgroup barrier unexpectedly accepted (%d bytes): %w", n, writeErr)
		}
		h, err = c.Health()
		if err != nil {
			return err
		}
		if h.MovementArmed != 1 || h.MovementFault != 0 || h.MovementSequence&1 != 0 {
			return fmt.Errorf("authorized cgroup mutex barrier not established")
		}
		return nil
	})
}

func (c *OwnerControl) Close() error {
	if c == nil || c.thread == nil {
		return nil
	}
	return c.thread.close()
}

// DuplicateProcPin returns a caller-owned duplicate; retain it until root-token invalidation and
// confirmed hook teardown, even if startup fails after partial initialization.
func DuplicateProcPin(file *os.File) (*os.File, error) {
	if file == nil {
		return nil, fmt.Errorf("trusted init proc pin required")
	}
	conn, err := file.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var duplicateErr error
	if err = conn.Control(func(original uintptr) { fd, duplicateErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0) }); err != nil {
		return nil, err
	}
	if duplicateErr != nil {
		return nil, duplicateErr
	}
	var stat unix.Stat_t
	if err = unix.Fstat(fd, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR {
		unix.Close(fd)
		if err == nil {
			err = fmt.Errorf("init pin is not a proc directory")
		}
		return nil, err
	}

	var fs unix.Statfs_t
	if err = unix.Fstatfs(fd, &fs); err != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		unix.Close(fd)
		if err == nil {
			err = fmt.Errorf("init pin is not procfs")
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), "sandbox init proc pin"), nil
}

// GenerationFault reads only the selected revision's observation/semantic faults.
// Structural identity/role corruption is separately sticky in ControlHealth.
func (c *OwnerControl) GenerationFault(generation uint64) (uint64, error) {
	var bits uint64
	err := c.resources.GenerationFaults.Lookup(generation, &bits)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return 0, nil
	}
	return bits, err
}
