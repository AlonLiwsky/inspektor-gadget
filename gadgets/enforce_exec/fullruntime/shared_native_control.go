// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"slices"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

const (
	sharedBindingOpen   uint32 = 7
	sharedObjectInspect uint32 = 14
	sharedNodeInspect   uint32 = 16
	sharedLastOperation uint32 = sharedNodeInspect
)

type sharedNodeWire struct {
	NodeCookie, Nonce                             uint64
	ABI, ProfileVersion, Bindings, Objects, Cells uint32
	Slots                                         [4]uint32
	Reserved                                      uint32
}
type sharedPinWire struct {
	Scope, SnapshotSerial, ObjectGeneration uint64
	Position, ObjectSlot, Phase, Reserved   uint32
}
type sharedSnapshotMetadataWire struct {
	RootEpochs                                  [8]uint64
	PolicyUIDs                                  [8]uint64
	ImageHandle                                 uint64
	RoleWriters, RequiredKnown, ContainerLength uint32
	Container                                   [256]byte
	Reserved                                    uint32
}
type sharedCommandWire struct {
	NodeCookie, Nonce, Sequence, Generation, Attempt, Scope, Serial, CgroupIdentity uint64
	Operation, Object, Binding, Record, Index, Count, ExecutionClass, Reserved      uint32
	Handles                                                                         [8]sharedPinWire
	Value                                                                           fullpolicy.Blob
	Metadata                                                                        sharedSnapshotMetadataWire
}
type sharedReceiptWire struct {
	NodeCookie, Sequence, Generation, Serial uint64
	Operation, Status, Value, Reserved       uint32
}
type sharedControlResources struct {
	maps     map[string]*ebpf.Map
	program  *ebpf.Program
	programs map[string]*ebpf.Program
	manifest *operators.NativeResources
}

// The sole protocol command references these maps, including transitive calls.
// se_route_index is still required as a loaded, shape-validated, distinct map;
// only the full image hook union references it. It is not a command dependency.
var sharedProtocolReferencedMapNames = []string{"se_configuration", "se_admin", "se_commands", "se_receipts", "se_objects", "se_bindings", "se_arena", "se_routes"}

func sharedProgramRequiresMap(name string, fullImage bool) bool {
	return slices.Contains(sharedProtocolReferencedMapNames, name) || (fullImage && name != ".bss" && name != ".rodata")
}

func validateSharedMapReferences(required, allowed, actual []ebpf.MapID) error {
	allowedIDs := make(map[ebpf.MapID]bool, len(allowed))
	for _, id := range allowed {
		if id == 0 || allowedIDs[id] {
			return fmt.Errorf("aliased admitted shared map identities")
		}
		allowedIDs[id] = true
	}
	seen := make(map[ebpf.MapID]bool, len(required))
	for _, id := range required {
		if id == 0 || seen[id] || !slices.Contains(actual, id) {
			return fmt.Errorf("missing or aliased shared program map identity")
		}
		seen[id] = true
	}
	for _, id := range actual {
		if id == 0 || !slices.Contains(allowed, id) {
			return fmt.Errorf("unaccounted actual shared program map identity")
		}
	}
	return nil
}

// Validate each required program's own map references before checking the union.
// A command-only receipt cannot stand in for the exec or lifetime programs.
func validateSharedProgramIDs(ids []ebpf.ProgramID) error {
	seen := make(map[ebpf.ProgramID]bool, len(ids))
	for _, id := range ids {
		if id == 0 || seen[id] {
			return fmt.Errorf("missing or aliased shared program identity")
		}
		seen[id] = true
	}
	return nil
}

func validateSharedProgramMapReferences(required, allowed []ebpf.MapID, names []string, programs map[string][]ebpf.MapID) error {
	if len(programs) != len(names) {
		return fmt.Errorf("incomplete loaded shared program inventory")
	}
	var union []ebpf.MapID
	for _, name := range names {
		ids, ok := programs[name]
		if !ok {
			return fmt.Errorf("missing loaded shared program %s", name)
		}
		if err := validateSharedMapReferences(nil, allowed, ids); err != nil {
			return fmt.Errorf("shared program %s: %w", name, err)
		}
		union = append(union, ids...)
	}
	return validateSharedMapReferences(required, allowed, union)
}

func sharedControlResourcesFromContext(gc operators.GadgetContext) (sharedControlResources, error) {
	r := sharedControlResources{maps: map[string]*ebpf.Map{}, programs: map[string]*ebpf.Program{}}
	if gc == nil {
		return r, fmt.Errorf("missing shared context")
	}
	value, _ := gc.GetVar(operators.NativeResourcesKey)
	r.manifest, _ = value.(*operators.NativeResources)
	if r.manifest == nil {
		return r, fmt.Errorf("missing shared native resource manifest")
	}
	programPrefix := operators.ProgramPrefix
	if _, recovered := r.manifest.Programs["se_rm_guardian"]; recovered {
		if selected, _ := gc.GetVar(operators.NativeRecoveryTestRunKey); selected != true {
			return r, fmt.Errorf("recovered loaded programs require trusted selection")
		}
		programPrefix = operators.NativeLoadedProgramPrefix
	}
	for name := range r.manifest.Maps {
		value, _ = gc.GetVar(operators.MapPrefix + name)
		m, _ := value.(*ebpf.Map)
		if m == nil {
			return r, fmt.Errorf("missing shared map %s", name)
		}
		r.maps[name] = m
	}
	for name := range r.manifest.Programs {
		value, _ = gc.GetVar(programPrefix + name)
		p, _ := value.(*ebpf.Program)
		if p == nil {
			return r, fmt.Errorf("missing shared program %s", name)
		}
		r.programs[name] = p
	}
	r.program = r.programs["se_command"]
	return r, nil
}

func (r sharedControlResources) validate(profile SharedProfile) error {
	fullImage := false
	recovered := false
	if r.manifest != nil {
		_, fullImage = r.manifest.Maps["se_tasks"]
		_, recovered = r.manifest.Programs["se_rm_guardian"]
	}
	if recovered {
		if err := validateSharedRecoveryImageGeometry(profile, r.manifest); err != nil {
			return err
		}
	} else if fullImage {
		if _, err := validateSharedImageResources(profile, r.manifest); err != nil {
			return err
		}
	} else if _, err := validateSharedProtocolResources(profile, r.manifest); err != nil {
		return err
	}
	if r.program == nil || r.program.FD() < 0 || r.program.Type() != ebpf.Syscall {
		return fmt.Errorf("missing loaded shared syscall program")
	}
	actualPrograms := make(map[string][]ebpf.MapID, len(r.manifest.Programs))
	names := make([]string, 0, len(r.manifest.Programs))
	programIDs := make([]ebpf.ProgramID, 0, len(r.manifest.Programs))
	for name, shape := range r.manifest.Programs {
		p := r.programs[name]
		if name == "se_command" && p == nil {
			p = r.program
		}
		if p == nil || p.FD() < 0 || uint32(p.Type()) != shape.Type {
			return fmt.Errorf("loaded shared program %s differs from admitted type", name)
		}
		info, err := p.Info()
		if err != nil {
			return err
		}
		id, ok := info.ID()
		if !ok {
			return fmt.Errorf("shared program %s identity unavailable", name)
		}
		programIDs = append(programIDs, id)
		ids, ok := info.MapIDs()
		if !ok {
			return fmt.Errorf("shared program %s map identities unavailable", name)
		}
		actualPrograms[name] = ids
		names = append(names, name)
	}
	if err := validateSharedProgramIDs(programIDs); err != nil {
		return err
	}
	var required, allowed []ebpf.MapID
	for name, shape := range r.manifest.Maps {
		m := r.maps[name]
		if m == nil || m.FD() < 0 || uint32(m.Type()) != shape.Type || m.KeySize() != shape.KeySize || m.ValueSize() != shape.ValueSize || m.MaxEntries() != shape.MaxEntries || m.Flags() != shape.Flags {
			return fmt.Errorf("loaded shared map %s differs from admitted shape", name)
		}
		mi, err := m.Info()
		if err != nil {
			return err
		}
		id, ok := mi.ID()
		if !ok {
			return fmt.Errorf("shared map %s identity unavailable", name)
		}
		allowed = append(allowed, id)
		if sharedProgramRequiresMap(name, fullImage) {
			required = append(required, id)
		}
	}
	if !fullImage && len(required) != len(sharedProtocolReferencedMapNames) {
		return fmt.Errorf("incomplete shared actual map identities")
	}
	return validateSharedProgramMapReferences(required, allowed, names, actualPrograms)
}

// sharedControl borrows the HOST collection. It creates only its pinned admin
// thread, never a manager, runtime, BPF map/program or attachment.
type sharedControl struct {
	resources sharedControlResources
	config    sharedNodeWire
	thread    *controlThread
	sequence  uint64                // owned only by thread jobs
	pending   *sharedPendingCommand // owned only by the same thread jobs
}

func sharedRandomIdentity() (uint64, error) {
	for range 4 {
		var raw [8]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return 0, err
		}
		v := binary.LittleEndian.Uint64(raw[:])
		if v != 0 && v != math.MaxUint64 {
			return v, nil
		}
	}
	return 0, fmt.Errorf("reserved random shared identity")
}

type sharedZeroTemplateMap interface {
	Freeze() error
	Lookup(key, valueOut interface{}) error
}

type sharedZeroTemplateSpec struct {
	name string
	size int
}

// Freeze first, then inspect: a successful check cannot race a subsequent
// userspace write. Callers must separately prove the map inventory and freeze
// before attaching any program that can consume the template.
func freezeZeroTemplates(templates map[string]sharedZeroTemplateMap, specs []sharedZeroTemplateSpec) error {
	for _, spec := range specs {
		m := templates[spec.name]
		if m == nil {
			return fmt.Errorf("missing zero template %s", spec.name)
		}
		if err := m.Freeze(); err != nil {
			return fmt.Errorf("freeze %s: %w", spec.name, err)
		}
		value := make([]byte, spec.size)
		if err := m.Lookup(uint32(0), value); err != nil {
			return err
		}
		for _, b := range value {
			if b != 0 {
				return fmt.Errorf("nonzero initialization template %s", spec.name)
			}
		}
	}
	return nil
}

func freezeSharedZeroTemplates(templates map[string]sharedZeroTemplateMap) error {
	return freezeZeroTemplates(templates, []sharedZeroTemplateSpec{
		{"se_zero_tasks", sharedTaskValueBytes},
		{"se_zero_invocations", sharedInvocationValueBytes},
		{".bss", 16},
	})
}

// Pool state maps are UAPI-readonly from creation. The two program-readable
// zero templates are different: freeze, then inspect before any attachment.
// This helper is not a product admission switch; the pool remains gated.
func freezeSharedPoolZeroTemplates(templates map[string]sharedZeroTemplateMap) error {
	return freezeZeroTemplates(templates, []sharedZeroTemplateSpec{
		{"se_pool_task_zero", 1280},
		{"se_pool_work_zero", 19456},
	})
}

func newSharedControl(ctx context.Context, profile SharedProfile, r sharedControlResources) (*sharedControl, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.manifest != nil {
		if _, recovered := r.manifest.Programs["se_rm_guardian"]; recovered {
			return nil, fmt.Errorf("recovered image requires native S, not Go control thread: %w", ErrSharedNativeUnavailable)
		}
	}
	if err := r.validate(profile); err != nil {
		return nil, err
	}
	if _, fullImage := r.manifest.Maps["se_tasks"]; fullImage {
		templates := map[string]sharedZeroTemplateMap{}
		for _, name := range []string{"se_zero_tasks", "se_zero_invocations", ".bss"} {
			if m := r.maps[name]; m != nil {
				templates[name] = m
			}
		}
		if err := freezeSharedZeroTemplates(templates); err != nil {
			return nil, err
		}
	}
	admission, err := profile.Validate()
	if err != nil {
		return nil, err
	}
	var old sharedNodeWire
	if err = r.maps["se_configuration"].Lookup(uint32(0), &old); err != nil {
		return nil, err
	}
	var receipt sharedReceiptWire
	if err = r.maps["se_receipts"].Lookup(uint32(0), &receipt); err != nil {
		return nil, err
	}
	if old != (sharedNodeWire{}) || receipt != (sharedReceiptWire{}) {
		return nil, fmt.Errorf("shared collection was already initialized")
	}
	cookie, err := sharedRandomIdentity()
	if err != nil {
		return nil, err
	}
	nonce, err := sharedRandomIdentity()
	if err != nil {
		return nil, err
	}
	c := &sharedControl{resources: r, config: sharedNodeWire{NodeCookie: cookie, Nonce: nonce, ABI: OwnerDevelopmentABI, ProfileVersion: SharedProfileVersion, Bindings: uint32(profile.Bindings), Objects: uint32(admission.PolicyObjects), Cells: uint32(admission.ArenaCells)}}
	for i, count := range profile.PolicySlots {
		c.config.Slots[i] = uint32(count)
	}
	c.thread, err = installSharedAdmin(r.maps["se_admin"], r.maps["se_configuration"], c.config)
	// Retain partial setup ownership until host collection teardown. Frozen maps
	// and dead-thread task storage are NOT proof of physical reclamation.
	if err != nil {
		return c, err
	}
	return c, ctx.Err()
}

// sharedAdminMap is the part of *ebpf.Map the admin install uses.
type sharedAdminMap interface {
	Put(key, value interface{}) error
	Freeze() error
}

// sharedAdminPidfdOpener is the unit-test seam for the admin thread's
// pidfd: a fake admin map supplies the fd its se_admin entry is keyed by, so
// commander and control tests do not depend on the host kernel providing
// PIDFD_THREAD (Linux 6.9). *ebpf.Map does not implement it, so the product
// always keys se_admin by a real PIDFD_THREAD of the admin thread.
type sharedAdminPidfdOpener interface {
	openAdminPidfd(tid int) (int, error)
}

// installSharedAdmin starts the node's single admin thread. On that locked OS
// thread it writes the thread's se_admin task-storage nonce (keyed by its own
// PIDFD_THREAD) and the node configuration, then freezes both, so exactly
// this physical thread holds command authority for the collection's
// lifetime. Shared by the protocol control (newSharedControl) and the
// product control (newSharedProductControl, G019 M4 section 2).
func installSharedAdmin(admin, configuration sharedAdminMap, config sharedNodeWire) (*controlThread, error) {
	if admin == nil || configuration == nil {
		return nil, fmt.Errorf("shared admin maps unavailable")
	}
	return startControlThread(func() error {
		open := func(tid int) (int, error) { return unix.PidfdOpen(tid, pidfdThread) }
		if opener, ok := admin.(sharedAdminPidfdOpener); ok {
			open = opener.openAdminPidfd
		}
		fd, err := open(unix.Gettid())
		if err != nil {
			return fmt.Errorf("shared admin PIDFD_THREAD: %w", err)
		}
		defer unix.Close(fd)
		if err = admin.Put(uint32(fd), config.Nonce); err != nil {
			return err
		}
		if err = admin.Freeze(); err != nil {
			return err
		}
		if err = configuration.Put(uint32(0), config); err != nil {
			return err
		}
		return configuration.Freeze()
	})
}

// sharedCommandTransport is the existing map/syscall exchange, isolated only
// so acknowledgement failures can be exercised without loading a BPF program.
type sharedCommandTransport interface {
	writeSharedCommand(sharedCommandWire) error
	runSharedCommand() (uint32, error)
	readSharedReceipt() (sharedReceiptWire, error)
}

func (r sharedControlResources) writeSharedCommand(command sharedCommandWire) error {
	return r.maps["se_commands"].Put(uint32(0), command)
}

func (r sharedControlResources) runSharedCommand() (uint32, error) {
	return r.program.Run(&ebpf.RunOptions{})
}

func (r sharedControlResources) readSharedReceipt() (sharedReceiptWire, error) {
	var receipt sharedReceiptWire
	err := r.maps["se_receipts"].Lookup(uint32(0), &receipt)
	return receipt, err
}

type sharedPendingCommand struct {
	request   sharedCommandWire
	sequence  uint64
	runResult uint32
	runKnown  bool
}

// call returns only a validated completed receipt (zero while unresolved),
// including when the joined job's context was
// canceled. A coordinator MUST classify that receipt before deciding to retry:
// a non-nil error alone does not mean the command was not executed. Resolved
// pending state is not a replay cache; blindly repeating a completed operation
// starts a NEW command. No candidate coordinator is exposed by this transport.
func (c *sharedControl) call(ctx context.Context, command sharedCommandWire) (sharedReceiptWire, error) {
	if c == nil {
		return sharedReceiptWire{}, ErrSharedNativeUnavailable
	}
	return c.callWithTransport(ctx, command, c.resources)
}

func (c *sharedControl) callWithTransport(ctx context.Context, command sharedCommandWire, transport sharedCommandTransport) (sharedReceiptWire, error) {
	var receipt sharedReceiptWire
	if c == nil || c.thread == nil {
		return receipt, ErrSharedNativeUnavailable
	}
	err := c.thread.do(ctx, func() error {
		var err error
		receipt, err = c.callCommand(command, transport)
		return err
	})
	return receipt, err
}

// sharedCommandResult is the transient execution boundary. Raw transport errors
// are returned unchanged to rich callers, or immediately reduced to source-bound
// scalar identities by private callers; it is not a retained private diagnostic.
type sharedCommandResult struct {
	receipt sharedReceiptWire
	code    sharedOutcomeCode
	err     error
}

func (r sharedCommandResult) richError() error {
	switch r.code {
	case sharedOutcomePendingConflict:
		return fmt.Errorf("shared command outcome unresolved; reconcile the original request")
	case sharedOutcomeUnsupported:
		return fmt.Errorf("unsupported shared command")
	case sharedOutcomeSequenceExhausted:
		return fmt.Errorf("shared command sequence exhausted")
	case sharedOutcomeContradictory:
		return fmt.Errorf("shared command receipt unresolved or contradictory")
	case sharedOutcomeRefused:
		return fmt.Errorf("shared command refused")
	default:
		return r.err
	}
}

func (c *sharedControl) callCommand(request sharedCommandWire, transport sharedCommandTransport) (sharedReceiptWire, error) {
	result := c.commandResult(request, transport)
	return result.receipt, result.richError()
}

// commandResult runs only inside the pinned admin thread's serialized job.
func (c *sharedControl) commandResult(request sharedCommandWire, transport sharedCommandTransport) sharedCommandResult {
	if c.pending != nil {
		// The sole kernel receipt must not be overwritten until its original
		// caller has reconciled it. Even read-only commands consume that receipt.
		if request != c.pending.request {
			return sharedCommandResult{code: sharedOutcomePendingConflict}
		}
		return c.reconcileResult(transport)
	}
	if request.Operation < 1 || request.Operation > sharedLastOperation || request.Reserved != 0 {
		return sharedCommandResult{code: sharedOutcomeUnsupported}
	}
	// No publication/withdraw opcode exists until the actual kernel boundary
	// authenticates routing, factual targets and qualification.
	if c.sequence >= math.MaxUint64-1 {
		return sharedCommandResult{code: sharedOutcomeSequenceExhausted}
	}
	c.sequence++
	command := request
	command.Sequence = c.sequence
	command.NodeCookie = c.config.NodeCookie
	command.Nonce = c.config.Nonce
	if command.Operation == sharedBindingOpen {
		command.Scope = command.Sequence
	}
	if err := transport.writeSharedCommand(command); err != nil {
		// No Run was issued: a failed input-map write cannot execute a command.
		return sharedCommandResult{code: sharedOutcomeWriteFailed, err: err}
	}
	c.pending = &sharedPendingCommand{request: request, sequence: command.Sequence}
	result, runErr := transport.runSharedCommand()
	c.pending.runResult, c.pending.runKnown = result, runErr == nil
	if runErr != nil {
		// Do not hide the syscall failure or blindly retry a non-idempotent
		// operation. The caller retries this exact request to inspect its receipt.
		return sharedCommandResult{code: sharedOutcomeRunFailed, err: runErr}
	}
	return c.reconcileResult(transport)
}

func (c *sharedControl) reconcileResult(transport sharedCommandTransport) sharedCommandResult {
	receipt, err := transport.readSharedReceipt()
	if err != nil {
		return sharedCommandResult{code: sharedOutcomeReadFailed, err: err}
	}
	p := c.pending
	if receipt.NodeCookie != c.config.NodeCookie || receipt.Sequence != p.sequence || receipt.Operation != p.request.Operation || receipt.Status > 1 || receipt.Reserved != 0 ||
		(p.runKnown && (p.runResult > 1 || (p.runResult == 0) != (receipt.Status == 0))) {
		return sharedCommandResult{code: sharedOutcomeContradictory}
	}
	// The authenticated C entry writes this exact sequence before mutation and
	// sets final status after its last access. Only that completed receipt clears
	// native ownership; an old/missing receipt intentionally leaves it pending.
	c.pending = nil
	if receipt.Status != 0 {
		return sharedCommandResult{receipt: receipt, code: sharedOutcomeRefused}
	}
	return sharedCommandResult{receipt: receipt}
}

func (c *sharedControl) close() error {
	if c == nil || c.thread == nil {
		return nil
	}
	return c.thread.close()
}
