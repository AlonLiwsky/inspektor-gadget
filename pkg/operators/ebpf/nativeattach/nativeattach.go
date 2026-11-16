// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Package nativeattach is the transactional attach and link readiness core of
// the eBPF operator's native-resource path (enforcement families only). It
// never runs for ordinary gadgets.
//
// Capacity model (G009, measured on the exact AL2023 6.12 and 6.18 kernels):
// every BPF trampoline accepts at most TrampolineLinkCap links, shared by the
// fentry, fexit, fmod_ret and LSM programs on it; one more attach fails with
// E2BIG. An LSM hook X uses the trampoline of the kernel function bpf_lsm_X.
//
//   - R (reserve): each family must leave R links free per trampoline for
//     third parties. Default DefaultReservePerHook = 8 of 38, so at most 30
//     are usable by enforcement families together.
//   - K (family need): the family's own per-trampoline link count from its
//     manifest; a family may use at most MaxFamilyLinksPerHook on any hook.
//
// The pre-attach capacity check is a hint only. The authority is the attach
// itself: any attach error rolls back every link of the transaction in
// reverse order, and E2BIG is reported as *ErrAttachCapacity.
package nativeattach

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	// TrampolineLinkCap is BPF_MAX_TRAMP_LINKS as measured on both exact
	// AL2023 kernels (G009 step 2): 38 links per trampoline.
	TrampolineLinkCap = 38
	// DefaultReservePerHook is R: links per trampoline left free for third
	// parties (8 of 38, about 20%, covering the 1 preexisting stock link seen
	// on file_open plus room for a few observability agents).
	DefaultReservePerHook = 8
	// MaxFamilyLinksPerHook is the documented maximum K of one family on one
	// trampoline. The exec family's qualified loader needs at most 3.
	MaxFamilyLinksPerHook = 8
)

// ErrAttachCapacity reports that a family could not attach its complete hook
// set because Target (a trampoline function, for example
// bpf_lsm_bprm_check_security) lacks capacity. Attached is the number of the
// family's links that were attached before the refusal; all of them were
// closed again. Err wraps unix.E2BIG.
type ErrAttachCapacity struct {
	Target   string
	Attached int
	Err      error
}

func (e *ErrAttachCapacity) Error() string {
	return fmt.Sprintf("attach capacity exhausted on %s (%d link(s) attached and rolled back): %v", e.Target, e.Attached, e.Err)
}

func (e *ErrAttachCapacity) Unwrap() error { return e.Err }

// ErrNotReady reports that a published link is no longer present.
type ErrNotReady struct {
	Name, Target string
	LinkID       uint32
	Err          error
}

func (e *ErrNotReady) Error() string {
	return fmt.Sprintf("NotReady: %s on %s (link %d): %v", e.Name, e.Target, e.LinkID, e.Err)
}

func (e *ErrNotReady) Unwrap() error { return e.Err }

// TrampolineTarget returns the kernel function whose trampoline p links into,
// or "" when p takes no trampoline link (tp_btf, iter, kprobe, syscall...).
func TrampolineTarget(p *ebpf.ProgramSpec) string {
	switch {
	case p.Type == ebpf.LSM && p.AttachType == ebpf.AttachLSMMac:
		return "bpf_lsm_" + p.AttachTo
	case p.Type == ebpf.Tracing && (p.AttachType == ebpf.AttachTraceFEntry ||
		p.AttachType == ebpf.AttachTraceFExit || p.AttachType == ebpf.AttachModifyReturn):
		return p.AttachTo
	}
	return ""
}

// Attach phases, lowest first. Stop and a failed transaction both detach in
// exact reverse, so every "attached before" below is also "detached after".
// Lifecycle hooks come first so that every task a later hook can see is
// already tracked: task_free first (the release and every death retire, such
// as the exec capsule's, exist before anything they release can be created
// and outlive it); then the credit-at-exit sched_process_exit tp_btf, whose
// settlement task_free consumes (G019 design section 1), so exit credit never
// runs without task_free; then task_alloc, so no allocation is recorded
// without its release. Movement, cgroup and other observer hooks come next.
// Decision hooks come last, outermost first: the bprm_execve fexit terminal
// before its fentry, then creds_for_exec, then bprm_check_security, so a
// decision never runs without its exit path.
const (
	rankTaskFree = iota
	rankTaskExit
	rankTaskAlloc
	rankMovement
	rankExecExit
	rankExecEntry
	rankCredsForExec
	rankBprmCheck
)

// Rank returns p's attach phase; see the rank constants.
func Rank(p *ebpf.ProgramSpec) int {
	if p.Type == ebpf.Tracing && p.AttachType == ebpf.AttachTraceRawTp && p.AttachTo == "sched_process_exit" {
		return rankTaskExit
	}
	switch TrampolineTarget(p) {
	case "bpf_lsm_task_free":
		return rankTaskFree
	case "bpf_lsm_task_alloc":
		return rankTaskAlloc
	case "bprm_execve":
		if p.AttachType == ebpf.AttachTraceFExit {
			return rankExecExit
		}
		return rankExecEntry
	case "security_bprm_creds_for_exec", "bpf_lsm_bprm_creds_for_exec":
		return rankCredsForExec
	case "bpf_lsm_bprm_check_security":
		return rankBprmCheck
	}
	return rankMovement
}

// Order returns the program names in deterministic attach order: by Rank,
// then by name. Detach order is its exact reverse.
func Order(programs map[string]*ebpf.ProgramSpec) []string {
	names := slices.Collect(maps.Keys(programs))
	sort.Slice(names, func(a, b int) bool {
		ra, rb := Rank(programs[names[a]]), Rank(programs[names[b]])
		if ra != rb {
			return ra < rb
		}
		return names[a] < names[b]
	})
	return names
}

// CheckCapacity is the pre-attach hint. need is the family's links per
// trampoline (K), existing the links already on each trampoline. It refuses
// when a family exceeds MaxFamilyLinksPerHook, or when fewer than
// need+reserve links are free. Targets are checked in sorted order.
func CheckCapacity(need, existing map[string]int, reserve int) error {
	if reserve < 0 || reserve+MaxFamilyLinksPerHook > TrampolineLinkCap {
		return fmt.Errorf("invalid trampoline reserve %d (0..%d)", reserve, TrampolineLinkCap-MaxFamilyLinksPerHook)
	}
	for _, target := range slices.Sorted(maps.Keys(need)) {
		n := need[target]
		if n > MaxFamilyLinksPerHook {
			return &ErrAttachCapacity{Target: target, Err: fmt.Errorf("family needs %d links, above K=%d: %w", n, MaxFamilyLinksPerHook, unix.E2BIG)}
		}
		if free := TrampolineLinkCap - existing[target]; free < n+reserve {
			return &ErrAttachCapacity{Target: target, Err: fmt.Errorf("%d of %d links free, family needs %d plus reserve %d: %w", max(free, 0), TrampolineLinkCap, n, reserve, unix.E2BIG)}
		}
	}
	return nil
}

// Step is one program of a transaction.
type Step struct {
	Name   string
	Target string // trampoline function, or the attach target otherwise
}

// Attach attaches steps in order. A nil link means the step attached nothing
// (for example a disabled program). On the first error every link this call
// attached is closed in reverse order before Attach returns. E2BIG becomes
// *ErrAttachCapacity naming the step's target. On success the returned slice
// is parallel to steps.
func Attach(steps []Step, attach func(int) (link.Link, error), closeLink func(link.Link)) ([]link.Link, error) {
	out := make([]link.Link, len(steps))
	attached := 0
	for k, step := range steps {
		l, err := attach(k)
		if err != nil {
			Rollback(out[:k], closeLink)
			if errors.Is(err, unix.E2BIG) {
				return nil, &ErrAttachCapacity{Target: step.Target, Attached: attached, Err: fmt.Errorf("attaching %s: %w", step.Name, err)}
			}
			return nil, fmt.Errorf("attaching eBPF program %q on %s: %w", step.Name, step.Target, err)
		}
		if l != nil {
			out[k] = l
			attached++
		}
	}
	return out, nil
}

// Rollback closes the non-nil links in reverse order.
func Rollback(links []link.Link, closeLink func(link.Link)) {
	for k := len(links) - 1; k >= 0; k-- {
		if links[k] != nil {
			closeLink(links[k])
		}
	}
}

// Expected is a published link: its ID must still exist and reference
// ProgramID.
type Expected struct {
	Name, Target      string
	LinkID, ProgramID uint32
}

// CheckPresent is the readiness check: every expected link must exist and
// still reference the same program. The first violation is returned as
// *ErrNotReady naming the target; a missing link is never reported Ready.
func CheckPresent(expected []Expected, lookup func(linkID uint32) (programID uint32, err error)) error {
	for _, e := range expected {
		program, err := lookup(e.LinkID)
		if err == nil && program != e.ProgramID {
			err = fmt.Errorf("link now references program %d, want %d", program, e.ProgramID)
		}
		if err != nil {
			return &ErrNotReady{Name: e.Name, Target: e.Target, LinkID: e.LinkID, Err: err}
		}
	}
	return nil
}

// LookupLink returns the program ID of the live link linkID, by ID (not
// through an owned FD).
func LookupLink(linkID uint32) (uint32, error) {
	l, err := link.NewFromID(link.ID(linkID))
	if err != nil {
		return 0, fmt.Errorf("link %d: %w", linkID, err)
	}
	defer l.Close()
	info, err := l.Info()
	if err != nil {
		return 0, fmt.Errorf("link %d info: %w", linkID, err)
	}
	return uint32(info.Program), nil
}

var trampolineAttachTypes = []ebpf.AttachType{ebpf.AttachTraceFEntry, ebpf.AttachTraceFExit, ebpf.AttachModifyReturn, ebpf.AttachLSMMac}

// CountLinks counts, for each vmlinux trampoline function in targets, the
// links currently attached to it by anyone, by walking all link IDs
// (BPF_LINK_GET_NEXT_ID) and their tracing link info. Any error is returned;
// callers fail closed.
func CountLinks(targets []string) (map[string]int, error) {
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, fmt.Errorf("loading kernel BTF: %w", err)
	}
	vmlinux, err := vmlinuxObjectID()
	if err != nil {
		return nil, err
	}
	byID := map[btf.TypeID]string{}
	for _, target := range targets {
		var fn *btf.Func
		if err := kernel.TypeByName(target, &fn); err != nil {
			return nil, fmt.Errorf("trampoline %s: %w", target, err)
		}
		id, err := kernel.TypeID(fn)
		if err != nil {
			return nil, fmt.Errorf("trampoline %s: %w", target, err)
		}
		byID[id] = target
	}
	counts := make(map[string]int, len(targets))
	it := new(link.Iterator)
	defer it.Close()
	for it.Next() {
		info, err := it.Link.Info()
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				continue
			}
			return nil, fmt.Errorf("link %d info: %w", it.ID, err)
		}
		t := info.Tracing()
		if t == nil || t.TargetObjectId != vmlinux || !slices.Contains(trampolineAttachTypes, ebpf.AttachType(t.AttachType)) {
			continue
		}
		if target, ok := byID[btf.TypeID(t.TargetBtfId)]; ok {
			counts[target]++
		}
	}
	if err := it.Err(); err != nil {
		return nil, fmt.Errorf("walking bpf links: %w", err)
	}
	return counts, nil
}

func vmlinuxObjectID() (uint32, error) {
	it := new(btf.HandleIterator)
	defer func() {
		if it.Handle != nil {
			it.Handle.Close()
		}
	}()
	for it.Next() {
		info, err := it.Handle.Info()
		if err != nil {
			return 0, fmt.Errorf("btf object %d: %w", it.ID, err)
		}
		if info.IsVmlinux() {
			return uint32(it.ID), nil
		}
	}
	if err := it.Err(); err != nil {
		return 0, fmt.Errorf("walking btf objects: %w", err)
	}
	return 0, fmt.Errorf("vmlinux btf object not found")
}
