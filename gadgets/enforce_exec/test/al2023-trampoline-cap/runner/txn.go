// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

// G009 steps 3 and 4 live modes. The exec candidate collection is attached
// through pkg/operators/ebpf/nativeattach, the same transaction the eBPF
// operator's native path uses (Order, CheckCapacity, Attach with reverse
// rollback, CheckPresent). Test only; not product enforcement or Ready.

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
)

// candidateAttachSet is what the qualified exec candidate loader
// (TestOpaqueRealPolicyVerdictAttached) keeps attached in steady state: the
// 8-link product shape (fullruntime sharedCandidateAttachSet), task_free 2
// (the product release and the exec capsule's death retire), task_alloc 1,
// bprm_execve 3, creds_for_exec 1, bprm_check 1. The other
// bprm_check_security programs are tail-call targets, and the two bootstrap
// programs are closed after bootstrap. The candidate object must carry
// real_owner_capsule_free (g19q/g19pkg; the G009 g25final128 objects do not).
var candidateAttachSet = []string{
	"opaque_real_owner_child_final_free_candidate", // lsm/task_free
	"real_owner_capsule_free",                      // lsm/task_free
	"opaque_real_owner_child_source_candidate",     // lsm/task_alloc
	"opaque_real_owner_failure_fexit_probe",        // fexit/bprm_execve
	"real_owner_capsule_terminal",                  // fexit/bprm_execve
	"real_owner_capsule_entry",                     // fentry/bprm_execve
	"real_owner_capsule_begin",                     // fentry/security_bprm_creds_for_exec
	"opaque_real_owner_reader_begin_probe",         // lsm/bprm_check_security
}

type family struct {
	coll  *ebpf.Collection
	specs map[string]*ebpf.ProgramSpec
	need  map[string]int
	progs map[uint32]bool // program IDs of this family
}

func loadFamily(path string, kernel *btf.Spec, names []string) (*family, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, err
	}
	selected := map[string]*ebpf.ProgramSpec{}
	need := map[string]int{}
	for _, name := range names {
		p := spec.Programs[name]
		if p == nil {
			return nil, fmt.Errorf("candidate lacks %s", name)
		}
		selected[name] = p
		if t := nativeattach.TrampolineTarget(p); t != "" {
			need[t]++
		}
	}
	spec.Programs = selected
	coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20, KernelTypes: kernel},
	})
	if err != nil {
		return nil, fmt.Errorf("loading candidate: %w", err)
	}
	f := &family{coll: coll, specs: selected, need: need, progs: map[uint32]bool{}}
	for name, prog := range coll.Programs {
		info, err := prog.Info()
		if err != nil {
			coll.Close()
			return nil, fmt.Errorf("%s info: %w", name, err)
		}
		id, _ := info.ID()
		f.progs[uint32(id)] = true
	}
	return f, nil
}

// start runs the native transaction: hint (unless skipped), ordered attach,
// reverse rollback on error.
func (f *family) start(reserve int, hint bool) ([]link.Link, []nativeattach.Expected, error) {
	if hint {
		existing, err := nativeattach.CountLinks(slices.Sorted(maps.Keys(f.need)))
		if err != nil {
			return nil, nil, err
		}
		if err := nativeattach.CheckCapacity(f.need, existing, reserve); err != nil {
			return nil, nil, err
		}
	}
	names := nativeattach.Order(f.specs)
	steps := make([]nativeattach.Step, len(names))
	for k, name := range names {
		steps[k] = nativeattach.Step{Name: name, Target: nativeattach.TrampolineTarget(f.specs[name])}
	}
	links, err := nativeattach.Attach(steps, func(k int) (link.Link, error) {
		p := f.specs[names[k]]
		if p.Type == ebpf.LSM {
			return link.AttachLSM(link.LSMOptions{Program: f.coll.Programs[names[k]]})
		}
		return link.AttachTracing(link.TracingOptions{Program: f.coll.Programs[names[k]]})
	}, func(l link.Link) { _ = l.Close() })
	if err != nil {
		return nil, nil, err
	}
	expected := make([]nativeattach.Expected, len(links))
	for k, l := range links {
		info, err := l.Info()
		if err != nil {
			nativeattach.Rollback(links, func(l link.Link) { _ = l.Close() })
			return nil, nil, err
		}
		expected[k] = nativeattach.Expected{Name: names[k], Target: steps[k].Target, LinkID: uint32(info.ID), ProgramID: uint32(info.Program)}
	}
	return links, expected, nil
}

// ours returns the live link IDs that reference one of the family's programs.
func (f *family) ours() ([]uint32, error) {
	ids, err := linkIDs()
	if err != nil {
		return nil, err
	}
	var out []uint32
	for _, id := range ids {
		program, err := nativeattach.LookupLink(id)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if f.progs[program] {
			out = append(out, id)
		}
	}
	return out, nil
}

// waitNoneOurs polls until no link of the family remains (link IDs are
// released asynchronously).
func (f *family) waitNoneOurs() error {
	deadline := time.Now().Add(10 * time.Second)
	for {
		left, err := f.ours()
		if err != nil || len(left) == 0 {
			return err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("leftover links of ours: %v", left)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

type fillers struct {
	links []link.Link
	progs []*ebpf.Program
	ids   map[uint32]uint32 // link ID -> program ID
}

func (fl *fillers) close() {
	for _, l := range fl.links {
		_ = l.Close()
	}
	for _, p := range fl.progs {
		_ = p.Close()
	}
	fl.links, fl.progs = nil, nil
}

// fill attaches fillers to trampoline until exactly free links remain.
func fill(spec *ebpf.CollectionSpec, kernel *btf.Spec, trampoline string, free int) (*fillers, error) {
	existing, err := nativeattach.CountLinks([]string{trampoline})
	if err != nil {
		return nil, err
	}
	fl := &fillers{ids: map[uint32]uint32{}}
	program, attachTo := programFEntry, trampoline
	if hook, ok := strings.CutPrefix(trampoline, "bpf_lsm_"); ok {
		program, attachTo = programLSM, hook
	}
	for n := existing[trampoline]; n < maxTrampLinks-free; n++ {
		ps := spec.Programs[program].Copy()
		ps.AttachTo = attachTo
		prog, err := ebpf.NewProgramWithOptions(ps, ebpf.ProgramOptions{KernelTypes: kernel})
		if err != nil {
			fl.close()
			return nil, err
		}
		fl.progs = append(fl.progs, prog)
		var l link.Link
		if program == programLSM {
			l, err = link.AttachLSM(link.LSMOptions{Program: prog})
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: prog})
		}
		if err != nil {
			fl.close()
			return nil, fmt.Errorf("filler %d: %w", n+1, err)
		}
		fl.links = append(fl.links, l)
		info, err := l.Info()
		if err != nil {
			fl.close()
			return nil, err
		}
		fl.ids[uint32(info.ID)] = uint32(info.Program)
	}
	return fl, nil
}

func (fl *fillers) unchanged() error {
	for id, program := range fl.ids {
		got, err := nativeattach.LookupLink(id)
		if err != nil {
			return fmt.Errorf("filler link %d: %w", id, err)
		}
		if got != program {
			return fmt.Errorf("filler link %d now on program %d, want %d", id, got, program)
		}
	}
	return nil
}

func expectCapacity(err error, target string) error {
	var capErr *nativeattach.ErrAttachCapacity
	if !errors.As(err, &capErr) || capErr.Target != target || !errors.Is(err, unix.E2BIG) {
		return fmt.Errorf("want ErrAttachCapacity on %s wrapping E2BIG, got %w", target, err)
	}
	return nil
}

// txnCase pre-fills target, starts the family and checks the refusal.
func txnCase(f *family, filler *ebpf.CollectionSpec, kernel *btf.Spec, target string, free, reserve int, hint bool) (string, error) {
	fl, err := fill(filler, kernel, target, free)
	if err != nil {
		return "", err
	}
	defer fl.close()
	links, _, err := f.start(reserve, hint)
	if err == nil {
		nativeattach.Rollback(links, func(l link.Link) { _ = l.Close() })
		return "", fmt.Errorf("transaction succeeded with %d free on %s", free, target)
	}
	if err := expectCapacity(err, target); err != nil {
		return "", err
	}
	var capErr *nativeattach.ErrAttachCapacity
	errors.As(err, &capErr)
	if err := f.waitNoneOurs(); err != nil {
		return "", err
	}
	if err := fl.unchanged(); err != nil {
		return "", err
	}
	return fmt.Sprintf("attached_then_rolled_back=%d fillers=%d err=%q", capErr.Attached, len(fl.links), err.Error()), nil
}

func liveTxn(filler *ebpf.CollectionSpec, candidate, target string, reserve int, readiness bool) error {
	release, err := kernelCheck()
	if err != nil {
		return err
	}
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return err
	}
	f, err := loadFamily(candidate, kernel, candidateAttachSet)
	if err != nil {
		return err
	}
	defer f.coll.Close()
	var needs []string
	for _, t := range slices.Sorted(maps.Keys(f.need)) {
		needs = append(needs, fmt.Sprintf("%s=%d", t, f.need[t]))
	}
	fmt.Printf("kernel %s candidate links per hook (K): %s reserve=%d\n", release, strings.Join(needs, ","), reserve)
	k := f.need[target]
	if k == 0 {
		return fmt.Errorf("candidate attaches nothing on %s", target)
	}
	if readiness {
		return liveReadiness(f, release)
	}
	// Hint: leave need+reserve-1 free, refused before any attach.
	detail, err := txnCase(f, filler, kernel, target, k+reserve-1, reserve, true)
	if err != nil {
		return fmt.Errorf("hint case: %w", err)
	}
	fmt.Printf("TXN kernel=%s case=hint target=%s %s leftover=0 fillers_unchanged=true\n", release, target, detail)
	// Authority: no hint, leave need-1 free, E2BIG mid-transaction.
	detail, err = txnCase(f, filler, kernel, target, k-1, reserve, false)
	if err != nil {
		return fmt.Errorf("authority case: %w", err)
	}
	fmt.Printf("TXN kernel=%s case=authority target=%s %s leftover=0 fillers_unchanged=true\n", release, target, detail)
	// Retry after the fillers are freed (they were closed by txnCase).
	links, expected, err := f.start(reserve, true)
	if err != nil {
		return fmt.Errorf("retry after freeing fillers: %w", err)
	}
	err = nativeattach.CheckPresent(expected, nativeattach.LookupLink)
	nativeattach.Rollback(links, func(l link.Link) { _ = l.Close() })
	if err != nil {
		return err
	}
	if err := f.waitNoneOurs(); err != nil {
		return err
	}
	fmt.Printf("TXN kernel=%s case=retry target=%s attached=%d leftover=0\n", release, target, len(links))
	fmt.Println("PASS: transactional attach; NOT product enforcement or Ready")
	return nil
}

// liveReadiness removes one published link outside the transaction's
// bookkeeping and requires CheckPresent to report NotReady naming its target.
func liveReadiness(f *family, release string) error {
	links, expected, err := f.start(nativeattach.DefaultReservePerHook, true)
	if err != nil {
		return err
	}
	defer func() { nativeattach.Rollback(links, func(l link.Link) { _ = l.Close() }) }()
	if err := nativeattach.CheckPresent(expected, nativeattach.LookupLink); err != nil {
		return fmt.Errorf("fresh transaction not ready: %w", err)
	}
	victim := slices.IndexFunc(expected, func(e nativeattach.Expected) bool { return e.Target == "bpf_lsm_bprm_check_security" })
	if victim < 0 {
		return fmt.Errorf("no bprm_check_security link")
	}
	// External detach first: BPF_LINK_DETACH through a separate FD from the ID.
	method := "BPF_LINK_DETACH"
	external, err := link.NewFromID(link.ID(expected[victim].LinkID))
	if err != nil {
		return err
	}
	detachErr := external.Detach()
	_ = external.Close()
	if detachErr != nil {
		// Tracing/LSM links may not implement detach; then the only way the
		// link goes away is that its last FD closes. Close the owning FD.
		method = fmt.Sprintf("close-owning-fd (detach: %s)", errnoName(detachErr))
		_ = links[victim].Close()
		links[victim] = nil
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		err = nativeattach.CheckPresent(expected, nativeattach.LookupLink)
		var notReady *nativeattach.ErrNotReady
		if errors.As(err, &notReady) {
			if notReady.Target != expected[victim].Target {
				return fmt.Errorf("NotReady names %s, want %s", notReady.Target, expected[victim].Target)
			}
			fmt.Printf("READY kernel=%s removed=%s method=%q state=NotReady target=%s err=%q\n", release, expected[victim].Name, method, notReady.Target, err.Error())
			break
		}
		if err != nil {
			return err
		}
		if time.Now().After(deadline) {
			// A detached link whose ID still references its program is not
			// detectable by this check; report it rather than a stale Ready.
			return fmt.Errorf("STALE: %s still present after %s", expected[victim].Name, method)
		}
		time.Sleep(100 * time.Millisecond)
	}
	nativeattach.Rollback(links, func(l link.Link) { _ = l.Close() })
	links = nil
	if err := f.waitNoneOurs(); err != nil {
		return err
	}
	fmt.Println("PASS: readiness reports NotReady on a removed link; NOT product Ready")
	return nil
}
