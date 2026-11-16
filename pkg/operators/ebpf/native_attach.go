// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
)

// Test seams; production uses the attach code and the live kernel.
var (
	nativeAttachProgram = (*ebpfInstance).attachProgram
	nativeCountLinks    = nativeattach.CountLinks
	nativeLinkLookup    = nativeattach.LookupLink
)

// attachNativePrograms is the all-or-nothing attach of an admitted native
// collection:
//  1. deterministic order (nativeattach.Order: lifecycle, movement, decision);
//  2. a capacity hint (nativeattach.CheckCapacity) that refuses before any
//     attach when a trampoline lacks the family's need plus the reserve;
//  3. attach, where any error closes this instance's links in reverse order
//     and E2BIG becomes *nativeattach.ErrAttachCapacity;
//  4. receipts are published only after every link is attached.
//
// Nothing of a failed transaction remains attached or published. Rollback
// closes links only, so a program that attaches without a bpf link is refused
// before anything is attached (checkNativeLinkBased).
func (i *ebpfInstance) attachNativePrograms(gc operators.GadgetContext) error {
	names := nativeattach.Order(i.collectionSpec.Programs)
	steps := make([]nativeattach.Step, len(names))
	need := map[string]int{}
	for k, name := range names {
		p := i.collectionSpec.Programs[name]
		if err := i.checkNativeLinkBased(gc, p); err != nil {
			return err
		}
		target := nativeattach.TrampolineTarget(p)
		if target != "" && i.programAttachTarget(p) != disabledProgram {
			need[target]++
		}
		if target == "" {
			target = i.programAttachTarget(p)
		}
		steps[k] = nativeattach.Step{Name: name, Target: target}
	}
	if len(need) > 0 {
		reserve, err := nativeAttachReserve(gc)
		if err != nil {
			return err
		}
		existing, err := nativeCountLinks(slices.Sorted(maps.Keys(need)))
		if err != nil {
			return fmt.Errorf("native attach capacity check: %w", err)
		}
		if err := nativeattach.CheckCapacity(need, existing, reserve); err != nil {
			return err
		}
	}
	links, err := nativeattach.Attach(steps, func(k int) (link.Link, error) {
		name := names[k]
		p := i.collectionSpec.Programs[name]
		l, err := nativeAttachProgram(i, gc, p, i.collection.Programs[name])
		if err != nil || l == nil || !nativeNeedsLinkInfo(p) {
			return l, err
		}
		// A kprobe falls back to a linkless perf-fd ioctl attach on kernels
		// without BPF perf links; refuse it at this step (closing the perf fd
		// detaches it) instead of admitting a link the receipts cannot name.
		if info, infoErr := l.Info(); infoErr != nil || info == nil || info.ID == 0 {
			gadgets.CloseLink(l)
			return nil, fmt.Errorf("native program %q attached without a bpf link: %w", name, errors.Join(infoErr, errors.ErrUnsupported))
		}
		return l, nil
	}, func(l link.Link) { gadgets.CloseLink(l) })
	if err != nil {
		// Attachments without a bpf_link (sk_skb/sk_msg) are undone too.
		i.detachRawPrograms()
		return err
	}
	for k, l := range links {
		if l == nil {
			continue
		}
		p := i.collectionSpec.Programs[names[k]]
		err := i.registerIteratorLink(names[k], p, l)
		if err == nil {
			err = i.publishNativeAttachment(gc, names[k], p, l)
		}
		if err != nil {
			i.unpublishNativeAttachments(gc)
			nativeattach.Rollback(links, func(l link.Link) { gadgets.CloseLink(l) })
			i.detachRawPrograms()
			return err
		}
	}
	for _, l := range links {
		if l != nil {
			i.links = append(i.links, l)
		}
	}
	return nil
}

// attachNativeProgramsRetrying retries attachNativePrograms on
// *nativeattach.ErrAttachCapacity until it attaches or the gadget context is
// done: by default with nativeattach.DefaultRetry, logging each NotReady
// refusal, or with the nativeattach.Retry under operators.NativeAttachRetryKey.
// The value false opts out and returns a refusal at once. Each attempt re-runs
// the capacity hint and the whole transaction; a refused attempt leaves no
// link or receipt behind.
func (i *ebpfInstance) attachNativeProgramsRetrying(gc operators.GadgetContext) error {
	retry := nativeattach.DefaultRetry
	retry.State = func(err error) {
		if err != nil {
			gc.Logger().Warnf("native attach not ready, retrying: %v", err)
		}
	}
	if value, ok := gc.GetVar(operators.NativeAttachRetryKey); ok {
		switch v := value.(type) {
		case nativeattach.Retry:
			retry = v
		case bool:
			if v {
				return fmt.Errorf("invalid native attach retry %v", v)
			}
			return i.attachNativePrograms(gc)
		default:
			return fmt.Errorf("invalid native attach retry %T", value)
		}
	}
	return retry.Run(gc.Context(), func() error { return i.attachNativePrograms(gc) })
}

// checkNativeLinkBased refuses, fail-closed and without retry, any enabled
// program whose attach would leave a side effect that rollback cannot undo:
// uprobe/socket-filter/TC/sockmap/perf_event attachments, tracefs
// tracepoints or iterator registration. Admitted are LSM and
// fentry/fexit/tp_btf tracing links, kprobe/kretprobe perf-event links and
// raw_tp links, which the exec candidate and owner families use, syscall
// commands (never attached) and admitted recovery TEST_RUN programs (never
// attached). Only fentry/fexit/fmod_ret/LSM count against trampoline capacity
// (nativeattach.TrampolineTarget); kprobes, raw_tp and tp_btf take no
// trampoline slot.
func (i *ebpfInstance) checkNativeLinkBased(gc operators.GadgetContext, p *ebpf.ProgramSpec) error {
	if i.programAttachTarget(p) == disabledProgram {
		return nil
	}
	switch p.Type {
	case ebpf.Syscall:
		return nil
	case ebpf.LSM:
		if p.AttachType == ebpf.AttachLSMMac {
			return nil
		}
	case ebpf.Tracing:
		if strings.HasPrefix(p.SectionName, fentryPrefix) || strings.HasPrefix(p.SectionName, fexitPrefix) ||
			strings.HasPrefix(p.SectionName, tpBtfPrefix) {
			return nil
		}
	case ebpf.Kprobe:
		// kprobe/kretprobe attach through a BPF perf-event link; the linkless
		// ioctl fallback is refused after attach (nativeNeedsLinkInfo).
		// uprobe/usdt go through the uprobe tracer and stay refused.
		if strings.HasPrefix(p.SectionName, kprobePrefix) || strings.HasPrefix(p.SectionName, kretprobePrefix) {
			return nil
		}
	case ebpf.RawTracepoint:
		// link.AttachRawTracepoint creates a BPF_LINK_TYPE_RAW_TRACEPOINT link.
		return nil
	case ebpf.SchedCLS:
		recovery, err := i.nativeRecoveryTestRunProgram(gc, p)
		if err != nil {
			return err
		}
		if recovery && i.recoveryTestRunAdmitted {
			return nil
		}
	}
	return fmt.Errorf("native program %q (%s, section %q) does not attach through a bpf link; native families admit only LSM, fentry/fexit/tp_btf, kprobe/kretprobe and raw_tp links", p.Name, p.Type, p.SectionName)
}

// nativeNeedsLinkInfo reports the admitted program types whose attach path
// can fall back to a linkless attachment, so the step itself must see a bpf
// link ID. LSM/tracing links are always links; their receipt requires it too.
func nativeNeedsLinkInfo(p *ebpf.ProgramSpec) bool {
	return p.Type == ebpf.Kprobe || p.Type == ebpf.RawTracepoint
}

func nativeAttachReserve(gc operators.GadgetContext) (int, error) {
	value, ok := gc.GetVar(operators.NativeAttachReserveKey)
	if !ok {
		return nativeattach.DefaultReservePerHook, nil
	}
	reserve, ok := value.(int)
	if !ok || reserve < 0 || reserve+nativeattach.MaxFamilyLinksPerHook > nativeattach.TrampolineLinkCap {
		return 0, fmt.Errorf("invalid native attach reserve %v", value)
	}
	return reserve, nil
}

// nativeReadinessCheck extends a native receipt check: the link must still
// exist by ID and reference the same program. Any failure is a typed
// NotReady naming the target.
func nativeReadinessCheck(name, target string, info *link.Info, base func() error, lookup func(uint32) (uint32, error)) func() error {
	expected := []nativeattach.Expected{{Name: name, Target: target, LinkID: uint32(info.ID), ProgramID: uint32(info.Program)}}
	return func() error {
		if err := base(); err != nil {
			return &nativeattach.ErrNotReady{Name: name, Target: target, LinkID: uint32(info.ID), Err: err}
		}
		return nativeattach.CheckPresent(expected, lookup)
	}
}
