// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/spf13/viper"
	"golang.org/x/sys/unix"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
)

type nativeTxnTestLink struct {
	link.Link
	id     link.ID
	closed *[]string
	name   string
}

func (l *nativeTxnTestLink) Info() (*link.Info, error) {
	return &link.Info{ID: l.id, Type: link.TracingType, Program: ebpf.ProgramID(l.id + 100)}, nil
}

func (l *nativeTxnTestLink) Close() error {
	*l.closed = append(*l.closed, l.name)
	return nil
}

func nativeTxnFixture(t *testing.T, failAt string, failErr error, existing int) (*ebpfInstance, operators.GadgetContext, *[]string, *[]string, *int) {
	t.Helper()
	lsm := func(name, hook string) *ebpf.ProgramSpec {
		return &ebpf.ProgramSpec{Name: name, Type: ebpf.LSM, AttachType: ebpf.AttachLSMMac, AttachTo: hook, SectionName: "lsm/" + hook}
	}
	specs := map[string]*ebpf.ProgramSpec{
		"check": lsm("check", "bprm_check_security"),
		"alloc": lsm("alloc", "task_alloc"),
		"free":  lsm("free", "task_free"),
		"exit": {
			Name: "exit", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFExit,
			AttachTo: "bprm_execve", SectionName: "fexit/bprm_execve",
		},
		"migrate": {
			Name: "migrate", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry,
			AttachTo: "cgroup_migrate", SectionName: "fentry/cgroup_migrate",
		},
	}
	programs := map[string]*ebpf.Program{}
	for name := range specs {
		programs[name] = nil
	}
	gc := newResolverGadgetCtx(t, nil)
	i := &ebpfInstance{nativeTxn: true, collectionSpec: &ebpf.CollectionSpec{Programs: specs}, collection: &ebpf.Collection{Programs: programs}}
	var attached, closed []string
	counts := new(int)
	oldAttach, oldCount := nativeAttachProgram, nativeCountLinks
	t.Cleanup(func() { nativeAttachProgram, nativeCountLinks = oldAttach, oldCount })
	nativeCountLinks = func(targets []string) (map[string]int, error) {
		*counts++
		out := map[string]int{}
		for _, target := range targets {
			out[target] = existing
		}
		return out, nil
	}
	nativeAttachProgram = func(_ *ebpfInstance, gc operators.GadgetContext, p *ebpf.ProgramSpec, _ *ebpf.Program) (link.Link, error) {
		for name := range specs {
			if v, _ := gc.GetVar(operators.NativeAttachmentPrefix + name); v != nil {
				t.Fatalf("receipt %s published before every link was attached", name)
			}
		}
		if p.Name == failAt {
			return nil, fmt.Errorf("attach %s: %w", p.Name, failErr)
		}
		attached = append(attached, p.Name)
		return &nativeTxnTestLink{id: link.ID(len(attached)), closed: &closed, name: p.Name}, nil
	}
	return i, gc, &attached, &closed, counts
}

var nativeTxnOrder = []string{"free", "alloc", "migrate", "exit", "check"}

func TestNativeAttachOrderAndLateReceipts(t *testing.T) {
	i, gc, attached, closed, _ := nativeTxnFixture(t, "", nil, 0)
	if err := i.attachNativePrograms(gc); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(*attached, nativeTxnOrder) || len(*closed) != 0 || len(i.links) != len(nativeTxnOrder) {
		t.Fatalf("attached %v closed %v links %d", *attached, *closed, len(i.links))
	}
	for _, name := range nativeTxnOrder {
		v, _ := gc.GetVar(operators.NativeAttachmentPrefix + name)
		if r, _ := v.(*operators.NativeAttachment); r == nil || r.Check == nil {
			t.Fatalf("receipt %s missing", name)
		}
	}
}

// TestNativeStopDetachesInReverseAttachOrder: Stop closes the links in the
// exact reverse of the attach order, so every attach-order invariant also
// holds on teardown. Both task_free programs (the release and a death retire
// such as the exec capsule's) attach first and detach last; the
// sched_process_exit tp_btf attaches after task_free and detaches before it,
// so exit credit never runs without its task_free consumer; task_alloc
// detaches before both.
func TestNativeStopDetachesInReverseAttachOrder(t *testing.T) {
	i, gc, attached, closed, _ := nativeTxnFixture(t, "", nil, 0)
	i.collectionSpec.Programs["texit"] = &ebpf.ProgramSpec{
		Name: "texit", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceRawTp,
		AttachTo: "sched_process_exit", SectionName: "tp_btf/sched_process_exit",
	}
	i.collectionSpec.Programs["capfree"] = &ebpf.ProgramSpec{
		Name: "capfree", Type: ebpf.LSM, AttachType: ebpf.AttachLSMMac,
		AttachTo: "task_free", SectionName: "lsm/task_free",
	}
	i.collection.Programs["texit"] = nil
	i.collection.Programs["capfree"] = nil
	if err := i.attachNativePrograms(gc); err != nil {
		t.Fatal(err)
	}
	want := []string{"capfree", "free", "texit", "alloc", "migrate", "exit", "check"}
	if !reflect.DeepEqual(*attached, want) {
		t.Fatalf("attached %v, want %v", *attached, want)
	}
	if err := i.Stop(gc); err != nil {
		t.Fatal(err)
	}
	reverse := slices.Clone(want)
	slices.Reverse(reverse)
	if !reflect.DeepEqual(*closed, reverse) || len(i.links) != 0 {
		t.Fatalf("Stop closed %v, want reverse %v", *closed, reverse)
	}
	// A second Stop (Close after Stop) closes nothing again.
	if err := i.Stop(gc); err != nil || len(*closed) != len(want) {
		t.Fatalf("second Stop: err=%v closed %v", err, *closed)
	}
}

func TestNativeAttachRollbackAtEachPosition(t *testing.T) {
	for n, failAt := range nativeTxnOrder {
		t.Run(failAt, func(t *testing.T) {
			i, gc, attached, closed, _ := nativeTxnFixture(t, failAt, unix.E2BIG, 0)
			err := i.attachNativePrograms(gc)
			var capErr *nativeattach.ErrAttachCapacity
			if !errors.As(err, &capErr) || !errors.Is(err, unix.E2BIG) || capErr.Attached != n {
				t.Fatalf("want ErrAttachCapacity after %d links, got %v", n, err)
			}
			wantTarget := nativeattach.TrampolineTarget(i.collectionSpec.Programs[failAt])
			if capErr.Target != wantTarget {
				t.Fatalf("target %q, want %q", capErr.Target, wantTarget)
			}
			want := []string{}
			for k := n - 1; k >= 0; k-- {
				want = append(want, nativeTxnOrder[k])
			}
			if !slices.Equal(*attached, nativeTxnOrder[:n]) || !slices.Equal(*closed, want) {
				t.Fatalf("attached %v closed %v, want reverse %v", *attached, *closed, want)
			}
			if len(i.links) != 0 || len(i.nativeAttachments) != 0 {
				t.Fatal("failed transaction left links or receipts")
			}
			for _, name := range nativeTxnOrder {
				if v, _ := gc.GetVar(operators.NativeAttachmentPrefix + name); v != nil {
					t.Fatalf("receipt %s published", name)
				}
			}
		})
	}
	i, gc, _, closed, _ := nativeTxnFixture(t, "check", unix.EINVAL, 0)
	var capErr *nativeattach.ErrAttachCapacity
	if err := i.attachNativePrograms(gc); err == nil || errors.As(err, &capErr) || len(*closed) != 4 {
		t.Fatalf("non-capacity failure: %v closed %v", err, *closed)
	}
}

func TestNativeAttachCapacityHintRefusesBeforeAttach(t *testing.T) {
	// One link short of need (1) plus the default reserve on every target.
	i, gc, attached, _, counts := nativeTxnFixture(t, "", nil, nativeattach.TrampolineLinkCap-nativeattach.DefaultReservePerHook)
	err := i.attachNativePrograms(gc)
	var capErr *nativeattach.ErrAttachCapacity
	if !errors.As(err, &capErr) || capErr.Attached != 0 || !errors.Is(err, unix.E2BIG) || *counts != 1 || len(*attached) != 0 {
		t.Fatalf("hint did not refuse before attach: %v attached %v", err, *attached)
	}
	i, gc, attached, _, _ = nativeTxnFixture(t, "", nil, nativeattach.TrampolineLinkCap-nativeattach.DefaultReservePerHook)
	gc.SetVar(operators.NativeAttachReserveKey, 7)
	if err := i.attachNativePrograms(gc); err != nil || len(*attached) != len(nativeTxnOrder) {
		t.Fatalf("configured reserve ignored: %v", err)
	}
	i, gc, attached, _, _ = nativeTxnFixture(t, "", nil, 0)
	gc.SetVar(operators.NativeAttachReserveKey, "8")
	if err := i.attachNativePrograms(gc); err == nil || len(*attached) != 0 {
		t.Fatal("invalid reserve accepted")
	}
}

func TestNativeReceiptReadinessNamesTarget(t *testing.T) {
	i, gc, _, _, _ := nativeTxnFixture(t, "", nil, 0)
	old := nativeLinkLookup
	t.Cleanup(func() { nativeLinkLookup = old })
	gone := link.ID(0)
	nativeLinkLookup = func(id uint32) (uint32, error) {
		if link.ID(id) == gone {
			return 0, unix.ENOENT
		}
		return id + 100, nil
	}
	if err := i.attachNativePrograms(gc); err != nil {
		t.Fatal(err)
	}
	v, _ := gc.GetVar(operators.NativeAttachmentPrefix + "check")
	receipt := v.(*operators.NativeAttachment)
	if err := receipt.Check(); err != nil {
		t.Fatal(err)
	}
	gone = link.ID(receipt.LinkID)
	var notReady *nativeattach.ErrNotReady
	if err := receipt.Check(); !errors.As(err, &notReady) || notReady.Target != "bprm_check_security" || !errors.Is(err, unix.ENOENT) {
		t.Fatalf("missing link reported as %v", err)
	}
}

func TestOrdinaryGadgetsSkipNativeTransaction(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	i := &ebpfInstance{collectionSpec: &ebpf.CollectionSpec{}}
	if err := i.validateNativeResources(gc); err != nil || i.nativeTxn {
		t.Fatalf("ordinary gadget entered the native path: %v", err)
	}
	// Ordinary receipts stay optional: an Info failure is not an error.
	spec := &ebpf.ProgramSpec{Name: "hook", Type: ebpf.LSM, AttachTo: "task_alloc"}
	if err := i.publishNativeAttachment(gc, "hook", spec, nativeInfoErrLink{}); err != nil || len(i.nativeAttachments) != 0 {
		t.Fatalf("ordinary optional receipt changed: %v", err)
	}
	i.nativeTxn = true
	if err := i.publishNativeAttachment(gc, "hook", spec, nativeInfoErrLink{}); err == nil {
		t.Fatal("native receipt silently skipped")
	}
}

// TestNativeAttachRetryNoLeakAcrossAttempts: attempt 1 is refused by the hint,
// attempt 2 by E2BIG mid-transaction, attempt 3 attaches. Between attempts
// the family is NotReady naming the target, with no link or receipt of ours.
func TestNativeAttachRetryNoLeakAcrossAttempts(t *testing.T) {
	i, gc, attached, closed, counts := nativeTxnFixture(t, "", nil, 0)
	full := nativeattach.TrampolineLinkCap - nativeattach.DefaultReservePerHook
	countLinks := nativeCountLinks
	nativeCountLinks = func(targets []string) (map[string]int, error) {
		out, err := countLinks(targets)
		if *counts == 1 {
			out["bpf_lsm_task_alloc"] = full // hint refusal
		}
		return out, err
	}
	attach := nativeAttachProgram
	nativeAttachProgram = func(i *ebpfInstance, gc operators.GadgetContext, p *ebpf.ProgramSpec, prog *ebpf.Program) (link.Link, error) {
		if *counts == 2 && p.Name == "exit" {
			return nil, fmt.Errorf("attach exit: %w", unix.E2BIG) // authority refusal
		}
		return attach(i, gc, p, prog)
	}
	var states []error
	gc.SetVar(operators.NativeAttachRetryKey, nativeattach.Retry{
		Initial: time.Millisecond, Max: 2 * time.Millisecond,
		State: func(err error) {
			states = append(states, err)
			if err == nil {
				return
			}
			if len(i.links) != 0 || len(i.nativeAttachments) != 0 || len(*attached) != len(*closed) {
				t.Fatalf("partial hook set while NotReady: links %d receipts %d attached %v closed %v",
					len(i.links), len(i.nativeAttachments), *attached, *closed)
			}
		},
	})
	if err := i.attachNativeProgramsRetrying(gc); err != nil {
		t.Fatal(err)
	}
	if *counts != 3 || len(states) != 3 || states[2] != nil {
		t.Fatalf("attempts %d states %v", *counts, states)
	}
	for k, want := range []string{"bpf_lsm_task_alloc", "bprm_execve"} {
		var capErr *nativeattach.ErrAttachCapacity
		if !errors.As(states[k], &capErr) || capErr.Target != want {
			t.Fatalf("NotReady %d: %v, want target %s", k, states[k], want)
		}
	}
	// Every link of a refused attempt was closed; exactly one full set is open.
	if len(*attached)-len(*closed) != len(nativeTxnOrder) || len(i.links) != len(nativeTxnOrder) ||
		!slices.Equal((*attached)[len(*attached)-len(nativeTxnOrder):], nativeTxnOrder) {
		t.Fatalf("attached %v closed %v links %d", *attached, *closed, len(i.links))
	}
}

func TestNativeAttachRetryStopsOnCancel(t *testing.T) {
	i, _, attached, closed, counts := nativeTxnFixture(t, "", nil, nativeattach.TrampolineLinkCap)
	ctx, cancel := context.WithCancel(context.Background())
	gc := gadgetcontext.New(ctx, "test")
	var states []error
	gc.SetVar(operators.NativeAttachRetryKey, nativeattach.Retry{
		Initial: time.Millisecond, Max: time.Millisecond,
		State: func(err error) {
			states = append(states, err)
			if len(states) == 3 {
				cancel()
			}
		},
	})
	err := i.attachNativeProgramsRetrying(gc)
	var capErr *nativeattach.ErrAttachCapacity
	if !errors.Is(err, context.Canceled) || !errors.As(err, &capErr) || *counts != 3 {
		t.Fatalf("err %v after %d attempts", err, *counts)
	}
	if slices.Contains(states, nil) || len(*attached) != 0 || len(*closed) != 0 || len(i.links) != 0 {
		t.Fatalf("canceled retry attached: states %v attached %v", states, *attached)
	}
	// The explicit opt-out (the legacy Owner's) returns a refusal at once.
	i, gc2, _, _, counts := nativeTxnFixture(t, "", nil, nativeattach.TrampolineLinkCap)
	gc2.SetVar(operators.NativeAttachRetryKey, false)
	if err := i.attachNativeProgramsRetrying(gc2); !errors.As(err, &capErr) || *counts != 1 {
		t.Fatalf("retry opt-out: %v after %d attempts", err, *counts)
	}
	for _, bad := range []any{"yes", true} {
		gc2.SetVar(operators.NativeAttachRetryKey, bad)
		if err := i.attachNativeProgramsRetrying(gc2); err == nil || *counts != 1 {
			t.Fatalf("invalid retry value %v accepted", bad)
		}
	}
}

// TestNativeAttachRetryIsDefault: without the key a native family retries
// with nativeattach.DefaultRetry (500ms doubling to 30s) until capacity frees,
// and stops when the gadget context is done.
func TestNativeAttachRetryIsDefault(t *testing.T) {
	if nativeattach.DefaultRetry.Initial != 500*time.Millisecond || nativeattach.DefaultRetry.Max != 30*time.Second ||
		nativeattach.DefaultRetry.MaxAttempts != 0 {
		t.Fatalf("default retry %+v", nativeattach.DefaultRetry)
	}
	i, gc, attached, _, counts := nativeTxnFixture(t, "", nil, 0)
	countLinks := nativeCountLinks
	nativeCountLinks = func(targets []string) (map[string]int, error) {
		out, err := countLinks(targets)
		if *counts == 1 {
			out["bprm_execve"] = nativeattach.TrampolineLinkCap
		}
		return out, err
	}
	start := time.Now()
	if err := i.attachNativeProgramsRetrying(gc); err != nil {
		t.Fatal(err)
	}
	if *counts != 2 || len(i.links) != len(nativeTxnOrder) || len(*attached) != len(nativeTxnOrder) {
		t.Fatalf("default retry: %d attempts, links %d", *counts, len(i.links))
	}
	if d := time.Since(start); d < nativeattach.DefaultRetry.Initial {
		t.Fatalf("retried after %v, before the default initial backoff", d)
	}
	i, _, _, _, counts = nativeTxnFixture(t, "", nil, nativeattach.TrampolineLinkCap)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var capErr *nativeattach.ErrAttachCapacity
	if err := i.attachNativeProgramsRetrying(gadgetcontext.New(ctx, "test")); !errors.Is(err, context.DeadlineExceeded) ||
		!errors.As(err, &capErr) || *counts != 1 || len(i.links) != 0 {
		t.Fatalf("default retry not canceled: %v after %d attempts", err, *counts)
	}
}

type nativeInfoFailLink struct{ *nativeTxnTestLink }

func (nativeInfoFailLink) Info() (*link.Info, error) { return nil, errors.ErrUnsupported }

// TestNativeAttachPublishFailureRollsBack: every link attached, but the
// second link's receipt cannot be built. All links close in reverse order,
// no receipt remains and nothing is kept.
func TestNativeAttachPublishFailureRollsBack(t *testing.T) {
	i, gc, attached, closed, _ := nativeTxnFixture(t, "", nil, 0)
	attach := nativeAttachProgram
	nativeAttachProgram = func(i *ebpfInstance, gc operators.GadgetContext, p *ebpf.ProgramSpec, prog *ebpf.Program) (link.Link, error) {
		l, err := attach(i, gc, p, prog)
		if err == nil && p.Name == nativeTxnOrder[1] {
			l = nativeInfoFailLink{l.(*nativeTxnTestLink)}
		}
		return l, err
	}
	err := i.attachNativePrograms(gc)
	var capErr *nativeattach.ErrAttachCapacity
	if err == nil || !errors.Is(err, errors.ErrUnsupported) || errors.As(err, &capErr) {
		t.Fatalf("publish failure: %v", err)
	}
	want := slices.Clone(nativeTxnOrder)
	slices.Reverse(want)
	if !slices.Equal(*attached, nativeTxnOrder) || !slices.Equal(*closed, want) {
		t.Fatalf("attached %v closed %v, want reverse %v", *attached, *closed, want)
	}
	if len(i.links) != 0 || len(i.nativeAttachments) != 0 {
		t.Fatalf("links %d receipts %d remain", len(i.links), len(i.nativeAttachments))
	}
	for _, name := range nativeTxnOrder {
		if v, _ := gc.GetVar(operators.NativeAttachmentPrefix + name); v != nil {
			t.Fatalf("receipt %s remains", name)
		}
	}
}

// TestNativeAttachCountFailureRefusesWithoutRetry: a failed link count is a
// fail-closed, non-capacity refusal before any attach, so it is not retried.
func TestNativeAttachCountFailureRefusesWithoutRetry(t *testing.T) {
	i, gc, attached, _, counts := nativeTxnFixture(t, "", nil, 0)
	nativeCountLinks = func([]string) (map[string]int, error) {
		*counts++
		return nil, unix.EPERM
	}
	err := i.attachNativeProgramsRetrying(gc)
	var capErr *nativeattach.ErrAttachCapacity
	if !errors.Is(err, unix.EPERM) || errors.As(err, &capErr) || *counts != 1 || len(*attached) != 0 || len(i.links) != 0 {
		t.Fatalf("count failure: %v after %d attempts, attached %v", err, *counts, *attached)
	}
}

// TestNativeAttachRejectsLinklessPrograms: rollback closes links only, so a
// native family refuses, before any attach and without retry, a program that
// would attach without a bpf link. Disabled programs are not attached.
func TestNativeAttachRejectsLinklessPrograms(t *testing.T) {
	for name, spec := range map[string]*ebpf.ProgramSpec{
		"uprobe":  {Type: ebpf.Kprobe, SectionName: "uprobe/libc:malloc", AttachTo: "libc:malloc"},
		"socket":  {Type: ebpf.SocketFilter, SectionName: "socket"},
		"perf":    {Type: ebpf.PerfEvent, SectionName: "perf_event/x"},
		"tc":      {Type: ebpf.SchedCLS, SectionName: "classifier"},
		"sk_skb":  {Type: ebpf.SkSKB, SectionName: "sk_skb/stream_verdict"},
		"iter":    {Type: ebpf.Tracing, AttachType: ebpf.AttachTraceIter, SectionName: "iter/task", AttachTo: "task"},
		"lsm_cg":  {Type: ebpf.LSM, AttachType: ebpf.AttachLSMCgroup, SectionName: "lsm_cgroup/bprm_check_security"},
		"tracept": {Type: ebpf.TracePoint, SectionName: "tracepoint/sched/sched_process_exec", AttachTo: "sched/sched_process_exec"},
	} {
		t.Run(name, func(t *testing.T) {
			i, gc, attached, _, counts := nativeTxnFixture(t, "", nil, 0)
			spec.Name = "extra"
			i.collectionSpec.Programs["extra"] = spec
			i.collection.Programs["extra"] = nil
			err := i.attachNativeProgramsRetrying(gc)
			var capErr *nativeattach.ErrAttachCapacity
			if err == nil || errors.As(err, &capErr) || *counts != 0 || len(*attached) != 0 || len(i.links) != 0 {
				t.Fatalf("linkless %s: %v, %d counts, attached %v", name, err, *counts, *attached)
			}
		})
	}
	i, gc, attached, _, _ := nativeTxnFixture(t, "", nil, 0)
	i.collectionSpec.Programs["extra"] = &ebpf.ProgramSpec{Name: "extra", Type: ebpf.Kprobe, SectionName: "kprobe/do_exit"}
	i.collection.Programs["extra"] = nil
	i.config = viper.New()
	i.config.Set("programs.extra.attach_to", disabledProgram)
	nativeAttachProgram = func(_ *ebpfInstance, _ operators.GadgetContext, p *ebpf.ProgramSpec, _ *ebpf.Program) (link.Link, error) {
		if p.Name == "extra" {
			return nil, nil
		}
		*attached = append(*attached, p.Name)
		return &nativeTxnTestLink{id: link.ID(len(*attached)), closed: new([]string), name: p.Name}, nil
	}
	if err := i.attachNativePrograms(gc); err != nil || len(*attached) != len(nativeTxnOrder) {
		t.Fatalf("disabled linkless program refused: %v", err)
	}
}

type nativeInfoErrLink struct{ link.Link }

func (nativeInfoErrLink) Info() (*link.Info, error) { return nil, errors.ErrUnsupported }

type nativeIoctlTestLink struct{ *nativeTxnTestLink }

func (nativeIoctlTestLink) Info() (*link.Info, error) {
	return nil, fmt.Errorf("perf event ioctl info: %w", link.ErrNotSupported)
}

// TestNativeAttachAdmitsLinkBasedProbes: kprobe/kretprobe and raw_tp attach
// through bpf links, are receipted, and take no trampoline capacity. A kprobe
// that falls back to a linkless perf-fd ioctl attach is refused at its step
// and the whole transaction rolls back.
func TestNativeAttachAdmitsLinkBasedProbes(t *testing.T) {
	probes := map[string]*ebpf.ProgramSpec{
		"kp":  {Name: "kp", Type: ebpf.Kprobe, SectionName: "kprobe/search_binary_handler", AttachTo: "search_binary_handler"},
		"krp": {Name: "krp", Type: ebpf.Kprobe, SectionName: "kretprobe/search_binary_handler", AttachTo: "search_binary_handler"},
		"rtp": {Name: "rtp", Type: ebpf.RawTracepoint, SectionName: "raw_tp/sched_process_fork", AttachTo: "sched_process_fork"},
		"tpb": {Name: "tpb", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceRawTp, SectionName: "tp_btf/sched_process_exec", AttachTo: "sched_process_exec"},
	}
	i, gc, attached, _, _ := nativeTxnFixture(t, "", nil, 0)
	var counted []string
	nativeCountLinks = func(targets []string) (map[string]int, error) {
		counted = append(counted, targets...)
		return map[string]int{}, nil
	}
	for name, p := range probes {
		i.collectionSpec.Programs[name] = p
		i.collection.Programs[name] = nil
	}
	if err := i.attachNativePrograms(gc); err != nil {
		t.Fatal(err)
	}
	if len(*attached) != len(nativeTxnOrder)+len(probes) || len(i.links) != len(*attached) {
		t.Fatalf("attached %v", *attached)
	}
	for name := range probes {
		if slices.Contains(counted, probes[name].AttachTo) {
			t.Errorf("%s counted against trampoline capacity: %v", name, counted)
		}
		if v, _ := gc.GetVar(operators.NativeAttachmentPrefix + name); v == nil {
			t.Errorf("no receipt for %s", name)
		}
	}

	i, gc, attached, closed, _ := nativeTxnFixture(t, "", nil, 0)
	i.collectionSpec.Programs["kp"] = probes["kp"]
	i.collection.Programs["kp"] = nil
	attach := nativeAttachProgram
	nativeAttachProgram = func(i *ebpfInstance, gc operators.GadgetContext, p *ebpf.ProgramSpec, prog *ebpf.Program) (link.Link, error) {
		l, err := attach(i, gc, p, prog)
		if err == nil && p.Name == "kp" {
			l = nativeIoctlTestLink{l.(*nativeTxnTestLink)}
		}
		return l, err
	}
	err := i.attachNativePrograms(gc)
	if err == nil || !errors.Is(err, errors.ErrUnsupported) || !strings.Contains(err.Error(), "without a bpf link") {
		t.Fatalf("linkless kprobe fallback admitted: %v", err)
	}
	if len(*closed) != len(*attached) || len(i.links) != 0 || len(i.nativeAttachments) != 0 {
		t.Fatalf("fallback left state: attached %v closed %v", *attached, *closed)
	}
}
