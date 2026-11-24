// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
	"oras.land/oras-go/v2/content/memory"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
)

// TestSharedNodeM2Attached (G019 M2) loads the real shared candidate object
// through StartNode and the host gadget context (OCI image = candidate
// gadget.yaml merged with the packaged attach declaration, plus both
// diagnostic overlays when IG_SHARED_M2_DIAGNOSTIC=1 selects a diagnostic
// twin), requires exactly the qualified loader's 16 links (8 trampoline + 8
// kprobe/raw_tp/tp_btf) through the native transaction, the
// attach order task_free, then the sched_process_exit link, then task_alloc
// (Stop detaches in exact reverse; nativeattach.Rank), the product reaper
// running, Ready still unavailable, one cgroup bound to a route slot with
// live Inspect, and after StopNode no link or program of the collection left
// and the reaper joined without a fault. Isolated exact-kernel VM only.
// Policy smoke (Strict allow/deny, Audit nonblocking) is NOT exercised here:
// the product path has no route/policy installer until M0/M3; run-m2.sh runs
// TestOpaqueRealPolicyVerdictAttached on the same object for that.
func TestSharedNodeM2Attached(t *testing.T) {
	object := os.Getenv("IG_SHARED_M2_OBJECT")
	if object == "" {
		t.Skip("set IG_SHARED_M2_OBJECT on an isolated exact-kernel VM")
	}
	cgroup := os.Getenv("IG_SHARED_M2_CGROUP")
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(cgroup), "ig15-g019-m2-") {
		t.Fatal("root and a dedicated ig15-g019-m2-* cgroup required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	elf, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	// D1: no failure-frame symbols to bind.
	// IG_SHARED_M2_PROFILE selects the object's q(task, work) geometry
	// (64, 128 default, 256, 512) and IG_SHARED_M2_TOMBSTONES its tombstone
	// table (unset: the legacy 32 x TASKS of qualification objects; product
	// objects: 8192); admission refuses any other map sizes. A product
	// object (se_admin) has the product policy objects (one spare for
	// make-before-break revision), a twin the two of compile.sh.
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	profileFor := sharedCandidateProfileFor
	_, product := spec.Maps["se_admin"]
	if product {
		profileFor = sharedProductProfileFor
	}
	var profile SharedProfile
	switch quota := os.Getenv("IG_SHARED_M2_PROFILE"); quota {
	case "", "128":
		// The product's 128 profile is 128/32 (G019 burst gate: 8 streams
		// zero-gated need capacity (W-1)/2 >= 8); twins stay 128/16.
		profile = profileFor(128, 16)
		if product {
			profile = profileFor(128, 32)
		}
	case "64":
		profile = profileFor(64, 8)
	case "256":
		profile = profileFor(256, 32)
	case "512":
		profile = profileFor(512, 16)
	default:
		t.Fatalf("IG_SHARED_M2_PROFILE %q: want 64, 128, 256 or 512", quota)
	}
	if v := os.Getenv("IG_SHARED_M2_TOMBSTONES"); v != "" {
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			t.Fatalf("IG_SHARED_M2_TOMBSTONES %q: %v", v, err)
		}
		profile.ExitTombstones = n
	}
	store := memory.New()
	image, err := BuildSharedCandidateImage(t.Context(), store, elf, KernelMatrixEntry{
		Profile: profile, Diagnostic: os.Getenv("IG_SHARED_M2_DIAGNOSTIC") == "1",
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := ocihandler.New()
	params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
	if err := params.Set("verify-image", "false"); err != nil {
		t.Fatal(err)
	}
	if err := handler.Init(params); err != nil {
		t.Fatal(err)
	}
	var gc *gadgetcontext.GadgetContext
	run := func(ctx context.Context, opt gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
		ctx, cancel := context.WithCancel(ctx)
		gc = gadgetcontext.New(ctx, image, gadgetcontext.WithDataOperators(handler, New()), gadgetcontext.WithOrasReadonlyTarget(store), opt)
		done, joined := make(chan error, 1), make(chan struct{})
		go func() { err := gc.Run(nil); done <- err; close(joined) }()
		return func(ctx context.Context) error {
			cancel()
			select {
			case <-joined:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}, done, nil
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()
	node, err := StartNode(WithSharedNodeQualification(ctx, SharedNodeQualification{Run: run}),
		SharedNodeConfig{Profile: profile, ABI3Development: true, Image: image})
	if err != nil {
		t.Fatalf("StartNode: %v", err)
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = node.StopNode(context.WithoutCancel(ctx))
		}
	}()
	receipts := node.host.live.receipts
	if len(receipts) != 20 { // S1: 6 BPF LSM links + 5 tracepoint links (+ the sched_process_fork witness, the two sys_exit programs merged into one), the 7 root barrier links and the 2 mapping gate links
		t.Fatalf("receipts %d, want 15 trampoline + 5 probe links", len(receipts))
	}
	// The capsule's death retire (lsm/task_free) attaches before the capsule
	// terminal, so no capsule exists without its retire.
	capFree, capTerminal := receipts["real_owner_capsule_free"], receipts["real_owner_capsule_terminal"]
	if capFree == nil || capTerminal == nil || capFree.LinkID >= capTerminal.LinkID {
		t.Fatalf("capsule task_free link must attach before the capsule terminal: free %+v terminal %+v", capFree, capTerminal)
	}
	// Link IDs are allocated monotonically: task_free, then the exit link,
	// then task_alloc (Stop detaches in exact reverse, so exit credit never
	// runs without task_free and no allocation without its release).
	free, exit := receipts["opaque_real_owner_child_final_free_candidate"], receipts["opaque_real_owner_child_exit_candidate"]
	alloc := receipts["opaque_real_owner_child_source_candidate"]
	if free == nil || exit == nil || alloc == nil || capFree.LinkID >= exit.LinkID ||
		free.LinkID >= exit.LinkID || exit.LinkID >= alloc.LinkID {
		t.Fatalf("attach order must be task_free, sched_process_exit, task_alloc: free %+v capsule free %+v exit %+v alloc %+v",
			free, capFree, exit, alloc)
	}
	reaper := node.host.live.reaper
	if reaper == nil {
		t.Fatal("StartNode runs no product reaper")
	}
	var expected []nativeattach.Expected
	for name, r := range receipts {
		target := sharedCandidateAttachSet[name]
		if target == "" {
			target = sharedCandidateProbeSet[name]
		}
		expected = append(expected, nativeattach.Expected{Name: name, Target: target, LinkID: r.LinkID, ProgramID: r.ProgramID})
	}
	if err := nativeattach.CheckPresent(expected, nativeattach.LookupLink); err != nil {
		t.Fatalf("attach set not present: %v", err)
	}
	if err := node.Ready(gc); !errors.Is(err, ErrSharedNativeUnavailable) || strings.Contains(err.Error(), "NotReady") {
		t.Fatalf("Ready: %v", err)
	}
	t.Logf("M2: StartNode attached %d links: %v", len(receipts), expected)

	// One binding over a container-like init in the dedicated cgroup.
	initCmd := startSharedTestInit(t, cgroup, "ig15-g019-m2-init", 600)
	var st unix.Stat_t
	if err := unix.Stat(cgroup, &st); err != nil {
		t.Fatal(err)
	}
	pid := initCmd.Process.Pid
	acquire := func(context.Context) (BindingLease, error) {
		l := &sharedM2Lease{}
		var err error
		open := func(path string, flags int) *os.File {
			f, e := os.OpenFile(path, flags, 0)
			err = errors.Join(err, e)
			return f
		}
		l.proc = open(fmt.Sprintf("/proc/%d", pid), unix.O_DIRECTORY|unix.O_RDONLY)
		l.cgroup = open(cgroup, unix.O_DIRECTORY|unix.O_RDONLY)
		l.mount = open(fmt.Sprintf("/proc/%d/ns/mnt", pid), unix.O_RDONLY)
		l.hostMount = open("/proc/self/ns/mnt", unix.O_RDONLY)
		return l, err
	}
	session, err := node.Bind(ctx, SharedBindingConfig{CgroupID: st.Ino, InitHostPID: uint32(pid), Acquire: acquire})
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	status := session.Inspect()
	if status.Fault != nil || !status.Attached || !status.RouteReserved || status.Ready {
		t.Fatalf("Inspect: %+v", status)
	}
	t.Logf("M2: cgroup %d bound to route slot %d (prepared %d)", st.Ino, status.RouteSlot, status.PreparedID)

	stats, statsErr := reaper.reaper.Stats()
	if err := node.StopNode(context.WithoutCancel(ctx)); err != nil {
		t.Fatalf("StopNode: %v", err)
	}
	stopped = true
	select {
	case <-reaper.waited:
	default:
		t.Fatal("product reaper survived StopNode")
	}
	if reaper.err != nil || statsErr != nil {
		t.Fatalf("product reaper: %v (stats %v)", reaper.err, statsErr)
	}
	t.Logf("M2: product reaper %s", stats)
	// Full cleanup: no link and, after RCU, no program of the collection.
	deadline := time.Now().Add(10 * time.Second)
	for _, e := range expected {
		if _, err := nativeattach.LookupLink(e.LinkID); err == nil {
			t.Errorf("link %d (%s) survived StopNode", e.LinkID, e.Name)
		}
		for {
			p, err := ebpf.NewProgramFromID(ebpf.ProgramID(e.ProgramID))
			if err != nil {
				break
			}
			p.Close()
			if time.Now().After(deadline) {
				t.Errorf("program %d (%s) survived StopNode", e.ProgramID, e.Name)
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if s := session.Inspect(); !errors.Is(s.Fault, ErrSharedNativeUnavailable) {
		t.Fatalf("Inspect after stop: %+v", s)
	}
	t.Log("PASS: M2 StartNode 11 links (S1) (task_free, exit, task_alloc order; capsule free before terminal), product reaper, bind, live Inspect, Ready unavailable, full cleanup")
}
