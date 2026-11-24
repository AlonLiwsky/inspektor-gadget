// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build !enforce_exec_shared_qualification

package fullruntime

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"oras.land/oras-go/v2/content/oci"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/common/rootbarrier"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
)

// Product attached tests (G011 pass 2, plan section 5). Product build only
// (no qualification tag): the node starts through WithSharedNodeHost, never
// the qualification seam. Root on a kernel the product gate admits.
//
//   IG_SHARED_PRODUCT_LAYOUT   OCI image layout directory holding the product
//                              images (built by the tag-only builder)
//   IG_SHARED_PRODUCT_IMAGE    the image reference of this kernel's product image
//   IG_SHARED_PRODUCT_OBJECT   the product object that image carries
//   IG_SHARED_PRODUCT_PROFILE  64, 128 (default), 256 or 512
//   IG_SHARED_PRODUCT_CGROUP_A, IG_SHARED_PRODUCT_CGROUP_B
//                              two dedicated ig-product-load-* cgroups
//   IG_SHARED_PRODUCT_FTRACE_NEG=1  required by TestSharedProductNodeFtraceNegativeAttached
//                              (it flips kernel.ftrace_enabled to 0 and back on
//                              its own node; the Ready test never touches ftrace)
//
// The unshare -m run (plan step 9) is driven by the harness through the
// child mode: IG_SHARED_PRODUCT_CHILD=1 starts the node, prints
// "PRODUCT-CHILD READY" (or "PRODUCT-CHILD REFUSED <reason>") and the
// receipt IDs, then blocks until killed, or exits with
// IG_SHARED_PRODUCT_CHILD_EXIT=1.

// sharedProductAttachedProfile is the image's profile (IG_SHARED_PRODUCT_PROFILE):
// the product q(task, work) builds, each with the burst-sized tombstone
// table of every product object.
func sharedProductAttachedProfile(t *testing.T) SharedProfile {
	t.Helper()
	v := os.Getenv("IG_SHARED_PRODUCT_PROFILE")
	if v == "" {
		v = "128"
	}
	profile, _, ok := sharedProductProfileNamed(v)
	if !ok {
		t.Fatalf("IG_SHARED_PRODUCT_PROFILE %q: want 64, 128, 256 or 512", v)
	}
	return profile
}

// sharedProductHost is the product SharedNodeHost over the read-only OCI
// layout: one gadget context per Run, through the real OCI handler and the
// eBPF operator.
func sharedProductHost(t *testing.T, layout, image string) (SharedNodeHost, func() *gadgetcontext.GadgetContext) {
	t.Helper()
	store, err := oci.NewFromFS(t.Context(), os.DirFS(layout))
	if err != nil {
		t.Fatalf("OCI layout %s: %v", layout, err)
	}
	handler := ocihandler.New()
	params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
	if err := params.Set("verify-image", "false"); err != nil {
		t.Fatal(err)
	}
	if err := handler.Init(params); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var gc *gadgetcontext.GadgetContext
	run := func(ctx context.Context, opt gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
		ctx, cancel := context.WithCancel(ctx)
		c := gadgetcontext.New(ctx, image, gadgetcontext.WithDataOperators(handler, New()), gadgetcontext.WithOrasReadonlyTarget(store), opt)
		mu.Lock()
		gc = c
		mu.Unlock()
		done, joined := make(chan error, 1), make(chan struct{})
		go func() { err := c.Run(nil); done <- err; close(joined) }()
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
	return SharedNodeHost{Run: run}, func() *gadgetcontext.GadgetContext { mu.Lock(); defer mu.Unlock(); return gc }
}

// sharedProductAttachedEnv checks the product-build preconditions and
// returns the layout, image and profile.
func sharedProductAttachedEnv(t *testing.T) (string, string, SharedProfile) {
	t.Helper()
	layout, image := os.Getenv("IG_SHARED_PRODUCT_LAYOUT"), os.Getenv("IG_SHARED_PRODUCT_IMAGE")
	if layout == "" || image == "" {
		t.Skip("set IG_SHARED_PRODUCT_LAYOUT and IG_SHARED_PRODUCT_IMAGE on a kernel the product gate admits")
	}
	if sharedQualificationBuild {
		t.Fatal("product attached test in a qualification build")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	return layout, image, sharedProductAttachedProfile(t)
}

// TestSharedProductNodeReadyAttached (plan section 5, steps 1-8): the
// product node on a kernel the product gate admits: identity, Ready with zero
// bindings, Strict deny and Audit pass-through with the per-binding
// contract, Ready under exec churn, a revision, the ftrace negative
// (opt-in), teardown without leftovers, and a SIGKILL restart.
func TestSharedProductNodeReadyAttached(t *testing.T) {
	if os.Getenv("IG_SHARED_PRODUCT_CHILD") == "1" {
		sharedProductChild(t)
		return
	}
	layout, image, profile := sharedProductAttachedEnv(t)
	cgroupA, cgroupB := os.Getenv("IG_SHARED_PRODUCT_CGROUP_A"), os.Getenv("IG_SHARED_PRODUCT_CGROUP_B")
	if !strings.HasPrefix(filepath.Base(cgroupA), "ig-product-load-") || !strings.HasPrefix(filepath.Base(cgroupB), "ig-product-load-") || cgroupA == cgroupB {
		t.Fatal("two dedicated ig-product-load-* cgroups required")
	}
	if err := checkSharedInitNamespaces(); err != nil {
		t.Fatalf("design 13.8: %v", err)
	}

	// Step 1: identity.
	id, err := SharedProductKernel()
	if err != nil {
		t.Fatalf("kernel gate: %v", err)
	}
	object, err := os.ReadFile(os.Getenv("IG_SHARED_PRODUCT_OBJECT"))
	if err != nil {
		t.Fatalf("IG_SHARED_PRODUCT_OBJECT: %v", err)
	}
	sum := sha256.Sum256(object)
	elf := hex.EncodeToString(sum[:])
	if !sharedProductObject(elf) {
		t.Fatalf("object sha256 %s is not a product ELF of this release", elf)
	}
	t.Logf("identity: release %s btf %s build-id %s elf-sha256 %s", id.Release, id.BTF, id.BuildID, elf)
	t.Logf("product-kernel-admitted: arch=%s release=%s btf=%s build-id=%s", id.Arch, id.Release, id.BTF, id.BuildID)

	// Step 2: StartNode through the product host; Ready with zero bindings.
	host, gcOf := sharedProductHost(t, layout, image)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	config := SharedNodeConfig{Profile: profile, ABI3Development: true, Image: image}
	node, err := StartNode(WithSharedNodeHost(ctx, host), config)
	if err != nil {
		t.Fatalf("StartNode: %v", err)
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = node.StopNode(context.WithoutCancel(ctx))
		}
	}()
	gc := gcOf()
	if !node.host.product || len(node.host.live.receipts) != sharedProductLinks {
		t.Fatalf("product=%v receipts=%d, want a product node with %d receipts", node.host.product, len(node.host.live.receipts), sharedProductLinks)
	}
	publisher, err := node.livePublisher(false)
	if _, product := publisher.(*sharedLiveProductPublisher); err != nil || !product {
		t.Fatalf("node publisher %T (%v), want the product publisher", publisher, err)
	}
	if err := node.Ready(gc); err != nil {
		t.Fatalf("Ready with zero bindings: %v", err)
	}
	t.Logf("product-ready: Ready nil with zero bindings; Degraded %v", node.Degraded(gc))
	expected := sharedProductExpectedLinks(node)

	// Step 3: A Strict (deny), B Audit; the per-binding contract.
	ia, ib := startSharedPipeInit(t, cgroupA, "ig-product-load-init-a"), startSharedPipeInit(t, cgroupB, "ig-product-load-init-b")
	a, err := node.Bind(ctx, SharedBindingConfig{CgroupID: ia.ino, InitHostPID: uint32(ia.cmd.Process.Pid), Acquire: ia.acquire})
	if err != nil {
		t.Fatalf("Bind A: %v", err)
	}
	b, err := node.Bind(ctx, SharedBindingConfig{CgroupID: ib.ino, InitHostPID: uint32(ib.cmd.Process.Pid), Acquire: ib.acquire})
	if err != nil {
		t.Fatalf("Bind B: %v", err)
	}
	if err := a.Inspect().Protected(1); err == nil {
		t.Fatal("unpublished binding A reported protected")
	}
	if _, err := a.Publish(ctx, SharedBindingPolicy{Source: sharedM4Policy("prod-a", "1", fullpolicy.Enforce, fullpolicy.Deny), Container: "a"}); err != nil {
		t.Fatalf("publish A: %v", err)
	}
	if _, err := b.Publish(ctx, SharedBindingPolicy{Source: sharedM4Policy("prod-b", "1", fullpolicy.Audit, fullpolicy.Deny), Container: "b"}); err != nil {
		t.Fatalf("publish B: %v", err)
	}
	for name, s := range map[string]*BindingSession{"A": a, "B": b} {
		if err := s.Inspect().Protected(1); err != nil {
			t.Fatalf("binding %s contract: %v", name, err)
		}
	}
	aVerdict, bVerdict := ia.smoke(t, ctx), ib.smoke(t, ctx)
	t.Logf("product-strict-deny A %s, product-audit B %s", aVerdict, bVerdict)
	if aVerdict != "r0=0 r1000=126" || bVerdict != "r0=0 r1000=0" {
		t.Fatalf("verdicts: A %q (want r0=0 r1000=126), B %q (want r0=0 r1000=0)", aVerdict, bVerdict)
	}
	// The root barrier on this product node (its start check passed in
	// StartNode): a root chroot in Strict A is denied by the barrier; the
	// same chroot in Audit B runs (Audit never blocks).
	chrootsBefore := sharedProductChrootDenials(t, gc)
	aChroot, _, errA := ia.run(ctx, `chroot / /bin/true; echo "chroot=$?"`)
	bChroot, _, errB := ib.run(ctx, `chroot / /bin/true; echo "chroot=$?"`)
	chroots := sharedProductChrootDenials(t, gc) - chrootsBefore
	t.Logf("product-root-barrier: A %s, B %s, barrier chroot denials +%d", strings.TrimSpace(aChroot), strings.TrimSpace(bChroot), chroots)
	if errA != nil || errB != nil || strings.TrimSpace(aChroot) == "chroot=0" || strings.TrimSpace(bChroot) != "chroot=0" || chroots != 1 {
		t.Fatalf("root barrier: A %q (%v), B %q (%v), denials +%d; want A refused, B chroot=0, one denial", aChroot, errA, bChroot, errB, chroots)
	}

	// Step 4: exec churn in B while sampling Ready and Degraded for at least
	// two fail-closed poll intervals.
	churnCtx, stopChurn := context.WithCancel(ctx)
	churned := make(chan error, 1)
	go func() {
		var err error
		for churnCtx.Err() == nil && err == nil {
			_, _, err = ib.run(churnCtx, `i=0; while [ $i -lt 200 ]; do /bin/true; i=$((i+1)); done`)
		}
		if churnCtx.Err() != nil {
			err = nil
		}
		churned <- err
	}()
	deadline := time.Now().Add(2*SharedFailClosedPollInterval + time.Second)
	samples, degradedSamples := 0, 0
	for time.Now().Before(deadline) {
		if err := node.Ready(gc); err != nil {
			stopChurn()
			t.Fatalf("product-churn-ready: Ready under churn (sample %d): %v", samples, err)
		}
		if d := node.Degraded(gc); d != nil {
			degradedSamples++
			t.Logf("churn sample %d Degraded: %v", samples, d)
		}
		samples++
		time.Sleep(100 * time.Millisecond)
	}
	stopChurn()
	if err := <-churned; err != nil {
		t.Fatalf("churn in B: %v", err)
	}
	t.Logf("product-churn-ready: %d samples Ready nil, %d Degraded", samples, degradedSamples)

	// Step 5: a revision of A (fallback allow).
	if _, err := a.Publish(ctx, SharedBindingPolicy{Source: sharedM4Policy("prod-a", "2", fullpolicy.Enforce, fullpolicy.Allow), Container: "a"}); err != nil {
		t.Fatalf("revise A: %v", err)
	}
	if err := node.Ready(gc); err != nil {
		t.Fatalf("Ready after the revision: %v", err)
	}
	if err := a.Inspect().Protected(2); err != nil {
		t.Fatalf("A contract after the revision: %v", err)
	}
	if err := b.Inspect().Protected(1); err != nil {
		t.Fatalf("B contract after A's revision: %v", err)
	}

	// Step 6, the ftrace negative, is its own test with its own node
	// (TestSharedProductNodeFtraceNegativeAttached): after an ftrace-off
	// window the node may stay Degraded until restart, so this node, which
	// must stop clean, never toggles ftrace.

	// Step 7: remove, stop, no leftovers.
	if err := a.Remove(ctx, a.Inspect().Generation); err != nil {
		t.Fatalf("Remove A: %v", err)
	}
	if err := b.Remove(ctx, b.Inspect().Generation); err != nil {
		t.Fatalf("Remove B: %v", err)
	}
	if err := node.StopNode(context.WithoutCancel(ctx)); err != nil {
		t.Fatalf("StopNode: %v", err)
	}
	stopped = true
	ia.stop()
	ib.stop()
	sharedProductRequireGone(t, expected)
	t.Log("leftover: every product link and program gone after StopNode")

	// Step 8: SIGKILL restart.
	sharedProductRestart(t, ctx, host, gcOf, config)
	t.Log("PASS: product node Ready, Strict deny, Audit, churn, revision, teardown, restart")
}

// sharedProductExpectedLinks is the node's receipts as link expectations.
func sharedProductExpectedLinks(node *NodeEnforcer) []nativeattach.Expected {
	var out []nativeattach.Expected
	for name, r := range node.host.live.receipts {
		out = append(out, nativeattach.Expected{Name: name, Target: r.Target, LinkID: r.LinkID, ProgramID: r.ProgramID})
	}
	return out
}

// sharedProductRequireGone requires every link and, after RCU, every
// program of expected to be gone.
func sharedProductRequireGone(t *testing.T, expected []nativeattach.Expected) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for _, e := range expected {
		if _, err := nativeattach.LookupLink(e.LinkID); err == nil {
			t.Errorf("link %d (%s) survived", e.LinkID, e.Name)
		}
		for {
			p, err := ebpf.NewProgramFromID(ebpf.ProgramID(e.ProgramID))
			if err != nil {
				break
			}
			p.Close()
			if time.Now().After(deadline) {
				t.Errorf("program %d (%s) survived", e.ProgramID, e.Name)
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
}

// sharedProductFtraceNegative is the ftrace window on a node whose binding
// A is on a deny policy: Ready nil and r1000=126 before; then
// kernel.ftrace_enabled=0, Ready must go NotReady naming ftrace, the same
// uid-0 and uid-1000 execs run, and it prints
//
//	product-ftrace-window: deny-policy r0=<rc> r1000=<rc> ready=<NotReady reason>
//
// An exec burst in A runs right before the toggle (its tasks' RCU-deferred
// frees can fall in the window) and another after Ready is back (exits that
// can reuse those addresses), so both outcomes below are reachable.
// The window verdict is evidence only (either outcome is recorded, never
// failed). ftrace is restored (also by a deferred restore on any failure),
// Ready must return to nil OR to a NotReady whose only fault is stale exit
// credit (sharedProductStaleOnlyCredit: frees missed while ftrace was off),
// r1000 must be 126 again, and it prints
//
//	product-ftrace-restore: r1000=<rc> ready=<nil|stale-credit>
//
// It returns whether Ready came back with stale exit credit.
func sharedProductFtraceNegative(t *testing.T, ctx context.Context, node *NodeEnforcer, gc *gadgetcontext.GadgetContext, ia *sharedPipeInit) bool {
	t.Helper()
	const path = "/proc/sys/kernel/ftrace_enabled"
	if err := node.Ready(gc); err != nil {
		t.Fatalf("product-ftrace-neg: Ready before the toggle: %v", err)
	}
	if v := ia.smoke(t, ctx); v != "r0=0 r1000=126" {
		t.Fatalf("product-ftrace-neg: deny policy before the toggle: %q, want r0=0 r1000=126", v)
	}
	restored := false
	restore := func() error {
		if restored {
			return nil
		}
		if err := os.WriteFile(path, []byte("1"), 0); err != nil {
			return fmt.Errorf("restore ftrace_enabled: %w", err)
		}
		restored = true
		return nil
	}
	defer func() {
		if err := restore(); err != nil {
			t.Errorf("product-ftrace-neg: %v", err)
		}
	}()
	const burst = `i=0; while [ $i -lt 500 ]; do /bin/true; i=$((i+1)); done`
	if _, code, err := ia.run(ctx, burst); err != nil || code != 0 {
		t.Fatalf("product-ftrace-neg: exec burst before the toggle: code %d: %v", code, err)
	}
	if err := os.WriteFile(path, []byte("0"), 0); err != nil {
		t.Fatalf("ftrace_enabled=0: %v", err)
	}
	notReady, ok := sharedProductWaitReady(ctx, node, gc, func(err error) bool {
		return errors.Is(err, ErrSharedNodeNotReady) && strings.Contains(err.Error(), "ftrace")
	})
	if !ok {
		t.Fatalf("product-ftrace-neg: Ready did not go NotReady naming ftrace: %v", notReady)
	}
	window, windowErr := ia.smokeE(ctx)
	r0, r1000 := sharedProductSmokeCodes(window)
	fmt.Printf("product-ftrace-window: deny-policy r0=%s r1000=%s ready=%s\n", r0, r1000, strings.ReplaceAll(notReady.Error(), "\n", "; "))
	// The harness keys on "product-ftrace-neg: Ready" (guest.sh).
	t.Logf("product-ftrace-neg: Ready %v; window verdicts %q (%v), evidence only", notReady, window, windowErr)
	if err := restore(); err != nil {
		t.Fatalf("product-ftrace-neg: %v", err)
	}
	// Stage 1: the kernel witness latched the silenced BPF LSM window, so
	// Ready stays NotReady until the agent restarts, even with ftrace on
	// again (tasks of the window are untracked). Its only other accepted
	// fault is stale exit credit.
	stale := false
	back, ok := sharedProductWaitReady(ctx, node, gc, func(err error) bool {
		if err == nil {
			return false
		}
		msg, found := strings.CutPrefix(err.Error(), ErrSharedNodeNotReady.Error()+": ")
		latched, staleOnly := sharedProductWitnessLatched(msg)
		stale = staleOnly
		return found && latched
	})
	if !ok {
		t.Fatalf("product-ftrace-neg: Ready after restore is not the latched kernel witness (plus stale exit credit at most): %v", back)
	}
	for i := 0; i < 3; i++ {
		if err := node.Ready(gc); !errors.Is(err, ErrSharedKernelWitness) {
			t.Fatalf("product-ftrace-neg: Ready read %d after restore: %v, want the latched kernel witness", i, err)
		}
	}
	if _, code, err := ia.run(ctx, burst); err != nil || code != 0 {
		t.Fatalf("product-ftrace-neg: exec burst after restore: code %d: %v", code, err)
	}
	after := ia.smoke(t, ctx)
	_, r1000 = sharedProductSmokeCodes(after)
	ready := "witness-latched"
	if stale {
		ready = "witness-latched+stale-credit"
	}
	fmt.Printf("product-ftrace-restore: r1000=%s ready=%s\n", r1000, ready)
	if after != "r0=0 r1000=126" {
		t.Fatalf("product-ftrace-neg: deny policy after restore: %q, want r0=0 r1000=126", after)
	}
	return stale
}

// sharedProductWitnessLatched reports whether msg (errors.Join lines) holds
// the latched kernel witness, and whether its only other lines are one
// stale-only exit credit fault; any other line refuses it.
func sharedProductWitnessLatched(msg string) (latched, stale bool) {
	for _, line := range strings.Split(msg, "\n") {
		switch {
		case strings.HasPrefix(line, ErrSharedKernelWitness.Error()):
			latched = true
		default:
			if _, only := sharedProductStaleOnlyCredit(line); !only || stale {
				return false, false
			}
			stale = true
		}
	}
	return latched, stale
}

// sharedProductStaleOnlyCredit reports whether msg is exactly one
// credit-at-exit Degraded fault (sharedLiveExitCredit.check, the
// ExitCreditVerdict format) whose only fault is stale tombstones: stale > 0,
// every other fault and refused-insert counter 0, below the high-water mark.
// It returns the stale count.
func sharedProductStaleOnlyCredit(msg string) (uint64, bool) {
	rest, ok := strings.CutPrefix(msg, "shared candidate credit at exit degraded, node degraded: ")
	if !ok || strings.Contains(rest, "\n") {
		return 0, false
	}
	values := map[string]string{}
	for _, field := range strings.Fields(rest) {
		k, v, ok := strings.Cut(field, "=")
		if _, dup := values[k]; !ok || dup {
			return 0, false
		}
		values[k] = v
	}
	if len(values) != len(exitCreditNames)+5 || values["high"] != "false" || values["degraded"] != "true" {
		return 0, false
	}
	n := map[string]uint64{}
	for _, k := range append(exitCreditNames[:], "capacity", "slow", "faults") {
		v, err := strconv.ParseUint(values[k], 10, 64)
		if err != nil {
			return 0, false
		}
		n[k] = v
	}
	for _, k := range []string{"dir-faulted", "tomb-fault", "lease-fault", "held-stuck", "unsettled-fault", "overflow", "account-overflow", "busy", "blocked", "dir-pending", "high-crossed"} {
		if n[k] != 0 {
			return 0, false
		}
	}
	if n["stale"] == 0 || n["faults"] != n["stale"] || n["slow"] != n["unsettled"] {
		return 0, false
	}
	return n["stale"], true
}

// sharedProductFreshExitCredit reads the credit-at-exit witness of e now
// against its baseline (the node's whole lifetime) and classifies it,
// ignoring the sticky fault e.check stored: a fault counted after the first
// stale reading (a lease fault, a stuck held lease, an overflow, a tombstone
// fault) is seen here even though check would keep returning the stale-only
// message. It returns "clean" (Healthy) or "stale" (Degraded with stale
// exit credit as the only fault), and an error otherwise.
func sharedProductFreshExitCredit(e *sharedLiveExitCredit) (string, error) {
	if e == nil {
		return "", errors.New("no credit-at-exit witness")
	}
	e.mu.Lock()
	read, baseline, capacity, closed := e.read, e.baseline, e.capacity, e.closed
	e.mu.Unlock()
	if closed {
		return "", errors.New("credit-at-exit witness closed")
	}
	now, readErr := read()
	v, health, err := ExitCreditCheck(baseline, now, readErr, capacity)
	switch health {
	case ExitCreditHealthy:
		return "clean", nil
	case ExitCreditDegraded:
		msg := fmt.Sprintf("shared candidate credit at exit degraded, node degraded: %s", v)
		if _, ok := sharedProductStaleOnlyCredit(msg); ok {
			return "stale", nil
		}
		return "", fmt.Errorf("fresh credit-at-exit reading has a fault other than stale: %s", v)
	}
	return "", fmt.Errorf("fresh credit-at-exit reading unknown: %w", err)
}

// TestSharedProductNodeFtraceNegativeAttached (plan section 5, step 6) runs
// the ftrace negative on its own product node: binding A (cgroup A) on a
// Strict deny policy, the ftrace window (sharedProductFtraceNegative), then
// Remove and StopNode. Stage 1: the kernel witness latches the silenced
// BPF LSM window, so Ready stays NotReady (ErrSharedKernelWitness) after
// ftrace is restored, and StopNode reports it. While ftrace was off the
// lsm/task_free trampolines also missed frees, so a later exit may find a
// tombstone of an earlier lifetime at a reused task address
// (REAL_OWNER_EXIT_STALE): credit at exit may then be Degraded too
// (accepted, fail closed). StopNode must fail with the witness and at most
// stale exit credit; anything else fails. It prints
//
//	product-ftrace-outcome: witness-latched (...)
//
// Requires IG_SHARED_PRODUCT_FTRACE_NEG=1 (it toggles kernel.ftrace_enabled).
func TestSharedProductNodeFtraceNegativeAttached(t *testing.T) {
	if os.Getenv("IG_SHARED_PRODUCT_FTRACE_NEG") != "1" {
		t.Skip("set IG_SHARED_PRODUCT_FTRACE_NEG=1 with the product env: this test toggles kernel.ftrace_enabled")
	}
	layout, image, profile := sharedProductAttachedEnv(t)
	cgroupA := os.Getenv("IG_SHARED_PRODUCT_CGROUP_A")
	if !strings.HasPrefix(filepath.Base(cgroupA), "ig-product-load-") {
		t.Fatal("a dedicated ig-product-load-* cgroup A required")
	}
	if err := checkSharedInitNamespaces(); err != nil {
		t.Fatalf("design 13.8: %v", err)
	}
	if _, err := verifySharedProductKernel(); err != nil {
		t.Fatalf("kernel gate: %v", err)
	}
	host, gcOf := sharedProductHost(t, layout, image)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()
	node, err := StartNode(WithSharedNodeHost(ctx, host), SharedNodeConfig{Profile: profile, ABI3Development: true, Image: image})
	if err != nil {
		t.Fatalf("StartNode: %v", err)
	}
	stopped := false
	defer func() {
		if !stopped {
			_ = node.StopNode(context.WithoutCancel(ctx))
		}
	}()
	gc := gcOf()
	if err := node.Ready(gc); err != nil {
		t.Fatalf("Ready with zero bindings: %v", err)
	}
	expected := sharedProductExpectedLinks(node)
	ia := startSharedPipeInit(t, cgroupA, "ig-product-load-init-f")
	a, err := node.Bind(ctx, SharedBindingConfig{CgroupID: ia.ino, InitHostPID: uint32(ia.cmd.Process.Pid), Acquire: ia.acquire})
	if err != nil {
		t.Fatalf("Bind A: %v", err)
	}
	if _, err := a.Publish(ctx, SharedBindingPolicy{Source: sharedM4Policy("prod-f", "1", fullpolicy.Enforce, fullpolicy.Deny), Container: "a"}); err != nil {
		t.Fatalf("publish A: %v", err)
	}
	if err := a.Inspect().Protected(1); err != nil {
		t.Fatalf("A contract: %v", err)
	}
	readyStale := sharedProductFtraceNegative(t, ctx, node, gc, ia)
	if err := a.Remove(ctx, a.Inspect().Generation); err != nil {
		t.Fatalf("Remove A: %v", err)
	}
	// The sticky fault never re-reads the witness once it holds the stale
	// reading, so StopNode alone could hide a later fault: classify a fresh
	// whole-lifetime reading taken after every exec, smoke and Remove.
	// Remaining limit: a fault counted inside StopNode itself, while a stale
	// fault is already stored, is covered only by StopNode's own final check
	// (the witness is closed after it); teardown runs no bound workload.
	node.mu.Lock()
	exit := node.host.live.exit
	node.mu.Unlock()
	fresh, err := sharedProductFreshExitCredit(exit)
	if err != nil {
		t.Fatalf("product-ftrace-outcome: before StopNode: %v", err)
	}
	stopErr := node.StopNode(context.WithoutCancel(ctx))
	stopped = true
	ia.stop()
	// Stage 1: StopNode reports the latched kernel witness, plus at most
	// stale exit credit.
	if stopErr == nil || !errors.Is(stopErr, ErrSharedKernelWitness) {
		t.Fatalf("product-ftrace-outcome: StopNode %v, want the latched kernel witness", stopErr)
	}
	latched, stale := sharedProductWitnessLatched(stopErr.Error())
	if !latched {
		t.Fatalf("product-ftrace-outcome: StopNode failed with more than the witness and stale exit credit: %v", stopErr)
	}
	outcome := fmt.Sprintf("witness-latched (stale exit credit %v, Ready stale %v; fresh reading before StopNode: %s)", stale, readyStale, fresh)
	sharedProductRequireGone(t, expected)
	fmt.Printf("product-ftrace-outcome: %s\n", outcome)
	t.Logf("product-ftrace-outcome: %s; every product link and program gone after StopNode", outcome)
}

// sharedProductWaitReady polls Ready (100 ms, at most 10 s) until done
// accepts its result; it returns that result and whether done accepted it.
func sharedProductWaitReady(ctx context.Context, node *NodeEnforcer, gc *gadgetcontext.GadgetContext, done func(error) bool) (error, bool) {
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := node.Ready(gc)
		if done(err) {
			return err, true
		}
		if ctx.Err() != nil || time.Now().After(deadline) {
			return err, false
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// sharedProductSmokeCodes parses "r0=<rc> r1000=<rc>" ("?" when absent).
func sharedProductSmokeCodes(out string) (string, string) {
	r0, r1000 := "?", "?"
	for _, field := range strings.Fields(out) {
		if v, ok := strings.CutPrefix(field, "r0="); ok {
			r0 = v
		} else if v, ok := strings.CutPrefix(field, "r1000="); ok {
			r1000 = v
		}
	}
	return r0, r1000
}

// sharedProductLinks is the product node's link count (S1: 6 BPF LSM + 5
// tracepoint links, the 7 root barrier links and the 2 mapping gate links;
// the restart child's check was still the pre-D1 16).
const sharedProductLinks = 20

// sharedProductChrootDenials is the root barrier's chroot denial count of the
// node's collection.
func sharedProductChrootDenials(t *testing.T, gc operators.GadgetContext) uint64 {
	t.Helper()
	value, _ := gc.GetVar(operators.MapPrefix + rootbarrier.CountersMap)
	m, _ := value.(*ebpf.Map)
	if m == nil {
		t.Fatalf("root barrier map %s not published", rootbarrier.CountersMap)
	}
	denials, err := rootbarrier.Denials(m)
	if err != nil {
		t.Fatal(err)
	}
	return denials[rootbarrier.OpChroot]
}

// sharedProductRestart starts the node in a child test process, SIGKILLs
// it, requires its links and programs gone, then starts the node again
// here: Ready nil and a publish works.
func sharedProductRestart(t *testing.T, ctx context.Context, host SharedNodeHost, gcOf func() *gadgetcontext.GadgetContext, config SharedNodeConfig) {
	t.Helper()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestSharedProductNodeReadyAttached$", "-test.count=1", "-test.timeout=5m")
	cmd.Env = append(os.Environ(), "IG_SHARED_PRODUCT_CHILD=1")
	cmd.Stderr = os.Stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var expected []nativeattach.Expected
	ready := false
	scanner := bufio.NewScanner(out)
	for !ready && scanner.Scan() {
		line := scanner.Text()
		var name string
		var link, prog uint32
		if _, err := fmt.Sscanf(line, "PRODUCT-CHILD LINK %s %d %d", &name, &link, &prog); err == nil {
			expected = append(expected, nativeattach.Expected{Name: name, LinkID: link, ProgramID: prog})
		}
		if strings.HasPrefix(line, "PRODUCT-CHILD REFUSED") {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			t.Fatalf("product-restart: child %s", line)
		}
		ready = line == "PRODUCT-CHILD READY"
	}
	if !ready || len(expected) != sharedProductLinks {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("product-restart: child ready=%v links=%d (%v)", ready, len(expected), scanner.Err())
	}
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	sharedProductRequireGone(t, expected)
	t.Logf("product-restart: SIGKILLed child left no link or program (%d receipts)", len(expected))
	node, err := StartNode(WithSharedNodeHost(ctx, host), config)
	if err != nil {
		t.Fatalf("product-restart: StartNode again: %v", err)
	}
	defer func() {
		if err := node.StopNode(context.WithoutCancel(ctx)); err != nil {
			t.Errorf("product-restart: StopNode: %v", err)
		}
	}()
	gc := gcOf()
	if err := node.Ready(gc); err != nil {
		t.Fatalf("product-restart: Ready after restart: %v", err)
	}
	ia := startSharedPipeInit(t, os.Getenv("IG_SHARED_PRODUCT_CGROUP_A"), "ig-product-load-init-r")
	a, err := node.Bind(ctx, SharedBindingConfig{CgroupID: ia.ino, InitHostPID: uint32(ia.cmd.Process.Pid), Acquire: ia.acquire})
	if err != nil {
		t.Fatalf("product-restart: Bind: %v", err)
	}
	if _, err := a.Publish(ctx, SharedBindingPolicy{Source: sharedM4Policy("prod-r", "1", fullpolicy.Enforce, fullpolicy.Deny), Container: "r"}); err != nil {
		t.Fatalf("product-restart: publish: %v", err)
	}
	if err := a.Inspect().Protected(1); err != nil {
		t.Fatalf("product-restart: contract: %v", err)
	}
	if v := ia.smoke(t, ctx); v != "r0=0 r1000=126" {
		t.Fatalf("product-restart: verdicts %q, want r0=0 r1000=126", v)
	}
	if err := a.Remove(ctx, a.Inspect().Generation); err != nil {
		t.Fatalf("product-restart: Remove: %v", err)
	}
}

// sharedProductChild is the child mode: start the node, report it, block
// (or exit with IG_SHARED_PRODUCT_CHILD_EXIT=1).
func sharedProductChild(t *testing.T) {
	layout, image, profile := sharedProductAttachedEnv(t)
	host, _ := sharedProductHost(t, layout, image)
	node, err := StartNode(WithSharedNodeHost(t.Context(), host), SharedNodeConfig{Profile: profile, ABI3Development: true, Image: image})
	if err != nil {
		fmt.Printf("PRODUCT-CHILD REFUSED %s\n", strconv.Quote(err.Error()))
		if os.Getenv("IG_SHARED_PRODUCT_CHILD_EXIT") == "1" {
			return
		}
		t.Fatal(err)
	}
	for name, r := range node.host.live.receipts {
		fmt.Printf("PRODUCT-CHILD LINK %s %d %d\n", name, r.LinkID, r.ProgramID)
	}
	fmt.Println("PRODUCT-CHILD READY")
	if os.Getenv("IG_SHARED_PRODUCT_CHILD_EXIT") == "1" {
		if err := node.StopNode(context.WithoutCancel(t.Context())); err != nil {
			t.Fatal(err)
		}
		return
	}
	<-t.Context().Done() // SIGKILLed by the parent
}

// TestSharedProductNodeNegativesAttached (plan section 5, negatives):
// every image of IG_SHARED_PRODUCT_NEG_IMAGES (comma separated references
// in IG_SHARED_PRODUCT_LAYOUT, for example the diagnostic twin) is refused
// with ErrSharedNativeUnavailable, and the qualification seam is ignored.
func TestSharedProductNodeNegativesAttached(t *testing.T) {
	layout, image, profile := sharedProductAttachedEnv(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	config := SharedNodeConfig{Profile: profile, ABI3Development: true, Image: image}
	qruns := 0
	qrun := func(context.Context, gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
		qruns++
		return func(context.Context) error { return nil }, make(chan error), nil
	}
	if _, err := StartNode(WithSharedNodeQualification(ctx, SharedNodeQualification{Run: qrun}), config); !errors.Is(err, ErrSharedNativeUnavailable) || qruns != 0 {
		t.Fatalf("product-neg-qualification: err=%v runs=%d", err, qruns)
	} else {
		t.Logf("product-neg-qualification: refused before any host run: %v", err)
	}
	for _, ref := range strings.Split(os.Getenv("IG_SHARED_PRODUCT_NEG_IMAGES"), ",") {
		if ref == "" {
			continue
		}
		host, _ := sharedProductHost(t, layout, ref)
		c := config
		c.Image = ref
		node, err := StartNode(WithSharedNodeHost(ctx, host), c)
		if err == nil {
			_ = node.StopNode(context.WithoutCancel(ctx))
			t.Fatalf("product-neg %s: started", ref)
		}
		if !errors.Is(err, ErrSharedNativeUnavailable) {
			t.Fatalf("product-neg %s: untyped refusal %v", ref, err)
		}
		t.Logf("product-neg %s: %v", ref, err)
	}
}

// TestSharedProductWitnessLatched: the stage-1 ftrace outcome classifier
// accepts the latched kernel witness, alone or with exactly one stale-only
// exit credit fault, and nothing else.
func TestSharedProductWitnessLatched(t *testing.T) {
	var stale [ExitCreditCounters]uint64
	stale[ExitCreditInserted], stale[ExitCreditSettled], stale[ExitCreditStale], stale[ExitCreditUnsettled] = 100, 100, 2, 3
	v, err := ExitCredit([ExitCreditCounters]uint64{}, stale, sharedProductExitTombstones)
	if err != nil {
		t.Fatal(err)
	}
	staleMsg := fmt.Sprintf("shared candidate credit at exit degraded, node degraded: %s", v)
	witness := fmt.Errorf("%w: kernel.ftrace_enabled was read as 0 at a syscall exit", ErrSharedKernelWitness).Error()
	for name, tc := range map[string]struct {
		msg            string
		latched, stale bool
	}{
		"witness alone":            {witness, true, false},
		"witness and stale credit": {witness + "\n" + staleMsg, true, true},
		"stale credit alone":       {staleMsg, false, true},
		"two stale lines":          {witness + "\n" + staleMsg + "\n" + staleMsg, false, false},
		"another fault":            {witness + "\nshared candidate capsule degraded", false, false},
		"empty":                    {"", false, false},
	} {
		latched, stale := sharedProductWitnessLatched(tc.msg)
		if latched != tc.latched || (tc.latched && stale != tc.stale) {
			t.Errorf("%s: latched %v stale %v, want %v %v", name, latched, stale, tc.latched, tc.stale)
		}
	}
}

// TestSharedProductStaleOnlyCredit: the ftrace outcome classifier accepts
// exactly one credit-at-exit fault whose only fault is stale tombstones.
func TestSharedProductStaleOnlyCredit(t *testing.T) {
	msg := func(after [ExitCreditCounters]uint64) string {
		v, err := ExitCredit([ExitCreditCounters]uint64{}, after, sharedProductExitTombstones)
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("shared candidate credit at exit degraded, node degraded: %s", v)
	}
	var stale [ExitCreditCounters]uint64
	stale[ExitCreditInserted], stale[ExitCreditSettled], stale[ExitCreditStale], stale[ExitCreditUnsettled] = 100, 100, 2, 3
	if n, ok := sharedProductStaleOnlyCredit(msg(stale)); !ok || n != 2 {
		t.Fatalf("stale only: %d %v", n, ok)
	}
	for name, counter := range map[string]int{"tomb fault": ExitCreditTombFault, "lease fault": ExitCreditLeaseFault, "held stuck": ExitCreditHeldStuck, "overflow": ExitCreditOverflow, "busy": ExitCreditBusy, "dir pending": ExitCreditDirPending, "high crossed": ExitCreditHighCrossed} {
		bad := stale
		bad[counter]++
		if _, ok := sharedProductStaleOnlyCredit(msg(bad)); ok {
			t.Errorf("%s accepted", name)
		}
	}
	noStale := stale
	noStale[ExitCreditStale] = 0
	noStale[ExitCreditTombFault] = 1
	if _, ok := sharedProductStaleOnlyCredit(msg(noStale)); ok {
		t.Error("a fault without stale accepted")
	}
	for name, counter := range map[string]int{"unsettled fault": ExitCreditUnsettledFault, "dir faulted": ExitCreditDirFaulted, "account overflow": ExitCreditAccountOverflow, "blocked": ExitCreditBlocked} {
		bad := stale
		bad[counter]++
		if _, ok := sharedProductStaleOnlyCredit(msg(bad)); ok {
			t.Errorf("%s accepted", name)
		}
	}
	high := stale
	high[ExitCreditLive] = sharedProductExitTombstones // at the high-water mark: high=true
	if _, ok := sharedProductStaleOnlyCredit(msg(high)); ok {
		t.Error("high=true accepted")
	}
	good := msg(stale)
	for name, m := range map[string]string{
		"joined":        good + "\nshared candidate reaper fault",
		"unknown":       "shared candidate credit at exit unknown, node degraded: unreadable",
		"other":         "shared candidate capsule degraded",
		"wrapped":       "shared node NotReady: " + good,
		"prefixed":      "x" + good,
		"duplicate key": good + " stale=2",
		"extra key":     good + " bonus=0",
		"bare token":    good + " junk",
	} {
		if _, ok := sharedProductStaleOnlyCredit(m); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

// TestSharedProductFreshExitCreditSeesLaterFaults: once check stored a
// stale-only fault it never re-reads the witness; the fresh reading the
// ftrace test classifies before StopNode does, so a lease fault counted
// after the stale reading is not hidden behind the stored message.
func TestSharedProductFreshExitCreditSeesLaterFaults(t *testing.T) {
	var now [ExitCreditCounters]uint64
	e := &sharedLiveExitCredit{capacity: sharedProductExitTombstones, read: func() ([ExitCreditCounters]uint64, error) { return now, nil }}
	if got, err := sharedProductFreshExitCredit(e); err != nil || got != "clean" {
		t.Fatalf("baseline: %q %v", got, err)
	}
	now[ExitCreditInserted], now[ExitCreditSettled], now[ExitCreditStale] = 10, 10, 1
	stored := e.check()
	if _, ok := sharedProductStaleOnlyCredit(fmt.Sprint(stored)); !ok {
		t.Fatalf("stored fault is not stale-only: %v", stored)
	}
	if got, err := sharedProductFreshExitCredit(e); err != nil || got != "stale" {
		t.Fatalf("stale reading: %q %v", got, err)
	}
	for name, counter := range map[string]int{"lease fault": ExitCreditLeaseFault, "held stuck": ExitCreditHeldStuck, "overflow": ExitCreditOverflow, "tomb fault": ExitCreditTombFault} {
		later := now
		now[counter]++
		if again := e.check(); !errors.Is(again, stored) {
			t.Fatalf("%s: check re-read the witness (%v); the seam this test guards changed", name, again)
		}
		if got, err := sharedProductFreshExitCredit(e); err == nil {
			t.Errorf("%s after the stale reading: fresh reading %q accepted", name, got)
		}
		now = later
	}
	e.close()
	if _, err := sharedProductFreshExitCredit(e); err == nil {
		t.Error("a closed witness was read")
	}
}
