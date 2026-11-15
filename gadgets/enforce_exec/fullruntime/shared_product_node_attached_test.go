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

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
)

// Product attached tests (G011 pass 2, plan section 5). Product build only
// (no qualification tag): the node starts through WithSharedNodeHost, never
// the qualification seam. Root on an exact pinned kernel build only.
//
//   IG_SHARED_PRODUCT_LAYOUT   OCI image layout directory holding the product
//                              images (built by the tag-only builder)
//   IG_SHARED_PRODUCT_IMAGE    the image reference of this kernel's product image
//   IG_SHARED_PRODUCT_OBJECT   the product object that image carries
//   IG_SHARED_PRODUCT_PROFILE  64, 128 (default), 256 or 512
//   IG_SHARED_PRODUCT_CGROUP_A, IG_SHARED_PRODUCT_CGROUP_B
//                              two dedicated ig15-g011-prod-* cgroups
//   IG_SHARED_PRODUCT_FTRACE_NEG=1  run the ftrace negative (flips
//                              kernel.ftrace_enabled to 0 and back)
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
	var profile SharedProfile
	switch v := os.Getenv("IG_SHARED_PRODUCT_PROFILE"); v {
	case "", "128":
		profile = sharedProductProfileFor(128, 32)
	case "64":
		profile = sharedProductProfileFor(64, 8)
	case "256":
		profile = sharedProductProfileFor(256, 32)
	case "512":
		profile = sharedProductProfileFor(512, 16)
	default:
		t.Fatalf("IG_SHARED_PRODUCT_PROFILE %q: want 64, 128, 256 or 512", v)
	}
	profile.ExitTombstones = sharedProductExitTombstones
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
		t.Skip("set IG_SHARED_PRODUCT_LAYOUT and IG_SHARED_PRODUCT_IMAGE on an exact pinned kernel")
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
// product node on an exact pinned kernel build: identity, Ready with zero
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
	if !strings.HasPrefix(filepath.Base(cgroupA), "ig15-g011-prod-") || !strings.HasPrefix(filepath.Base(cgroupB), "ig15-g011-prod-") || cgroupA == cgroupB {
		t.Fatal("two dedicated ig15-g011-prod-* cgroups required")
	}
	if err := checkSharedInitNamespaces(); err != nil {
		t.Fatalf("design 13.8: %v", err)
	}

	// Step 1: identity.
	digest, pin, err := verifySharedProductKernel()
	if err != nil {
		t.Fatalf("kernel gate: %v", err)
	}
	object, err := os.ReadFile(os.Getenv("IG_SHARED_PRODUCT_OBJECT"))
	if err != nil {
		t.Fatalf("IG_SHARED_PRODUCT_OBJECT: %v", err)
	}
	sum := sha256.Sum256(object)
	elf := hex.EncodeToString(sum[:])
	if _, ok := pin.ProductELF[elf]; !ok {
		t.Fatalf("object sha256 %s is not a product ELF of %s", elf, pin.Release)
	}
	t.Logf("identity: release %s btf %s build-id %s elf-sha256 %s", pin.Release, digest, pin.BuildID, elf)

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
	if !node.host.product || len(node.host.live.receipts) != 16 {
		t.Fatalf("product=%v receipts=%d, want a product node with 16 receipts", node.host.product, len(node.host.live.receipts))
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
	ia, ib := startSharedPipeInit(t, cgroupA, "ig15-g011-prod-init-a"), startSharedPipeInit(t, cgroupB, "ig15-g011-prod-init-b")
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

	// Step 6 (opt-in): the ftrace negative.
	if os.Getenv("IG_SHARED_PRODUCT_FTRACE_NEG") == "1" {
		sharedProductFtraceNegative(t, ctx, node, gc, ia)
	}

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

// sharedProductFtraceNegative flips kernel.ftrace_enabled to 0: Ready must
// fail; restored to 1, Ready is nil again. The exec verdicts inside the
// window are recorded as evidence only.
func sharedProductFtraceNegative(t *testing.T, ctx context.Context, node *NodeEnforcer, gc *gadgetcontext.GadgetContext, ia *sharedPipeInit) {
	t.Helper()
	const path = "/proc/sys/kernel/ftrace_enabled"
	restore := func() {
		if err := os.WriteFile(path, []byte("1"), 0); err != nil {
			t.Errorf("restore ftrace_enabled: %v", err)
		}
	}
	if err := os.WriteFile(path, []byte("0"), 0); err != nil {
		t.Fatalf("ftrace_enabled=0: %v", err)
	}
	err := node.Ready(gc)
	verdict, verdictErr := ia.smokeE(ctx)
	restore()
	if !errors.Is(err, ErrSharedNodeNotReady) || !strings.Contains(err.Error(), "ftrace") {
		t.Fatalf("product-ftrace-neg: Ready with ftrace off: %v", err)
	}
	t.Logf("product-ftrace-neg: Ready %v; A verdicts in the window %q (%v), evidence only", err, verdict, verdictErr)
	if err := node.Ready(gc); err != nil {
		t.Fatalf("product-ftrace-neg: Ready after restore: %v", err)
	}
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
	if !ready || len(expected) != 16 {
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
	ia := startSharedPipeInit(t, os.Getenv("IG_SHARED_PRODUCT_CGROUP_A"), "ig15-g011-prod-init-r")
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

// TestSharedProductNodeNegativesAttached (plan section 5, negatives and the
// unpinned instance): every image of IG_SHARED_PRODUCT_NEG_IMAGES (comma
// separated references in IG_SHARED_PRODUCT_LAYOUT: the other kernel's
// product image, the diagnostic twin) is refused with
// ErrSharedNativeUnavailable; the qualification seam is ignored; with
// IG_SHARED_PRODUCT_UNPINNED=1 (an unpinned kernel) StartNode refuses
// before the host runs anything.
func TestSharedProductNodeNegativesAttached(t *testing.T) {
	layout, image, profile := sharedProductAttachedEnv(t)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	config := SharedNodeConfig{Profile: profile, ABI3Development: true, Image: image}
	if os.Getenv("IG_SHARED_PRODUCT_UNPINNED") == "1" {
		runs := 0
		run := func(context.Context, gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
			runs++
			return func(context.Context) error { return nil }, make(chan error), errors.New("host reached")
		}
		_, err := StartNode(WithSharedNodeHost(ctx, SharedNodeHost{Run: run}), config)
		if !errors.Is(err, ErrSharedNativeUnavailable) || runs != 0 {
			t.Fatalf("unpinned-refusal: err=%v runs=%d", err, runs)
		}
		t.Logf("unpinned-refusal: %v", err)
		return
	}
	qruns := 0
	qrun := func(context.Context, gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
		qruns++
		return func(context.Context) error { return nil }, make(chan error), nil
	}
	if _, err := StartNode(WithSharedNodeQualification(ctx, SharedNodeQualification{Run: qrun}), config); !errors.Is(err, ErrSharedNativeUnavailable) || qruns != 0 {
		t.Fatalf("product-neg-qualification: err=%v runs=%d", err, qruns)
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
