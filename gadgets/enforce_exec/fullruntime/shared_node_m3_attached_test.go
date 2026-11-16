// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
)

// sharedBootstrapPublisher is the BOOTSTRAP-PATH route installer (test only).
// The product publication path (se_publication_arm, an fexit on
// cgroup_kn_lock_live) is disabled in the candidate and has no host trigger,
// so this loads the test-only TC seed programs of the SAME object a second
// time with the live collection's maps (MapReplacements) and TEST_RUNs them:
//   - slot 0, first: opaque_real_live_bootstrap_control + policy seed (object
//     0), then the reload policy (object 1, same class, flipped fallback);
//   - slot 1, first: opaque_real_live_bootstrap_second_route (route only, the
//     opposite class; no object of its own);
//   - slot 0, revision: opaque_real_live_bootstrap_advance (the PRODUCT
//     se_route_commit_preflight_locked/publish_locked pair), faultNext=true
//     injects its mid-publication fault (code 2, last-good kept).
//
// There is no kernel withdrawal program: Withdraw is unavailable and the
// route keeps last-good. Productizing this needs BPF work (G019 M4).
//
// The object is the diagnostic twin of the product object (same source,
// SE_PRODUCT_NO_POOL_REAPER plus recovery, live bootstrap, route migration
// and reload diagnostics), loaded with the diagnostic metadata merge. The
// product reaper runs inside StartNode exactly as on the product object, so
// B's unbounded exec churn returns its TASK credits; only this publisher is
// bootstrap (test only).
type sharedBootstrapPublisher struct {
	mu        sync.Mutex
	c         *ebpf.Collection
	maps      map[string]*ebpf.Map
	first     SharedBindingPolicy
	firstSet  bool
	fallback  uint32
	faultNext bool
}

var sharedBootstrapPrograms = []string{
	"opaque_real_live_bootstrap_control", "opaque_real_live_bootstrap_second_route",
	"opaque_real_owner_policy_seed_diagnostic", "opaque_real_owner_second_policy_seed",
	"opaque_real_live_bootstrap_advance", "opaque_real_owner_child_target_candidate",
}

func newSharedBootstrapPublisher(gc operators.GadgetContext, spec *ebpf.CollectionSpec) (*sharedBootstrapPublisher, error) {
	p := &sharedBootstrapPublisher{maps: map[string]*ebpf.Map{}}
	for name := range spec.Maps {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		m, _ := value.(*ebpf.Map)
		if m == nil {
			return nil, fmt.Errorf("live collection has no map %s", name)
		}
		p.maps[name] = m
	}
	want := append([]string(nil), sharedBootstrapPrograms...)
	for _, program := range opaqueVerdictGraphs {
		want = append(want, program)
	}
	sub := spec.Copy()
	sub.Programs = map[string]*ebpf.ProgramSpec{}
	for _, name := range want {
		if spec.Programs[name] == nil {
			return nil, fmt.Errorf("object lacks bootstrap program %s (needs ROUTE_MIGRATION and RELOAD diagnostics)", name)
		}
		sub.Programs[name] = spec.Programs[name]
	}
	c, err := ebpf.NewCollectionWithOptions(sub, ebpf.CollectionOptions{MapReplacements: p.maps})
	if err != nil {
		return nil, fmt.Errorf("load bootstrap programs over the live maps: %w", err)
	}
	p.c = c
	// One-time node configuration, exactly as the qualified loader seeds it.
	wire := sharedNodeWire{NodeCookie: 11, Nonce: 22, ABI: 3, ProfileVersion: 1, Bindings: 2, Objects: 2, Cells: 512, Slots: [4]uint32{2}}
	// The tail-call arrays (birth constructor and verdict graphs) are
	// installed and frozen by the eBPF operator at load (metadata
	// tail_calls); a twin with the configuration gate is armed by this
	// se_configuration write, an older twin by its test gate.
	err = errors.Join(
		p.maps["se_configuration"].Update(uint32(0), wire, ebpf.UpdateAny),
		p.maps["opaque_real_owner_rule_uid_expect"].Update(uint32(0), uint32(0), ebpf.UpdateAny))
	if gate := p.maps["opaque_real_owner_child_gate"]; gate != nil {
		err = errors.Join(err, gate.Update(uint32(0), uint32(1), ebpf.UpdateAny))
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	return p, nil
}

func (p *sharedBootstrapPublisher) run(name string) (uint32, error) {
	code, _, err := p.c.Programs[name].Test(make([]byte, 64))
	return code, err
}

func (p *sharedBootstrapPublisher) Publish(_ context.Context, slot uint32, cgroup uint64, policy SharedBindingPolicy, first bool, _ SharedInitIdentity) (SharedRouteState, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	type gate struct {
		Cgroup, Scope           uint64
		Enabled, ExecutionClass uint32
	}
	type secondPolicy struct{ ExecutionClass, Fallback, Binding, Enabled uint32 }
	update := func(name string, value any) error { return p.maps[name].Update(uint32(0), value, ebpf.UpdateAny) }
	check := func(name string, code uint32, err error) error {
		if err != nil || int32(code) != 0 {
			return fmt.Errorf("%s: code=%d: %w", name, int32(code), err)
		}
		return nil
	}
	switch {
	case slot == 0 && first:
		if err := errors.Join(update("opaque_real_live_bootstrap_gate", gate{cgroup, 10, 1, policy.Class}),
			update("opaque_real_policy_verdict_fallback", policy.Fallback), update("opaque_real_policy_verdict_rules", policy.Rules),
			update("opaque_real_policy_verdict_set_role", policy.SetRole),
			update("opaque_real_second_policy", secondPolicy{policy.Class, 3 - policy.Fallback, 0, 1})); err != nil {
			return SharedRouteState{}, err
		}
		for _, name := range []string{"opaque_real_live_bootstrap_control", "opaque_real_owner_policy_seed_diagnostic", "opaque_real_owner_second_policy_seed"} {
			code, err := p.run(name)
			if err := check(name, code, err); err != nil {
				return SharedRouteState{}, err
			}
		}
		p.first, p.firstSet, p.fallback = policy, true, policy.Fallback
	case slot == 1 && first:
		if !p.firstSet || policy.Class != 3-p.first.Class {
			return SharedRouteState{}, fmt.Errorf("bootstrap second route needs slot 0 first and the opposite class")
		}
		if err := update("opaque_real_live_second_route_gate", gate{cgroup, 11, 1, policy.Class}); err != nil {
			return SharedRouteState{}, err
		}
		code, err := p.run("opaque_real_live_bootstrap_second_route")
		if err := check("second route", code, err); err != nil {
			return SharedRouteState{}, err
		}
	case slot == 0:
		// The advance alternates the two fixed objects: the next record's
		// object carries the other fallback. Rules/role stay seeded.
		if policy.Fallback != 3-p.fallback {
			return SharedRouteState{}, fmt.Errorf("bootstrap revision can only flip the fallback to %d", 3-p.fallback)
		}
		fault := uint32(0)
		if p.faultNext {
			fault, p.faultNext = 1, false
		}
		if err := update("opaque_real_live_advance_request", struct{ Fault, Enabled uint32 }{fault, 1}); err != nil {
			return SharedRouteState{}, err
		}
		code, err := p.run("opaque_real_live_bootstrap_advance")
		switch {
		case err != nil:
			return SharedRouteState{}, err
		case int32(code) == 1:
			return SharedRouteState{}, fmt.Errorf("advance refused by the commit preflight (last-good kept)")
		case int32(code) == 2:
			return SharedRouteState{}, fmt.Errorf("injected mid-publication fault (last-good kept)")
		case code != 0:
			return SharedRouteState{}, fmt.Errorf("advance invariant code %d", int32(code))
		}
		p.fallback = policy.Fallback
	default:
		return SharedRouteState{}, fmt.Errorf("bootstrap revision exists only for route slot 0: %w", ErrSharedNativeUnavailable)
	}
	return p.Route(slot)
}

func (*sharedBootstrapPublisher) Withdraw(context.Context, uint32, uint64) error {
	return fmt.Errorf("no kernel route withdrawal program: %w", ErrSharedNativeUnavailable)
}

// Route decodes struct se_route_anchor (amd64): lock, incarnation u32,
// cgroup_identity, scope, payload_generation, active_serial, admission_serial
// u64, payload_slot, active_record, execution_class, phase u32. Transient
// counters (claims, admissions, usage) are not part of the witness.
func (p *sharedBootstrapPublisher) Route(slot uint32) (SharedRouteState, error) {
	raw := make([]byte, p.maps["se_routes"].ValueSize())
	if len(raw) < 64 {
		return SharedRouteState{}, fmt.Errorf("se_routes value too small")
	}
	if err := p.maps["se_routes"].Lookup(slot, &raw); err != nil {
		return SharedRouteState{}, err
	}
	u32 := func(o int) uint32 { return binary.LittleEndian.Uint32(raw[o:]) }
	u64 := func(o int) uint64 { return binary.LittleEndian.Uint64(raw[o:]) }
	if u32(60) == 0 {
		return SharedRouteState{}, fmt.Errorf("route slot %d: %w", slot, ErrSharedRouteFree)
	}
	return SharedRouteState{
		Incarnation: u32(4), Cgroup: u64(8), Scope: u64(16), Generation: u64(24), Serial: u64(32),
		Record: u32(52), Class: u32(56), Phase: u32(60),
	}, nil
}

func (p *sharedBootstrapPublisher) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.c != nil {
		p.c.Close()
		p.c = nil
	}
	return nil
}

// sharedM3Cgroup is one dedicated cgroup with a trusted init process.
type sharedM3Cgroup struct {
	path string
	ino  uint64
	init *exec.Cmd
}

func newSharedM3Cgroup(t *testing.T, path string) *sharedM3Cgroup {
	t.Helper()
	// A container-like init: own mount namespace, cloned into the cgroup.
	cmd := startSharedTestInit(t, path, "ig15-g019-m3-init", 900)
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		t.Fatal(err)
	}
	return &sharedM3Cgroup{path: path, ino: st.Ino, init: cmd}
}

func (g *sharedM3Cgroup) acquire(context.Context) (BindingLease, error) {
	pid := g.init.Process.Pid
	l := &sharedM2Lease{}
	var err error
	open := func(path string, flags int) *os.File {
		f, e := os.OpenFile(path, flags, 0)
		err = errors.Join(err, e)
		return f
	}
	l.proc = open(fmt.Sprintf("/proc/%d", pid), unix.O_DIRECTORY|unix.O_RDONLY)
	l.cgroup = open(g.path, unix.O_DIRECTORY|unix.O_RDONLY)
	l.mount = open(fmt.Sprintf("/proc/%d/ns/mnt", pid), unix.O_RDONLY)
	l.hostMount = open("/proc/self/ns/mnt", unix.O_RDONLY)
	return l, err
}

// smoke runs, inside the cgroup, one exec as euid 0 and one as euid 1000 and
// returns their exit codes ("r0=<c> r1000=<c>"): the cgroup's verdicts.
//
// The shell joins the cgroup from the host (it is not a descendant of the
// bound init), then forks the two execs. On failure the exact command, exit
// status, stdout and stderr are reported: bash exits 254 when a fork is
// refused (EX_NOEXEC|128), 126 when an exec is refused.
func (g *sharedM3Cgroup) smoke(t *testing.T) string {
	t.Helper()
	out, err := sharedM3Exec(g.path, "ig15-g019-m3-smoke", sharedM3SmokeScript)
	if err != nil {
		t.Fatalf("smoke in %s: %v", g.path, err)
	}
	return out
}

// requireStrictRefusesUntracked: the bootstrap publisher never adopts the
// cgroup's tasks (M4 does), so in Strict a shell joined from the host has
// no TASK and its fork is refused (fail-closed, EPERM; bash 254). That
// refusal is the correct Strict outcome here; adopted Strict verdicts are
// covered by TestSharedNodeM4ProductAttached.
//
// The caller keeps every other exec quiet around the probe (B's churn is
// paused), so the source class moves by exactly one and no other cell
// moves: a latched or faulted A refusal (uncounted, or another class) would
// show.
func (g *sharedM3Cgroup) requireStrictRefusesUntracked(t *testing.T, gc *gadgetcontext.GadgetContext, step string) {
	t.Helper()
	before := sharedFailClosedCells(t, gc)
	// /bin/bash explicitly: its fork refusal status is 254.
	cmd := exec.Command("/bin/bash", "-c", sharedM3SmokeScript, "ig15-g019-m3-smoke", g.path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	var exit *exec.ExitError
	if err == nil || !errors.As(err, &exit) || exit.ExitCode() != 254 || !strings.Contains(stderr.String(), "Operation not permitted") {
		t.Fatalf("%s: Strict A let an untracked host-joined shell fork: %q %q %v", step, stdout.String(), stderr.String(), err)
	}
	// Exactly one counted refusal: the untracked fork, in the source class
	// [1] (design 6); no other class, no retry exhaustion, no ENTRY.
	after := sharedFailClosedCells(t, gc)
	for i := range after {
		want := uint64(0)
		if i == 1 {
			want = 1
		}
		if after[i]-before[i] != want {
			t.Fatalf("%s: fail-closed witness delta %v -> %v: want exactly one source refusal [1]", step, before, after)
		}
	}
}

// sharedFailClosedCells reads the whole fail-closed rate witness (11 cells,
// or 12 with ENTRY); a missing witness is unknown, never zero.
func sharedFailClosedCells(t *testing.T, gc *gadgetcontext.GadgetContext) []uint64 {
	t.Helper()
	value, _ := gc.GetVar(operators.MapPrefix + "opaque_real_fail_closed_rates")
	m, _ := value.(*ebpf.Map)
	if m == nil {
		t.Fatal("fail-closed rate witness not published")
	}
	n, err := FailClosedRateCells(m.MaxEntries())
	if err != nil {
		t.Fatal(err)
	}
	cells := make([]uint64, n)
	for i := range cells {
		if err := m.Lookup(uint32(i), &cells[i]); err != nil {
			t.Fatal(err)
		}
	}
	return cells
}

const sharedM3SmokeScript = `echo $$ > "$1/cgroup.procs" || exit 99
/bin/true; a=$?
setpriv --reuid=1000 --regid=1000 --clear-groups /bin/true; b=$?
echo "r0=$a r1000=$b"`

// sharedM3Exec runs script under /bin/sh with $1 = cgroup and returns its
// trimmed stdout, or an error naming the command, exit status, stdout,
// stderr and, for bash's fork-refusal status, the likely cause.
func sharedM3Exec(cgroup, name, script string) (string, error) {
	cmd := exec.Command("/bin/sh", "-c", script, name, cgroup)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	if err == nil {
		return out, nil
	}
	hint := ""
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 254 {
		hint = " (bash 254: a fork in the cgroup was refused; in a Strict route a task without a charged TASK, here a shell that joined the cgroup from the host, cannot fork)"
	}
	return out, fmt.Errorf("%s: %q in %s: %w%s; stdout %q; stderr %q", name, cmd.String(), cgroup, err, hint, out, strings.TrimSpace(stderr.String()))
}

// startSharedCandidateNode loads object through StartNode and the host
// gadget context (OCI image = candidate gadget.yaml merged with the packaged
// attach declaration and the diagnostic overlays), with newPublisher(spec) as
// the route publisher (nil: the node's own, G1). handlerEnv names the exec
// handler symbol override (falling back to IG_SHARED_M3_HANDLER_SYMBOL).
// configure, when not nil, adjusts the node configuration (e.g. the
// fail-closed poll interval) before StartNode.
// Shared by M3 (bootstrap publisher, unchanged) and M4 (product publisher).
// sharedTestQualification, when set by a test, adjusts the qualification
// startSharedCandidateNode starts the node with (test-only seams).
var sharedTestQualification func(*SharedNodeQualification)

func startSharedCandidateNode(t *testing.T, object, handlerEnv string, newPublisher func(*ebpf.CollectionSpec) func(operators.GadgetContext) (SharedRoutePublisher, error), configure func(*SharedNodeConfig)) (*NodeEnforcer, *gadgetcontext.GadgetContext, context.Context) {
	t.Helper()
	elf, err := os.ReadFile(object)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	kallsyms, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		t.Fatal(err)
	}
	outer, err := opaqueDiagnosticExecOuterSymbol(bytes.NewReader(kallsyms))
	if err != nil {
		t.Fatal(err)
	}
	handlerName := os.Getenv(handlerEnv)
	if handlerName == "" {
		handlerName = os.Getenv("IG_SHARED_M3_HANDLER_SYMBOL")
	}
	handlerSymbol, err := opaqueDiagnosticExecHandlerSymbol(bytes.NewReader(kallsyms), handlerName)
	if err != nil {
		t.Fatal(err)
	}
	// A product-control object (se_admin: g19pkgpubf128, the birth-park
	// spin twin g19pkgparkf128) has the product geometry: the product
	// policy objects (one spare for make-before-break revision) at the
	// product's q(128,32) (G019 burst gate); every other object of this
	// harness is a compile.sh twin with two at q(128,16). Both have the
	// burst-sized tombstone table.
	profile := sharedCandidateQualificationProfile()
	if _, product := spec.Maps["se_admin"]; !product {
		profile = sharedCandidateProfileFor(128, 16)
		profile.ExitTombstones = sharedProductExitTombstones
	}
	// The node configuration (configure may change the profile, e.g. a
	// test object's own geometry) before the image annotations it pins.
	const image = "local/shared-candidate:abi3-development"
	nodeConfig := SharedNodeConfig{Profile: profile, ABI3Development: true, Image: image}
	if configure != nil {
		configure(&nodeConfig)
	}
	merged := packagingForObject(t, mergedSharedCandidateMetadataFor(t, true), spec, "m3 object")
	for key, value := range sharedGeometryAnnotations(nodeConfig.Profile) {
		merged.Set(key, value)
	}
	for name, symbol := range map[string]string{
		"opaque_real_owner_failure_outer_enter": outer, "opaque_real_owner_failure_outer_exit": outer,
		"opaque_real_owner_failure_handler_enter": handlerSymbol, "opaque_real_owner_failure_handler_exit": handlerSymbol,
	} {
		merged.Set("programs."+name+".attach_to", symbol)
	}
	// The diagnostic object adds TEST_RUN programs; none may attach. The
	// pinned commands (the product reaper's opaque_real_reap) stay enabled.
	manifestPrograms := map[string]operators.NativeProgramResource{}
	for name, p := range spec.Programs {
		manifestPrograms[name] = operators.NativeProgramResource{Type: uint32(p.Type)}
	}
	commands, err := sharedCandidateCommandsOf(manifestPrograms)
	if err != nil {
		t.Fatal(err)
	}
	for name := range spec.Programs {
		if _, command := commands[name]; command {
			continue // the product reaper's and (G1) the product publisher's commands stay enabled
		}
		if !sharedCandidateAttached(name) && merged.GetString("programs."+name+".attach_to") != sharedProgramDisabled {
			merged.Set("programs."+name+".attach_to", sharedProgramDisabled)
			t.Logf("M3: disabled diagnostic program %s", name)
		}
	}
	metadata, err := yaml.Marshal(merged.AllSettings())
	if err != nil {
		t.Fatal(err)
	}
	store := memory.New()
	push := func(media string, data []byte) ocispec.Descriptor {
		desc := content.NewDescriptorFromBytes(media, data)
		if err := store.Push(t.Context(), desc, bytes.NewReader(data)); err != nil {
			t.Fatal(err)
		}
		return desc
	}
	config := push("application/vnd.gadget.config.v1+yaml", metadata)
	layer := push("application/vnd.gadget.ebpf.program.v1+binary", elf)
	manifest, _ := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, Config: config, Layers: []ocispec.Descriptor{layer}})
	desc := push(ocispec.MediaTypeImageManifest, manifest)
	desc.Platform = &ocispec.Platform{Architecture: runtime.GOARCH, OS: "linux"}
	index, _ := json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{desc}})
	// The oci handler resolves the normalized reference (default domain
	// ghcr.io); gadgetcontext keeps the short name that StartNode pins.
	domain, remainder := oci.SplitIGDomain(image)
	if err := store.Tag(t.Context(), push(ocispec.MediaTypeImageIndex, index), domain+"/"+remainder); err != nil {
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
	var publisherFor func(operators.GadgetContext) (SharedRoutePublisher, error)
	if newPublisher != nil {
		publisherFor = newPublisher(spec)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 4*time.Minute)
	t.Cleanup(cancel)
	q := SharedNodeQualification{Run: run, Publisher: publisherFor}
	if sharedTestQualification != nil {
		sharedTestQualification(&q)
	}
	node, err := StartNode(WithSharedNodeQualification(ctx, q), nodeConfig)
	if err != nil {
		t.Fatalf("StartNode: %v", err)
	}
	return node, gc, ctx
}

// TestSharedNodeM3Attached (G019 M3): two bindings on the one StartNode
// collection with independent revision, removal and fault. Binding A (slot
// 0, Strict, deny fallback, rule for euid 0) and B (slot 1, Audit) are
// published through the BOOTSTRAP-PATH publisher; then A is republished
// (fallback flipped) under exec churn in B, removed, and its publication
// faulted. B's verdicts, route witness and status never change, Ready stays
// unavailable, and StopNode leaves nothing. A's Strict verdict here is the
// refusal of an untracked host-joined shell's fork (the bootstrap publisher
// never adopts); adopted Strict verdicts are M4's. Isolated exact-kernel VM only,
// with an object carrying the ROUTE_MIGRATION and RELOAD diagnostics.
func TestSharedNodeM3Attached(t *testing.T) {
	object := os.Getenv("IG_SHARED_M3_OBJECT")
	if object == "" {
		t.Skip("set IG_SHARED_M3_OBJECT on an isolated exact-kernel VM")
	}
	cgroupA, cgroupB := os.Getenv("IG_SHARED_M3_CGROUP_A"), os.Getenv("IG_SHARED_M3_CGROUP_B")
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(cgroupA), "ig15-g019-m3-") || !strings.HasPrefix(filepath.Base(cgroupB), "ig15-g019-m3-") || cgroupA == cgroupB {
		t.Fatal("root and two dedicated ig15-g019-m3-* cgroups required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	var publisher *sharedBootstrapPublisher
	node, gc, ctx := startSharedCandidateNode(t, object, "IG_SHARED_M3_HANDLER_SYMBOL", func(spec *ebpf.CollectionSpec) func(operators.GadgetContext) (SharedRoutePublisher, error) {
		newPublisher := func(gc operators.GadgetContext) (SharedRoutePublisher, error) {
			p, err := newSharedBootstrapPublisher(gc, spec)
			publisher = p
			if p == nil {
				return nil, err
			}
			return p, err
		}
		return newPublisher
	}, nil)
	stopped := false
	defer func() {
		if !stopped {
			_ = node.StopNode(context.WithoutCancel(ctx))
		}
	}()
	var expected []sharedM3Link
	for name, r := range node.host.live.receipts {
		expected = append(expected, sharedM3Link{name, r.LinkID, r.ProgramID})
	}

	ga, gb := newSharedM3Cgroup(t, cgroupA), newSharedM3Cgroup(t, cgroupB)
	a, err := node.Bind(ctx, SharedBindingConfig{CgroupID: ga.ino, InitHostPID: uint32(ga.init.Process.Pid), Acquire: ga.acquire})
	if err != nil {
		t.Fatalf("Bind A: %v", err)
	}
	b, err := node.Bind(ctx, SharedBindingConfig{CgroupID: gb.ino, InitHostPID: uint32(gb.init.Process.Pid), Acquire: gb.acquire})
	if err != nil {
		t.Fatalf("Bind B: %v", err)
	}
	if a.Inspect().RouteSlot != 0 || b.Inspect().RouteSlot != 1 {
		t.Fatalf("bootstrap needs A on slot 0 and B on slot 1: %+v %+v", a.Inspect(), b.Inspect())
	}
	if _, err := a.Publish(ctx, SharedBindingPolicy{Class: 2, Fallback: 2, Rules: 1}); err != nil {
		t.Fatalf("publish A: %v", err)
	}
	if _, err := b.Publish(ctx, SharedBindingPolicy{Class: 1, Fallback: 2, Rules: 1}); err != nil {
		t.Fatalf("publish B: %v", err)
	}
	bStatus := b.Inspect()
	bRoute, err := publisher.Route(1)
	if err != nil || bStatus.Fault != nil || !bStatus.RoutePublished || bStatus.Ready {
		t.Fatalf("B: %+v route=%+v err=%v", bStatus, bRoute, err)
	}
	bVerdict := gb.smoke(t)
	ga.requireStrictRefusesUntracked(t, gc, "baseline")
	t.Logf("M3: A(Strict) refuses the untracked shell's fork, B(Audit) %s, B route %+v", bVerdict, bRoute)
	if bVerdict != "r0=0 r1000=0" {
		t.Fatalf("baseline verdicts: B %q (want Audit nonblocking)", bVerdict)
	}
	requireB := func(step string) {
		t.Helper()
		st := b.Inspect()
		route, err := publisher.Route(1)
		if err != nil || st.Fault != nil || !st.RoutePublished || st.Removed || st.Generation != bStatus.Generation || route != bRoute {
			t.Fatalf("%s: B changed: %+v route=%+v err=%v (want %+v)", step, st, route, err, bRoute)
		}
		if v := gb.smoke(t); v != bVerdict {
			t.Fatalf("%s: B verdicts %q, want %q", step, v, bVerdict)
		}
		if err := node.Ready(gc); !errors.Is(err, ErrSharedNativeUnavailable) {
			t.Fatalf("%s: Ready %v", step, err)
		}
	}
	requireB("published")

	// Revision of A under exec churn in B.
	churnCtx, stopChurn := context.WithCancel(ctx)
	var churn sync.WaitGroup
	var churnBad []string
	var churnN int
	var churnMu sync.Mutex
	// churnPause is held by each churn iteration and by each A probe: the
	// probe's witness deltas see no B exec (B's untracked Audit forks are
	// source refusals too).
	var churnPause sync.Mutex
	churn.Add(1)
	go func() {
		defer churn.Done()
		for churnCtx.Err() == nil {
			churnPause.Lock()
			v, err := sharedM3Exec(gb.path, "ig15-g019-m3-churn", sharedM3SmokeScript)
			churnPause.Unlock()
			churnMu.Lock()
			churnN++
			if err != nil || v != bVerdict {
				churnBad = append(churnBad, fmt.Sprintf("%q %v", v, err))
			}
			churnMu.Unlock()
		}
	}()
	fallback := uint32(2)
	for i := 0; i < 4; i++ {
		fallback = 3 - fallback
		var state SharedRouteState
		for attempt := 0; ; attempt++ {
			if state, err = a.Publish(ctx, SharedBindingPolicy{Class: 2, Fallback: fallback, Rules: 1}); err == nil || attempt == 50 {
				break
			}
			time.Sleep(20 * time.Millisecond) // preflight refuses while A has in-flight claims
		}
		if err != nil {
			stopChurn()
			churn.Wait()
			t.Fatalf("republish A #%d: %v", i, err)
		}
		t.Logf("M3: A revision gen %d fallback %d", state.Generation, fallback)
		if route := mustSharedRoute(t, publisher, 0); route.Generation != state.Generation || route.Class != 2 {
			t.Fatalf("A revision %d: kernel route %+v, want generation %d Strict", i, route, state.Generation)
		}
		// Paused by a deferred unlock: a failing probe (t.Fatalf) never
		// leaves B's churn blocked on the pause.
		func() {
			churnPause.Lock()
			defer churnPause.Unlock()
			ga.requireStrictRefusesUntracked(t, gc, fmt.Sprintf("revision %d (B churn paused)", i))
		}()
	}
	stopChurn()
	churn.Wait()
	ga.requireStrictRefusesUntracked(t, gc, "after the churn")
	if len(churnBad) != 0 || churnN == 0 {
		t.Fatalf("B churn during A's revisions: %d runs, bad %v", churnN, churnBad)
	}
	t.Logf("M3: %d B churn execs unchanged during 4 A revisions", churnN)
	reaper := node.host.live.reaper
	if reaper == nil {
		t.Fatal("StartNode runs no product reaper")
	}
	if err := reaper.fault(); err != nil {
		t.Fatalf("product reaper during churn: %v", err)
	}
	// No credit assertion here: B's churn is an untracked host-joined shell
	// under the bootstrap publisher (no adoption), so it is never TASK
	// charged and leaves nothing to reap. The reaper's credit return under
	// adopted churn is asserted by M4.
	if stats, err := reaper.reaper.Stats(); err == nil {
		t.Logf("M3: product reaper %s", stats)
	}
	requireB("A revised")

	// Fault in A's publication: A stays on last-good, B unaffected.
	aBefore := a.Inspect()
	aRoute, _ := publisher.Route(0)
	publisher.mu.Lock()
	publisher.faultNext = true
	publisher.mu.Unlock()
	if _, err := a.Publish(ctx, SharedBindingPolicy{Class: 2, Fallback: 3 - fallback, Rules: 1}); err == nil || !strings.Contains(err.Error(), "injected") {
		t.Fatalf("faulted publish A: %v", err)
	}
	if st, route := a.Inspect(), mustSharedRoute(t, publisher, 0); st.Fault != nil || st.Generation != aBefore.Generation || route != aRoute {
		t.Fatalf("A after fault: %+v route=%+v, last-good %+v", st, route, aRoute)
	}
	requireB("A faulted")

	// Removal of A: the session retires; the kernel route keeps last-good.
	if err := a.Remove(ctx, aBefore.Generation); err != nil {
		t.Fatalf("Remove A: %v", err)
	}
	if st := a.Inspect(); !st.Removed || !st.WithdrawPending {
		t.Fatalf("A after remove: %+v", st)
	}
	requireB("A removed")
	t.Logf("M3: A removed (withdraw pending, last-good kept), B unchanged")

	if err := node.StopNode(context.WithoutCancel(ctx)); err != nil {
		t.Fatalf("StopNode: %v", err)
	}
	stopped = true
	deadline := time.Now().Add(10 * time.Second)
	for _, e := range expected {
		for {
			p, err := ebpf.NewProgramFromID(ebpf.ProgramID(e.program))
			if err != nil {
				break
			}
			p.Close()
			if time.Now().After(deadline) {
				t.Errorf("program %d (%s, link %d) survived StopNode", e.program, e.name, e.link)
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	if publisher.c != nil {
		t.Error("bootstrap programs survived StopNode")
	}
	if reaper.err != nil {
		t.Errorf("product reaper: %v", reaper.err)
	}
	t.Log("PASS: M3 two bindings, independent revision/fault/removal, B unchanged, full cleanup")
}

type sharedM3Link struct {
	name          string
	link, program uint32
}

func mustSharedRoute(t *testing.T, p *sharedBootstrapPublisher, slot uint32) SharedRouteState {
	t.Helper()
	r, err := p.Route(slot)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
