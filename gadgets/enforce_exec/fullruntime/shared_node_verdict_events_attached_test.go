// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

// sharedVerdictEvent is one decoded "verdict" datasource record (event ABI 1).
type sharedVerdictEvent struct {
	generation, cgroup, scope, execID, taskCookie uint64
	loadEpoch                                     uint64
	deny, mode, hostPID, errorCode                uint32
	execClass, pass, uncertain, factsUnknown      uint32
	pathResult                                    int32
	path                                          string
	matched                                       [4]uint64
}

// rules is the matched-rule bit indexes of e.
func (e sharedVerdictEvent) rules() []int {
	var out []int
	for w, word := range e.matched {
		for word != 0 {
			b := bits.TrailingZeros64(word)
			out = append(out, 64*w+b)
			word &^= 1 << b
		}
	}
	return out
}

// sharedVerdictCollector subscribes to the node gadget's "verdict"
// datasource through the eBPF operator (the product path). While stalled
// (stall/resume), the subscriber blocks: the operator's ring reader stops
// consuming.
type sharedVerdictCollector struct {
	mu     sync.Mutex
	events []sharedVerdictEvent
	errs   []error
	gate   chan struct{}
}

func (c *sharedVerdictCollector) stall() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gate = make(chan struct{})
}

func (c *sharedVerdictCollector) resume() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.gate != nil {
		close(c.gate)
		c.gate = nil
	}
}

func (c *sharedVerdictCollector) operator() operators.DataOperator {
	return simple.New("g020-verdict-events", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
		ds := gc.GetDataSources()[SharedVerdictDataSource]
		if ds == nil {
			return fmt.Errorf("missing %q datasource", SharedVerdictDataSource)
		}
		fields := map[string]datasource.FieldAccessor{}
		for _, name := range []string{"generation", "cgroup", "deny", "mode", "path_result", "host_pid", "path", "matched_rules", "error", "exec_class", "scope", "exec_id", "pass", "uncertain", "facts_unknown", "task_cookie", "load_epoch"} {
			if fields[name] = ds.GetField(name); fields[name] == nil {
				return fmt.Errorf("verdict datasource lacks field %s", name)
			}
		}
		return ds.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
			c.mu.Lock()
			gate := c.gate
			c.mu.Unlock()
			if gate != nil {
				<-gate
			}
			var e sharedVerdictEvent
			var errs []error
			u64 := func(name string, out *uint64) {
				v, err := fields[name].Uint64(data)
				*out = v
				errs = append(errs, err)
			}
			u32 := func(name string, out *uint32) {
				v, err := fields[name].Uint32(data)
				*out = v
				errs = append(errs, err)
			}
			u64("generation", &e.generation)
			u64("cgroup", &e.cgroup)
			u64("scope", &e.scope)
			u64("exec_id", &e.execID)
			u64("task_cookie", &e.taskCookie)
			u64("load_epoch", &e.loadEpoch)
			u32("deny", &e.deny)
			u32("mode", &e.mode)
			u32("host_pid", &e.hostPID)
			u32("error", &e.errorCode)
			u32("exec_class", &e.execClass)
			u32("pass", &e.pass)
			u32("uncertain", &e.uncertain)
			u32("facts_unknown", &e.factsUnknown)
			pr, err := fields["path_result"].Int32(data)
			e.pathResult = pr
			errs = append(errs, err)
			e.path, err = fields["path"].String(data)
			e.path = strings.TrimRight(e.path, "\x00")
			errs = append(errs, err)
			matched, err := fields["matched_rules"].Uint64Array(data)
			errs = append(errs, err)
			if len(matched) == 4 {
				copy(e.matched[:], matched)
			} else {
				errs = append(errs, fmt.Errorf("matched_rules has %d words", len(matched)))
			}
			c.mu.Lock()
			defer c.mu.Unlock()
			if err := errors.Join(errs...); err != nil {
				c.errs = append(c.errs, err)
				return nil
			}
			c.events = append(c.events, e)
			return nil
		}, 100)
	}))
}

func (c *sharedVerdictCollector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// since returns the events after index from, of cgroup.
func (c *sharedVerdictCollector) since(from int, cgroup uint64) []sharedVerdictEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []sharedVerdictEvent
	for _, e := range c.events[from:] {
		if e.cgroup == cgroup {
			out = append(out, e)
		}
	}
	return out
}

func (c *sharedVerdictCollector) decodeErrors() []error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.errs
}

// startSharedVerdictNode starts object through StartNode with the collector
// on its gadget context, its profile adapted to the object's verdict ring and
// 1024-cell policy objects (the product's 3 x 256 kept).
func startSharedVerdictNode(t *testing.T, object string, c *sharedVerdictCollector) (*NodeEnforcer, *gadgetcontext.GadgetContext, context.Context) {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	ring, arena := spec.Maps[SharedVerdictRingMap], spec.Maps["se_arena"]
	if ring == nil || arena == nil {
		t.Fatalf("%s: no verdict ring (%v) or arena: not an emitter object", object, ring)
	}
	sharedTestQualification = func(q *SharedNodeQualification) {
		run := q.Run
		q.Run = func(ctx context.Context, opt gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
			return run(ctx, func(gc *gadgetcontext.GadgetContext) {
				opt(gc)
				gadgetcontext.WithAdditionalDataOperators(c.operator())(gc)
			})
		}
	}
	defer func() { sharedTestQualification = nil }()
	return startSharedCandidateNode(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, func(cfg *SharedNodeConfig) {
		cfg.Profile.VerdictRing = uint64(ring.MaxEntries)
		cfg.Profile.PolicySlots[1] = (uint64(arena.MaxEntries) - 256*cfg.Profile.PolicySlots[0]) / 1024
	})
}

// TestSharedNodeVerdictEventsAttached (G020 items 1+2): the product verdict
// events of a StartNode collection, read from the "verdict" datasource
// through the eBPF operator, on two bindings A (Strict) and B (Audit):
// Strict allow and deny, Audit would-deny, an UNKNOWN fact (path longer
// than 255 bytes: Strict error 2, Audit uncertain), a 2-pass #! script (two
// events, one exec_id, passes 0 and 1), a 256-rule policy matching rule
// 255 (bit 255), a continuation refusal (the stale-resume injector: a D1
// fault event), every matched-rule bit i naming SharedCompiled.Program.Rules[i]
// (BindingSession.Compile), generation and scope those of the publication,
// and Submitted == the events read. Then a 4 KiB-ring object whose reader
// is stalled under a Strict deny storm: every exec EPERM, Lost > 0
// (Degraded), and once the reader resumes Submitted == the events read.
// Isolated exact-kernel VM only.
func TestSharedNodeVerdictEventsAttached(t *testing.T) {
	object, starve := os.Getenv("IG_SHARED_VERDICT_OBJECT"), os.Getenv("IG_SHARED_VERDICT_STARVE_OBJECT")
	if object == "" || starve == "" {
		t.Skip("set IG_SHARED_VERDICT_OBJECT and IG_SHARED_VERDICT_STARVE_OBJECT on an isolated exact-kernel VM")
	}
	root := os.Getenv("IG_SHARED_VERDICT_CGROUP_ROOT")
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(root), "ig15-g020-events") {
		t.Fatal("root and a dedicated ig15-g020-events* cgroup root required")
	}
	if err := checkSharedInitNamespaces(); err != nil {
		t.Fatalf("design 13.8: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	files := newSharedFactFiles(t)
	const eperm = 126

	// bind starts the command-pipe inits of names in their own cgroups.
	bind := func(node *NodeEnforcer, ctx context.Context, names ...string) (map[string]*sharedPipeInit, map[string]*BindingSession) {
		inits, sessions := map[string]*sharedPipeInit{}, map[string]*BindingSession{}
		for _, name := range names {
			cgroup := filepath.Join(root, strings.ToLower(name))
			if err := os.MkdirAll(cgroup, 0o755); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Remove(cgroup) })
			p := startSharedPipeInitShell(t, cgroup, "ig15-g020-events-init-"+strings.ToLower(name), "/usr/bin/bash")
			t.Cleanup(p.stop)
			s, err := node.Bind(ctx, SharedBindingConfig{CgroupID: p.ino, InitHostPID: uint32(p.cmd.Process.Pid), Acquire: p.acquire})
			if err != nil {
				t.Fatalf("Bind %s: %v", name, err)
			}
			inits[name], sessions[name] = p, s
		}
		return inits, sessions
	}
	// rc runs command in init and returns its exit status.
	rc := func(ctx context.Context, init *sharedPipeInit, label, command string) int {
		t.Helper()
		out, code, err := init.run(ctx, command+"; echo rc=$?")
		i := strings.LastIndex(out, "rc=")
		if err != nil || code != 0 || i < 0 {
			t.Fatalf("%s: %q code %d: %v", label, out, code, err)
		}
		n, err := strconv.Atoi(strings.TrimSpace(out[i+3:]))
		if err != nil {
			t.Fatalf("%s: status %q", label, out)
		}
		return n
	}
	// wait returns the events of cgroup after from whose path is one of
	// paths (the init's own /bin/sh -c execs are evaluated too) once there
	// are n (none more after a grace period).
	wait := func(c *sharedVerdictCollector, from int, cgroup uint64, n int, label string, paths ...string) []sharedVerdictEvent {
		t.Helper()
		mine := func() []sharedVerdictEvent {
			var out []sharedVerdictEvent
			for _, e := range c.since(from, cgroup) {
				if slices.Contains(paths, e.path) {
					out = append(out, e)
				}
			}
			return out
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) && len(mine()) < n {
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
		got := mine()
		if len(got) != n {
			t.Fatalf("%s: %d events, want %d: %+v", label, len(got), n, got)
		}
		return got
	}
	// drained waits until the events read equal Submitted.
	drained := func(node *NodeEnforcer, c *sharedVerdictCollector, label string) KernelEventCounters {
		t.Helper()
		var k KernelEventCounters
		var err error
		for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
			if k, err = node.KernelEventCounters(); err == nil && uint64(c.count()) == k.Submitted {
				break
			}
		}
		if err != nil || uint64(c.count()) != k.Submitted {
			t.Fatalf("%s: read %d events, counters %+v (%v)", label, c.count(), k, err)
		}
		if errs := c.decodeErrors(); len(errs) != 0 {
			t.Fatalf("%s: decode errors %v", label, errs)
		}
		return k
	}

	c := &sharedVerdictCollector{}
	node, gc, ctx := startSharedVerdictNode(t, object, c)
	stopped := false
	defer func() {
		if !stopped {
			_ = node.StopNode(context.WithoutCancel(ctx))
		}
	}()
	modes := map[string]fullpolicy.Mode{"A": fullpolicy.Enforce, "B": fullpolicy.Audit}
	classes := map[string]uint32{"A": 2, "B": 1}
	inits, sessions := bind(node, ctx, "A", "B")
	revision := 0
	compiled := map[string]SharedCompiled{}
	states := map[string]SharedRouteState{}
	// publish compiles (BindingSession.Compile) and commits rules to both.
	publish := func(label string, rules ...fullpolicy.Rule) {
		t.Helper()
		revision++
		for _, name := range []string{"A", "B"} {
			policy := &fullpolicy.Policy{ID: "g020-events-" + strings.ToLower(name), Revision: strconv.Itoa(revision), Mode: modes[name], RootRole: "app", Default: fullpolicy.Allow, Rules: rules}
			cp, err := sessions[name].Compile(SharedBindingPolicy{Source: policy, Container: strings.ToLower(name)})
			if err != nil {
				t.Fatalf("%s: compile %s: %v", label, name, err)
			}
			st, err := sessions[name].PublishCompiled(ctx, cp)
			if err != nil {
				t.Fatalf("%s: publish %s: %v", label, name, err)
			}
			if st.Generation != cp.Generation || cp.Program == nil {
				t.Fatalf("%s: %s published generation %d, compiled %d", label, name, st.Generation, cp.Generation)
			}
			compiled[name], states[name] = cp, st
		}
	}
	// ruleNames maps the matched-rule bits of e through the binding's
	// SharedCompiled.Program.Rules (mandatory: bit i == Rules[i]).
	ruleNames := func(name string, e sharedVerdictEvent) []string {
		t.Helper()
		var out []string
		for _, i := range e.rules() {
			if i >= len(compiled[name].Program.Rules) {
				t.Fatalf("%s: matched bit %d beyond the %d compiled rules", name, i, len(compiled[name].Program.Rules))
			}
			out = append(out, compiled[name].Program.Rules[i].Name)
		}
		return out
	}
	type want struct {
		path            string
		deny, mode, err uint32
		pass            uint32
		uncertain       uint32
		rules           []string
	}
	// expect runs command in name, checks its status and its events.
	expect := func(label, name, command string, status int, wants ...want) []sharedVerdictEvent {
		t.Helper()
		from := c.count()
		if got := rc(ctx, inits[name], label, command); got != status {
			t.Fatalf("%s %s: rc %d, want %d", label, name, got, status)
		}
		var paths []string
		for _, w := range wants {
			paths = append(paths, w.path)
		}
		events := wait(c, from, inits[name].ino, len(wants), label+" "+name, paths...)
		for i, w := range wants {
			e := events[i]
			if e.path != w.path || e.deny != w.deny || e.mode != w.mode || e.errorCode != w.err || e.pass != w.pass || e.uncertain != w.uncertain || e.execClass != classes[name] {
				t.Fatalf("%s %s: event %d %+v, want %+v (class %d)", label, name, i, e, w, classes[name])
			}
			if w.err != 1 {
				if names := ruleNames(name, e); strings.Join(names, ",") != strings.Join(w.rules, ",") {
					t.Fatalf("%s %s: event %d matched rules %v (bits %v), want %v", label, name, i, names, e.rules(), w.rules)
				}
			}
			if e.generation != states[name].Generation || e.scope != states[name].Scope || e.scope == 0 || e.execID == 0 || e.taskCookie == 0 || e.hostPID == 0 {
				t.Fatalf("%s %s: event %d identity %+v, route %+v", label, name, i, e, states[name])
			}
			if e.execID != events[0].execID || e.taskCookie != events[0].taskCookie || e.hostPID != events[0].hostPID {
				t.Fatalf("%s %s: exec identity (%d, %d) then (%d, %d) within one exec", label, name, events[0].taskCookie, events[0].execID, e.taskCookie, e.execID)
			}
		}
		t.Logf("%s %s: rc %d, %d events %+v", label, name, status, len(events), events)
		return events
	}
	fault := func(path string, mode uint32) want {
		return want{path: path, deny: 1, mode: mode, err: 1, pass: SharedVerdictPassUnknown}
	}

	never := fullpolicy.Rule{Name: "never", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{"/nonexistent/never"}}}
	publish("base", never)
	// Strict allow (mode 2: the Strict default allow), Audit allow. Three
	// processes' first execs: each task's exec sequence starts at 1, their
	// task_cookie differ: (task_cookie, exec_id) is node-unique.
	first := expect("allow", "A", "/usr/bin/true", 0, want{path: "/usr/bin/true", mode: 2})[0]
	second := expect("allow again", "A", "/usr/bin/true", 0, want{path: "/usr/bin/true", mode: 2})[0]
	other := expect("allow", "B", "/usr/bin/true", 0, want{path: "/usr/bin/true", mode: 1})[0]
	if first.hostPID == second.hostPID || first.taskCookie == second.taskCookie || first.taskCookie == other.taskCookie || second.taskCookie == other.taskCookie {
		t.Fatalf("first execs of three processes share a task_cookie: %+v %+v %+v", first, second, other)
	}
	// M7: one nonzero epoch for the whole load qualifies task_cookie.
	if first.loadEpoch == 0 || second.loadEpoch != first.loadEpoch || other.loadEpoch != first.loadEpoch {
		t.Fatalf("load_epoch not one nonzero value per load: %#x %#x %#x", first.loadEpoch, second.loadEpoch, other.loadEpoch)
	}
	t.Logf("load_epoch %#x", first.loadEpoch)
	t.Logf("first execs: (task_cookie, exec_id) (%d, %d) (%d, %d) (%d, %d)", first.taskCookie, first.execID, second.taskCookie, second.execID, other.taskCookie, other.execID)

	// Strict deny, Audit would-deny, with the matched rule.
	publish("deny interpreter", never, fullpolicy.Rule{Name: "interp", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{files.interp}}})
	expect("deny", "A", files.interp, eperm, want{path: files.interp, deny: 1, mode: 2, rules: []string{"interp"}})
	expect("would-deny", "B", files.interp, 0, want{path: files.interp, deny: 1, mode: 1, rules: []string{"interp"}})

	// Two passes of one #! exec: the allowed script, the denied interpreter.
	expect("script", "A", files.script, eperm,
		want{path: files.script, mode: 2},
		want{path: files.interp, deny: 1, mode: 2, pass: 1, rules: []string{"interp"}})
	expect("script", "B", files.script, 0,
		want{path: files.script, mode: 1},
		want{path: files.interp, deny: 1, mode: 1, pass: 1, rules: []string{"interp"}})

	// A path longer than 255 bytes is UNKNOWN: Strict denies with error 2
	// (FE_UNKNOWN), Audit allows, error 0 (AUDIT_UNKNOWN normalized), both
	// uncertain; the event's path is empty and its target-path bit set.
	publish("base again", never)
	for name, w := range map[string]want{"A": {deny: 1, mode: 2, err: 2, uncertain: 1}, "B": {mode: 1, uncertain: 1}} {
		status := 0
		if name == "A" {
			status = eperm
		}
		events := expect("unknown path", name, files.long, status, w)
		if e := events[0]; e.pathResult != -1 || e.factsUnknown&SharedVerdictUnknownTargetPath == 0 {
			t.Fatalf("unknown path %s: %+v", name, e)
		}
	}

	// 256 rules, rule 255 matching: bit 255 names Rules[255].
	var many []fullpolicy.Rule
	for i := range 255 {
		many = append(many, fullpolicy.Rule{Name: fmt.Sprintf("r%d", i), Action: fullpolicy.Deny, Actor: fullpolicy.Actor{UID: []int64{int64(60000 + i)}}})
	}
	many = append(many, fullpolicy.Rule{Name: "r255", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{files.interp}}})
	publish("256 rules", many...)
	for name, mode := range map[string]uint32{"A": 2, "B": 1} {
		status := 0
		if name == "A" {
			status = eperm
		}
		events := expect("bit 255", name, files.interp, status, want{path: files.interp, deny: 1, mode: mode, rules: []string{"r255"}})
		if events[0].matched[3] != 1<<63 || len(compiled[name].Program.Rules) != 256 {
			t.Fatalf("bit 255 %s: %+v (%d rules)", name, events[0], len(compiled[name].Program.Rules))
		}
	}

	// Continuation refusal (the stale-resume injector): pass 0 is a
	// decision, the refused interpreter pass a D1 fault event of the same
	// exec; Strict denies, Audit allows unevaluated.
	publish("base for refusal", never)
	value, _ := gc.GetVar(operators.MapPrefix + "opaque_real_interp_stale_resume")
	arm, _ := value.(*ebpf.Map)
	if arm == nil {
		t.Fatal("IG_SHARED_VERDICT_OBJECT needs ENFORCE_EXEC_POOL_OPAQUE_INTERP_STALE_RESUME_DIAGNOSTIC (g19pkgevf128)")
	}
	for name, mode := range map[string]uint32{"A": 2, "B": 1} {
		if err := arm.Update(uint32(0), uint64(1), 0); err != nil {
			t.Fatal(err)
		}
		status := 0
		if name == "A" {
			status = eperm
		}
		expect("continuation refusal", name, files.script, status, want{path: files.script, mode: mode}, fault("", mode))
		var left uint64
		if err := arm.Lookup(uint32(0), &left); err != nil || left != 0 {
			t.Fatalf("stale-resume injector not consumed: %d %v", left, err)
		}
	}
	expect("after refusal", "A", files.script, 0, want{path: files.script, mode: 2}, want{path: files.interp, mode: 2, pass: 1})

	// H2: a clean proposal whose WORK suspension fails (the suspend-fault
	// injector) is not final: its staged decision event is never
	// published, the pass's one event is the D1 fault of the class
	// failure, so (deny && mode == 2) still equals the LSM verdict. The
	// injector takes the init's next exec (its /bin/sh -c): Strict denies
	// it (126, no output), Audit allows it unevaluated.
	value, _ = gc.GetVar(operators.MapPrefix + "opaque_real_verdict_suspend_fault")
	suspend, _ := value.(*ebpf.Map)
	if suspend == nil {
		t.Fatal("IG_SHARED_VERDICT_OBJECT needs ENFORCE_EXEC_POOL_OPAQUE_VERDICT_SUSPEND_FAULT_DIAGNOSTIC (g19pkgevf128)")
	}
	for _, name := range []string{"A", "B"} {
		if err := suspend.Update(uint32(0), uint64(1), 0); err != nil {
			t.Fatal(err)
		}
		from := c.count()
		out, code, err := inits[name].run(ctx, "exit 0")
		want := map[string]int{"A": eperm, "B": 0}[name]
		if err != nil || code != want {
			t.Fatalf("suspend fault %s: %q code %d (want %d): %v", name, out, code, want, err)
		}
		var left uint64
		if err := suspend.Lookup(uint32(0), &left); err != nil || left != 0 {
			t.Fatalf("suspend-fault injector not consumed: %d %v", left, err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) && len(c.since(from, inits[name].ino)) < 1 {
			time.Sleep(20 * time.Millisecond)
		}
		time.Sleep(200 * time.Millisecond)
		got := c.since(from, inits[name].ino)
		if len(got) != 1 {
			t.Fatalf("suspend fault %s: %d events, want the one fault event: %+v", name, len(got), got)
		}
		e := got[0]
		if e.path != "" || e.deny != 1 || e.mode != classes[name] || e.errorCode != 1 || e.pass != SharedVerdictPassUnknown || e.execClass != classes[name] {
			t.Fatalf("suspend fault %s: event %+v, want the class fault", name, e)
		}
		if (e.deny == 1 && e.mode == 2) != (code == eperm) {
			t.Fatalf("suspend fault %s: event %+v disagrees with the LSM verdict (rc %d)", name, e, code)
		}
		t.Logf("suspend fault %s: rc %d, one fault event %+v", name, code, e)
	}

	k := drained(node, c, "events")
	if k.Lost != 0 || k.ObservationErrors != 0 {
		t.Fatalf("counters %+v", k)
	}
	if err := node.Ready(gc); !errors.Is(err, ErrSharedNativeUnavailable) || errors.Is(err, ErrSharedVerdictEventLoss) {
		t.Fatalf("Ready without loss: %v", err)
	}
	t.Logf("events: read %d = submitted, counters %+v", c.count(), k)
	stopped = true
	if err := node.StopNode(context.WithoutCancel(ctx)); err != nil {
		t.Fatalf("StopNode: %v", err)
	}
	if final, err := node.KernelEventCounters(); err != nil || !final.Final || final.Submitted != uint64(c.count()) {
		t.Fatalf("final counters %+v (%v), read %d", final, err, c.count())
	}

	// Starvation: a 4 KiB ring (11 events), the reader stalled, a Strict
	// deny storm. Delivery never decides a verdict: every exec is EPERM.
	c2 := &sharedVerdictCollector{}
	node2, gc2, ctx2 := startSharedVerdictNode(t, starve, c2)
	defer func() { _ = node2.StopNode(context.WithoutCancel(ctx2)) }()
	inits2, sessions2 := bind(node2, ctx2, "S")
	policy := &fullpolicy.Policy{
		ID: "g020-events-starve", Revision: "1", Mode: fullpolicy.Enforce, RootRole: "app", Default: fullpolicy.Allow,
		Rules: []fullpolicy.Rule{{Name: "interp", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{files.interp}}}},
	}
	if _, err := sessions2["S"].Publish(ctx2, SharedBindingPolicy{Source: policy, Container: "s"}); err != nil {
		t.Fatal(err)
	}
	c2.stall()
	const storm = 300
	out, code, err := inits2["S"].run(ctx2, fmt.Sprintf("n=0; for i in $(seq %d); do %s; [ $? -eq %d ] && n=$((n+1)); done; echo denied=$n", storm, files.interp, eperm))
	if err != nil || code != 0 || !strings.Contains(out, fmt.Sprintf("denied=%d", storm)) {
		c2.resume()
		t.Fatalf("storm: %q code %d: %v", out, code, err)
	}
	k2, err := node2.KernelEventCounters()
	if err != nil || k2.Lost == 0 || k2.Submitted+k2.Lost < storm {
		c2.resume()
		t.Fatalf("storm counters %+v (%v): want losses and every pass counted", k2, err)
	}
	if err := node2.Ready(gc2); !errors.Is(err, ErrSharedVerdictEventLoss) || !errors.Is(err, ErrSharedNativeUnavailable) {
		c2.resume()
		t.Fatalf("Ready after loss: %v (want Degraded only)", err)
	}
	c2.resume()
	k2 = drained(node2, c2, "starved")
	denied := 0
	for _, e := range c2.since(0, inits2["S"].ino) {
		if e.path != files.interp {
			continue // the init's own /bin/sh -c
		}
		if e.deny != 1 || e.mode != 2 || e.errorCode != 0 {
			t.Fatalf("storm event %+v", e)
		}
		denied++
	}
	if denied == 0 || denied >= storm {
		t.Fatalf("storm: %d deny events read of %d execs with %d lost", denied, storm, k2.Lost)
	}
	t.Logf("starvation: %d execs all EPERM, %d deny events read, counters %+v, read %d", storm, denied, k2, c2.count())
}
