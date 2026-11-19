// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// D1 (LSM-only prototype) semantic oracle. It drives the shared product
// engine (the product-control test twin built with ENFORCE_EXEC_D1_LSM_ONLY,
// its own product publisher, adoption and reaper) through StartNode on a
// stock distro kernel, with two bindings per node: A Strict and B Audit.
//
//	IG_D1_OBJECT        the D1 object (scripts/compile.sh d1oracle128)
//	IG_D1_CGROUP_ROOT   a dedicated parent cgroup, basename ig15-d1-*
//	IG_D1_HELPER        the static testdata/d1_oracle_helper.c build
//	IG_ENFORCE_EXEC_PROBED_KERNEL=1  the test-only admission override
//	                    (d1_unpinned_kernel_test.go)
//
// Root, initial pid/time namespaces, an isolated VM. The oracle creates
// and removes /d1 on the root filesystem.

const (
	d1Dir    = "/d1"
	d1EPERM  = 101 // helper child status: 100 + EPERM
	d1ENOENT = 2
	d1ENOEXE = 8
)

type d1Oracle struct {
	t        *testing.T
	node     *NodeEnforcer
	gc       *gadgetcontext.GadgetContext
	ctx      context.Context
	c        *sharedVerdictCollector
	inits    map[string]*sharedPipeInit
	sessions map[string]*BindingSession
	states   map[string]SharedRouteState
	compiled map[string]SharedCompiled
	revision int
	stopped  bool
	// witnessLatched: the test latched the kernel witness deliberately.
	witnessLatched bool
}

var d1Modes = map[string]fullpolicy.Mode{"A": fullpolicy.Enforce, "B": fullpolicy.Audit}

func d1Env(t *testing.T) (object, root, helper string) {
	t.Helper()
	object, root, helper = os.Getenv("IG_D1_OBJECT"), os.Getenv("IG_D1_CGROUP_ROOT"), os.Getenv("IG_D1_HELPER")
	if object == "" {
		t.Skip("set IG_D1_OBJECT on an isolated VM")
	}
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(root), "ig15-d1-") || helper == "" {
		t.Fatal("root, a dedicated ig15-d1-* cgroup root (IG_D1_CGROUP_ROOT) and IG_D1_HELPER required")
	}
	if err := checkSharedInitNamespaces(); err != nil {
		t.Fatalf("design 13.8: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	return object, root, helper
}

// d1InstallFiles creates /d1 with the helper under every path the oracle's
// rules select, and the files whose exec fails inside the kernel.
func d1InstallFiles(t *testing.T, helper string) {
	t.Helper()
	_ = os.RemoveAll(d1Dir)
	if err := os.Mkdir(d1Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d1Dir) })
	write := func(name string, data []byte) {
		if err := os.WriteFile(filepath.Join(d1Dir, name), data, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(d1Dir, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"helper", "promote-ok", "marker", "interp", "denied-interp"} {
		write(name, raw)
	}
	// ENOEXEC: no binfmt takes it (not ELF, no #!, no printable first line).
	garbage := bytes.Repeat([]byte{0x01, 0xfe, 0x00, 0x7f}, 1024)
	write("promote-enoexec", garbage)
	write("denied-enoexec", garbage)
	// A #! whose interpreter does not exist: ENOENT from binfmt_script.
	write("promote-badinterp", []byte("#!/d1/no-such-interpreter\n"))
	// An ELF whose PT_INTERP does not exist: ENOENT inside binfmt_elf, after
	// the bprm_check pass of the file itself.
	dynamic, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	const ld = "/lib64/ld-linux-x86-64.so.2"
	if !bytes.Contains(dynamic, []byte(ld)) {
		t.Fatalf("/usr/bin/true has no PT_INTERP %s to break", ld)
	}
	write("promote-elfnointerp", bytes.Replace(dynamic, []byte(ld), []byte("/d1xxx/ld-linux-x86-64.so.2"), 1))
	// A 3-pass #! chain ending in a missing interpreter.
	write("promote-chain0", []byte("#!/d1/chain1\n"))
	write("chain1", []byte("#!/d1/chain2\n"))
	write("chain2", []byte("#!/d1/no-such-interpreter\n"))
	// A successful 2-pass exec: the script, then the helper as interpreter.
	write("promote-script", []byte("#!/d1/interp marker-check\n"))
	// Pass 0 allowed, the interpreter pass denied.
	write("script-denied-interp", []byte("#!/d1/denied-interp noop\n"))
}

// d1Start starts one node over object with A (Strict) and B (Audit) bound.
func d1Start(t *testing.T) *d1Oracle {
	t.Helper()
	object, root, helper := d1Env(t)
	d1InstallFiles(t, helper)
	sharedCandidateNodeTimeout = 12 * time.Minute
	o := &d1Oracle{t: t, c: &sharedVerdictCollector{}, inits: map[string]*sharedPipeInit{}, sessions: map[string]*BindingSession{}, states: map[string]SharedRouteState{}, compiled: map[string]SharedCompiled{}}
	o.node, o.gc, o.ctx = startSharedVerdictNode(t, object, o.c)
	t.Cleanup(o.stop)
	for _, name := range []string{"A", "B"} {
		cgroup := filepath.Join(root, strings.ToLower(name)+"-"+strconv.Itoa(os.Getpid()))
		if err := os.MkdirAll(cgroup, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(cgroup) })
		p := startSharedPipeInitShell(t, cgroup, "ig15-d1-init-"+strings.ToLower(name), "/usr/bin/bash")
		t.Cleanup(p.stop)
		s, err := o.node.Bind(o.ctx, SharedBindingConfig{CgroupID: p.ino, InitHostPID: uint32(p.cmd.Process.Pid), Acquire: p.acquire})
		if err != nil {
			t.Fatalf("Bind %s: %v", name, err)
		}
		o.inits[name], o.sessions[name] = p, s
	}
	return o
}

func (o *d1Oracle) stop() {
	if o.stopped {
		return
	}
	o.stopped = true
	for _, p := range o.inits {
		p.stop()
	}
	// A teardown fault fails the test, except the kernel witness latched on
	// purpose by the ftrace window test.
	if err := o.node.StopNode(context.WithoutCancel(o.ctx)); err != nil && !(o.witnessLatched && errors.Is(err, ErrSharedKernelWitness)) {
		o.t.Errorf("StopNode: %v", err)
	}
}

// publishOne commits one revision to binding name, retrying the retryable
// refusal (in-flight claims or pins) only.
func (o *d1Oracle) publishOne(label, name string, def fullpolicy.Action, rules []fullpolicy.Rule) SharedRouteState {
	o.t.Helper()
	policy := &fullpolicy.Policy{ID: "d1-" + strings.ToLower(name), Revision: strconv.Itoa(o.revision), Mode: d1Modes[name], RootRole: "app", Default: def, Rules: rules}
	cp, err := o.sessions[name].Compile(SharedBindingPolicy{Source: policy, Container: strings.ToLower(name)})
	if err != nil {
		o.t.Fatalf("%s: compile %s: %v", label, name, err)
	}
	var st SharedRouteState
	for attempt := 0; ; attempt++ {
		st, err = o.sessions[name].PublishCompiled(o.ctx, cp)
		if err == nil || attempt == 100 || !strings.Contains(err.Error(), "retryable") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		o.t.Fatalf("%s: publish %s: %v", label, name, err)
	}
	if st.Generation != cp.Generation {
		o.t.Fatalf("%s: %s published generation %d, compiled %d", label, name, st.Generation, cp.Generation)
	}
	o.states[name], o.compiled[name] = st, cp
	return st
}

func (o *d1Oracle) publish(label string, def fullpolicy.Action, rules ...fullpolicy.Rule) {
	o.t.Helper()
	o.revision++
	for _, name := range []string{"A", "B"} {
		o.publishOne(label, name, def, rules)
	}
}

// run executes command in binding name's init and returns the helper's
// KEY=VALUE lines (every value of a key, in order) and the shell status.
func (o *d1Oracle) run(label, name, command string) (map[string][]int, int) {
	o.t.Helper()
	out, code, err := o.inits[name].run(o.ctx, command+"; echo SHELL=$?")
	if err != nil || code != 0 {
		o.t.Fatalf("%s %s: %q code %d: %v", label, name, out, code, err)
	}
	kv := map[string][]int{}
	for _, line := range strings.Split(out, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		n, err := strconv.Atoi(v)
		if err != nil {
			o.t.Fatalf("%s %s: line %q", label, name, line)
		}
		kv[k] = append(kv[k], n)
	}
	if len(kv["SHELL"]) != 1 {
		o.t.Fatalf("%s %s: no shell status in %q", label, name, out)
	}
	return kv, kv["SHELL"][0]
}

func d1One(kv map[string][]int, key string) int {
	if len(kv[key]) != 1 {
		return -1000 - len(kv[key])
	}
	return kv[key][0]
}

// events returns the events of binding name after index from whose path is
// one of paths, once there are at least n (waiting up to 10 s).
func (o *d1Oracle) events(label, name string, from, n int, paths ...string) []sharedVerdictEvent {
	o.t.Helper()
	mine := func() []sharedVerdictEvent {
		var out []sharedVerdictEvent
		for _, e := range o.c.since(from, o.inits[name].ino) {
			for _, p := range paths {
				if e.path == p {
					out = append(out, e)
				}
			}
		}
		return out
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && len(mine()) < n {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)
	got := mine()
	if len(got) != n {
		o.t.Fatalf("%s %s: %d events for %v, want %d: %+v", label, name, len(got), paths, n, got)
	}
	return got
}

func (o *d1Oracle) mapOf(name string) *ebpf.Map {
	o.t.Helper()
	value, _ := o.gc.GetVar(operators.MapPrefix + name)
	m, _ := value.(*ebpf.Map)
	if m == nil {
		o.t.Fatalf("map %s not published", name)
	}
	return m
}

func (o *d1Oracle) hasMap(name string) bool {
	value, _ := o.gc.GetVar(operators.MapPrefix + name)
	m, _ := value.(*ebpf.Map)
	return m != nil
}

func (o *d1Oracle) entries(name string) int {
	o.t.Helper()
	it := o.mapOf(name).Iterate()
	var key, value []byte
	n := 0
	for it.Next(&key, &value) {
		n++
	}
	if err := it.Err(); err != nil {
		o.t.Fatalf("iterate %s: %v", name, err)
	}
	return n
}

// reconciled requires the exec frame state of every finished exec to be
// gone: no outer or handler frame and no terminal receipt is left once the
// scenario's tasks returned from their execve (exactly-once completion).
func (o *d1Oracle) reconciled(label string) {
	o.t.Helper()
	var counts [3]int
	names := []string{"se_failure_outer_frames", "se_failure_handler_frames", "se_exec_terminal_receipts"}
	deadline := time.Now().Add(5 * time.Second)
	for {
		total := 0
		for i, name := range names {
			counts[i] = o.entries(name)
			total += counts[i]
		}
		if total == 0 {
			return
		}
		if time.Now().After(deadline) {
			o.t.Fatalf("%s: exec state not reconciled: outer frames %d, handler frames %d, terminal receipts %d", label, counts[0], counts[1], counts[2])
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (o *d1Oracle) capsuleStats() [15]uint64 {
	o.t.Helper()
	var stats [15]uint64
	if err := o.mapOf("se_exec_capsule_stats").Lookup(uint32(0), &stats); err != nil {
		o.t.Fatalf("capsule stats: %v", err)
	}
	return stats
}

// managed runs fn and requires the fail-closed witness to count its execs
// as managed attempts with no refusal of any class, no ENTRY and no
// ADMISSION fault: every verdict fn saw was a policy decision.
func (o *d1Oracle) managed(label string, fn func()) {
	o.t.Helper()
	before := sharedM4ReadWitness(o.t, o.gc)
	fn()
	after := sharedM4ReadWitness(o.t, o.gc)
	v, err := FailClosedProductRate(before.rates, after.rates, before.attempts, after.attempts, 0)
	attempts := (after.attempts[0] - before.attempts[0]) + (after.attempts[1] - before.attempts[1])
	if err != nil || attempts == 0 || v.Total != 0 || v.Entry != 0 || v.Admission != 0 {
		o.t.Fatalf("%s: witness %+v attempts +%d (%v); rates %v -> %v: want managed attempts with no fail-closed refusal", label, v, attempts, err, before.rates, after.rates)
	}
}

// recursionMisses is, per attached program, the number of times the kernel
// skipped it (the tracing recursion guard). A skipped terminal is a missed
// exec completion, so the oracle requires zero.
func (o *d1Oracle) recursionMisses() map[string]uint64 {
	o.t.Helper()
	out := map[string]uint64{}
	for name, r := range o.node.host.live.receipts {
		p, err := ebpf.NewProgramFromID(ebpf.ProgramID(r.ProgramID))
		if err != nil {
			o.t.Fatalf("program %s: %v", name, err)
		}
		st, err := p.Stats()
		p.Close()
		if err != nil {
			o.t.Fatalf("program %s stats: %v", name, err)
		}
		out[name] = st.RecursionMisses
	}
	return out
}

func d1Status(name string, strict, audit int) int {
	if name == "A" {
		return strict
	}
	return audit
}

var d1Never = fullpolicy.Rule{Name: "never", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{"/nonexistent/never"}}}

// TestD1OracleVerdicts: Strict deny, allow, Audit would-deny that does not
// block, fork/clone inheritance, an unknown task in a bound cgroup, and a
// fault before classification (the route-invariant admission fault), which
// denies in both modes.
func TestD1OracleVerdicts(t *testing.T) {
	o := d1Start(t)
	o.publish("uid", fullpolicy.Allow, d1Never, fullpolicy.Rule{Name: "uid1000", Action: fullpolicy.Deny, Actor: fullpolicy.Actor{UID: []int64{1000}}})
	marker := d1Dir + "/marker"
	for _, name := range []string{"A", "B"} {
		class := uint32(d1Status(name, 2, 1))
		o.managed("allow "+name, func() {
			from := o.c.count()
			kv, _ := o.run("allow", name, "/d1/helper asuid 0 /d1/marker noop")
			if st := d1One(kv, "ST"); st != 0 {
				t.Fatalf("allow %s: status %d, want 0", name, st)
			}
			e := o.events("allow", name, from, 1, marker)[0]
			if e.deny != 0 || e.errorCode != 0 || e.mode != class || e.execClass != class || e.generation != o.states[name].Generation {
				t.Fatalf("allow %s: event %+v", name, e)
			}
		})
		o.managed("deny "+name, func() {
			from := o.c.count()
			kv, _ := o.run("deny", name, "/d1/helper asuid 1000 /d1/marker noop")
			want := d1Status(name, d1EPERM, 0)
			if st := d1One(kv, "ST"); st != want {
				t.Fatalf("uid 1000 exec in %s: status %d, want %d", name, st, want)
			}
			e := o.events("deny", name, from, 1, marker)[0]
			if e.deny != 1 || e.errorCode != 0 || e.mode != class || e.execClass != class {
				t.Fatalf("uid 1000 exec in %s: event %+v, want deny 1 mode %d error 0", name, e, class)
			}
			t.Logf("%s: uid 1000 exec status %d, event deny %d mode %d (Strict deny / Audit would-deny, not blocked)", name, d1One(kv, "ST"), e.deny, e.mode)
		})
		// Inheritance: three fork+exec generations below the init, then the
		// uid 1000 exec. Its verdict is a policy decision (error 0) of the
		// bound generation, counted as a managed attempt.
		o.managed("inherit "+name, func() {
			from := o.c.count()
			kv, _ := o.run("inherit", name, "/d1/helper tree 3 1000 /d1/marker noop")
			want := d1Status(name, d1EPERM, 0)
			if st := d1One(kv, "ST"); st != want || len(kv["TREE_FAIL"]) != 0 {
				t.Fatalf("inherited exec in %s: %v, want ST=%d", name, kv, want)
			}
			e := o.events("inherit", name, from, 1, marker)[0]
			if e.deny != 1 || e.errorCode != 0 || e.mode != class {
				t.Fatalf("inherited exec in %s: event %+v", name, e)
			}
		})
		o.reconciled("verdicts " + name)
	}

	// An unknown task: a shell that joins the bound cgroup from the host has
	// no TASK. Its exec in place is refused under Strict (EPERM, bash 126);
	// Audit never blocks it. Both are counted ENTRY, never a policy verdict.
	for _, name := range []string{"A", "B"} {
		before := sharedM4ReadWitness(t, o.gc)
		cmd := exec.Command("/usr/bin/bash", "-c", `echo $$ > "$1/cgroup.procs" || exit 99; exec /d1/helper noop`, "ig15-d1-unknown", o.inits[name].path)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err := cmd.Run()
		code := 0
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else if err != nil {
			t.Fatalf("unknown task in %s: %v", name, err)
		}
		after := sharedM4ReadWitness(t, o.gc)
		entry := after.rates[FailClosedRateEntry] - before.rates[FailClosedRateEntry]
		want := d1Status(name, 126, 0)
		if code != want || entry != 1 {
			t.Fatalf("unknown task in %s: exit %d (want %d), ENTRY +%d (want 1), stderr %q", name, code, want, entry, stderr.String())
		}
		t.Logf("%s: unknown task exec exit %d, ENTRY +%d", name, code, entry)
	}

	// A fault before classification: the route-invariant admission fault
	// (test twin injector d1_preclass_fault). It denies in BOTH modes and is
	// counted ADMISSION; disarmed, the bindings decide again.
	// The non-twin product object has no injector: this pin (review F4: a
	// regression pin of the fault mapping, not evidence of a natural
	// pre-classification fault) runs on the test twin only.
	if os.Getenv("IG_D1_PRODUCT_OBJECT") == "1" {
		if o.hasMap("d1_preclass_fault") || o.hasMap("d1_skip_sys_exit") || o.hasMap("opaque_real_publish_fault") {
			t.Fatal("IG_D1_PRODUCT_OBJECT=1 but the object carries a test injector")
		}
		t.Log("product object: no test injector map (d1_preclass_fault, d1_skip_sys_exit, opaque_real_publish_fault absent)")
		o.reconciled("verdicts end")
		return
	}
	inject := o.mapOf("d1_preclass_fault")
	for _, name := range []string{"A", "B"} {
		before := sharedM4ReadWitness(t, o.gc)
		if err := inject.Update(uint32(0), o.inits[name].ino, ebpf.UpdateAny); err != nil {
			t.Fatalf("arm the pre-classification fault: %v", err)
		}
		// The init's own fork of /bin/sh still works (fork admission is not
		// injected); its exec of /bin/sh is refused, so the line fails.
		out, code, err := o.inits[name].run(o.ctx, "/d1/helper noop")
		if uerr := inject.Update(uint32(0), uint64(0), ebpf.UpdateAny); uerr != nil {
			t.Fatalf("disarm: %v", uerr)
		}
		after := sharedM4ReadWitness(t, o.gc)
		admission := after.rates[FailClosedRateAdmission] - before.rates[FailClosedRateAdmission]
		if err != nil || code != 126 || admission == 0 {
			t.Fatalf("pre-classification fault in %s: %q code %d (%v), ADMISSION +%d: want every exec refused (126) in every mode", name, out, code, err, admission)
		}
		kv, _ := o.run("after the fault", name, "/d1/helper asuid 0 /d1/marker noop")
		if st := d1One(kv, "ST"); st != 0 {
			t.Fatalf("%s after the fault was disarmed: %v", name, kv)
		}
		t.Logf("%s: pre-classification fault refused the exec (code %d, ADMISSION +%d); disarmed: allowed", name, code, admission)
	}
	o.reconciled("verdicts end")
}

// TestD1OracleExecFailures: an exec that fails in the kernel after an allow
// and after a deny (ENOEXEC, a missing #! interpreter, a missing ELF
// interpreter inside the binfmt, a 3-pass chain), interpreter passes, a
// non-leader thread's exec (de_thread), racing execs of one thread group,
// and execs racing a kill or a group exit. After each: the task's role is
// the one of its last SUCCESSFUL exec, its next exec is decided normally
// (no pending receipt), nothing is counted fail-closed, and no exec frame or
// receipt is left.
func TestD1OracleExecFailures(t *testing.T) {
	o := d1Start(t)
	promote := []string{"/d1/promote-ok", "/d1/promote-enoexec", "/d1/promote-badinterp", "/d1/promote-elfnointerp", "/d1/promote-chain0", "/d1/promote-script"}
	o.publish("roles", fullpolicy.Allow, d1Never,
		fullpolicy.Rule{Name: "promote", Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: promote, SetRole: "b"}},
		fullpolicy.Rule{Name: "b-marker", Action: fullpolicy.Deny, Actor: fullpolicy.Actor{Role: []string{"b"}}, Target: fullpolicy.Target{Path: []string{"/d1/marker"}}},
		fullpolicy.Rule{Name: "denied", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{"/d1/denied-enoexec", "/d1/denied-interp"}}})
	stats0 := o.capsuleStats()
	marker := "/d1/marker"
	for _, name := range []string{"A", "B"} {
		class := uint32(d1Status(name, 2, 1))
		roleB := d1Status(name, d1EPERM, 0) // the marker under role b
		step := func(label string, fn func()) {
			t.Helper()
			o.managed(label+" "+name, fn)
			o.reconciled(label + " " + name)
		}
		// requireMarker checks the marker exec's event of the scenario.
		requireMarker := func(label string, from int, denied bool) {
			t.Helper()
			e := o.events(label, name, from, 1, marker)[0]
			deny := uint32(0)
			if denied {
				deny = 1
			}
			if e.deny != deny || e.errorCode != 0 || e.mode != class {
				t.Fatalf("%s %s: marker event %+v, want deny %d error 0", label, name, e, deny)
			}
		}
		step("root role", func() {
			from := o.c.count()
			kv, _ := o.run("root role", name, "/d1/helper marker-check")
			if d1One(kv, "MARKER") != 0 {
				t.Fatalf("root role %s: %v", name, kv)
			}
			requireMarker("root role", from, false)
		})
		step("successful promote", func() {
			from := o.c.count()
			kv, _ := o.run("promote", name, "/d1/helper exec /d1/promote-ok marker-check")
			if d1One(kv, "MARKER") != roleB {
				t.Fatalf("promote %s: %v, want MARKER=%d (role b committed by the successful exec)", name, kv, roleB)
			}
			requireMarker("promote", from, true)
		})
		// Failures after an ALLOW with a role proposal: the exec fails in
		// the kernel, so the role must stay "app" (marker allowed, by the
		// same task's child) and the same task's next exec must succeed.
		for _, c := range []struct {
			label, path string
			errno       int
			passes      []string
		}{
			{"ENOEXEC after allow", "/d1/promote-enoexec", d1ENOEXE, []string{"/d1/promote-enoexec"}},
			{"missing #! interpreter after allow", "/d1/promote-badinterp", d1ENOENT, []string{"/d1/promote-badinterp"}},
			{"ENOENT inside binfmt_elf after allow", "/d1/promote-elfnointerp", d1ENOENT, []string{"/d1/promote-elfnointerp"}},
			{"3-pass chain failing after allow", "/d1/promote-chain0", d1ENOENT, []string{"/d1/promote-chain0", "/d1/chain1", "/d1/chain2"}},
		} {
			step(c.label, func() {
				from := o.c.count()
				kv, _ := o.run(c.label, name, "/d1/helper execfail "+c.path)
				if d1One(kv, "ERRNO") != c.errno || d1One(kv, "MARKER") != 0 || d1One(kv, "REEXEC") != 0 {
					t.Fatalf("%s %s: %v, want ERRNO=%d MARKER=0 REEXEC=0", c.label, name, kv, c.errno)
				}
				events := o.events(c.label, name, from, len(c.passes), c.passes...)
				for i, e := range events {
					if e.path != c.passes[i] || e.pass != uint32(i) || e.deny != 0 || e.errorCode != 0 || e.execID != events[0].execID || e.taskCookie != events[0].taskCookie {
						t.Fatalf("%s %s: pass %d event %+v (of %+v)", c.label, name, i, e, events)
					}
				}
				requireMarker(c.label, from, false)
			})
		}
		// Two passes of one successful exec: the role is committed once.
		step("2-pass #! success", func() {
			from := o.c.count()
			kv, _ := o.run("script", name, "/d1/helper exec /d1/promote-script x")
			if d1One(kv, "MARKER") != roleB {
				t.Fatalf("script %s: %v, want MARKER=%d", name, kv, roleB)
			}
			events := o.events("script", name, from, 2, "/d1/promote-script", "/d1/interp")
			if events[0].pass != 0 || events[1].pass != 1 || events[0].execID != events[1].execID || events[0].taskCookie != events[1].taskCookie || events[0].deny != 0 || events[1].deny != 0 {
				t.Fatalf("script %s: events %+v", name, events)
			}
			requireMarker("script", from, true)
		})
		// A failure after a DENY. Strict: the deny is the failure (EPERM).
		// Audit: would-deny, then the kernel's own ENOEXEC.
		step("ENOEXEC after deny", func() {
			from := o.c.count()
			kv, _ := o.run("denied enoexec", name, "/d1/helper execfail /d1/denied-enoexec")
			if d1One(kv, "ERRNO") != d1Status(name, 1, d1ENOEXE) || d1One(kv, "MARKER") != 0 || d1One(kv, "REEXEC") != 0 {
				t.Fatalf("denied enoexec %s: %v", name, kv)
			}
			e := o.events("denied enoexec", name, from, 1, "/d1/denied-enoexec")[0]
			if e.deny != 1 || e.mode != class || e.errorCode != 0 {
				t.Fatalf("denied enoexec %s: event %+v", name, e)
			}
		})
		// Pass 0 allowed, the interpreter pass denied: Strict fails the exec
		// after its first pass was allowed; Audit runs it.
		step("denied interpreter pass", func() {
			from := o.c.count()
			kv, _ := o.run("denied interp", name, "/d1/helper execfail /d1/script-denied-interp")
			if name == "A" {
				if d1One(kv, "ERRNO") != 1 || d1One(kv, "MARKER") != 0 || d1One(kv, "REEXEC") != 0 {
					t.Fatalf("denied interp A: %v", kv)
				}
			} else if len(kv["ERRNO"]) != 0 {
				t.Fatalf("denied interp B: %v: Audit must not block", kv)
			}
			events := o.events("denied interp", name, from, 2, "/d1/script-denied-interp", "/d1/denied-interp")
			if events[0].deny != 0 || events[1].deny != 1 || events[1].pass != 1 || events[1].mode != class || events[0].execID != events[1].execID {
				t.Fatalf("denied interp %s: events %+v", name, events)
			}
		})
		// de_thread: a non-leader thread execs; the role still commits.
		step("non-leader thread exec", func() {
			from := o.c.count()
			kv, _ := o.run("thread-exec", name, "/d1/helper thread-exec /d1/promote-ok marker-check")
			if d1One(kv, "MARKER") != roleB || len(kv["ERRNO"]) != 0 {
				t.Fatalf("thread-exec %s: %v, want MARKER=%d", name, kv, roleB)
			}
			requireMarker("thread-exec", from, true)
		})
		// Eight threads of one group exec at once: exactly one image runs.
		step("racing execs of one thread group", func() {
			for i := 0; i < 20; i++ {
				kv, _ := o.run("race-exec", name, "/d1/helper race-exec 8 /d1/promote-ok marker-check")
				if d1One(kv, "MARKER") != roleB {
					t.Fatalf("race-exec %s round %d: %v, want exactly one MARKER=%d", name, i, kv, roleB)
				}
			}
		})
		step("exec racing SIGKILL", func() {
			kv, _ := o.run("kill-race", name, "/d1/helper kill-race 300 /d1/promote-ok")
			if d1One(kv, "ITER") != 300 || d1One(kv, "KILLED")+d1One(kv, "RAN") != 300 {
				t.Fatalf("kill-race %s: %v", name, kv)
			}
			t.Logf("%s kill-race: %v", name, kv)
		})
		step("exec racing a thread-group exit", func() {
			kv, _ := o.run("exit-race", name, "/d1/helper exit-race 300 /d1/promote-ok")
			if d1One(kv, "ITER") != 300 || d1One(kv, "EXITED")+d1One(kv, "RAN") != 300 {
				t.Fatalf("exit-race %s: %v", name, kv)
			}
			t.Logf("%s exit-race: %v", name, kv)
		})
		// After every race: the binding still decides, from a clean state.
		step("after the races", func() {
			kv, _ := o.run("after", name, "/d1/helper marker-check; /d1/helper exec /d1/promote-ok marker-check")
			if len(kv["MARKER"]) != 2 || kv["MARKER"][0] != 0 || kv["MARKER"][1] != roleB {
				t.Fatalf("after the races %s: %v", name, kv)
			}
		})
	}
	for name, misses := range o.recursionMisses() {
		if misses != 0 {
			t.Fatalf("program %s was skipped %d times by the recursion guard", name, misses)
		}
	}
	t.Logf("recursion misses: 0 on all %d attached programs", len(o.node.host.live.receipts))
	stats := o.capsuleStats()
	delta := func(i int) uint64 { return stats[i] - stats0[i] }
	t.Logf("capsule stats delta: begin %d terminal %d success %d foreign-terminal %d stale-retired %d death-retired %d fault %d release-fault %d",
		delta(0), delta(8), delta(10), delta(9), delta(2), delta(14), delta(13), delta(12))
	// Every covered begin met its own terminal: none was retired as stale by
	// a later begin or at task death, and no capsule faulted.
	if delta(13) != 0 || delta(12) != 0 || delta(2) != 0 || delta(14) != 0 || delta(0) == 0 || delta(0) != delta(8) {
		t.Fatalf("capsule terminals: begin %d terminal %d stale %d death %d fault %d release-fault %d: want begin == terminal and no stale, death, fault", delta(0), delta(8), delta(2), delta(14), delta(13), delta(12))
	}
}

// TestD1OracleGenerationSwitch: revisions of A (Strict) and B (Audit)
// committed while four exec streams run in each binding. Every exec is
// decided by exactly one published generation: its event's verdict is that
// generation's, no exec faults, and after a Publish returns the next exec
// follows the new generation.
func TestD1OracleGenerationSwitch(t *testing.T) {
	o := d1Start(t)
	flip := fullpolicy.Rule{Name: "flip", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{"/d1/marker"}}}
	denies := map[string]map[uint64]bool{"A": {}, "B": {}}
	var mu sync.Mutex
	publish := func(k int) {
		o.revision++
		rules := []fullpolicy.Rule{d1Never}
		if k%2 == 1 {
			rules = append(rules, flip)
		}
		for _, name := range []string{"A", "B"} {
			st := o.publishOne("switch", name, fullpolicy.Allow, rules)
			mu.Lock()
			denies[name][st.Generation] = k%2 == 1
			mu.Unlock()
		}
	}
	publish(0)
	before := sharedM4ReadWitness(t, o.gc)
	from := o.c.count()
	const streams, rounds = 4, 500
	type result struct {
		kv  map[string][]int
		err string
	}
	results := map[string]result{}
	var wg sync.WaitGroup
	for _, name := range []string{"A", "B"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			line := fmt.Sprintf(`for j in $(seq %d); do ( i=0; while [ $i -lt %d ]; do /d1/helper marker-check; i=$((i+1)); done ) & done; wait`, streams, rounds)
			out, code, err := o.inits[name].run(o.ctx, line)
			kv := map[string][]int{}
			for _, l := range strings.Split(out, "\n") {
				if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok {
					n, _ := strconv.Atoi(v)
					kv[k] = append(kv[k], n)
				}
			}
			r := result{kv: kv}
			if err != nil || code != 0 {
				r.err = fmt.Sprintf("code %d err %v", code, err)
			}
			mu.Lock()
			results[name] = r
			mu.Unlock()
		}()
	}
	// Revisions while the streams run.
	revisions := 0
	for k := 1; k <= 12; k++ {
		time.Sleep(40 * time.Millisecond)
		publish(k)
		revisions++
	}
	wg.Wait()
	// The streams ended under revision 12 (allow). One more deny revision:
	// the first exec after Publish returned follows it.
	publish(13)
	for _, name := range []string{"A", "B"} {
		kv, _ := o.run("after the last revision", name, "/d1/helper marker-check")
		if want := d1Status(name, d1EPERM, 0); d1One(kv, "MARKER") != want {
			t.Fatalf("%s after the last (deny) revision: %v, want MARKER=%d", name, kv, want)
		}
	}
	after := sharedM4ReadWitness(t, o.gc)
	v, err := FailClosedProductRate(before.rates, after.rates, before.attempts, after.attempts, 0)
	for name, misses := range o.recursionMisses() {
		if misses != 0 {
			t.Logf("RECURSION-MISS program %s was skipped %d times by the kernel's recursion guard", name, misses)
		}
	}
	if err != nil || v.Total != 0 || v.Entry != 0 || v.Admission != 0 {
		t.Fatalf("fail-closed witness during the switches: %+v (%v); rates %v -> %v", v, err, before.rates, after.rates)
	}
	for _, name := range []string{"A", "B"} {
		r := results[name]
		if r.err != "" || len(r.kv["MARKER"]) != streams*rounds {
			t.Fatalf("%s streams: %s, %d results, want %d", name, r.err, len(r.kv["MARKER"]), streams*rounds)
		}
		allowed, denied := 0, 0
		for _, m := range r.kv["MARKER"] {
			switch {
			case m == 0:
				allowed++
			case m == d1EPERM && name == "A":
				denied++
			default:
				t.Fatalf("%s stream result MARKER=%d: neither generation's verdict", name, m)
			}
		}
		// Every marker exec has exactly one decision event, of one published
		// generation, with that generation's verdict.
		deadline := time.Now().Add(20 * time.Second)
		var events []sharedVerdictEvent
		for {
			events = events[:0]
			for _, e := range o.c.since(from, o.inits[name].ino) {
				if e.path == "/d1/marker" {
					events = append(events, e)
				}
			}
			if len(events) >= streams*rounds+1 || time.Now().After(deadline) {
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if len(events) != streams*rounds+1 {
			t.Fatalf("%s: %d marker events, want %d", name, len(events), streams*rounds+1)
		}
		seen := map[uint64]int{}
		eventDenied := 0
		for _, e := range events {
			want, known := denies[name][e.generation]
			if !known || e.errorCode != 0 || (e.deny == 1) != want {
				t.Fatalf("%s: event %+v: generation known %v, its verdict deny=%v", name, e, known, want)
			}
			seen[e.generation]++
			if e.deny == 1 {
				eventDenied++
			}
		}
		if name == "A" && eventDenied != denied+1 {
			t.Fatalf("A: %d deny events, %d refused execs (+1 after the last revision)", eventDenied, denied)
		}
		var gens []uint64
		for g := range seen {
			gens = append(gens, g)
		}
		sort.Slice(gens, func(i, j int) bool { return gens[i] < gens[j] })
		if len(gens) < 6 {
			t.Fatalf("%s: the streams saw only generations %v: no switch overlapped them", name, gens)
		}
		t.Logf("%s: %d execs over %d revisions: %d allowed, %d refused; generations seen %v (execs per generation %v)", name, streams*rounds, revisions, allowed, denied, gens, seen)
	}
	o.reconciled("generation switch")
}

// TestD1OracleRefusesUnpinnedKernel: without the test-only override the
// engine refuses a kernel outside its pinned list; nothing is loaded. On a
// pinned build it shows the converse: admitted and started without it.
func TestD1OracleRefusesUnpinnedKernel(t *testing.T) {
	object, _, _ := d1Env(t)
	digest, err := kernelBTFDigest()
	if err != nil {
		t.Fatal(err)
	}
	saved := sharedProbedKernelOverride
	if _, pinned := sharedCandidateKernelBTF[digest]; pinned {
		// A pinned build (the AL2023 qualification runs): the same gate,
		// without the override, must ADMIT it, and the node must start.
		sharedProbedKernelOverride = func() bool { return false }
		defer func() { sharedProbedKernelOverride = saved }()
		if err := verifySharedCandidateKernel(); err != nil {
			t.Fatalf("pinned kernel (BTF %s) refused without the override: %v", digest, err)
		}
		node, _, ctx, err := startSharedCandidateNodeE(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, nil)
		if err != nil {
			t.Fatalf("StartNode on the pinned kernel without the override: %v", err)
		}
		if err := node.StopNode(context.WithoutCancel(ctx)); err != nil {
			t.Fatalf("StopNode: %v", err)
		}
		t.Logf("pinned kernel (BTF %s): admitted and started without the override", digest)
		return
	}
	sharedProbedKernelOverride = func() bool { return false }
	defer func() { sharedProbedKernelOverride = saved }()
	node, _, ctx, err := startSharedCandidateNodeE(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, nil)
	if err == nil {
		_ = node.StopNode(context.WithoutCancel(ctx))
		t.Fatal("StartNode admitted an unpinned kernel without the override")
	}
	if !strings.Contains(err.Error(), "outside proved shared candidate matrix") {
		t.Fatalf("refusal reason: %v", err)
	}
	t.Logf("refused (BTF %s): %v", digest, err)
}

// TestD1OracleRefusesWithoutBPFLSM: run on a boot WITHOUT bpf in the active
// LSM list (IG_D1_NO_BPF_LSM_BOOT=1). Even with the test-only override the
// engine refuses to start.
func TestD1OracleRefusesWithoutBPFLSM(t *testing.T) {
	object, _, _ := d1Env(t)
	if os.Getenv("IG_D1_NO_BPF_LSM_BOOT") != "1" {
		t.Skip("set IG_D1_NO_BPF_LSM_BOOT=1 on a boot without the bpf LSM")
	}
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Fatal(err)
	}
	if requireBPFLSM(string(lsm)) == nil {
		t.Fatalf("this boot has the bpf LSM active (%s)", strings.TrimSpace(string(lsm)))
	}
	if !sharedProbedKernelOverride() {
		t.Fatal(SharedProbedKernelEnv + "=1 required: the refusal must come from the LSM check, not the pin")
	}
	node, _, ctx, err := startSharedCandidateNodeE(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, nil)
	if err == nil {
		_ = node.StopNode(context.WithoutCancel(ctx))
		t.Fatal("StartNode admitted a kernel without the bpf LSM")
	}
	if !strings.Contains(err.Error(), "BPF LSM not active") {
		t.Fatalf("refusal reason: %v", err)
	}
	t.Logf("refused (lsm=%s): %v", strings.TrimSpace(string(lsm)), err)
}

// TestD1FtraceMeasurement is a MEASUREMENT, not an oracle case: what
// kernel.ftrace_enabled=0 does to the D1 attach set (BPF LSM trampolines
// and tracepoint programs) on this kernel. It records, per attached
// program, its run count over the same exec batch with ftrace on, off and
// on again, the Strict verdict in each phase, and whether the runtime
// check reports it. It fails only if enforcement does not come back.
func TestD1FtraceMeasurement(t *testing.T) {
	if os.Getenv("IG_D1_FTRACE_MEASURE") != "1" {
		t.Skip("set IG_D1_FTRACE_MEASURE=1")
	}
	// Syscall cost of the tp_btf/sys_exit programs: a getppid loop in the
	// test's own (unbound) cgroup before the node attaches and after.
	bench := func(label string) {
		out, err := exec.Command(os.Getenv("IG_D1_HELPER"), "bench", "2000000").CombinedOutput()
		t.Logf("SYSCALL-COST %s: %s (%v)", label, strings.TrimSpace(string(out)), err)
	}
	bench("before attach")
	o := d1Start(t)
	bench("attached, no binding published")
	o.publish("uid", fullpolicy.Allow, d1Never, fullpolicy.Rule{Name: "uid1000", Action: fullpolicy.Deny, Actor: fullpolicy.Actor{UID: []int64{1000}}})
	bench("attached, two bindings published")
	const ftrace, stats = "/proc/sys/kernel/ftrace_enabled", "/proc/sys/kernel/bpf_stats_enabled"
	if err := os.WriteFile(stats, []byte("1"), 0o644); err != nil {
		t.Fatalf("bpf_stats_enabled: %v", err)
	}
	defer func() { _ = os.WriteFile(stats, []byte("0"), 0o644) }()
	runs := func() map[string]uint64 {
		out := map[string]uint64{}
		for name, r := range o.node.host.live.receipts {
			p, err := ebpf.NewProgramFromID(ebpf.ProgramID(r.ProgramID))
			if err != nil {
				t.Fatalf("program %s: %v", name, err)
			}
			st, err := p.Stats()
			p.Close()
			if err != nil {
				t.Fatalf("program %s stats: %v", name, err)
			}
			out[name+" ("+r.Target+")"] = st.RunCount
		}
		return out
	}
	phase := func(label string) (int, map[string]uint64) {
		before := runs()
		kv, _ := o.run(label, "A", "/d1/helper asuid 1000 /d1/marker noop; /d1/helper asuid 1000 /d1/marker noop; /d1/helper asuid 1000 /d1/marker noop")
		after := runs()
		delta := map[string]uint64{}
		for k := range after {
			delta[k] = after[k] - before[k]
		}
		st := -1
		if len(kv["ST"]) == 3 && kv["ST"][0] == kv["ST"][1] && kv["ST"][1] == kv["ST"][2] {
			st = kv["ST"][0]
		}
		var names []string
		for k := range delta {
			names = append(names, k)
		}
		sort.Strings(names)
		for _, k := range names {
			t.Logf("FTRACE-MEASURE %s: runs +%d %s", label, delta[k], k)
		}
		t.Logf("FTRACE-MEASURE %s: Strict uid-1000 exec status %d (101 = EPERM, 0 = allowed); CheckKernelRuntime: %v", label, st, CheckKernelRuntime())
		return st, delta
	}
	on, _ := phase("ftrace=1")
	if on != d1EPERM {
		t.Fatalf("ftrace on: Strict status %d, want %d", on, d1EPERM)
	}
	o.witnessLatched = true // the window latches the kernel witness
	werr := os.WriteFile(ftrace, []byte("0"), 0o644)
	t.Logf("FTRACE-MEASURE write ftrace_enabled=0: %v", werr)
	now, _ := os.ReadFile(ftrace)
	t.Logf("FTRACE-MEASURE ftrace_enabled now %s", strings.TrimSpace(string(now)))
	off, offDelta := phase("ftrace=0")
	if err := os.WriteFile(ftrace, []byte("1"), 0o644); err != nil {
		t.Fatalf("restore ftrace_enabled=1: %v", err)
	}
	back, _ := phase("ftrace=1 again")
	lsmRuns, tpRuns := uint64(0), uint64(0)
	for k, n := range offDelta {
		if strings.Contains(k, "(task_free)") || strings.Contains(k, "(task_alloc)") || strings.Contains(k, "(bprm_") {
			lsmRuns += n
		} else {
			tpRuns += n
		}
	}
	verdict := "ENFORCED (deny kept)"
	if off == 0 {
		verdict = "FAIL-OPEN (Strict deny became allow)"
	}
	t.Logf("FTRACE-MEASURE RESULT: sysctl write error %v; with ftrace_enabled=0: %s; BPF LSM program runs %d, tracepoint program runs %d; restored: status %d", werr, verdict, lsmRuns, tpRuns, back)
	if back != d1EPERM {
		t.Fatalf("enforcement did not come back with ftrace re-enabled: status %d", back)
	}
}

// TestD1OracleStaleFrameHeal (review F1): a task whose syscall-exit programs
// never run (the test twin's d1_skip_sys_exit injector stands in for a task
// that missed the kernel's syscall-tracepoint flag) keeps its exec frame.
// Its next exec must heal it at begin instead of failing closed for ever:
// after a SUCCESSFUL exec the stale frame is dropped; after a FAILED exec
// that was allowed with a role proposal the pending receipt gets its FAILURE
// terminal there (self_exec_id unchanged), the role is not committed and the
// exec is decided normally. Nothing is counted fail-closed.
func TestD1OracleStaleFrameHeal(t *testing.T) {
	o := d1Start(t)
	o.publish("roles", fullpolicy.Allow, d1Never,
		fullpolicy.Rule{Name: "promote", Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: []string{"/d1/promote-ok", "/d1/promote-enoexec"}, SetRole: "b"}},
		fullpolicy.Rule{Name: "b-marker", Action: fullpolicy.Deny, Actor: fullpolicy.Actor{Role: []string{"b"}}, Target: fullpolicy.Target{Path: []string{"/d1/marker"}}})
	skip := o.mapOf("d1_skip_sys_exit")
	healed := func() uint64 {
		cells, _ := o.node.KernelWitness()
		return cells[5]
	}
	for _, name := range []string{"A", "B"} {
		before := healed()
		if err := skip.Update(uint32(0), o.inits[name].ino, ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		o.managed("stale frames "+name, func() {
			// Failed exec in a task of root role: ENOEXEC, then the same
			// task execs again: allowed, role still "app" (marker runs).
			kv, _ := o.run("failed then exec", name, "/d1/helper execfail2 /d1/promote-enoexec")
			if d1One(kv, "ERRNO") != d1ENOEXE || d1One(kv, "REEXEC") != 0 || d1One(kv, "MARKER") != 0 {
				t.Fatalf("%s failed exec with a skipped exit: %v, want ERRNO=8 REEXEC=0 MARKER=0", name, kv)
			}
			// Successful promote (stale frame of a committed exec), then a
			// failed exec, then another exec: role b kept, nothing more.
			kv, _ = o.run("promote, fail, exec", name, "/d1/helper exec /d1/promote-ok execfail2 /d1/promote-enoexec")
			if d1One(kv, "ERRNO") != d1ENOEXE || d1One(kv, "REEXEC") != 0 || d1One(kv, "MARKER") != d1Status(name, d1EPERM, 0) {
				t.Fatalf("%s promote, failed exec, exec with skipped exits: %v", name, kv)
			}
		})
		if err := skip.Update(uint32(0), uint64(0), ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
		if got := healed() - before; got < 4 {
			t.Fatalf("%s: %d stale frames healed, want at least 4", name, got)
		}
		t.Logf("%s: every exec decided with the syscall-exit programs skipped; %d stale frames healed at begin", name, healed()-before)
		// The tasks are gone: task_free removed their last frames.
		o.reconciled("stale frames " + name)
		o.managed("after "+name, func() {
			kv, _ := o.run("after", name, "/d1/helper marker-check")
			if d1One(kv, "MARKER") != 0 {
				t.Fatalf("%s after: %v", name, kv)
			}
		})
	}
	if _, err := o.node.KernelWitness(); err != nil {
		t.Fatalf("kernel witness after the heal scenario: %v", err)
	}
}

// requireWitnessSignals asserts the armed ftrace ksym and which of the
// three witness signals latched: [4] ftrace read as 0, [6] an unmarked exec,
// [7] an unmarked fork.
func (o *d1Oracle) requireWitnessSignals(label string, ftraceOff, exec, fork bool) [sharedKernelWitnessCells]uint64 {
	o.t.Helper()
	cells, _ := o.node.KernelWitness()
	o.t.Logf("%s: witness cells %v", label, cells)
	if cells[sharedWitnessKsymResolved] != 1 || cells[sharedWitnessKsymMissing] != 0 {
		o.t.Fatalf("%s: ftrace ksym not armed: %v", label, cells)
	}
	for _, sig := range []struct {
		name string
		cell int
		want bool
	}{{"ftrace off [4]", sharedWitnessFtraceOff, ftraceOff}, {"unmarked exec [6]", sharedWitnessExecUnmarked, exec}, {"unmarked fork [7]", sharedWitnessForkUnmarked, fork}} {
		if got := cells[sig.cell] != 0; got != sig.want {
			o.t.Fatalf("%s: signal %s latched=%v, want %v (cells %v)", label, sig.name, got, sig.want, cells)
		}
	}
	return cells
}

// TestD1OracleFtraceWitness (review F2 and F3): kernel.ftrace_enabled is
// switched off and back on BETWEEN two status reads. While it is off the
// attach canary must fail and name exactly the BPF LSM programs; after it is
// back on, the node must still report NotReady: the kernel witness latched
// (ErrSharedKernelWitness, in KernelWitness, liveHealthFault and Ready) and
// stays latched over later clean readings.
func TestD1OracleFtraceWitness(t *testing.T) {
	o := d1Start(t)
	o.publish("uid", fullpolicy.Allow, d1Never, fullpolicy.Rule{Name: "uid1000", Action: fullpolicy.Deny, Actor: fullpolicy.Actor{UID: []int64{1000}}})
	const ftrace = "/proc/sys/kernel/ftrace_enabled"
	receipts := o.node.host.live.receipts
	if err := runSharedAttachCanary(receipts); err != nil {
		t.Fatalf("attach canary on the live node: %v", err)
	}
	t.Logf("attach canary: all %d attached programs ran during a fork+exec+exit", len(receipts))
	if cells, err := o.node.KernelWitness(); err != nil || o.node.liveHealthFault() != nil {
		t.Fatalf("witness before the window: %v %v (health %v)", cells, err, o.node.liveHealthFault())
	}
	if err := os.WriteFile(ftrace, []byte("0"), 0o644); err != nil {
		t.Fatalf("ftrace_enabled=0: %v", err)
	}
	o.witnessLatched = true
	kv, _ := o.run("window", "A", "/d1/helper asuid 1000 /d1/marker noop")
	canary := runSharedAttachCanary(receipts)
	if err := os.WriteFile(ftrace, []byte("1"), 0o644); err != nil {
		t.Fatalf("restore ftrace_enabled=1: %v", err)
	}
	t.Logf("in the window: Strict uid-1000 exec status %d (101 EPERM, 0 allowed); canary: %v", d1One(kv, "ST"), canary)
	if canary == nil {
		t.Fatal("the attach canary passed with ftrace off")
	}
	for name, r := range receipts {
		lsm := strings.HasPrefix(r.Target, "task_") || strings.HasPrefix(r.Target, "bprm_")
		if named := strings.Contains(canary.Error(), name+" ("); named != lsm {
			t.Fatalf("canary with ftrace off: program %s (%s) named %v, want %v: %v", name, r.Target, named, lsm, canary)
		}
	}
	// ftrace is on again and no status read happened in the window.
	if err := CheckKernelRuntime(); err != nil {
		t.Fatalf("runtime check after the window: %v", err)
	}
	// S1 review F2(3): the specific signals that latched. The window ran
	// forks and execs (the helper, the canary) with every BPF LSM program
	// silenced, so each of the three signals must have fired by itself.
	o.requireWitnessSignals("ftrace window", true, true, true)
	for i := 0; i < 3; i++ {
		cells, err := o.node.KernelWitness()
		if !errors.Is(err, ErrSharedKernelWitness) {
			t.Fatalf("read %d after the window: witness %v, fault %v: want the latched ErrSharedKernelWitness", i, cells, err)
		}
		if h := o.node.liveHealthFault(); !errors.Is(h, ErrSharedKernelWitness) {
			t.Fatalf("read %d: liveHealthFault %v", i, h)
		}
		if r := o.node.Ready(o.gc); !errors.Is(r, ErrSharedKernelWitness) {
			t.Fatalf("read %d: Ready %v: want NotReady with the kernel witness", i, r)
		}
		if i == 0 {
			t.Logf("after the window (ftrace on again): witness cells %v; Ready: %v", cells, err)
		}
		// Clean execs after the window never clear the latch.
		after, _ := o.run("after", "A", "/d1/helper asuid 1000 /d1/marker noop")
		if d1One(after, "ST") != d1EPERM {
			t.Fatalf("enforcement after the window: %v", after)
		}
	}
}

// d1BankCgroup is a cgroup with pids.max=1 outside every binding: its one
// task's forks fail in cgroup_can_fork, after security_task_alloc.
func d1BankCgroup(t *testing.T) *os.File {
	t.Helper()
	const root = "/sys/fs/cgroup"
	dir := filepath.Join(root, "ig15-d1-bank")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	if _, err := os.Stat(filepath.Join(dir, "pids.max")); err != nil {
		if err := os.WriteFile(filepath.Join(root, "cgroup.subtree_control"), []byte("+pids"), 0o644); err != nil {
			t.Fatalf("enable the pids controller: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "pids.max"), []byte("1"), 0o644); err != nil {
		t.Fatalf("pids.max: %v", err)
	}
	fd, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { fd.Close() })
	return fd
}

// d1HelperKV runs the helper outside every binding and parses its lines.
func d1HelperKV(t *testing.T, cgroup *os.File, args ...string) map[string]int {
	t.Helper()
	cmd := exec.Command("/d1/helper", args...)
	if cgroup != nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("helper %v: %v (%q)", args, err, out)
	}
	kv := map[string]int{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			n, err := strconv.Atoi(v)
			if err != nil {
				t.Fatalf("helper %v: line %q", args, line)
			}
			kv[k] = n
		}
	}
	return kv
}

// TestD1OracleWitnessBankedCredit (S1 review F2): forks that fail after
// lsm/task_alloc (pids.max) and execs that fail after the point of no
// return (RLIMIT_AS) bank "LSM ran, tracepoint did not" events. With the
// D1 cumulative-count comparison that credit masked a later silenced
// window. With per-task marks, a short ftrace-off window that runs FEWER
// unhooked execs and forks than the banked credit still latches both the
// exec and the fork signal, and the node stays NotReady.
func TestD1OracleWitnessBankedCredit(t *testing.T) {
	o := d1Start(t)
	o.publish("uid", fullpolicy.Allow, d1Never, fullpolicy.Rule{Name: "uid1000", Action: fullpolicy.Deny, Actor: fullpolicy.Actor{UID: []int64{1000}}})
	before, err := o.node.KernelWitness()
	if err != nil {
		t.Fatalf("witness before banking: %v %v", before, err)
	}
	const forks, execs = 1000, 300
	bank := d1BankCgroup(t)
	f := d1HelperKV(t, bank, "bank-forks", strconv.Itoa(forks))
	e := d1HelperKV(t, nil, "late-exec", strconv.Itoa(execs), "/d1/helper", "200000")
	t.Logf("banking: forks EAGAIN %d ok %d; execs killed after the point of no return %d, failed before %d", f["FORK_EAGAIN"], f["FORK_OK"], e["LATE"], e["EARLY"])
	if f["FORK_EAGAIN"] < forks*9/10 || e["LATE"] < execs*9/10 {
		t.Fatalf("could not bank credit: %v %v", f, e)
	}
	banked, err := o.node.KernelWitness()
	if err != nil {
		t.Fatalf("banked credit latched by itself (it must not): %v %v", banked, err)
	}
	execCredit := int64(banked[sharedWitnessLSMCommit]-banked[sharedWitnessTPExec]) - int64(before[sharedWitnessLSMCommit]-before[sharedWitnessTPExec])
	forkCredit := int64(banked[sharedWitnessLSMAlloc]-banked[sharedWitnessTPFork]) - int64(before[sharedWitnessLSMAlloc]-before[sharedWitnessTPFork])
	t.Logf("banked credit: exec %d, fork %d (cells %v)", execCredit, forkCredit, banked)
	if execCredit < execs*9/10 || forkCredit < forks*9/10 {
		t.Fatalf("the counts did not bank the credit (exec %d, fork %d)", execCredit, forkCredit)
	}
	const ftrace = "/proc/sys/kernel/ftrace_enabled"
	if err := os.WriteFile(ftrace, []byte("0"), 0o644); err != nil {
		t.Fatalf("ftrace_enabled=0: %v", err)
	}
	o.witnessLatched = true
	for i := 0; i < 3; i++ {
		_ = exec.Command("/d1/helper", "noop").Run()
	}
	if err := os.WriteFile(ftrace, []byte("1"), 0o644); err != nil {
		t.Fatalf("restore ftrace_enabled=1: %v", err)
	}
	cells := o.requireWitnessSignals("banked window", true, true, true)
	// The window's unhooked events stayed below the banked credit: the D1
	// count comparison (tp > lsm) would NOT have fired.
	if cells[sharedWitnessTPExec] > cells[sharedWitnessLSMCommit] || cells[sharedWitnessTPFork] > cells[sharedWitnessLSMAlloc] {
		t.Fatalf("the window exceeded the banked credit (cells %v): the masking case was not reproduced", cells)
	}
	t.Logf("masking reproduced: tp exec %d <= lsm commit %d, tp fork %d <= lsm alloc %d; marks latched exec %d fork %d", cells[0], cells[1], cells[2], cells[3], cells[6], cells[7])
	for i := 0; i < 2; i++ {
		if _, err := o.node.KernelWitness(); !errors.Is(err, ErrSharedKernelWitness) || !strings.Contains(err.Error(), "without the lsm/bprm_committed_creds mark") || !strings.Contains(err.Error(), "without the lsm/task_alloc mark") {
			t.Fatalf("read %d: %v", i, err)
		}
		if r := o.node.Ready(o.gc); !errors.Is(r, ErrSharedKernelWitness) {
			t.Fatalf("read %d: Ready %v: want NotReady with the kernel witness", i, r)
		}
	}
}

// TestD1OracleRefusesUnresolvedFtraceKsym (S1 review F2(1)): an object whose
// ftrace_enabled weak ksym does not resolve (the twin built with
// ENFORCE_EXEC_D1_UNRESOLVED_KSYM_DIAGNOSTIC names a symbol no kernel has,
// as on a kernel without CONFIG_KALLSYMS_ALL) never starts: StartNode
// refuses after the canary with the kernel witness reason.
func TestD1OracleRefusesUnresolvedFtraceKsym(t *testing.T) {
	_, _, _ = d1Env(t)
	object := os.Getenv("IG_D1_NOSYM_OBJECT")
	if object == "" {
		t.Fatal("IG_D1_NOSYM_OBJECT required (the unresolved-ksym twin)")
	}
	node, _, ctx, err := startSharedCandidateNodeE(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, nil)
	if err == nil {
		_ = node.StopNode(context.WithoutCancel(ctx))
		t.Fatal("StartNode admitted an object whose ftrace_enabled ksym did not resolve")
	}
	if !errors.Is(err, ErrSharedKernelWitness) || !strings.Contains(err.Error(), "ftrace_enabled ksym did not resolve") {
		t.Fatalf("refusal reason: %v", err)
	}
	t.Logf("refused: %v", err)
}

// TestD1OracleCanaryRefusesWithoutBPFLSM (S1 review, canary as a second
// line): on a boot WITHOUT bpf in the active LSM list, with the userspace
// LSM-list check bypassed (qualification-only knob), the links attach but
// no BPF LSM program ever runs: the startup canary alone must refuse
// StartNode and name every LSM program and no tracepoint program.
func TestD1OracleCanaryRefusesWithoutBPFLSM(t *testing.T) {
	object, _, _ := d1Env(t)
	if os.Getenv("IG_D1_NO_BPF_LSM_BOOT") != "1" {
		t.Fatal("IG_D1_NO_BPF_LSM_BOOT=1 required (a boot without the bpf LSM)")
	}
	lsm, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Fatal(err)
	}
	if requireBPFLSM(string(lsm)) == nil {
		t.Fatalf("this boot has the bpf LSM active (%s)", strings.TrimSpace(string(lsm)))
	}
	if !sharedSkipLSMListGate() {
		t.Fatal("IG_ENFORCE_EXEC_PROBED_KERNEL=1 and IG_ENFORCE_EXEC_SKIP_LSM_LIST_GATE=1 required in a qualification build")
	}
	node, _, ctx, err := startSharedCandidateNodeE(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, nil)
	if err == nil {
		_ = node.StopNode(context.WithoutCancel(ctx))
		t.Fatal("StartNode admitted a kernel without the bpf LSM (canary bypassed?)")
	}
	msg := err.Error()
	if !strings.Contains(msg, "attach canary: attached but never ran") {
		t.Fatalf("refusal is not the canary's: %v", err)
	}
	for _, lsmTarget := range []string{"(bprm_creds_for_exec)", "(bprm_check_security)", "(bprm_committed_creds)", "(task_alloc)", "(task_free)"} {
		if !strings.Contains(msg, lsmTarget) {
			t.Fatalf("canary does not name the LSM program on %s: %v", lsmTarget, err)
		}
	}
	for _, tp := range []string{"(sys_exit)", "(sched_process_exec)", "(sched_process_fork)", "(sched_process_exit)"} {
		if strings.Contains(msg, tp) {
			t.Fatalf("canary names a tracepoint program %s as silent: %v", tp, err)
		}
	}
	t.Logf("canary refused: %v", err)
}

// d1HeldHelper starts the helper in cgroup (outside every binding) and
// reads its KEY=VALUE lines until key appears; release ends it.
func d1HeldHelper(t *testing.T, cgroup *os.File, key string, args ...string) (value int, lines map[string]int, release func(), err error) {
	t.Helper()
	cmd := exec.Command("/d1/helper", args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cgroup.Fd())}
	stdin, perr := cmd.StdinPipe()
	if perr != nil {
		t.Fatal(perr)
	}
	stdout, perr := cmd.StdoutPipe()
	if perr != nil {
		t.Fatal(perr)
	}
	if perr := cmd.Start(); perr != nil {
		t.Fatal(perr)
	}
	released := false
	release = func() {
		if released {
			return
		}
		released = true
		_ = stdin.Close()
		_ = cmd.Wait()
	}
	t.Cleanup(release)
	lines = map[string]int{}
	scan := bufio.NewScanner(stdout)
	for scan.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(scan.Text()), "=")
		if !ok {
			continue
		}
		n, aerr := strconv.Atoi(v)
		if aerr != nil {
			t.Fatalf("helper %v: line %q", args, scan.Text())
		}
		lines[k] = n
		if k == key {
			return n, lines, release, nil
		}
	}
	release()
	return 0, lines, release, fmt.Errorf("helper %v ended without %s (lines %v)", args, key, lines)
}

// TestD1OracleWitnessManyMarks (S1 review N1): more than 8192 (the former
// HASH capacity of each mark map) io_uring io-wq workers (create_io_thread:
// a task_alloc fork mark, never a sched_process_fork) AND more than 8192
// unreaped zombies of execs killed after the point of no return (an exec
// mark, never a sched_process_exec), all held at once, outside every
// binding. With task-storage marks each task holds only its own mark: no
// mark creation fails, the node never latches, enforcement still works,
// and afterwards an ftrace window still latches every signal.
func TestD1OracleWitnessManyMarks(t *testing.T) {
	o := d1Start(t)
	o.publish("uid", fullpolicy.Allow, d1Never, fullpolicy.Rule{Name: "uid1000", Action: fullpolicy.Deny, Actor: fullpolicy.Actor{UID: []int64{1000}}})
	const many = 8300 // > 8192
	before, err := o.node.KernelWitness()
	if err != nil {
		t.Fatalf("witness before: %v %v", before, err)
	}
	// Its own cgroup, without a pids limit (a service's TasksMax would
	// stop it far below the number of tasks needed).
	dir := "/sys/fs/cgroup/ig15-d1-many"
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(dir) })
	cg, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cg.Close() })
	// The two halves are independent: a failure of one is reported and the
	// other still runs and is judged.
	zombies, zl, releaseZombies, zerr := d1HeldHelper(t, cg, "ZOMBIES", "zombies", strconv.Itoa(many), "/d1/helper", "200000")
	if zerr != nil || zombies <= 8192 {
		t.Errorf("zombie half: %d post-PONR zombies held (want > 8192): %v", zombies, zerr)
	}
	// io_uring may be disabled by the distribution (RHEL 10 ships
	// kernel.io_uring_disabled=2). TEST-ONLY DEVIATION: enable it for this
	// test and restore the recorded value afterwards, also on failure.
	const iouSysctl = "/proc/sys/kernel/io_uring_disabled"
	if raw, err := os.ReadFile(iouSysctl); err == nil {
		was := strings.TrimSpace(string(raw))
		t.Logf("kernel.io_uring_disabled=%s at start", was)
		if was != "0" {
			if err := os.WriteFile(iouSysctl, []byte("0"), 0o644); err != nil {
				t.Fatalf("enable io_uring: %v", err)
			}
			t.Logf("TEST-ONLY DEVIATION: kernel.io_uring_disabled set %s -> 0 for this test", was)
			t.Cleanup(func() {
				if err := os.WriteFile(iouSysctl, []byte(was), 0o644); err != nil {
					t.Errorf("restore kernel.io_uring_disabled=%s: %v", was, err)
				} else {
					t.Logf("kernel.io_uring_disabled restored to %s", was)
				}
			})
		}
	}
	workers, wl, releaseWorkers, werr := d1HeldHelper(t, cg, "WORKERS", "iowq", strconv.Itoa(many), "/d1/iowq-fifo")
	if werr != nil || workers <= 8192 {
		t.Errorf("io-wq half: %d workers held (want > 8192): %v", workers, werr)
	}
	t.Logf("held at once: %d io-wq workers %v, %d post-PONR zombies %v", workers, wl, zombies, zl)
	cells, err := o.node.KernelWitness()
	if err != nil || o.node.liveHealthFault() != nil {
		t.Fatalf("with %d workers and %d zombies held: witness %v fault %v health %v", workers, zombies, cells, err, o.node.liveHealthFault())
	}
	if cells[sharedWitnessMarkFailed] != before[sharedWitnessMarkFailed] {
		t.Fatalf("mark creations failed: %d -> %d", before[sharedWitnessMarkFailed], cells[sharedWitnessMarkFailed])
	}
	if cells[sharedWitnessLSMAlloc]-before[sharedWitnessLSMAlloc] < uint64(max(workers, 0)+max(zombies, 0)) || cells[sharedWitnessLSMCommit]-before[sharedWitnessLSMCommit] < uint64(max(zombies, 0)) {
		t.Fatalf("the held tasks were not marked by the LSM halves: before %v after %v", before, cells)
	}
	t.Logf("witness with the tasks held: %v (clean; %d marks never consumed by a tracepoint)", cells, (cells[3]-before[3])-(cells[2]-before[2])+(cells[1]-before[1])-(cells[0]-before[0]))
	// Enforcement is unaffected meanwhile.
	if kv, _ := o.run("held", "A", "/d1/helper asuid 1000 /d1/marker noop"); d1One(kv, "ST") != d1EPERM {
		t.Fatalf("Strict uid-1000 exec with the tasks held: %v", kv)
	}
	releaseWorkers()
	releaseZombies()
	if cells, err := o.node.KernelWitness(); err != nil || o.node.liveHealthFault() != nil {
		t.Fatalf("after release: witness %v fault %v", cells, err)
	}
	// The witness still latches afterwards.
	const ftrace = "/proc/sys/kernel/ftrace_enabled"
	if err := os.WriteFile(ftrace, []byte("0"), 0o644); err != nil {
		t.Fatalf("ftrace_enabled=0: %v", err)
	}
	o.witnessLatched = true
	for i := 0; i < 3; i++ {
		_ = exec.Command("/d1/helper", "noop").Run()
	}
	if err := os.WriteFile(ftrace, []byte("1"), 0o644); err != nil {
		t.Fatalf("restore ftrace_enabled=1: %v", err)
	}
	o.requireWitnessSignals("after the held tasks", true, true, true)
	if _, err := o.node.KernelWitness(); !errors.Is(err, ErrSharedKernelWitness) {
		t.Fatalf("not latched after the window: %v", err)
	}
}
