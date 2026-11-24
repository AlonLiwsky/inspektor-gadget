// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
)

// Kernel test of the executable-mapping gate (full/shared_exec_map.h). It
// records every case and fails at the end if any case failed, so one run
// shows all results.

// The cells of struct em_counts (enum em_cell).
const (
	emJudged = iota
	emAllowImage
	emAllowExe
	emNotImage
	emUnknown
	emAnon
	emModified
	emDenied
	emWouldDeny
	emRace
	emMprotect
	emShmem
	emDevZero
	emCells
)

var execMapCells = []string{"judged", "image", "exe", "notimage", "unknown", "anon", "modified", "denied", "would", "race", "mprotect", "shmem", "devzero"}

// execMapEvent is one event of the "execmap" datasource.
type execMapEvent struct {
	generation, scope, cgroup, ino, loadEpoch         uint64
	dev, hook, reason, execClass, deny, hostPID, slot uint32
	comm, path                                        string
}

// execMapCollector subscribes to the "execmap" datasource.
type execMapCollector struct {
	mu     sync.Mutex
	events []execMapEvent
}

func (c *execMapCollector) operator() operators.DataOperator {
	return simple.New("exec-map-events", simple.WithPriority(100), simple.OnInit(func(gc operators.GadgetContext) error {
		ds := gc.GetDataSources()[SharedExecMapDataSource]
		if ds == nil {
			return fmt.Errorf("missing %q datasource", SharedExecMapDataSource)
		}
		fields := map[string]datasource.FieldAccessor{}
		for _, name := range []string{"generation", "scope", "cgroup", "ino", "load_epoch", "dev", "hook", "reason", "exec_class", "deny", "host_pid", "slot", "comm", "path"} {
			if fields[name] = ds.GetField(name); fields[name] == nil {
				return fmt.Errorf("execmap datasource lacks field %s", name)
			}
		}
		return ds.Subscribe(func(_ datasource.DataSource, data datasource.Data) error {
			var e execMapEvent
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
			u64("scope", &e.scope)
			u64("cgroup", &e.cgroup)
			u64("ino", &e.ino)
			u64("load_epoch", &e.loadEpoch)
			u32("dev", &e.dev)
			u32("hook", &e.hook)
			u32("reason", &e.reason)
			u32("exec_class", &e.execClass)
			u32("deny", &e.deny)
			u32("host_pid", &e.hostPID)
			u32("slot", &e.slot)
			var err error
			e.comm, err = fields["comm"].String(data)
			errs = append(errs, err)
			e.path, err = fields["path"].String(data)
			errs = append(errs, err)
			if err := errors.Join(errs...); err != nil {
				return err
			}
			c.mu.Lock()
			c.events = append(c.events, e)
			c.mu.Unlock()
			return nil
		}, 0)
	}))
}

func (c *execMapCollector) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.events)
}

// since returns the events after the first n.
func (c *execMapCollector) since(n int) []execMapEvent {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.events[min(n, len(c.events)):])
}

// newExecMapFixture is one "container" whose image is a copy of the host
// userland (/usr, /etc) plus the test helpers, as an overlay lower layer.
func newExecMapFixture(t *testing.T, base, name, helpers string) *sharedOverlayFixture {
	t.Helper()
	dir := filepath.Join(base, name)
	// The upper layer and the work dir are on tmpfs (review 2, item 4):
	// overlayfs opens a file of the upper layer on a private clone of that
	// mount, which has the internal mount namespace like shmem; the gate must
	// still judge it as a file at mprotect.
	rw := filepath.Join(dir, "rw")
	f := &sharedOverlayFixture{dir: dir, lower: filepath.Join(dir, "lower"), upper: filepath.Join(rw, "upper"), work: filepath.Join(rw, "work"), merged: filepath.Join(dir, "merged")}
	for _, d := range []string{f.lower, rw, f.merged} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := unix.Mount("tmpfs", rw, "tmpfs", 0, "size=512m"); err != nil {
		t.Fatalf("mount tmpfs %s: %v", rw, err)
	}
	t.Cleanup(func() { _ = unix.Unmount(rw, unix.MNT_DETACH) })
	for _, d := range []string{f.upper, f.work} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sh := func(script string) {
		t.Helper()
		if out, err := exec.Command("/bin/bash", "-ec", script).CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", script, err, out)
		}
	}
	sh(fmt.Sprintf(`cd %q && cp -a --reflink=auto /usr usr && cp -a --reflink=auto /etc etc &&
ln -s usr/bin bin && ln -s usr/sbin sbin && ln -s usr/lib lib && ln -s usr/lib64 lib64 &&
mkdir -p proc dev sys opt root var/tmp && mkdir -m 1777 tmp &&
install -m 0755 %q/emtest usr/bin/emtest && install -m 0755 %q/empre.so usr/lib64/empre.so &&
cp %q/Hello.java opt/Hello.java`, f.lower, helpers, helpers, helpers))
	opts := "lowerdir=" + f.lower + ",upperdir=" + f.upper + ",workdir=" + f.work + ",index=off"
	if err := unix.Mount("overlay", f.merged, "overlay", 0, opts); err != nil {
		t.Fatalf("mount overlay %s: %v", f.merged, err)
	}
	t.Cleanup(func() { _ = unix.Unmount(f.merged, unix.MNT_DETACH) })
	// The runtimes (JVM, node) need /proc and /dev. Mounted before the init
	// starts, so the root barrier never judges them.
	if err := unix.Mount("proc", filepath.Join(f.merged, "proc"), "proc", 0, ""); err != nil {
		t.Fatalf("mount proc: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(filepath.Join(f.merged, "proc"), unix.MNT_DETACH) })
	if err := unix.Mount("/dev", filepath.Join(f.merged, "dev"), "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		t.Fatalf("bind /dev: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(filepath.Join(f.merged, "dev"), unix.MNT_DETACH) })
	return f
}

// TestSharedNodeExecMapAttached: the mapping gate on two fixture containers,
// A Strict and B Audit, policy "default deny, allow a target from the
// image". IG_SHARED_EXECMAP_OBJECT is a product object built from this
// tree; IG_SHARED_IMAGE_BASE a directory on XFS or ext4;
// IG_SHARED_LIVE_KERNEL=1 (the classifier needs this kernel's own overlay
// layout); IG_SHARED_EXECMAP_HELPERS a directory with emtest, empre.so and Hello.java
// built from testdata/exec_map (gcc -O2 -o emtest emtest.c -ldl; gcc -O2
// -shared -fPIC -o empre.so empre.c); IG_SHARED_EXECMAP_CGROUP_ROOT a
// dedicated ig15-em-* cgroup. The node needs python3, node and java 21.
func TestSharedNodeExecMapAttached(t *testing.T) {
	object, base, helpers := os.Getenv("IG_SHARED_EXECMAP_OBJECT"), os.Getenv("IG_SHARED_IMAGE_BASE"), os.Getenv("IG_SHARED_EXECMAP_HELPERS")
	if object == "" {
		t.Skip("set IG_SHARED_EXECMAP_OBJECT on an isolated exact-kernel VM")
	}
	root := os.Getenv("IG_SHARED_EXECMAP_CGROUP_ROOT")
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(root), "ig15-em-") || base == "" || helpers == "" {
		t.Fatal("root, a dedicated ig15-em-* cgroup root, IG_SHARED_IMAGE_BASE and IG_SHARED_EXECMAP_HELPERS required")
	}
	if err := checkSharedInitNamespaces(); err != nil {
		t.Fatalf("design 13.8: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(base, "ig15-em-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = exec.Command("rm", "-rf", base).Run() })
	source := sharedImageTestSource{}
	fixtures := map[string]*sharedOverlayFixture{}
	names := []string{"A", "B"}
	for _, name := range names {
		fixtures[name] = newExecMapFixture(t, base, strings.ToLower(name), helpers)
		source["ig15-em-"+strings.ToLower(name)] = fixtures[name]
	}
	events := &execMapCollector{}
	verdicts := &sharedVerdictCollector{}
	sharedTestQualification = func(q *SharedNodeQualification) {
		q.imageSource = source
		run := q.Run
		q.Run = func(ctx context.Context, opt gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
			return run(ctx, func(gc *gadgetcontext.GadgetContext) {
				opt(gc)
				gadgetcontext.WithAdditionalDataOperators(events.operator(), verdicts.operator())(gc)
			})
		}
	}
	t.Cleanup(func() { sharedTestQualification = nil })
	// On a failure, the exec verdicts explain a refused exec.
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}
		time.Sleep(500 * time.Millisecond)
		verdicts.mu.Lock()
		defer verdicts.mu.Unlock()
		for _, e := range verdicts.events[max(0, len(verdicts.events)-40):] {
			t.Logf("VERDICT cgroup=%d deny=%d mode=%d class=%d err=%d uncertain=%d unknown=%#x pass=%d rules=%v path=%q", e.cgroup, e.deny, e.mode, e.execClass, e.errorCode, e.uncertain, e.factsUnknown, e.pass, e.rules(), e.path)
		}
	})
	sharedCandidateNodeTimeout = 20 * time.Minute
	// The start self-test (verifySharedExecMap) ran: the node is live.
	node, gc, ctx := startSharedCandidateNode(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, nil)
	defer func() { _ = node.StopNode(context.WithoutCancel(ctx)) }()
	for name, r := range node.host.live.receipts {
		if strings.HasPrefix(name, "em_") {
			t.Logf("ATTACHED %s -> %s (link %d, program %d)", name, r.Target, r.LinkID, r.ProgramID)
		}
	}
	mapOf := func(name string) *ebpf.Map {
		value, _ := gc.GetVar(operators.MapPrefix + name)
		m, _ := value.(*ebpf.Map)
		if m == nil {
			t.Fatalf("%s was not published", name)
		}
		return m
	}
	counters, faults := mapOf(sharedExecMapCountersMap), mapOf(sharedExecMapFaultsMap)
	if reason := sharedOverlayLayoutFailure.Load(); reason != nil {
		t.Fatalf("overlay layout or FMODE_BACKING probe failed: %v (IG_SHARED_LIVE_KERNEL=1 set?)", *reason)
	}

	modes := map[string]fullpolicy.Mode{"A": fullpolicy.Enforce, "B": fullpolicy.Audit}
	inits := map[string]*sharedPipeInit{}
	sessions := map[string]*BindingSession{}
	for _, name := range names {
		cgroup := filepath.Join(root, strings.ToLower(name))
		if err := os.MkdirAll(cgroup, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(cgroup) })
		p := startSharedPipeInitImage(t, cgroup, "ig15-em-init-"+strings.ToLower(name), fixtures[name])
		config := SharedBindingConfig{ContainerID: "ig15-em-" + strings.ToLower(name)}
		config.CgroupID, config.InitHostPID, config.Acquire = p.ino, uint32(p.cmd.Process.Pid), p.acquire
		s, err := node.Bind(ctx, config)
		if err != nil {
			t.Fatalf("Bind %s: %v", name, err)
		}
		inits[name], sessions[name] = p, s
	}
	loader, err := filepath.EvalSymlinks("/lib64/ld-linux-x86-64.so.2")
	if err != nil {
		t.Fatal(err)
	}
	yes := true
	rules := []fullpolicy.Rule{
		{Name: "image", Action: fullpolicy.Allow, Target: fullpolicy.Target{FromImage: &yes}},
		{Name: "deny-id", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{"/usr/bin/id"}}},
	}
	gate := SharedExecMap{}
	revision := 0
	// publish sets the policy and the gate in one publish.
	publish := func(label string) {
		t.Helper()
		revision++
		for _, name := range names {
			p := &fullpolicy.Policy{ID: "em-" + strings.ToLower(name), Revision: strconv.Itoa(revision), Mode: modes[name], RootRole: "app", Default: fullpolicy.Deny, Rules: rules}
			if _, err := sessions[name].Publish(ctx, SharedBindingPolicy{Source: p, Container: strings.ToLower(name), ExecMap: gate}); err != nil {
				t.Fatalf("%s: publish %s revision %d: %v", label, name, revision, err)
			}
			if st := sessions[name].Inspect(); st.Fault != nil || !st.RoutePublished {
				t.Fatalf("%s: %s after publish: %+v", label, name, st)
			}
		}
		t.Logf("PUBLISHED revision %d (%s), %d rules, gate %+v", revision, label, len(rules), gate)
	}
	setGate := func(g SharedExecMap, label string) {
		t.Helper()
		gate = g
		publish(label)
	}
	read := func(name string) [emCells]uint64 {
		var per []struct{ Count [emCells]uint64 }
		slot := sessions[name].Inspect().RouteSlot
		if err := counters.Lookup(slot, &per); err != nil {
			t.Fatalf("%s %s slot %d: %v", sharedExecMapCountersMap, name, slot, err)
		}
		var sum [emCells]uint64
		for _, c := range per {
			for i, n := range c.Count {
				sum[i] += n
			}
		}
		return sum
	}
	readFaults := func() uint64 {
		var total uint64
		for key := uint32(0); key < 2; key++ {
			var per []uint64
			if err := faults.Lookup(key, &per); err != nil {
				t.Fatalf("%s: %v", sharedExecMapFaultsMap, err)
			}
			for _, n := range per {
				total += n
			}
		}
		return total
	}
	type outcome struct {
		rc     int
		out    string
		delta  [emCells]int64
		events []execMapEvent
	}
	run := func(name, command string) outcome {
		t.Helper()
		before, seen := read(name), events.count()
		out, code, err := inits[name].run(ctx, command+" 2>&1; echo rc=$?")
		if err != nil || code != 0 {
			t.Fatalf("%s %q: %q code %d: %v", name, command, out, code, err)
		}
		after := read(name)
		o := outcome{rc: -1}
		if i := strings.LastIndex(out, "rc="); i >= 0 {
			o.rc, _ = strconv.Atoi(strings.TrimSpace(out[i+3:]))
			out = out[:i]
		}
		o.out = strings.Join(strings.Fields(out), " ")
		if len(o.out) > 160 {
			o.out = o.out[:160]
		}
		for i := range o.delta {
			o.delta[i] = int64(after[i] - before[i])
		}
		// Events of this binding's cgroup: the ring is drained
		// asynchronously, so wait briefly for the ones the counters saw.
		want := int(o.delta[emDenied] + o.delta[emWouldDeny])
		deadline := time.Now().Add(2 * time.Second)
		for {
			o.events = o.events[:0]
			for _, e := range events.since(seen) {
				if e.cgroup == inits[name].ino {
					o.events = append(o.events, e)
				}
			}
			if len(o.events) >= want || time.Now().After(deadline) {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		return o
	}
	show := func(o outcome) string {
		var parts []string
		for i, n := range o.delta {
			if n != 0 {
				parts = append(parts, fmt.Sprintf("%s+%d", execMapCells[i], n))
			}
		}
		var evs []string
		for _, e := range o.events {
			evs = append(evs, fmt.Sprintf("{hook=%d %s class=%d deny=%d ino=%d %q %q}", e.hook, execMapCells[min(int(e.reason), emCells-1)], e.execClass, e.deny, e.ino, e.comm, e.path))
		}
		return fmt.Sprintf("rc=%d [%s] events=%v %q", o.rc, strings.Join(parts, " "), evs, o.out)
	}
	failed := 0
	// check runs one case in A (Strict) and B (Audit); okA and okB judge
	// the outcome.
	check := func(label, command string, okA, okB func(outcome) bool) {
		t.Helper()
		a, b := run("A", command), run("B", command)
		verdict := "PASS"
		if !okA(a) || !okB(b) {
			verdict = "FAIL"
			failed++
		}
		t.Logf("CASE %s | %s | %s\n    A(strict) %s\n    B(audit)  %s", verdict, label, command, show(a), show(b))
	}
	// Every denied or would-deny mapping has its event, with the hook and the
	// file identity (0 for anonymous memory).
	evented := func(o outcome, class uint32) bool {
		want := int(o.delta[emDenied] + o.delta[emWouldDeny])
		if len(o.events) != want {
			return false
		}
		for _, e := range o.events {
			if e.execClass != class || (e.deny == 1) != (class == 2) || e.hook < 1 || e.hook > 2 || e.generation == 0 || e.scope == 0 {
				return false
			}
			if (e.reason == emNotImage || e.reason == emUnknown) && e.ino == 0 {
				return false
			}
		}
		return true
	}
	ran := func(o outcome) bool { return o.rc == 0 && o.delta[emDenied] == 0 && o.delta[emWouldDeny] == 0 }
	has := func(s string) func(outcome) bool {
		return func(o outcome) bool { return ran(o) && strings.Contains(o.out, s) }
	}
	deniedMap := func(o outcome) bool { return o.rc != 0 && o.delta[emDenied] >= 1 && evented(o, 2) }
	wouldMap := func(o outcome) bool {
		return o.rc == 0 && o.delta[emWouldDeny] >= 1 && o.delta[emDenied] == 0 && evented(o, 1)
	}
	deniedExec := func(o outcome) bool { return o.rc == 126 && o.delta[emDenied] == 0 }
	auditRan := func(o outcome) bool { return o.rc == 0 && o.delta[emDenied] == 0 }
	cell := func(c int, ok func(outcome) bool) func(outcome) bool {
		return func(o outcome) bool { return ok(o) && o.delta[c] >= 1 }
	}
	ld := "/lib64/ld-linux-x86-64.so.2"
	py := `python3 -c "import ctypes,zlib,json,hashlib,sqlite3,ssl; print('py-ok')"`
	nodeJIT := `node -e "let s=0;for(let i=0;i<30000000;i++)s+=i%7;console.log('node-ok',s)"`
	javaJIT := `java -XX:TieredStopAtLevel=1 /opt/Hello.java`
	faultsAtStart := readFaults()

	publish("allow image, deny /usr/bin/id, gate off")
	for _, name := range names {
		if o := run(name, "cp /usr/bin/true /tmp/evil && cp /usr/lib64/empre.so /tmp/empre.so && cp /usr/bin/emtest /tmp/emtool && cp "+ld+" /tmp/ld.so && ln -s "+ld+" /tmp/ldlink"); o.rc != 0 {
			t.Fatalf("setup %s: %s", name, show(o))
		}
	}

	t.Log("PHASE 0: gate off (the gap on this engine)")
	check("gap: exec of a non-image copy is denied at exec", "/tmp/evil", deniedExec, auditRan)
	check("gap: loader runs the non-image copy", ld+" /tmp/evil", ran, ran)
	check("gap: LD_PRELOAD of a non-image library loads", "LD_PRELOAD=/tmp/empre.so /usr/bin/true", has("EMPRE-LOADED"), has("EMPRE-LOADED"))
	check("gap: dlopen of a non-image library loads", "emtest dlopen /tmp/empre.so", ran, ran)

	t.Log("PHASE 1: gate on (Judge), in the same publish as the policy")
	setGate(SharedExecMap{Judge: true}, "gate on")
	check("image program, dynamic", "/usr/bin/true", ran, ran)
	check("exec of a non-image copy (exec verdict, unchanged)", "/tmp/evil", deniedExec, auditRan)
	check("loader + non-image program", ld+" /tmp/evil", deniedMap, wouldMap)
	check("LD_PRELOAD non-image library (glibc skips it)", "LD_PRELOAD=/tmp/empre.so /usr/bin/true",
		func(o outcome) bool {
			return !strings.Contains(o.out, "EMPRE-LOADED") && o.delta[emDenied] >= 1 && evented(o, 2)
		},
		func(o outcome) bool { return wouldMap(o) && strings.Contains(o.out, "EMPRE-LOADED") })
	check("LD_PRELOAD image library", "LD_PRELOAD=/usr/lib64/empre.so /usr/bin/true", has("EMPRE-LOADED"), has("EMPRE-LOADED"))
	check("dlopen non-image library", "emtest dlopen /tmp/empre.so", deniedMap, wouldMap)
	check("dlopen image library", "emtest dlopen /usr/lib64/empre.so", ran, ran)
	check("mmap PROT_EXEC of a non-image file", "emtest mmapx /tmp/evil", deniedMap, wouldMap)
	check("mmap PROT_EXEC of an image file", "emtest mmapx /usr/bin/true", ran, ran)
	check("mmap PROT_READ then mprotect +EXEC, non-image file (upper layer on tmpfs)", "emtest mprotx /tmp/evil", cell(emMprotect, deniedMap), cell(emMprotect, wouldMap))
	check("mmap PROT_READ then mprotect +EXEC, image file", "emtest mprotx /usr/bin/true", cell(emAllowImage, cell(emMprotect, ran)), cell(emMprotect, ran))
	t.Log("PHASE 1b: anonymous memory (allowed, counted)")
	check("anonymous memory, mprotect +EXEC, run it", "emtest anonx", cell(emAnon, ran), ran)
	check("anonymous memory, mmap RWX, run it", "emtest anonwx", cell(emAnon, ran), ran)
	check("memfd mapped PROT_EXEC", "emtest memfdx", cell(emShmem, ran), cell(emShmem, ran))
	check("memfd double mapping (RW view + RX view), run it", "emtest dualmap", cell(emShmem, ran), ran)
	check("shared anonymous memory, mprotect +EXEC, run it", "emtest shmanonx", cell(emShmem, ran), ran)
	check("SysV shm, shmat(SHM_EXEC), run it", "emtest shmatx", cell(emShmem, ran), ran)
	check("SysV shm, mprotect +EXEC, run it", "emtest shmprotx", cell(emShmem, ran), ran)
	check("/dev/zero private PROT_EXEC, run it", "emtest zerox", cell(emDevZero, ran), ran)
	check("/dev/zero shared PROT_EXEC, run it", "emtest zerosx", cell(emDevZero, ran), ran)
	check("POSIX shm file in /dev/shm PROT_EXEC (a file: not from the image)", "emtest posixshmx", deniedMap, wouldMap)
	check("written private image mapping, mprotect +EXEC", "emtest modx /usr/bin/true", cell(emModified, ran), ran)
	check("written private NON-image mapping, mprotect +EXEC (anonymous class)", "emtest modx /tmp/evil", cell(emModified, ran), ran)
	t.Log("PHASE 1c: runtimes")
	check("python with C extension modules", py, has("py-ok"), has("py-ok"))
	check("python dlopen (ctypes) of a non-image library", `python3 -c "import ctypes; ctypes.CDLL('/tmp/empre.so'); print('py-loaded')"`,
		func(o outcome) bool {
			return !strings.Contains(o.out, "py-loaded") && o.delta[emDenied] >= 1 && evented(o, 2)
		},
		func(o outcome) bool { return wouldMap(o) && strings.Contains(o.out, "py-loaded") })
	check("node (V8 JIT)", nodeJIT, cell(emAnon, has("node-ok")), has("node-ok"))
	check("java (HotSpot JIT)", javaJIT, cell(emAnon, has("java-ok")), has("java-ok"))
	check("explicit loader + image program, no loader rule", ld+" /usr/bin/true", ran, ran)
	check("image program denied by path, direct", "/usr/bin/id -u", deniedExec, auditRan)
	check("explicit loader + path-denied image program, no loader rule (stays open)", ld+" /usr/bin/id -u", has("0"), has("0"))

	t.Log("PHASE 2: gate on, plus an exec deny rule for the loader path " + loader)
	rules = append(rules, fullpolicy.Rule{Name: "deny-loader", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{loader}}})
	publish("plus deny loader")
	check("image program, dynamic (PT_INTERP load is not an exec)", "/usr/bin/true", ran, ran)
	check("python with C extension modules", py, has("py-ok"), has("py-ok"))
	check("explicit loader + image program", ld+" /usr/bin/true", deniedExec, auditRan)
	check("explicit loader + path-denied image program", ld+" /usr/bin/id -u", deniedExec, auditRan)
	check("loader by its canonical path", loader+" /usr/bin/id -u", deniedExec, auditRan)
	check("loader through a symlink in /tmp", "/tmp/ldlink /usr/bin/id -u", deniedExec, auditRan)
	check("loader through /proc/self/root", "/proc/self/root"+ld+" /usr/bin/id -u", deniedExec, auditRan)
	check("a copy of the loader (not from the image)", "/tmp/ld.so /usr/bin/id -u", deniedExec, auditRan)
	check("loader + non-image program", ld+" /tmp/evil", deniedExec, auditRan)

	t.Log("PHASE 3: Judge + DenyAnonymous (deny anonymous executable memory)")
	setGate(SharedExecMap{Judge: true, DenyAnonymous: true}, "deny anonymous")
	check("anonymous memory, mprotect +EXEC", "emtest anonx", deniedMap, wouldMap)
	check("anonymous memory, mmap RWX", "emtest anonwx", deniedMap, wouldMap)
	check("memfd mapped PROT_EXEC", "emtest memfdx", deniedMap, wouldMap)
	check("SysV shm, shmat(SHM_EXEC)", "emtest shmatx", deniedMap, wouldMap)
	check("/dev/zero private PROT_EXEC", "emtest zerox", deniedMap, wouldMap)
	check("written private image mapping, mprotect +EXEC", "emtest modx /usr/bin/true", deniedMap, wouldMap)
	check("node (V8 JIT) under DenyAnonymous", nodeJIT, func(o outcome) bool { return o.rc != 0 && o.delta[emDenied] >= 1 }, func(o outcome) bool { return o.rc == 0 && o.delta[emWouldDeny] >= 1 })
	check("python without JIT under DenyAnonymous", py, func(o outcome) bool { return strings.Contains(o.out, "py-ok") }, func(o outcome) bool { return strings.Contains(o.out, "py-ok") })
	check("image program under DenyAnonymous", "/usr/bin/true", ran, ran)

	t.Log("PHASE 4: a path allow rule for a non-image program (program-file exemption from the exec record)")
	rules = append(rules, fullpolicy.Rule{Name: "allow-tool", Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: []string{"/tmp/evil", "/tmp/emtool"}}})
	setGate(SharedExecMap{Judge: true}, "plus allow /tmp/evil and /tmp/emtool")
	check("path-allowed non-image program runs (its own mappings exempt)", "/tmp/evil", cell(emAllowExe, ran), ran)
	check("path-allowed non-image program: text relocation of its own file (mprotect +EXEC)", "/tmp/emtool mprotx /tmp/emtool", cell(emAllowExe, ran), ran)
	check("the exemption does not open dlopen of another non-image library", "/tmp/emtool dlopen /tmp/empre.so", deniedMap, wouldMap)
	check("the exemption is per program: another non-image file", "/tmp/emtool mmapx /tmp/evil", deniedMap, wouldMap)

	t.Log("PHASE 5: policy revisions under mapping churn (race retry)")
	before := map[string][emCells]uint64{"A": read("A"), "B": read("B")}
	churned := make(chan error, 2)
	stop := make(chan struct{})
	for _, name := range names {
		go func() {
			var err error
			for err == nil {
				select {
				case <-stop:
					churned <- nil
					return
				default:
				}
				var out string
				var code int
				out, code, err = inits[name].run(ctx, `i=0; f=0; while [ $i -lt 100 ]; do /usr/bin/true || f=$((f+1)); emtest dlopen /usr/lib64/empre.so >/dev/null || f=$((f+1)); i=$((i+1)); done; echo "fail=$f"`)
				if err == nil && (code != 0 || !strings.Contains(out, "fail=0")) {
					err = fmt.Errorf("churn %s: %q code %d", name, out, code)
				}
			}
			churned <- err
		}()
	}
	for i := 0; i < 12; i++ {
		publish("churn revision")
		time.Sleep(200 * time.Millisecond)
	}
	close(stop)
	for range names {
		if err := <-churned; err != nil {
			failed++
			t.Logf("CASE FAIL | revisions under churn | %v", err)
		}
	}
	for _, name := range names {
		after := read(name)
		d := func(i int) uint64 { return after[i] - before[name][i] }
		verdict := "PASS"
		if d(emDenied) != 0 || d(emWouldDeny) != 0 || d(emUnknown) != 0 {
			verdict = "FAIL"
			failed++
		}
		t.Logf("CASE %s | revisions under churn %s | judged+%d image+%d denied+%d would+%d unknown+%d race+%d", verdict, name, d(emJudged), d(emAllowImage), d(emDenied), d(emWouldDeny), d(emUnknown), d(emRace))
	}

	t.Log("PHASE 5b: revisions while Strict maps a NON-image file: every attempt is denied (no fail-open in the race)")
	{
		before := read("A")
		const loops = 400
		done := make(chan error, 1)
		go func() {
			out, code, err := inits["A"].run(ctx, fmt.Sprintf(`i=0; ok=0; d=0; while [ $i -lt %d ]; do emtest mmapx /tmp/evil >/dev/null; r=$?; [ $r -eq 0 ] && ok=$((ok+1)); [ $r -eq 13 ] && d=$((d+1)); i=$((i+1)); done; echo "ok=$ok denied=$d"`, loops))
			if err == nil && (code != 0 || !strings.Contains(out, fmt.Sprintf("ok=0 denied=%d", loops))) {
				err = fmt.Errorf("%q code %d", strings.TrimSpace(out), code)
			}
			done <- err
		}()
		for i := 0; i < 12; i++ {
			publish("churn revision (non-image)")
			time.Sleep(150 * time.Millisecond)
		}
		err := <-done
		after := read("A")
		d := func(i int) uint64 { return after[i] - before[i] }
		verdict := "PASS"
		if err != nil || d(emDenied) < loops {
			verdict = "FAIL"
			failed++
		}
		t.Logf("CASE %s | revisions while Strict maps a non-image file x%d | %v | denied+%d notimage+%d unknown+%d race+%d", verdict, loops, err, d(emDenied), d(emNotImage), d(emUnknown), d(emRace))
	}

	t.Log("PHASE 6: Audit dlopen loop does not push out exec verdicts (own ring)")
	{
		seen := events.count()
		o := run("B", `i=0; while [ $i -lt 2000 ]; do emtest dlopen /tmp/empre.so >/dev/null; i=$((i+1)); done; echo done`)
		var lost [2]uint64
		var per []uint64
		for key := uint32(0); key < 2; key++ {
			if err := mapOf(sharedExecMapEventCountersMap).Lookup(key, &per); err != nil {
				t.Fatal(err)
			}
			for _, n := range per {
				lost[key] += n
			}
		}
		verdict := "PASS"
		if o.rc != 0 || o.delta[emWouldDeny] < 2000 {
			verdict = "FAIL"
			failed++
		}
		t.Logf("CASE %s | audit dlopen loop x2000 | would+%d events+%d submitted=%d lost=%d", verdict, o.delta[emWouldDeny], len(events.since(seen)), lost[0], lost[1])
	}

	t.Log("PHASE 7: cost of one executable mapping of an image file (mmap + munmap, 300000 times)")
	for _, g := range []SharedExecMap{{}, {Judge: true}, {}, {Judge: true}} {
		setGate(g, "bench")
		for _, name := range names {
			o := run(name, "emtest bench /usr/bin/true 300000")
			t.Logf("BENCH gate=%+v %s: %s", g, name, o.out)
		}
	}

	for _, name := range names {
		g := read(name)
		var parts []string
		for i, n := range g {
			parts = append(parts, fmt.Sprintf("%s=%d", execMapCells[i], n))
		}
		t.Logf("TOTAL %s: %s", name, strings.Join(parts, " "))
		if st := sessions[name].Inspect(); st.Fault != nil {
			failed++
			t.Logf("CASE FAIL | binding %s fault at end: %+v", name, st)
		}
	}
	if f := readFaults() - faultsAtStart; f != 0 {
		failed++
		t.Logf("CASE FAIL | %s moved by %d (route faults or UNKNOWN results)", sharedExecMapFaultsMap, f)
	}
	health, herr := node.FailClosedHealth()
	t.Logf("fail-closed health execmap=%d state=%v (%v)", health.ExecMap, health.State, herr)
	if failed != 0 {
		t.Fatalf("%d case(s) failed", failed)
	}
}
