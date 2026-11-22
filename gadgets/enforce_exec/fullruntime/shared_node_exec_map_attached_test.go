// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Kernel test of the executable-mapping gate (full/shared_exec_map.h). It
// records every case and fails at the end if any case failed, so one run
// shows all results.

// execMapGate is struct em_gate (full/shared_exec_map.h).
type execMapGate struct {
	Flags, LastHook   uint32
	LastIno           uint64
	LastDev, LastCell uint32
	Count             [11]uint64
}

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
)

var execMapCells = []string{"judged", "image", "exe", "notimage", "unknown", "anon", "modified", "denied", "would", "race", "mprotect"}

// newExecMapFixture is one "container" whose image is a copy of the host
// userland (/usr, /etc) plus the test helpers, as an overlay lower layer.
func newExecMapFixture(t *testing.T, base, name, helpers string) *sharedOverlayFixture {
	t.Helper()
	dir := filepath.Join(base, name)
	f := &sharedOverlayFixture{dir: dir, lower: filepath.Join(dir, "lower"), upper: filepath.Join(dir, "upper"), work: filepath.Join(dir, "work"), merged: filepath.Join(dir, "merged")}
	for _, d := range []string{f.lower, f.upper, f.work, f.merged} {
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
// IG_SHARED_EXECMAP_HELPERS a directory with emtest, empre.so and Hello.java
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
	sharedTestQualification = func(q *SharedNodeQualification) { q.imageSource = source }
	t.Cleanup(func() { sharedTestQualification = nil })
	sharedCandidateNodeTimeout = 20 * time.Minute
	node, gc, ctx := startSharedCandidateNode(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, nil)
	defer func() { _ = node.StopNode(context.WithoutCancel(ctx)) }()
	for name, r := range node.host.live.receipts {
		if strings.HasPrefix(name, "em_") {
			t.Logf("ATTACHED %s -> %s (link %d, program %d)", name, r.Target, r.LinkID, r.ProgramID)
		}
	}
	value, _ := gc.GetVar(operators.MapPrefix + "exec_map_gate")
	gate, _ := value.(*ebpf.Map)
	if gate == nil {
		t.Fatal("exec_map_gate was not published")
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
	revision := 0
	publish := func(label string) {
		t.Helper()
		revision++
		for _, name := range names {
			p := &fullpolicy.Policy{ID: "em-" + strings.ToLower(name), Revision: strconv.Itoa(revision), Mode: modes[name], RootRole: "app", Default: fullpolicy.Deny, Rules: rules}
			if _, err := sessions[name].Publish(ctx, SharedBindingPolicy{Source: p, Container: strings.ToLower(name)}); err != nil {
				t.Fatalf("%s: publish %s revision %d: %v", label, name, revision, err)
			}
			if st := sessions[name].Inspect(); st.Fault != nil || !st.RoutePublished {
				t.Fatalf("%s: %s after publish: %+v", label, name, st)
			}
		}
		t.Logf("PUBLISHED revision %d (%s), %d rules", revision, label, len(rules))
	}
	read := func(name string) execMapGate {
		var g execMapGate
		if err := gate.Lookup(inits[name].ino, &g); err != nil {
			t.Fatalf("exec_map_gate %s: %v", name, err)
		}
		return g
	}
	setFlags := func(flags uint32) {
		t.Helper()
		for _, name := range names {
			var g execMapGate
			_ = gate.Lookup(inits[name].ino, &g)
			g.Flags = flags
			if err := gate.Put(inits[name].ino, &g); err != nil {
				t.Fatalf("exec_map_gate put %s: %v", name, err)
			}
		}
		t.Logf("GATE flags %d", flags)
	}
	type outcome struct {
		rc    int
		out   string
		delta [11]int64
	}
	run := func(name, command string) outcome {
		t.Helper()
		before := read(name)
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
			o.delta[i] = int64(after.Count[i] - before.Count[i])
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
		return fmt.Sprintf("rc=%d [%s] %q", o.rc, strings.Join(parts, " "), o.out)
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
	ran := func(o outcome) bool { return o.rc == 0 && o.delta[emDenied] == 0 && o.delta[emWouldDeny] == 0 }
	has := func(s string) func(outcome) bool {
		return func(o outcome) bool { return ran(o) && strings.Contains(o.out, s) }
	}
	deniedMap := func(o outcome) bool { return o.rc != 0 && o.delta[emDenied] >= 1 }
	wouldMap := func(o outcome) bool { return o.rc == 0 && o.delta[emWouldDeny] >= 1 && o.delta[emDenied] == 0 }
	deniedExec := func(o outcome) bool { return o.rc == 126 && o.delta[emDenied] == 0 }
	auditRan := func(o outcome) bool { return o.rc == 0 && o.delta[emDenied] == 0 }
	ld := "/lib64/ld-linux-x86-64.so.2"
	py := `python3 -c "import ctypes,zlib,json,hashlib,sqlite3,ssl; print('py-ok')"`
	nodeJIT := `node -e "let s=0;for(let i=0;i<30000000;i++)s+=i%7;console.log('node-ok',s)"`
	javaJIT := `java -XX:TieredStopAtLevel=1 /opt/Hello.java`

	publish("allow image, deny /usr/bin/id")
	setFlags(0)
	for _, name := range names {
		if o := run(name, "cp /usr/bin/true /tmp/evil && cp /usr/lib64/empre.so /tmp/empre.so && cp /usr/bin/true /tmp/tool && cp "+ld+" /tmp/ld.so && ln -s "+ld+" /tmp/ldlink"); o.rc != 0 {
			t.Fatalf("setup %s: %s", name, show(o))
		}
	}

	t.Log("PHASE 0: gate off (the gap on this engine)")
	check("gap: exec of a non-image copy is denied at exec", "/tmp/evil", deniedExec, auditRan)
	check("gap: loader runs the non-image copy", ld+" /tmp/evil", ran, ran)
	check("gap: LD_PRELOAD of a non-image library loads", "LD_PRELOAD=/tmp/empre.so /usr/bin/true", has("EMPRE-LOADED"), has("EMPRE-LOADED"))
	check("gap: dlopen of a non-image library loads", "emtest dlopen /tmp/empre.so", ran, ran)

	t.Log("PHASE 1: gate on (flags JUDGE)")
	setFlags(1)
	check("image program, dynamic", "/usr/bin/true", ran, ran)
	check("exec of a non-image copy (exec verdict, unchanged)", "/tmp/evil", deniedExec, auditRan)
	check("loader + non-image program", ld+" /tmp/evil", deniedMap, wouldMap)
	check("LD_PRELOAD non-image library (glibc skips it)", "LD_PRELOAD=/tmp/empre.so /usr/bin/true",
		func(o outcome) bool { return !strings.Contains(o.out, "EMPRE-LOADED") && o.delta[emDenied] >= 1 },
		func(o outcome) bool { return wouldMap(o) && strings.Contains(o.out, "EMPRE-LOADED") })
	check("LD_PRELOAD image library", "LD_PRELOAD=/usr/lib64/empre.so /usr/bin/true", has("EMPRE-LOADED"), has("EMPRE-LOADED"))
	check("dlopen non-image library", "emtest dlopen /tmp/empre.so", deniedMap, wouldMap)
	check("dlopen image library", "emtest dlopen /usr/lib64/empre.so", has("EMPRE-LOADED"), has("EMPRE-LOADED"))
	check("mmap PROT_EXEC of a non-image file", "emtest mmapx /tmp/evil", deniedMap, wouldMap)
	check("mmap PROT_EXEC of an image file", "emtest mmapx /usr/bin/true", ran, ran)
	check("mmap PROT_READ then mprotect +EXEC, non-image file", "emtest mprotx /tmp/evil",
		func(o outcome) bool { return deniedMap(o) && o.delta[emMprotect] >= 1 },
		func(o outcome) bool { return wouldMap(o) && o.delta[emMprotect] >= 1 })
	check("mmap PROT_READ then mprotect +EXEC, image file", "emtest mprotx /usr/bin/true",
		func(o outcome) bool { return ran(o) && o.delta[emMprotect] >= 1 && o.delta[emAllowImage] >= 1 },
		func(o outcome) bool { return ran(o) && o.delta[emMprotect] >= 1 })
	check("memfd mapped PROT_EXEC (UNKNOWN)", "emtest memfdx",
		func(o outcome) bool { return deniedMap(o) && o.delta[emUnknown] >= 1 },
		func(o outcome) bool { return wouldMap(o) && o.delta[emUnknown] >= 1 })
	check("anonymous memory, mprotect +EXEC, run it", "emtest anonx", func(o outcome) bool { return ran(o) && o.delta[emAnon] >= 1 }, ran)
	check("anonymous memory, mmap RWX, run it", "emtest anonwx", func(o outcome) bool { return ran(o) && o.delta[emAnon] >= 1 }, ran)
	check("written private image mapping, mprotect +EXEC", "emtest modx /usr/bin/true", func(o outcome) bool { return ran(o) && o.delta[emModified] >= 1 }, ran)
	check("python with C extension modules", py, has("py-ok"), has("py-ok"))
	check("python dlopen (ctypes) of a non-image library", `python3 -c "import ctypes; ctypes.CDLL('/tmp/empre.so'); print('py-loaded')"`,
		func(o outcome) bool { return !strings.Contains(o.out, "py-loaded") && o.delta[emDenied] >= 1 },
		func(o outcome) bool { return wouldMap(o) && strings.Contains(o.out, "py-loaded") })
	check("node (V8 JIT)", nodeJIT, func(o outcome) bool { return has("node-ok")(o) && o.delta[emAnon] >= 1 }, has("node-ok"))
	check("java (HotSpot JIT)", javaJIT, func(o outcome) bool { return has("java-ok")(o) && o.delta[emAnon] >= 1 }, has("java-ok"))
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

	t.Log("PHASE 3: flags JUDGE|DENY_ANON (deny anonymous executable memory)")
	setFlags(1 | 2)
	check("anonymous memory, mprotect +EXEC", "emtest anonx", deniedMap, wouldMap)
	check("anonymous memory, mmap RWX", "emtest anonwx", deniedMap, wouldMap)
	check("written private image mapping, mprotect +EXEC", "emtest modx /usr/bin/true", deniedMap, wouldMap)
	check("node (V8 JIT) under DENY_ANON", nodeJIT, func(o outcome) bool { return o.rc != 0 && o.delta[emDenied] >= 1 }, wouldMap)
	check("python without JIT under DENY_ANON", py, func(o outcome) bool { return strings.Contains(o.out, "py-ok") }, func(o outcome) bool { return strings.Contains(o.out, "py-ok") })
	check("image program under DENY_ANON", "/usr/bin/true", ran, ran)

	t.Log("PHASE 4: a path allow rule for a non-image program, /tmp/tool")
	setFlags(1)
	rules = append(rules, fullpolicy.Rule{Name: "allow-tool", Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: []string{"/tmp/tool"}}})
	publish("plus allow /tmp/tool")
	check("path-allowed non-image program, no exemption: its own mapping is refused", "/tmp/tool", deniedMap, wouldMap)
	setFlags(1 | 4)
	check("path-allowed non-image program, EXE_EXEMPT", "/tmp/tool", func(o outcome) bool { return ran(o) && o.delta[emAllowExe] >= 1 }, ran)
	check("EXE_EXEMPT does not open dlopen of a non-image library", "emtest dlopen /tmp/empre.so", deniedMap, wouldMap)
	setFlags(1)

	t.Log("PHASE 5: policy revisions under mapping churn")
	before := map[string]execMapGate{"A": read("A"), "B": read("B")}
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
		d := func(i int) uint64 { return after.Count[i] - before[name].Count[i] }
		verdict := "PASS"
		if d(emDenied) != 0 || d(emWouldDeny) != 0 {
			verdict = "FAIL"
			failed++
		}
		t.Logf("CASE %s | revisions under churn %s | judged+%d image+%d denied+%d would+%d unknown+%d race+%d", verdict, name, d(emJudged), d(emAllowImage), d(emDenied), d(emWouldDeny), d(emUnknown), d(emRace))
	}

	t.Log("PHASE 6: cost of one executable mapping of an image file (mmap + munmap, 300000 times)")
	for _, flags := range []uint32{0, 1, 0, 1} {
		setFlags(flags)
		for _, name := range names {
			o := run(name, "emtest bench /usr/lib64/libc.so.6 300000")
			t.Logf("BENCH flags=%d %s: %s", flags, name, o.out)
		}
	}
	setFlags(1)

	for _, name := range names {
		g := read(name)
		var parts []string
		for i, n := range g.Count {
			parts = append(parts, fmt.Sprintf("%s=%d", execMapCells[i], n))
		}
		t.Logf("TOTAL %s: %s", name, strings.Join(parts, " "))
		if st := sessions[name].Inspect(); st.Fault != nil {
			failed++
			t.Logf("CASE FAIL | binding %s fault at end: %+v", name, st)
		}
	}
	health, herr := node.FactHealth()
	t.Logf("fact health %+v (%v)", health, herr)
	if failed != 0 {
		t.Fatalf("%d case(s) failed", failed)
	}
}
