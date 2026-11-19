// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedFactRecord is one struct real_owner_pass_witness of the test-only
// per-pass fact witness ring (opaque_real_fact_witness).
type sharedFactRecord struct {
	seq, tgid                              uint64
	result, stdin, targetImage, actorImage int32
	fsMask, fsKnown, ancestors, complete   uint32
	target, actor, ancestor0               string
	targetLength, actorLength, anc0Length  uint32
}

func sharedFactWitness(t *testing.T, gc *gadgetcontext.GadgetContext) *ebpf.Map {
	t.Helper()
	value, _ := gc.GetVar(operators.MapPrefix + sharedFactWitnessMap)
	m, _ := value.(*ebpf.Map)
	if m == nil {
		t.Fatalf("%s not published: the facts test needs the witness twin (g19pkgpubf128w, PASS_FACTS_WITNESS)", sharedFactWitnessMap)
	}
	return m
}

// sharedFactRecords returns the witness records after seq since, in order.
// The ring holds the last 16 passes; a case that overflows it fails.
func sharedFactRecords(t *testing.T, m *ebpf.Map, since uint64) []sharedFactRecord {
	t.Helper()
	var head []byte
	if err := m.Lookup(uint32(0), &head); err != nil {
		t.Fatal(err)
	}
	last := binary.LittleEndian.Uint64(head)
	if last-since > 16 {
		t.Fatalf("fact witness overflowed: %d passes since %d", last-since, since)
	}
	var out []sharedFactRecord
	for k := uint32(1); k <= 16; k++ {
		var raw []byte
		if err := m.Lookup(k, &raw); err != nil || len(raw) != 832 {
			t.Fatalf("witness[%d]: %d bytes %v", k, len(raw), err)
		}
		u := func(o int) uint32 { return binary.LittleEndian.Uint32(raw[o:]) }
		str := func(o, n int) string { return string(raw[o : o+min(n, 256)]) }
		r := sharedFactRecord{
			seq: binary.LittleEndian.Uint64(raw[0:]), tgid: binary.LittleEndian.Uint64(raw[8:]),
			result: int32(u(16)), targetImage: int32(u(20)), actorImage: int32(u(24)), stdin: int32(u(28)), fsMask: u(32), fsKnown: u(36), ancestors: u(40), complete: u(44),
			targetLength: u(48), actorLength: u(52), anc0Length: u(56),
		}
		r.target, r.actor, r.ancestor0 = str(64, int(r.targetLength)), str(320, int(r.actorLength)), str(576, int(r.anc0Length))
		if r.seq > since && r.seq <= last {
			out = append(out, r)
		}
	}
	slices.SortFunc(out, func(a, b sharedFactRecord) int { return int(a.seq) - int(b.seq) })
	if uint64(len(out)) != last-since {
		t.Fatalf("fact witness: %d records for %d passes", len(out), last-since)
	}
	return out
}

func sharedFactHead(t *testing.T, m *ebpf.Map) uint64 {
	t.Helper()
	var head []byte
	if err := m.Lookup(uint32(0), &head); err != nil {
		t.Fatal(err)
	}
	return binary.LittleEndian.Uint64(head)
}

// sharedFactFiles is the facts test's file set, in one tmpfs directory
// readable by the inits: true (a private copy of /usr/bin/true), s0
// ("#!<dir>/true"), anc-sh (a private bash), long/.../true (an absolute path
// longer than 255 bytes), x.igf (a binfmt_misc file) and root/x.igf (the
// same in a chroot that cannot reach the F interpreter).
type sharedFactFiles struct {
	dir, interp, script, ancestor, long, binfmt, chroot string
}

func newSharedFactFiles(t *testing.T) sharedFactFiles {
	t.Helper()
	dir := t.TempDir()
	f := sharedFactFiles{dir: dir, interp: filepath.Join(dir, "true"), script: filepath.Join(dir, "s0"), ancestor: filepath.Join(dir, "anc-sh"), binfmt: filepath.Join(dir, "x.igf"), chroot: filepath.Join(dir, "root")}
	long := dir
	for len(long) < 280 {
		long = filepath.Join(long, strings.Repeat("d", 60))
	}
	f.long = filepath.Join(long, "true")
	if err := os.MkdirAll(filepath.Dir(f.long), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(f.chroot, 0o755); err != nil {
		t.Fatal(err)
	}
	copyFile := func(from, to string) {
		raw, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, raw, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(sharedTruePath, f.interp)
	copyFile(sharedTruePath, f.long)
	copyFile("/usr/bin/bash", f.ancestor)
	copyFile(sharedTruePath, filepath.Join(f.chroot, "true"))
	for name, body := range map[string]string{f.script: "#!" + f.interp + "\n", f.binfmt: "binfmt payload\n", filepath.Join(f.chroot, "x.igf"): "binfmt payload\n"} {
		if err := os.WriteFile(name, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	chmodTempAncestors(t, dir)
	return f
}

// TestSharedNodeFactsAttached (G020 step 2): the per-pass exec facts
// consumed by real path predicates through the product publisher, on two
// bindings, A Strict and B Audit (same rules), each with a command-pipe
// init: an allowed script with a denied interpreter (and the reverse),
// exactly one evaluation per pass; an ancestor predicate; an fs-class
// (tmpfs) predicate; a stdin-pipe predicate; a list of more than 8 paths; a
// path longer than 255 bytes and a binfmt_misc F interpreter outside the
// task's root (D5), each UNKNOWN (Strict deny, Audit unknown) with its own
// fact counter. Each pass is checked in the test-only witness ring.
// Isolated exact-kernel VM only (IG_SHARED_FACTS_OBJECT: the witness twin).
func TestSharedNodeFactsAttached(t *testing.T) {
	object := os.Getenv("IG_SHARED_FACTS_OBJECT")
	if object == "" {
		t.Skip("set IG_SHARED_FACTS_OBJECT on an isolated exact-kernel VM")
	}
	root := os.Getenv("IG_SHARED_FACTS_CGROUP_ROOT")
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(root), "ig15-g020-facts") {
		t.Fatal("root and a dedicated ig15-g020-facts* cgroup root required")
	}
	if err := checkSharedInitNamespaces(); err != nil {
		t.Fatalf("design 13.8: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	files := newSharedFactFiles(t)
	node, gc, ctx := startSharedCandidateNode(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, nil)
	defer func() { _ = node.StopNode(context.WithoutCancel(ctx)) }()
	publisher, err := node.livePublisher(false)
	if _, product := publisher.(*sharedLiveProductPublisher); err != nil || !product {
		t.Fatalf("node publisher %T (%v), want the product publisher", publisher, err)
	}
	witness := sharedFactWitness(t, gc)
	inits := map[string]*sharedPipeInit{}
	sessions := map[string]*BindingSession{}
	modes := map[string]fullpolicy.Mode{"A": fullpolicy.Enforce, "B": fullpolicy.Audit}
	for _, name := range []string{"A", "B"} {
		cgroup := filepath.Join(root, strings.ToLower(name))
		if err := os.MkdirAll(cgroup, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(cgroup) })
		p := startSharedPipeInitShell(t, cgroup, "ig15-g020-facts-init-"+strings.ToLower(name), "/usr/bin/bash")
		t.Cleanup(p.stop)
		s, err := node.Bind(ctx, SharedBindingConfig{CgroupID: p.ino, InitHostPID: uint32(p.cmd.Process.Pid), Acquire: p.acquire})
		if err != nil {
			t.Fatalf("Bind %s: %v", name, err)
		}
		inits[name], sessions[name] = p, s
	}
	revision := 0
	// publish revises both bindings to rules (default allow).
	publish := func(label string, rules ...fullpolicy.Rule) {
		t.Helper()
		revision++
		for _, name := range []string{"A", "B"} {
			policy := &fullpolicy.Policy{ID: "g020-facts-" + strings.ToLower(name), Revision: strconv.Itoa(revision), Mode: modes[name], RootRole: "app", Default: fullpolicy.Allow, Rules: rules}
			if _, err := sessions[name].Publish(ctx, SharedBindingPolicy{Source: policy, Container: strings.ToLower(name)}); err != nil {
				t.Fatalf("%s: publish %s revision %d: %v", label, name, revision, err)
			}
		}
	}
	// run returns the exit status of command in the init of binding name,
	// and the witness records of its passes whose target is in targets.
	run := func(label, name, command string, targets ...string) (int, []sharedFactRecord) {
		t.Helper()
		since := sharedFactHead(t, witness)
		out, code, err := inits[name].run(ctx, command+"; echo rc=$?")
		if err != nil || code != 0 {
			t.Fatalf("%s %s: %q code %d: %v", label, name, out, code, err)
		}
		i := strings.LastIndex(out, "rc=")
		if i < 0 {
			t.Fatalf("%s %s: no status in %q", label, name, out)
		}
		rc, err := strconv.Atoi(strings.TrimSpace(out[i+3:]))
		if err != nil {
			t.Fatalf("%s %s: status %q", label, name, out)
		}
		var mine []sharedFactRecord
		for _, r := range sharedFactRecords(t, witness, since) {
			if r.result != 0 {
				t.Fatalf("%s %s: collector result %d", label, name, r.result)
			}
			if len(targets) == 0 || slices.Contains(targets, r.target) || (r.targetLength == 0 && slices.Contains(targets, "")) {
				mine = append(mine, r)
			}
		}
		return rc, mine
	}
	targetsOf := func(records []sharedFactRecord) []string {
		var out []string
		for _, r := range records {
			out = append(out, r.target)
		}
		return out
	}
	// expect runs command in both bindings: A (Strict) exits strict, B
	// (Audit) exits 0; passes are the targets of the evaluated passes of
	// interest, per binding.
	expectRC := func(label, command string, strict, audit int, passesA, passesB []string, targets ...string) map[string][]sharedFactRecord {
		t.Helper()
		got := map[string][]sharedFactRecord{}
		for name, want := range map[string]struct {
			rc     int
			passes []string
		}{"A": {strict, passesA}, "B": {audit, passesB}} {
			rc, records := run(label, name, command, targets...)
			if rc != want.rc || !slices.Equal(targetsOf(records), want.passes) {
				t.Fatalf("%s %s: rc %d passes %q, want rc %d passes %q (records %+v)", label, name, rc, targetsOf(records), want.rc, want.passes, records)
			}
			got[name] = records
		}
		t.Logf("%s: A rc %d passes %q; B rc %d passes %q", label, strict, passesA, audit, passesB)
		return got
	}
	expect := func(label, command string, strict int, passesA, passesB []string, targets ...string) map[string][]sharedFactRecord {
		t.Helper()
		return expectRC(label, command, strict, 0, passesA, passesB, targets...)
	}
	const eperm = 126 // bash: the exec was refused (EPERM)

	// Adoption with the base policy: one rule consulting the target path.
	never := fullpolicy.Rule{Name: "never", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{"/nonexistent/never"}}}
	publish("base", never)
	for name, s := range sessions {
		if st := s.Inspect(); st.Fault != nil || !st.RoutePublished || st.Adoption != nil {
			t.Fatalf("%s after adoption: %+v", name, st)
		}
	}
	both := []string{files.script, files.interp}
	expect("plain /usr/bin/true", sharedTruePath, 0, []string{sharedTruePath}, []string{sharedTruePath}, sharedTruePath)
	expect("script, base", files.script, 0, both, both, both...)

	// Allowed script, denied interpreter: exactly two evaluations; Strict
	// refuses the interpreter pass.
	publish("deny interpreter", never, fullpolicy.Rule{Name: "interp", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{files.interp}}})
	expect("allowed script, denied interpreter", files.script, eperm, both, both, both...)
	// The reverse: the script pass is refused, the interpreter is never
	// evaluated (Strict); Audit evaluates both.
	publish("deny script", never, fullpolicy.Rule{Name: "script", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{files.script}}})
	expect("denied script", files.script, eperm, []string{files.script}, both, both...)

	// More than 8 paths in one predicate (the match is the last of 9; short
	// decoys keep the compiled policy within one 256-cell object).
	var many []string
	for i := range 8 {
		many = append(many, fmt.Sprintf("/n/p%d", i))
	}
	publish("many paths", never, fullpolicy.Rule{Name: "many", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: append(many, files.interp)}})
	expect("9-path list", files.interp, eperm, []string{files.interp}, []string{files.interp}, files.interp)
	expect("9-path list, unmatched", sharedTruePath, 0, []string{sharedTruePath}, []string{sharedTruePath}, sharedTruePath)

	// Ancestor: the private interpreter is refused only below anc-sh.
	publish("ancestor", never, fullpolicy.Rule{Name: "ancestor", Action: fullpolicy.Deny, Actor: fullpolicy.Actor{Ancestor: &fullpolicy.Ancestor{Path: []string{files.ancestor}, Depth: 2}}, Target: fullpolicy.Target{Path: []string{files.interp}}})
	records := expect("below anc-sh", fmt.Sprintf("%s -c '%s; exit $?'", files.ancestor, files.interp), eperm, []string{files.interp}, []string{files.interp}, files.interp)
	for name, rs := range records {
		if r := rs[0]; r.ancestor0 != files.ancestor || r.complete != 1 || r.ancestors < 2 {
			t.Fatalf("ancestor %s: record %+v, want ancestor0 %s, a complete chain", name, r, files.ancestor)
		}
	}
	expect("not below anc-sh", files.interp, 0, []string{files.interp}, []string{files.interp}, files.interp)

	// fs class: the tmpfs copy is refused, /usr/bin/true is not.
	publish("tmpfs", never, fullpolicy.Rule{Name: "tmpfs", Action: fullpolicy.Deny, Target: fullpolicy.Target{FSType: []string{"tmpfs"}}})
	records = expect("tmpfs target", files.interp, eperm, []string{files.interp}, []string{files.interp}, files.interp)
	if r := records["A"][0]; r.fsMask&1 == 0 || r.fsKnown&1 == 0 {
		t.Fatalf("tmpfs record %+v", r)
	}
	expect("rootfs target", sharedTruePath, 0, []string{sharedTruePath}, []string{sharedTruePath}, sharedTruePath)

	// stdin pipe.
	yes := true
	publish("stdin", never, fullpolicy.Rule{Name: "stdin", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{files.interp}, Argv: &fullpolicy.Argv{StdinIsPipe: &yes}}})
	expect("stdin pipe", "echo x | "+files.interp, eperm, []string{files.interp}, []string{files.interp}, files.interp)
	expect("stdin not a pipe", files.interp+" </dev/null", 0, []string{files.interp}, []string{files.interp}, files.interp)

	// A path longer than 255 bytes is UNKNOWN (never truncated): Strict
	// denies (the base rule consults the target path), Audit allows.
	publish("base again", never)
	before, err := node.FactHealth()
	if err != nil {
		t.Fatal(err)
	}
	expect("path longer than 255 bytes", files.long, eperm, []string{""}, []string{""}, "")
	after, err := node.FactHealth()
	if err != nil || after.TargetTooLong-before.TargetTooLong != 2 {
		t.Fatalf("too-long counter %d -> %d (%v), want +2 (A and B)", before.TargetTooLong, after.TargetTooLong, err)
	}

	// D5: a binfmt_misc F interpreter is opened at registration, here by
	// the test in the host mount namespace. Each binding's init runs in its
	// own mount namespace (CLONE_NEWNS, like a container), whose root cannot
	// reach that file: the interpreter pass's target path is UNKNOWN
	// (d_path alone would print the host path). (A chroot is H1, below.) The
	// reachable F interpreter (registered and exec'd in one namespace) is the
	// verdict matrix's binfmt_misc igtestf case (TestOpaqueRealPolicyVerdictAttached).
	const bm = "/proc/sys/fs/binfmt_misc"
	if _, err := os.Stat(filepath.Join(bm, "register")); err != nil {
		if err := unix.Mount("binfmt_misc", bm, "binfmt_misc", 0, ""); err != nil {
			t.Fatalf("binfmt_misc: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(bm, "register"), []byte(":ig20f:E::igf::"+files.interp+":F"), 0o200); err != nil {
		t.Fatalf("binfmt_misc register: %v", err)
	}
	t.Cleanup(func() { _ = os.WriteFile(filepath.Join(bm, "ig20f"), []byte("-1"), 0o200) })
	// Audit lets both execs run: the chroot has no dynamic loader for the
	// interpreter, so its exec then fails ENOENT (127), never EPERM (126).
	for _, c := range []struct {
		label, command, script string
		audit                  int
	}{
		{"binfmt F from another mount namespace (D5)", files.binfmt, files.binfmt, 0},
	} {
		before, err = node.FactHealth()
		if err != nil {
			t.Fatal(err)
		}
		expectRC(c.label, c.command, eperm, c.audit, []string{c.script, ""}, []string{c.script, ""}, c.script, "")
		after, err = node.FactHealth()
		if err != nil || after.TargetOutsideRoot-before.TargetOutsideRoot != 2 {
			t.Fatalf("%s: outside-root counter %d -> %d (%v), want +2 (A and B)", c.label, before.TargetOutsideRoot, after.TargetOutsideRoot, err)
		}
	}

	// H1: path facts are anchored to the binding's root recorded at Bind,
	// never to the exec'ing task's own root: after a chroot (CAP_SYS_CHROOT)
	// every path fact is UNKNOWN (target, actor, ancestors), so a chroot can
	// neither spoof a target path (the F interpreter's script, which the
	// chroot can reach, is no known path either) nor hide the ancestors.
	// Strict refuses the first pass (EPERM), Audit runs it (the chroot has
	// no dynamic loader: ENOENT, 127).
	// chroot(8) by PATH: /usr/sbin/chroot is not everywhere (Ubuntu 25.10
	// and 26.04 have /usr/bin/chroot only). Not symlink-resolved: it may be
	// a multi-call binary that dispatches on argv[0].
	chroot, err := exec.LookPath("chroot")
	if err != nil {
		t.Fatalf("chroot(8): %v", err)
	}
	t.Logf("chroot(8): %s", chroot)
	rootCases := []struct {
		label, command string
		passesB        []string
	}{
		{"target spoof in a chroot (H1)", chroot + " " + files.chroot + " /x.igf", []string{"", ""}},
		{"ancestor hiding in a chroot (H1)", fmt.Sprintf("%s -c '%s %s /true; exit $?'", files.ancestor, chroot, files.chroot), []string{""}},
	}
	for i, c := range rootCases {
		if i == 1 {
			// The ancestor rule: the private interpreter only below
			// anc-sh; in the chroot its copy is /true, which neither
			// rule names, so only the UNKNOWN facts can refuse it.
			publish("ancestor (H1)", never, fullpolicy.Rule{Name: "ancestor", Action: fullpolicy.Deny, Actor: fullpolicy.Actor{Ancestor: &fullpolicy.Ancestor{Path: []string{files.ancestor}, Depth: 2}}, Target: fullpolicy.Target{Path: []string{files.interp}}})
		}
		before, err = node.FactHealth()
		if err != nil {
			t.Fatal(err)
		}
		records := expectRC(c.label, c.command, eperm, 127, []string{""}, c.passesB, "")
		after, err = node.FactHealth()
		if err != nil || after.RootMismatch-before.RootMismatch != uint64(1+len(c.passesB)) || after.TargetOutsideRoot != before.TargetOutsideRoot {
			t.Fatalf("%s: root-mismatch counter %d -> %d, outside-root %d -> %d (%v), want +%d and +0", c.label, before.RootMismatch, after.RootMismatch, before.TargetOutsideRoot, after.TargetOutsideRoot, err, 1+len(c.passesB))
		}
		for name, rs := range records {
			for _, r := range rs {
				if r.target != "" || r.actor != "" || r.ancestors != 0 || r.complete != 0 {
					t.Fatalf("%s %s: record %+v, want every path fact UNKNOWN", c.label, name, r)
				}
			}
		}
	}
	// Outside the chroot the same ancestor rule still decides on the
	// complete chain (ending at the binding's init).
	records = expect("below anc-sh (H1 control)", fmt.Sprintf("%s -c '%s; exit $?'", files.ancestor, files.interp), eperm, []string{files.interp}, []string{files.interp}, files.interp)
	for name, rs := range records {
		if r := rs[0]; r.ancestor0 != files.ancestor || r.complete != 1 || r.ancestors < 2 {
			t.Fatalf("H1 control %s: record %+v, want ancestor0 %s, a complete chain", name, r, files.ancestor)
		}
	}

	final, err := node.FactHealth()
	t.Logf("fact health %+v (%v)", final, err)
	if err := node.Ready(gc); !errors.Is(err, ErrSharedNativeUnavailable) || strings.Contains(fmt.Sprint(err), "fact witness") {
		t.Fatalf("Ready: %v", err)
	}
}
