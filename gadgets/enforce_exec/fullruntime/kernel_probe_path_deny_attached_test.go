// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// TestSharedProbedPathDenyAttached (D3): the evaluator sees the target path
// fact on the running kernel. Two bindings, A Strict and B Audit, default
// allow, one rule that denies ONLY on the target path of a private copy of
// bash. A must refuse that file (126, also through a symlink) and run an
// identical copy under another path; B must run both. A missing path fact
// would show as the denied file running under Strict (a silent bypass) or,
// if it is UNKNOWN, as the allowed copy being refused.
// IG_SHARED_PATH_DENY_OBJECT: a product-publisher object;
// IG_SHARED_PATH_DENY_CGROUP_ROOT: a dedicated ig15-d3-pathdeny* cgroup.
func TestSharedProbedPathDenyAttached(t *testing.T) {
	object := os.Getenv("IG_SHARED_PATH_DENY_OBJECT")
	if object == "" {
		t.Skip("set IG_SHARED_PATH_DENY_OBJECT on an isolated VM")
	}
	root := os.Getenv("IG_SHARED_PATH_DENY_CGROUP_ROOT")
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(root), "ig15-d3-pathdeny") {
		t.Fatal("root and a dedicated ig15-d3-pathdeny* cgroup root required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	bash, err := filepath.EvalSymlinks("/usr/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(bash)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp("/var/tmp", "ig15-d3-pathdeny-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	denied, allowed, link := filepath.Join(dir, "denied"), filepath.Join(dir, "allowed"), filepath.Join(dir, "link")
	for _, p := range []string{denied, allowed} {
		if err := os.WriteFile(p, raw, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(denied, link); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/usr/bin/true", "/usr/bin/bash"} {
		real, _ := filepath.EvalSymlinks(p)
		t.Logf("PATHDENY %s resolves to %s", p, real)
	}

	node, _, ctx := startSharedCandidateNode(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, nil)
	defer func() { _ = node.StopNode(context.WithoutCancel(ctx)) }()
	modes := map[string]fullpolicy.Mode{"A": fullpolicy.Enforce, "B": fullpolicy.Audit}
	inits := map[string]*sharedPipeInit{}
	for _, name := range []string{"A", "B"} {
		cgroup := filepath.Join(root, strings.ToLower(name))
		if err := os.MkdirAll(cgroup, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(cgroup) })
		p := startSharedPipeInitShell(t, cgroup, "ig15-d3-pathdeny-init-"+strings.ToLower(name), "/usr/bin/bash")
		t.Cleanup(p.stop)
		s, err := node.Bind(ctx, SharedBindingConfig{CgroupID: p.ino, InitHostPID: uint32(p.cmd.Process.Pid), Acquire: p.acquire})
		if err != nil {
			t.Fatalf("Bind %s: %v", name, err)
		}
		policy := &fullpolicy.Policy{
			ID: "d3-pathdeny-" + strings.ToLower(name), Revision: "1", Mode: modes[name], RootRole: "app", Default: fullpolicy.Allow,
			Rules: []fullpolicy.Rule{{Name: "deny-path", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{denied}}}},
		}
		if _, err := s.Publish(ctx, SharedBindingPolicy{Source: policy, Container: strings.ToLower(name)}); err != nil {
			t.Fatalf("publish %s: %v", name, err)
		}
		if st := s.Inspect(); st.Fault != nil || !st.RoutePublished || st.Adoption != nil {
			t.Fatalf("%s after adoption: %+v", name, st)
		}
		inits[name] = p
	}
	rc := func(name, file string) int {
		t.Helper()
		out, code, err := inits[name].run(ctx, file+" -c true; echo rc=$?")
		if err != nil || code != 0 {
			t.Fatalf("%s %s: %q code %d: %v", name, file, out, code, err)
		}
		i := strings.LastIndex(out, "rc=")
		if i < 0 {
			t.Fatalf("%s %s: no status in %q", name, file, out)
		}
		n, err := strconv.Atoi(strings.TrimSpace(out[i+3:]))
		if err != nil {
			t.Fatalf("%s %s: status %q", name, file, out)
		}
		return n
	}
	const eperm = 126 // bash: the exec was refused
	failed := false
	for _, tc := range []struct {
		name, file string
		want       int
	}{
		{"A", allowed, 0},
		{"A", denied, eperm},
		{"A", link, eperm},
		{"A", allowed, 0},
		{"B", allowed, 0},
		{"B", denied, 0},
		{"B", link, 0},
	} {
		got := rc(tc.name, tc.file)
		t.Logf("PATHDENY binding %s (%v) exec %s: rc %d, want %d", tc.name, modes[tc.name], filepath.Base(tc.file), got, tc.want)
		failed = failed || got != tc.want
	}
	if failed {
		t.Fatal("the path-fact verdicts differ from the policy")
	}
}

// sharedTruePath is the resolved path of /usr/bin/true. The engine records
// the path of the file that is executed, and on some distributions
// /usr/bin/true is a symlink (Ubuntu 26.04: /usr/bin/gnutrue), so the
// attached tests compare against the resolved path, never the literal.
var sharedTruePath = func() string {
	if p, err := filepath.EvalSymlinks("/usr/bin/true"); err == nil {
		return p
	}
	return "/usr/bin/true"
}()
