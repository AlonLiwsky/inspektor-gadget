// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification && enforce_exec_s1_bench

package fullruntime

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

// TestS1OverheadBench (S1 review N2) measures the workloads below in a
// cgroup bound Strict to an allow-all policy (or, with no object, in the
// same cgroup and no engine at all). It only uses helpers the base tree
// ab57bdda6 has too, so the same file builds the base and the stage-1
// binaries. Every sample is one line "BENCH metric=<m> rep=<i> value=<v>".
// A measurement tool behind its own tag (enforce_exec_s1_bench), absent from
// every test suite: go test -c -tags 'enforce_exec_shared_qualification
// enforce_exec_s1_bench'.
//
//	IG_S1_BENCH_OBJECT   the object (empty: no engine)
//	IG_S1_BENCH_HELPER   the static d1-helper (bench / noop modes)
//	IG_S1_BENCH_REPS     repetitions (default 5)
func TestS1OverheadBench(t *testing.T) {
	helper := os.Getenv("IG_S1_BENCH_HELPER")
	if helper == "" || os.Geteuid() != 0 {
		t.Skip("set IG_S1_BENCH_HELPER, as root")
	}
	reps, _ := strconv.Atoi(os.Getenv("IG_S1_BENCH_REPS"))
	if reps <= 0 {
		reps = 5
	}
	object := os.Getenv("IG_S1_BENCH_OBJECT")
	cgroup := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("ig15-s1-bench-%d", os.Getpid()))
	if err := os.MkdirAll(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(cgroup) })
	var run func(line string) string
	if object == "" {
		fd, err := os.Open(cgroup)
		if err != nil {
			t.Fatal(err)
		}
		defer fd.Close()
		run = func(line string) string {
			cmd := exec.Command("/bin/bash", "-c", line)
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(fd.Fd())}
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("%q: %v (%q)", line, err, out)
			}
			return string(out)
		}
	} else {
		c := &sharedVerdictCollector{}
		node, _, ctx := startSharedVerdictNode(t, object, c)
		defer func() { _ = node.StopNode(context.WithoutCancel(ctx)) }()
		p := startSharedPipeInitShell(t, cgroup, "ig15-s1-bench-init", "/usr/bin/bash")
		defer p.stop()
		s, err := node.Bind(ctx, SharedBindingConfig{CgroupID: p.ino, InitHostPID: uint32(p.cmd.Process.Pid), Acquire: p.acquire})
		if err != nil {
			t.Fatalf("Bind: %v", err)
		}
		cp, err := s.Compile(SharedBindingPolicy{Source: &fullpolicy.Policy{ID: "s1-bench", Revision: "1", Mode: fullpolicy.Enforce, RootRole: "app", Default: fullpolicy.Allow, Rules: []fullpolicy.Rule{{Name: "never", Action: fullpolicy.Deny, Target: fullpolicy.Target{Path: []string{"/nonexistent/never"}}}}}, Container: "bench"})
		if err != nil {
			t.Fatalf("compile: %v", err)
		}
		for attempt := 0; ; attempt++ {
			_, err = s.PublishCompiled(ctx, cp)
			if err == nil || attempt == 100 || !strings.Contains(err.Error(), "retryable") {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("publish: %v", err)
		}
		run = func(line string) string {
			out, code, err := p.run(ctx, line)
			if err != nil || code != 0 {
				t.Fatalf("%q: %q code %d: %v", line, out, code, err)
			}
			return out
		}
	}
	value := func(out, key string) int64 {
		for _, line := range strings.Split(out, "\n") {
			if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok && k == key {
				n, err := strconv.ParseInt(v, 10, 64)
				if err == nil {
					return n
				}
			}
		}
		t.Fatalf("no %s in %q", key, out)
		return 0
	}
	const forks = 500
	workloads := []struct{ metric, line, key string }{
		// getppid in a loop: ns per 1000 syscalls (the helper's best of 5).
		{"syscall_ns_per_1000", helper + " bench 200000", "NS_PER_1000_SYSCALLS"},
		// fork+exec+exit+wait of the static helper, ns each.
		{"forkexec_ns", fmt.Sprintf(`s=$(date +%%s%%N); for i in $(seq %d); do %s noop || exit $?; done; e=$(date +%%s%%N); echo FE=$(( (e-s)/%d ))`, forks, helper, forks), "FE"},
		// build-like: many short processes reading and hashing files.
		{"buildish_ms", `s=$(date +%s%N); find /usr/lib /usr/share -type f 2>/dev/null | head -6000 | xargs -n 20 -P 4 sha256sum >/dev/null 2>&1 || exit $?; e=$(date +%s%N); echo B=$(( (e-s)/1000000 ))`, "B"},
	}
	// Warm the page cache once.
	_ = run(workloads[2].line)
	for rep := 0; rep < reps; rep++ {
		for _, w := range workloads {
			v := value(run(w.line), w.key)
			t.Logf("BENCH metric=%s rep=%d value=%d", w.metric, rep, v)
		}
	}
}
