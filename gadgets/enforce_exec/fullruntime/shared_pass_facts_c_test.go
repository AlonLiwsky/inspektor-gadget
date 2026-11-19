// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// buildSharedPassFacts compiles the host contract of full/shared_pass_facts.h
// (testdata/shared_pass_facts.c) against header, the collector source.
func buildSharedPassFacts(t *testing.T, header string) string {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal("C compiler required", err)
	}
	full, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	policy, err := filepath.Abs("../fullpolicy/bpf")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "shared_pass_facts.h"), []byte(header), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "shared-pass-facts")
	// The header directory comes first: it shadows ../full's copy.
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-unknown-pragmas",
		"-iquote", dir, "-iquote", full, "-iquote", policy, "testdata/shared_pass_facts.c", "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	return binary
}

// TestSharedPassFactsContract (G020): the actual per-pass collector over
// reference-counting kfunc stubs: per-pass reset of every owned fact, each
// failure UNKNOWN with its own reason cell, the held ancestor chain (a
// reparent between iterations never splices two chains; every acquire and
// exe-file get released exactly once on every path), the 16-ancestor and
// 255-byte bounds, and the D5 root boundary.
func TestSharedPassFactsContract(t *testing.T) {
	header := mustRead(t, "../full/shared_pass_facts.h")
	out, err := exec.Command(buildSharedPassFacts(t, header)).CombinedOutput()
	if err != nil {
		t.Fatalf("pass facts contract: %v\n%s", err, out)
	}
	t.Log(strings.TrimSpace(string(out)))
}

// TestSharedPassFactsMutations: the contract fails each mutant of the
// collector that would let a fact through that the pass did not collect.
func TestSharedPassFactsMutations(t *testing.T) {
	header := mustRead(t, "../full/shared_pass_facts.h")
	for _, m := range []struct{ name, from, to string }{
		// No per-pass reset: the interpreter continuation's previous pass
		// target path (and fs, ancestors) survive a pass that cannot
		// collect them.
		{"no per-pass reset", "\tse_pf_reset(facts);\n", "\n"},
		// Each link read from the current task, not the held ancestor.
		{"unheld chain", "struct task_struct *next = se_pf_parent(held, &root);", "struct task_struct *next = se_pf_parent(task, &root);"},
		// D5: a path outside the task's root accepted as an ordinary path.
		{"outside root accepted", "\tif (reachable == 0)\n\t\treturn cells->outside;", "\tif (reachable == 0)\n\t\treachable = 1;"},
		// H1: path facts from a task root that is not the binding's anchor.
		{"root anchor ignored", "\tint rooted = !(fs_seq & 1) && SE_PF_ROOTED(anchor) == 1;", "\tint rooted = !(fs_seq & 1);"},
		// H1: an unreachable ancestor of the workload ending the chain
		// complete (ancestor hiding).
		{"hidden ancestor boundary", "\t\tif (fault) {\n\t\t\tfailed = 1;\n\t\t\tbreak;\n\t\t}\n\t\tcount = i + 1;", "\t\tif (fault) {\n\t\t\tboundary = 1;\n\t\t\tbreak;\n\t\t}\n\t\tcount = i + 1;"},
		// H1 race: no closing bracket (a sibling's chroot after the root
		// check spoofs the paths read after it).
		{"no closing root bracket", "\tif (SE_PF_FS_SEQ() != fs_seq || SE_PF_ROOTED(anchor) != 1) {", "\tif (0) {"},
		// H1 race: the closing bracket rechecks the root but not the
		// sequence (a chroot there and back).
		{"closing bracket without sequence", "\tif (SE_PF_FS_SEQ() != fs_seq || SE_PF_ROOTED(anchor) != 1) {", "\tif (SE_PF_ROOTED(anchor) != 1) {"},
		// H1 race: an odd (in-flight) sequence accepted at the check.
		{"odd sequence accepted", "\tint rooted = !(fs_seq & 1) && SE_PF_ROOTED(anchor) == 1;", "\tint rooted = SE_PF_ROOTED(anchor) == 1;"},
		// M1: invalid UTF-8 accepted as a known path.
		{"utf-8 unchecked", "\tif (!SE_PF_UTF8(out->bytes, n - 1))\n\t\treturn cells->utf8;\n", "\n"},
		// M2: a deleted actor accepted.
		{"deleted actor accepted", "\tif (cells->deleted && SE_PF_UNLINKED(file) != 0)\n\t\treturn cells->deleted;\n", "\n"},
		// A failed ancestor walk keeping its partial prefix.
		{"partial failed walk", "\t\tfacts->ancestor_count = 0;\n\t\tfacts->ancestors_complete = 0;\n\t\tSE_PF_STAT(SE_PF_ANCESTOR_UNKNOWN);\n\t\treturn;", "\t\tfacts->ancestor_count = count;\n\t\tSE_PF_STAT(SE_PF_ANCESTOR_UNKNOWN);\n\t\treturn;"},
	} {
		t.Run(m.name, func(t *testing.T) {
			if strings.Count(header, m.from) != 1 {
				t.Fatalf("mutation site %q not found exactly once: update the mutant", m.from)
			}
			mutant := strings.Replace(header, m.from, m.to, 1)
			out, err := exec.Command(buildSharedPassFacts(t, mutant)).CombinedOutput()
			if err == nil {
				t.Fatalf("the contract passed the mutant %q:\n%s", m.name, out)
			}
			t.Logf("mutant refused: %s", strings.TrimSpace(string(out)))
		})
	}
}
