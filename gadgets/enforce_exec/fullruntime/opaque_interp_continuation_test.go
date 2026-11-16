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

const interpContinuationMarker = "opaque interpreter continuation contract: PASS"

// interpContinuationBuilds are the host contract's compilations: both
// optimisation levels, and ASan/UBSan with no recovery.
var interpContinuationBuilds = []struct {
	name  string
	flags []string
}{
	{"O0", []string{"-O0"}},
	{"O2", []string{"-O2"}},
	{"asan-ubsan", []string{"-O1", "-g", "-fsanitize=address,undefined", "-fno-sanitize-recover=all"}},
}

func runInterpContinuationContract(t *testing.T, dir string, flags []string) (string, error) {
	t.Helper()
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "interp-continuation")
	args := append([]string{
		"-std=gnu11", "-Wall", "-Wextra", "-Werror",
		"-iquote", "../full", "-iquote", "../fullpolicy/bpf",
	}, flags...)
	args = append(args, "testdata/opaque_interp_continuation.c", "-o", binary)
	compile := exec.CommandContext(t.Context(), cc, args...)
	compile.Dir = dir
	if out, err := compile.CombinedOutput(); err != nil {
		return string(out), err
	}
	out, err := exec.CommandContext(t.Context(), binary).CombinedOutput()
	return string(out), err
}

// TestOpaqueInterpContinuationHostContract runs the G019 gap 4 (review H1)
// host contract (testdata/opaque_interp_continuation.c) on the real
// candidate ownership fixture: stage classes for passes 0..5 and the depth
// refusal, every stage's class-only resume and cleanup cascade, the
// suspended evaluation claim of every pass, the CONTINUE-only reader
// classification relaxation, the pending/continue receipt classes (a stale
// same-bprm receipt at a first admission stays pending), the failure-frame
// and WORK identity predicates, and accumulated proposals.
func TestOpaqueInterpContinuationHostContract(t *testing.T) {
	for _, build := range interpContinuationBuilds {
		t.Run(build.name, func(t *testing.T) {
			out, err := runInterpContinuationContract(t, ".", build.flags)
			if err != nil || !strings.Contains(out, interpContinuationMarker) {
				t.Fatalf("interpreter continuation contract: %v\n%s", err, out)
			}
		})
	}
}

// interpContinuationMutations are single-site source mutations of the
// production headers. Each must make the host contract fail (compile or
// run): the contract pins every premise the continuation relies on.
var interpContinuationMutations = []struct {
	name, file, from, to string
}{
	{
		"class-residue", "full/shared_pool_opaque_work_continuation_candidate.h",
		"stage % 3U == (expected & 3U)", "stage % 3U != (expected & 3U)",
	},
	{
		"class-pass-bound", "full/shared_pool_opaque_work_continuation_candidate.h",
		"return stage && stage <= se_owk_stage_class_last(expected) &&", "return stage &&",
	},
	{
		"class-token-pass-limit", "full/shared_pool_opaque_work_continuation_candidate.h",
		"((expected >> 2) & 0x3fU) < SE_OWK_EXEC_PASSES &&", "",
	},
	{
		"resume-ticket-stage", "full/shared_pool_opaque_work_continuation_candidate.h",
		"candidate->continuation_stage = (__u16)stage_seen;", "(void)stage_seen;",
	},
	{
		"classify-continue-only-work", "full/shared_pool_opaque_exec_reader_candidate.h",
		"(suspended_work || !owner->lease.meta->current_work_owned)", "(!owner->lease.meta->current_work_owned)",
	},
	{
		"classify-continue-no-new", "full/shared_pool_opaque_exec_reader_candidate.h",
		"if (exact && !suspended_work && !receipt", "if (exact && !receipt",
	},
	{
		"classify-continue-no-terminal", "full/shared_pool_opaque_exec_reader_candidate.h",
		"else if (!suspended_work &&", "else if (1 &&",
	},
	{
		"pending-needs-later", "full/shared_exec_interp_continuation.h",
		"return later && physical && bprm &&", "return physical && bprm &&",
	},
	{
		"pending-needs-identity", "full/shared_exec_interp_continuation.h",
		"receipt->invocation && receipt->scope &&", "receipt->scope &&",
	},
	{
		"continue-depth-bound", "full/shared_exec_interp_continuation.h",
		"return pass && pass < passes ? pass : 0;", "return pass && pass <= passes ? pass : 0;",
	},
	{
		"frames-handler-depth", "full/shared_exec_interp_continuation.h",
		"(handler_)->depth == 1 && !(handler_)->uncertain)", "!(handler_)->uncertain)",
	},
	{
		"frames-outer-bound", "full/shared_exec_interp_continuation.h",
		"(outer_)->invocation == (rcpt)->invocation &&", "",
	},
	{
		"work-class", "full/shared_exec_interp_continuation.h",
		"work->history.transaction.execution_class == mode;", "1;",
	},
	{
		"work-proposed", "full/shared_exec_interp_continuation.h",
		"SE_OWK_PROPOSAL_CONSUMED &&", "SE_OWK_PROPOSAL_CONSUMED || 1 ||",
	},
}

// copyInterpContinuationTree copies the sources the contract includes
// (../full, ../fullpolicy/bpf and this testdata file) so that a mutation
// is seen by every quoted include, which resolves relative to its file.
func copyInterpContinuationTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"full", "fullpolicy/bpf"} {
		src := filepath.Join("..", dir)
		err := filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(src, path)
			if err != nil {
				return err
			}
			dst := filepath.Join(root, dir, rel)
			if d.IsDir() {
				return os.MkdirAll(dst, 0o755)
			}
			if !strings.HasSuffix(path, ".h") && !strings.HasSuffix(path, ".c") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			return os.WriteFile(dst, data, 0o644)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile("testdata/opaque_interp_continuation.c")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "fullruntime/testdata"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "fullruntime/testdata/opaque_interp_continuation.c"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestOpaqueInterpContinuationHostMutations kills every mutation in
// interpContinuationMutations, after proving the unmutated copy passes.
func TestOpaqueInterpContinuationHostMutations(t *testing.T) {
	root := copyInterpContinuationTree(t)
	dir := filepath.Join(root, "fullruntime")
	if out, err := runInterpContinuationContract(t, dir, []string{"-O2"}); err != nil || !strings.Contains(out, interpContinuationMarker) {
		t.Fatalf("unmutated copy: %v\n%s", err, out)
	}
	for _, m := range interpContinuationMutations {
		t.Run(m.name, func(t *testing.T) {
			path := filepath.Join(root, m.file)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(string(original), m.from); n != 1 {
				t.Fatalf("mutation site %q occurs %d times in %s", m.from, n, m.file)
			}
			mutated := strings.Replace(string(original), m.from, m.to, 1)
			if err := os.WriteFile(path, []byte(mutated), 0o644); err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := os.WriteFile(path, original, 0o644); err != nil {
					t.Fatal(err)
				}
			}()
			if out, err := runInterpContinuationContract(t, dir, []string{"-O2"}); err == nil && strings.Contains(out, interpContinuationMarker) {
				t.Fatalf("mutation %s survived", m.name)
			}
		})
	}
}

// TestInterpContinuationRefusalPins pins the verdict object's interpreter
// continuation refusals (G019 final review L2, L4): GAP [9] is counted only
// at the continuation refusal, with its reason in opaque_real_interp_stats;
// a later pass that carries a terminal fault (first-exec qualification or
// terminal drain) is refused before any continuation dispatch with the
// static class verdict and cleanup, counted once in its own class (QUALIFY
// [6] or PENDING [7], as on a first pass), never also GAP.
func TestInterpContinuationRefusalPins(t *testing.T) {
	raw, err := os.ReadFile("bpf/opaque_real_owner_child_candidate.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	src := squashSpace(string(raw))
	for name, pin := range map[string]string{
		"GAP only with an interp reason": "real_owner_continue_refuse(unsigned long long *ctx, __u32 reason, __u32 mode)\n{\n" +
			"\tif (reason < SE_INTERP_STATS) {\n\t\treal_owner_interp_stat(reason);\n" +
			"\t\tSE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_GAP);\n\t}\n" +
			"\tlong verdict = real_owner_policy_failure_global(ctx, mode);\n" +
			"\t(void)real_owner_reader_quarantine_pending(\n\t\t(__u64)bpf_get_current_task_btf());",
		"terminal fault refuses before dispatch": "__u32 reason = SE_INTERP_STAT_FRAME;\n\t\tif (terminal_fault) {\n" +
			"\t\t\tSE_FAIL_CLOSED_RATE(terminal_fault & 2 ?\n\t\t\t\t\t\t    REAL_OWNER_RATE_QUALIFY :\n" +
			"\t\t\t\t\t\t    REAL_OWNER_RATE_PENDING);\n\t\t\treason = SE_INTERP_STATS;\n" +
			"\t\t} else if (!(result & 32)) {\n\t\t\tif (result & 1)\n" +
			"\t\t\t\tbpf_tail_call(ctx, &opaque_real_continue_strict,\n\t\t\t\t\t      0);\n\t\t\telse\n" +
			"\t\t\t\tbpf_tail_call(ctx, &opaque_real_continue_audit,\n\t\t\t\t\t      0);\n" +
			"\t\t\treason = SE_INTERP_STAT_GRAPH_MISS;\n\t\t}\n" +
			"\t\tif (result & 1)\n\t\t\treturn real_owner_continue_refuse(ctx, reason, 2);\n" +
			"\t\treturn real_owner_continue_refuse(ctx, reason, 1);",
	} {
		if strings.Count(src, squashSpace(pin)) != 1 {
			t.Errorf("interp continuation pin %q missing or duplicated:\n%s", name, pin)
		}
	}
	// GAP [9] is the interpreter continuation's class only (migration
	// relabel, gap 5, is a binding status, never a counted refusal).
	if n := strings.Count(src, squashSpace("SE_FAIL_CLOSED_RATE(REAL_OWNER_RATE_GAP)")); n != 1 {
		t.Errorf("REAL_OWNER_RATE_GAP counted at %d sites, want only real_owner_continue_refuse", n)
	}
}
