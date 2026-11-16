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

// TestOpaqueExecCapsuleContract drives the default-off source-only
// physical-exec capsule (full/shared_exec_capsule.h) through the actual
// shared_route.h helpers. It is the original-class replacement for the
// current-route fallback that TestOpaqueSourceModeHeaderlessMigrationContract
// keeps as a deliberate counterexample. Kernel serialization and hook
// coverage are proved separately on the exact AL2023 kernels.
// capsuleLaterVariants compiles each capsule contract without and with the
// later-admission report (SE_CAP_REPORT_LATER): its later-bit scenario
// requires the bit exactly on later admissions of the same exec when it is
// reported, and never otherwise.
var capsuleLaterVariants = []struct {
	name    string
	defines []string
}{
	{name: "", defines: nil},
	{name: "later", defines: []string{"-DSE_CAP_REPORT_LATER=1"}},
}

func TestOpaqueExecCapsuleContract(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	scenarios := []string{
		"same-scope", "headerless-migrated", "fresh-control",
		"losing-waiter", "nonleader-dethread",
		"wrong-duplicate-terminal", "stale-reuse", "check-only",
		"late-attach", "unselected-first", "fault-first",
		"sequence-exhausted", "out-of-range", "busy-capsule-degrades",
		"check-frozen-never-success", "tampered-owner-or-route",
		"pin-failed", "stale-then-exhausted", "terminal-and-entry-skipped",
		"stale-frozen-reused-bprm", "legacy-fallback-is-unsafe",
		"later-bit",
	}
	// G019 gap 4: with and without the later-admission report
	// (SE_CAP_REPORT_LATER, the interpreter-continuation objects).
	for _, variant := range capsuleLaterVariants {
		for _, optimization := range []string{"-O0", "-O2"} {
			t.Run(variant.name+optimization, func(t *testing.T) {
				binary := filepath.Join(t.TempDir(), "exec-capsule")
				args := append([]string{
					"-std=gnu11", optimization, "-Wall", "-Wextra",
					"-Werror", "-iquote", "../full", "-iquote",
					"../fullpolicy/bpf",
				}, variant.defines...)
				args = append(args, "testdata/opaque_exec_capsule_contract.c", "-o", binary)
				if out, err := exec.CommandContext(t.Context(), cc, args...).CombinedOutput(); err != nil {
					t.Fatalf("compile capsule fixture: %v\n%s", err, out)
				}
				for _, mode := range []string{"audit", "strict"} {
					for _, scenario := range scenarios {
						t.Run(mode+"/"+scenario, func(t *testing.T) {
							out, err := exec.CommandContext(t.Context(), binary,
								scenario, mode).CombinedOutput()
							if err != nil {
								t.Fatalf("capsule contract: %v\n%s", err, out)
							}
							want := scenario + "/" + mode + ": PASS"
							if !strings.Contains(string(out), want) {
								t.Fatalf("scenario did not run: %q", out)
							}
						})
					}
				}
			})
		}
	}
}

// TestOpaqueExecCapsuleTaskStorageContract drives the same capsule state
// machine through its task-storage adapter (G019 M4 user decision (ii)):
// storage only for execs that can matter, a failed create degrades and is
// counted, per-task isolation, and the lsm/task_free death retire that
// releases a missed terminal's original-route pin.
func TestOpaqueExecCapsuleTaskStorageContract(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	scenarios := []string{
		"selected-covered", "unselected-creates-nothing", "task-key-matters",
		"migrate-in-uncovered", "create-fails-degrades", "begin-create-skipped",
		"identity-mismatch-faults", "death-retires-pin",
		"death-after-terminal", "per-task-isolation", "stale-same-task",
		"entry-only", "stale-frozen-reused-bprm", "stale-ident-reused-bprm",
		"later-bit",
	}
	// G019 gap 4: with and without the later-admission report
	// (SE_CAP_REPORT_LATER, the interpreter-continuation objects).
	for _, variant := range capsuleLaterVariants {
		for _, optimization := range []string{"-O0", "-O2"} {
			t.Run(variant.name+optimization, func(t *testing.T) {
				binary := filepath.Join(t.TempDir(), "exec-capsule-ts")
				args := append([]string{
					"-std=gnu11", optimization, "-Wall", "-Wextra",
					"-Werror", "-iquote", "../full", "-iquote",
					"../fullpolicy/bpf",
				}, variant.defines...)
				args = append(args, "testdata/opaque_exec_capsule_task_storage_contract.c", "-o", binary)
				if out, err := exec.CommandContext(t.Context(), cc, args...).CombinedOutput(); err != nil {
					t.Fatalf("compile task-storage capsule fixture: %v\n%s", err, out)
				}
				for _, mode := range []string{"audit", "strict"} {
					for _, scenario := range scenarios {
						t.Run(mode+"/"+scenario, func(t *testing.T) {
							out, err := exec.CommandContext(t.Context(), binary,
								scenario, mode).CombinedOutput()
							if err != nil {
								t.Fatalf("task-storage capsule contract: %v\n%s", err, out)
							}
							if want := scenario + "/" + mode + ": PASS"; !strings.Contains(string(out), want) {
								t.Fatalf("scenario did not run: %q", out)
							}
						})
					}
				}
			})
		}
	}
}

// TestOpaqueExecCapsuleRequiresSourcePin keeps the capsule unusable without
// the explicit source-pin route candidate.
func TestOpaqueExecCapsuleRequiresSourcePin(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(t.TempDir(), "nopin.c")
	if err := os.WriteFile(src, []byte("#include <linux/bpf.h>\n#include \"shared_exec_capsule.h\"\nint main(void){return 0;}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.CommandContext(t.Context(), cc, "-std=gnu11", "-fsyntax-only",
		"-iquote", "../full", "-iquote", "../fullpolicy/bpf", src).CombinedOutput()
	if err == nil || !strings.Contains(string(out), "requires the source-mode route pin candidate") {
		t.Fatalf("capsule compiled without the source-pin candidate: %v\n%s", err, out)
	}
}

// TestOpaqueExecCapsuleTaskStorageSourcePins pins the verdict object's
// capsule adapter (G019 M4 user decision (ii)): task local storage on the
// executing task, never a loader-sized ARRAY; lookups never create; storage
// is created only for an exec that can matter; and the lsm/task_free death
// retire, a lookup-only program of its own.
func TestOpaqueExecCapsuleTaskStorageSourcePins(t *testing.T) {
	raw, err := os.ReadFile("bpf/opaque_real_owner_child_candidate.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	src := squashSpace(string(raw))
	for _, pin := range []string{
		"struct {\n\t__uint(type, BPF_MAP_TYPE_TASK_STORAGE);\n\t__uint(map_flags, BPF_F_NO_PREALLOC);\n" +
			"\t__type(key, int);\n\t__type(value, struct se_exec_capsule);\n} se_exec_capsules SEC(\".maps\");",
		"struct {\n\t__uint(type, BPF_MAP_TYPE_TASK_STORAGE);\n\t__uint(map_flags, BPF_F_NO_PREALLOC);\n" +
			"\t__type(key, int);\n\t__type(value, struct se_exec_marker);\n} se_exec_markers SEC(\".maps\");",
		"#define SE_CAP_ABSENT_OK 1\n#define SE_CAP_LOOKUP(tgid) ((void)(tgid), real_owner_capsule(0))",
		"#define SE_CAP_MARKER_LOOKUP(pid) ((void)(pid), real_owner_marker(0))",
		"#define SE_CAP_MATTERS() real_owner_capsule_matters()",
		// Review OQ: product objects mark an exec entry with a live capsule.
		// G019 gap 4: the continuation objects report SE_CAP_LATER and
		// require the task-storage adapter (absent storage is a first,
		// uncovered admission, never a later one).
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n#define SE_CAP_ENTRY_MARKS_LIVE_CAPSULE 1\n#endif\n/* G019 gap 4:",
		"#ifdef ENFORCE_EXEC_POOL_OPAQUE_INTERP_CONTINUATION_CANDIDATE\n#ifndef SE_CAP_ABSENT_OK\n" +
			"#error \"interpreter continuation requires the task-storage capsule adapter\"\n#endif\n" +
			"#define SE_CAP_REPORT_LATER 1\n#endif\n#include \"shared_exec_capsule.h\"",
		"__u32 later = frozen_class & SE_CAP_LATER;\n\tfrozen_class &= ~SE_CAP_LATER;\n#endif\n" +
			"\tif (admission == SE_ROUTE_OWNED &&\n\t    (frozen_class != claim.execution_class ||\n" +
			// The test-only exec admission injector (0 outside
			// ENFORCE_EXEC_POOL_OPAQUE_FAIL_CLOSED_INJECTOR_EXT_DIAGNOSTIC,
			// pinned in TestOpaqueRealVerdictCandidateCompileGuards).
			"\t     SE_FC_EXEC_ADMISSION_FAULT(later))) {",
		"if (entry && *entry)\n\t\treturn 1;\n\t__u64 key = (__u64)bpf_get_current_task_btf();\n" +
			"\treturn bpf_map_lookup_elem(&se_opaque_keys, &key) != 0;",
		// G019 gap 1: the product's death retire also releases a birth
		// park its target never took (lookup only, never create).
		"SEC(\"lsm/task_free\")\nint BPF_PROG(real_owner_capsule_free, struct task_struct *task)\n{\n" +
			"\t(void)se_cap_on_free(\n\t\tbpf_task_storage_get(&se_exec_capsules, task, 0, 0));\n" +
			"#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n" +
			"\tse_birth_park_drop(bpf_task_storage_get(&se_birth_parks, task, 0, 0),\n\t\t\t   SE_BIRTH_PARK_STALE);\n#endif\n\treturn 0;\n}",
	} {
		if strings.Count(src, squashSpace(pin)) != 1 {
			t.Errorf("task-storage capsule pin missing or duplicated:\n%s", pin)
		}
	}
	// Creation only through the CREATE adapters (begin/entry when the exec
	// matters, or the first selected admission); never an ARRAY capsule.
	route, err := os.ReadFile("../full/shared_route.h")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(squashSpace(string(route)), squashSpace(
		"if (c->owned || SE_SOURCE_TOKEN_RECORD_BAD(t) ||\n\t    t->execution_class != frozen_class ||\n"+
			"#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n\t    t->record != a->active_record ||\n#endif\n"+
			"\t    a->phase != SE_ROUTE_ACTIVE || a->reserved || !a->incarnation ||\n"+
			"\t    t->slot != a->payload_slot || t->incarnation != a->incarnation ||\n"+
			"\t    t->scope != a->scope || t->generation != a->payload_generation ||\n"+
			"\t    a->execution_class != frozen_class ||")) {
		t.Error("identity-bound re-admission must require the original route's exact payload identity")
	}
	// The two capsule CREATE adapters, the birth park's put (G019 gap 1:
	// the source's park on the forking task), and the staged verdict event
	// of a clean proposal (G020 H2, the exec'ing task's own storage).
	if n := strings.Count(src, "BPF_LOCAL_STORAGE_GET_F_CREATE"); n != 4 {
		t.Errorf("BPF_LOCAL_STORAGE_GET_F_CREATE appears %d times, want exactly the two CREATE adapters, the birth park's put and the staged verdict event", n)
	}
	if !strings.Contains(src, squashSpace("bpf_task_storage_get(&se_verdict_staging,\n\t\t\t\t     bpf_get_current_task_btf(), 0,\n\t\t\t\t     BPF_LOCAL_STORAGE_GET_F_CREATE);")) {
		t.Error("the only verdict-staging CREATE is on the current task")
	}
	if strings.Contains(src, squashSpace("__type(value, struct se_exec_capsule);\n} se_exec_capsules")) &&
		strings.Contains(src, squashSpace("__uint(type, BPF_MAP_TYPE_ARRAY);\n\t__uint(max_entries, 1);\n\t__type(key, __u32);\n\t__type(value, struct se_exec_capsule);")) {
		t.Error("the capsule must never be an ARRAY")
	}
	header, err := os.ReadFile("../full/shared_exec_capsule.h")
	if err != nil {
		t.Fatal(err)
	}
	h := squashSpace(string(header))
	for _, pin := range []string{
		"#define SE_CAP_STAT_DEATH_RETIRED 14 /* non-FREE capsule retired at task_free */\n#define SE_CAP_STATS 15",
		"if (c->phase == SE_CAP_OPEN || c->phase == SE_CAP_FROZEN) {\n\t\tse_cap_view_locked(c, &v);\n\t\tc->phase = SE_CAP_RETIRING;",
		"SE_CAP_STAT(SE_CAP_STAT_DEATH_RETIRED);\n\treturn se_cap_retire(c, &v) ? -1 : 1;",
		// Review M2: an unpinned frozen exec re-claims only the ORIGINAL
		// route by its recorded identity, never the current route by class.
		"if (!(v.flags & SE_CAP_F_IDENT))\n\t\t\t\treturn fault;",
		"int ir = se_route_claim_ident_locked(\n\t\t\t\tia, &c->owner.token, cls, claim);",
		"freeze_err = se_cap_freeze_uncovered_locked(\n\t\t\t\tc, task, bprm, sequence, cls,\n\t\t\t\tr == SE_ROUTE_OWNED ? claim : 0);",
		"if (ident && ident->owned &&\n\t    ident->execution_class == execution_class) {",
		// Review follow-up: a capsule is mine only if this exec opened
		// it; a pending entry marker means it opened nothing yet.
		"if (!entry_pending && se_cap_mine(c, task, bprm))",
		"int entry_pending = m && task && bprm && m->task == task &&\n\t\t\t    m->bprm == bprm;",
		"if (entry_pending)\n\t\t\t\t(void)se_cap_take_marker(m, task, bprm);",
	} {
		if !strings.Contains(h, squashSpace(pin)) {
			t.Errorf("capsule death-retire pin missing:\n%s", pin)
		}
	}
}
