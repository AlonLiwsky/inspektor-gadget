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

// TestBirthParkContract drives full/shared_birth_receipt.h on the host (G019
// gaps 1 and 2): the cross-generation qualification truth table and the
// birth park's put, take, abandon, stale release and latch over the actual
// shared_route.h claim helpers, in both classes, at -O0 and -O2.
func TestBirthParkContract(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	scenarios := []string{"admits-truth-table", "put-take", "take-failures", "take-latch", "abandon", "stale", "latch", "put-fails"}
	for _, optimization := range []string{"-O0", "-O2"} {
		t.Run(optimization, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "birth-park")
			args := []string{
				"-std=gnu11", optimization, "-Wall", "-Wextra", "-Werror",
				"-iquote", "../full", "-iquote", "../fullpolicy/bpf",
				"testdata/birth_park_contract.c", "-o", binary,
			}
			if out, err := exec.CommandContext(t.Context(), cc, args...).CombinedOutput(); err != nil {
				t.Fatalf("compile birth park fixture: %v\n%s", err, out)
			}
			for _, mode := range []string{"audit", "strict"} {
				for _, scenario := range scenarios {
					t.Run(mode+"/"+scenario, func(t *testing.T) {
						out, err := exec.CommandContext(t.Context(), binary, scenario, mode).CombinedOutput()
						if err != nil {
							t.Fatalf("birth park contract: %v\n%s", err, out)
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

// TestBirthParkSourcePins pins the verdict object's use of the birth park
// and the cross-generation qualification (product publisher objects only;
// every other object keeps its bytes): the source parks its claim instead of
// releasing it, the target takes it instead of re-admitting the cgroup,
// every failure before construction abandons it, task_free releases a park
// no target took, and real_owner_birth_qualify admits through
// se_birth_receipt_admits with the receipt's class.
func TestBirthParkSourcePins(t *testing.T) {
	raw, err := os.ReadFile("bpf/opaque_real_owner_child_candidate.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	src := squashSpace(string(raw))
	const pub = "#ifdef ENFORCE_EXEC_POOL_OPAQUE_PRODUCT_PUBLISHER_CANDIDATE\n"
	for name, pin := range map[string]string{
		"park storage": "struct {\n\t__uint(type, BPF_MAP_TYPE_TASK_STORAGE);\n\t__uint(map_flags, BPF_F_NO_PREALLOC);\n" +
			"\t__type(key, int);\n\t__type(value, struct se_birth_park);\n} se_birth_parks SEC(\".maps\");",
		"park witness": "__uint(max_entries, SE_BIRTH_PARK_CELLS);\n\t__uint(map_flags, BPF_F_RDONLY);\n" +
			"\t__type(key, __u32);\n\t__type(value, __u64);\n} opaque_real_birth_park SEC(\".maps\");",
		"park requires the capsule death retire": pub + "#ifndef ENFORCE_EXEC_POOL_OPAQUE_SOURCE_CAPSULE_CANDIDATE\n" +
			"#error \"the birth park's task_free release rides the exec capsule death retire\"\n#endif",
		"receipt class field": pub + "\t/* G019 gap 2: the birth claim's execution class (1 Audit, 2 Strict). */\n" +
			"\t__u32 slot, incarnation, record, state, observation, execution_class;\n#else\n" +
			"\t__u32 slot, incarnation, record, state, observation, reserved;\n#endif",
		"receipt records the class": pub + "\treceipt->execution_class = claim->execution_class;\n#endif\n\treceipt->state = 1;",
		"source parks its claim": pub + "/* G019 gap 1: the claim goes to the target through the birth park. A\n" +
			"\t * failed put releases it here and finishes the suspended WORK through\n" +
			"\t * the missing-target path (-2, counted there: one class). */\n" +
			"\tif (!result && !se_birth_park_put(&claim, (__u64)child, parent_cookie)) {\n" +
			"#ifdef ENFORCE_EXEC_POOL_OPAQUE_BIRTH_PARK_SPIN_DIAGNOSTIC\n\t\treal_owner_birth_park_spin();\n#endif\n\t\treturn 0;\n\t}\n" +
			"\tif (!result)\n\t\tresult = -2;\n#endif\n\tint released = real_owner_child_release_claim(&claim);",
		"target takes the park": pub + "\tint admission = se_birth_park_take((__u64)child, &claim, mode_out);\n#else\n" +
			"\tint admission = se_route_admit(bpf_get_current_cgroup_id(), &claim);\n#endif",
		"open-parent failure abandons": "SE_EXEC_EXCLUSION_WITNESS(2);\n" + pub + "\t\tse_birth_park_abandon(mode_out);\n#endif\n" +
			"\t\treturn -3; /* fail-closed rate [8], counted by the caller */",
		"close-parent failure abandons": "close_parent:\n" + pub + "\tse_birth_park_abandon(mode_out);\n#endif",
		"task_free releases a stale park": pub + "\tse_birth_park_drop(bpf_task_storage_get(&se_birth_parks, task, 0, 0),\n" +
			"\t\t\t   SE_BIRTH_PARK_STALE);\n#endif\n\treturn 0;\n}",
		"qualify admits across generations": "int same_claim = admits > 0;\n#else",
		"qualify re-checks the same verdict": "claim.execution_class) == admits) {\n\t\treceipt->state = 3;\n" +
			"\t\tif (admits == 2)\n\t\t\treal_owner_birth_park_count(\n\t\t\t\tSE_BIRTH_PARK_CROSS_GENERATION);\n\t\treturn 1;\n\t}",
		"qualify invariant is a fault": "return same_claim || released || admits < 0 ? -1 : 0;\n#else",
	} {
		if strings.Count(src, squashSpace(pin)) != 1 {
			t.Errorf("birth park pin %q missing or duplicated:\n%s", name, pin)
		}
	}
	// The straddle-widening spin is a diagnostic twin's only.
	// Its only product-composition carrier is the explicit test twin
	// (SE_PRODUCT_DIAGNOSTIC_TWIN), which product admission refuses.
	if !strings.Contains(src, squashSpace("#if defined(SE_PRODUCT_NO_TEST_RUN) && !defined(SE_PRODUCT_DIAGNOSTIC_TWIN)\n"+
		"#error \"the birth-park spin widens a diagnostic twin's straddle window only\"\n#endif")) {
		t.Error("the birth-park spin must refuse a product object")
	}
	if n := strings.Count(src, "se_birth_park_abandon("); n != 3 {
		t.Errorf("se_birth_park_abandon at %d sites, want the source fall-through and the two target pre-construction failures", n)
	}
	// The target's own parked claim that no longer validates is latched
	// under the route lock (as a failed release in se_birth_park_drop) and
	// counted LATCHED, never released; TAKE_FAILED still counts its
	// CONSTRUCT (G019 final review L3).
	header, err := os.ReadFile("../full/shared_birth_receipt.h")
	if err != nil {
		t.Fatal(err)
	}
	take := "bpf_spin_lock(&route->lock);\n\t\t\t\tvalid = se_route_claim_valid(route, claim);\n" +
		"\t\t\t\tif (!valid)\n\t\t\t\t\troute->unresolved_sources = 1;\n\t\t\t\tbpf_spin_unlock(&route->lock);\n\t\t\t}\n" +
		"\t\t\t/* Never release an invalid claim (it is not ours). */\n\t\t\tif (!valid) {\n\t\t\t\tclaim->owned = 0;\n" +
		"\t\t\t\tSE_BIRTH_PARK_COUNT(SE_BIRTH_PARK_LATCHED);\n\t\t\t}\n\t\t}\n\t}\n" +
		"\tSE_BIRTH_PARK_COUNT(valid ? SE_BIRTH_PARK_TAKEN :\n\t\t\t\t    SE_BIRTH_PARK_TAKE_FAILED);"
	if strings.Count(squashSpace(string(header)), squashSpace(take)) != 1 {
		t.Errorf("se_birth_park_take must latch an invalid parked claim's route and count LATCHED:\n%s", take)
	}
}
