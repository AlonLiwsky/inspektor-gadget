// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// Compile-only ABI regression: this does NOT prove verifier or runtime behavior.
func TestFullOwnerImageCompile(t *testing.T) {
	header := os.Getenv("IG_EXEC_OWNER_VMLINUX")
	if header == "" {
		t.Skip("set IG_EXEC_OWNER_VMLINUX for compile-only coverage")
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []bool{false, true} {
		name := "immutable"
		if owner {
			name = "owner"
		}
		t.Run(name, func(t *testing.T) {
			obj := filepath.Join(t.TempDir(), "full.o")
			args := []string{"-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-Wno-missing-declarations", "-I" + filepath.Dir(header), "-I" + filepath.Join(root, "include"), "-I" + filepath.Join(root, "gadgets/enforce_exec/fullpolicy/bpf")}
			if owner {
				args = append(args, "-DENFORCE_EXEC_PERSISTENT_OWNER")
			}
			args = append(args, "-c", filepath.Join(root, "gadgets/enforce_exec/full/program.bpf.c"), "-o", obj)
			if out, err := exec.Command("clang", args...).CombinedOutput(); err != nil {
				t.Fatalf("%v\n%s", err, out)
			}
			spec, err := ebpf.LoadCollectionSpec(obj)
			if err != nil {
				t.Fatal(err)
			}
			if spec.Programs["enforce_exec_full"] == nil {
				t.Fatal("missing enforcement hook")
			}
			if _, ok := spec.Variables["enforce_exec_test_inject_error"]; ok {
				t.Fatal("production defines carry the test-only error injection switch")
			}
			if owner {
				resources := &operators.NativeResources{Maps: map[string]operators.NativeMapResource{}, Programs: map[string]operators.NativeProgramResource{}}
				for name, m := range spec.Maps {
					resource := operators.NativeMapResource{Type: uint32(m.Type), KeySize: m.KeySize, ValueSize: m.ValueSize, MaxEntries: m.MaxEntries, Flags: m.Flags}
					if inner := m.InnerMap; inner != nil {
						resource.InnerMap = &operators.NativeMapResource{Type: uint32(inner.Type), KeySize: inner.KeySize, ValueSize: inner.ValueSize, MaxEntries: inner.MaxEntries, Flags: inner.Flags}
					}
					resources.Maps[name] = resource
				}
				for name, p := range spec.Programs {
					resources.Programs[name] = operators.NativeProgramResource{Type: uint32(p.Type), Target: p.AttachTo, Instructions: uint64(len(p.Instructions)) * 2}
				}
				if err := validateOwnerResources(resources, 8); err != nil {
					t.Fatal(err)
				}
				for _, n := range []string{"eo_command", "eo_sched_exec", "eo_task_exit", "eo_movement_arm"} {
					if spec.Programs[n] == nil {
						t.Errorf("missing %s", n)
					}
				}
				for _, n := range []string{"policy", "bindings", "full_program", "full_faults"} {
					if spec.Maps[n] != nil {
						t.Errorf("legacy map %s in owner", n)
					}
				}
				if spec.Maps["eo_programs"] == nil || spec.Maps["eo_generation_faults"] == nil {
					t.Fatal("missing owner publication/fault maps")
				}
			} else if spec.Maps["full_program"] == nil || spec.Programs["eo_command"] != nil {
				t.Fatal("immutable profile changed")
			}
		})
	}
}

// Exercise the exact Makefile packaging without pulling a builder or publishing
// an image. The fake ig compiles the produced context against archived BTF.
func TestOwnerBuildContext(t *testing.T) {
	header := os.Getenv("IG_EXEC_OWNER_VMLINUX")
	if header == "" {
		t.Skip("archived vmlinux.h required")
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "ig-compile-context")
	body := `#!/bin/sh
set -eu
[ "$1" = image ] && [ "$2" = build ] && [ "$3" = -t ]
context=$5
[ -f "$context/fullruntime/bpf/gate.h" ]
grep -q 'enforce-exec-owner-abi: "2"' "$context/gadget.yaml"
! grep -q '^  enforce-exec-full:' "$context/gadget.yaml"
clang -target bpf -O2 -g -D__TARGET_ARCH_x86 -Wno-missing-declarations -I"$(dirname "$IG_EXEC_OWNER_VMLINUX")" -I"$OWNER_INCLUDE" -c "$context/program.bpf.c" -o "$OWNER_OBJECT"
`
	if err = os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	object := filepath.Join(dir, "packaged.o")
	command := exec.Command("make", "build", "IG="+script)
	command.Dir = filepath.Join(root, "gadgets/enforce_exec/full/owner")
	command.Env = append(os.Environ(), "OWNER_INCLUDE="+filepath.Join(root, "include"), "OWNER_OBJECT="+object)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatalf("context compile: %v\n%s", err, out)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	if spec.Programs["eo_command"] == nil || spec.Maps["eo_programs"] == nil {
		t.Fatal("owner context lost owner profile")
	}
}

// Guard: a fault on the exec path must never force a Strict decision
// (d->deny = 1; d->mode = 2), which blocked Audit bindings. The binding class
// decides through fe_lsm_verdict, on both the legacy and the ABI3 owner.
func TestOwnerExecFaultNeverForcesStrict(t *testing.T) {
	source, err := os.ReadFile("../full/program.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	if forced := regexp.MustCompile(`\b(decision|d)\s*(->|\.)\s*(mode|deny)\s*=[^=]`).FindAll(source, -1); len(forced) != 0 {
		t.Fatalf("program.bpf.c assigns the evaluator decision on a fault: %q", forced)
	}
	verdict := regexp.MustCompile(`fe_lsm_verdict\s*\(\s*execution_class\s*,\s*ret\s*,\s*error\s*,\s*d\s*\)`)
	if got := len(verdict.FindAll(source, -1)); got != 2 {
		t.Fatalf("want the ABI3 and legacy verdicts through fe_lsm_verdict, got %d", got)
	}
}
