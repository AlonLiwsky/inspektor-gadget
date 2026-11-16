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

func TestOwnerTaskStageCanonicalHistory(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}
	extract := func(path, begin, end string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		source := string(data)
		a, b := strings.Index(source, begin), strings.Index(source, end)
		if a < 0 || b <= a {
			t.Fatalf("missing actual stage boundary %s", begin)
		}
		return source[a+len(begin) : b]
	}
	driver, err := os.ReadFile("testdata/owner_task_stage.c")
	if err != nil {
		t.Fatal(err)
	}
	source := string(driver)
	for marker, body := range map[string]string{
		"/* ACTUAL_TRANSITIONS */":    extract("../full/owner_control.h", "/* EO_DISPATCH_TRANSITIONS_BEGIN */", "/* EO_DISPATCH_TRANSITIONS_END */"),
		"/* ACTUAL_DISPATCH_TYPES */": extract("../full/owner_types.h", "/* EO_DISPATCH_TYPES_BEGIN */", "/* EO_DISPATCH_TYPES_END */"),
		"/* ACTUAL_TASK_TYPES */":     "struct eo_exec_tx {" + extract("../full/owner_types.h", "struct eo_exec_tx {", "_Static_assert(sizeof(struct eo_config)"),
		"/* ACTUAL_STAGE_WRAPPER */":  extract("../full/owner_roles.h", "/* EO_TASK_STAGE_WRAPPER_BEGIN */", "/* EO_TASK_STAGE_WRAPPER_END */"),
		"/* ACTUAL_TASK_STAGE */":     extract("../full/owner_roles.h", "/* EO_TASK_STAGE_BEGIN */", "/* EO_TASK_STAGE_END */"),
	} {
		source = strings.Replace(source, marker, body, 1)
	}
	dir := t.TempDir()
	file, binary := filepath.Join(dir, "stage.c"), filepath.Join(dir, "stage")
	if err := os.WriteFile(file, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-DENFORCE_EXEC_ABI3_DEVELOPMENT=1", "-iquote", root, file, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("stage: %v\n%s", err, out)
	}
}

func TestOwnerCanonicalForkOwnership(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}
	extract := func(path, begin, end string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		source := string(data)
		a, b := strings.Index(source, begin), strings.Index(source, end)
		if a < 0 || b <= a {
			t.Fatalf("missing actual stage boundary %s", begin)
		}
		return source[a+len(begin) : b]
	}
	driver, err := os.ReadFile("testdata/owner_fork_canonical.c")
	if err != nil {
		t.Fatal(err)
	}
	source := string(driver)
	for marker, body := range map[string]string{
		"/* ACTUAL_DISPATCH_TYPES */": extract("../full/owner_types.h", "/* EO_DISPATCH_TYPES_BEGIN */", "/* EO_DISPATCH_TYPES_END */"),
		"/* ACTUAL_TASK_TYPES */":     "struct eo_exec_tx {" + extract("../full/owner_types.h", "struct eo_exec_tx {", "_Static_assert(sizeof(struct eo_config)"),
		"/* ACTUAL_TRANSITIONS */":    extract("../full/owner_control.h", "/* EO_DISPATCH_TRANSITIONS_BEGIN */", "/* EO_DISPATCH_TRANSITIONS_END */"),
		"/* ACTUAL_MUTATION */":       extract("../full/owner_control.h", "/* EO_MUTATION_CLAIM_BEGIN */", "/* EO_MUTATION_CLAIM_END */"),
		"/* ACTUAL_RELEASE */":        extract("../full/owner_roles.h", "/* EO_EXEC_ADMISSION_BEGIN */", "static __always_inline int eo_exec_begin_development"),
		"/* ACTUAL_FORK */":           extract("../full/owner_roles.h", "/* EO_CANONICAL_FORK_BEGIN */", "/* EO_CANONICAL_FORK_END */"),
		"/* ACTUAL_QUARANTINE */":     "static __always_inline void eo_quarantine(" + extract("../full/owner_types.h", "static __always_inline void eo_quarantine(", "// Force concrete local BTF"),
	} {
		source = strings.Replace(source, marker, body, 1)
	}
	dir := t.TempDir()
	file, binary := filepath.Join(dir, "stage.c"), filepath.Join(dir, "stage")
	if err := os.WriteFile(file, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-DENFORCE_EXEC_ABI3_DEVELOPMENT=1", "-iquote", root, file, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("stage: %v\n%s", err, out)
	}
}
