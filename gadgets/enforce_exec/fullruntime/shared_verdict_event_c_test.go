// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// buildSharedVerdictEvent compiles the host contract of
// full/shared_verdict_event.h (testdata/shared_verdict_event.c) against
// header, the mapping source.
func buildSharedVerdictEvent(t *testing.T, header string) string {
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
	if err := os.WriteFile(filepath.Join(dir, "shared_verdict_event.h"), []byte(header), 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "shared-verdict-event")
	// The header directory comes first: it shadows ../full's copy.
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-unknown-pragmas",
		"-iquote", dir, "-iquote", full, "-iquote", policy, "testdata/shared_verdict_event.c", "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	return binary
}

// TestSharedVerdictEventContract (G020): the verdict event mapping table:
// Strict allow/deny, Audit would-deny, AUDIT_UNKNOWN -> error 0 and
// uncertain, Strict UNKNOWN / role conflict as the class verdict, out-of-range
// errors as FE_INVALID (error always 0..3), a path longer than 255 bytes or
// unknown, matched-rule bit 255, each facts_unknown bit, the D1 fault
// events, every byte written, and (deny && mode == 2) exactly the LSM
// verdict in every case.
func TestSharedVerdictEventContract(t *testing.T) {
	header := mustRead(t, "../full/shared_verdict_event.h")
	out, err := exec.Command(buildSharedVerdictEvent(t, header)).CombinedOutput()
	if err != nil {
		t.Fatalf("verdict event contract: %v\n%s", err, out)
	}
	t.Log(strings.TrimSpace(string(out)))
}

// TestSharedVerdictEventMutations: the contract kills each mutant that would
// report another verdict than the LSM's, leak an out-of-range error or a
// stale path.
func TestSharedVerdictEventMutations(t *testing.T) {
	header := mustRead(t, "../full/shared_verdict_event.h")
	for _, m := range []struct{ name, from, to string }{
		{"AUDIT_UNKNOWN kept as error", "\te->error = error <= FE_ROLE_CONFLICT ? error : FE_INVALID;", "\te->error = error;"},
		{"Audit class reports mode 2", "e->mode = class_mode == 2 && d->mode == 2 ? 2 : 1;", "e->mode = d->mode == 2 ? 2 : 1;"},
		{"fault reports allow", "\t\te->deny = 1;\n\t\te->mode = class_mode;\n\t\te->error = FE_INVALID;", "\t\te->mode = class_mode;\n\t\te->error = FE_INVALID;"},
		{"unknown path copied", "\tif (f && !(e->facts_unknown & SE_VERDICT_UNKNOWN_TARGET_PATH)) {", "\tif (f) {"},
		{"task cookie dropped", "\te->task_cookie = m->task_cookie;\n", "\n"},
		{"load epoch dropped", "\te->load_epoch = se_verdict_load_epoch;\n", "\n"},
		{"uncertainty dropped", "e->uncertain = error == FE_AUDIT_UNKNOWN || d->audit_unknown;", "e->uncertain = 0;"},
	} {
		t.Run(m.name, func(t *testing.T) {
			if strings.Count(header, m.from) != 1 {
				t.Fatalf("mutation site %q not found exactly once: update the mutant", m.from)
			}
			out, err := exec.Command(buildSharedVerdictEvent(t, strings.Replace(header, m.from, m.to, 1))).CombinedOutput()
			if err == nil {
				t.Fatalf("mutant survived: %s", out)
			}
		})
	}
}

// legacyVerdictEventStruct extracts struct event { ... }; of the legacy
// program (full/program.bpf.c).
func legacyVerdictEventStruct(t *testing.T) string {
	t.Helper()
	src := mustRead(t, "../full/program.bpf.c")
	m := regexp.MustCompile(`(?s)\nstruct event \{.*?\n\};`).FindString(src)
	if m == "" {
		t.Fatal("legacy struct event not found in full/program.bpf.c")
	}
	return m
}

type sharedBTFMember struct {
	name           string
	offset, size   uint32
	kind, typeName string
}

func sharedBTFMembers(t *testing.T, spec *btf.Spec, name string) []sharedBTFMember {
	t.Helper()
	var s *btf.Struct
	if err := spec.TypeByName(name, &s); err != nil {
		t.Fatalf("BTF struct %s: %v", name, err)
	}
	var out []sharedBTFMember
	for _, m := range s.Members {
		size, err := btf.Sizeof(m.Type)
		if err != nil {
			t.Fatal(err)
		}
		typ := btf.UnderlyingType(m.Type)
		out = append(out, sharedBTFMember{name: m.Name, offset: m.Offset.Bytes(), size: uint32(size), kind: fmt.Sprintf("%T", typ), typeName: typ.TypeName()})
	}
	return out
}

// TestSharedVerdictEventLegacyPrefix (G020 event ABI 1): compiled to BPF BTF
// (what the eBPF operator decodes the "verdict" datasource from), the
// shared event's members up to error are the legacy struct event's: names,
// offsets, sizes and kinds identical; the additive members follow, inside
// the legacy tail padding first. IG_SHARED_VERDICT_OBJECT additionally
// checks a built product object's own BTF.
func TestSharedVerdictEventLegacyPrefix(t *testing.T) {
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Fatal("clang required (BPF BTF)", err)
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
	src := "typedef unsigned char __u8;\ntypedef unsigned int __u32;\ntypedef int __s32;\ntypedef unsigned long long __u64;\n" +
		"#define FM_BLOB_LOOKUP(context, key) ((void)(context), (void)(key), (const struct fm_blob *)0)\n#include \"evaluator.h\"\n#include \"shared_verdict_event.h\"\n" + legacyVerdictEventStruct(t) + "\n" +
		"struct event legacy_event;\nstruct shared_verdict_event shared_event;\n"
	if err := os.WriteFile(filepath.Join(dir, "parity.c"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	obj := filepath.Join(dir, "parity.o")
	if out, err := exec.Command(clang, "-target", "bpf", "-O2", "-g", "-iquote", full, "-iquote", policy, "-c", filepath.Join(dir, "parity.c"), "-o", obj).CombinedOutput(); err != nil {
		t.Fatalf("clang: %v\n%s", err, out)
	}
	spec, err := btf.LoadSpec(obj)
	if err != nil {
		t.Fatal(err)
	}
	legacy := sharedBTFMembers(t, spec, "event")
	check := func(label string, shared []sharedBTFMember) {
		t.Helper()
		if len(shared) != len(legacy)+8 {
			t.Fatalf("%s: %d members, want the %d legacy + 8 additive", label, len(shared), len(legacy))
		}
		for i, m := range legacy {
			if shared[i] != m {
				t.Fatalf("%s: member %d is %+v, legacy %+v", label, i, shared[i], m)
			}
		}
		var names []string
		for _, m := range shared[len(legacy):] {
			names = append(names, fmt.Sprintf("%s@%d/%d", m.name, m.offset, m.size))
		}
		if got := strings.Join(names, " "); got != "exec_class@324/4 scope@328/8 exec_id@336/8 pass@344/4 uncertain@348/4 facts_unknown@352/4 task_cookie@360/8 load_epoch@368/8" {
			t.Fatalf("%s: additive members %s", label, got)
		}
	}
	// M7: the load epoch is an 8-byte read-only constant the agent sets
	// per load (operators.NativeConstantsKey).
	epoch := func(label, object string) {
		t.Helper()
		collection, err := ebpf.LoadCollectionSpec(object)
		if err != nil {
			t.Fatal(err)
		}
		v := collection.Variables[sharedVerdictLoadEpochConstant]
		if v == nil || !v.Constant() || v.Size() != 8 {
			t.Fatalf("%s: %s is not an 8-byte read-only constant: %v", label, sharedVerdictLoadEpochConstant, v)
		}
	}
	check("compiled header", sharedBTFMembers(t, spec, "shared_verdict_event"))
	epoch("compiled header", obj)
	if object := os.Getenv("IG_SHARED_VERDICT_OBJECT"); object != "" {
		product, err := btf.LoadSpec(object)
		if err != nil {
			t.Fatal(err)
		}
		check(object, sharedBTFMembers(t, product, "shared_verdict_event"))
		epoch(object, object)
	}
}
