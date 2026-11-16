// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/nativeattach"
)

// G009 step 1: static per-target BPF trampoline link inventory. Only programs
// that take a trampoline link are counted: Tracing fentry/fexit/fmod_ret and
// LSM. An LSM hook X shares the trampoline of the kernel function bpf_lsm_X,
// so it is keyed by that name. tp_btf, kprobes, syscall and TC programs do
// not count. This is a count of ELF programs, not of what a loader attaches.

func trampolineInventory(programs map[string]*ebpf.ProgramSpec) map[string]int {
	counts := map[string]int{}
	for _, p := range programs {
		if target := nativeattach.TrampolineTarget(p); target != "" {
			counts[target]++
		}
	}
	return counts
}

func TestTrampolineInventoryCounting(t *testing.T) {
	programs := map[string]*ebpf.ProgramSpec{
		"lsm":      {Type: ebpf.LSM, AttachType: ebpf.AttachLSMMac, AttachTo: "bprm_check_security"},
		"lsm2":     {Type: ebpf.LSM, AttachType: ebpf.AttachLSMMac, AttachTo: "bprm_check_security"},
		"fentry":   {Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry, AttachTo: "bprm_execve"},
		"fexit":    {Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFExit, AttachTo: "bprm_execve"},
		"modret":   {Type: ebpf.Tracing, AttachType: ebpf.AttachModifyReturn, AttachTo: "copy_process"},
		"lsmtramp": {Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry, AttachTo: "bpf_lsm_bprm_check_security"},
		"tp_btf":   {Type: ebpf.Tracing, AttachType: ebpf.AttachTraceRawTp, AttachTo: "sched_process_exec"},
		"kprobe":   {Type: ebpf.Kprobe, AttachTo: "bprm_execve"},
		"syscall":  {Type: ebpf.Syscall},
		"tc":       {Type: ebpf.SchedCLS},
		"iter":     {Type: ebpf.Tracing, AttachType: ebpf.AttachTraceIter, AttachTo: "task"},
	}
	want := map[string]int{"bpf_lsm_bprm_check_security": 3, "bprm_execve": 2, "copy_process": 1}
	if got := trampolineInventory(programs); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("inventory %v, want %v", got, want)
	}
}

// goldenTrampolineInventory pins the per-target counts of known objects.
// Labels come from IG_ENFORCE_EXEC_INVENTORY_OBJECTS; see
// ~/.local/state/sandbox-policy-recovery/g009-capacity-20261110/build-inventory.sh.
var goldenTrampolineInventory = map[string]map[string]int{
	"product":        {"bpf_lsm_bprm_check_security": 1},
	"full-immutable": {"bpf_lsm_bprm_check_security": 1, "bpf_lsm_inode_init_security_anon": 1},
	"full-owner": {
		"bpf_lsm_bprm_check_security": 1, "bpf_lsm_inode_init_security_anon": 1, "bpf_lsm_task_alloc": 1,
		"bprm_execve": 1, "cgroup_kn_lock_live": 1, "cgroup_migrate": 2, "cgroup_update_dfl_csses": 2,
		"copy_process": 1,
	},
	// Qualified candidate g25final128 (ELF programs; the candidate loader may
	// attach a subset).
	"g25final128":      goldenCandidateInventory,
	"g25final128-6.12": goldenCandidateInventory,
}

var goldenCandidateInventory = map[string]int{
	"bpf_lsm_bprm_check_security": 13, "bpf_lsm_task_alloc": 3, "bpf_lsm_task_free": 1,
	"bpf_lsm_task_kill": 1, "bpf_lsm_task_prctl": 1, "bprm_execve": 3,
	"security_bprm_creds_for_exec": 1,
}

func TestTrampolineInventoryObjects(t *testing.T) {
	env := os.Getenv("IG_ENFORCE_EXEC_INVENTORY_OBJECTS")
	if env == "" {
		t.Skip("set IG_ENFORCE_EXEC_INVENTORY_OBJECTS=label=/path/obj.o[,label=/path/obj.o...] for the static trampoline inventory")
	}
	inventories := map[string]map[string]int{}
	var labels []string
	targets := map[string]bool{}
	for _, entry := range strings.Split(env, ",") {
		label, path, ok := strings.Cut(entry, "=")
		if !ok || label == "" || path == "" {
			t.Fatalf("malformed entry %q, want label=path", entry)
		}
		if inventories[label] != nil {
			t.Fatalf("duplicate label %q", label)
		}
		spec, err := ebpf.LoadCollectionSpec(path)
		if err != nil {
			t.Fatalf("%s: %v", label, err)
		}
		inventories[label] = trampolineInventory(spec.Programs)
		labels = append(labels, label)
		for target := range inventories[label] {
			targets[target] = true
		}
	}
	sortedTargets := make([]string, 0, len(targets))
	for target := range targets {
		sortedTargets = append(sortedTargets, target)
	}
	sort.Strings(sortedTargets)
	var b strings.Builder
	fmt.Fprintf(&b, "%-36s", "target")
	for _, label := range labels {
		fmt.Fprintf(&b, " %18s", label)
	}
	b.WriteByte('\n')
	for _, target := range sortedTargets {
		fmt.Fprintf(&b, "%-36s", target)
		for _, label := range labels {
			fmt.Fprintf(&b, " %18d", inventories[label][target])
		}
		b.WriteByte('\n')
	}
	t.Logf("trampoline links per target:\n%s", b.String())
	for _, label := range labels {
		golden, ok := goldenTrampolineInventory[label]
		if !ok {
			t.Errorf("%s: no golden inventory; pin %#v", label, inventories[label])
			continue
		}
		if fmt.Sprint(golden) != fmt.Sprint(inventories[label]) {
			t.Errorf("%s: inventory changed: got %v, golden %v", label, inventories[label], golden)
		}
	}
}

// TestLegacyOwnerTrampolineSource derives, for documentation only, the
// per-Owner trampoline link count from ownerHooks in owner.go and the SEC()
// of each hook in the full/ sources. Every legacy Owner attaches its own
// copy of each hook.
func TestLegacyOwnerTrampolineSource(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "owner.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var hooks []string
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.ValueSpec)
		if !ok || len(spec.Names) != 1 || spec.Names[0].Name != "ownerHooks" {
			return true
		}
		for _, elt := range spec.Values[0].(*ast.CompositeLit).Elts {
			key, err := strconv.Unquote(elt.(*ast.KeyValueExpr).Key.(*ast.BasicLit).Value)
			if err != nil {
				t.Fatal(err)
			}
			hooks = append(hooks, key)
		}
		return false
	})
	if len(hooks) == 0 {
		t.Fatal("ownerHooks not found in owner.go")
	}
	sections := map[string]string{}
	re := regexp.MustCompile(`SEC\("([^"]+)"\)[\s\S]{0,120}?BPF_PROG\(\s*(\w+)`)
	for _, name := range []string{"program.bpf.c", "owner_control.h", "owner_roles.h"} {
		data, err := os.ReadFile(filepath.Join("..", "full", name))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			if prev, ok := sections[m[2]]; ok && prev != m[1] {
				t.Fatalf("%s has sections %s and %s", m[2], prev, m[1])
			}
			sections[m[2]] = m[1]
		}
	}
	perTarget := map[string]int{}
	total := 0
	for _, hook := range hooks {
		section, ok := sections[hook]
		if !ok {
			t.Fatalf("no SEC() for owner hook %s", hook)
		}
		kind, target, _ := strings.Cut(section, "/")
		switch kind {
		case "lsm", "lsm.s":
			target = "bpf_lsm_" + target
		case "fentry", "fexit", "fmod_ret":
		default:
			continue
		}
		perTarget[target]++
		total++
	}
	sorted := make([]string, 0, len(perTarget))
	for target := range perTarget {
		sorted = append(sorted, target)
	}
	sort.Strings(sorted)
	var b strings.Builder
	for _, target := range sorted {
		fmt.Fprintf(&b, "%-36s %d\n", target, perTarget[target])
	}
	t.Logf("legacy Owner (source, per owner; documentation only): %d hooks, %d trampoline links:\n%s",
		len(hooks), total, b.String())
}

// G009 packaging: the candidate's attach set is the ELF minus the programs its
// packaged metadata disables (programs.<name>.attach_to:
// gadget_program_disabled, read by the eBPF operator exactly like this).
// Diagnostic twins (live bootstrap) merge candidateDiagnosticPackaging after
// candidatePackaging; the product object takes candidatePackaging alone.
const (
	candidatePackaging           = "bpf/opaque_real_owner_child_candidate.programs.yaml"
	candidateDiagnosticPackaging = "bpf/opaque_real_owner_child_candidate.programs.diagnostic.yaml"
	disabledProgram              = "gadget_program_disabled"
)

// candidateAttachSet is the qualified loader's steady-state trampoline attach
// set (TestOpaqueRealPolicyVerdictAttached), pinned per program and per hook.
var (
	candidateAttachSet = map[string]string{
		"opaque_real_owner_child_final_free_candidate": "bpf_lsm_task_free",
		"opaque_real_owner_child_source_candidate":     "bpf_lsm_task_alloc",
		"real_owner_capsule_free":                      "bpf_lsm_task_free",
		"opaque_real_owner_failure_fexit_probe":        "bprm_execve",
		"real_owner_capsule_terminal":                  "bprm_execve",
		"real_owner_capsule_entry":                     "bprm_execve",
		"real_owner_capsule_begin":                     "security_bprm_creds_for_exec",
		"opaque_real_owner_reader_begin_probe":         "bpf_lsm_bprm_check_security",
	}
	candidateAttachPerHook = map[string]int{
		"bpf_lsm_task_free": 2, "bpf_lsm_task_alloc": 1, "bprm_execve": 3,
		"security_bprm_creds_for_exec": 1, "bpf_lsm_bprm_check_security": 1,
	}
)

func loadCandidatePackaging(t *testing.T) *viper.Viper {
	t.Helper()
	return loadCandidateMetadata(t, candidatePackaging)
}

// loadCandidateMetadata reads and merges the metadata files in order, as the
// OCI handler reads gadget.yaml into the operator config.
func loadCandidateMetadata(t *testing.T, paths ...string) *viper.Viper {
	t.Helper()
	config := viper.New()
	config.SetConfigType("yaml")
	for k, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		read := config.MergeConfig
		if k == 0 {
			read = config.ReadConfig
		}
		if err := read(strings.NewReader(string(data))); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	return config
}

func candidateDisabled(config *viper.Viper) map[string]bool {
	out := map[string]bool{}
	for name := range config.GetStringMap("programs") {
		if config.GetString("programs."+name+".attach_to") == disabledProgram {
			out[name] = true
		}
	}
	return out
}

// TestCandidateAttachSetDeclaration checks the packaging without the object:
// every tail-call target the loader installs is disabled, no steady-state
// program is, and every entry only disables.
func TestCandidateAttachSetDeclaration(t *testing.T) {
	config := loadCandidatePackaging(t)
	disabled := candidateDisabled(config)
	diagnostic := loadCandidateMetadata(t, candidateDiagnosticPackaging)
	for _, c := range []*viper.Viper{config, diagnostic} {
		only := candidateDisabled(c)
		for name, entry := range c.GetStringMap("programs") {
			fields, ok := entry.(map[string]any)
			if !ok || len(fields) != 1 || !only[name] {
				t.Errorf("%s: packaging entry %v must be exactly attach_to: %s", name, entry, disabledProgram)
			}
		}
	}
	for name := range candidateDisabled(diagnostic) {
		if disabled[name] {
			t.Errorf("%s is in both the product and the diagnostic packaging", name)
		}
	}
	tailCallTargets := []string{"opaque_real_owner_child_target_candidate", "opaque_real_owner_terminal_retain_target"}
	for _, program := range opaqueVerdictGraphs {
		tailCallTargets = append(tailCallTargets, program)
	}
	for _, name := range tailCallTargets {
		if !disabled[name] {
			t.Errorf("tail-call target %s is not disabled", name)
		}
	}
	for name := range candidateAttachSet {
		if disabled[name] {
			t.Errorf("steady-state program %s is disabled", name)
		}
	}
	perHook := map[string]int{}
	for _, target := range candidateAttachSet {
		perHook[target]++
	}
	if fmt.Sprint(perHook) != fmt.Sprint(candidateAttachPerHook) {
		t.Fatalf("pinned attach set %v, per hook %v", perHook, candidateAttachPerHook)
	}
}

// TestCandidateAttachSetObjects derives the attach set from the packaging plus
// each object and pins it: a new trampoline program fails until it is
// disabled in the packaging or added to the pinned set. Objects in
// IG_ENFORCE_EXEC_PRODUCT_OBJECTS take the product packaging alone; objects
// in IG_ENFORCE_EXEC_CANDIDATE_OBJECTS (diagnostic twins with live
// bootstrap) take it merged with the diagnostic packaging. Both are
// comma-separated object paths.
func TestCandidateAttachSetObjects(t *testing.T) {
	product, diagnostic := os.Getenv("IG_ENFORCE_EXEC_PRODUCT_OBJECTS"), os.Getenv("IG_ENFORCE_EXEC_CANDIDATE_OBJECTS")
	if product == "" && diagnostic == "" {
		t.Skip("set IG_ENFORCE_EXEC_PRODUCT_OBJECTS and/or IG_ENFORCE_EXEC_CANDIDATE_OBJECTS=/path/<object>.bpf.o[,...] for the packaged attach set")
	}
	for _, path := range candidateObjectPaths(product, diagnostic) {
		packaging := loadCandidatePackaging(t)
		if path.diagnostic {
			packaging = loadCandidateMetadata(t, candidatePackaging, candidateDiagnosticPackaging)
		}
		spec, err := ebpf.LoadCollectionSpec(path.path)
		if err != nil {
			t.Fatalf("%s: %v", path.path, err)
		}
		// G019 gap 4: a frozen non-product object without the interpreter
		// continuation is checked without exactly its two disables.
		checkCandidateAttachSetObject(t, path.path, candidateDisabled(packagingForObject(t, packaging, spec, path.path)))
	}
}

type candidateObjectPath struct {
	path       string
	diagnostic bool
}

// candidateObjectPaths splits the product and diagnostic object lists.
func candidateObjectPaths(product, diagnostic string) []candidateObjectPath {
	var out []candidateObjectPath
	for _, list := range []struct {
		env        string
		diagnostic bool
	}{{product, false}, {diagnostic, true}} {
		if list.env == "" {
			continue
		}
		for _, path := range strings.Split(list.env, ",") {
			out = append(out, candidateObjectPath{path, list.diagnostic})
		}
	}
	return out
}

func checkCandidateAttachSetObject(t *testing.T, path string, disabled map[string]bool) {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	for name := range disabled {
		if p := spec.Programs[name]; p == nil || nativeattach.TrampolineTarget(p) == "" {
			t.Errorf("%s: disabled %s is not a trampoline program of the object (stale packaging)", path, name)
		}
	}
	attached := map[string]string{}
	need := map[string]int{}
	for name, p := range spec.Programs {
		target := nativeattach.TrampolineTarget(p)
		if target == "" || disabled[name] {
			continue
		}
		attached[name] = target
		need[target]++
	}
	if fmt.Sprint(attached) != fmt.Sprint(candidateAttachSet) {
		t.Errorf("%s: attach set %v, pinned %v", path, attached, candidateAttachSet)
	}
	if fmt.Sprint(need) != fmt.Sprint(candidateAttachPerHook) {
		t.Errorf("%s: per-hook need %v, pinned %v", path, need, candidateAttachPerHook)
	}
	if err := nativeattach.CheckCapacity(need, nil, nativeattach.DefaultReservePerHook); err != nil {
		t.Errorf("%s: packaged need refused on empty trampolines: %v", path, err)
	}
	t.Logf("%s: packaged attach set per hook %v (%d programs disabled)", path, need, len(disabled))
}
