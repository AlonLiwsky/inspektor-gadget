// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullruntime

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
)

func TestOwnerDispatchCandidateOwnership(t *testing.T) {
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
		text := string(data)
		a, b := strings.Index(text, begin), strings.Index(text, end)
		if a < 0 || b <= a {
			t.Fatalf("actual dispatch boundary missing in %s", path)
		}
		return text[a+len(begin) : b]
	}
	types := extract("../full/owner_types.h", "/* EO_DISPATCH_TYPES_BEGIN */", "/* EO_DISPATCH_TYPES_END */")
	functions := extract("../full/owner_control.h", "/* EO_DISPATCH_TRANSITIONS_BEGIN */", "/* EO_DISPATCH_TRANSITIONS_END */")
	// Interpose only the actual cell copy to schedule SEAL during the real
	// production writer critical section, not a parallel transition model.
	functions = strings.ReplaceAll(functions, "__builtin_memcpy(", "dispatch_checked_copy(")
	driver, err := os.ReadFile("testdata/owner_dispatch.c")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.ReplaceAll(strings.ReplaceAll(string(driver), "/* ACTUAL_TYPES */", types), "/* ACTUAL_TRANSITIONS */", functions)
	dir := t.TempDir()
	file, binary := filepath.Join(dir, "dispatch.c"), filepath.Join(dir, "dispatch")
	if err := os.WriteFile(file, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", file, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("dispatch: %v\n%s", err, out)
	}
}

func TestOwnerDispatchWireLayout(t *testing.T) {
	for _, row := range []struct {
		name      string
		got, want uintptr
	}{
		{"descriptor", unsafe.Sizeof(DispatchDescriptor{}), 32},
		{"candidate", unsafe.Sizeof(CandidateRecord{}), 256},
		{"dispatch", unsafe.Sizeof(DispatchRecord{}), 400},
		{"input", unsafe.Sizeof(CandidateInput{}), 320},
		{"seal workspace", unsafe.Sizeof(SealWorkspace{}), 2080},
		{"active offset", unsafe.Offsetof(DispatchRecord{}.Active), 40},
		{"candidate offset", unsafe.Offsetof(DispatchRecord{}.Candidate), 144},
	} {
		if row.got != row.want {
			t.Errorf("%s: got %d want %d", row.name, row.got, row.want)
		}
	}
	if err := (ControlResources{}).validate(OwnerDevelopmentABI); err == nil || !strings.Contains(err.Error(), "dispatch map ABI") {
		t.Fatalf("missing persistent dispatch accepted: %v", err)
	}
}

func TestCandidateCommandRejectsLegacyBeforeThread(t *testing.T) {
	control := &OwnerControl{config: ControlConfig{ABI: OwnerABI, Cookie: 7}}
	if _, err := control.CandidateCall(t.Context(), OwnerCandidateBegin, CandidateInput{}); err == nil {
		t.Fatal("legacy owner accepted candidate command")
	}
	control.config.ABI = OwnerDevelopmentABI
	if _, err := control.CandidateCall(t.Context(), OwnerCandidateBegin, CandidateInput{Request: CandidateRequest{SessionCookie: 8, Attempt: 2}}); err == nil {
		t.Fatal("foreign scope candidate accepted")
	}
}

func TestOwnerExecAdmissionFaultMatrix(t *testing.T) {
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
		text := string(data)
		a, b := strings.Index(text, begin), strings.Index(text, end)
		if a < 0 || b <= a {
			t.Fatalf("actual boundary missing: %s", begin)
		}
		return text[a+len(begin) : b]
	}
	source, err := os.ReadFile("testdata/owner_dispatch_admission.c")
	if err != nil {
		t.Fatal(err)
	}
	content := string(source)
	for marker, value := range map[string]string{
		"/* ACTUAL_TYPES */":             extract("../full/owner_types.h", "/* EO_DISPATCH_TYPES_BEGIN */", "/* EO_DISPATCH_TYPES_END */"),
		"/* ACTUAL_TRANSITIONS */":       extract("../full/owner_control.h", "/* EO_DISPATCH_TRANSITIONS_BEGIN */", "/* EO_DISPATCH_TRANSITIONS_END */"),
		"/* ACTUAL_EXEC_TYPE */":         "struct eo_exec_tx {" + extract("../full/owner_types.h", "struct eo_exec_tx {", "struct eo_fork_tx {"),
		"/* ACTUAL_OBSERVATION_FAULT */": extract("../full/owner_roles.h", "/* EO_EXEC_OBSERVATION_FAULT_BEGIN */", "/* EO_EXEC_OBSERVATION_FAULT_END */"),
		"/* ACTUAL_EXEC_ADMISSION */":    extract("../full/owner_roles.h", "/* EO_EXEC_ADMISSION_BEGIN */", "/* EO_EXEC_ADMISSION_END */"),
	} {
		content = strings.Replace(content, marker, value, 1)
	}
	dir := t.TempDir()
	file, binary := filepath.Join(dir, "admission.c"), filepath.Join(dir, "admission")
	if err := os.WriteFile(file, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-DENFORCE_EXEC_ABI3_DEVELOPMENT=1", "-DER_ACTIVE=8", file, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("admission: %v\n%s", err, out)
	}
}

func TestOwnerRetainedBankLookup(t *testing.T) {
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
		text := string(data)
		a, b := strings.Index(text, begin), strings.Index(text, end)
		if a < 0 || b <= a {
			t.Fatalf("missing actual boundary %s", begin)
		}
		return text[a+len(begin) : b]
	}
	driver, err := os.ReadFile("testdata/owner_dispatch_blob.c")
	if err != nil {
		t.Fatal(err)
	}
	source := string(driver)
	for marker, body := range map[string]string{
		"/* ACTUAL_TYPES */":         extract("../full/owner_types.h", "/* EO_DISPATCH_TYPES_BEGIN */", "/* EO_DISPATCH_TYPES_END */"),
		"/* ACTUAL_PHYSICAL_BLOB */": extract("../full/owner_types.h", "/* EO_PHYSICAL_BLOB_BEGIN */", "/* EO_PHYSICAL_BLOB_END */"),
		"/* ACTUAL_CURRENT_BLOB */":  extract("../full/owner_types.h", "/* EO_CURRENT_BLOB_BEGIN */", "/* EO_CURRENT_BLOB_END */"),
		"/* ACTUAL_GLOBAL_BLOB */":   extract("../full/program.bpf.c", "/* EO_GLOBAL_BLOB_BEGIN */", "/* EO_GLOBAL_BLOB_END */"),
	} {
		source = strings.Replace(source, marker, body, 1)
	}
	dir := t.TempDir()
	file, binary := filepath.Join(dir, "blob.c"), filepath.Join(dir, "blob")
	if err := os.WriteFile(file, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-DENFORCE_EXEC_ABI3_DEVELOPMENT=1", file, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("lookup: %v\n%s", err, out)
	}
}

func TestOwnerCandidateSealActualProgram(t *testing.T) { runOwnerSealFixture(t, "") }

func runOwnerSealFixture(t *testing.T, compiledCases string) {
	t.Helper()
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
		text := string(data)
		a, b := strings.Index(text, begin), strings.Index(text, end)
		if a < 0 || b <= a {
			t.Fatalf("missing actual boundary %s", begin)
		}
		return text[a+len(begin) : b]
	}
	driver, err := os.ReadFile("testdata/owner_dispatch_seal.c")
	if err != nil {
		t.Fatal(err)
	}
	source := strings.Replace(string(driver), "/* COMPILED_DEPENDENCY_CASES */", compiledCases, 1)
	source = strings.Replace(source, "/* NATIVE_OPERATION_ASSERTS */", fmt.Sprintf("_Static_assert(EO_CANDIDATE_BEGIN==%d && EO_CANDIDATE_ABORT==%d && EO_CANDIDATE_WRITE==%d && EO_CANDIDATE_SEAL==%d, \"native operation ABI\");", OwnerCandidateBegin, OwnerCandidateAbort, OwnerCandidateWrite, OwnerCandidateSeal), 1)
	for marker, body := range map[string]string{
		"/* ACTUAL_TYPES */":         extract("../full/owner_types.h", "/* EO_DISPATCH_TYPES_BEGIN */", "/* EO_DISPATCH_TYPES_END */"),
		"/* ACTUAL_TRANSITIONS */":   extract("../full/owner_control.h", "/* EO_DISPATCH_TRANSITIONS_BEGIN */", "/* EO_DISPATCH_TRANSITIONS_END */"),
		"/* ACTUAL_PHYSICAL_BLOB */": extract("../full/owner_types.h", "/* EO_PHYSICAL_BLOB_BEGIN */", "/* EO_PHYSICAL_BLOB_END */"),
		"/* ACTUAL_CURRENT_BLOB */":  extract("../full/owner_types.h", "/* EO_CURRENT_BLOB_BEGIN */", "/* EO_CURRENT_BLOB_END */"),
		"/* ACTUAL_GLOBAL_BLOB */":   extract("../full/program.bpf.c", "/* EO_GLOBAL_BLOB_BEGIN */", "/* EO_GLOBAL_BLOB_END */"),
		"/* ACTUAL_FRESH_SESSION */": extract("../full/owner_control.h", "/* EO_FRESH_SESSION_BEGIN */", "/* EO_FRESH_SESSION_END */"),
		"/* ACTUAL_OPERATIONS */":    "enum eo_operation {" + extract("../full/owner_types.h", "enum eo_operation {", "enum eo_result {"),
		"/* ACTUAL_CANDIDATE_IO */":  extract("../full/owner_control.h", "/* EO_CANDIDATE_COMMAND_BEGIN */", "/* EO_CANDIDATE_COMMAND_END */"),
		"/* ACTUAL_SEAL */":          extract("../full/owner_control.h", "/* EO_CANDIDATE_SEAL_BEGIN */", "/* EO_CANDIDATE_SEAL_END */"),
		"/* ACTUAL_PUT_WORK */":      "static __always_inline void eo_put_work(" + extract("../full/owner_types.h", "static __always_inline void eo_put_work(", "static __always_inline __u64 eo_group("),
	} {
		source = strings.Replace(source, marker, body, 1)
	}
	dir := t.TempDir()
	file, binary := filepath.Join(dir, "seal.c"), filepath.Join(dir, "seal")
	if err := os.WriteFile(file, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../fullpolicy/bpf")
	if err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-DENFORCE_EXEC_ABI3_DEVELOPMENT=1", "-iquote", root, file, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("seal: %v\n%s", err, out)
	}
}

func TestOwnerSealedDependencyClosure(t *testing.T) {
	rule := func(name string, mode fullpolicy.Mode, role bool, action fullpolicy.Action, write bool) fullpolicy.Rule {
		r := fullpolicy.Rule{Name: name, Mode: mode, Action: action}
		if role {
			r.Actor.Role = []string{"root"}
		}
		if write {
			r.Target.SetRole = "next"
		}
		return r
	}
	policy := func(id string, mode fullpolicy.Mode, fallback fullpolicy.Action, rules ...fullpolicy.Rule) fullpolicy.Policy {
		return fullpolicy.Policy{ID: id, Revision: "r", Mode: mode, RootRole: "root", Default: fallback, Rules: rules}
	}
	allow := fullpolicy.Allow
	deny := fullpolicy.Deny
	audit := fullpolicy.Audit
	enforce := fullpolicy.Enforce
	tests := []struct {
		name     string
		policies []fullpolicy.Policy
		required []string
	}{
		{"unrelated audit role", []fullpolicy.Policy{policy("a", enforce, "", rule("allow", enforce, false, allow, false)), policy("b", audit, "", rule("audit", audit, true, allow, false))}, nil},
		{"enforced role", []fullpolicy.Policy{policy("a", enforce, "", rule("role", enforce, true, allow, false))}, []string{"a"}},
		{"enforced deny default exception", []fullpolicy.Policy{policy("a", enforce, deny), policy("b", audit, "", rule("exception", audit, true, allow, false))}, []string{"b"}},
		{"enforced allow default independent", []fullpolicy.Policy{policy("a", enforce, allow), policy("b", audit, "", rule("exception", audit, true, allow, false))}, nil},
		{"enforced writer global audit deny", []fullpolicy.Policy{policy("a", enforce, "", rule("write", enforce, false, allow, true)), policy("b", audit, "", rule("deny", audit, true, deny, false))}, []string{"b"}},
		{"earlier writer audit fallback exception", []fullpolicy.Policy{policy("a", enforce, "", rule("write", enforce, false, allow, true)), policy("b", audit, "", rule("exception", audit, true, allow, false)), policy("c", audit, deny)}, []string{"b"}},
		{"same UID audit writer", []fullpolicy.Policy{policy("a", enforce, "", rule("enforced", enforce, false, allow, true), rule("audit", audit, true, allow, true))}, []string{"a"}},
		{"transitive authority", []fullpolicy.Policy{policy("a", enforce, "", rule("authority", enforce, true, allow, false), rule("write", audit, false, allow, true)), policy("b", audit, "", rule("deny", audit, true, deny, false)), policy("c", audit, deny), policy("d", audit, "", rule("exception", audit, true, allow, false))}, []string{"a", "b", "d"}},
		{"audit only no strict requirement", []fullpolicy.Policy{policy("a", audit, "", rule("write", audit, false, allow, true)), policy("b", audit, "", rule("deny", audit, true, deny, false)), policy("c", audit, deny)}, nil},
		{"audit override", []fullpolicy.Policy{policy("a", enforce, "", rule("audit", audit, true, allow, false))}, nil},
		{"enforced override", []fullpolicy.Policy{policy("a", audit, "", rule("enforced", enforce, true, allow, false))}, []string{"a"}},
	}
	var generated strings.Builder
	for _, tc := range tests {
		for reverse := 0; reverse < 2; reverse++ {
			policies := append([]fullpolicy.Policy(nil), tc.policies...)
			if reverse != 0 {
				for i, j := 0, len(policies)-1; i < j; i, j = i+1, j-1 {
					policies[i], policies[j] = policies[j], policies[i]
				}
			}
			program, err := fullpolicy.CompileKernel(policies, 2, "app")
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			header, err := fullpolicy.Decode[fullpolicy.KernelHeader](program.Entries[0])
			if err != nil {
				t.Fatal(err)
			}
			var required uint32
			for i := uint32(0); i < header.PolicyCount; i++ {
				kp, err := fullpolicy.Decode[fullpolicy.KernelPolicy](program.Entries[fullpolicy.KernelPolicyBase+i])
				if err != nil {
					t.Fatal(err)
				}
				for _, id := range tc.required {
					if program.Identities[kp.UID] == id {
						required |= 1 << i
					}
				}
			}
			fmt.Fprintf(&generated, "/* %s reverse=%d */\n{ static const unsigned char image[][288]={\n", tc.name, reverse)
			for _, blob := range program.Entries {
				generated.WriteString("{")
				for _, b := range blob {
					fmt.Fprintf(&generated, "%d,", b)
				}
				generated.WriteString("},\n")
			}
			generated.WriteString("};\nmemset(cells,0,sizeof(cells));memset(&work,0,sizeof(work));\n")
			generated.WriteString("dispatch=(struct eo_dispatch){.scope_state=EO_SCOPE_ACTIVE,.session_cookie=7,.cgroup=42,.serial=1,.active={.generation=1,.execution_class=1,.policy_count=1}};\n")
			fmt.Fprintf(&generated, "assert(!eo_candidate_begin_locked(&dispatch,7,2,%d));\n", len(program.Entries))
			fmt.Fprintf(&generated, "for(__u32 key=0;key<%d;key++){struct eo_candidate_input input={.request={.session_cookie=7,.attempt=2,.entries=%d,.index=key,.bank=1}};memcpy(input.data,image[key],288);assert(!eo_candidate_write_cell(&dispatch,&input.request,input.data,&cells[1][key]));}\n", len(program.Entries), len(program.Entries))
			fmt.Fprintf(&generated, "assert(eo_seal_candidate(&dispatch,7,2)==EO_OK);assert(dispatch.candidate.required_known_mask==%d);assert(!work.busy&&!work.reader.owned&&!dispatch.authority_readers&&!dispatch.bank_readers[1]);}\n", required)
		}
	}
	runOwnerSealFixture(t, generated.String())
}

func TestCandidateNativeCommandIdentity(t *testing.T) {
	control := &OwnerControl{config: ControlConfig{ABI: OwnerDevelopmentABI, Cookie: 7}}
	input := CandidateInput{Request: CandidateRequest{SessionCookie: 7, Attempt: 23, Bank: 1, Index: 17}}
	for _, operation := range []uint32{OwnerCandidateBegin, OwnerCandidateAbort, OwnerCandidateWrite, OwnerCandidateSeal} {
		command, err := control.candidateCommand(operation, input)
		if err != nil || command != (ControlCommand{Nonce: 7, Generation: 23, Operation: operation}) {
			t.Fatalf("operation %d: command=%+v err=%v", operation, command, err)
		}
	}
	if _, err := control.candidateCommand(OwnerPublicationBegin, input); err == nil {
		t.Fatal("legacy operation accepted")
	}
	input.Request.SessionCookie = 8
	if _, err := control.candidateCommand(OwnerCandidateSeal, input); err == nil {
		t.Fatal("foreign input accepted")
	}
}
