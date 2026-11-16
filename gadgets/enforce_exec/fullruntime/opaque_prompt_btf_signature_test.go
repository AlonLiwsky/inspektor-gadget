// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// The prompt BPF program reads ctx[0] as bprm and truncates the return to
// signed int32. Reject any target whose kernel BTF does not prove that ABI.
func opaquePromptFailurePrototype(function *btf.Func) error {
	if function == nil {
		return fmt.Errorf("missing bprm_execve BTF function")
	}
	prototype, ok := btf.UnderlyingType(function.Type).(*btf.FuncProto)
	if !ok {
		return fmt.Errorf("bprm_execve lacks a BTF function prototype")
	}
	result, ok := btf.UnderlyingType(prototype.Return).(*btf.Int)
	if !ok || result.Size != 4 || result.Encoding != btf.Signed || len(prototype.Params) != 1 {
		return fmt.Errorf("bprm_execve requires signed int32 return and exactly one argument")
	}
	pointer, ok := btf.UnderlyingType(prototype.Params[0].Type).(*btf.Pointer)
	if !ok {
		return fmt.Errorf("bprm_execve argument must be a pointer to struct linux_binprm")
	}
	structure, ok := btf.UnderlyingType(pointer.Target).(*btf.Struct)
	if !ok || structure.Name != "linux_binprm" {
		return fmt.Errorf("bprm_execve argument must point to struct linux_binprm")
	}
	return nil
}

func TestOpaquePromptFailurePrototype(t *testing.T) {
	integer := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
	bprm := &btf.Pointer{Target: &btf.Struct{Name: "linux_binprm"}}
	for _, tc := range []struct {
		name     string
		function *btf.Func
		valid    bool
	}{
		{"exact", &btf.Func{Type: &btf.FuncProto{Return: integer, Params: []btf.FuncParam{{Type: bprm}}}}, true},
		{"missing function", nil, false},
		{"missing prototype", &btf.Func{Type: integer}, false},
		{"unsigned return", &btf.Func{Type: &btf.FuncProto{Return: &btf.Int{Size: 4}, Params: []btf.FuncParam{{Type: bprm}}}}, false},
		{"wide return", &btf.Func{Type: &btf.FuncProto{Return: &btf.Int{Size: 8, Encoding: btf.Signed}, Params: []btf.FuncParam{{Type: bprm}}}}, false},
		{"void return", &btf.Func{Type: &btf.FuncProto{Return: &btf.Void{}, Params: []btf.FuncParam{{Type: bprm}}}}, false},
		{"missing argument", &btf.Func{Type: &btf.FuncProto{Return: integer}}, false},
		{"extra argument", &btf.Func{Type: &btf.FuncProto{Return: integer, Params: []btf.FuncParam{{Type: bprm}, {Type: integer}}}}, false},
		{"nonpointer argument", &btf.Func{Type: &btf.FuncProto{Return: integer, Params: []btf.FuncParam{{Type: &btf.Struct{Name: "linux_binprm"}}}}}, false},
		{"wrong pointee", &btf.Func{Type: &btf.FuncProto{Return: integer, Params: []btf.FuncParam{{Type: &btf.Pointer{Target: &btf.Struct{Name: "task_struct"}}}}}}, false},
		{"incomplete pointee", &btf.Func{Type: &btf.FuncProto{Return: integer, Params: []btf.FuncParam{{Type: &btf.Pointer{Target: &btf.Fwd{Name: "linux_binprm"}}}}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := opaquePromptFailurePrototype(tc.function); (err == nil) != tc.valid {
				t.Fatalf("signature valid=%v, want=%v: %v", err == nil, tc.valid, err)
			}
		})
	}
}
