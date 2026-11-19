// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// Compile every role entry point against an explicitly supplied archived kernel
// BTF header. This neither loads BPF nor substitutes for lifecycle/kernel proof.
func TestOwnerRolesCompile(t *testing.T) {
	vmlinux := os.Getenv("IG_EXEC_OWNER_VMLINUX")
	if vmlinux == "" {
		t.Skip("set IG_EXEC_OWNER_VMLINUX to an archived vmlinux.h for compile-only coverage")
	}
	if _, err := os.Stat(vmlinux); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	source := filepath.Join(dir, "owner_roles.c")
	content := `
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
struct fm_blob;
static inline const struct fm_blob *fixture_lookup(void *,unsigned int);
#define FM_BLOB_LOOKUP(ctx,key) fixture_lookup(ctx,key)
#include "evaluator.h"
#include "owner_types.h"
#include "owner_roles.h"
static inline const struct fm_blob *fixture_lookup(void *unused,unsigned int key){(void)unused;return eo_blob(0,key);}
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct fe_facts);} fixture_facts SEC(".maps");
struct {__uint(type,BPF_MAP_TYPE_ARRAY);__uint(max_entries,1);__type(key,__u32);__type(value,struct fe_decision);} fixture_decision SEC(".maps");
SEC("lsm.s/bprm_check_security") int BPF_PROG(fixture_check,struct linux_binprm*bprm,int ret){
 __u64 generation;int result=eo_exec_begin(bprm,&generation);if(result<=0)return result? -1:ret;
 __u32 zero=0;struct fe_facts*f=bpf_map_lookup_elem(&fixture_facts,&zero);struct fe_decision*d=bpf_map_lookup_elem(&fixture_decision,&zero);
 if(ret||!f||!d||eo_fill_roles(f)||eo_exec_propose(bprm,d)){eo_exec_suppress();return -1;}return 0;
}
SEC("syscall") int fixture_stage(void*unused){
 struct task_struct*task=bpf_get_current_task_btf();struct eo_task*s=eo_get_task(task);struct eo_work*w=eo_get_work();
 if(!s||!w)return -1;
 int result=eo_load_candidate(w,1,255);if(!result)result=eo_stage_task(task,s,w,255);if(!result)result=eo_validate_task(s,w);
 eo_put_work(w);return result;
}
char LICENSE[] SEC("license")="GPL";
`
	if err = os.WriteFile(source, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-target", "bpf", "-O2", "-g", "-Wall", "-Wextra", "-Werror", "-Wno-missing-declarations", "-Wno-unused-parameter", "-Wno-unused-function", "-I", filepath.Dir(vmlinux), "-I", filepath.Join(root, "fullpolicy/bpf"), "-I", filepath.Join(root, "full"), "-c", source, "-o", filepath.Join(dir, "owner_roles.o")}
	if out, err := exec.Command("clang", args...).CombinedOutput(); err != nil {
		t.Fatalf("owner role compile: %v\n%s", err, out)
	}
}
