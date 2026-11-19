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

func TestOwnerRowsNative(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler required")
	}
	header, err := os.ReadFile("../full/owner_roles.h")
	if err != nil {
		t.Fatal(err)
	}
	text := string(header)
	name := strings.Index(text, "eo_rows_complete(")
	start := -1
	if name >= 0 {
		start = strings.LastIndex(text[:name], "__noinline")
	}
	endName := strings.Index(text, "eo_validate_task_impl(")
	end := -1
	if endName >= 0 {
		end = strings.LastIndex(text[:endName], "static __noinline")
	}
	if start < 0 || end <= start {
		t.Fatal("actual completeness predicate missing")
	}
	source := `
#include <stdint.h>
#include <assert.h>
#define __noinline __attribute__((noinline))
#define __u32 uint32_t
#define __u64 uint64_t
#define ER_ACCEPTED_EPOCH(uid) 2
#include "epoch_roles.h"
struct eo_work{struct{uint32_t count,reserved;struct er_authority active[8];}candidate;struct{struct er_row rows[16];}merge;};
` + text[start:end] + `
int main(void){
 struct eo_work w={0};assert(eo_rows_complete(&w)==0);assert(eo_rows_complete(0)==-1);
 w.candidate.count=9;assert(eo_rows_complete(&w)==-1);w.candidate.count=8;
 for(int i=0;i<8;i++){w.candidate.active[i].uid=i+1;w.candidate.active[i].epoch=2;w.merge.rows[i]=er_known_row(i+1,2,3);}
 assert(eo_rows_complete(&w)==0);
 for(int i=0;i<8;i++){
  struct er_row saved=w.merge.rows[i];w.merge.rows[i].role=0;assert(eo_rows_complete(&w)==-1);w.merge.rows[i]=saved;
  w.merge.rows[15]=saved;assert(eo_rows_complete(&w)==-1);w.merge.rows[15]=(struct er_row){0};
  w.merge.rows[i].epoch++;assert(eo_rows_complete(&w)==-1);w.merge.rows[i]=saved;
 }
#ifdef ENFORCE_EXEC_ABI3_DEVELOPMENT
 w.merge.rows[0].knowledge=ER_ROLE_UNKNOWN;
 assert(eo_rows_complete(&w)==-1);
 w.merge.rows[0].knowledge=ER_ROLE_KNOWN;
#endif
 assert(eo_rows_complete(&w)==0);return 0;
}
`
	dir := t.TempDir()
	file := filepath.Join(dir, "rows.c")
	binary := filepath.Join(dir, "rows")
	if err = os.WriteFile(file, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	for _, development := range []bool{false, true} {
		args := []string{"-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root}
		if development {
			args = append(args, "-DENFORCE_EXEC_ABI3_DEVELOPMENT=1")
		}
		args = append(args, file, "-o", binary)
		if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
			t.Fatalf("compile development=%v: %v\n%s", development, err, out)
		}
		if out, err := exec.Command(binary).CombinedOutput(); err != nil {
			t.Fatalf("rows development=%v: %v\n%s", development, err, out)
		}
	}
}
