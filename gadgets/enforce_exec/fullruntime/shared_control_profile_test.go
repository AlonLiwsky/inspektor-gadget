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
)

func TestSharedControlRejectsMalformedCompiledProfile(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile("testdata/shared_control.c")
	if err != nil {
		t.Fatal(err)
	}
	for name, values := range map[string][2]string{"negative-compensated": {"5", "-1"}, "oversized-compensated": {"4294967296ULL", "-1073741824LL"}} {
		t.Run(name, func(t *testing.T) {
			code := strings.Replace(string(source), "#define SE_PROFILE_SLOTS_256 2", "#define SE_PROFILE_SLOTS_256 "+values[0], 1)
			code = strings.Replace(code, "#define SE_PROFILE_SLOTS_1024 0", "#define SE_PROFILE_SLOTS_1024 "+values[1], 1)
			dir := t.TempDir()
			file := filepath.Join(dir, "profile.c")
			if err := os.WriteFile(file, []byte(code), 0o600); err != nil {
				t.Fatal(err)
			}
			// This test requires a hard language-level assertion, not a warning that
			// disappears when a downstream build does not enable -Werror.
			out, err := exec.Command(cc, "-std=gnu11", "-O2", "-iquote", root, "-c", file, "-o", filepath.Join(dir, "profile.o")).CombinedOutput()
			if err == nil {
				t.Fatal("malformed image geometry compiled")
			}
			if !strings.Contains(string(out), "slot count domain") {
				t.Fatalf("wrong refusal: %s", out)
			}
		})
	}
}

func TestSharedNodeProbeAllSizeClasses(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../full")
	if err != nil {
		t.Fatal(err)
	}
	fixtures, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for class := 0; class < 4; class++ {
		t.Run(fmt.Sprint(class), func(t *testing.T) {
			var defines strings.Builder
			for i, size := range []int{256, 1024, 4096, 16384} {
				count := 0
				if i == class {
					count = 2
				}
				fmt.Fprintf(&defines, "#define SE_PROFILE_SLOTS_%d %d\n", size, count)
			}
			code := defines.String() + `#define main original_fixture_main
#include "shared_control.c"
#undef main
int main(void) {
 command=(struct se_control_command){.node_cookie=11,.nonce=22,.sequence=1,.operation=SE_NODE_INSPECT};
 assert(!se_command(0));
 assert(!object_lookups);
 assert(!receipt.status && receipt.sequence==1 && receipt.value==1);
 assert(SE_NODE_INSPECT==16);
 struct se_control_receipt saved=receipt;
 assert(se_command(0)); /* replay refused */
 assert(!memcmp(&saved,&receipt,sizeof(saved)));
 command.sequence=2;admin=0;assert(se_command(0));
 assert(!memcmp(&saved,&receipt,sizeof(saved)));
 assert(!object_lookups);
 return 0;
}
`
			dir := t.TempDir()
			file := filepath.Join(dir, "probe.c")
			exe := filepath.Join(dir, "probe")
			if err := os.WriteFile(file, []byte(code), 0o600); err != nil {
				t.Fatal(err)
			}
			if out, err := exec.Command(cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror", "-iquote", root, "-iquote", fixtures, file, "-o", exe).CombinedOutput(); err != nil {
				t.Fatalf("compile: %v %s", err, out)
			}
			if out, err := exec.Command(exe).CombinedOutput(); err != nil {
				t.Fatalf("probe: %v %s", err, out)
			}
		})
	}
}
