// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const testExpected = `# kernel	step	test	profile
kernel	identity	uname_r	-
kernel	ready	TestSharedProductNodeReadyAttached	64
kernel	ready	TestSharedProductNodeReadyAttached	128
`

// ev builds test2json lines: "run T", "pass T", "skip T", "output T text",
// "pass" (package), "fail" (package).
func ev(lines ...string) string {
	var b strings.Builder
	for _, l := range lines {
		action, rest, _ := strings.Cut(l, " ")
		test, out, _ := strings.Cut(rest, " ")
		b.WriteString(`{"Action":"` + action + `"`)
		if test != "" {
			b.WriteString(`,"Test":"` + test + `"`)
		}
		if out != "" {
			b.WriteString(`,"Output":"` + out + `\n"`)
		}
		b.WriteString("}\n")
	}
	return b.String()
}

const readyTest = "TestSharedProductNodeReadyAttached"

// green is a complete, passing results tree for testExpected.
func green() map[string]string {
	return map[string]string{
		"kernel/infra.tsv":          "launch\t0\tok\nguest\t0\tok\n",
		"kernel/identity__-.json":   ev("run uname_r", "output uname_r 6.8.0", "pass uname_r", "pass"),
		"kernel/ready__64.json":     ev("run "+readyTest, "pass "+readyTest, "pass"),
		"kernel/ready__128.json":    ev("run "+readyTest, "output "+readyTest+" product-ready", "pass "+readyTest, "pass"),
		"kernel/verifier-stats.txt": "not a stream, ignored",
	}
}

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func runCheck(t *testing.T, files map[string]string, profiles string) (string, error) {
	t.Helper()
	dir := writeTree(t, files)
	exp := filepath.Join(t.TempDir(), "expected.tsv")
	if err := os.WriteFile(exp, []byte(testExpected), 0o644); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	err := run([]string{"check", "-expected", exp, "-results", dir, "-kernels", "kernel", "-profiles", profiles, "-out", filepath.Join(t.TempDir(), "r.tsv")}, &out)
	return out.String(), err
}

func TestCheckGreen(t *testing.T) {
	out, err := runCheck(t, green(), "64,128")
	if err != nil || !strings.Contains(out, "GREEN (kernels kernel, profiles 64,128): exactly 3 unique PASS rows") {
		t.Fatalf("green run: %v\n%s", err, out)
	}
}

// TestCheckRed: every way a run can be incomplete or wrong turns it red.
func TestCheckRed(t *testing.T) {
	for name, tc := range map[string]struct {
		edit func(map[string]string)
		want string
	}{
		"skip": {func(f map[string]string) {
			f["kernel/ready__64.json"] = ev("run "+readyTest, "output "+readyTest+" set IG_SHARED_PRODUCT_LAYOUT", "skip "+readyTest, "pass")
		}, "skipped (a skip is a failure): set IG_SHARED_PRODUCT_LAYOUT"},
		"missing row": {func(f map[string]string) {
			f["kernel/identity__-.json"] = ev("pass")
		}, "kernel identity uname_r -: missing row"},
		"missing stream": {func(f map[string]string) {
			delete(f, "kernel/ready__128.json")
		}, "missing stream"},
		"duplicate pass": {func(f map[string]string) {
			f["kernel/ready__64.json"] = ev("run "+readyTest, "pass "+readyTest, "run "+readyTest, "pass "+readyTest, "pass")
		}, "2 passes, want exactly 1"},
		"unexpected test": {func(f map[string]string) {
			f["kernel/ready__64.json"] = ev("run "+readyTest, "pass "+readyTest, "run TestOther", "pass TestOther", "pass")
		}, "TestOther 64: unexpected test"},
		"unexpected stream": {func(f map[string]string) {
			f["kernel/ready__512.json"] = ev("run "+readyTest, "pass "+readyTest, "pass")
		}, "is not in the expected list"},
		"empty stream": {func(f map[string]string) {
			f["kernel/ready__64.json"] = ""
		}, "empty stream"},
		"truncated stream": {func(f map[string]string) {
			f["kernel/ready__64.json"] = ev("run "+readyTest, "pass "+readyTest)
		}, "truncated stream: no package result"},
		"test never ended": {func(f map[string]string) {
			f["kernel/ready__64.json"] = ev("run "+readyTest, "run TestOther", "pass TestOther", "pass")
		}, "started and never ended"},
		"failed test": {func(f map[string]string) {
			f["kernel/ready__64.json"] = ev("run "+readyTest, "output "+readyTest+" verdicts: A r1000=0", "fail "+readyTest, "fail")
		}, "failed: verdicts: A r1000=0"},
		"package fail after a pass": {func(f map[string]string) {
			f["kernel/ready__64.json"] = ev("run "+readyTest, "pass "+readyTest, "fail")
		}, `passed in a broken stream: package result "fail"`},
		"not json": {func(f map[string]string) {
			f["kernel/ready__64.json"] = "panic: boom\n" + ev("run "+readyTest, "pass "+readyTest, "pass")
		}, "is not a test2json event"},
		"two runs in one stream": {func(f map[string]string) {
			f["kernel/ready__64.json"] = ev("run "+readyTest, "pass "+readyTest, "pass", "run "+readyTest, "pass "+readyTest, "pass")
		}, "event after the package result"},
		"infra failure": {func(f map[string]string) {
			f["kernel/infra.tsv"] = "launch\t0\tok\nfetch\t255\tssh: connection refused\n"
		}, "infra fetch exited 255: ssh: connection refused"},
		"infra missing": {func(f map[string]string) {
			delete(f, "kernel/infra.tsv")
		}, "infra record"},
		"infra empty": {func(f map[string]string) {
			f["kernel/infra.tsv"] = "# nothing ran\n"
		}, "infra record is empty"},
		"everything missing": {func(f map[string]string) {
			for k := range f {
				delete(f, k)
			}
		}, "missing stream"},
	} {
		t.Run(name, func(t *testing.T) {
			files := green()
			tc.edit(files)
			out, err := runCheck(t, files, "64,128")
			if err == nil || !strings.HasPrefix(err.Error(), "RED (kernels kernel, profiles 64,128):") {
				t.Fatalf("want RED, got %v\n%s", err, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("output lacks %q:\n%s", tc.want, out)
			}
		})
	}
}

// TestCheckProfiles: the profile set selects rows; a profile or kernel
// with no rows is a configuration error, never an empty green.
func TestCheckProfiles(t *testing.T) {
	files := green()
	delete(files, "kernel/ready__64.json")
	if out, err := runCheck(t, files, "128"); err != nil || !strings.Contains(out, "exactly 2 unique PASS") {
		t.Fatalf("profile 128 only: %v\n%s", err, out)
	}
	if _, err := runCheck(t, green(), "256"); err == nil || !strings.Contains(err.Error(), `profile "256" has no expected rows in the judged kernels`) {
		t.Fatalf("unknown profile: %v", err)
	}
	if _, err := runCheck(t, green(), ""); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("no profiles: %v", err)
	}
	rows, _ := parseExpected(strings.NewReader(testExpected + "build\tobjects\tpin/x\t-\n"))
	if _, err := selectRows(rows, []string{"nosuch"}, []string{"128"}); err == nil {
		t.Fatal("a kernel without rows was accepted")
	}
	// A profile with rows only in a kernel that is not judged is refused.
	if _, err := selectRows(rows, []string{"build"}, []string{"128"}); err == nil {
		t.Fatal("profile 128 accepted for the build group alone")
	}
	// "-" judges only the profile-agnostic rows.
	if sel, err := selectRows(rows, []string{"build", "kernel"}, []string{"-"}); err != nil || len(sel) != 2 {
		t.Fatalf("profile-agnostic selection: %v %v", sel, err)
	}
}

// TestCheckPinnedRows: -rows pins the selection size, so a narrowed
// expected list or selection is red before any stream is read.
func TestCheckPinnedRows(t *testing.T) {
	dir := writeTree(t, green())
	exp := filepath.Join(t.TempDir(), "expected.tsv")
	if err := os.WriteFile(exp, []byte(testExpected), 0o644); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	args := []string{"check", "-expected", exp, "-results", dir, "-kernels", "kernel", "-profiles", "64,128"}
	if err := run(append(args, "-rows", "3"), &out); err != nil {
		t.Fatalf("pinned 3: %v\n%s", err, out.String())
	}
	if err := run(append(args, "-rows", "141"), &out); err == nil || !strings.Contains(err.Error(), "holds 3 expected rows, the run pins 141") {
		t.Fatalf("pinned 141: %v", err)
	}
}

func TestParseExpected(t *testing.T) {
	for name, in := range map[string]string{
		"empty":       "# only a comment\n",
		"duplicate":   "kernel\tready\tT\t64\nkernel\tready\tT\t64\n",
		"three cols":  "kernel\tready\tT\n",
		"slash step":  "kernel\tre/ady\tT\t64\n",
		"blank field": "kernel\t\tT\t64\n",
	} {
		if _, err := parseExpected(strings.NewReader(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	rows, err := parseExpected(strings.NewReader("kernel\tready\tTestA/sub\t64\n"))
	if err != nil || len(rows) != 1 || rows[0].Test != "TestA/sub" {
		t.Fatalf("subtest row: %v %v", rows, err)
	}
}

// TestRowEnd: the harness writer produces streams check accepts, and a
// failed row or a missing end makes them red.
func TestRowEnd(t *testing.T) {
	dir := t.TempDir()
	s := filepath.Join(dir, "s.json")
	for _, args := range [][]string{
		{"row", "-stream", s, "-test", "uname_r", "-status", "pass", "-detail", `uname -r = "kernel"`},
		{"row", "-stream", s, "-test", "btf", "-status", "fail", "-detail", "sha mismatch"},
		{"end", "-stream", s},
	} {
		if err := run(args, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	f, _ := os.Open(s)
	tests, err := readStream(f)
	f.Close()
	if err == nil || !strings.Contains(err.Error(), `package result "fail"`) || tests["uname_r"].pass != 1 || tests["btf"].fail != 1 {
		t.Fatalf("failed row: %v %+v", err, tests)
	}
	if err := run([]string{"end", "-stream", s}, io.Discard); err == nil {
		t.Fatal("a second end was accepted")
	}

	ok := filepath.Join(dir, "ok.json")
	_ = run([]string{"row", "-stream", ok, "-test", "a", "-status", "pass"}, io.Discard)
	f, _ = os.Open(ok)
	if _, err := readStream(f); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("stream without end: %v", err)
	}
	f.Close()
	_ = run([]string{"end", "-stream", ok}, io.Discard)
	f, _ = os.Open(ok)
	if _, err := readStream(f); err != nil {
		t.Fatalf("closed stream: %v", err)
	}
	f.Close()
	if err := run([]string{"row", "-stream", ok, "-test", "a", "-status", "skip"}, io.Discard); err == nil {
		t.Fatal("a skip row was accepted")
	}
}
