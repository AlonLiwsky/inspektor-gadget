// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// tempAncestors returns dir and every ancestor strictly below tmp, deepest
// first. tmp itself is never included. It fails when dir is not strictly
// below tmp (including tmp == "/"), so a caller never silently skips the
// chmod and then fails later with an unexplained EACCES.
func tempAncestors(tmp, dir string) ([]string, error) {
	tmp, dir = filepath.Clean(tmp), filepath.Clean(dir)
	if tmp == string(filepath.Separator) {
		return nil, fmt.Errorf("temp dir is %q: refusing to chmod below the root", tmp)
	}
	var out []string
	for d := dir; strings.HasPrefix(d, tmp+string(filepath.Separator)); d = filepath.Dir(d) {
		out = append(out, d)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%q is not below temp dir %q", dir, tmp)
	}
	return out, nil
}

// chmodTempAncestors makes dir and every ancestor strictly below
// os.TempDir() mode 0755, so a uid-1000 child can reach files that
// testing.T.TempDir created under its 0700 per-test parent. os.TempDir()
// itself is never touched: an attached test runs as root, and chmod 0755 on
// /tmp strips its sticky bit and world-write for the whole host (G011 EC2
// run g011ec2-20261114t151016-0ea5 lost every later /tmp write that way).
func chmodTempAncestors(t interface {
	Helper()
	Fatal(...any)
}, dir string,
) {
	t.Helper()
	dirs, err := tempAncestors(os.TempDir(), dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dirs {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTempAncestors(t *testing.T) {
	for _, tc := range []struct {
		tmp, dir string
		want     []string
		wantErr  bool
	}{
		{tmp: "/tmp", dir: "/tmp/TestX1/001", want: []string{"/tmp/TestX1/001", "/tmp/TestX1"}},
		{tmp: "/tmp/", dir: "/tmp/TestX1/001/", want: []string{"/tmp/TestX1/001", "/tmp/TestX1"}},
		{tmp: "/tmp", dir: "/tmp", wantErr: true},
		{tmp: "/tmp", dir: "/tmpx/TestX1", wantErr: true},
		{tmp: "/tmp", dir: "/var/tmp/TestX1", wantErr: true},
		{tmp: "/", dir: "/TestX1/001", wantErr: true},
		{tmp: "tmp", dir: "/tmp/TestX1", wantErr: true},
	} {
		got, err := tempAncestors(tc.tmp, tc.dir)
		if (err != nil) != tc.wantErr || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("tempAncestors(%q, %q) = %q, %v; want %q, err=%v", tc.tmp, tc.dir, got, err, tc.want, tc.wantErr)
		}
	}
}

func TestChmodTempAncestorsLeavesTempDirAlone(t *testing.T) {
	for _, suffix := range []string{"", "/"} {
		base := t.TempDir()
		if err := os.Chmod(base, os.ModePerm|os.ModeSticky); err != nil {
			t.Fatal(err)
		}
		t.Setenv("TMPDIR", base+suffix)
		// A sibling sharing base's name as a prefix must not count as below it.
		sibling := base + "x"
		if err := os.Mkdir(sibling, 0o700); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(sibling) })
		dir := filepath.Join(base, "TestX123", "001")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(base, "TestX123"), 0o700); err != nil {
			t.Fatal(err)
		}

		chmodTempAncestors(t, dir)

		for path, want := range map[string]os.FileMode{
			dir:                             0o755,
			filepath.Join(base, "TestX123"): 0o755,
			base:                            os.ModePerm | os.ModeSticky,
			sibling:                         0o700,
		} {
			st, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if got := st.Mode() & (os.ModePerm | os.ModeSticky); got != want {
				t.Errorf("TMPDIR=%q: %s: mode %v, want %v", base+suffix, path, got, want)
			}
		}
	}
}
