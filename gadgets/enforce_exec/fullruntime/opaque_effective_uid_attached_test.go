// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
)

// The helper changes only its own test credentials. Procfs independently
// verifies them before and after exec; the BPF rule witness checks the fact.
func opaqueSetDivergentUIDs(t *testing.T, stdin io.Writer, stdout *bufio.Reader) int {
	t.Helper()
	if _, err := io.WriteString(stdin, "UIDS\n"); err != nil {
		t.Fatal(err)
	}
	line, err := stdout.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "UIDS:") {
		t.Fatalf("helper UID setup: line=%q err=%v", line, err)
	}
	pid, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(line, "UIDS:"), "\n"))
	if err != nil || pid <= 0 {
		t.Fatalf("invalid helper PID: line=%q err=%v", line, err)
	}
	opaqueAssertDivergentUIDs(t, pid)
	return pid
}

func opaqueAssertDivergentUIDs(t *testing.T, pid int) {
	t.Helper()
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	uids, err := opaqueProcUIDs(string(status))
	if err != nil || uids != [4]uint32{1000, 0, 0, 0} {
		t.Fatalf("actual helper credentials differ: real/effective/saved/fs=%v err=%v", uids, err)
	}
}

func opaqueProcUIDs(status string) ([4]uint32, error) {
	var result [4]uint32
	for _, line := range strings.Split(status, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "Uid:" {
			continue
		}
		if len(fields) != 5 {
			return result, fmt.Errorf("invalid proc Uid row %q", line)
		}
		for i := range result {
			value, err := strconv.ParseUint(fields[i+1], 10, 32)
			if err != nil {
				return result, err
			}
			result[i] = uint32(value)
		}
		return result, nil
	}
	return result, fmt.Errorf("proc status lacks Uid row")
}

func TestOpaqueProcUIDs(t *testing.T) {
	for _, tc := range []struct {
		name, status string
		want         [4]uint32
		valid        bool
	}{
		{"divergent", "Name:\thelper\nUid:\t1000\t0\t0\t0\n", [4]uint32{1000, 0, 0, 0}, true},
		{"equal", "Uid: 1000 1000 1000 1000\n", [4]uint32{1000, 1000, 1000, 1000}, true},
		{"missing", "Gid: 0 0 0 0\n", [4]uint32{}, false},
		{"short", "Uid: 1000 0\n", [4]uint32{}, false},
		{"negative", "Uid: -1 0 0 0\n", [4]uint32{}, false},
		{"overflow", "Uid: 4294967296 0 0 0\n", [4]uint32{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := opaqueProcUIDs(tc.status)
			if (err == nil) != tc.valid || tc.valid && got != tc.want {
				t.Fatalf("got=%v err=%v want=%v valid=%v", got, err, tc.want, tc.valid)
			}
		})
	}
}
