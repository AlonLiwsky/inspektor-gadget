// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestPinnedInitIdentityAndClosedDescriptor(t *testing.T) {
	proc, err := os.Open(fmt.Sprintf("/proc/%d", os.Getpid()))
	if err != nil {
		t.Fatal(err)
	}
	copy, err := DuplicateProcPin(proc)
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	if err = proc.Close(); err != nil {
		t.Fatal(err)
	}
	if start, err := readPinnedInitStart(copy, uint32(os.Getpid())); err != nil || start == "" {
		t.Fatal(start, err)
	}
	if _, err = readPinnedInitStart(copy, uint32(os.Getpid()+1)); err == nil {
		t.Fatal("wrong PID accepted")
	}
	if _, err = DuplicateProcPin(proc); err == nil {
		t.Fatal("closed source duplicated")
	}
	ordinary, err := os.Open("/proc/stat")
	if err != nil {
		t.Fatal(err)
	}
	defer ordinary.Close()
	if pin, err := DuplicateProcPin(ordinary); err == nil {
		pin.Close()
		t.Fatal("non-directory proc file accepted")
	}
}

func TestPinnedStatParsing(t *testing.T) {
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0] = "S"
	fields[19] = "123"
	valid := "12 (odd name ) ( child) " + strings.Join(fields, " ")
	if start, err := parsePinnedStat([]byte(valid), 12); err != nil || start != "123" {
		t.Fatal(start, err)
	}
	for _, data := range []string{"", "cpu 12 3", "12 (x) S 2", strings.Replace(valid, "123", "0", 1), strings.Replace(valid, "123", "garbage", 1)} {
		if _, err := parsePinnedStat([]byte(data), 12); err == nil {
			t.Fatal("malformed stat accepted", data)
		}
	}
}
