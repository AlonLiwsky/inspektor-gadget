// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"errors"
	"os"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// Stage 1: the D1 oracle uses D3's test-only probed-kernel admission
// (kernel_probe_override_tag.go, IG_ENFORCE_EXEC_PROBED_KERNEL=1 in a
// qualification build); D1's separate override variable is gone.

// TestD1LoadOnly loads every map and program of IG_D1_OBJECT through the
// kernel verifier and closes them again. Nothing is attached.
func TestD1LoadOnly(t *testing.T) {
	object := os.Getenv("IG_D1_OBJECT")
	if object == "" {
		t.Skip("set IG_D1_OBJECT")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	failed := 0
	// Per program, so that one refusal does not hide the others.
	for name := range spec.Programs {
		one := spec.Copy()
		for other := range one.Programs {
			if other != name {
				delete(one.Programs, other)
			}
		}
		coll, err := ebpf.NewCollectionWithOptions(one, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogLevel: ebpf.LogLevelStats}})
		if err != nil {
			failed++
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				tail := ve.Log
				if len(tail) > 12 {
					tail = tail[len(tail)-12:]
				}
				t.Errorf("REFUSED %s (%s): %v\n%v", name, spec.Programs[name].SectionName, err, tail)
			} else {
				t.Errorf("REFUSED %s (%s): %v", name, spec.Programs[name].SectionName, err)
			}
			continue
		}
		log := coll.Programs[name].VerifierLog
		t.Logf("LOADED %s (%s) %s", name, spec.Programs[name].SectionName, lastLine(log))
		coll.Close()
	}
	t.Logf("load-only: %d programs, %d refused", len(spec.Programs), failed)
}

func lastLine(s string) string {
	for len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '\n' {
			return s[i+1:]
		}
	}
	return s
}
