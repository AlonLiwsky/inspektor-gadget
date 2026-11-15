// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func phaseSample(args []string, p uint64) sample {
	s := sample{PIDTGID: 7<<32 | 7, Bprm: 0x1000, Task: 0x2000, PendingP: p, Argv: argvResult{ABI: 1, Status: 1, Complete: 1, Argc: uint32(len(args))}}
	for i, a := range args {
		s.Argv.Offsets[i] = s.Argv.Bytes
		copy(s.Argv.Data[s.Argv.Bytes:], a)
		s.Argv.Bytes += uint32(len(a) + 1)
	}
	return s
}

func TestExactInterpreterPhases(t *testing.T) {
	phases := [][]string{{"/script", "nonce"}, {"/elf", "--phase", "/script", "nonce"}}
	a := phaseSample(phases[0], 0x9000)
	b := phaseSample(phases[1], 0x9000-uint64(len("/elf")+len("--phase")+2))
	if err := validateSamples([]sample{a, b}, 7, phases, false, false); err != nil {
		t.Fatal(err)
	}
	tests := map[string][]sample{"missing-first": {b}, "missing-last": {a}, "duplicate-first": {a, a}, "reordered": {b, a}}
	for name, mutate := range map[string]func(*sample){"bprm": func(s *sample) { s.Bprm++ }, "task": func(s *sample) { s.Task++ }, "pid": func(s *sample) { s.PIDTGID++ }, "pending-end": func(s *sample) { s.PendingP++ }, "prefix": func(s *sample) { s.Argv.Data[0] = 'x' }, "incomplete": func(s *sample) { s.Argv.Complete = 0 }, "prior": func(s *sample) { s.Prior = -1 }} {
		bad := b
		mutate(&bad)
		tests[name] = []sample{a, bad}
	}
	for name, ss := range tests {
		t.Run(name, func(t *testing.T) {
			if validateSamples(ss, 7, phases, false, false) == nil {
				t.Fatal("accepted incomplete or misattributed phases")
			}
		})
	}
}

func TestRequiresObservedArgumentPageCrossing(t *testing.T) {
	phases := [][]string{{"/elf", "abcdefgh"}}
	crossing := phaseSample(phases[0], 0x1ff8)
	if err := validateSamples([]sample{crossing}, 7, phases, false, true); err != nil {
		t.Fatal(err)
	}
	samePage := crossing
	samePage.PendingP = 0x1000
	if validateSamples([]sample{samePage}, 7, phases, false, true) == nil {
		t.Fatal("accepted same-page argument")
	}
}
