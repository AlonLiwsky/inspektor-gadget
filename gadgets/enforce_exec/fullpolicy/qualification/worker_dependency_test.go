// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"strings"
	"testing"
)

func workerDependencyFixture() workerSnapshot {
	s := workerProjectFixture()
	for name, hash := range workerDependencySourcePins {
		s.Inputs[name] = hash
	}
	return s
}

func TestWorkerDependencyConditionalFormulaAndPins(t *testing.T) {
	s := workerDependencyFixture()
	b, err := deriveWorkerDependency(s)
	if err != nil || b.Write != 1454 || b.Read != 310 || b.Run != 207 || b.Tail != 1454 {
		t.Fatalf("%+v %v", b, err)
	}
	for name, hash := range workerDependencySourcePins {
		for _, bad := range []string{"", strings.Repeat("f", 64)} {
			s.Inputs[name] = bad
			if _, err := deriveWorkerDependency(s); err == nil {
				t.Fatal("changed source accepted", name)
			}
		}
		s.Inputs[name] = hash
	}
	for name, hash := range s.Consumer.ToolHashes {
		s.Consumer.ToolHashes[name] = ""
		if _, err := deriveWorkerDependency(s); err == nil {
			t.Fatal("missing tool accepted", name)
		}
		s.Consumer.ToolHashes[name] = hash
	}
	for name, value := range s.RawProfile {
		delete(s.RawProfile, name)
		if _, err := deriveWorkerDependency(s); err == nil {
			t.Fatal("missing raw profile accepted", name)
		}
		s.RawProfile[name] = "changed"
		if _, err := deriveWorkerDependency(s); err == nil {
			t.Fatal("changed raw profile accepted", name)
		}
		s.RawProfile[name] = value
	}
	for name, value := range s.Consumer.Profile {
		delete(s.Consumer.Profile, name)
		if _, err := deriveWorkerDependency(s); err == nil {
			t.Fatal("missing effective profile accepted", name)
		}
		s.Consumer.Profile[name] = value
	}
	for _, name := range []string{"GOVERSION", "GOOS", "GOARCH", "GOAMD64", "CGO_ENABLED", "GOEXPERIMENT", "GODEBUG", "GOFIPS140"} {
		old := s.Consumer.Profile[name]
		s.Consumer.Profile[name] = "changed"
		if _, err := deriveWorkerDependency(s); err == nil {
			t.Fatal("changed effective profile accepted", name)
		}
		s.Consumer.Profile[name] = old
	}
	// The numerical component is conditional: it must not create complete evidence.
	if _, err := deriveWorkerTail(workerProjectFixture()); err == nil || err.Error() != workerMissingDependency {
		t.Fatalf("aggregate refusal changed: %v", err)
	}
}

func TestWorkerDependencyLoweringGuards(t *testing.T) {
	for _, functions := range []map[string][]string{workerDependencyLoweringFunctions, workerDependencyStdlibLoweringFunctions} {
		var fixture strings.Builder
		for symbol, calls := range functions {
			fixture.WriteString(symbol + " STEXT size=1\n")
			for _, call := range calls {
				fixture.WriteString("\tCALL\t" + call + "(SB)\n")
			}
		}
		text := fixture.String()
		if err := checkWorkerDependencyFunctions(text, functions); err != nil {
			t.Fatal(err)
		}
		for symbol, calls := range functions {
			missing := strings.Replace(text, symbol+" STEXT ", "unrelated STEXT ", 1)
			if err := checkWorkerDependencyFunctions(missing, functions); err == nil {
				t.Fatal("missing function accepted", symbol)
			}
			for _, call := range calls {
				marker := symbol + " STEXT size=1\n"
				start := strings.Index(text, marker) + len(marker)
				at := start + strings.Index(text[start:], "\tCALL\t"+call+"(SB)")
				bad := text[:at] + strings.Replace(text[at:], "\tCALL\t"+call+"(SB)", "\tCALL\tunrelated(SB)", 1)
				// Put the missing call in another function: global substring matching must fail.
				bad += "unrelated STEXT size=1\n\tCALL\t" + call + "(SB)\n"
				if err := checkWorkerDependencyFunctions(bad, functions); err == nil {
					t.Fatal("out-of-function premise accepted", symbol, call)
				}
			}
		}
	}
}
