// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import "testing"

// This checks the source inputs needed by a FUTURE admission adapter, not an
// executing compiler budget. Model qualification is not build attestation.
func TestSyntaxAdmissionPreservesAuthoredOccurrences(t *testing.T) {
	// Equivalent canonical expressions do not imply identical conversion work:
	// globExpression parses the class for every original authored occurrence,
	// before kernelCompiler.pathList can deduplicate its expression.
	authored := []string{"/[a]", "/[a-a]", "/[a]"}
	var expression string
	var allClasses, firstClasses, longestClasses uint64
	for i, pattern := range authored {
		n := uint64(len(pattern)) // derive from actual authored input, never expression length
		classes, err := syntaxWorkspaceAllClassCalls(n)
		if err != nil {
			t.Fatal(err)
		}
		full, err := syntaxWorkspaceFullParse(n)
		if err != nil {
			t.Fatal(err)
		}
		compile, err := syntaxWorkspaceKnownCosts(n)
		if err != nil {
			t.Fatal(err)
		}
		// FullParse includes Regexp nodes already. Only Prog and instruction history
		// from KnownCosts belong in addition to the two parser envelopes.
		total := uint64(0)
		for _, term := range []uint64{classes, full, compile.progBytes, compile.instructionBytes} {
			total, err = syntaxWorkspaceSum(total, term)
			if err != nil {
				t.Fatal(err)
			}
		}
		if total <= classes || total <= full {
			t.Fatal("parser/compile components missing")
		}
		allClasses, err = syntaxWorkspaceSum(allClasses, classes)
		if err != nil {
			t.Fatal(err)
		}
		longestClasses = max(longestClasses, classes)
		generated, err := globExpression(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			expression = generated
			firstClasses = classes
		} else if generated != expression {
			t.Fatal("fixture no longer has equivalent expressions")
		}
	}
	if allClasses <= longestClasses || allClasses <= 3*firstClasses {
		t.Fatal("canonical dedup or representative length lost original class work")
	}
}
