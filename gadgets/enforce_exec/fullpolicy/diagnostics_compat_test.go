// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"errors"
	"path"
	"regexp/syntax"
	"testing"
)

func TestRichDiagnosticCauses(t *testing.T) {
	for _, compile := range []func([]Policy) error{
		func(p []Policy) error { _, err := Compile(p); return err },
		func(p []Policy) error { _, err := CompileKernel(p, 1, "container"); return err },
		func(p []Policy) error { _, err := CompileSharedPolicy(p[0]); return err },
	} {
		p := []Policy{{ID: "p", Revision: "r", Mode: Audit, Rules: []Rule{{Name: "rule", Action: Allow, Target: Target{Path: []string{"/["}}}}}}
		err := compile(p)
		if !errors.Is(err, path.ErrBadPattern) {
			t.Fatalf("missing bad-pattern cause: %v", err)
		}
		if want := "rule rule target: malformed glob \"/[\": syntax error in pattern"; err.Error() != want {
			t.Fatalf("got %q want %q", err, want)
		}
		p[0].Rules[0].Target.Path[0] = "/[z-a]"
		err = compile(p)
		var syntaxErr *syntax.Error
		if !errors.As(err, &syntaxErr) || syntaxErr.Code != syntax.ErrInvalidCharRange {
			t.Fatalf("missing syntax range cause: %v", err)
		}
	}
}
