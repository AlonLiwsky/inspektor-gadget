// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"regexp/syntax"
	"strings"
	"testing"
)

func TestGlobCapacityCompatibility(t *testing.T) {
	cases := []struct{ pattern, expression string }{
		{`/[a][b]`, `\A(?s:/[\x{61}-\x{61}][\x{62}-\x{62}])\z`},
		{`/[^a]`, `\A(?s:/[\x{0}-\x{60}\x{62}-\x{10ffff}])\z`},
		{`/[\]]`, `\A(?s:/[\x{5d}-\x{5d}])\z`},
		{`/[\-]`, `\A(?s:/[\x{2d}-\x{2d}])\z`},
		{`/[α-ω]`, `\A(?s:/[\x{3b1}-\x{3c9}])\z`},
		{"/[^\x00-\U0010ffff]", `\A(?s:/[^\x{0}-\x{10ffff}])\z`},
	}
	for _, tc := range cases {
		for _, d := range []diagnosticPolicy{richDiagnostics, compactDiagnosticsPolicy} {
			got, err := globExpressionWithDiagnostics(tc.pattern, d)
			if err != nil || got != tc.expression {
				t.Fatalf("%q got %q / %v want %q", tc.pattern, got, err, tc.expression)
			}
		}
	}
	// The direct converter is unrestricted; native preparePaths owns the 255 cap.
	pattern := "/" + strings.Repeat("a", 1024)
	want := `\A(?s:` + pattern + `)\z`
	if got, err := globExpression(pattern); err != nil || got != want {
		t.Fatalf("direct large input changed: %v", err)
	}
}

func TestGlobCapacityRejectionOrder(t *testing.T) {
	for _, pattern := range []string{`/[a][z-a]`, `/[α-ω][z-a]`} {
		_, err := globExpression(pattern)
		var leaf *syntax.Error
		if !errors.As(err, &leaf) || leaf.Code != syntax.ErrInvalidCharRange {
			t.Fatalf("original class Parse rejection changed: %v", err)
		}
		_, err = globExpressionWithDiagnostics(pattern, compactDiagnosticsPolicy)
		requireCompact(t, err, DiagnosticInvalidInput, DiagnosticNone)
	}
	// path.Match must reject malformed trailing structure before any class Parse.
	_, err := globExpression(`/[z-a][`)
	if !errors.Is(err, path.ErrBadPattern) {
		t.Fatalf("initial pathname rejection moved: %v", err)
	}
}

func TestGlobCheckedCapacity(t *testing.T) {
	maxInt := int(^uint(0) >> 1)
	for _, tc := range []struct {
		count, scale, base, want int
		ok                       bool
	}{
		{255, 21, 9, 5364, true},
		{0, 21, 9, 9, true},
		{(maxInt - 9) / 21, 21, 9, 9 + 21*((maxInt-9)/21), true},
		{(maxInt-9)/21 + 1, 21, 9, 0, false},
		{maxInt, 10, 3, 0, false},
		{-1, 21, 9, 0, false},
	} {
		got, ok := checkedGlobCapacity(tc.count, tc.scale, tc.base)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("%+v got %d/%v", tc, got, ok)
		}
	}
	for _, tc := range []struct {
		pattern string
		want    int
	}{
		{`[a]`, 12}, {`[^a]`, 13}, {`[\]]`, 12}, {`[\-]`, 12}, {`[α-ω]`, 32}, {`[a-cx]`, 42},
	} {
		got, ok := globClassCapacity([]rune(tc.pattern), 0)
		if !ok || got != tc.want {
			t.Fatalf("%q got %d/%v want %d", tc.pattern, got, ok, tc.want)
		}
	}
}

func TestGlobConstructionLengths(t *testing.T) {
	patterns := append([]string(nil), compatibilityGlobs...)
	for _, atom := range []string{"*", "**", "?", "界", `[a]`, `[^a]`, `[\]]`, `[α-ω]`, `[acegikmoqs]`} {
		patterns = append(patterns, "/"+strings.Repeat(atom, 80))
	}
	for _, pattern := range patterns {
		expression, err := globExpression(pattern)
		if err != nil {
			continue
		}
		capacity, ok := checkedGlobCapacity(len(pattern), 21, 9)
		if !ok || len(expression) > capacity {
			t.Fatalf("length %d exceeds bound %d for %q", len(expression), capacity, pattern)
		}
	}
}

// Supporting source guard only: the length proof and byte/error tests are the
// behavioral evidence. Each zero builder gets one checked Grow before writes;
// overflow has no rejection branch and the literal adapter cannot append.
func TestGlobBuildersGrowOnceBeforeWrites(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "glob.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var body *ast.BlockStmt
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "globExpressionWithDiagnostics" {
			body = fn.Body
		}
	}
	if body == nil {
		t.Fatal("converter missing")
	}
	grows := map[string][]token.Pos{}
	writes := map[string]token.Pos{}
	checked := 0
	ast.Inspect(body, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "append" {
				t.Error("literal adapter append returned")
			}
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
				if id, ok := selector.X.(*ast.Ident); ok && (id.Name == "b" || id.Name == "classPattern") {
					if selector.Sel.Name == "Grow" {
						grows[id.Name] = append(grows[id.Name], call.Pos())
					}
					if strings.HasPrefix(selector.Sel.Name, "Write") && writes[id.Name] == 0 {
						writes[id.Name] = call.Pos()
					}
				}
			}
		}
		if branch, ok := node.(*ast.IfStmt); ok {
			init, ok := branch.Init.(*ast.AssignStmt)
			if !ok || len(init.Rhs) != 1 {
				return true
			}
			call, ok := init.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := call.Fun.(*ast.Ident)
			if !ok || (name.Name != "checkedGlobCapacity" && name.Name != "globClassCapacity") {
				return true
			}
			checked++
			if branch.Else != nil {
				t.Error("overflow fallback gained an else/rejection")
			}
			ast.Inspect(branch.Body, func(n ast.Node) bool {
				if _, ok := n.(*ast.ReturnStmt); ok {
					t.Error("growth optimization gained rejection")
				}
				return true
			})
		}
		return true
	})
	if checked != 2 {
		t.Fatalf("checked growth sites=%d", checked)
	}
	for _, name := range []string{"b", "classPattern"} {
		if len(grows[name]) != 1 || writes[name] == 0 || grows[name][0] >= writes[name] {
			t.Fatalf("%s does not grow once before writes", name)
		}
	}
}
