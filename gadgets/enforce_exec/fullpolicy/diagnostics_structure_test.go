// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"slices"
	"testing"
)

// This narrow guard supplements call-path review: project formatting in shared
// compiler cores must follow an early compact return, not format then classify.
// It does not make a claim about standard-library parser/codec allocations.
func TestCompactFormattingSelectionPrecedesConstruction(t *testing.T) {
	targets := map[string][]string{
		"policy.go":          {"preparePoliciesWithDiagnostics", "preparePoliciesWithDiagnosticsSemantic", "preparePathsWithDiagnostics", "cloneStringsWithDiagnostics", "validateStringWithDiagnostics"},
		"glob.go":            {"globExpressionWithDiagnostics", "nativeGlobWithDiagnostics"},
		"kernel.go":          {"decodeWithDiagnostics", "encodeWithDiagnostics", "compilePreparedKernelWithDiagnostics", "identifier", "reserve", "put", "strings", "values", "pathList", "regex", "packInstructionWithDiagnostics"},
		"fixed_lookup.go":    {"insertWithDiagnostics", "validateWithDiagnostics"},
		"validate_kernel.go": {"validateKernelDataWithDiagnostics", "identity", "stringAt", "list", "patternAt"},
		"shared.go":          {"compileSharedPolicy", "newSharedSnapshot", "sharedExecutionMetadataWithDiagnostics"},
	}
	forbidden := []string{"fmtError", "Decode", "encode", "preparePolicies", "preparePaths", "validateString", "cloneStrings", "globExpression", "nativeGlob", "compilePreparedKernel", "validateKernelData", "sharedExecutionMetadata", "packInstruction"}
	checked := 0
	for file, names := range targets {
		parsed, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]bool{}
		for _, decl := range parsed.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !slices.Contains(names, fn.Name.Name) {
				continue
			}
			found[fn.Name.Name] = true
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					name := ""
					switch f := call.Fun.(type) {
					case *ast.Ident:
						name = f.Name
					case *ast.IndexExpr:
						if id, ok := f.X.(*ast.Ident); ok {
							name = id.Name
						}
					}
					if slices.Contains(forbidden, name) {
						t.Errorf("%s calls rich-only %s", fn.Name.Name, name)
					}
					if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
						if selector.Sel.Name == "Error" || selector.Sel.Name == "Join" {
							t.Errorf("%s renders or dynamically joins diagnostics", fn.Name.Name)
						}
					}
				}
				block, ok := n.(*ast.BlockStmt)
				if !ok {
					return true
				}
				for i, statement := range block.List {
					ret, ok := statement.(*ast.ReturnStmt)
					if !ok {
						continue
					}
					formatting := false
					ast.Inspect(ret, func(n ast.Node) bool {
						if call, ok := n.(*ast.CallExpr); ok {
							if s, ok := call.Fun.(*ast.SelectorExpr); ok {
								if id, ok := s.X.(*ast.Ident); ok && id.Name == "fmt" {
									formatting = true
								}
							}
						}
						return true
					})
					if !formatting {
						continue
					}
					checked++
					if i == 0 {
						t.Errorf("%s formats without compact guard", fn.Name.Name)
						continue
					}
					guard, ok := block.List[i-1].(*ast.IfStmt)
					if !ok {
						t.Errorf("%s formats before policy selection", fn.Name.Name)
						continue
					}
					selector, ok := guard.Cond.(*ast.SelectorExpr)
					if !ok || selector.Sel.Name != "compact" {
						t.Errorf("%s formatting guard is not compact policy", fn.Name.Name)
						continue
					}
					if _, ok := guard.Body.List[len(guard.Body.List)-1].(*ast.ReturnStmt); !ok {
						t.Errorf("%s compact branch does not return before formatting", fn.Name.Name)
					}
				}
				return true
			})
		}
		for _, name := range names {
			if !found[name] {
				t.Errorf("guarded function %s missing", name)
			}
		}
	}
	if checked < 70 {
		t.Fatalf("formatting audit unexpectedly small: %d", checked)
	}
	t.Logf("checked %d pre-format policy selections", checked)
}
