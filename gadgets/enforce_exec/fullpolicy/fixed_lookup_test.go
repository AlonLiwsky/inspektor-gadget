// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"testing"
)

func TestFixedIdentities(t *testing.T) {
	empty := fixedIdentities{}
	if _, ok := empty.lookup(1); ok {
		t.Fatal("empty lookup")
	}
	if err := empty.insert(1, "one"); err == nil {
		t.Fatal("empty insertion")
	}
	table := fixedIdentities{slots: make([]identitySlot, 3)}
	for i, id := range []uint64{1, 4, 7} {
		if err := table.insert(id, fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	if table.count != 3 {
		t.Fatal("distinct occupancy")
	}
	if _, ok := table.lookup(10); ok {
		t.Fatal("full absent lookup")
	}
	if err := table.insert(4, "1"); err != nil || table.count != 3 {
		t.Fatal("full duplicate failed", err)
	}
	if err := table.insert(10, "new"); err == nil {
		t.Fatal("full table inserted")
	}
	if err := table.insert(4, "different"); err == nil || err.Error() != "stable identity hash collision between \"1\" and \"different\"" {
		t.Fatal("collision semantics", err)
	}
	if err := table.insert(0, "zero"); err == nil || err.Error() != "stable identity hash is reserved zero" {
		t.Fatal("zero identity", err)
	}
}

func TestFixedExpressions(t *testing.T) {
	table := fixedExpressions{slots: make([]expressionSlot, 2)}
	var keys []string
	for i := 0; len(keys) < 3; i++ {
		key := fmt.Sprint(i)
		if expressionHash(key)%2 == 0 {
			keys = append(keys, key)
		}
	}
	for i, key := range keys[:2] {
		if err := table.insert(key, KernelPattern{CodeBase: uint32(i + 1), Start: 2, Count: 3}); err != nil {
			t.Fatal(err)
		}
	}
	if _, ok := table.lookup(keys[2]); ok {
		t.Fatal("full absent expression")
	}
	if err := table.insert(keys[0], KernelPattern{CodeBase: 1, Start: 2, Count: 3}); err != nil {
		t.Fatal("full duplicate", err)
	}
	if err := table.insert(keys[2], KernelPattern{}); err == nil {
		t.Fatal("capacity overflow")
	}
	if got, ok := table.lookup(keys[1]); !ok || got.CodeBase != 2 || got.Padding != ([276]byte{}) {
		t.Fatal("packed expression entry changed", got)
	}
	if allocations := testing.AllocsPerRun(100, func() { table.lookup(keys[0]); table.lookup(keys[2]) }); allocations != 0 {
		t.Fatal("lookup allocated", allocations)
	}
}

func TestFixedLookupPreparedBounds(t *testing.T) {
	policies := capacityPolicies(MaxPolicies, MaxRules/MaxPolicies)
	for i := range policies {
		for j := range policies[i].Rules {
			r := &policies[i].Rules[j]
			r.Target.SetRole = "set"
			r.Actor.Role = make([]string, MaxValues)
			for n := range r.Actor.Role {
				r.Actor.Role[n] = "role"
			}
		}
	}
	prepared, err := preparePolicies(policies, nativeGlob)
	if err != nil {
		t.Fatal(err)
	}
	ids, expressions := preparedLookupCapacities(prepared)
	if ids != 65808 || expressions != 0 {
		t.Fatal("authored call bound", ids, expressions)
	}
	// Capacity is a call bound, not the validator's distinct-identity bound.
	table := fixedIdentities{slots: make([]identitySlot, ids)}
	if err := table.insert(stableHash("same"), "same"); err != nil {
		t.Fatal(err)
	}
	if err := (identityView{fixed: &table}).validate(); err != nil {
		t.Fatal(err)
	}
}

func TestFixedIdentityOccupiedLimit(t *testing.T) {
	table := fixedIdentities{slots: make([]identitySlot, 65808)}
	for i := 0; i < MaxKernelEntries+2*MaxPolicies; i++ {
		name := fmt.Sprintf("identity-%d", i)
		if err := table.insert(stableHash(name), name); err != nil {
			t.Fatal(err)
		}
	}
	if err := (identityView{fixed: &table}).validate(); err != nil {
		t.Fatal("valid occupied limit refused", err)
	}
	name := "one-more"
	if err := table.insert(stableHash(name), name); err != nil {
		t.Fatal(err)
	}
	if err := (identityView{fixed: &table}).validate(); err == nil || err.Error() != "invalid identity registry budget" {
		t.Fatal("occupied validator limit changed", err)
	}
}

func TestFixedIdentityCallTiming(t *testing.T) {
	p := base()
	p.Rules = []Rule{{Name: "bad-native-range", Action: Allow, Actor: Actor{Role: []string{"after-path"}}, Target: Target{SetRole: "before-path", Path: []string{"/[acegikmoq]"}}}}
	prepared, err := preparePolicies([]Policy{p}, nativeGlob)
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	_, err = compilePreparedKernel(prepared, 1, "worker", func(value string) uint64 { calls = append(calls, value); return stableHash(value) })
	if err == nil || err.Error() != "regexp instruction exceeds 8 rune ranges" {
		t.Fatal("native error changed", err)
	}
	if fmt.Sprint(calls) != fmt.Sprint([]string{p.ID, "agent", "before-path"}) {
		t.Fatal("identities pre-interned/reordered", calls)
	}
	for _, hash := range []uint64{0, 7} {
		calls = nil
		_, err = compilePreparedKernel(prepared, 1, "worker", func(value string) uint64 { calls = append(calls, value); return hash })
		want := 1
		if hash != 0 {
			want = 2
		}
		if err == nil || len(calls) != want {
			t.Fatal("zero/collision timing changed", calls, err)
		}
	}
}

func TestFixedExpressionFailedCompilationNotCached(t *testing.T) {
	bad, err := nativeGlob("/[acegikmoq]")
	if err != nil {
		t.Fatal(err)
	}
	compiler := kernelCompiler{patterns: fixedExpressions{slots: make([]expressionSlot, 1)}}
	if _, err = compiler.pathList([]nativePath{bad}); err == nil {
		t.Fatal("invalid native expression compiled")
	}
	if compiler.patterns.slots[0].occupied {
		t.Fatal("failed expression cached")
	}
	good, err := nativeGlob("/ok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = compiler.pathList([]nativePath{good}); err != nil {
		t.Fatal(err)
	}
	first, _ := compiler.patterns.lookup(good.expression)
	if _, err = compiler.pathList([]nativePath{good}); err != nil {
		t.Fatal("full duplicate cache failed", err)
	}
	second, _ := compiler.patterns.lookup(good.expression)
	if first != second {
		t.Fatal("cached native code changed")
	}
}

func TestPrivateEmittedLegacyCompatibility(t *testing.T) {
	prepared, err := preparePolicies(kernelFixture(), nativeGlob)
	if err != nil {
		t.Fatal(err)
	}
	emitted, err := compilePreparedKernel(prepared, 77, "worker", stableHash)
	if err != nil {
		t.Fatal(err)
	}
	if err = emitted.validate(); err != nil {
		t.Fatal(err)
	}
	public, err := CompileKernel(kernelFixture(), 77, "worker")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(emitted.legacy(), public) {
		t.Fatal("public compatibility map/content changed")
	}
}

// Guard the concrete shared pipeline boundaries against accidentally returning
// to map allocation or public legacy materialization. This complements, rather
// than replaces, review of the fixed identity-view branch and caller ownership.
func TestSharedPipelineNoMapMaterialization(t *testing.T) {
	targets := map[string][]string{
		"policy.go":          {"preparePolicies", "preparePoliciesWithDiagnostics"},
		"kernel.go":          {"compilePreparedKernel", "compilePreparedKernelWithDiagnostics", "identifier", "pathList"},
		"shared.go":          {"CompileSharedPolicy", "CompileSharedPolicyCompact", "compileSharedPolicy", "NewSharedSnapshot", "NewSharedSnapshotCompact", "newSharedSnapshot", "sharedExecutionMetadata", "sharedExecutionMetadataWithDiagnostics"},
		"validate_kernel.go": {"validateKernelData", "validateKernelDataWithDiagnostics"},
	}
	for filename, names := range targets {
		file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range names {
			found := false
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Name.Name != name {
					continue
				}
				found = true
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					if _, ok := node.(*ast.MapType); ok {
						t.Errorf("map allocation/type returned to %s", name)
					}
					if call, ok := node.(*ast.CallExpr); ok {
						if id, ok := call.Fun.(*ast.Ident); ok && (id.Name == "CompileKernel" || id.Name == "ValidateKernelProgram") {
							t.Errorf("legacy public path returned to %s", name)
						}
						if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "legacy" {
							t.Errorf("legacy materialization returned to %s", name)
						}
					}
					return true
				})
			}
			if !found {
				t.Fatalf("pipeline boundary %s missing", name)
			}
		}
	}
}

func TestFixedEmptyExpressionKey(t *testing.T) {
	empty := fixedExpressions{}
	if _, ok := empty.lookup(""); ok {
		t.Fatal("zero table has key")
	}
	if err := empty.insert("", KernelPattern{}); err == nil {
		t.Fatal("zero capacity accepted key")
	}
	table := fixedExpressions{slots: make([]expressionSlot, 1)}
	if err := table.insert("", KernelPattern{Count: 1}); err != nil {
		t.Fatal(err)
	}
	if p, ok := table.lookup(""); !ok || p.Count != 1 {
		t.Fatal("occupied flag confused empty expression")
	}
}

func TestFixedExpressionOriginalOccurrenceCapacity(t *testing.T) {
	prepared, err := preparePolicies(sharedCapacityPolicies("patterns", 2, 512), nativeGlob)
	if err != nil {
		t.Fatal(err)
	}
	_, capacity := preparedLookupCapacities(prepared)
	if capacity != MaxPatterns {
		t.Fatal("original paths deduplicated before capacity", capacity)
	}
	emitted, err := compilePreparedKernel(prepared, 1, "worker", stableHash)
	if err != nil {
		t.Fatal(err)
	}
	if err = emitted.validate(); err != nil {
		t.Fatal(err)
	}
	if _, err = preparePolicies(sharedCapacityPolicies("patterns", 2, 513), nativeGlob); err == nil {
		t.Fatal("original pattern count limit weakened")
	}
}

func TestIdentityViewErrorParity(t *testing.T) {
	for _, slot := range []identitySlot{{ID: 0, Name: "zero"}, {ID: 1, Name: ""}, {ID: 1, Name: "wrong-hash"}, {ID: stableHash("valid"), Name: "valid"}} {
		legacy := identityView{legacy: map[uint64]string{slot.ID: slot.Name}}
		fixed := identityView{fixed: &fixedIdentities{slots: []identitySlot{slot}, count: 1}}
		if a, b := fmt.Sprint(legacy.validate()), fmt.Sprint(fixed.validate()); a != b {
			t.Fatalf("identity error differs: %q / %q", a, b)
		}
	}
}
