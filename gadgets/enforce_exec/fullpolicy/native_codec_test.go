// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"math/rand/v2"
	"os"
	"reflect"
	"strings"
	"testing"
)

func checkNativeCodec[T any](t *testing.T, blob Blob, decode func(Blob) T, encodeNative func(T) Blob) {
	t.Helper()
	oracle, err := Decode[T](blob)
	if err != nil {
		t.Fatal(err)
	}
	got := decode(blob)
	if !reflect.DeepEqual(got, oracle) {
		t.Fatalf("typed decode differs for %T", got)
	}
	encoded, err := encode(oracle)
	if err != nil {
		t.Fatal(err)
	}
	if actual := encodeNative(oracle); actual != encoded || actual != blob {
		t.Fatalf("typed encoding differs for %T", got)
	}
	if encodeNative(got) != blob {
		t.Fatalf("arbitrary bytes lost for %T", got)
	}
}

func TestNativeCodecsDifferential(t *testing.T) {
	random := rand.New(rand.NewPCG(111, 222))
	for sample := 0; sample < 512; sample++ {
		var blob Blob
		for i := range blob {
			blob[i] = byte(random.Uint32())
		}
		checkNativeCodec(t, blob, decodeKernelHeader, encodeKernelHeader)
		checkNativeCodec(t, blob, decodeKernelPolicy, encodeKernelPolicy)
		checkNativeCodec(t, blob, decodeKernelRule, encodeKernelRule)
		checkNativeCodec(t, blob, decodeKernelString, encodeKernelString)
		checkNativeCodec(t, blob, decodeKernelValue, encodeKernelValue)
		checkNativeCodec(t, blob, decodeKernelPattern, encodeKernelPattern)
		checkNativeCodec(t, blob, decodeKernelInstruction, encodeKernelInstruction)
	}
}

func TestNativeCodecsOffsets(t *testing.T) {
	cases := []struct {
		blob   Blob
		offset int
	}{
		{encodeKernelHeader(KernelHeader{Generation: 1}), 0},
		{encodeKernelHeader(KernelHeader{PolicyCount: 1}), 8},
		{encodeKernelHeader(KernelHeader{RuleBase: 1}), 12},
		{encodeKernelHeader(KernelHeader{RuleCount: 1}), 16},
		{encodeKernelHeader(KernelHeader{ContainerRef: 1}), 20},
		{encodeKernelHeader(KernelHeader{Padding: [264]byte{1}}), 24},
		{encodeKernelPolicy(KernelPolicy{UID: 1}), 0},
		{encodeKernelPolicy(KernelPolicy{RootRole: 1}), 8},
		{encodeKernelPolicy(KernelPolicy{Default: 1}), 16},
		{encodeKernelPolicy(KernelPolicy{Mode: 1}), 20},
		{encodeKernelPolicy(KernelPolicy{RootEpoch: 1}), 24},
		{encodeKernelPolicy(KernelPolicy{Padding: [256]byte{1}}), 32},
		{encodeKernelRule(KernelRule{PolicyIndex: 1}), 0},
		{encodeKernelRule(KernelRule{Mode: 1}), 4},
		{encodeKernelRule(KernelRule{Deny: 1}), 8},
		{encodeKernelRule(KernelRule{ActorImage: 1}), 12},
		{encodeKernelRule(KernelRule{TargetImage: 1}), 16},
		{encodeKernelRule(KernelRule{Stdin: 1}), 20},
		{encodeKernelRule(KernelRule{AncestorDepth: 1}), 24},
		{encodeKernelRule(KernelRule{Reserved: 1}), 28},
		{encodeKernelRule(KernelRule{SetRole: 1}), 32},
		{encodeKernelRule(KernelRule{ActorPath: KernelList{Base: 1}}), 40},
		{encodeKernelRule(KernelRule{TargetPath: KernelList{Base: 1}}), 48},
		{encodeKernelRule(KernelRule{AncestorPath: KernelList{Base: 1}}), 56},
		{encodeKernelRule(KernelRule{ActorRole: KernelList{Base: 1}}), 64},
		{encodeKernelRule(KernelRule{UID: KernelList{Base: 1}}), 72},
		{encodeKernelRule(KernelRule{Container: KernelList{Base: 1}}), 80},
		{encodeKernelRule(KernelRule{FSType: KernelList{Base: 1}}), 88},
		{encodeKernelRule(KernelRule{ArgContains: KernelList{Base: 1}}), 96},
		{encodeKernelRule(KernelRule{ArgPrefix: KernelList{Count: 1}}), 108},
		{encodeKernelRule(KernelRule{Padding: [176]byte{1}}), 112},
		{encodeKernelString(KernelString{Length: 1}), 0},
		{encodeKernelString(KernelString{Bytes: [256]byte{1}}), 4},
		{encodeKernelString(KernelString{Padding: [28]byte{1}}), 260},
		{encodeKernelValue(KernelValue{Value: 1}), 0},
		{encodeKernelValue(KernelValue{Padding: [280]byte{1}}), 8},
		{encodeKernelPattern(KernelPattern{CodeBase: 1}), 0},
		{encodeKernelPattern(KernelPattern{Start: 1}), 4},
		{encodeKernelPattern(KernelPattern{Count: 1}), 8},
		{encodeKernelPattern(KernelPattern{Padding: [276]byte{1}}), 12},
		{encodeKernelInstruction(KernelInstruction{Op: 1}), 0},
		{encodeKernelInstruction(KernelInstruction{Out: 1}), 4},
		{encodeKernelInstruction(KernelInstruction{Arg: 1}), 8},
		{encodeKernelInstruction(KernelInstruction{Count: 1}), 12},
		{encodeKernelInstruction(KernelInstruction{Ranges: [16]uint32{1}}), 16},
		{encodeKernelInstruction(KernelInstruction{Padding: [208]byte{1}}), 80},
	}
	for i, tc := range cases {
		var want Blob
		want[tc.offset] = 1
		if tc.blob != want {
			t.Fatalf("offset fixture %d at %d differs", i, tc.offset)
		}
	}
	r := KernelRule{ActorImage: math.MinInt32, TargetImage: math.MaxInt32, Stdin: -1}
	if got := decodeKernelRule(encodeKernelRule(r)); got != r {
		t.Fatal("signed bits changed")
	}
}

var nativeCodecSink Blob

func TestNativeCodecsAllocations(t *testing.T) {
	var blob Blob
	for i := range blob {
		blob[i] = byte(i)
	}
	got := testing.AllocsPerRun(100, func() {
		nativeCodecSink = encodeKernelHeader(decodeKernelHeader(blob))
		nativeCodecSink = encodeKernelPolicy(decodeKernelPolicy(blob))
		nativeCodecSink = encodeKernelRule(decodeKernelRule(blob))
		nativeCodecSink = encodeKernelString(decodeKernelString(blob))
		nativeCodecSink = encodeKernelValue(decodeKernelValue(blob))
		nativeCodecSink = encodeKernelPattern(decodeKernelPattern(blob))
		nativeCodecSink = encodeKernelInstruction(decodeKernelInstruction(blob))
	})
	if got != 0 || nativeCodecSink != blob {
		t.Fatalf("typed codec allocations=%v or bytes changed", got)
	}
	t.Logf("local typed seven-record roundtrip allocations=%v (not whole compiler qualification)", got)
}

func TestNativeCodecsListAndRangeOffsets(t *testing.T) {
	for index := 0; index < 9; index++ {
		for member := 0; member < 2; member++ {
			var rule KernelRule
			fields := []*KernelList{&rule.ActorPath, &rule.TargetPath, &rule.AncestorPath, &rule.ActorRole, &rule.UID, &rule.Container, &rule.FSType, &rule.ArgContains, &rule.ArgPrefix}
			if member == 0 {
				fields[index].Base = 1
			} else {
				fields[index].Count = 1
			}
			var want Blob
			want[40+8*index+4*member] = 1
			if got := encodeKernelRule(rule); got != want {
				t.Fatalf("list %d member %d offset changed", index, member)
			}
		}
	}
	for index := range (KernelInstruction{}).Ranges {
		var instruction KernelInstruction
		instruction.Ranges[index] = 1
		var want Blob
		want[16+4*index] = 1
		if got := encodeKernelInstruction(instruction); got != want {
			t.Fatalf("range %d offset changed", index)
		}
	}
}

func TestNativeProductionDoesNotCallGenericCodecs(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	generic := func(name string) bool {
		return name == "Decode" || name == "encode" || name == "decodeWithDiagnostics" || name == "encodeWithDiagnostics"
	}
	checked := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || generic(fn.Name.Name) {
				continue
			}
			checked++
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					var id *ast.Ident
					switch target := call.Fun.(type) {
					case *ast.Ident:
						id = target
					case *ast.IndexExpr:
						id, _ = target.X.(*ast.Ident)
					}
					if id != nil && generic(id.Name) {
						t.Errorf("production %s/%s calls generic codec %s", name, fn.Name.Name, id.Name)
					}
				}
				return true
			})
		}
		if name == "native_codec.go" {
			ast.Inspect(file, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && (id.Name == "any" || id.Name == "reflect" || id.Name == "unsafe") {
					t.Errorf("native codec uses %s", id.Name)
				}
				if _, ok := n.(*ast.InterfaceType); ok {
					t.Error("native codec has interface")
				}
				if _, ok := n.(*ast.TypeSwitchStmt); ok {
					t.Error("native codec has type switch")
				}
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatal("production guard did not inspect functions")
	}
}
