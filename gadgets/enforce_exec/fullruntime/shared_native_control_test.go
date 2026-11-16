// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullruntime

import (
	"bytes"
	"encoding"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

// These are caller-layout premises only, not a Cilium marshaling allocation
// bound. No map/program operation is needed to inspect the actual Go payloads.
func TestSharedCommandReceiptNativeScalarLayout(t *testing.T) {
	if unsafe.Sizeof(sharedCommandWire{}) != 1112 || unsafe.Sizeof(sharedReceiptWire{}) != 48 {
		t.Fatal("native command/receipt size differs from fixed map value size")
	}
	for _, tc := range []struct {
		value   any
		names   []string
		offsets []uintptr
	}{
		{sharedCommandWire{}, []string{"NodeCookie", "Nonce", "Sequence", "Generation", "Attempt", "Scope", "Serial", "CgroupIdentity", "Operation", "Object", "Binding", "Record", "Index", "Count", "ExecutionClass", "Reserved", "Handles", "Value", "Metadata"}, []uintptr{0, 8, 16, 24, 32, 40, 48, 56, 64, 68, 72, 76, 80, 84, 88, 92, 96, 416, 704}},
		{sharedReceiptWire{}, []string{"NodeCookie", "Sequence", "Generation", "Serial", "Operation", "Status", "Value", "Reserved"}, []uintptr{0, 8, 16, 24, 32, 36, 40, 44}},
	} {
		t.Run(reflect.TypeOf(tc.value).Name(), func(t *testing.T) {
			typ := reflect.TypeOf(tc.value)
			if typ.NumField() != len(tc.names) {
				t.Fatal("wire field count changed")
			}
			for i, name := range tc.names {
				field := typ.Field(i)
				if field.Name != name || field.Offset != tc.offsets[i] {
					t.Fatalf("field %d=%s offset%d, want %s offset%d", i, field.Name, field.Offset, name, tc.offsets[i])
				}
			}
			value := reflect.New(typ).Elem()
			fillSharedScalarWire(t, value)
			encoded := make([]byte, typ.Size())
			if n, err := binary.Encode(encoded, binary.NativeEndian, value.Interface()); err != nil || n != len(encoded) {
				t.Fatalf("fixed wire encoding: bytes%d err%v", n, err)
			}
			native := unsafe.Slice((*byte)(value.Addr().UnsafePointer()), int(typ.Size()))
			if !bytes.Equal(native, encoded) {
				t.Fatal("native payload differs from complete scalar encoding")
			}
			decoded := reflect.New(typ)
			if n, err := binary.Decode(encoded, binary.NativeEndian, decoded.Interface()); err != nil || n != len(encoded) || !reflect.DeepEqual(decoded.Elem().Interface(), value.Interface()) {
				t.Fatalf("fixed wire decoding: bytes%d err%v", n, err)
			}
		})
	}
}

func fillSharedScalarWire(t *testing.T, value reflect.Value) {
	t.Helper()
	typ := value.Type()
	for _, candidate := range []reflect.Type{typ, reflect.PointerTo(typ)} {
		if candidate.Implements(reflect.TypeFor[encoding.BinaryMarshaler]()) || candidate.Implements(reflect.TypeFor[encoding.BinaryUnmarshaler]()) {
			t.Fatalf("wire type %s has custom binary marshaling", candidate)
		}
	}
	switch value.Kind() {
	case reflect.Struct:
		var end uintptr
		for i := range typ.NumField() {
			field := typ.Field(i)
			if !field.IsExported() || field.Offset != end {
				t.Fatalf("wire field %s.%s is unexported or padded", typ, field.Name)
			}
			fillSharedScalarWire(t, value.Field(i))
			end += field.Type.Size()
		}
		if end != typ.Size() {
			t.Fatalf("wire type %s has trailing padding", typ)
		}
	case reflect.Array:
		for i := range value.Len() {
			fillSharedScalarWire(t, value.Index(i))
		}
	case reflect.Uint8, reflect.Uint32, reflect.Uint64:
		value.SetUint(0xa1b2c3d4e5f60718)
	default:
		t.Fatalf("wire type %s is not a fixed unsigned scalar/array/struct", typ)
	}
}

func TestSharedNativeControlWire(t *testing.T) {
	if sharedNodeInspect != 16 || sharedLastOperation != sharedNodeInspect {
		t.Fatal("node probe opcode disagrees with actual C entry")
	}
	for _, v := range []struct {
		value any
		size  int
	}{{sharedNodeWire{}, 56}, {sharedCommandWire{}, 1112}, {sharedReceiptWire{}, 48}, {sharedPinWire{}, 40}, {sharedSnapshotMetadataWire{}, 408}} {
		if got := binary.Size(v.value); got != v.size {
			t.Fatalf("wire %T=%d want%d", v.value, got, v.size)
		}
	}
	if unsafe.Offsetof(sharedCommandWire{}.Handles) != 96 || unsafe.Offsetof(sharedCommandWire{}.Value) != 416 || unsafe.Offsetof(sharedNodeWire{}.Slots) != 36 {
		t.Fatal("shared C/native offsets disagree")
	}
	if err := validateSharedMapReferences([]ebpf.MapID{1, 2}, []ebpf.MapID{1, 2}, []ebpf.MapID{1, 2}); err != nil {
		t.Fatal(err)
	}
	for _, actual := range [][]ebpf.MapID{{1}, {1, 3}, {1, 2, 3}} {
		if err := validateSharedMapReferences([]ebpf.MapID{1, 2}, []ebpf.MapID{1, 2}, actual); err == nil {
			t.Fatal("foreign/missing actual program map accepted")
		}
	}
	if err := validateSharedMapReferences([]ebpf.MapID{1, 1}, []ebpf.MapID{1}, []ebpf.MapID{1}); err == nil {
		t.Fatal("aliased distinct protocol maps")
	}
	if _, err := newSharedControl(t.Context(), sharedTestProfile(), sharedControlResources{}); err == nil {
		t.Fatal("missing actual loaded resources accepted")
	}
}

func TestSharedMapOptionalAliasRejected(t *testing.T) {
	if err := validateSharedMapReferences([]ebpf.MapID{1, 2, 3, 4, 5, 6, 7}, []ebpf.MapID{1, 2, 3, 4, 5, 6, 7, 1}, []ebpf.MapID{1, 2, 3, 4, 5, 6, 7}); err == nil {
		t.Fatal("optional rodata aliases configuration")
	}
}

func TestSharedProgramMapIdentityUnion(t *testing.T) {
	required := []ebpf.MapID{1, 2, 3}
	allowed := []ebpf.MapID{1, 2, 3, 4}
	programs := map[string][]ebpf.MapID{"command": {1}, "exec": {2, 3}}
	if err := validateSharedProgramMapReferences(required, allowed, []string{"command", "exec"}, programs); err != nil {
		t.Fatal(err)
	}
	delete(programs, "exec")
	if err := validateSharedProgramMapReferences(required, allowed, []string{"command", "exec"}, programs); err == nil {
		t.Fatal("missing hook accepted")
	}
	programs["exec"] = []ebpf.MapID{2, 9}
	if err := validateSharedProgramMapReferences(required, allowed, []string{"command", "exec"}, programs); err == nil {
		t.Fatal("foreign hook map accepted")
	}
	programs["exec"] = []ebpf.MapID{2}
	if err := validateSharedProgramMapReferences(required, allowed, []string{"command", "exec"}, programs); err == nil {
		t.Fatal("unreferenced required map accepted")
	}
}

type sharedZeroMapTest struct {
	frozen    bool
	dirty     bool
	freezeErr bool
}

func (m *sharedZeroMapTest) Freeze() error {
	if m.freezeErr {
		return fmt.Errorf("freeze failure")
	}
	m.frozen = true
	return nil
}

func (m *sharedZeroMapTest) Lookup(_ interface{}, out interface{}) error {
	if !m.frozen {
		return fmt.Errorf("read before freeze")
	}
	b := out.([]byte)
	if m.dirty {
		b[len(b)-1] = 1
	}
	return nil
}

func TestSharedZeroTemplatesFrozenBeforeInspection(t *testing.T) {
	for _, dirty := range []bool{false, true} {
		a, b := &sharedZeroMapTest{}, &sharedZeroMapTest{dirty: dirty}
		err := freezeSharedZeroTemplates(map[string]sharedZeroTemplateMap{"se_zero_tasks": a, "se_zero_invocations": b, ".bss": &sharedZeroMapTest{}})
		if (err != nil) != dirty {
			t.Fatalf("dirty=%v err=%v", dirty, err)
		}
		if !a.frozen || !b.frozen {
			t.Fatal("zero templates not frozen")
		}
	}
	if err := freezeSharedZeroTemplates(map[string]sharedZeroTemplateMap{}); err == nil {
		t.Fatal("missing zero templates accepted")
	}
	if err := freezeSharedZeroTemplates(map[string]sharedZeroTemplateMap{"se_zero_tasks": &sharedZeroMapTest{freezeErr: true}}); err == nil {
		t.Fatal("freeze failure ignored")
	}
}

func TestSharedPoolZeroTemplatesFrozenBeforeInspection(t *testing.T) {
	for _, dirty := range []bool{false, true} {
		task, work := &sharedZeroMapTest{}, &sharedZeroMapTest{dirty: dirty}
		err := freezeSharedPoolZeroTemplates(map[string]sharedZeroTemplateMap{
			"se_pool_task_zero": task, "se_pool_work_zero": work,
		})
		if (err != nil) != dirty || !task.frozen || !work.frozen {
			t.Fatalf("pool zero templates: dirty=%v err=%v task=%v work=%v", dirty, err, task.frozen, work.frozen)
		}
	}
	if err := freezeSharedPoolZeroTemplates(map[string]sharedZeroTemplateMap{}); err == nil {
		t.Fatal("missing pool zero templates accepted")
	}
}

func TestSharedProgramIdentityAliasesRejected(t *testing.T) {
	for _, ids := range [][]ebpf.ProgramID{{0, 2}, {1, 1}} {
		if err := validateSharedProgramIDs(ids); err == nil {
			t.Fatalf("unsafe program identities %v", ids)
		}
	}
	if err := validateSharedProgramIDs([]ebpf.ProgramID{1, 2}); err != nil {
		t.Fatal(err)
	}
}
