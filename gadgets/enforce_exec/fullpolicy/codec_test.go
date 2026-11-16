// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
)

// These frozen oracles are the pre-refactor implementations, including size
// checks and failure semantics. They intentionally retain the old intermediates.
func legacyCodecDecode[T any](blob Blob) (T, error) {
	var result T
	if binary.Size(result) != KernelBlobSize {
		return result, fmt.Errorf("entry layout must be %d bytes", KernelBlobSize)
	}
	err := binary.Read(bytes.NewReader(blob[:]), binary.LittleEndian, &result)
	return result, err
}

func legacyCodecEncode(value any) (Blob, error) {
	var result Blob
	if binary.Size(value) != KernelBlobSize {
		return result, fmt.Errorf("entry layout must be %d bytes", KernelBlobSize)
	}
	var b bytes.Buffer
	if err := binary.Write(&b, binary.LittleEndian, value); err != nil {
		return result, err
	}
	copy(result[:], b.Bytes())
	return result, nil
}

type codecRecord struct {
	Number uint64
	Signed int32
	Flag   bool
	Tail   [275]byte
}
type codecPadding struct {
	Number uint64
	_      [280]byte
}
type (
	codecHidden      struct{ hidden [288]byte }
	codecUnsupported struct{ Data []byte }
	codecBytes       [288]byte
)

type codecOutcome[T any] struct {
	Value                   T
	Error, ErrorType, Panic string
}

func observeCodec[T any](call func() (T, error)) (out codecOutcome[T]) {
	defer func() {
		if p := recover(); p != nil {
			out.Panic = fmt.Sprintf("%T: %v", p, p)
		}
	}()
	value, err := call()
	out.Value = value
	if err != nil {
		out.Error = err.Error()
		out.ErrorType = fmt.Sprintf("%T", err)
	}
	return
}

func compareCodecDecode[T any](t *testing.T, input Blob) {
	t.Helper()
	old := observeCodec(func() (T, error) { return legacyCodecDecode[T](input) })
	got := observeCodec(func() (T, error) { return Decode[T](input) })
	if !reflect.DeepEqual(old, got) {
		t.Fatalf("decode %T differs: old=%+v got=%+v", old.Value, old, got)
	}
}

func TestCodecGenericCompatibility(t *testing.T) {
	var input Blob
	for i := range input {
		input[i] = byte(i*37 + 19)
	}
	compareCodecDecode[Blob](t, input)
	compareCodecDecode[codecBytes](t, input)
	compareCodecDecode[[288]bool](t, input)
	compareCodecDecode[[36]uint64](t, input)
	compareCodecDecode[codecRecord](t, input)
	compareCodecDecode[codecPadding](t, input)
	compareCodecDecode[codecHidden](t, input)
	compareCodecDecode[*Blob](t, input)
	compareCodecDecode[[]byte](t, input)
	compareCodecDecode[codecUnsupported](t, input)
	compareCodecDecode[uint64](t, input)
	compareCodecDecode[[287]byte](t, input)
	compareCodecDecode[[289]byte](t, input)
	compareCodecDecode[any](t, input)
	values := []any{nil, (*Blob)(nil), input, &input, codecBytes(input), [288]bool{true}, [36]uint64{0x0102030405060708}, codecRecord{Number: 0x0102030405060708, Signed: -3, Flag: true}, codecPadding{Number: 7}, codecHidden{}, codecUnsupported{}, uint64(1), [287]byte{}, [289]byte{}, input[:], "unsupported"}
	for _, value := range values {
		old := observeCodec(func() (Blob, error) { return legacyCodecEncode(value) })
		got := observeCodec(func() (Blob, error) { return encode(value) })
		if !reflect.DeepEqual(old, got) {
			t.Fatalf("encode %T differs: old=%+v got=%+v", value, old, got)
		}
	}
}

func TestCodecOwnedBytesAndEndian(t *testing.T) {
	source := codecRecord{Number: 0x0102030405060708, Signed: -3, Flag: true}
	blob, err := encode(&source)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(blob[:13], []byte{8, 7, 6, 5, 4, 3, 2, 1, 253, 255, 255, 255, 1}) {
		t.Fatal("little endian layout changed")
	}
	source.Number = 0
	if blob[0] != 8 {
		t.Fatal("output aliases input")
	}
	decoded, err := Decode[codecRecord](blob)
	if err != nil {
		t.Fatal(err)
	}
	blob[0] = 0
	if decoded.Number != 0x0102030405060708 {
		t.Fatal("decoded value aliases blob")
	}
}

var (
	codecSinkBlob   Blob
	codecSinkHeader KernelHeader
)

func TestCodecAllocationObservation(t *testing.T) {
	source := KernelHeader{Generation: 1, PolicyCount: 1}
	blob, err := legacyCodecEncode(source)
	if err != nil {
		t.Fatal(err)
	}
	oldEncode := testing.AllocsPerRun(100, func() { codecSinkBlob, _ = legacyCodecEncode(source) })
	newEncode := testing.AllocsPerRun(100, func() { codecSinkBlob, _ = encode(source) })
	oldDecode := testing.AllocsPerRun(100, func() { codecSinkHeader, _ = legacyCodecDecode[KernelHeader](blob) })
	newDecode := testing.AllocsPerRun(100, func() { codecSinkHeader, _ = Decode[KernelHeader](blob) })
	t.Logf("allocations per call: encode old=%v new=%v; decode old=%v new=%v", oldEncode, newEncode, oldDecode, newDecode)
	if newEncode > oldEncode || newDecode > oldDecode {
		t.Fatal("codec allocations increased")
	}
}
