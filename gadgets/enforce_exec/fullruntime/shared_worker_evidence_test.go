// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"strings"
	"testing"
	"unsafe"
)

func testWorkerCarrier() string {
	return "IGW1" + "0001" + "0001" + "01" + strings.Repeat("1", 64*5) + "0000000000000001" + "0000000000000002"
}

func TestSharedWorkerCarrierParser(t *testing.T) {
	good := testWorkerCarrier()
	d, ok := parseSharedWorkerEvidence(good)
	if len(good) != 366 || !ok || d.bootstrap != 1 || d.tail != 2 {
		t.Fatal("canonical carrier not parsed")
	}
	for _, bad := range []string{"", good + "0", good[:365], "BAD!" + good[4:], good[:4] + "0002" + good[8:], good[:8] + "0002" + good[12:], good[:12] + "03" + good[14:], good[:14] + strings.Repeat("0", 64) + good[78:], good[:14] + "A" + good[15:], good[:334] + strings.Repeat("f", 16) + "0000000000000001", good[:334] + strings.Repeat("0", 16) + good[350:]} {
		if _, ok := parseSharedWorkerEvidence(bad); ok {
			t.Fatal("malformed carrier accepted")
		}
	}
	if _, ok := decodeSharedWorkerDescriptor(); ok {
		t.Fatal("default production descriptor unexpectedly available")
	}
}

func TestSharedWorkerCarrierParserNoAllocation(t *testing.T) {
	carrier := testWorkerCarrier()
	if n := testing.AllocsPerRun(100, func() { _, _ = parseSharedWorkerEvidence(carrier) }); n != 0 {
		t.Fatal(n)
	}
}

func TestSharedWorkerFrozenEvidenceLayout(t *testing.T) {
	t.Logf("descriptor=%d frozen=%d carrierHeader=%d carrierWire=366 populatedCarrierBacking=367", unsafe.Sizeof(sharedWorkerDescriptor{}), unsafe.Sizeof(sharedWorkerFrozenEvidence{}), unsafe.Sizeof(sharedWorkerEvidence))
	// The selected linker owns a NUL beyond the exposed366-byte string.
	// The pure linked fixture verifies this backing byte, not just Go len.
	const linkedCarrierBacking = 366 + 1
	if linkedCarrierBacking+unsafe.Sizeof(sharedWorkerEvidence)+unsafe.Sizeof(sharedWorkerFrozenEvidence{}) != 575 {
		t.Fatal("fixed startup owner changed")
	}
	d, ok := parseSharedWorkerEvidence(testWorkerCarrier())
	if !ok {
		t.Fatal("fixture")
	}
	frozen := freezeSharedWorkerEvidence(testWorkerCarrier())
	if !frozen.available || frozen.descriptor != d {
		t.Fatal("freeze did not copy scalar descriptor")
	}
	if actual, available := decodeSharedWorkerDescriptor(); available || actual != (sharedWorkerDescriptor{}) {
		t.Fatal("production default changed")
	}
}
