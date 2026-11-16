// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"fmt"
	"math"
	"testing"
	"unsafe"
)

const reservationMetadata = uint64(unsafe.Sizeof(workspaceReservation{}))

func TestCompilerWorkspaceReservations(t *testing.T) {
	w := compilerWorkspace{limit: math.MaxUint64}
	a, err := w.reserve(math.MaxUint64 - reservationMetadata)
	if err != nil || w.used != math.MaxUint64 {
		t.Fatal(err, w)
	}
	if _, err = w.reserve(1); err == nil || w.used != math.MaxUint64 {
		t.Fatal("overflow changed accounting")
	}
	if err = a.release(); err != nil || w.used != reservationMetadata {
		t.Fatal(err, w)
	}
	if err = a.release(); err == nil || w.used != reservationMetadata {
		t.Fatal("double refund")
	}
	b, err := w.reserve(7)
	if err != nil {
		t.Fatal(err)
	}
	w.used = 2*reservationMetadata + 6 // A broken owner invariant must fail closed, not wrap subtraction.
	if err = b.release(); err == nil || w.used != 2*reservationMetadata+6 {
		t.Fatal("underflow changed accounting")
	}
	w.used = 2*reservationMetadata + 7
	if err = b.release(); err != nil {
		t.Fatal(err)
	}
}

func TestCompilerBlobGrowthAdmission(t *testing.T) {
	const cell = uint64(KernelBlobSize)
	w := compilerWorkspace{limit: 6*cell + 2*reservationMetadata}
	c := kernelCompiler{work: &w}
	if _, err := c.reserve(2); err != nil {
		t.Fatal(err)
	}
	c.entries[0][0] = 17
	original := &c.entries[0]
	w.limit = 6*cell + 2*reservationMetadata - 1 // Existing 2 + replacement 4 must overlap.
	if _, err := c.reserve(1); err == nil {
		t.Fatal("growth admitted below overlap")
	}
	if len(c.entries) != 2 || cap(c.entries) != 2 || &c.entries[0] != original || c.entries[0][0] != 17 || w.used != 2*cell+reservationMetadata {
		t.Fatal("refusal changed live buffer")
	}
	w.limit = 6*cell + 2*reservationMetadata
	list, err := c.reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	if list.Base != 2 || list.Count != 1 || cap(c.entries) != 4 || w.used != 4*cell+2*reservationMetadata || w.peak != 6*cell+2*reservationMetadata || c.entries[0][0] != 17 || c.entries[2] != (Blob{}) {
		t.Fatal("growth/accounting mismatch")
	}
	c.entries[:cap(c.entries)][3][0] = 99
	if _, err = c.reserve(1); err != nil || c.entries[3] != (Blob{}) || w.used != 4*cell+2*reservationMetadata {
		t.Fatal("in-capacity reserve must zero new cells", err)
	}
	// Moving the reservation alongside the backing transfers ownership without a
	// refund. The eventual owner releases only when its logical backing dies.
	retained := c.entriesWork
	c.entries, c.entriesWork = nil, nil
	if w.used != 4*cell+2*reservationMetadata {
		t.Fatal("transfer refunded live storage")
	}
	if err = retained.release(); err != nil || w.used != 2*reservationMetadata {
		t.Fatal(err)
	}
	if err = retained.release(); err == nil {
		t.Fatal("retained charge refunded twice")
	}
}

func TestCompilerBlobGrowthGeometry(t *testing.T) {
	c := kernelCompiler{}
	for n := 1; n <= MaxKernelEntries; n++ {
		if _, err := c.reserve(1); err != nil {
			t.Fatal(err)
		}
		if len(c.entries) != n || cap(c.entries) < n || cap(c.entries) > MaxKernelEntries || cap(c.entries) >= 2*n {
			t.Fatalf("capacity=%d length=%d", cap(c.entries), n)
		}
	}
	old := &c.entries[0]
	if _, err := c.reserve(1); err == nil || &c.entries[0] != old || len(c.entries) != MaxKernelEntries {
		t.Fatal("entry cap changed")
	}
	if _, err := c.reserve(-1); err == nil {
		t.Fatal("negative count")
	}
	if list, err := c.reserve(0); err != nil || list != (KernelList{}) {
		t.Fatal("zero reserve changed")
	}
}

func TestCompilerWorkspaceInvalidOwnerAndNoAllocRefusal(t *testing.T) {
	w := compilerWorkspace{limit: KernelBlobSize + reservationMetadata}
	if got := testing.AllocsPerRun(100, func() {
		if _, err := w.reserve(KernelBlobSize + 1); err == nil {
			t.Fatal("expected refusal")
		}
	}); got != 0 {
		t.Fatalf("refusal allocated: %v", got)
	}
	c := kernelCompiler{work: &w, entries: make([]Blob, 1)}
	if _, err := c.reserve(1); err == nil || len(c.entries) != 1 || w.used != 0 {
		t.Fatal("adopted uncharged backing")
	}
	c = kernelCompiler{work: &w}
	if _, err := c.reserve(1); err != nil {
		t.Fatal(err)
	}
	original := &c.entries[0]
	if err := c.entriesWork.release(); err != nil {
		t.Fatal(err)
	}
	if _, err := c.reserve(1); err == nil || &c.entries[0] != original || w.used != reservationMetadata {
		t.Fatal("reused released backing owner")
	}
	empty := compilerWorkspace{limit: reservationMetadata}
	token, err := empty.reserve(0)
	if err != nil {
		t.Fatal(err)
	}
	if err = token.release(); err != nil {
		t.Fatal(err)
	}
	if err = token.release(); err == nil {
		t.Fatal("zero reservation refunded twice")
	}
}

func TestCompilerWorkspaceCopiedReservation(t *testing.T) {
	for _, copyFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("copy-first-%t", copyFirst), func(t *testing.T) {
			w := compilerWorkspace{limit: 14 + 2*reservationMetadata}
			first, err := w.reserve(7)
			if err != nil {
				t.Fatal(err)
			}
			second, err := w.reserve(7)
			if err != nil {
				t.Fatal(err)
			}
			copied := *first
			if copyFirst {
				if err = copied.release(); err == nil {
					t.Fatal("copied value released allocation")
				}
				if w.used != 14+2*reservationMetadata {
					t.Fatal("copy stole live budget")
				}
			}
			if err = first.release(); err != nil {
				t.Fatal(err)
			}
			if err = copied.release(); err == nil || w.used != 7+2*reservationMetadata {
				t.Fatal("copy refunded second live allocation", w.used)
			}
			if _, err = w.reserve(8); err == nil {
				t.Fatal("stolen capacity readmitted")
			}
			if err = second.release(); err != nil || w.used != 2*reservationMetadata {
				t.Fatal(err, w.used)
			}
		})
	}
}

func TestCompilerWorkspaceReservationIdentity(t *testing.T) {
	w := compilerWorkspace{limit: 14 + reservationMetadata}
	other := compilerWorkspace{limit: 14 + reservationMetadata}
	original, err := w.reserve(7)
	if err != nil {
		t.Fatal(err)
	}
	second, err := other.reserve(7)
	if err != nil {
		t.Fatal(err)
	}
	stale := *original
	transferred := original
	original = nil
	foreign := stale
	foreign.owner = &other
	if err = foreign.release(); err == nil || other.used != 7+reservationMetadata || w.used != 7+reservationMetadata {
		t.Fatal("copy modified another owner")
	}
	if err = stale.release(); err == nil || w.used != 7+reservationMetadata {
		t.Fatal("old value copy released transferred ownership")
	}
	alias := transferred
	if err = transferred.release(); err != nil {
		t.Fatal(err)
	}
	after := *transferred
	for _, token := range []*workspaceReservation{alias, &stale, &after} {
		if err = token.release(); err == nil || w.used != reservationMetadata || other.used != 7+reservationMetadata {
			t.Fatal("released alias/copy changed charge")
		}
	}
	if err = second.release(); err != nil || other.used != reservationMetadata {
		t.Fatal(err)
	}
}

func TestCompilerBlobRejectsCopiedReservation(t *testing.T) {
	w := compilerWorkspace{limit: 10 * KernelBlobSize}
	c := kernelCompiler{work: &w}
	if _, err := c.reserve(2); err != nil {
		t.Fatal(err)
	}
	if _, err := c.reserve(1); err != nil {
		t.Fatal(err)
	} // capacity four, length three
	original := c.entriesWork
	copied := *original
	c.entriesWork = &copied
	for _, count := range []int{1, 2} {
		if _, err := c.reserve(count); err == nil || len(c.entries) != 3 || w.used != 4*KernelBlobSize+2*reservationMetadata {
			t.Fatal("copied ownership admitted extension/growth")
		}
	}
	c.entriesWork = original
	if _, err := c.reserve(1); err != nil {
		t.Fatal(err)
	}
}

func TestCompilerWorkspaceMetadataBudget(t *testing.T) {
	const payload = uint64(7)
	w := compilerWorkspace{limit: payload + reservationMetadata - 1}
	if _, err := w.reserve(payload); err == nil || w.used != 0 {
		t.Fatal("metadata not admitted before token allocation")
	}
	w.limit++
	token, err := w.reserve(payload)
	if err != nil {
		t.Fatal(err)
	}
	if token.bytes != payload || w.used != payload+reservationMetadata {
		t.Fatal("payload/token accounting changed")
	}
	if err = token.release(); err != nil || w.used != reservationMetadata {
		t.Fatal("metadata refunded while aliases may remain", err)
	}
	if _, err = w.reserve(payload); err == nil {
		t.Fatal("released token metadata reused")
	}
	overflow := compilerWorkspace{limit: math.MaxUint64}
	if _, err = overflow.reserve(math.MaxUint64); err == nil || overflow.used != 0 {
		t.Fatal("payload plus metadata overflow")
	}
	empty := compilerWorkspace{limit: 2 * reservationMetadata}
	for i := uint64(1); i <= 2; i++ {
		r, e := empty.reserve(0)
		if e != nil {
			t.Fatal(e)
		}
		if e = r.release(); e != nil || empty.used != i*reservationMetadata {
			t.Fatal("zero payload lost token metadata", e)
		}
	}
	if _, err = empty.reserve(0); err == nil {
		t.Fatal("zero payload bypassed cumulative metadata budget")
	}
	var nilWork *compilerWorkspace
	if allocations := testing.AllocsPerRun(100, func() {
		r, e := nilWork.reserve(math.MaxUint64)
		if r != nil || e != nil {
			t.Fatal("nil public path changed")
		}
	}); allocations != 0 {
		t.Fatal("nil path allocated", allocations)
	}
}

func TestCompilerWorkspaceMetadataFloor(t *testing.T) {
	w := compilerWorkspace{limit: 3*reservationMetadata + 20}
	first, err := w.reserve(7)
	if err != nil {
		t.Fatal(err)
	}
	second, err := w.reserve(7)
	if err != nil {
		t.Fatal(err)
	}
	if w.metadata != 2*reservationMetadata || w.peak != 14+2*reservationMetadata {
		t.Fatal("metadata/peak missing")
	}
	w.used = w.metadata - 1
	before := w
	if _, err = w.reserve(0); err == nil || w != before {
		t.Fatal("reserve crossed corrupt metadata floor")
	}
	if err = first.release(); err == nil || w != before || first.owner == nil {
		t.Fatal("release crossed corrupt metadata floor")
	}
	w.used = w.metadata + 6
	before = w
	if err = first.release(); err == nil || w != before {
		t.Fatal("payload consumed metadata")
	}
	w.used = w.metadata + 14
	if err = first.release(); err != nil {
		t.Fatal(err)
	}
	if err = second.release(); err != nil || w.used != w.metadata {
		t.Fatal(err)
	}
}

func TestCompilerBlobMetadataFloor(t *testing.T) {
	w := compilerWorkspace{limit: 10 * KernelBlobSize}
	c := kernelCompiler{work: &w}
	if _, err := c.reserve(2); err != nil {
		t.Fatal(err)
	}
	if _, err := c.reserve(1); err != nil {
		t.Fatal(err)
	}
	original := &c.entries[0]
	used := w.used
	for _, corrupt := range []uint64{w.metadata - 1, w.metadata + c.entriesWork.bytes - 1} {
		w.used = corrupt
		if _, err := c.reserve(1); err == nil || len(c.entries) != 3 || &c.entries[0] != original || w.used != corrupt {
			t.Fatal("in-capacity extension ignored metadata floor")
		}
	}
	w.used = used
	if _, err := c.reserve(1); err != nil {
		t.Fatal(err)
	}
}
