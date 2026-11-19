// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"errors"
	"reflect"
	"testing"
	"unsafe"
)

func validatorScratchBytes(t *testing.T, p *KernelProgram) uint64 {
	t.Helper()
	h := mustDecode[KernelHeader](t, p, 0)
	return uint64(len(p.Entries))*uint64(unsafe.Sizeof(false)) + uint64(h.PolicyCount)*uint64(unsafe.Sizeof(KernelPolicy{}))
}

func TestValidatorScratchBoundary(t *testing.T) {
	p := denseValidatorFixture(t)
	before := cloneKernel(p)
	payload := validatorScratchBytes(t, p)
	w := compilerWorkspace{limit: payload + reservationMetadata - 1}
	if err := validateKernelProgram(p, &w); !errors.Is(err, errWorkspaceLimit) || w.used != 0 || w.metadata != 0 {
		t.Fatal("scratch limit refusal changed accounting", err, w)
	}
	if !reflect.DeepEqual(p, before) {
		t.Fatal("refusal changed input")
	}
	w.limit++
	if err := validateKernelProgram(p, &w); err != nil {
		t.Fatal(err)
	}
	if w.used != reservationMetadata || w.metadata != reservationMetadata || w.peak != payload+reservationMetadata {
		t.Fatal("scratch lifetime accounting", w)
	}
	if !reflect.DeepEqual(p, before) {
		t.Fatal("validation changed input")
	}
}

func TestValidatorScratchInvalidHeaderBeforeReservation(t *testing.T) {
	p := denseValidatorFixture(t)
	mutateEntry(t, p, 0, func(h *KernelHeader) { h.PolicyCount = MaxPolicies + 1 })
	w := compilerWorkspace{limit: 0}
	want := ValidateKernelProgram(p)
	got := validateKernelProgram(p, &w)
	if got == nil || want == nil || got.Error() != want.Error() || w.used != 0 || w.metadata != 0 {
		t.Fatal("invalid header reached scratch reservation", got, w)
	}
}

func TestValidatorScratchFailureAndRepeatedCalls(t *testing.T) {
	p := denseValidatorFixture(t)
	w := compilerWorkspace{limit: validatorScratchBytes(t, p) + 3*reservationMetadata}
	p.Rules[1].Name = p.Rules[0].Name
	for i := uint64(1); i <= 3; i++ {
		err := validateKernelProgram(p, &w)
		if err == nil || err.Error() != "duplicate rule name" {
			t.Fatal("validation error changed", err)
		}
		if w.used != i*reservationMetadata || w.metadata != i*reservationMetadata {
			t.Fatal("failed validation retained payload/refunded metadata", w)
		}
	}
	if err := validateKernelProgram(p, &w); !errors.Is(err, errWorkspaceLimit) || w.metadata != 3*reservationMetadata {
		t.Fatal("cumulative token records ignored", err)
	}
}

func TestValidatorScratchSharesExistingBlobAllowance(t *testing.T) {
	p := denseValidatorFixture(t)
	payload := validatorScratchBytes(t, p)
	w := compilerWorkspace{limit: 2*KernelBlobSize + payload + 2*reservationMetadata}
	c := kernelCompiler{work: &w}
	if _, err := c.reserve(2); err != nil {
		t.Fatal(err)
	}
	blobCharge := w.used
	if err := validateKernelProgram(p, &w); err != nil {
		t.Fatal(err)
	}
	if w.used != blobCharge+reservationMetadata || w.peak != w.limit {
		t.Fatal("scratch did not overlap existing Blob charge", w)
	}
	if err := c.entriesWork.release(); err != nil || w.used != 2*reservationMetadata {
		t.Fatal("scratch consumed Blob ownership", err)
	}
}

func TestValidatorScratchRefusalAllocationScope(t *testing.T) {
	p := denseValidatorFixture(t)
	baseline := testing.AllocsPerRun(50, func() {
		// Measure the actual typed prerequisite used by the validator, not the
		// unrestricted generic compatibility codec (which still allocates).
		if decodeKernelHeader(p.Entries[0]).Generation == 0 {
			t.Fatal("invalid fixture header")
		}
	})
	w := compilerWorkspace{}
	refused := testing.AllocsPerRun(50, func() {
		if err := validateKernelProgram(p, &w); !errors.Is(err, errWorkspaceLimit) {
			t.Fatal(err)
		}
	})
	t.Logf("existing header prerequisite allocations=%g; scratch refusal allocations=%g", baseline, refused)
	if refused != baseline || w.used != 0 || w.metadata != 0 {
		t.Fatal("scratch/token/error allocation occurred on refusal")
	}
}

func TestValidatorScratchEarlyFailureRelease(t *testing.T) {
	p := denseValidatorFixture(t)
	mutateEntry(t, p, 0, func(h *KernelHeader) { h.ContainerRef = uint32(len(p.Entries)) })
	before := cloneKernel(p)
	w := compilerWorkspace{limit: validatorScratchBytes(t, p) + reservationMetadata}
	want := ValidateKernelProgram(p)
	got := validateKernelProgram(p, &w)
	if got == nil || want == nil || got.Error() != want.Error() || w.used != reservationMetadata || !reflect.DeepEqual(p, before) {
		t.Fatal("early validation failure did not release scratch/preserve input", got, w)
	}
}
