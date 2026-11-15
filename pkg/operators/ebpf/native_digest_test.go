// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// instantiateLayer runs the real image operator entry point on program as
// one eBPF layer. The bytes are not an ELF, so construction fails after the
// digest is recorded; the result is ignored.
func instantiateLayer(t *testing.T, gc *gadgetcontext.GadgetContext, program []byte) {
	t.Helper()
	desc := content.NewDescriptorFromBytes("application/vnd.gadget.ebpf.program.v1+binary", program)
	store := memory.New()
	if err := store.Push(gc.Context(), desc, bytes.NewReader(program)); err != nil {
		t.Fatal(err)
	}
	if instance, err := (&ebpfOperator{}).InstantiateImageOperator(gc, store, desc, nil); instance != nil || err == nil {
		t.Fatalf("non-ELF layer constructed: %v %v", instance, err)
	}
}

// TestNativeProgramDigestOnlyForNativeOwners: the layer sha256 is recorded
// for a native owner only, and a second layer invalidates it.
func TestNativeProgramDigestOnlyForNativeOwners(t *testing.T) {
	program := []byte("product object bytes")
	sum := sha256.Sum256(program)
	want := hex.EncodeToString(sum[:])

	ordinary := newResolverGadgetCtx(t, nil)
	instantiateLayer(t, ordinary, program)
	if v, ok := ordinary.GetVar(operators.NativeProgramDigestKey); ok {
		t.Fatalf("ordinary gadget got a program digest %v", v)
	}

	notTrue := newResolverGadgetCtx(t, nil)
	notTrue.SetVar(operators.NativeOwnerRequiredKey, "true")
	instantiateLayer(t, notTrue, program)
	if v, ok := notTrue.GetVar(operators.NativeProgramDigestKey); ok {
		t.Fatalf("non-boolean owner marker got a program digest %v", v)
	}

	owner := newResolverGadgetCtx(t, nil)
	owner.SetVar(operators.NativeOwnerRequiredKey, true)
	instantiateLayer(t, owner, program)
	if v, _ := owner.GetVar(operators.NativeProgramDigestKey); v != want {
		t.Fatalf("native owner digest %v, want %s", v, want)
	}
	instantiateLayer(t, owner, []byte("second layer"))
	if v, ok := owner.GetVar(operators.NativeProgramDigestKey); !ok || v != "" {
		t.Fatalf("second layer left digest %v (set %v), want sticky empty", v, ok)
	}
	instantiateLayer(t, owner, program)
	if v, _ := owner.GetVar(operators.NativeProgramDigestKey); v != "" {
		t.Fatalf("third layer restored digest %v", v)
	}
}
