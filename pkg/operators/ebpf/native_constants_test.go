// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

const nativeConstantsSource = `
const volatile unsigned int c32 = 7;
const volatile unsigned long long c64 = 7;
unsigned int rw32 = 7;
__attribute__((section("socket"), used)) int prog(void *ctx)
{
	return c32 + c64 + rw32;
}
char _license[] __attribute__((section("license"), used)) = "GPL";
`

func nativeConstantsSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	clang, err := exec.LookPath("clang")
	if err != nil {
		t.Skip("native constants test needs clang")
	}
	dir := t.TempDir()
	src, obj := filepath.Join(dir, "c.bpf.c"), filepath.Join(dir, "c.bpf.o")
	if err := os.WriteFile(src, []byte(nativeConstantsSource), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(clang, "-target", "bpf", "-O2", "-g", "-c", src, "-o", obj).CombinedOutput(); err != nil {
		t.Fatalf("clang: %v\n%s", err, out)
	}
	spec, err := ebpf.LoadCollectionSpec(obj)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

// TestNativeConstants: the native owner's 4- and 8-byte read-only constants are set
// in the collection spec before loading; an absent name is skipped; a
// constant of another size or a writable variable refuses; no key is a
// no-op.
func TestNativeConstants(t *testing.T) {
	run := func(t *testing.T, constants any) (*ebpfInstance, error) {
		t.Helper()
		i := &ebpfInstance{collectionSpec: nativeConstantsSpec(t)}
		gc := gadgetcontext.New(context.Background(), "test")
		if constants != nil {
			gc.SetVar(operators.NativeConstantsKey, constants)
		}
		return i, i.applyNativeConstants(gc)
	}
	i, err := run(t, map[string]uint32{"c32": 2, "absent": 9})
	if err != nil {
		t.Fatal(err)
	}
	var got uint32
	if err := i.collectionSpec.Variables["c32"].Get(&got); err != nil || got != 2 {
		t.Fatalf("c32 = %d (%v), want 2", got, err)
	}
	if fmt.Sprint(i.nativeResources().Constants) != "map[c32:4]" {
		t.Fatalf("reported constants %v", i.nativeResources().Constants)
	}
	i, err = run(t, map[string]any{"c32": uint32(3), "c64": uint64(1) << 40, "absent": uint64(1)})
	if err != nil {
		t.Fatal(err)
	}
	var got64 uint64
	if err := i.collectionSpec.Variables["c64"].Get(&got64); err != nil || got64 != 1<<40 {
		t.Fatalf("c64 = %d (%v), want 1<<40", got64, err)
	}
	if fmt.Sprint(i.nativeResources().Constants) != "map[c32:4 c64:8]" {
		t.Fatalf("reported constants %v", i.nativeResources().Constants)
	}
	if i, err := run(t, nil); err != nil {
		t.Fatal(err)
	} else if err := i.collectionSpec.Variables["c32"].Get(&got); err != nil || got != 7 {
		t.Fatalf("no key: c32 = %d (%v), want the compiled 7", got, err)
	}
	for name, constants := range map[string]any{
		"8-byte constant": map[string]uint32{"c64": 1},
		"writable":        map[string]uint32{"rw32": 1},
		"wrong type":      map[string]uint64{"c32": 1},
		"wrong any type":  map[string]any{"c64": uint32(1)},
		"invalid value":   map[string]any{"c32": 1},
	} {
		if _, err := run(t, constants); err == nil || !strings.Contains(err.Error(), "constant") {
			t.Errorf("%s: %v, want a refusal", name, err)
		}
	}
}

// TestNativeConstantsAdmission: native admission sees the constants the load
// sets on both paths: the preflight manifest (publishNativeResources, read
// by an owner at instantiation) and the final validator after
// applyNativeConstants; nothing is set at preflight.
func TestNativeConstantsAdmission(t *testing.T) {
	i := &ebpfInstance{collectionSpec: nativeConstantsSpec(t)}
	gc := gadgetcontext.New(context.Background(), "test")
	gc.SetVar(operators.NativeConstantsKey, map[string]any{"c32": uint32(3), "c64": uint64(5), "absent": uint32(1)})
	i.publishNativeResources(gc)
	value, _ := gc.GetVar(operators.NativeResourcesKey)
	preflight, ok := value.(*operators.NativeResources)
	if !ok || fmt.Sprint(preflight.Constants) != "map[c32:4 c64:8]" {
		t.Fatalf("preflight manifest constants %+v", value)
	}
	var got uint32
	if err := i.collectionSpec.Variables["c32"].Get(&got); err != nil || got != 7 {
		t.Fatalf("preflight set c32 = %d (%v)", got, err)
	}
	var seen map[string]uint32
	gc.SetVar(operators.NativeResourceValidatorKey, func(r *operators.NativeResources) error {
		seen = r.Constants
		if r.Constants["c64"] != 8 {
			return fmt.Errorf("c64 not set")
		}
		return nil
	})
	if err := i.applyNativeConstants(gc); err != nil {
		t.Fatal(err)
	}
	if err := i.validateNativeResources(gc); err != nil || fmt.Sprint(seen) != "map[c32:4 c64:8]" {
		t.Fatalf("final admission: %v, constants %v", err, seen)
	}
	if err := i.collectionSpec.Variables["c32"].Get(&got); err != nil || got != 3 {
		t.Fatalf("load c32 = %d (%v), want 3", got, err)
	}
	// Without the key, admission sees no constants and can refuse.
	j := &ebpfInstance{collectionSpec: nativeConstantsSpec(t)}
	bare := gadgetcontext.New(context.Background(), "test")
	j.publishNativeResources(bare)
	value, _ = bare.GetVar(operators.NativeResourcesKey)
	if r := value.(*operators.NativeResources); r.Constants != nil {
		t.Fatalf("constants without the key: %v", r.Constants)
	}
}
