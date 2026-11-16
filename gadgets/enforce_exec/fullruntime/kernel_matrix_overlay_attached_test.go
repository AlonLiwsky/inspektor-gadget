// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"errors"
	"os"
	"os/exec"
	"testing"
)

// TestSharedImageOverlayLayoutLiveModuleBTF asserts that on an exact matrix
// kernel with the overlay module loaded, the vmlinux digest + overlay module
// BTF shape selects the expected layout (6.12 realfile, 6.18 ovl_file) and
// that the production constants carry it. Gate: IG_SHARED_OVL_BTF=1 (VM).
func TestSharedImageOverlayLayoutLiveModuleBTF(t *testing.T) {
	if os.Getenv("IG_SHARED_OVL_BTF") != "1" {
		t.Skip("set IG_SHARED_OVL_BTF=1 on an exact-kernel VM with the overlay module loaded")
	}
	digest, err := kernelBTFDigest()
	if err != nil {
		t.Fatal(err)
	}
	release := sharedCandidateKernelBTF[digest]
	want := sharedImageOverlayLayouts[release]
	if want == sharedImageOverlayLayoutUnset {
		t.Fatalf("kernel BTF %s outside the shared candidate matrix", digest)
	}
	got, err := liveSharedImageOverlayLayout()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("%s: live layout %d, want %d", release, got, want)
	}
	constants, err := sharedImageOverlayConstants()
	if err != nil {
		t.Fatal(err)
	}
	if constants[sharedImageOverlayLayoutConstant] != want {
		t.Fatalf("constants layout %v, want %d", constants[sharedImageOverlayLayoutConstant], want)
	}
	t.Logf("kernel %s vmlinux BTF %s overlay module BTF shape -> layout %d", release, digest, got)
}

// TestSharedImageOverlayAutoloadLive (IG_SHARED_OVL_AUTOLOAD=1, root, no
// overlay mounts): with overlay.ko unloaded, the layout is unavailable and a
// FromImage build is refused with that reason while the node health is
// Degraded; the fsopen autoload then loads the module and sets the layout.
func TestSharedImageOverlayAutoloadLive(t *testing.T) {
	if os.Getenv("IG_SHARED_OVL_AUTOLOAD") != "1" {
		t.Skip("set IG_SHARED_OVL_AUTOLOAD=1 as root on an exact-kernel VM without overlay mounts")
	}
	if out, err := exec.Command("rmmod", "overlay").CombinedOutput(); err != nil {
		t.Fatalf("rmmod overlay: %v: %s", err, out)
	}
	if _, err := os.Stat("/sys/kernel/btf/overlay"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("overlay BTF still present after rmmod: %v", err)
	}
	// Autoload disabled: the failure is recorded and surfaces.
	realLoader := overlayModuleLoader
	overlayModuleLoader = func() error { return errors.New("autoload disabled for the test") }
	c, err := sharedImageOverlayConstants()
	overlayModuleLoader = realLoader
	if err != nil || c[sharedImageOverlayLayoutConstant] != sharedImageOverlayLayoutUnset {
		t.Fatalf("unloaded constants %v err %v", c, err)
	}
	x := &productImageIndex{resolver: noopImageResolver{}, overlayUnavailable: sharedImageOverlayUnavailable}
	_, _, berr := x.build(t.Context(), 0, 0, SharedInitIdentity{ContainerID: "c"})
	if !errors.Is(berr, ErrSharedImageIndexUnavailable) {
		t.Fatalf("build with overlay unloaded: %v", berr)
	}
	// Degraded, never startup-fatal: the reason is recorded for
	// NodeEnforcer.Ready (overlayDegraded), the live health stays clean.
	if sharedImageOverlayUnavailable() == nil {
		t.Fatal("no overlay-unavailable reason with overlay unloaded")
	}
	if herr := (sharedLiveHealth{image: healthyImage{}}).check(); herr != nil {
		t.Fatalf("startup health fails with overlay unloaded: %v", herr)
	}
	t.Logf("unloaded: build refused: %v", berr)
	// Real autoload.
	c, err = sharedImageOverlayConstants()
	if err != nil || c[sharedImageOverlayLayoutConstant] == sharedImageOverlayLayoutUnset {
		t.Fatalf("autoload did not set the layout: %v err %v", c, err)
	}
	if sharedImageOverlayUnavailable() != nil {
		t.Fatal("unavailable reason not cleared after autoload")
	}
	t.Logf("autoload set layout %v", c[sharedImageOverlayLayoutConstant])
}
