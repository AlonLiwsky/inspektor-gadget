// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"maps"
	"os"
	"slices"
	"strings"
	"testing"
	"unicode"

	"github.com/cilium/ebpf"
)

// TestSharedProductManifestSets: the generated sets are sorted, unique and
// non-empty, carry every product command and the reaper command, and none
// of the diagnostic-twin, recovery or pool-reaper resources.
func TestSharedProductManifestSets(t *testing.T) {
	for name, set := range map[string][]string{"maps": sharedProductManifestMaps, "programs": sharedProductManifestPrograms} {
		if len(set) == 0 || !slices.IsSorted(set) || len(slices.Compact(slices.Clone(set))) != len(set) {
			t.Fatalf("%s: %d entries, sorted %v, want non-empty sorted unique", name, len(set), slices.IsSorted(set))
		}
	}
	for _, name := range append(slices.Clone(sharedProductCommands), "opaque_real_reap") {
		if !slices.Contains(sharedProductManifestPrograms, name) {
			t.Errorf("product command %s missing from the manifest", name)
		}
	}
	for _, name := range sharedProductForbiddenMaps {
		if slices.Contains(sharedProductManifestMaps, name) {
			t.Errorf("diagnostic-twin map %s in the product manifest", name)
		}
	}
	for _, name := range slices.Concat(sharedProductManifestMaps, sharedProductManifestPrograms) {
		if strings.HasPrefix(name, "se_rm_") || strings.HasPrefix(name, "se_pool_reap") {
			t.Errorf("recovery or pool-reaper resource %s in the product manifest", name)
		}
	}
}

// TestSharedProductManifestMatchesObjects (plan 3.8): with
// IG_ENFORCE_EXEC_PRODUCT_OBJECTS (comma or white-space separated object
// paths) every object carries exactly the generated name sets and its
// sha256 is a pinned product ELF of exactly one kernel.
func TestSharedProductManifestMatchesObjects(t *testing.T) {
	objects := strings.FieldsFunc(os.Getenv("IG_ENFORCE_EXEC_PRODUCT_OBJECTS"), func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(objects) == 0 {
		t.Skip("set IG_ENFORCE_EXEC_PRODUCT_OBJECTS to the product objects")
	}
	for _, path := range objects {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(data))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if got := slices.Sorted(maps.Keys(spec.Maps)); !slices.Equal(got, sharedProductManifestMaps) {
			t.Errorf("%s: maps %v, manifest %v", path, got, sharedProductManifestMaps)
		}
		if got := slices.Sorted(maps.Keys(spec.Programs)); !slices.Equal(got, sharedProductManifestPrograms) {
			t.Errorf("%s: programs %v, manifest %v", path, got, sharedProductManifestPrograms)
		}
		sum := sha256.Sum256(data)
		if digest := hex.EncodeToString(sum[:]); !sharedProductObject(digest) {
			t.Errorf("%s: sha256 %s is not a product object", path, digest)
		}
	}
}
