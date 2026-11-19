// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// TestSharedFactStatsCells pins the witness cells against the kernel
// collector's enum (full/shared_pass_facts.h) and the map size against the
// verdict source.
func TestSharedFactStatsCells(t *testing.T) {
	header := squashSpace(mustRead(t, "../full/shared_pass_facts.h"))
	names := []string{
		"SE_PF_PASSES = 0", "SE_PF_TARGET_MISSING", "SE_PF_TARGET_PATH", "SE_PF_TARGET_TOO_LONG",
		"SE_PF_TARGET_OUTSIDE_ROOT", "SE_PF_ACTOR_MISSING", "SE_PF_ACTOR_PATH", "SE_PF_ACTOR_OUTSIDE_ROOT",
		"SE_PF_FS_UNKNOWN", "SE_PF_STDIN_UNKNOWN", "SE_PF_ANCESTOR_UNKNOWN", "SE_PF_ANCESTOR_BOUNDARY",
		"SE_PF_ANCESTOR_TRUNCATED", "SE_PF_ROOT_MISMATCH", "SE_PF_TARGET_MEMFD", "SE_PF_PATH_UTF8",
		"SE_PF_ACTOR_DELETED", "SE_PF_STATS",
	}
	if len(names) != FactStats+1 {
		t.Fatalf("%d names for %d cells", len(names), FactStats)
	}
	at := 0
	for i, name := range names {
		next := strings.Index(header[at:], squashSpace(name))
		if next < 0 {
			t.Fatalf("cell %d %s missing or out of order in shared_pass_facts.h", i, name)
		}
		at += next + len(squashSpace(name))
	}
	source := squashSpace(mustRead(t, "bpf/opaque_real_owner_child_candidate.bpf.c"))
	if !strings.Contains(source, squashSpace(fmt.Sprintf("__uint(max_entries, %d);\n\t__uint(map_flags, BPF_F_RDONLY);\n\t__type(key, __u32);\n\t__type(value, __u64);\n} %s SEC(\".maps\");", FactStats, FactStatsMap))) {
		t.Fatalf("%s is not a %d-cell RDONLY u64 array in the verdict source", FactStatsMap, FactStats)
	}
	if !strings.Contains(source, squashSpace(fmt.Sprintf("} %s SEC(\".maps\");", sharedFactWitnessMap))) {
		t.Fatalf("witness %s not found", sharedFactWitnessMap)
	}
	// The witness is test-only: refused in a product object by the source.
	if !strings.Contains(source, squashSpace("#if defined(ENFORCE_EXEC_POOL_OPAQUE_PASS_FACTS_WITNESS) && \\\n\tdefined(SE_PRODUCT_NO_TEST_RUN) && \\\n\t!defined(SE_PRODUCT_DIAGNOSTIC_TWIN)\n#error")) {
		t.Fatal("the fact witness is not refused in a product object")
	}
}

// TestSharedFactNodeHealth: the fact witness of an object with the per-pass
// facts is reported by FactHealth; unknown counts never degrade the node;
// a backwards or unreadable witness is a sticky fault of Ready and StopNode;
// a malformed witness refuses startup; an object without it has none.
func TestSharedFactNodeHealth(t *testing.T) {
	sharedEnableQualification(t)
	start := func(t *testing.T, manifest *operators.NativeResources) (*NodeEnforcer, *sharedFakeNativeHost, error) {
		host := &sharedFakeNativeHost{manifest: manifest}
		q := host.qualification(nil)
		q.newProductPublisher = func(operators.GadgetContext, *operators.NativeResources) (SharedRoutePublisher, error) {
			return newSharedFakePublisher(), nil
		}
		n, err := StartNode(WithSharedNodeQualification(t.Context(), q), sharedQualifiedConfig())
		return n, host, err
	}

	t.Run("product object", func(t *testing.T) {
		m := sharedProductFakeManifest()
		if m.Maps[FactStatsMap] != sharedFactStats {
			t.Fatalf("product manifest %s %+v", FactStatsMap, m.Maps[FactStatsMap])
		}
		n, host, err := start(t, m)
		if err != nil {
			t.Fatal(err)
		}
		host.setFacts(func(c *[FactStats]uint64, _ *error) {
			c[FactPasses], c[FactTargetTooLong], c[FactTargetOutsideRoot], c[FactAncestorUnknown] = 9, 1, 2, 3
		})
		got, err := n.FactHealth()
		if err != nil || got.Passes != 9 || got.TargetTooLong != 1 || got.TargetOutsideRoot != 2 || got.AncestorUnknown != 3 {
			t.Fatalf("FactHealth %+v, %v", got, err)
		}
		// Policy-UNKNOWN counts are reported, never a node fault.
		if err := n.Ready(host.gc); !errors.Is(err, ErrSharedNativeUnavailable) || strings.Contains(err.Error(), "fact witness") {
			t.Fatalf("Ready with unknown facts: %v", err)
		}
		host.setFacts(func(c *[FactStats]uint64, _ *error) { c[FactPasses] = 3 })
		if err := n.Ready(host.gc); err == nil || !strings.Contains(err.Error(), "fact witness unknown") || !strings.Contains(err.Error(), "backwards") {
			t.Fatalf("backwards Ready: %v", err)
		}
		host.setFacts(func(c *[FactStats]uint64, _ *error) { c[FactPasses] = 100 })
		if _, err := n.FactHealth(); err == nil || !strings.Contains(err.Error(), "backwards") {
			t.Fatalf("the fault is sticky: %v", err)
		}
		if err := n.StopNode(t.Context()); err == nil || !strings.Contains(err.Error(), "fact witness unknown") {
			t.Fatalf("StopNode: %v, want the witness fault", err)
		}
	})

	t.Run("unreadable witness", func(t *testing.T) {
		n, host, err := start(t, sharedProductFakeManifest())
		if err != nil {
			t.Fatal(err)
		}
		host.setFacts(func(_ *[FactStats]uint64, e *error) { *e = errors.New("lookup failed") })
		if err := n.Ready(host.gc); err == nil || !strings.Contains(err.Error(), "lookup failed") {
			t.Fatalf("unreadable Ready: %v", err)
		}
		_ = n.StopNode(t.Context())
	})

	t.Run("malformed witness refuses startup", func(t *testing.T) {
		m := sharedProductFakeManifest()
		w := m.Maps[FactStatsMap]
		w.Flags = 0
		m.Maps[FactStatsMap] = w
		n, _, err := start(t, m)
		if n != nil || err == nil || !strings.Contains(err.Error(), FactStatsMap) {
			t.Fatalf("malformed fact witness: node=%v err=%v", n, err)
		}
	})

	t.Run("object without facts", func(t *testing.T) {
		n, _, err := start(t, sharedCandidateFakeManifest())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = n.StopNode(t.Context()) }()
		if _, err := n.FactHealth(); !errors.Is(err, ErrSharedNativeUnavailable) {
			t.Fatalf("FactHealth without the facts: %v", err)
		}
	})
}
