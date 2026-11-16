// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRouteHoldersContract drives full/shared_route.h and shared_snapshot.h
// with the product publisher's per-record holders (G019 gap 3) on the host:
// a commit while the old record is held, the drop and the third revision
// refused while it is held, the ticket RELEASE refused while a reader of
// the RETIRING record reads, a reused record's copied claim refused, a
// source pin on the RETIRING record (pinned re-claim allowed, identity
// re-claim refused) and saturation, at -O0 and -O2.
func TestRouteHoldersContract(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Fatal(err)
	}
	scenarios := []string{"commit-while-held", "drop-and-third-revision", "reader-holds-retiring", "reused-record-refused", "source-pin-on-retiring", "saturation"}
	for _, optimization := range []string{"-O0", "-O2"} {
		t.Run(optimization, func(t *testing.T) {
			binary := filepath.Join(t.TempDir(), "route-holders")
			args := []string{
				"-std=gnu11", optimization, "-Wall", "-Wextra", "-Werror",
				"-iquote", "../full", "-iquote", "../fullpolicy/bpf",
				"testdata/route_holders_contract.c", "-o", binary,
			}
			if out, err := exec.CommandContext(t.Context(), cc, args...).CombinedOutput(); err != nil {
				t.Fatalf("compile route holders fixture: %v\n%s", err, out)
			}
			for _, scenario := range scenarios {
				t.Run(scenario, func(t *testing.T) {
					out, err := exec.CommandContext(t.Context(), binary, scenario).CombinedOutput()
					if err != nil {
						t.Fatalf("route holders contract: %v\n%s", err, out)
					}
					if !strings.Contains(string(out), scenario+": PASS") {
						t.Fatalf("scenario did not run: %q", out)
					}
				})
			}
		})
	}
}

// TestRouteHoldersSourcePins pins the product-only wiring of the per-record
// holders (G019 gap 3) in the verdict object: the construct target reads a
// RETIRING record of its claim's identity, the product commands include
// opaque_real_route_drop_retired, the anchor is 176 B, and every holder
// transition updates its record's mirror.
func TestRouteHoldersSourcePins(t *testing.T) {
	read := func(path string) string {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return squashSpace(string(raw))
	}
	route := read("../full/shared_route.h")
	verdict := read("bpf/opaque_real_owner_child_candidate.bpf.c")
	product := read("bpf/opaque_real_owner_product_publisher.h")
	for name, pin := range map[string]struct {
		src, text string
		n         int
	}{
		"claim stamps the active record":             {route, "a->early_claims++;\n\tSE_ROUTE_REC_ADD(a, a->active_record, early_claims, 1);", 2},        // the fresh claim and the identity re-claim
		"release updates the record":                 {route, "a->early_claims--;\n\tSE_ROUTE_REC_ADD(a, c->record, early_claims, -1);\n\treturn 0;", 2}, // the release and the transfer
		"pin acquire updates the record":             {route, "a->source_pins++;\n\tSE_ROUTE_REC_ADD(a, claim->record, source_pins, 1);", 1},
		"pin release updates the record":             {route, "a->source_pins--;\n\tSE_ROUTE_REC_ADD(a, token->record, source_pins, -1);", 1},
		"commit checks the candidate's holders only": {route, "a->unresolved_sources || se_route_rec_held(a, record) ||", 1},
		"construct reads its claim's record": {verdict, "if ((snapshot->phase == SE_SNAPSHOT_ACTIVE ||\n\t\t\t\t     snapshot->phase ==\n\t\t\t\t\t     SE_SNAPSHOT_RETIRING) &&\n" +
			"\t\t\t\t    snapshot->serial == claim.serial &&\n\t\t\t\t    snapshot->generation == claim.generation) {", 1},
		"drop_retired command":              {product, "SEC(\"syscall\")\nint opaque_real_route_drop_retired(struct opaque_real_route_drop_request *r)", 1},
		"adoption claim updates the record": {product, "a->early_claims++;\n\t\tSE_ROUTE_REC_ADD(a, a->active_record, early_claims, 1);", 1},
	} {
		if strings.Count(pin.src, squashSpace(pin.text)) != pin.n {
			t.Errorf("gap 3 pin %q missing or duplicated", name)
		}
	}
	if !strings.Contains(strings.Join(sharedProductCommands, ","), "opaque_real_route_drop_retired") {
		t.Error("opaque_real_route_drop_retired is not a product command")
	}
}
