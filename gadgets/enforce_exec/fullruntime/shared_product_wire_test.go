// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"encoding/binary"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// TestSharedProductWireMatchesBPF pins the Go encodings to the BPF header's
// _Static_assert sizes, so a layout change on either side fails here.
func TestSharedProductWireMatchesBPF(t *testing.T) {
	src, err := os.ReadFile("bpf/opaque_real_owner_product_publisher.h")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]int{
		"opaque_real_cmd_header":             sharedProductHeaderBytes,
		"opaque_real_route_withdraw_request": sharedProductWithdrawRequestBytes,
		"opaque_real_route_recycle_request":  sharedProductRecycleRequestBytes,
		"opaque_real_adopt_request":          sharedProductAdoptRequestBytes,
		"se_route_anchor":                    sharedProductRouteAnchorBytes,
		"opaque_real_policy_stage_request":   sharedProductStageRequestBytes,
		"opaque_real_route_publish_request":  sharedProductPublishRequestBytes,
		"opaque_real_adopt_state":            sharedProductAdoptStateBytes,
		"opaque_real_route_drop_request":     sharedProductDropRequestBytes,
	} {
		m := regexp.MustCompile(`_Static_assert\(sizeof\(struct ` + name + `\) == (\d+)`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("no size assert for %s", name)
		}
		if got, _ := strconv.Atoi(string(m[1])); got != want {
			t.Errorf("%s: BPF %d bytes, Go %d", name, got, want)
		}
	}
	for _, field := range []string{"adopting, adopt_failed, adopted, iterated, bad, leaders,", "incarnation, init_tgid, quarantined, missed, exiting, faults,", "finishes, gone, recorded;", "__u64 generation, cgroup, scope, last_cgroup, init_start_ticks,", "init_mntns, init_role;"} {
		if !regexp.MustCompile(regexp.QuoteMeta(field)).Match(src) {
			t.Errorf("opaque_real_adopt_state layout changed: %q", field)
		}
	}
	if got := len(sharedProductWithdrawBody(1, 2, 3)) + sharedProductHeaderBytes; got != sharedProductWithdrawRequestBytes {
		t.Errorf("withdraw request %d", got)
	}
	if got := len(sharedProductRecycleBody(1)) + sharedProductHeaderBytes; got != sharedProductRecycleRequestBytes {
		t.Errorf("recycle request %d", got)
	}
	// G019 gap 3: {u32 slot, reserved; u64 scope, generation}.
	if drop := sharedProductDropBody(1, 0xabc, 7); len(drop)+sharedProductHeaderBytes != sharedProductDropRequestBytes ||
		binary.LittleEndian.Uint32(drop) != 1 || binary.LittleEndian.Uint32(drop[4:]) != 0 ||
		binary.LittleEndian.Uint64(drop[8:]) != 0xabc || binary.LittleEndian.Uint64(drop[16:]) != 7 {
		t.Errorf("drop_retired body %x", drop)
	}
	if !regexp.MustCompile(`__u32 slot, reserved;\s+__u64 scope, generation;\s+\};\s+_Static_assert\(sizeof\(struct opaque_real_route_drop_request\)`).Match(src) {
		t.Error("opaque_real_route_drop_request layout changed")
	}
	body := sharedProductAdoptBody(0x1122334455667788, 1, 4242)
	if len(body)+sharedProductHeaderBytes != sharedProductAdoptRequestBytes ||
		binary.LittleEndian.Uint64(body) != 0x1122334455667788 || binary.LittleEndian.Uint32(body[8:]) != 1 || binary.LittleEndian.Uint32(body[12:]) != 4242 {
		t.Errorf("adopt body %x", body)
	}
}

func TestSharedProductStateAndRouteDecode(t *testing.T) {
	raw := make([]byte, sharedProductAdoptStateBytes)
	for i, v := range []uint32{1, 0, 3, 2, 1, 1, 9, 77, 0, 0, 1, 6, 4, 2, 5} {
		binary.LittleEndian.PutUint32(raw[4+4*i:], v)
	}
	for i, v := range []uint64{5, 11, 10, 0, 4242, 4026531999, 1} {
		binary.LittleEndian.PutUint64(raw[64+8*i:], v)
	}
	st, err := decodeSharedProductAdoptState(raw)
	want := sharedProductAdoptState{Adopting: 1, Adopted: 3, Iterated: 2, Bad: 1, Leaders: 1, Incarnation: 9, InitTGID: 77, Exiting: 1, Faults: 6, Finishes: 4, Gone: 2, Recorded: 5, Generation: 5, Cgroup: 11, Scope: 10, InitStartTicks: 4242, InitMountNS: 4026531999, InitRole: 1}
	if err != nil || st != want {
		t.Fatalf("adopt state %+v %v, want %+v", st, err, want)
	}
	if _, err := decodeSharedProductAdoptState(raw[:112]); err == nil {
		t.Fatal("short adopt state decoded")
	}
	route := make([]byte, sharedProductRouteAnchorBytes)
	binary.LittleEndian.PutUint32(route[4:], 3)
	binary.LittleEndian.PutUint64(route[8:], 11)
	binary.LittleEndian.PutUint64(route[24:], 2)
	binary.LittleEndian.PutUint32(route[56:], 2)
	binary.LittleEndian.PutUint32(route[60:], 2)
	binary.LittleEndian.PutUint32(route[104:], 1)
	binary.LittleEndian.PutUint32(route[108:], 4)
	// G019 gap 3: holder totals and the two struct se_route_rec.
	binary.LittleEndian.PutUint32(route[64:], 3)
	binary.LittleEndian.PutUint32(route[96:], 1)
	for i, rec := range []sharedProductRouteRec{{Serial: 1, Generation: 1, EarlyClaims: 2, SourcePins: 1, Phase: sharedSnapshotRetiring}, {Serial: 2, Generation: 2, EarlyClaims: 1, Phase: sharedSnapshotActive}} {
		o := 112 + 32*i
		binary.LittleEndian.PutUint64(route[o:], rec.Serial)
		binary.LittleEndian.PutUint64(route[o+8:], rec.Generation)
		binary.LittleEndian.PutUint32(route[o+16:], rec.EarlyClaims)
		binary.LittleEndian.PutUint32(route[o+20:], rec.SourcePins)
		binary.LittleEndian.PutUint32(route[o+24:], rec.Phase)
	}
	r, err := decodeSharedProductRoute(route)
	if err != nil || r.State.Incarnation != 3 || r.State.Cgroup != 11 || r.State.Generation != 2 || r.State.Class != 2 || r.Adopting != 1 || r.AdoptingFault != 4 ||
		r.EarlyClaims != 3 || r.SourcePins != 1 ||
		r.Rec != [2]sharedProductRouteRec{{Serial: 1, Generation: 1, EarlyClaims: 2, SourcePins: 1, Phase: sharedSnapshotRetiring}, {Serial: 2, Generation: 2, EarlyClaims: 1, Phase: sharedSnapshotActive}} {
		t.Fatalf("route %+v %v", r, err)
	}
	if d := sharedFinishDetailOf(st, r); d.Iterated != 2 || d.Adopted != 3 || d.AdoptingFaults != 6 || !d.Exiting || d.Bad != 1 || d.ExitingCount != 1 {
		t.Fatalf("finish detail %+v", d)
	}
	for _, short := range []int{88, 112} {
		if _, err := decodeSharedProductRoute(route[:short]); err == nil {
			t.Fatalf("%d-byte anchor decoded as the 176-byte product anchor", short)
		}
	}
}

// TestSharedProductCodesMatchBPF pins the Go command result codes to the
// header's OPAQUE_REAL_CMD_* (and recycle UNCLEAN) defines.
func TestSharedProductCodesMatchBPF(t *testing.T) {
	src, err := os.ReadFile("bpf/opaque_real_owner_product_publisher.h")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]int{
		"OPAQUE_REAL_CMD_OK": sharedProductOK, "OPAQUE_REAL_CMD_RETRY": sharedProductRetry,
		"OPAQUE_REAL_CMD_REFUSED": sharedProductRefused, "OPAQUE_REAL_CMD_LATCHED": sharedProductLatched,
		"OPAQUE_REAL_CMD_REUSED": sharedProductReused, "OPAQUE_REAL_CMD_AUTH": sharedProductAuthFailed,
		"OPAQUE_REAL_RECYCLE_UNCLEAN": sharedProductRecycleUnclean, "OPAQUE_REAL_CMD_UNARMED": sharedProductUnarmed,
	} {
		m := regexp.MustCompile(`#define ` + name + ` (\d+)`).FindSubmatch(src)
		if m == nil {
			t.Fatalf("no define for %s", name)
		}
		if got, _ := strconv.Atoi(string(m[1])); got != want {
			t.Errorf("%s: BPF %d, Go %d", name, got, want)
		}
	}
	if !regexp.MustCompile(`#define OPAQUE_REAL_CMD_INVARIANT -1`).Match(src) || sharedProductInvariant != ^uint32(0) {
		t.Error("invariant code is not -1")
	}
}
