// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"encoding/binary"
	"fmt"
)

// Wire layouts of the product commands and maps
// (bpf/opaque_real_owner_product_publisher.h, little-endian). Each request
// is struct opaque_real_cmd_header (sharedProductRequest) followed by the
// body encoded here; the sizes below are the full request sizes the BPF
// _Static_asserts pin.
const (
	sharedProductWithdrawRequestBytes = 48  // struct opaque_real_route_withdraw_request
	sharedProductRecycleRequestBytes  = 32  // struct opaque_real_route_recycle_request
	sharedProductAdoptRequestBytes    = 40  // struct opaque_real_adopt_request
	sharedProductAdoptStateBytes      = 120 // struct opaque_real_adopt_state
	sharedProductDropRequestBytes     = 48  // struct opaque_real_route_drop_request
)

// sharedProductDropBody: {u32 slot, reserved; u64 scope, generation}, the
// RETIRING record of exactly that generation (G019 gap 3).
func sharedProductDropBody(slot uint32, scope, generation uint64) []byte {
	b := make([]byte, sharedProductDropRequestBytes-sharedProductHeaderBytes)
	binary.LittleEndian.PutUint32(b[0:4], slot)
	binary.LittleEndian.PutUint64(b[8:16], scope)
	binary.LittleEndian.PutUint64(b[16:24], generation)
	return b
}

// sharedProductWithdrawBody: {u64 cgroup, scope; u32 slot, reserved}.
func sharedProductWithdrawBody(cgroup, scope uint64, slot uint32) []byte {
	b := make([]byte, sharedProductWithdrawRequestBytes-sharedProductHeaderBytes)
	binary.LittleEndian.PutUint64(b[0:8], cgroup)
	binary.LittleEndian.PutUint64(b[8:16], scope)
	binary.LittleEndian.PutUint32(b[16:20], slot)
	return b
}

// sharedProductRecycleBody: {u32 slot, reserved}.
func sharedProductRecycleBody(slot uint32) []byte {
	b := make([]byte, sharedProductRecycleRequestBytes-sharedProductHeaderBytes)
	binary.LittleEndian.PutUint32(b[0:4], slot)
	return b
}

// sharedProductAdoptBody: {u64 cgroup; u32 slot, tid}, for verify, task,
// finish and quarantine (tid only for adopt_task).
func sharedProductAdoptBody(cgroup uint64, slot, tid uint32) []byte {
	b := make([]byte, sharedProductAdoptRequestBytes-sharedProductHeaderBytes)
	binary.LittleEndian.PutUint64(b[0:8], cgroup)
	binary.LittleEndian.PutUint32(b[8:12], slot)
	binary.LittleEndian.PutUint32(b[12:16], tid)
	return b
}

// sharedProductAdoptState is struct opaque_real_adopt_state without its lock.
type sharedProductAdoptState struct {
	Adopting, AdoptFailed, Adopted, Iterated, Bad, Leaders uint32
	Incarnation, InitTGID, Quarantined, Missed, Exiting    uint32
	Faults, Finishes, Gone, Recorded                       uint32
	Generation, Cgroup, Scope, LastCgroup                  uint64
	InitStartTicks, InitMountNS, InitRole                  uint64
}

func decodeSharedProductAdoptState(raw []byte) (sharedProductAdoptState, error) {
	if len(raw) != sharedProductAdoptStateBytes {
		return sharedProductAdoptState{}, fmt.Errorf("adopt state is %d bytes, want %d", len(raw), sharedProductAdoptStateBytes)
	}
	u32 := func(o int) uint32 { return binary.LittleEndian.Uint32(raw[o:]) }
	u64 := func(o int) uint64 { return binary.LittleEndian.Uint64(raw[o:]) }
	return sharedProductAdoptState{
		Adopting: u32(4), AdoptFailed: u32(8), Adopted: u32(12), Iterated: u32(16), Bad: u32(20), Leaders: u32(24),
		Incarnation: u32(28), InitTGID: u32(32), Quarantined: u32(36), Missed: u32(40),
		Exiting: u32(44), Faults: u32(48), Finishes: u32(52), Gone: u32(56), Recorded: u32(60),
		Generation: u64(64), Cgroup: u64(72), Scope: u64(80), LastCgroup: u64(88),
		InitStartTicks: u64(96), InitMountNS: u64(104), InitRole: u64(112),
	}, nil
}

// sharedProductRoute is the part of the 176-byte product se_route_anchor the
// publisher reads: the route tuple, the holder totals, the adoption marker
// and the per-record holder mirrors (G019 gap 3).
type sharedProductRoute struct {
	State                   SharedRouteState
	EarlyClaims, SourcePins uint32
	UnresolvedSources       uint32
	Adopting, AdoptingFault uint32
	Rec                     [2]sharedProductRouteRec
}

// sharedProductRouteRec is struct se_route_rec: the holders of one snapshot
// record (phase: the SE_SNAPSHOT_* phase the route last stamped).
type sharedProductRouteRec struct {
	Serial, Generation      uint64
	EarlyClaims, SourcePins uint32
	Phase                   uint32
}

// Snapshot record phases (SE_SNAPSHOT_*, full/shared_snapshot.h).
const (
	sharedSnapshotActive   = 3
	sharedSnapshotRetiring = 4
)

func decodeSharedProductRoute(raw []byte) (sharedProductRoute, error) {
	if len(raw) != sharedProductRouteAnchorBytes {
		return sharedProductRoute{}, fmt.Errorf("route anchor is %d bytes, want %d", len(raw), sharedProductRouteAnchorBytes)
	}
	u32 := func(o int) uint32 { return binary.LittleEndian.Uint32(raw[o:]) }
	u64 := func(o int) uint64 { return binary.LittleEndian.Uint64(raw[o:]) }
	return sharedProductRoute{
		State: SharedRouteState{
			Incarnation: u32(4), Cgroup: u64(8), Scope: u64(16), Generation: u64(24), Serial: u64(32),
			Record: u32(52), Class: u32(56), Phase: u32(60),
		},
		EarlyClaims: u32(64), SourcePins: u32(96),
		UnresolvedSources: u32(100), Adopting: u32(104), AdoptingFault: u32(108),
		Rec: [2]sharedProductRouteRec{
			{Serial: u64(112), Generation: u64(120), EarlyClaims: u32(128), SourcePins: u32(132), Phase: u32(136)},
			{Serial: u64(144), Generation: u64(152), EarlyClaims: u32(160), SourcePins: u32(164), Phase: u32(168)},
		},
	}, nil
}

// sharedFinishDetailOf derives finish's refusal detail from the slot's adopt
// state and route (design 13.1/13.5): finish snapshots the route's
// adopting_faults into the state (the route word is cleared with adopting),
// so the larger of the two is reported. A nonzero Bad with equal counts and
// no exiting task (a task whose TASK is not the adopted one) is reported as
// a generic finish refusal.
func sharedFinishDetailOf(state sharedProductAdoptState, route sharedProductRoute) sharedFinishDetail {
	return sharedFinishDetail{
		Iterated: uint64(state.Iterated), Adopted: uint64(state.Adopted),
		AdoptingFaults: uint64(max(state.Faults, route.AdoptingFault)),
		Exiting:        state.Exiting != 0,
		Bad:            uint64(state.Bad),
		ExitingCount:   uint64(state.Exiting),
	}
}
