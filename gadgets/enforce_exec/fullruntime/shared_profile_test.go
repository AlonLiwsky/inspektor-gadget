// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package fullruntime

import (
	"math"
	"testing"
)

func sharedTestProfile() SharedProfile {
	return SharedProfile{Version: 1, CandidateBytes: 1 << 20, Bindings: 2, PolicySlots: [4]uint64{4, 2, 1, 1}, Tasks: 20000, Scratch: 128, InodeFacts: 1024, AcceptedUIDs: 128, Images: 2, CompileBytes: 8 << 20, CompileConcurrency: 2, TelemetryBytes: 4096, RolloutBytes: 4096, PossibleCPUs: 64, PerBinding: SharedQuota{Tasks: 10000, Scratch: 64, InodeFacts: 512, AcceptedUIDs: 64, Images: 1}}
}

func TestSharedProfileAdmission(t *testing.T) {
	p := sharedTestProfile()
	a, err := p.Validate()
	if err != nil {
		t.Fatal(err)
	}
	if a.Snapshots != 4 || a.PinTickets != 32 || a.ArenaCells != 4*256+2*1024+4096+16384 || a.ArenaBytes != a.ArenaCells*288 {
		t.Fatalf("wrong geometry: %+v", a)
	}
	cases := []func(*SharedProfile){func(p *SharedProfile) { p.Version = 0 }, func(p *SharedProfile) { p.Bindings = 0 }, func(p *SharedProfile) { p.PossibleCPUs = 65 }, func(p *SharedProfile) { p.CompileBytes = 0 }, func(p *SharedProfile) { p.PerBinding.Tasks++ }, func(p *SharedProfile) { p.PolicySlots[3] = math.MaxUint64 }, func(p *SharedProfile) { p.Bindings = math.MaxUint64 }, func(p *SharedProfile) { p.RolloutBytes = 0 }}
	for i, mutate := range cases {
		q := p
		mutate(&q)
		if _, err := q.Validate(); err == nil {
			t.Fatalf("invalid profile %d admitted", i)
		}
	}
}

func TestSharedArenaRanges(t *testing.T) {
	p := sharedTestProfile()
	next := uint64(0)
	for class := uint32(0); class < 4; class++ {
		for slot := uint64(0); slot < p.PolicySlots[class]; slot++ {
			base, cells, err := p.ObjectRange(class, slot)
			if err != nil || base != next {
				t.Fatalf("overlap/hole: %d %d %v", base, next, err)
			}
			next += cells
		}
	}
	a, err := p.Validate()
	if err != nil || next != a.ArenaCells {
		t.Fatal("range end", err)
	}
	for _, index := range [][2]uint64{{4, 0}, {0, p.PolicySlots[0]}} {
		if _, _, err := p.ObjectRange(uint32(index[0]), index[1]); err == nil {
			t.Fatal("invalid range")
		}
	}
}

// Pool reservations include all live key cells: active, candidate and retiring.
// Two snapshot records may share immutable evidence; Images is not handle count.
func TestSharedImageKeyCellReservations(t *testing.T) {
	p := sharedTestProfile()
	p.Images = 65538
	p.PerBinding.Images = 32769
	a, err := p.Validate()
	if err != nil || a.Snapshots != 4 {
		t.Fatalf("key pool confused with handles: %+v %v", a, err)
	}
	for name, mutate := range map[string]func(*SharedProfile){
		"missing pool":   func(p *SharedProfile) { p.Images = 0 },
		"missing quota":  func(p *SharedProfile) { p.PerBinding.Images = 0 },
		"pool overflow":  func(p *SharedProfile) { p.Images = uint64(math.MaxUint32) + 1 },
		"quota overflow": func(p *SharedProfile) { p.PerBinding.Images = math.MaxUint64 },
		"overreserved":   func(p *SharedProfile) { p.PerBinding.Images++ },
	} {
		t.Run(name, func(t *testing.T) {
			q := p
			mutate(&q)
			if _, err := q.Validate(); err == nil {
				t.Fatal("invalid key reservation accepted")
			}
		})
	}
}
