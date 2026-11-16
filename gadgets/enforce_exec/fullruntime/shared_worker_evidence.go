// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

// The sole linker carrier. Empty means unavailable; no environment, public
// setter or runtime configuration can change the init-frozen descriptor.
var sharedWorkerEvidence string

type sharedWorkerDescriptor struct {
	scope, model    uint16
	profile         uint8
	digests         [5][32]byte // PREBUILD, inputs, profile, checks, tail proof
	bootstrap, tail uint64
}

type sharedWorkerFrozenEvidence struct {
	descriptor sharedWorkerDescriptor
	available  bool
}

// Explicit package-init dependency keeps the exact -X target reachable.
// The descriptor contains no reference to the carrier or caller graph.
var sharedWorkerFrozen = freezeSharedWorkerEvidence(sharedWorkerEvidence)

func freezeSharedWorkerEvidence(carrier string) sharedWorkerFrozenEvidence {
	d, ok := parseSharedWorkerEvidence(carrier)
	return sharedWorkerFrozenEvidence{descriptor: d, available: ok}
}

func decodeSharedWorkerDescriptor() (sharedWorkerDescriptor, bool) {
	return sharedWorkerFrozen.descriptor, sharedWorkerFrozen.available
}

// IGW1: scope0001=fresh-scope-objects-union-stage-v1; model0001=
// worker-model-v1 (ig-owned-logical-v1 accounting); profile01=raw-empty,
// profile02=raw-greenteagc on the pinned
// Go1.27.3 linux/amd64v1 CGO0 profile. Digests are references, NOT authentication.
func parseSharedWorkerEvidence(carrier string) (sharedWorkerDescriptor, bool) {
	var d sharedWorkerDescriptor
	if len(carrier) != 366 || carrier[:4] != "IGW1" {
		return d, false
	}
	scope, ok := sharedWorkerHex(carrier[4:8])
	if !ok || scope != 1 {
		return d, false
	}
	model, ok := sharedWorkerHex(carrier[8:12])
	if !ok || model != 1 {
		return d, false
	}
	profile, ok := sharedWorkerHex(carrier[12:14])
	if !ok || (profile != 1 && profile != 2) {
		return d, false
	}
	d.scope, d.model, d.profile = uint16(scope), uint16(model), uint8(profile)
	for i := range d.digests {
		var nonzero byte
		for j := range d.digests[i] {
			value, ok := sharedWorkerHex(carrier[14+i*64+j*2 : 14+i*64+j*2+2])
			if !ok {
				return sharedWorkerDescriptor{}, false
			}
			d.digests[i][j] = byte(value)
			nonzero |= byte(value)
		}
		if nonzero == 0 {
			return sharedWorkerDescriptor{}, false
		}
	}
	d.bootstrap, ok = sharedWorkerHex(carrier[334:350])
	if !ok || d.bootstrap == 0 {
		return sharedWorkerDescriptor{}, false
	}
	d.tail, ok = sharedWorkerHex(carrier[350:366])
	if !ok || d.tail == 0 || d.tail > ^uint64(0)-d.bootstrap {
		return sharedWorkerDescriptor{}, false
	}
	return d, true
}

func sharedWorkerHex(text string) (uint64, bool) {
	if len(text) == 0 || len(text) > 16 {
		return 0, false
	}
	var value uint64
	for i := range len(text) {
		c := text[i]
		var digit byte
		switch {
		case c >= '0' && c <= '9':
			digit = c - '0'
		case c >= 'a' && c <= 'f':
			digit = c - 'a' + 10
		default:
			return 0, false
		}
		value = value<<4 | uint64(digit)
	}
	return value, true
}
