// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestCompleteWire(t *testing.T) {
	good := sample{Argv: argvResult{ABI: 1, Status: 1, Argc: 1, Bytes: 2, Complete: 1}}
	good.Argv.Data[0] = 'x'
	if err := validateWire(good, []string{"x"}, false); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*sample){
		func(s *sample) { s.Argv.Data[2] = 1 },
		func(s *sample) { s.Argv.Offsets[1] = 1 },
		func(s *sample) { s.Argv.Error = -1 },
	} {
		bad := good
		mutate(&bad)
		if validateWire(bad, []string{"x"}, false) == nil {
			t.Fatal("accepted dirty success wire")
		}
	}
	rejected := sample{Result: -int32(unix.E2BIG), Argv: argvResult{ABI: 1, Status: 2, Error: -int32(unix.E2BIG)}}
	if err := validateWire(rejected, nil, true); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*sample){
		func(s *sample) { s.Argv.Error = 0 },
		func(s *sample) { s.Argv.Data[4095] = 1 },
		func(s *sample) { s.Argv.Offsets[63] = 1 },
	} {
		bad := rejected
		mutate(&bad)
		if validateWire(bad, nil, true) == nil {
			t.Fatal("accepted dirty rejection wire")
		}
	}
}
