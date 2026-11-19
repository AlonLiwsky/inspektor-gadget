// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import "testing"

func TestObservationContract(t *testing.T) {
	tests := []struct {
		name                string
		policy              samplePolicy
		target              string
		errno, exit, signal int
		want                bool
	}{
		{"strict deny EPERM", liveStrict, "denied", 1, 100, 0, true},
		{"strict denied success fails", liveStrict, "denied", 0, 0, 0, false},
		{"strict deny EACCES fails", liveStrict, "denied", 13, 100, 0, false},
		{"live allowed proves recovery", liveStrict, "allowed", 0, 0, 0, true},
		{"never-moved mutant fails", liveStrict, "allowed", 1, 100, 0, false},
		{"fence denies otherwise allowed", fencedStrict, "allowed", 1, 100, 0, true},
		{"fence hole fails", fencedStrict, "allowed", 0, 0, 0, false},
		{"audit denied path allowed", allowAll, "denied", 0, 0, 0, true},
		{"audit blocking fails", allowAll, "denied", 1, 100, 0, false},
		{"transition may fence allowed", transitionStrict, "allowed", 1, 100, 0, true},
		{"transition may permit allowed", transitionStrict, "allowed", 0, 0, 0, true},
		{"transition never permits denied", transitionStrict, "denied", 0, 0, 0, false},
		{"observer failure is not denial", fencedStrict, "denied", 1, 101, 0, false},
		{"signal is not a verdict", fencedStrict, "denied", 0, -1, 9, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := observation{Target: tt.target, Errno: tt.errno, Exit: tt.exit, Signal: tt.signal, Start: 1, End: 2}
			if got := checkObservation(r, tt.policy) == nil; got != tt.want {
				t.Fatalf("accepted=%v want=%v", got, tt.want)
			}
		})
	}
}
