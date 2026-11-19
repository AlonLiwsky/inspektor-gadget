// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build !enforce_exec_shared_qualification

package fullruntime

import (
	"context"
	"errors"
	"testing"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
)

// TestSharedProductBuildIgnoresQualification: a binary without the
// enforce_exec_shared_qualification tag never enables the candidate path:
// the opt-in is ignored, nothing runs and StartNode stays unavailable.
func TestSharedProductBuildIgnoresQualification(t *testing.T) {
	if sharedQualificationBuild {
		t.Fatal("untagged build enables shared qualification")
	}
	runs := 0
	run := func(context.Context, gadgetcontext.Option) (func(context.Context) error, <-chan error, error) {
		runs++
		return func(context.Context) error { return nil }, make(chan error), nil
	}
	n, err := StartNode(WithSharedNodeQualification(t.Context(), SharedNodeQualification{Run: run}), sharedQualifiedConfig())
	if n != nil || !errors.Is(err, ErrSharedNativeUnavailable) || runs != 0 {
		t.Fatalf("product StartNode: node=%v err=%v runs=%d", n, err, runs)
	}
}
