// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullpolicy

import (
	"math"
	"testing"
)

func TestLimitedEntrypointsUseActualModels(t *testing.T) {
	p := Policy{}
	want, d, e := compileSharedPolicyModel(p, math.MaxUint64)
	got, actual, err := CompileSharedPolicyLimited(p, math.MaxUint64)
	if got != want || actual != d || err != e { //nolint:errorlint // Exact compiler static diagnostic identity, not wrapped compatibility.
		t.Fatal("limited compiler must forward actual model result")
	}
	_, d, err = CompileSharedPolicyLimited(p, 0)
	if d != 0 || err == nil {
		t.Fatal("unadmitted attempt")
	}
	_, wantD, wantErr := newSharedSnapshotModel(1, 1, "app", nil, math.MaxUint64)
	_, gotD, gotErr := NewSharedSnapshotLimited(1, 1, "app", nil, math.MaxUint64)
	if gotD != wantD || gotErr != wantErr { //nolint:errorlint // Exact compiler static diagnostic identity.
		t.Fatal("limited union must forward actual model result")
	}
}
