// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build !amd64

package restartfence

import (
	"fmt"
	"runtime"
)

// Object refuses to attest an embedded fence on an unqualified architecture.
func Object() ([]byte, error) {
	return nil, fmt.Errorf("no embedded exec restart fence for linux/%s", runtime.GOARCH)
}
