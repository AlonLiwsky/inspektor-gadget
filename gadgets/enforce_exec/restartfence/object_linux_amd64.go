// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package restartfence

import (
	"bytes"
	_ "embed"
)

//go:generate env FENCE_ARCH=amd64 bash bpf/build.sh bpf/fence_amd64.elf

//go:embed bpf/fence_amd64.elf
var fenceObject []byte

// Object returns the embedded, separately built fence ELF for this
// architecture. The caller receives a copy; it cannot change the embedded
// object subsequently returned to a different caller.
func Object() ([]byte, error) {
	return bytes.Clone(fenceObject), nil
}
