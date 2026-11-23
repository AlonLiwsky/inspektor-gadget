// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import "os"

// SharedSkipLSMListGateEnv is the TEST-ONLY knob of the canary negative
// test: the qualified candidate's kernel admission skips its LSM-list check
// (the startup canary must then refuse a kernel without the bpf LSM by
// itself). Qualification builds only.
const SharedSkipLSMListGateEnv = "IG_ENFORCE_EXEC_SKIP_LSM_LIST_GATE"

func init() {
	sharedSkipLSMListGate = func() bool { return os.Getenv(SharedSkipLSMListGateEnv) == "1" }
}
