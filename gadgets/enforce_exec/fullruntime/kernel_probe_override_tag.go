// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import "os"

// SharedProbedKernelEnv is the TEST-ONLY opt-in that lets a qualification
// build admit a kernel outside the pinned matrix on its probes
// (verifySharedProbedKernel). It exists only in binaries built with the
// enforce_exec_shared_qualification tag, which the product StartNode path
// refuses; a default build has no way to enable it. With it, a kernel
// without the bpf LSM, with ftrace off or livepatched is still refused
// (stage 1: D1's LSM-only engine has no failure frames to resolve).
const SharedProbedKernelEnv = "IG_ENFORCE_EXEC_PROBED_KERNEL"

// SharedSkipLSMListGateEnv is the TEST-ONLY knob of the canary negative test:
// with the probed-kernel override also set, the probed admission skips its
// LSM-list check (the startup canary must then refuse a kernel without the
// bpf LSM by itself). Qualification builds only.
const SharedSkipLSMListGateEnv = "IG_ENFORCE_EXEC_SKIP_LSM_LIST_GATE"

func init() {
	sharedProbedKernelOverride = func() bool { return os.Getenv(SharedProbedKernelEnv) == "1" }
	sharedSkipLSMListGate = func() bool {
		return sharedProbedKernelOverride() && os.Getenv(SharedSkipLSMListGateEnv) == "1"
	}
}
