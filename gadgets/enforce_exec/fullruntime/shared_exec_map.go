// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

// The executable-mapping gate of the product object (full/shared_exec_map.h):
// two programs in the pinned attach set (sharedCandidateAttachSet). README,
// "Executable-mapping gate".
const (
	// sharedExecMapMmap judges a new mapping with PROT_EXEC. The attach
	// canary waits for it: the kernel's ELF loader maps the canary's program
	// through security_mmap_file.
	sharedExecMapMmap = "em_mmap_file"
	// sharedExecMapMprotect judges an mprotect that adds PROT_EXEC to a file
	// mapping. A fork, exec and exit need not do that, so the attach canary
	// does not wait for it (runSharedAttachCanary). Nothing else proves it at
	// start yet: a self-test like the root barrier's is an open item.
	sharedExecMapMprotect = "em_file_mprotect"
)
