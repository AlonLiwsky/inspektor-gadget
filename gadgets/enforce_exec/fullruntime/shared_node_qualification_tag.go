// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

// Qualification binaries only: enables the WithSharedNodeQualification
// candidate StartNode path. Product builds never carry this tag.
func init() { sharedQualificationBuild = true }
