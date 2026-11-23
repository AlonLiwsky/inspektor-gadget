// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

// PublicationResult separates the irreversible map commit from admission:
// Committed is the commit, Generation the committed generation and
// Admitting whether that generation admits execs. Ready is intentionally
// absent.
type PublicationResult struct {
	Committed  bool
	Generation uint64
	Admitting  bool
}
