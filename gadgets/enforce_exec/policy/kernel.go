// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package execpolicy

import (
	"fmt"
	"path"
	"strings"
)

const (
	KernelMaxBindings = 1024
	KernelMaxRules    = 128
	KernelPathSize    = 256
)

// KernelEntry is the map value shared with the execution BPF program. Entry zero
// holds the generation header; subsequent entries each describe one path.
type KernelEntry struct {
	Generation  uint64
	Mode        uint32
	DefaultDeny uint32
	Count       uint32
	Deny        uint32
	Prefix      uint32
	Length      uint32
	Path        [KernelPathSize]byte
}

// CompileKernel prepares a complete generation before any kernel map is changed.
// It preserves rule order; the BPF evaluator gives matching denies precedence.
// Unsupported configurations return an empty generation, never partial rules.
func CompileKernel(d Document, generation uint64) ([KernelMaxRules + 1]KernelEntry, error) {
	var entries [KernelMaxRules + 1]KernelEntry
	fail := func(err error) ([KernelMaxRules + 1]KernelEntry, error) {
		return [KernelMaxRules + 1]KernelEntry{}, err
	}
	if err := d.Validate(DefaultLimits()); err != nil {
		return fail(err)
	}
	if generation == 0 {
		return fail(fmt.Errorf("kernel generation must be nonzero"))
	}
	entries[0].Generation = generation
	switch d.Policy.Mode {
	case "audit":
		entries[0].Mode = 1
	case "enforce":
		entries[0].Mode = 2
	}
	if d.Policy.Exec.Default == "deny" {
		entries[0].DefaultDeny = 1
	}
	for _, rule := range d.Policy.Exec.Rules {
		if d.Policy.Mode == "off" && rule.Mode != "" {
			return fail(fmt.Errorf("rule %q cannot override an off policy", rule.Name))
		}
		for _, pattern := range rule.Target.Path {
			if entries[0].Count == KernelMaxRules {
				return fail(fmt.Errorf("kernel expanded path capacity exceeded (%d)", KernelMaxRules))
			}
			var entry KernelEntry
			switch rule.Mode {
			case "audit":
				entry.Mode = 1
			case "enforce":
				entry.Mode = 2
			}
			if strings.HasSuffix(pattern, "/**") {
				pattern = strings.TrimSuffix(pattern, "**")
				entry.Prefix = 1
			}
			if len(pattern) >= KernelPathSize {
				return fail(fmt.Errorf("rule %q encoded path must be shorter than %d bytes", rule.Name, KernelPathSize))
			}
			entry.Length = uint32(len(pattern))
			copy(entry.Path[:], pattern)
			if rule.Action == "deny" {
				entry.Deny = 1
			}
			entries[0].Count++
			entries[entries[0].Count] = entry
		}
	}
	return entries, nil
}

// ValidateKernel rejects malformed compiled data from native callers before load.
func ValidateKernel(entries [KernelMaxRules + 1]KernelEntry) error {
	h := entries[0]
	if h.Generation == 0 || h.Mode > 2 || h.DefaultDeny > 1 || h.Count > KernelMaxRules || h.Deny != 0 || h.Prefix != 0 || h.Length != 0 || h.Path != ([KernelPathSize]byte{}) {
		return fmt.Errorf("invalid policy header")
	}
	for i := 1; i < len(entries); i++ {
		e := entries[i]
		if uint32(i) > h.Count {
			if e != (KernelEntry{}) {
				return fmt.Errorf("nonzero unused rule")
			}
			continue
		}
		if e.Generation != 0 || e.Mode > 2 || (h.Mode == 0 && e.Mode != 0) || e.DefaultDeny != 0 || e.Count != 0 || e.Deny > 1 || e.Prefix > 1 || e.Length == 0 || e.Length >= KernelPathSize {
			return fmt.Errorf("invalid rule %d", i)
		}
		for _, b := range e.Path[e.Length:] {
			if b != 0 {
				return fmt.Errorf("nonzero path padding")
			}
		}
		p := string(e.Path[:e.Length])
		if e.Prefix == 1 {
			if !strings.HasSuffix(p, "/") || strings.HasSuffix(p, "//") {
				return fmt.Errorf("prefix must end in exactly one slash")
			}
			// Prefix entries encode the directory including its trailing slash.
			// Exact entries must retain every byte for wildcard validation.
			if p != "/" {
				p = strings.TrimSuffix(p, "/")
			}
		}
		if !path.IsAbs(p) || path.Clean(p) != p || strings.ContainsAny(p, "*?[]\\\x00") {
			return fmt.Errorf("invalid compiled path")
		}
	}
	return nil
}
