// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package execpolicy

import (
	"fmt"
	"path"
	"strings"
)

type Match struct {
	Name   string `json:"name"`
	Origin string `json:"origin,omitempty"`
}
type Decision struct {
	Simulated  bool    `json:"simulated"`
	Enforced   bool    `json:"enforced"`
	Path       string  `json:"path"`
	Verdict    string  `json:"verdict"`
	Mode       string  `json:"mode"`
	WouldDeny  bool    `json:"wouldDeny"`
	WouldBlock bool    `json:"wouldBlock"`
	Matches    []Match `json:"matches,omitempty"`
	Reason     string  `json:"reason"`
}

// Evaluate uses a supplied, already-resolved path solely for simulation.
// It does not inspect files, execute commands, or implement kernel enforcement.
func (d Document) Evaluate(executable string) (Decision, error) {
	out := Decision{Simulated: true, Path: executable, Mode: d.Policy.Mode}
	if !path.IsAbs(executable) || path.Clean(executable) != executable || strings.ContainsRune(executable, 0) {
		return out, fmt.Errorf("evaluation requires a clean absolute executable path")
	}
	if d.Policy.Mode == "off" {
		out.Verdict, out.Reason = "allow", "policy_off"
		return out, nil
	}
	var denies, allows []Match
	enforceDeny := false
	for _, r := range d.Policy.Exec.Rules {
		matched := false
		for _, pattern := range r.Target.Path {
			if pattern == executable || (strings.HasSuffix(pattern, "/**") && strings.HasPrefix(executable, strings.TrimSuffix(pattern, "**"))) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		match := Match{Name: r.Name, Origin: r.Origin}
		if r.Action == "deny" {
			denies = append(denies, match)
			mode := r.Mode
			if mode == "" {
				mode = d.Policy.Mode
			}
			enforceDeny = enforceDeny || mode == "enforce"
		} else {
			allows = append(allows, match)
		}
	}
	switch {
	case len(denies) > 0:
		out.Verdict, out.Matches, out.Reason, out.Mode = "deny", denies, "matching_deny", "audit"
		if enforceDeny {
			out.Mode = "enforce"
		}
	case len(allows) > 0:
		out.Verdict, out.Matches, out.Reason = "allow", allows, "matching_allow"
	default:
		out.Verdict, out.Reason = d.Policy.Exec.Default, "section_default"
	}
	out.WouldDeny = out.Verdict == "deny" && out.Mode == "audit"
	out.WouldBlock = out.Verdict == "deny" && out.Mode == "enforce"
	return out, nil
}
