// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Package execpolicy prototypes a standalone execution-policy contract.
// It does not attach programs or resolve kernel identities.
package execpolicy

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// Limits bound authoring input and preparation, independently of CRD status limits.
type Limits struct {
	MaxBytes int64 `json:"maxBytes"`
	MaxRules int   `json:"maxRules"`
	MaxPaths int   `json:"maxPaths"`
}

func DefaultLimits() Limits { return Limits{MaxBytes: 64 * 1024, MaxRules: 128, MaxPaths: 512} }

type Document struct {
	Version int     `yaml:"version" json:"version"`
	Binding Binding `yaml:"binding" json:"binding"`
	Policy  Policy  `yaml:"policy" json:"policy"`
}

type Binding struct {
	Container  *Container  `yaml:"container,omitempty" json:"container,omitempty"`
	Containers []Container `yaml:"containers,omitempty" json:"containers,omitempty"`
}
type Container struct {
	Runtime string `yaml:"runtime" json:"runtime"`
	ID      string `yaml:"id" json:"id"`
}
type Policy struct {
	Mode string  `yaml:"mode" json:"mode"`
	Exec Section `yaml:"exec" json:"exec"`
}
type Section struct {
	Default string `yaml:"default" json:"default"`
	Rules   []Rule `yaml:"rules,omitempty" json:"rules,omitempty"`
}
type Rule struct {
	Name   string `yaml:"name" json:"name"`
	Target Target `yaml:"target" json:"target"`
	Action string `yaml:"action" json:"action"`
	Mode   string `yaml:"mode,omitempty" json:"mode,omitempty"`
	Origin string `yaml:"origin,omitempty" json:"origin,omitempty"`
}
type Target struct {
	Path []string `yaml:"path" json:"path"`
}

// Parse rejects unsupported fields, multiple documents and oversized inputs.
// In particular, unsupported predicates cannot disappear into a broader rule.
func Parse(r io.Reader, limits Limits) (Document, error) {
	var d Document
	if err := decode(r, limits, &d); err != nil {
		return Document{}, err
	}
	if err := d.Validate(limits); err != nil {
		return Document{}, err
	}
	return d, nil
}

func decode(r io.Reader, limits Limits, into any) error {
	if limits.MaxBytes <= 0 || limits.MaxRules <= 0 || limits.MaxPaths <= 0 {
		return fmt.Errorf("limits must be positive")
	}
	data, err := io.ReadAll(io.LimitReader(r, limits.MaxBytes+1))
	if err != nil {
		return fmt.Errorf("read policy: %w", err)
	}
	if int64(len(data)) > limits.MaxBytes {
		return fmt.Errorf("policy exceeds %d bytes", limits.MaxBytes)
	}
	decoder := yaml.NewDecoder(strings.NewReader(string(data)))
	decoder.KnownFields(true)
	if err := decoder.Decode(into); err != nil {
		return fmt.Errorf("decode policy: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return fmt.Errorf("expected exactly one YAML document")
	}
	return nil
}

func (d Document) Validate(limits Limits) error {
	if limits.MaxBytes <= 0 || limits.MaxRules <= 0 || limits.MaxPaths <= 0 {
		return fmt.Errorf("limits must be positive")
	}
	if d.Version != 1 {
		return fmt.Errorf("unsupported version %d", d.Version)
	}
	if d.Binding.Container != nil && len(d.Binding.Containers) > 0 {
		return fmt.Errorf("use container or containers, not both")
	}
	if len(d.Binding.Targets()) == 0 || len(d.Binding.Targets()) > KernelMaxBindings {
		return fmt.Errorf("require 1 to %d container targets", KernelMaxBindings)
	}
	seen := map[Container]bool{}
	for _, c := range d.Binding.Targets() {
		if strings.TrimSpace(c.Runtime) == "" || strings.TrimSpace(c.ID) == "" || seen[c] {
			return fmt.Errorf("container runtime and ID must be nonempty and unique")
		}
		seen[c] = true
	}
	if d.Policy.Mode != "audit" && d.Policy.Mode != "enforce" && d.Policy.Mode != "off" {
		return fmt.Errorf("mode must be audit, enforce or off")
	}
	if !validAction(d.Policy.Exec.Default) {
		return fmt.Errorf("exec.default must be allow or deny")
	}
	if len(d.Policy.Exec.Rules) > limits.MaxRules {
		return fmt.Errorf("rule capacity exceeded (%d)", limits.MaxRules)
	}
	names := map[string]bool{}
	paths := 0
	for _, r := range d.Policy.Exec.Rules {
		if strings.TrimSpace(r.Name) == "" || names[r.Name] {
			return fmt.Errorf("rule names must be nonempty and unique: %q", r.Name)
		}
		names[r.Name] = true
		if !validAction(r.Action) || (r.Mode != "" && r.Mode != "audit" && r.Mode != "enforce") {
			return fmt.Errorf("invalid action or mode for rule %q", r.Name)
		}
		if len(r.Target.Path) == 0 {
			return fmt.Errorf("rule %q requires target.path", r.Name)
		}
		for _, pattern := range r.Target.Path {
			base := strings.TrimSuffix(pattern, "/**")
			if pattern == "/**" {
				base = "/"
			}
			if path.Clean(pattern) != pattern || !path.IsAbs(base) || path.Clean(base) != base || strings.ContainsAny(base, "*?[]\\\x00") {
				return fmt.Errorf("unsupported path %q: use a clean absolute path or directory/**", pattern)
			}
		}
		paths += len(r.Target.Path)
	}
	if paths > limits.MaxPaths {
		return fmt.Errorf("expanded path capacity exceeded (%d)", limits.MaxPaths)
	}
	// Bound programmatic callers too, not just YAML readers.
	encoded, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("encode policy: %w", err)
	}
	if int64(len(encoded)) > limits.MaxBytes {
		return fmt.Errorf("encoded policy exceeds %d bytes", limits.MaxBytes)
	}
	return nil
}

func validAction(s string) bool { return s == "allow" || s == "deny" }

// Hash identifies the complete parsed document, including the target and origin.
// It is a revision hash, not a semantic-equivalence hash (rule order is retained).
func (d Document) Hash() string {
	data, _ := json.Marshal(d)
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

// Targets returns the initial discovery selectors, independently of live map membership.
func (b Binding) Targets() []Container {
	if b.Container != nil {
		return []Container{*b.Container}
	}
	return append([]Container(nil), b.Containers...)
}
