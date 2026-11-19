// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package execpolicy

import (
	"encoding/binary"
	"strings"
	"testing"
)

func TestCompileKernelLayoutAndPaths(t *testing.T) {
	d := document(t)
	d.Policy.Exec.Rules[0].Target.Path = []string{"/usr/bin/**", "/**", "/bin/tool"}
	d.Policy.Exec.Rules = append(d.Policy.Exec.Rules, Rule{
		Name: "denied", Target: Target{Path: []string{"/bin/blocked"}}, Action: "deny",
	})
	got, err := CompileKernel(d, 42)
	if err != nil {
		t.Fatal(err)
	}
	if size := binary.Size(KernelEntry{}); size != 288 {
		t.Fatalf("kernel entry size = %d, want 288", size)
	}
	if got[0] != (KernelEntry{Generation: 42, Mode: 2, DefaultDeny: 1, Count: 4}) {
		t.Fatalf("unexpected header: %+v", got[0])
	}
	for i, want := range []struct {
		path   string
		prefix uint32
		deny   uint32
	}{{"/usr/bin/", 1, 0}, {"/", 1, 0}, {"/bin/tool", 0, 0}, {"/bin/blocked", 0, 1}} {
		entry := KernelEntry{Prefix: want.prefix, Deny: want.deny, Length: uint32(len(want.path))}
		copy(entry.Path[:], want.path)
		if got[i+1] != entry {
			t.Errorf("entry %d = %+v, want %+v", i+1, got[i+1], entry)
		}
	}
	for _, entry := range got[5:] {
		if entry != (KernelEntry{}) {
			t.Fatal("unused entry is not zero")
		}
	}
	again, err := CompileKernel(d, 42)
	if err != nil || again != got {
		t.Fatalf("compilation is not deterministic: %v", err)
	}
}

func TestCompileKernelModes(t *testing.T) {
	for mode, value := range map[string]uint32{"off": 0, "audit": 1, "enforce": 2} {
		t.Run(mode, func(t *testing.T) {
			d := document(t)
			d.Policy.Mode = mode
			d.Policy.Exec.Default = "allow"
			if mode != "off" {
				d.Policy.Exec.Rules[0].Mode = mode
			}
			got, err := CompileKernel(d, 1)
			if err != nil {
				t.Fatal(err)
			}
			if got[0].Mode != value || got[0].DefaultDeny != 0 {
				t.Fatalf("unexpected header: %+v", got[0])
			}
		})
	}
}

func TestCompileKernelBoundaries(t *testing.T) {
	for _, pattern := range []string{"/" + strings.Repeat("x", 254), "/" + strings.Repeat("é", 127), "/" + strings.Repeat("x", 253) + "/**"} {
		d := document(t)
		d.Policy.Exec.Rules[0].Target.Path = make([]string, KernelMaxRules)
		for i := range d.Policy.Exec.Rules[0].Target.Path {
			d.Policy.Exec.Rules[0].Target.Path[i] = pattern
		}
		got, err := CompileKernel(d, 1)
		if err != nil {
			t.Fatal(err)
		}
		if got[0].Count != KernelMaxRules || got[1].Length != 255 || got[1].Path[255] != 0 {
			t.Fatalf("boundary policy compiled incorrectly: %+v", got[0])
		}
	}
}

func TestCompileKernelRejectsUnsupported(t *testing.T) {
	cases := map[string]func(*Document){
		"invalid document": func(d *Document) { d.Version = 2 },
		"empty path": func(d *Document) {
			d.Policy.Exec.Rules = append(d.Policy.Exec.Rules, Rule{
				Name: "denied", Target: Target{Path: []string{""}}, Action: "deny",
			})
		},
		"expanded capacity": func(d *Document) {
			for range KernelMaxRules {
				d.Policy.Exec.Rules[0].Target.Path = append(d.Policy.Exec.Rules[0].Target.Path, "/tool")
			}
		},
		"path bytes": func(d *Document) {
			d.Policy.Exec.Rules[0].Target.Path = append(d.Policy.Exec.Rules[0].Target.Path, "/"+strings.Repeat("x", 255))
		},
		"multibyte path bytes": func(d *Document) {
			d.Policy.Exec.Rules[0].Target.Path = []string{"/" + strings.Repeat("é", 128)}
		},
		"prefix bytes": func(d *Document) {
			d.Policy.Exec.Rules[0].Target.Path = []string{"/" + strings.Repeat("x", 254) + "/**"}
		},
		"off with active rule": func(d *Document) {
			d.Policy.Mode = "off"
			d.Policy.Exec.Rules[0].Mode = "enforce"
		},
		"encoded document limit": func(d *Document) { d.Policy.Exec.Rules[0].Origin = strings.Repeat("x", 65536) },
	}
	for name, modify := range cases {
		t.Run(name, func(t *testing.T) {
			d := document(t)
			modify(&d)
			got, err := CompileKernel(d, 1)
			if err == nil {
				t.Fatal("unsupported policy accepted")
			}
			if got != ([KernelMaxRules + 1]KernelEntry{}) {
				t.Fatal("error returned a partial generation")
			}
		})
	}
	got, err := CompileKernel(document(t), 0)
	if err == nil || got != ([KernelMaxRules + 1]KernelEntry{}) {
		t.Fatalf("zero generation accepted: %v", err)
	}
}

func TestValidateKernel(t *testing.T) {
	entries, err := CompileKernel(document(t), 9)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateKernel(entries); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*[KernelMaxRules + 1]KernelEntry){
		"revision":     func(e *[KernelMaxRules + 1]KernelEntry) { e[0].Generation = 0 },
		"mode":         func(e *[KernelMaxRules + 1]KernelEntry) { e[0].Mode = 3 },
		"capacity":     func(e *[KernelMaxRules + 1]KernelEntry) { e[0].Count = KernelMaxRules + 1 },
		"rule mode":    func(e *[KernelMaxRules + 1]KernelEntry) { e[1].Mode = 3 },
		"off override": func(e *[KernelMaxRules + 1]KernelEntry) { e[0].Mode = 0; e[1].Mode = 2 },
		"unused":       func(e *[KernelMaxRules + 1]KernelEntry) { e[8].Deny = 1 },
		"length":       func(e *[KernelMaxRules + 1]KernelEntry) { e[1].Length = 256 },
		"padding":      func(e *[KernelMaxRules + 1]KernelEntry) { e[1].Path[255] = 1 },
		"relative":     func(e *[KernelMaxRules + 1]KernelEntry) { e[1].Path[0] = 'x' },
		"nul":          func(e *[KernelMaxRules + 1]KernelEntry) { e[1].Path[2] = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			copy := entries
			mutate(&copy)
			if ValidateKernel(copy) == nil {
				t.Fatal("invalid compiled policy accepted")
			}
		})
	}
}

func TestCompileKernelMixedRuleModes(t *testing.T) {
	for _, policyMode := range []string{"audit", "enforce"} {
		d := document(t)
		d.Policy.Mode = policyMode
		d.Policy.Exec.Rules = []Rule{
			{Name: "audited-deny", Target: Target{Path: []string{"/bin/tool"}}, Action: "deny", Mode: "audit"},
			{Name: "enforced-deny", Target: Target{Path: []string{"/bin/tool"}}, Action: "deny", Mode: "enforce"},
			{Name: "inherited-allow", Target: Target{Path: []string{"/bin/tool"}}, Action: "allow"},
		}
		entries, err := CompileKernel(d, 1)
		if err != nil {
			t.Fatal(err)
		}
		if entries[1].Mode != 1 || entries[2].Mode != 2 || entries[3].Mode != 0 {
			t.Fatalf("rule modes not preserved: %+v", entries[:4])
		}
		if err := ValidateKernel(entries); err != nil {
			t.Fatal(err)
		}
	}
}

func TestValidateKernelNativePaths(t *testing.T) {
	for _, tc := range []struct {
		path   string
		prefix uint32
		valid  bool
	}{
		{"/bin/**", 0, false},
		{"/**", 0, false},
		{"/bin/*", 0, false},
		{"/bin/?", 0, false},
		{"/bin/[ab]", 0, false},
		{"/bin/", 0, false},
		{"/bin/tool", 0, true},
		{"/", 0, true},
		{"/bin/", 1, true},
		{"/", 1, true},
		{"//", 1, false},
		{"///", 1, false},
		{"/bin/**/", 1, false},
		{"/bin//", 1, false},
	} {
		t.Run(tc.path+string(rune('0'+tc.prefix)), func(t *testing.T) {
			var entries [KernelMaxRules + 1]KernelEntry
			entries[0] = KernelEntry{Generation: 1, Mode: 2, Count: 1}
			entries[1] = KernelEntry{Deny: 1, Prefix: tc.prefix, Length: uint32(len(tc.path))}
			copy(entries[1].Path[:], tc.path)
			if err := ValidateKernel(entries); (err == nil) != tc.valid {
				t.Fatalf("ValidateKernel(path=%q, prefix=%d) = %v, valid=%v", tc.path, tc.prefix, err, tc.valid)
			}
		})
	}
}

func TestCompileKernelRejectsNoncanonicalPatterns(t *testing.T) {
	for _, pattern := range []string{"//**", "///**", "/bin//**", "/bin/../**"} {
		t.Run(pattern, func(t *testing.T) {
			d := document(t)
			d.Policy.Exec.Default = "allow"
			d.Policy.Exec.Rules[0].Action = "deny"
			d.Policy.Exec.Rules[0].Target.Path = []string{pattern}
			if err := d.Validate(DefaultLimits()); err == nil {
				t.Error("noncanonical authoring path accepted")
			}
			entries, err := CompileKernel(d, 1)
			if err == nil {
				t.Fatal("noncanonical path compiled")
			}
			if entries != ([KernelMaxRules + 1]KernelEntry{}) {
				t.Fatal("rejected policy returned partial entries")
			}
		})
	}
}
