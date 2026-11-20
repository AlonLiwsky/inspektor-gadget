// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package restartfence

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

func pinTestSpec() *ebpf.CollectionSpec {
	s := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{}, Programs: map[string]*ebpf.ProgramSpec{}}
	s.Maps = map[string]*ebpf.MapSpec{
		"fence_state":   {Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1},
		"fence_owner":   {Type: ebpf.Hash, KeySize: 4, ValueSize: 24, MaxEntries: 1},
		"fence_nonce":   {Type: ebpf.Hash, KeySize: 4, ValueSize: 24, MaxEntries: 1},
		"fence_cgroups": {Type: ebpf.Hash, KeySize: 8, ValueSize: 32, MaxEntries: 4096},
		"fence_counts":  {Type: ebpf.PerCPUHash, KeySize: 8, ValueSize: 24, MaxEntries: 4097},
		"fence_events":  {Type: ebpf.RingBuf, KeySize: 0, ValueSize: 0, MaxEntries: 1048576},
	}
	for name, section := range map[string]string{"fence_exec": "lsm/bprm_check_security", "fence_reg": "tp_btf/sys_enter", "fence_exit": "tp_btf/sched_process_exit", "fence_selfexec": "tp_btf/sched_process_exec"} {
		typ, attach := ebpf.LSM, ebpf.AttachLSMMac
		if strings.HasPrefix(section, "tp_btf/") {
			typ, attach = ebpf.Tracing, ebpf.AttachTraceRawTp
		}
		s.Programs[name] = &ebpf.ProgramSpec{Name: name, SectionName: section, Type: typ, AttachType: attach, Instructions: asm.Instructions{asm.LoadMapPtr(asm.R1, 0).WithReference("fence_state")}}
	}
	return s
}

func pinTestManifest(s *ebpf.CollectionSpec) fencePinManifest {
	m := fencePinManifest{Format: fencePinFormat, BootID: "boot", ObjectSHA256: strings.Repeat("a", 64)}
	var stateID ebpf.MapID
	for i, name := range sortedKeys(s.Maps) {
		ms := s.Maps[name]
		id := ebpf.MapID(i + 1)
		if name == "fence_state" {
			stateID = id
		}
		m.Maps = append(m.Maps, fencePinnedMap{Name: name, ID: id, Type: ms.Type, KeySize: ms.KeySize, ValueSize: ms.ValueSize, MaxEntries: ms.MaxEntries, Flags: ms.Flags})
	}
	for i, name := range sortedKeys(s.Programs) {
		ps := s.Programs[name]
		typ, target := link.TracingType, uint32(10)
		targetName := ""
		if ps.Type == ebpf.Tracing {
			typ, target = link.RawTracepointType, 0
			targetName = strings.TrimPrefix(ps.SectionName, "tp_btf/")
		}
		m.Links = append(m.Links, fencePinnedLink{Name: name, ID: link.ID(i + 1), Type: typ, ProgramID: ebpf.ProgramID(i + 1), ProgramType: ps.Type, Tag: "0123456789abcdef", Section: ps.SectionName, Attach: ps.AttachType, TargetBTF: target, TargetObject: target, TargetName: targetName, MapIDs: []ebpf.MapID{stateID}})
	}
	return m
}

func TestFenceManifestRoundTrip(t *testing.T) {
	s := pinTestSpec()
	m := pinTestManifest(s)
	if err := validateFenceSpec(s); err != nil {
		t.Fatal(err)
	}
	b, err := m.encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeFenceManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	if err := got.check(s, "boot", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
}

func TestFenceManifestRejectsUnattestedGraph(t *testing.T) {
	cases := map[string]func(*fencePinManifest){
		"ABI":                func(m *fencePinManifest) { m.Format++ },
		"boot":               func(m *fencePinManifest) { m.BootID = "other" },
		"object":             func(m *fencePinManifest) { m.ObjectSHA256 = strings.Repeat("b", 64) },
		"missing map":        func(m *fencePinManifest) { m.Maps = m.Maps[1:] },
		"duplicate map name": func(m *fencePinManifest) { m.Maps[1].Name = m.Maps[0].Name },
		"duplicate map ID":   func(m *fencePinManifest) { m.Maps[1].ID = m.Maps[0].ID },
		"zero map ID":        func(m *fencePinManifest) { m.Maps[0].ID = 0 },
		"map type":           func(m *fencePinManifest) { m.Maps[0].Type = ebpf.Array },
		"map key":            func(m *fencePinManifest) { m.Maps[0].KeySize++ },
		"map value":          func(m *fencePinManifest) { m.Maps[0].ValueSize++ },
		"map capacity":       func(m *fencePinManifest) { m.Maps[0].MaxEntries++ },
		"map flags":          func(m *fencePinManifest) { m.Maps[0].Flags++ },
		"missing link":       func(m *fencePinManifest) { m.Links = m.Links[1:] },
		"duplicate link":     func(m *fencePinManifest) { m.Links[1] = m.Links[0] },
		"duplicate program":  func(m *fencePinManifest) { m.Links[1].ProgramID = m.Links[0].ProgramID },
		"zero link ID":       func(m *fencePinManifest) { m.Links[0].ID = 0 },
		"program type":       func(m *fencePinManifest) { m.Links[0].ProgramType = ebpf.XDP },
		"section":            func(m *fencePinManifest) { m.Links[0].Section = "lsm/wrong" },
		"attach":             func(m *fencePinManifest) { m.Links[0].Attach = ebpf.AttachNone },
		"target":             func(m *fencePinManifest) { m.Links[0].TargetBTF = 0 },
		"link type":          func(m *fencePinManifest) { m.Links[0].Type = link.RawTracepointType },
		"tag":                func(m *fencePinManifest) { m.Links[0].Tag = "invalid" },
		"foreign map":        func(m *fencePinManifest) { m.Links[0].MapIDs = []ebpf.MapID{900} },
		"wrong owned map":    func(m *fencePinManifest) { m.Links[0].MapIDs = []ebpf.MapID{1} },
		"duplicate map ref":  func(m *fencePinManifest) { m.Links[0].MapIDs = append(m.Links[0].MapIDs, m.Links[0].MapIDs[0]) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := pinTestSpec()
			m := pinTestManifest(s)
			mutate(&m)
			if m.check(s, "boot", strings.Repeat("a", 64)) == nil {
				t.Fatal("accepted invalid graph")
			}
		})
	}
}

func TestFenceManifestDecodeStrict(t *testing.T) {
	for _, text := range []string{"{} {}", `{"unknown":true}`, "\x00", "not JSON"} {
		b := make([]byte, fenceManifestSize)
		copy(b, text)
		if _, err := decodeFenceManifest(b); err == nil {
			t.Fatalf("accepted %q", text)
		}
	}
	if _, err := decodeFenceManifest([]byte("{}")); err == nil {
		t.Fatal("accepted wrong size")
	}
	m := pinTestManifest(pinTestSpec())
	m.BootID = strings.Repeat("a", fenceManifestSize)
	if _, err := m.encode(); err == nil {
		t.Fatal("accepted oversized manifest")
	}
}

func TestFenceSpecRejectsUnsafeShape(t *testing.T) {
	cases := map[string]func(*ebpf.CollectionSpec){
		"missing program": func(s *ebpf.CollectionSpec) { delete(s.Programs, "fence_exec") },
		"missing map":     func(s *ebpf.CollectionSpec) { delete(s.Maps, "fence_state") },
		"unknown map":     func(s *ebpf.CollectionSpec) { s.Maps["unknown"] = s.Maps["fence_state"]; delete(s.Maps, "fence_state") },
		"wrong section":   func(s *ebpf.CollectionSpec) { s.Programs["fence_exec"].SectionName = "lsm/file_open" },
		"wrong type":      func(s *ebpf.CollectionSpec) { s.Programs["fence_exec"].Type = ebpf.XDP },
		"wrong attach":    func(s *ebpf.CollectionSpec) { s.Programs["fence_exit"].AttachType = ebpf.AttachTraceFEntry },
		"autopin":         func(s *ebpf.CollectionSpec) { s.Maps["fence_state"].Pinning = ebpf.PinByName },
		"nonempty": func(s *ebpf.CollectionSpec) {
			s.Maps["fence_state"].Contents = []ebpf.MapKV{{Key: uint64(1), Value: uint64(2)}}
		},
		"inner": func(s *ebpf.CollectionSpec) { s.Maps["fence_state"].InnerMap = &ebpf.MapSpec{} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s := pinTestSpec()
			mutate(s)
			if validateFenceSpec(s) == nil {
				t.Fatal("accepted unsafe ELF")
			}
		})
	}
}

func TestFenceParentRejectsNonBPFFSWithoutCreating(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "new_parent", fenceDirectory)
	if p, err := lockPinRoot(root); err == nil {
		unlockPinRoot(p)
		t.Fatal("accepted ordinary filesystem")
	}
	if _, err := os.Lstat(filepath.Dir(root)); !os.IsNotExist(err) {
		t.Fatalf("created parent outside bpffs: %v", err)
	}
	for _, root := range []string{"relative/fence-v1", "/sys/fs/bpf/../bpf/fence-v1", "/sys/fs/bpf/fence-v2"} {
		if p, err := lockPinRoot(root); err == nil {
			unlockPinRoot(p)
			t.Fatalf("accepted %q", root)
		}
	}
}

func TestFenceSafePinNames(t *testing.T) {
	for _, s := range []string{"", "../map", "bad.name", "a/b", "a\\b", strings.Repeat("a", 64)} {
		if fenceSafeName(s) {
			t.Fatalf("accepted %q", s)
		}
	}
	if !fenceSafeName("fence_state") {
		t.Fatal("rejected safe name")
	}
}

// Parsing the shipped ELF is unprivileged: no program/map is loaded or attached.
func TestFenceObjectPinInventory(t *testing.T) {
	s, err := ebpf.LoadCollectionSpec("bpf/fence_amd64.elf")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateFenceSpec(s); err != nil {
		t.Fatal(err)
	}
	m := pinTestManifest(s)
	for i, row := range m.Links {
		refs := map[string]bool{}
		for _, ins := range s.Programs[row.Name].Instructions {
			if ins.IsLoadFromMap() {
				refs[ins.Reference()] = true
			}
		}
		m.Links[i].MapIDs = nil
		for _, mr := range m.Maps {
			if refs[mr.Name] {
				m.Links[i].MapIDs = append(m.Links[i].MapIDs, mr.ID)
			}
		}
	}
	if err := m.check(s, "boot", strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
}
