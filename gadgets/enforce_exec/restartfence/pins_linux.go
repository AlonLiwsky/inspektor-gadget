// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package restartfence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	fencePinFormat    = 1
	fenceManifestSize = 16384
	fenceDirectory    = "fence-v1"
)

// pinnedFence owns only descriptors. Close NEVER removes a pin, including after
// an error. Incomplete sets require explicit operator recovery, not restart cleanup.
type pinnedFence struct {
	maps     map[string]*ebpf.Map
	programs map[string]*ebpf.Program
	links    map[string]link.Link
	dir      *os.File
	manifest *ebpf.Map
}

func (p *pinnedFence) Close() error {
	if p == nil {
		return nil
	}
	var err error
	for _, l := range p.links {
		err = errors.Join(err, l.Close())
	}
	for _, prog := range p.programs {
		err = errors.Join(err, prog.Close())
	}
	for _, m := range p.maps {
		err = errors.Join(err, m.Close())
	}
	if p.manifest != nil {
		err = errors.Join(err, p.manifest.Close())
		p.manifest = nil
	}
	if p.dir != nil {
		err = errors.Join(err, p.dir.Close())
		p.dir = nil
	}
	p.maps, p.programs, p.links = nil, nil, nil
	return err
}

type fencePinnedMap struct {
	Name       string       `json:"name"`
	ID         ebpf.MapID   `json:"id"`
	Type       ebpf.MapType `json:"type"`
	KeySize    uint32       `json:"keySize"`
	ValueSize  uint32       `json:"valueSize"`
	MaxEntries uint32       `json:"maxEntries"`
	Flags      uint32       `json:"flags"`
}

type fencePinnedLink struct {
	Name         string           `json:"name"`
	ID           link.ID          `json:"id"`
	Type         link.Type        `json:"type"`
	ProgramID    ebpf.ProgramID   `json:"programID"`
	ProgramType  ebpf.ProgramType `json:"programType"`
	Tag          string           `json:"tag"`
	Section      string           `json:"section"`
	Attach       ebpf.AttachType  `json:"attach"`
	TargetName   string           `json:"targetName,omitempty"`
	TargetObject uint32           `json:"targetObject"`
	TargetBTF    uint32           `json:"targetBTF"`
	MapIDs       []ebpf.MapID     `json:"mapIDs"`
}

type fencePinManifest struct {
	Format       int               `json:"format"`
	BootID       string            `json:"bootID"`
	ObjectSHA256 string            `json:"objectSHA256"`
	Maps         []fencePinnedMap  `json:"maps"`
	Links        []fencePinnedLink `json:"links"`
}

func (m fencePinManifest) encode() ([]byte, error) {
	b, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	if len(b) > fenceManifestSize {
		return nil, fmt.Errorf("fence manifest exceeds %d bytes", fenceManifestSize)
	}
	out := make([]byte, fenceManifestSize)
	copy(out, b)
	return out, nil
}

func decodeFenceManifest(value []byte) (fencePinManifest, error) {
	var m fencePinManifest
	if len(value) != fenceManifestSize {
		return m, fmt.Errorf("invalid fence manifest size")
	}
	d := json.NewDecoder(bytes.NewReader(bytes.TrimRight(value, "\x00")))
	d.DisallowUnknownFields()
	if err := d.Decode(&m); err != nil {
		return m, fmt.Errorf("decode fence manifest: %w", err)
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return m, fmt.Errorf("trailing fence manifest data")
	}
	return m, nil
}

// openPins loads or creates one exact ABI. Different/unfinished ABI directories
// are never removed or replaced. An adoption error must prevent engine readiness.
// The caller must supply the independently qualified fence ELF, not product ELF.
func openPins(root string, object []byte) (*pinnedFence, error) {
	return openPinsMode(root, object, true)
}

// openExistingPins never installs a graph, including when called by uninstall.
func openExistingPins(root string, object []byte) (*pinnedFence, error) {
	return openPinsMode(root, object, false)
}

func openPinsMode(root string, object []byte, allowCreate bool) (_ *pinnedFence, retErr error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("fence ELF: %w", err)
	}
	if err := validateFenceSpec(spec); err != nil {
		return nil, err
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return nil, fmt.Errorf("fence boot id: %w", err)
	}
	bootID := strings.TrimSpace(string(boot))
	if bootID == "" {
		return nil, fmt.Errorf("empty fence boot id")
	}
	digest := sha256.Sum256(object)
	sha := hex.EncodeToString(digest[:])
	parent, err := lockPinRoot(root)
	if err != nil {
		return nil, err
	}
	defer unlockPinRoot(parent)
	entries, err := os.ReadDir(procDirectory(parent))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "fence-") && e.Name() != fenceDirectory {
			return nil, fmt.Errorf("unreconciled fence ABI or pending set %q (retained)", e.Name())
		}
	}
	fd, err := unix.Openat(int(parent.Fd()), fenceDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err == nil {
		dir := os.NewFile(uintptr(fd), root)
		if err := validateFenceDirectory(fd, true); err != nil {
			dir.Close()
			return nil, err
		}
		return reopenFencePins(dir, spec, bootID, sha)
	}
	if !errors.Is(err, unix.ENOENT) {
		return nil, fmt.Errorf("open fence directory: %w", err)
	}
	if !allowCreate {
		return nil, fmt.Errorf("existing fence is absent: %w", unix.ENOENT)
	}
	// A fixed pending basename makes interrupted creation visible to the next
	// process. Never remove it or silently load a second graph over unknown pins.
	pending := fenceDirectory + "_tmp"
	if err := unix.Mkdirat(int(parent.Fd()), pending, 0o700); err != nil {
		return nil, fmt.Errorf("create pending fence: %w", err)
	}
	fd, err = unix.Openat(int(parent.Fd()), pending, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open pending fence (retained): %w", err)
	}
	dir := os.NewFile(uintptr(fd), root+"_tmp")
	if err := validateFenceDirectory(fd, true); err != nil {
		dir.Close()
		return nil, err
	}
	p, err := createFencePins(dir, spec, bootID, sha)
	if err != nil {
		return nil, fmt.Errorf("create fence (pending pins retained): %w", err)
	}
	defer func() {
		if retErr != nil {
			_ = p.Close()
		}
	}()
	if err := unix.Renameat2(int(parent.Fd()), pending, int(parent.Fd()), fenceDirectory, unix.RENAME_NOREPLACE); err != nil {
		return nil, fmt.Errorf("publish fence (pending pins retained): %w", err)
	}
	// Verify from independent opens before returning a usable collection.
	checkFD, err := unix.Openat(int(parent.Fd()), fenceDirectory, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	checked, err := reopenFencePins(os.NewFile(uintptr(checkFD), root), spec, bootID, sha)
	if err != nil {
		return nil, err
	}
	if err := p.Close(); err != nil {
		_ = checked.Close()
		return nil, err
	}
	return checked, nil
}

// lockPinRoot serializes creation, attestation, lifecycle map changes and lift.
// Every caller must use this same parent-directory lock and defer unlockPinRoot.
// For operations on an already opened graph, check that its directory inode is
// still the published root while holding this lock before any mutation.
func lockPinRoot(root string) (*os.File, error) {
	parent, err := fenceParent(root)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(parent.Fd()), unix.LOCK_EX); err != nil {
		parent.Close()
		return nil, fmt.Errorf("lock fence parent: %w", err)
	}
	return parent, nil
}

func unlockPinRoot(parent *os.File) error {
	if parent == nil {
		return nil
	}
	return errors.Join(unix.Flock(int(parent.Fd()), unix.LOCK_UN), parent.Close())
}

// checkPublishedFence prevents stale handles from mutating a replacement set.
func checkPublishedFence(parent *os.File, p *pinnedFence) error {
	if p == nil || p.dir == nil {
		return fmt.Errorf("closed fence pins")
	}
	var opened, published unix.Stat_t
	if err := unix.Fstat(int(p.dir.Fd()), &opened); err != nil {
		return err
	}
	if err := unix.Fstatat(int(parent.Fd()), fenceDirectory, &published, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if opened.Dev != published.Dev || opened.Ino != published.Ino || published.Mode&unix.S_IFMT != unix.S_IFDIR {
		return fmt.Errorf("published fence directory changed")
	}
	return validateFenceDirectory(int(p.dir.Fd()), true)
}

func procDirectory(f *os.File) string             { return fmt.Sprintf("/proc/self/fd/%d", f.Fd()) }
func fencePinPath(f *os.File, name string) string { return procDirectory(f) + "/" + name }
func fenceMapPin(name string) string              { return "map_" + name }
func fenceLinkPin(name string) string             { return "link_" + name }

func fenceSafeName(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_':
		default:
			return false
		}
	}
	return true
}

func validateFenceSpec(s *ebpf.CollectionSpec) error {
	if s == nil || len(s.Maps) != 6 || len(s.Programs) != 4 {
		return fmt.Errorf("incomplete fence ELF")
	}
	expectedPrograms := map[string]string{
		"fence_exec": "lsm/bprm_check_security", "fence_reg": "tp_btf/sys_enter",
		"fence_exit": "tp_btf/sched_process_exit", "fence_selfexec": "tp_btf/sched_process_exec",
	}
	expectedMaps := map[string]ebpf.MapSpec{
		"fence_state":   {Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1},
		"fence_owner":   {Type: ebpf.Hash, KeySize: 4, ValueSize: 24, MaxEntries: 1},
		"fence_nonce":   {Type: ebpf.Hash, KeySize: 4, ValueSize: 24, MaxEntries: 1},
		"fence_cgroups": {Type: ebpf.Hash, KeySize: 8, ValueSize: 32, MaxEntries: 4096},
		"fence_counts":  {Type: ebpf.PerCPUHash, KeySize: 8, ValueSize: 24, MaxEntries: 4097},
		"fence_events":  {Type: ebpf.RingBuf, KeySize: 0, ValueSize: 0, MaxEntries: 1048576},
	}
	sections := map[string]bool{}
	for name, p := range s.Programs {
		if !fenceSafeName(name) || p == nil || expectedPrograms[name] != p.SectionName {
			return fmt.Errorf("invalid fence program %q", name)
		}
		switch p.SectionName {
		case "lsm/bprm_check_security":
			if p.Type != ebpf.LSM || p.AttachType != ebpf.AttachLSMMac {
				return fmt.Errorf("unexpected fence LSM type")
			}
		case "tp_btf/sched_process_exit", "tp_btf/sched_process_exec", "tp_btf/sys_enter":
			if p.Type != ebpf.Tracing || p.AttachType != ebpf.AttachTraceRawTp {
				return fmt.Errorf("unexpected fence trace type")
			}
		default:
			return fmt.Errorf("unqualified fence section %q", p.SectionName)
		}
		if sections[p.SectionName] {
			return fmt.Errorf("duplicate fence section %q", p.SectionName)
		}
		sections[p.SectionName] = true
	}
	for name, m := range s.Maps {
		want, known := expectedMaps[name]
		if !known || !fenceSafeName(name) || m == nil || m.Pinning != ebpf.PinNone || m.InnerMap != nil || len(m.Contents) != 0 || m.Flags != 0 ||
			m.Type != want.Type || m.KeySize != want.KeySize || m.ValueSize != want.ValueSize || m.MaxEntries != want.MaxEntries {
			return fmt.Errorf("invalid/nonempty fence map %q", name)
		}
	}
	return nil
}

// Traverse without following symlinks. Missing components may only be created
// on bpffs. The shared parent must be private and owned by this privileged user.
func fenceParent(root string) (*os.File, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Base(root) != fenceDirectory {
		return nil, fmt.Errorf("fence root must be an absolute clean path ending in %s", fenceDirectory)
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "/")
	parts := strings.Split(strings.TrimPrefix(filepath.Dir(root), "/"), "/")
	for _, part := range parts {
		if part == "" {
			continue
		}
		next, err := unix.Openat(int(dir.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if errors.Is(err, unix.ENOENT) {
			var fs unix.Statfs_t
			if e := unix.Fstatfs(int(dir.Fd()), &fs); e != nil {
				dir.Close()
				return nil, e
			}
			if fs.Type != unix.BPF_FS_MAGIC {
				dir.Close()
				return nil, fmt.Errorf("refuse to create fence parent outside bpffs")
			}
			err = unix.Mkdirat(int(dir.Fd()), part, 0o700)
			if err != nil && !errors.Is(err, unix.EEXIST) {
				dir.Close()
				return nil, err
			}
			next, err = unix.Openat(int(dir.Fd()), part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		}
		if err != nil {
			dir.Close()
			return nil, fmt.Errorf("open fence ancestor %q: %w", part, err)
		}
		dir.Close()
		dir = os.NewFile(uintptr(next), part)
		var st unix.Stat_t
		if err := unix.Fstat(next, &st); err != nil {
			dir.Close()
			return nil, err
		}
		// The bpffs mountpoint may be sticky/writable, but private descendants
		// cannot be replaced by an unprivileged user in that mountpoint.
		if st.Uid != uint32(os.Geteuid()) || st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0 {
			dir.Close()
			return nil, fmt.Errorf("untrusted fence ancestor %q", part)
		}
	}
	if err := validateFenceDirectory(int(dir.Fd()), true); err != nil {
		dir.Close()
		return nil, err
	}
	return dir, nil
}

func validateFenceDirectory(fd int, private bool) error {
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != uint32(os.Geteuid()) || fs.Type != unix.BPF_FS_MAGIC || private && st.Mode&0o7777 != 0o700 {
		return fmt.Errorf("fence directory must be owned 0700 bpffs")
	}
	return nil
}

func createFencePins(dir *os.File, spec *ebpf.CollectionSpec, boot, digest string) (_ *pinnedFence, retErr error) {
	p := &pinnedFence{dir: dir, links: map[string]link.Link{}}
	defer func() {
		if retErr != nil {
			_ = p.Close()
		}
	}()
	c, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load fence: %w", err)
	}
	p.maps, p.programs = c.Maps, c.Programs
	// Every fresh map starts empty/zero, so no pod is assigned to an unarmed graph.
	// Pin maps before links; the manifest is the sole completeness marker.
	manifest := fencePinManifest{Format: fencePinFormat, BootID: boot, ObjectSHA256: digest}
	for _, name := range sortedKeys(p.maps) {
		m := p.maps[name]
		if err := m.Pin(fencePinPath(dir, fenceMapPin(name))); err != nil {
			return nil, err
		}
		row, err := inspectFenceMap(name, m)
		if err != nil {
			return nil, err
		}
		manifest.Maps = append(manifest.Maps, row)
	}
	for _, name := range sortedKeys(p.programs) {
		prog, ps := p.programs[name], spec.Programs[name]
		var l link.Link
		if ps.Type == ebpf.LSM {
			l, err = link.AttachLSM(link.LSMOptions{Program: prog})
		} else {
			l, err = link.AttachTracing(link.TracingOptions{Program: prog})
		}
		if err != nil {
			return nil, fmt.Errorf("attach fence %s: %w", name, err)
		}
		p.links[name] = l
		if err := l.Pin(fencePinPath(dir, fenceLinkPin(name))); err != nil {
			return nil, err
		}
		row, err := inspectFenceLink(name, l, prog, ps)
		if err != nil {
			return nil, err
		}
		manifest.Links = append(manifest.Links, row)
	}
	if err := manifest.check(spec, boot, digest); err != nil {
		return nil, err
	}
	value, err := manifest.encode()
	if err != nil {
		return nil, err
	}
	p.manifest, err = ebpf.NewMap(&ebpf.MapSpec{Name: "fence_manifest", Type: ebpf.Array, KeySize: 4, ValueSize: fenceManifestSize, MaxEntries: 1})
	if err != nil {
		return nil, err
	}
	if err := p.manifest.Put(uint32(0), value); err != nil {
		return nil, err
	}
	if err := p.manifest.Freeze(); err != nil {
		return nil, err
	}
	if err := p.manifest.Pin(fencePinPath(dir, "manifest")); err != nil {
		return nil, err
	}
	return p, nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

func inspectFenceMap(name string, m *ebpf.Map) (fencePinnedMap, error) {
	info, err := m.Info()
	if err != nil {
		return fencePinnedMap{}, err
	}
	id, ok := info.ID()
	if !ok || id == 0 {
		return fencePinnedMap{}, fmt.Errorf("fence map ID unavailable")
	}
	return fencePinnedMap{name, id, info.Type, info.KeySize, info.ValueSize, info.MaxEntries, info.Flags}, nil
}

func inspectFenceLink(name string, l link.Link, prog *ebpf.Program, ps *ebpf.ProgramSpec) (fencePinnedLink, error) {
	li, err := l.Info()
	if err != nil {
		return fencePinnedLink{}, err
	}
	pi, err := prog.Info()
	if err != nil {
		return fencePinnedLink{}, err
	}
	id, ok := pi.ID()
	if !ok || id == 0 || id != li.Program || li.ID == 0 {
		return fencePinnedLink{}, fmt.Errorf("fence link/program identity mismatch")
	}
	ids, ok := pi.MapIDs()
	if !ok {
		return fencePinnedLink{}, fmt.Errorf("fence program maps unavailable")
	}
	slices.Sort(ids)
	row := fencePinnedLink{Name: name, ID: li.ID, Type: li.Type, ProgramID: id, ProgramType: pi.Type, Tag: pi.Tag, Section: ps.SectionName, Attach: ps.AttachType, MapIDs: ids}
	if ps.Type == ebpf.LSM {
		tr := li.Tracing()
		if li.Type != link.TracingType || tr == nil {
			return row, fmt.Errorf("expected tracing link for fence LSM, got %v", li.Type)
		}
		if ebpf.AttachType(tr.AttachType) != ps.AttachType || tr.TargetBtfId == 0 || tr.TargetObjectId == 0 {
			return row, fmt.Errorf("invalid fence LSM metadata: attach=%d target_object=%d target_btf=%d", tr.AttachType, tr.TargetObjectId, tr.TargetBtfId)
		}
		row.TargetObject = tr.TargetObjectId
		row.TargetBTF = uint32(tr.TargetBtfId)
		// Kernel tracing link metadata names the vmlinux BTF object by
		// its (nonzero) kernel ID, not a separate attached BPF program.
		handle, err := btf.NewHandleFromID(btf.ID(row.TargetObject))
		if err != nil {
			return row, fmt.Errorf("open fence LSM target BTF object: %w", err)
		}
		defer handle.Close()
		info, err := handle.Info()
		if err != nil {
			return row, fmt.Errorf("inspect fence LSM target BTF object: %w", err)
		}
		if !info.IsVmlinux() {
			return row, fmt.Errorf("fence LSM target BTF %d is not vmlinux", row.TargetObject)
		}
		kernel, err := btf.LoadKernelSpec()
		if err != nil {
			return row, fmt.Errorf("attest fence LSM BTF: %w", err)
		}
		var target *btf.Func
		if err := kernel.TypeByName("bpf_lsm_"+ps.AttachTo, &target); err != nil {
			return row, err
		}
		targetID, err := kernel.TypeID(target)
		if err != nil {
			return row, err
		}
		if row.TargetBTF != uint32(targetID) {
			return row, fmt.Errorf("fence LSM attached to unexpected BTF target")
		}
	} else {
		rt := li.RawTracepoint()
		if li.Type != link.RawTracepointType || rt == nil || rt.Name != strings.TrimPrefix(ps.SectionName, "tp_btf/") {
			return row, fmt.Errorf("invalid fence tp_btf link target: type=%v target=%+v want=%s", li.Type, rt, ps.SectionName)
		}
		row.TargetName = rt.Name
	}
	return row, nil
}

func (m fencePinManifest) check(spec *ebpf.CollectionSpec, boot, digest string) error {
	if m.Format != fencePinFormat || m.BootID == "" || m.BootID != boot || m.ObjectSHA256 != digest || len(digest) != 64 || len(m.Maps) != len(spec.Maps) || len(m.Links) != len(spec.Programs) {
		return fmt.Errorf("fence manifest ABI, boot, object, or graph mismatch")
	}
	names, mapIDs := map[string]bool{}, map[ebpf.MapID]bool{}
	for _, row := range m.Maps {
		want := spec.Maps[row.Name]
		if want == nil || names[row.Name] || row.ID == 0 || mapIDs[row.ID] || row.Type != want.Type || row.KeySize != want.KeySize || row.ValueSize != want.ValueSize || row.MaxEntries != want.MaxEntries || row.Flags != want.Flags {
			return fmt.Errorf("fence map manifest mismatch for %q", row.Name)
		}
		names[row.Name], mapIDs[row.ID] = true, true
	}
	names, linkIDs, progIDs := map[string]bool{}, map[link.ID]bool{}, map[ebpf.ProgramID]bool{}
	for _, row := range m.Links {
		ps := spec.Programs[row.Name]
		tag, tagErr := hex.DecodeString(row.Tag)
		if ps == nil || names[row.Name] || row.ID == 0 || linkIDs[row.ID] || row.ProgramID == 0 || progIDs[row.ProgramID] || tagErr != nil || len(tag) != 8 || row.ProgramType != ps.Type || row.Section != ps.SectionName || row.Attach != ps.AttachType {
			return fmt.Errorf("fence link manifest mismatch for %q", row.Name)
		}
		if ps.Type == ebpf.LSM && (row.Type != link.TracingType || row.TargetObject == 0 || row.TargetBTF == 0 || row.TargetName != "") || ps.Type == ebpf.Tracing && (row.Type != link.RawTracepointType || row.TargetObject != 0 || row.TargetBTF != 0 || row.TargetName != strings.TrimPrefix(ps.SectionName, "tp_btf/")) {
			return fmt.Errorf("fence link attach mismatch")
		}
		previous := ebpf.MapID(0)
		for _, id := range row.MapIDs {
			if !mapIDs[id] || id <= previous {
				return fmt.Errorf("fence program references foreign/duplicate maps")
			}
			previous = id
		}
		expectedIDs := []ebpf.MapID{}
		referenced := map[string]bool{}
		for _, ins := range ps.Instructions {
			if !ins.IsLoadFromMap() {
				continue
			}
			name := ins.Reference()
			if spec.Maps[name] == nil {
				return fmt.Errorf("fence program has unresolved map reference %q", name)
			}
			referenced[name] = true
		}
		for _, mapRow := range m.Maps {
			if referenced[mapRow.Name] {
				expectedIDs = append(expectedIDs, mapRow.ID)
			}
		}
		slices.Sort(expectedIDs)
		if !slices.Equal(expectedIDs, row.MapIDs) {
			return fmt.Errorf("fence program map graph differs from ELF")
		}
		names[row.Name], linkIDs[row.ID], progIDs[row.ProgramID] = true, true, true
	}
	return nil
}

func reopenFencePins(dir *os.File, spec *ebpf.CollectionSpec, boot, digest string) (_ *pinnedFence, retErr error) {
	p := &pinnedFence{dir: dir, maps: map[string]*ebpf.Map{}, programs: map[string]*ebpf.Program{}, links: map[string]link.Link{}}
	defer func() {
		if retErr != nil {
			_ = p.Close()
		}
	}()
	expected := map[string]bool{"manifest": true}
	for name := range spec.Maps {
		expected[fenceMapPin(name)] = true
	}
	for name := range spec.Programs {
		expected[fenceLinkPin(name)] = true
	}
	entries, err := os.ReadDir(procDirectory(dir))
	if err != nil {
		return nil, err
	}
	if len(entries) != len(expected) {
		return nil, fmt.Errorf("incomplete/extra fence pins (retained)")
	}
	for _, entry := range entries {
		if !expected[entry.Name()] || entry.Type()&os.ModeSymlink != 0 || entry.IsDir() {
			return nil, fmt.Errorf("unexpected fence pin %q", entry.Name())
		}
	}
	p.manifest, err = ebpf.LoadPinnedMap(fencePinPath(dir, "manifest"), nil)
	if err != nil {
		return nil, err
	}
	mi, err := p.manifest.Info()
	if err != nil {
		return nil, err
	}
	if mi.Type != ebpf.Array || mi.KeySize != 4 || mi.ValueSize != fenceManifestSize || mi.MaxEntries != 1 || mi.Flags != 0 || !mi.Frozen() {
		return nil, fmt.Errorf("fence manifest is not a frozen singleton array")
	}
	value := make([]byte, fenceManifestSize)
	if err := p.manifest.Lookup(uint32(0), value); err != nil {
		return nil, err
	}
	manifest, err := decodeFenceManifest(value)
	if err != nil {
		return nil, err
	}
	if err := manifest.check(spec, boot, digest); err != nil {
		return nil, err
	}
	for _, row := range manifest.Maps {
		m, err := ebpf.LoadPinnedMap(fencePinPath(dir, fenceMapPin(row.Name)), nil)
		if err != nil {
			return nil, err
		}
		p.maps[row.Name] = m
		actual, err := inspectFenceMap(row.Name, m)
		if err != nil {
			return nil, err
		}
		if actual != row {
			return nil, fmt.Errorf("fence map %q changed", row.Name)
		}
	}
	for _, row := range manifest.Links {
		l, err := link.LoadPinnedLink(fencePinPath(dir, fenceLinkPin(row.Name)), nil)
		if err != nil {
			return nil, err
		}
		p.links[row.Name] = l
		prog, err := ebpf.NewProgramFromID(row.ProgramID)
		if err != nil {
			return nil, err
		}
		p.programs[row.Name] = prog
		actual, err := inspectFenceLink(row.Name, l, prog, spec.Programs[row.Name])
		if err != nil {
			return nil, err
		}
		if !equalFenceLink(actual, row) {
			return nil, fmt.Errorf("fence link %q changed", row.Name)
		}
	}
	return p, nil
}

func equalFenceLink(a, b fencePinnedLink) bool {
	return a.Name == b.Name && a.ID == b.ID && a.Type == b.Type &&
		a.ProgramID == b.ProgramID && a.ProgramType == b.ProgramType &&
		a.Tag == b.Tag && a.Section == b.Section && a.Attach == b.Attach &&
		a.TargetBTF == b.TargetBTF && a.TargetName == b.TargetName && slices.Equal(a.MapIDs, b.MapIDs)
}
