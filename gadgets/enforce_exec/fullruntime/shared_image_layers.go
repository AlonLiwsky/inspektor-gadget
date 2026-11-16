// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// G020 image layers: the Go side of the generation-qualified shared image
// index. A file is from-image when the exec'd real inode lives on one of the
// bound container's overlay LOWER layers; the index keys are the lower-layer
// root directories {ino, major, minor}, at most sharedImageLayersMax per
// binding. Discovery is Resolve (snapshotter mounts + live kernel cross-check)
// -> Keys (statx of each lower root in the host mount namespace) -> Reattest
// (the same cross-check and keys again, right before sealing).

// ErrSharedImageIndexUnsupported is wrapped by every refusal of a container
// whose rootfs the image index cannot represent exactly (wrong snapshotter or
// mount type, metacopy, data-only or unresolvable lowers, over quota, a lower
// on a filesystem other than XFS/ext4).
var ErrSharedImageIndexUnsupported = errors.New("shared image index unsupported")

// ErrSharedImageAttestation is wrapped when the snapshotter's view and the
// live kernel state of the bound init disagree, or the init is gone.
var ErrSharedImageAttestation = errors.New("shared image layer attestation failed")

// SharedImageReason names why discovery refused or failed.
type SharedImageReason string

const (
	SharedImageReasonSnapshotter      SharedImageReason = "snapshotter"       // not the overlayfs snapshotter
	SharedImageReasonMountType        SharedImageReason = "mount-type"        // not exactly one overlay mount
	SharedImageReasonMetacopy         SharedImageReason = "metacopy"          // metacopy=on: data may live on another layer
	SharedImageReasonDataOnlyLower    SharedImageReason = "data-only-lower"   // "::" / datadir+ lowers
	SharedImageReasonRelativeLowerdir SharedImageReason = "relative-lowerdir" // lowerdir not resolvable to absolute paths
	SharedImageReasonOverlayOption    SharedImageReason = "overlay-option"    // unknown/duplicate/malformed overlay option
	SharedImageReasonLowerQuota       SharedImageReason = "lower-quota"       // more lowers than the per-binding quota
	SharedImageReasonLowerFilesystem  SharedImageReason = "lower-filesystem"  // lower root not on XFS or ext4
	SharedImageReasonInit             SharedImageReason = "init-identity"     // bound init died or changed
	SharedImageReasonRootMount        SharedImageReason = "root-mount"        // mountinfo "/" not the snapshot overlay
	SharedImageReasonRootDevice       SharedImageReason = "root-device"       // stat(/proc/<pid>/root).st_dev != overlay dev
	SharedImageReasonLowerIdentity    SharedImageReason = "lower-identity"    // lower root keys changed before sealing
)

// SharedImageLayerError is the typed refusal/failure; it unwraps to
// ErrSharedImageIndexUnsupported or ErrSharedImageAttestation.
type SharedImageLayerError struct {
	Kind   error
	Reason SharedImageReason
	Detail string
}

func (e *SharedImageLayerError) Error() string {
	return fmt.Sprintf("%s: %s: %s", e.Kind, e.Reason, e.Detail)
}

func (e *SharedImageLayerError) Unwrap() error { return e.Kind }

func sharedImageUnsupported(reason SharedImageReason, format string, args ...any) error {
	return &SharedImageLayerError{Kind: ErrSharedImageIndexUnsupported, Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

func sharedImageAttestFailed(reason SharedImageReason, format string, args ...any) error {
	return &SharedImageLayerError{Kind: ErrSharedImageAttestation, Reason: reason, Detail: fmt.Sprintf(format, args...)}
}

const (
	// sharedImageLayersMax is the BPF index ceiling of lower roots per
	// binding; it is also the default per-binding quota.
	sharedImageLayersMax = 128
	// sharedImageOverlaySnapshotter is the only admitted containerd snapshotter.
	sharedImageOverlaySnapshotter = "overlayfs"
	// Kernel dev_t (include/linux/kdev_t.h): MINORBITS 20, major 12 bits.
	sharedKernelMinorBits = 20
	sharedKernelMinorMask = 1<<sharedKernelMinorBits - 1
	sharedKernelMajorMax  = 1<<(32-sharedKernelMinorBits) - 1
	// sharedImageMountinfoMax bounds one mountinfo read: 128 lowers of
	// ~100-byte paths exceed the 64KiB generic pinned proc read.
	sharedImageMountinfoMax = 1 << 20
	// Accepted lower filesystems (statfs f_type). EXT4_SUPER_MAGIC is shared
	// by ext2/ext3/ext4, all served by the ext4 driver on admitted kernels.
	sharedXFSMagic  = 0x58465342
	sharedExt4Magic = 0xef53
)

// sharedKernelDev encodes major/minor exactly as the kernel's internal
// dev_t (MKDEV: major<<20 | minor), which is what BPF reads from
// super_block->s_dev. It is NOT the userspace st_dev encoding
// (new_encode_dev / glibc makedev), which interleaves the minor's low byte.
func sharedKernelDev(major, minor uint32) (uint32, error) {
	if major > sharedKernelMajorMax || minor > sharedKernelMinorMask {
		return 0, fmt.Errorf("device %d:%d does not fit the kernel dev_t", major, minor)
	}
	return major<<sharedKernelMinorBits | minor, nil
}

// SharedImageLayerKey is one lower-layer root directory identity in the host
// mount namespace (statx stx_ino, stx_dev_major, stx_dev_minor).
type SharedImageLayerKey struct {
	Ino          uint64
	Major, Minor uint32
}

// KernelDev is the key's device in the kernel's internal dev_t encoding.
func (k SharedImageLayerKey) KernelDev() (uint32, error) { return sharedKernelDev(k.Major, k.Minor) }

// sharedImageMount is one snapshotter mount (containerd mount.Mount).
type sharedImageMount struct {
	Type, Source string
	Options      []string
}

// sharedImageRootfs is a container's rootfs snapshot: the snapshotter, the
// snapshot key, and the snapshotter's Mounts(key).
type sharedImageRootfs struct {
	Snapshotter, Key string
	Mounts           []sharedImageMount
}

// sharedImageLayerSource resolves a container's rootfs snapshot mounts from
// the container runtime.
type sharedImageLayerSource interface {
	RootfsMounts(ctx context.Context, containerID string) (sharedImageRootfs, error)
}

// sharedImageInitView is one bracketed read of the bound init's live state:
// StartTicks before and EndTicks after the reads, all through one handle on
// the init (a /proc/<pid> directory, which never follows PID reuse).
type sharedImageInitView struct {
	StartTicks, EndTicks uint64
	MountNS              uint64
	Mountinfo            []byte
	// RootMajor/RootMinor decode stat(/proc/<pid>/root).st_dev.
	RootMajor, RootMinor uint32
}

// sharedImageLowerStat is one lower root, statfs'd and statx'd through one
// O_PATH handle.
type sharedImageLowerStat struct {
	Magic int64
	Dir   bool
	Key   SharedImageLayerKey
}

// sharedImageHost reads live kernel state; tests substitute it.
type sharedImageHost interface {
	InitView(init SharedInitIdentity) (sharedImageInitView, error)
	LowerRoot(path string) (sharedImageLowerStat, error)
}

// SharedImageLayers is one container's attested lower layers.
type SharedImageLayers struct {
	ContainerID string
	Init        SharedInitIdentity
	Snapshotter string
	SnapshotKey string
	UpperDir    string
	// Lowers are the snapshot's lowerdir entries, top to bottom.
	Lowers []string
	// OverlayDev is the container root overlay's super_block s_dev in the
	// kernel's internal encoding (MKDEV(0, minor)), as BPF reads it.
	OverlayDev uint32
	// Keys are the deduplicated lower root keys (set by Keys); Expected is
	// their count, the exact number of index cells this binding fills.
	Keys     []SharedImageLayerKey
	Expected uint64
}

// sharedImageLayerResolver discovers and attests a container's lowers.
type sharedImageLayerResolver struct {
	source sharedImageLayerSource
	host   sharedImageHost
	quota  uint64
}

// newSharedImageLayerResolver takes the per-binding quota
// (SharedProfile.PerBinding.Images); 0 selects sharedImageLayersMax.
func newSharedImageLayerResolver(source sharedImageLayerSource, host sharedImageHost, quota uint64) (*sharedImageLayerResolver, error) {
	if source == nil || host == nil {
		return nil, fmt.Errorf("image layer source and host required")
	}
	if quota == 0 {
		quota = sharedImageLayersMax
	}
	if quota > sharedImageLayersMax {
		return nil, fmt.Errorf("image layer quota %d exceeds the index ceiling %d", quota, sharedImageLayersMax)
	}
	return &sharedImageLayerResolver{source: source, host: host, quota: quota}, nil
}

// Resolve reads the container's rootfs snapshot, validates it and
// cross-checks it against the bound init's live root mount.
func (r *sharedImageLayerResolver) Resolve(ctx context.Context, containerID string, init SharedInitIdentity) (*SharedImageLayers, error) {
	if containerID == "" {
		return nil, fmt.Errorf("container ID required")
	}
	if init.TGID == 0 || init.StartTicks == 0 || init.MountNS == 0 {
		return nil, sharedImageAttestFailed(SharedImageReasonInit, "complete init identity required")
	}
	rootfs, err := r.source.RootfsMounts(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("container %s rootfs mounts: %w", containerID, err)
	}
	upper, lowers, err := parseSharedImageSnapshot(rootfs, r.quota)
	if err != nil {
		return nil, err
	}
	layers := &SharedImageLayers{
		ContainerID: containerID, Init: init, Snapshotter: rootfs.Snapshotter, SnapshotKey: rootfs.Key,
		UpperDir: upper, Lowers: lowers,
	}
	dev, err := r.attestInit(layers)
	if err != nil {
		return nil, err
	}
	layers.OverlayDev = dev
	return layers, nil
}

// Keys statx's each lower root in the host mount namespace, refuses any not
// on XFS/ext4, deduplicates and records Keys/Expected.
func (r *sharedImageLayerResolver) Keys(layers *SharedImageLayers) ([]SharedImageLayerKey, error) {
	keys, err := r.lowerKeys(layers.UpperDir, layers.Lowers)
	if err != nil {
		return nil, err
	}
	layers.Keys, layers.Expected = keys, uint64(len(keys))
	return keys, nil
}

// Reattest repeats the live cross-check and the key derivation right before
// sealing; any change fails closed.
func (r *sharedImageLayerResolver) Reattest(ctx context.Context, layers *SharedImageLayers) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if layers == nil || layers.Keys == nil {
		return fmt.Errorf("image layers not keyed")
	}
	dev, err := r.attestInit(layers)
	if err != nil {
		return err
	}
	if dev != layers.OverlayDev {
		return sharedImageAttestFailed(SharedImageReasonRootDevice, "overlay dev changed %#x -> %#x", layers.OverlayDev, dev)
	}
	keys, err := r.lowerKeys(layers.UpperDir, layers.Lowers)
	if err != nil {
		return err
	}
	if len(keys) != len(layers.Keys) {
		return sharedImageAttestFailed(SharedImageReasonLowerIdentity, "lower key count changed %d -> %d", len(layers.Keys), len(keys))
	}
	for i := range keys {
		if keys[i] != layers.Keys[i] {
			return sharedImageAttestFailed(SharedImageReasonLowerIdentity, "lower %d key changed %+v -> %+v", i, layers.Keys[i], keys[i])
		}
	}
	return nil
}

// lowerKeys derives the lower root keys and refuses when the container's own
// upperdir has the same host {ino,dev} as any lower: the classifier would
// otherwise index writable upper content as image content.
func (r *sharedImageLayerResolver) lowerKeys(upper string, lowers []string) ([]SharedImageLayerKey, error) {
	seen := make(map[SharedImageLayerKey]struct{}, len(lowers))
	keys := make([]SharedImageLayerKey, 0, len(lowers))
	for _, lower := range lowers {
		st, err := r.host.LowerRoot(lower)
		if err != nil {
			return nil, fmt.Errorf("lower %s: %w", lower, err)
		}
		if st.Magic != sharedXFSMagic && st.Magic != sharedExt4Magic {
			return nil, sharedImageUnsupported(SharedImageReasonLowerFilesystem, "lower %s is on filesystem magic %#x (only XFS and ext4)", lower, st.Magic)
		}
		if !st.Dir || st.Key.Ino == 0 {
			return nil, sharedImageUnsupported(SharedImageReasonLowerFilesystem, "lower %s is not a directory", lower)
		}
		if _, err := st.Key.KernelDev(); err != nil {
			return nil, sharedImageUnsupported(SharedImageReasonLowerFilesystem, "lower %s: %v", lower, err)
		}
		if _, dup := seen[st.Key]; dup {
			continue
		}
		seen[st.Key] = struct{}{}
		keys = append(keys, st.Key)
	}
	up, err := r.host.LowerRoot(upper)
	if err != nil {
		return nil, fmt.Errorf("upperdir %s: %w", upper, err)
	}
	if _, alias := seen[up.Key]; alias {
		return nil, sharedImageAttestFailed(SharedImageReasonLowerIdentity, "upperdir %s has the same key %+v as a lower layer", upper, up.Key)
	}
	return keys, nil
}

// attestInit cross-checks layers against the bound init's live state and
// returns the root overlay's kernel dev_t.
func (r *sharedImageLayerResolver) attestInit(layers *SharedImageLayers) (uint32, error) {
	init := layers.Init
	view, err := r.host.InitView(init)
	if err != nil {
		return 0, sharedImageAttestFailed(SharedImageReasonInit, "init %d: %v", init.TGID, err)
	}
	if view.StartTicks != init.StartTicks || view.EndTicks != init.StartTicks {
		return 0, sharedImageAttestFailed(SharedImageReasonInit, "init %d start ticks %d/%d, bound %d", init.TGID, view.StartTicks, view.EndTicks, init.StartTicks)
	}
	if view.MountNS != init.MountNS {
		return 0, sharedImageAttestFailed(SharedImageReasonInit, "init %d mount namespace %d, bound %d", init.TGID, view.MountNS, init.MountNS)
	}
	root, err := parseSharedRootMount(view.Mountinfo)
	if err != nil {
		return 0, err
	}
	if root.FSType != "overlay" || root.Major != 0 {
		return 0, sharedImageAttestFailed(SharedImageReasonRootMount, "root is %s %d:%d, not an anonymous overlay", root.FSType, root.Major, root.Minor)
	}
	opts, err := parseSharedOverlayOptions(root.SuperOptions, false)
	if err != nil {
		return 0, err
	}
	if opts.upper != layers.UpperDir {
		return 0, sharedImageAttestFailed(SharedImageReasonRootMount, "root upperdir %q, snapshot %q", opts.upper, layers.UpperDir)
	}
	if err := matchSharedKernelLowers(opts.lowers, layers.Lowers); err != nil {
		return 0, err
	}
	dev, err := sharedKernelDev(root.Major, root.Minor)
	if err != nil {
		return 0, sharedImageAttestFailed(SharedImageReasonRootMount, "%v", err)
	}
	if view.RootMajor != root.Major || view.RootMinor != root.Minor {
		return 0, sharedImageAttestFailed(SharedImageReasonRootDevice, "root st_dev %d:%d, mountinfo %d:%d", view.RootMajor, view.RootMinor, root.Major, root.Minor)
	}
	return dev, nil
}

// parseSharedImageSnapshot validates the snapshotter's view and returns the
// upperdir and lowers.
func parseSharedImageSnapshot(rootfs sharedImageRootfs, quota uint64) (string, []string, error) {
	if rootfs.Snapshotter != sharedImageOverlaySnapshotter {
		return "", nil, sharedImageUnsupported(SharedImageReasonSnapshotter, "snapshotter %q (only %q)", rootfs.Snapshotter, sharedImageOverlaySnapshotter)
	}
	if len(rootfs.Mounts) != 1 || rootfs.Mounts[0].Type != "overlay" {
		types := make([]string, len(rootfs.Mounts))
		for i, m := range rootfs.Mounts {
			types[i] = m.Type
		}
		return "", nil, sharedImageUnsupported(SharedImageReasonMountType, "snapshot %q mounts %v (need exactly one overlay)", rootfs.Key, types)
	}
	opts, err := parseSharedOverlayOptions(rootfs.Mounts[0].Options, true)
	if err != nil {
		return "", nil, err
	}
	if opts.upper == "" {
		return "", nil, sharedImageUnsupported(SharedImageReasonOverlayOption, "snapshot %q has no upperdir (not an active snapshot)", rootfs.Key)
	}
	for _, lower := range opts.lowers {
		if !sharedAbsClean(lower) {
			return "", nil, sharedImageUnsupported(SharedImageReasonRelativeLowerdir, "lowerdir %q is not an absolute clean path", lower)
		}
	}
	if uint64(len(opts.lowers)) > quota {
		return "", nil, sharedImageUnsupported(SharedImageReasonLowerQuota, "%d lowers exceed the per-binding quota %d", len(opts.lowers), quota)
	}
	return opts.upper, opts.lowers, nil
}

func sharedAbsClean(p string) bool { return filepath.IsAbs(p) && filepath.Clean(p) == p }

type sharedOverlayOptions struct {
	upper  string
	lowers []string
}

// sharedSnapshotOverlayOptions is the allowlist of overlay option keys a
// snapshot mount may carry (containerd's overlay snapshotter plus its
// configurable mount options). Mountinfo super options are kernel-printed
// and only checked for the keys that matter.
var sharedSnapshotOverlayOptions = map[string]bool{
	"lowerdir": true, "upperdir": true, "workdir": true, "index": true, "userxattr": true,
	"redirect_dir": true, "volatile": true, "xino": true, "metacopy": true, "uidmap": true,
	"gidmap": true, "nfs_export": true, "ro": true, "rw": true,
}

// parseSharedOverlayOptions extracts upperdir and the ordered lowers,
// refusing metacopy=on and data-only lowers. strict applies the snapshot
// option allowlist and requires absolute upperdir.
func parseSharedOverlayOptions(options []string, strict bool) (sharedOverlayOptions, error) {
	var out sharedOverlayOptions
	seen := map[string]bool{}
	lowerdir, appended := false, false
	for _, opt := range options {
		key, value, hasValue := strings.Cut(opt, "=")
		if strict && !sharedSnapshotOverlayOptions[key] {
			return out, sharedImageUnsupported(SharedImageReasonOverlayOption, "overlay option %q", key)
		}
		if seen[key] && key != "lowerdir+" {
			return out, sharedImageUnsupported(SharedImageReasonOverlayOption, "duplicate overlay option %q", key)
		}
		seen[key] = true
		switch key {
		case "metacopy":
			if value != "off" {
				return out, sharedImageUnsupported(SharedImageReasonMetacopy, "metacopy=%s: file data may live on a different layer than its inode", value)
			}
		case "datadir+":
			return out, sharedImageUnsupported(SharedImageReasonDataOnlyLower, "data-only lower %q", value)
		case "upperdir":
			if !hasValue || !sharedAbsClean(value) {
				return out, sharedImageUnsupported(SharedImageReasonOverlayOption, "upperdir %q is not an absolute clean path", value)
			}
			out.upper = value
		case "lowerdir":
			lowerdir = true
			lowers, err := splitSharedLowerdir(value)
			if err != nil {
				return out, err
			}
			out.lowers = lowers
		case "lowerdir+":
			appended = true
			if err := checkSharedLowerPath(value); err != nil {
				return out, err
			}
			out.lowers = append(out.lowers, value)
		}
	}
	if lowerdir && appended {
		return out, sharedImageUnsupported(SharedImageReasonOverlayOption, "both lowerdir and lowerdir+")
	}
	if len(out.lowers) == 0 {
		return out, sharedImageUnsupported(SharedImageReasonOverlayOption, "overlay without lowers")
	}
	return out, nil
}

// splitSharedLowerdir splits a lowerdir value; "::" introduces data-only
// lowers.
func splitSharedLowerdir(value string) ([]string, error) {
	if strings.Contains(value, "::") {
		return nil, sharedImageUnsupported(SharedImageReasonDataOnlyLower, "lowerdir %q has data-only lowers", value)
	}
	lowers := strings.Split(value, ":")
	for _, lower := range lowers {
		if err := checkSharedLowerPath(lower); err != nil {
			return nil, err
		}
	}
	return lowers, nil
}

func checkSharedLowerPath(lower string) error {
	if lower == "" {
		return sharedImageUnsupported(SharedImageReasonOverlayOption, "empty lowerdir entry")
	}
	// Escaped ':' / ',' ("\:") cannot be split exactly; containerd never
	// emits them.
	if strings.ContainsRune(lower, '\\') {
		return sharedImageUnsupported(SharedImageReasonOverlayOption, "escaped lowerdir entry %q", lower)
	}
	return nil
}

// matchSharedKernelLowers requires the kernel's lowers to be the snapshot's,
// in order. An absolute kernel entry must equal the snapshot entry; a
// relative one (containerd compacts long lowerdir options relative to their
// common directory at mount time) must be the snapshot entry with one common
// directory prefix shared by every relative entry. Anything else cannot be
// resolved absolutely and is refused.
func matchSharedKernelLowers(kernel, snapshot []string) error {
	if len(kernel) != len(snapshot) {
		return sharedImageAttestFailed(SharedImageReasonRootMount, "root has %d lowers, snapshot %d", len(kernel), len(snapshot))
	}
	base := ""
	for i, k := range kernel {
		s := snapshot[i]
		if filepath.IsAbs(k) {
			if k != s {
				return sharedImageAttestFailed(SharedImageReasonRootMount, "root lower %d %q, snapshot %q", i, k, s)
			}
			continue
		}
		if filepath.Clean(k) != k || k == "." || strings.HasPrefix(k, "../") || k == ".." || !strings.HasSuffix(s, "/"+k) {
			return sharedImageUnsupported(SharedImageReasonRelativeLowerdir, "root lower %d %q does not resolve to snapshot %q", i, k, s)
		}
		dir := strings.TrimSuffix(s, "/"+k)
		if base == "" {
			base = dir
		} else if dir != base {
			return sharedImageUnsupported(SharedImageReasonRelativeLowerdir, "root lower %d %q resolves against %q, not %q", i, k, dir, base)
		}
	}
	return nil
}

// sharedMountinfoEntry is one parsed /proc/<pid>/mountinfo line.
type sharedMountinfoEntry struct {
	Major, Minor     uint32
	Root, MountPoint string
	FSType, Source   string
	SuperOptions     []string
}

// parseSharedMountinfoLine parses one mountinfo line (proc(5)), unescaping
// the octal escapes the kernel applies to paths and options.
func parseSharedMountinfoLine(line string) (sharedMountinfoEntry, error) {
	var e sharedMountinfoEntry
	fields := strings.Split(line, " ")
	sep := -1
	for i := 6; i < len(fields); i++ {
		if fields[i] == "-" {
			sep = i
			break
		}
	}
	if len(fields) < 10 || sep < 0 || len(fields) != sep+4 {
		return e, fmt.Errorf("malformed mountinfo line %q", sharedTruncate(line))
	}
	majorText, minorText, ok := strings.Cut(fields[2], ":")
	if !ok {
		return e, fmt.Errorf("mountinfo device %q", fields[2])
	}
	major, err := strconv.ParseUint(majorText, 10, 32)
	if err != nil {
		return e, fmt.Errorf("mountinfo major: %w", err)
	}
	minor, err := strconv.ParseUint(minorText, 10, 32)
	if err != nil {
		return e, fmt.Errorf("mountinfo minor: %w", err)
	}
	e.Major, e.Minor = uint32(major), uint32(minor)
	e.Root, e.MountPoint = unescapeSharedMountinfo(fields[3]), unescapeSharedMountinfo(fields[4])
	e.FSType, e.Source = unescapeSharedMountinfo(fields[sep+1]), unescapeSharedMountinfo(fields[sep+2])
	// Commas inside values are escaped (\054), so splitting first is exact.
	for _, opt := range strings.Split(fields[sep+3], ",") {
		e.SuperOptions = append(e.SuperOptions, unescapeSharedMountinfo(opt))
	}
	return e, nil
}

// parseSharedRootMount returns the single mountinfo entry mounted at "/".
func parseSharedRootMount(mountinfo []byte) (sharedMountinfoEntry, error) {
	var root sharedMountinfoEntry
	found := 0
	for _, line := range strings.Split(strings.TrimRight(string(mountinfo), "\n"), "\n") {
		if line == "" {
			continue
		}
		e, err := parseSharedMountinfoLine(line)
		if err != nil {
			return root, sharedImageAttestFailed(SharedImageReasonRootMount, "%v", err)
		}
		if e.MountPoint == "/" {
			root = e
			found++
		}
	}
	if found != 1 {
		return root, sharedImageAttestFailed(SharedImageReasonRootMount, "%d mountinfo entries at \"/\" (need exactly one)", found)
	}
	return root, nil
}

// unescapeSharedMountinfo reverses the kernel's \ooo octal escaping.
func unescapeSharedMountinfo(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+4 <= len(s) {
			if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(v))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func sharedTruncate(s string) string {
	if len(s) > 128 {
		return s[:128] + "..."
	}
	return s
}

// sharedImageProcHost is the live sharedImageHost: ProcRoot is the host PID
// namespace's procfs ("/proc" when the publisher shares it), HostRoot the
// host mount namespace's root as seen by the publisher ("/" or e.g. "/host");
// lower paths are resolved beneath it (RESOLVE_IN_ROOT).
type sharedImageProcHost struct {
	ProcRoot, HostRoot string
}

func (h sharedImageProcHost) InitView(init SharedInitIdentity) (sharedImageInitView, error) {
	var view sharedImageInitView
	procRoot := h.ProcRoot
	if procRoot == "" {
		procRoot = "/proc"
	}
	dir, err := os.OpenFile(filepath.Join(procRoot, strconv.FormatUint(uint64(init.TGID), 10)), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return view, err
	}
	defer dir.Close()
	ticks := func() (uint64, error) {
		start, err := readPinnedInitStart(dir, init.TGID)
		if err != nil {
			return 0, err
		}
		return strconv.ParseUint(start, 10, 64)
	}
	if view.StartTicks, err = ticks(); err != nil {
		return view, err
	}
	var ns unix.Stat_t
	if err = unix.Fstatat(int(dir.Fd()), "ns/mnt", &ns, 0); err != nil {
		return view, fmt.Errorf("ns/mnt: %w", err)
	}
	view.MountNS = ns.Ino
	fd, err := unix.Openat(int(dir.Fd()), "mountinfo", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return view, fmt.Errorf("mountinfo: %w", err)
	}
	mi := os.NewFile(uintptr(fd), "mountinfo")
	view.Mountinfo, err = io.ReadAll(io.LimitReader(mi, sharedImageMountinfoMax+1))
	mi.Close()
	if err != nil {
		return view, fmt.Errorf("mountinfo: %w", err)
	}
	if len(view.Mountinfo) > sharedImageMountinfoMax {
		return view, fmt.Errorf("oversized mountinfo")
	}
	// "root" is a magic link to the init's root dentry; following it stats
	// the container root overlay itself.
	var root unix.Stat_t
	if err = unix.Fstatat(int(dir.Fd()), "root", &root, 0); err != nil {
		return view, fmt.Errorf("root: %w", err)
	}
	view.RootMajor, view.RootMinor = unix.Major(root.Dev), unix.Minor(root.Dev)
	if view.EndTicks, err = ticks(); err != nil {
		return view, err
	}
	return view, nil
}

func (h sharedImageProcHost) LowerRoot(path string) (sharedImageLowerStat, error) {
	var out sharedImageLowerStat
	hostRoot := h.HostRoot
	if hostRoot == "" {
		hostRoot = "/"
	}
	rootFD, err := unix.Open(hostRoot, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return out, fmt.Errorf("host root: %w", err)
	}
	defer unix.Close(rootFD)
	fd, err := unix.Openat2(rootFD, strings.TrimPrefix(path, "/"), &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_IN_ROOT | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return out, err
	}
	defer unix.Close(fd)
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		return out, err
	}
	var stx unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_STATX_SYNC_AS_STAT, unix.STATX_TYPE|unix.STATX_INO, &stx); err != nil {
		return out, err
	}
	if stx.Mask&(unix.STATX_TYPE|unix.STATX_INO) != unix.STATX_TYPE|unix.STATX_INO {
		return out, fmt.Errorf("statx did not return type and inode")
	}
	out.Magic = int64(fs.Type)
	out.Dir = stx.Mode&unix.S_IFMT == unix.S_IFDIR
	out.Key = SharedImageLayerKey{Ino: stx.Ino, Major: stx.Dev_major, Minor: stx.Dev_minor}
	return out, nil
}

// ErrSharedImageLedger is wrapped by every image ledger refusal.
var ErrSharedImageLedger = errors.New("shared image ledger")

// SharedImageLedgerEntry is one binding generation's image key cells:
// Reserved before the kernel insert, Present once the kernel confirmed them.
type SharedImageLedgerEntry struct{ Reserved, Present uint64 }

type sharedImageLedgerKey struct {
	slot       uint32
	generation uint64
}

// sharedImageLedger is the exact Go-side accounting of image key cells,
// per binding slot and evidence generation, that the health poller compares
// with the kernel map counts. A binding's generations together stay within
// the per-binding quota, all bindings within the global pool.
type sharedImageLedger struct {
	mu                sync.Mutex
	perBinding, total uint64
	entries           map[sharedImageLedgerKey]SharedImageLedgerEntry
}

func newSharedImageLedger(perBinding, total uint64) (*sharedImageLedger, error) {
	if perBinding == 0 || total == 0 || perBinding > total {
		return nil, fmt.Errorf("%w: invalid quota %d/%d", ErrSharedImageLedger, perBinding, total)
	}
	return &sharedImageLedger{perBinding: perBinding, total: total, entries: map[sharedImageLedgerKey]SharedImageLedgerEntry{}}, nil
}

// sums returns the slot's reserved cells and the global reserved cells; l.mu
// is held.
func (l *sharedImageLedger) sums(slot uint32) (binding, total uint64) {
	for k, e := range l.entries {
		total += e.Reserved
		if k.slot == slot {
			binding += e.Reserved
		}
	}
	return binding, total
}

// Reserve charges n cells for one new binding generation.
func (l *sharedImageLedger) Reserve(slot uint32, generation, n uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := sharedImageLedgerKey{slot, generation}
	if _, ok := l.entries[key]; ok {
		return fmt.Errorf("%w: slot %d generation %d already reserved", ErrSharedImageLedger, slot, generation)
	}
	if n == 0 {
		return fmt.Errorf("%w: slot %d generation %d reserves no cells", ErrSharedImageLedger, slot, generation)
	}
	binding, total := l.sums(slot)
	if n > l.perBinding-binding {
		return fmt.Errorf("%w: slot %d needs %d cells, %d of %d reserved", ErrSharedImageLedger, slot, n, binding, l.perBinding)
	}
	if n > l.total-total {
		return fmt.Errorf("%w: pool needs %d cells, %d of %d reserved", ErrSharedImageLedger, n, total, l.total)
	}
	l.entries[key] = SharedImageLedgerEntry{Reserved: n}
	return nil
}

// SetPresent records the kernel-confirmed cell count (≤ Reserved).
func (l *sharedImageLedger) SetPresent(slot uint32, generation, n uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := sharedImageLedgerKey{slot, generation}
	e, ok := l.entries[key]
	if !ok {
		return fmt.Errorf("%w: slot %d generation %d not reserved", ErrSharedImageLedger, slot, generation)
	}
	if n > e.Reserved {
		return fmt.Errorf("%w: slot %d generation %d present %d exceeds reserved %d", ErrSharedImageLedger, slot, generation, n, e.Reserved)
	}
	e.Present = n
	l.entries[key] = e
	return nil
}

// Release returns one binding generation's cells.
func (l *sharedImageLedger) Release(slot uint32, generation uint64) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	key := sharedImageLedgerKey{slot, generation}
	if _, ok := l.entries[key]; !ok {
		return fmt.Errorf("%w: slot %d generation %d not reserved", ErrSharedImageLedger, slot, generation)
	}
	delete(l.entries, key)
	return nil
}

// Entry returns one binding generation's accounting.
func (l *sharedImageLedger) Entry(slot uint32, generation uint64) (SharedImageLedgerEntry, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.entries[sharedImageLedgerKey{slot, generation}]
	return e, ok
}

// Binding sums a slot's generations.
func (l *sharedImageLedger) Binding(slot uint32) SharedImageLedgerEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out SharedImageLedgerEntry
	for k, e := range l.entries {
		if k.slot == slot {
			out.Reserved += e.Reserved
			out.Present += e.Present
		}
	}
	return out
}

// Totals sums every binding.
func (l *sharedImageLedger) Totals() SharedImageLedgerEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out SharedImageLedgerEntry
	for _, e := range l.entries {
		out.Reserved += e.Reserved
		out.Present += e.Present
	}
	return out
}

// CheckKernel compares a slot's Present cells with the kernel map's count
// for that slot; any difference is a health failure.
func (l *sharedImageLedger) CheckKernel(slot uint32, kernelCount uint64) error {
	if present := l.Binding(slot).Present; present != kernelCount {
		return fmt.Errorf("%w: slot %d ledger present %d, kernel %d", ErrSharedImageLedger, slot, present, kernelCount)
	}
	return nil
}
