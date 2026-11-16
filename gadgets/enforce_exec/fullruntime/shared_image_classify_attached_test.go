// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Mirrors enum se_image_class_reason in full/shared_image_classify.h.
const (
	imageClassHit = iota
	imageClassUpper
	imageClassNotOverlay
	imageClassForeignOverlay
	imageClassNoIndex
	imageClassAuth
	imageClassNested
	imageClassReadFault
	imageClassInsertUncertain
	imageClassDeleteUncertain
	imageClassPrepareRefused
	imageClassWritableLayer
	imageClassMemfd
	imageClassSlots
)

var imageClassNames = [imageClassSlots]string{
	"HIT", "UPPER", "NOT_OVERLAY", "FOREIGN_OVERLAY", "NO_INDEX", "AUTH",
	"NESTED", "READ_FAULT", "INSERT_UNCERTAIN", "DELETE_UNCERTAIN", "PREPARE_REFUSED", "WRITABLE_LAYER", "MEMFD",
}

type imageClassWitness struct{ Count [imageClassSlots]uint64 }

type layerKey struct {
	Handle       uint64
	Inode        uint64
	Major, Minor uint32
}

type imageClassProbe struct {
	collection *ebpf.Collection
	attached   link.Link
}

// TestSharedImageClassifyAttached exercises se_image_classify from a
// pass-through bprm_check_security probe against real overlay mounts on an
// exact shared-candidate kernel. Test object only: no product wiring,
// publisher, snapshot authority or enforcement claim.
func TestSharedImageClassifyAttached(t *testing.T) {
	object, helper := os.Getenv("IG_SHARED_IMAGE_CLASSIFY_OBJECT"), os.Getenv("IG_SHARED_IMAGE_CLASSIFY_HELPER")
	if object == "" && helper == "" {
		t.Skip("set IG_SHARED_IMAGE_CLASSIFY_OBJECT and IG_SHARED_IMAGE_CLASSIFY_HELPER on a disposable exact kernel")
	}
	if os.Geteuid() != 0 || !filepath.IsAbs(object) || !filepath.IsAbs(helper) {
		t.Fatal("root and absolute object/helper paths required")
	}
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		t.Fatal(err)
	}
	cstr := func(value []byte) string { return string(bytes.TrimRight(value, "\x00")) }
	if cstr(uname.Machine[:]) != "x86_64" {
		t.Fatal("exact x86_64 matrix only")
	}
	release := cstr(uname.Release[:])
	btfFile, err := os.Open("/sys/kernel/btf/vmlinux")
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	_, err = io.Copy(hash, btfFile)
	btfFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	layout, err := liveSharedImageOverlayLayout()
	if err != nil {
		t.Fatal(err)
	}
	if sharedCandidateKernelBTF[digest] != release {
		t.Fatalf("release %q does not match BTF %s", release, digest)
	}
	t.Logf("kernel %s BTF %s overlay layout %d", release, digest, layout)
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		t.Fatal(err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}

	tmp := t.TempDir()
	cgroup := filepath.Join("/sys/fs/cgroup", fmt.Sprintf("ig15-g020-image-%d", os.Getpid()))
	if err := os.Mkdir(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cgroup)
	var cgStat unix.Stat_t
	if err := unix.Stat(cgroup, &cgStat); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	dir := func(parts ...string) string {
		path := filepath.Join(append([]string{tmp}, parts...)...)
		if err := os.MkdirAll(path, 0o755); err != nil {
			t.Fatal(err)
		}
		return path
	}
	write := func(path string) {
		t.Helper()
		if err := os.WriteFile(path, binary, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	lower1, lower2, host := dir("lower1"), dir("lower2"), dir("host")
	for _, name := range []string{"untouched", "chmodme", "unlinkme", "bindtarget"} {
		write(filepath.Join(lower1, name))
	}
	write(filepath.Join(lower2, "deep"))
	write(filepath.Join(host, "true"))
	mount := func(merged, opts string) {
		t.Helper()
		if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
			t.Fatalf("overlay %s: %v", opts, err)
		}
		t.Cleanup(func() {
			if err := unix.Unmount(merged, unix.MNT_DETACH); err != nil {
				t.Errorf("unmount %s: %v", merged, err)
			}
		})
	}
	lowers := lower1 + ":" + lower2
	merged, merged2, readonly, nested := dir("merged"), dir("merged2"), dir("readonly"), dir("nested")
	mount(merged, fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,metacopy=off,index=off", lowers, dir("upper"), dir("work")))
	mount(merged2, fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,metacopy=off,index=off", lowers, dir("upper2"), dir("work2")))
	mount(readonly, fmt.Sprintf("lowerdir=%s", lowers))
	mount(nested, fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,metacopy=off,index=off", readonly, dir("uppern"), dir("workn")))
	devs := mountDevs(t)
	devOf := func(path string) uint32 {
		t.Helper()
		dev, ok := devs[path]
		if !ok {
			t.Fatalf("no mountinfo entry for %s", path)
		}
		return dev
	}
	imageDev, image2Dev, nestedDev := devOf(merged), devOf(merged2), devOf(nested)
	if imageDev == image2Dev {
		t.Fatal("second overlay shares the superblock dev")
	}
	const handle = uint64(0x6702000000000001)
	var keys []layerKey
	for _, root := range []string{lower1, lower2} {
		var st unix.Stat_t
		if err := unix.Stat(root, &st); err != nil {
			t.Fatal(err)
		}
		keys = append(keys, layerKey{handle, st.Ino, unix.Major(st.Dev), unix.Minor(st.Dev)})
	}
	t.Logf("image dev %d:%d second %d:%d nested %d:%d layer keys %+v", imageDev>>20, imageDev&0xfffff, image2Dev>>20, image2Dev&0xfffff, nestedDev>>20, nestedDev&0xfffff, keys)

	load := func(layout uint32, extra ...layerKey) *imageClassProbe {
		t.Helper()
		spec, err := ebpf.LoadCollectionSpec(object)
		if err != nil {
			t.Fatal(err)
		}
		const name = "se_image_classify_probe"
		program := spec.Programs[name]
		if program == nil || program.Type != ebpf.LSM || program.AttachTo != "bprm_check_security" {
			t.Fatal("exact bprm_check_security probe required")
		}
		variable := spec.Variables["se_image_ovl_layout"]
		if variable == nil || !variable.Constant() {
			t.Fatal("se_image_ovl_layout rodata constant required")
		}
		if err := variable.Set(layout); err != nil {
			t.Fatal(err)
		}
		collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{KernelTypes: kernel, LogLevel: ebpf.LogLevelStats, LogSizeStart: 1 << 20}})
		if err != nil {
			var verifier *ebpf.VerifierError
			if errors.As(err, &verifier) {
				t.Logf("verifier:\n%+v", verifier)
			}
			t.Fatal(err)
		}
		prog := collection.Programs[name]
		info, err := prog.Info()
		if err != nil {
			collection.Close()
			t.Fatal(err)
		}
		insns, _ := info.VerifiedInstructions()
		t.Logf("layout %d verifier: verified_insns=%d %s", layout, insns, verifierStats(prog.VerifierLog))
		maps := collection.Maps
		if maps["se_image_keys"] == nil || maps["se_image_keys"].KeySize() != 24 || maps["probe_config"].ValueSize() != 24 || maps["probe_results"].ValueSize() != 16 || maps["se_image_class_witnesses"].ValueSize() != 104 {
			collection.Close()
			t.Fatal("malformed probe maps")
		}
		for _, key := range append(append([]layerKey{}, keys...), extra...) {
			if err := maps["se_image_keys"].Update(key, uint8(1), ebpf.UpdateNoExist); err != nil {
				collection.Close()
				t.Fatal(err)
			}
		}
		attached, err := link.AttachLSM(link.LSMOptions{Program: prog})
		if err != nil {
			collection.Close()
			t.Fatal(err)
		}
		return &imageClassProbe{collection, attached}
	}
	witness := func(p *imageClassProbe) imageClassWitness {
		t.Helper()
		var perCPU []imageClassWitness
		if err := p.collection.Maps["se_image_class_witnesses"].Lookup(uint32(0), &perCPU); err != nil {
			t.Fatal(err)
		}
		var sum imageClassWitness
		for _, cpu := range perCPU {
			for i := range sum.Count {
				sum.Count[i] += cpu.Count[i]
			}
		}
		return sum
	}
	type config struct {
		Cgroup, Handle  uint64
		ImageDev, Armed uint32
	}
	type result struct {
		Value                 int32
		Count                 uint32
		BTFOffset, SizeOffset uint32
	}
	procs := filepath.Join(cgroup, "cgroup.procs")
	var table []string
	run := func(p *imageClassProbe, name, mode, path string, h uint64, dev uint32, want int32, reasons ...int) {
		t.Helper()
		if err := p.collection.Maps["probe_config"].Put(uint32(0), config{cgStat.Ino, h, dev, 1}); err != nil {
			t.Fatal(err)
		}
		if err := p.collection.Maps["probe_results"].Put(uint32(0), result{}); err != nil {
			t.Fatal(err)
		}
		before := witness(p)
		out, err := exec.Command(helper, procs, mode, path).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: helper %v %q", name, err, out)
		}
		if err := p.collection.Maps["probe_config"].Put(uint32(0), config{}); err != nil {
			t.Fatal(err)
		}
		var got result
		if err := p.collection.Maps["probe_results"].Lookup(uint32(0), &got); err != nil {
			t.Fatal(err)
		}
		after := witness(p)
		reason, moved := -1, 0
		for i := range after.Count {
			if delta := after.Count[i] - before.Count[i]; delta != 0 {
				moved += int(delta)
				reason = i
			}
		}
		if got.Count != 1 || got.Value != want || moved != 1 {
			t.Fatalf("%s: result %+v want %d, witness moved %d", name, got, want, moved)
		}
		matched := false
		for _, r := range reasons {
			matched = matched || r == reason
		}
		if !matched || reason == imageClassHit && want != 1 {
			t.Fatalf("%s: reason %s not in %v", name, imageClassNames[reason], reasons)
		}
		if got.BTFOffset == 0 || got.BTFOffset != got.SizeOffset {
			t.Fatalf("%s: user_path offsets btf=%d size=%d", name, got.BTFOffset, got.SizeOffset)
		}
		row := fmt.Sprintf("%-28s %3d %-16s user_path@%d", name, got.Value, imageClassNames[reason], got.BTFOffset)
		table = append(table, row)
		t.Log(row)
	}

	p := load(layout)
	run(p, "untouched-lower", "exec", filepath.Join(merged, "untouched"), handle, imageDev, 1, imageClassHit)
	run(p, "untouched-second-lower", "exec", filepath.Join(merged, "deep"), handle, imageDev, 1, imageClassHit)
	run(p, "handle-zero", "exec", filepath.Join(merged, "untouched"), 0, imageDev, -1, imageClassNoIndex)
	run(p, "unpublished-handle", "exec", filepath.Join(merged, "untouched"), handle+1, imageDev, 0, imageClassUpper)
	if err := os.Chmod(filepath.Join(merged, "chmodme"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "upper", "chmodme")); err != nil {
		t.Fatalf("chmod did not copy up: %v", err)
	}
	run(p, "chmod-copy-up", "exec", filepath.Join(merged, "chmodme"), handle, imageDev, 0, imageClassUpper)
	write(filepath.Join(merged, "created"))
	run(p, "new-upper", "exec", filepath.Join(merged, "created"), handle, imageDev, 0, imageClassUpper)
	run(p, "unlinked-lower-fexecve", "fd-unlink", filepath.Join(merged, "unlinkme"), handle, imageDev, 1, imageClassHit)
	if _, err := os.Lstat(filepath.Join(merged, "unlinkme")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("lower unlink not visible: %v", err)
	}
	write(filepath.Join(merged, "created2"))
	run(p, "unlinked-upper-fexecve", "fd-unlink", filepath.Join(merged, "created2"), handle, imageDev, 0, imageClassUpper)
	run(p, "memfd-fexecve", "memfd", filepath.Join(merged, "untouched"), handle, imageDev, -1, imageClassMemfd)
	bindTarget := filepath.Join(merged, "bindtarget")
	if err := unix.Mount(filepath.Join(host, "true"), bindTarget, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	run(p, "bind-mounted-host-binary", "exec", bindTarget, handle, imageDev, 0, imageClassNotOverlay)
	if err := unix.Unmount(bindTarget, 0); err != nil {
		t.Fatal(err)
	}
	tmpfsDir := dir("usertmpfs")
	if err := unix.Mount("tmpfs", tmpfsDir, "tmpfs", 0, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Unmount(tmpfsDir, unix.MNT_DETACH) })
	write(filepath.Join(tmpfsDir, "true"))
	run(p, "user-tmpfs-file", "exec", filepath.Join(tmpfsDir, "true"), handle, imageDev, 0, imageClassNotOverlay)
	run(p, "layer-host-path", "exec", filepath.Join(lower1, "untouched"), handle, imageDev, 0, imageClassNotOverlay)
	run(p, "second-overlay-same-lowers", "exec", filepath.Join(merged2, "untouched"), handle, imageDev, 0, imageClassForeignOverlay)
	run(p, "second-overlay-own-dev", "exec", filepath.Join(merged2, "untouched"), handle, image2Dev, 1, imageClassHit)
	run(p, "nested-overlay-lower", "exec", filepath.Join(nested, "untouched"), handle, nestedDev, -1, imageClassNested)
	p.attached.Close()
	p.collection.Close()

	// P11: an upper dir root wrongly indexed must never classify as image. The
	// upper mount clone lacks MNT_READONLY, the lower clones carry it.
	var upperSt unix.Stat_t
	if err := unix.Stat(filepath.Join(tmp, "upper"), &upperSt); err != nil {
		t.Fatal(err)
	}
	u := load(layout, layerKey{handle, upperSt.Ino, unix.Major(upperSt.Dev), unix.Minor(upperSt.Dev)})
	run(u, "indexed-upper-copy-up", "exec", filepath.Join(merged, "chmodme"), handle, imageDev, -1, imageClassWritableLayer)
	run(u, "indexed-upper-new-file", "exec", filepath.Join(merged, "created"), handle, imageDev, -1, imageClassWritableLayer)
	write(filepath.Join(merged, "created3"))
	run(u, "indexed-upper-new-file-2", "exec", filepath.Join(merged, "created3"), handle, imageDev, -1, imageClassWritableLayer)
	run(u, "indexed-upper-lower-still-hit", "exec", filepath.Join(merged, "untouched"), handle, imageDev, 1, imageClassHit)
	run(u, "indexed-upper-second-lower-hit", "exec", filepath.Join(merged, "deep"), handle, imageDev, 1, imageClassHit)
	run(u, "indexed-upper-other-overlay", "exec", filepath.Join(merged2, "untouched"), handle, image2Dev, 1, imageClassHit)
	u.attached.Close()
	u.collection.Close()

	// Forced authentication mismatch: the other kernel's layout, and unset.
	for _, forced := range []uint32{sharedImageOverlayLayoutRealFile + sharedImageOverlayLayoutOvlFile - layout, sharedImageOverlayLayoutUnset} {
		q := load(forced)
		reasons := []int{imageClassAuth}
		if forced != sharedImageOverlayLayoutUnset {
			reasons = append(reasons, imageClassReadFault)
		}
		run(q, fmt.Sprintf("forced-layout-%d", forced), "exec", filepath.Join(merged, "untouched"), handle, imageDev, -1, reasons...)
		q.attached.Close()
		q.collection.Close()
	}
	t.Logf("%s per-case table:\n%s", release, strings.Join(table, "\n"))
}

// mountDevs maps mount points to their superblock kernel dev_t (major<<20|minor).
func mountDevs(t *testing.T) map[string]uint32 {
	t.Helper()
	file, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	devs := map[string]uint32{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 {
			continue
		}
		parts := strings.Split(fields[2], ":")
		if len(parts) != 2 {
			continue
		}
		major, err1 := strconv.ParseUint(parts[0], 10, 12)
		minor, err2 := strconv.ParseUint(parts[1], 10, 20)
		if err1 != nil || err2 != nil {
			continue
		}
		devs[fields[4]] = uint32(major<<20 | minor)
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	return devs
}

var verifierStatsPattern = regexp.MustCompile(`processed \d+ insns.*|stack depth [\d+]+`)

func verifierStats(log string) string {
	return strings.Join(verifierStatsPattern.FindAllString(log, -1), "; ")
}
