// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

//go:build enforce_exec_shared_qualification

package fullruntime

import (
	"bufio"
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// sharedOverlayFixture is one containerd-free "container": a real overlay
// mount (lower = a minimal userland, the image; upper/work beside it) on an
// XFS/ext4 directory, served to the node's real layer resolver through the
// test image source as an overlayfs snapshot.
type sharedOverlayFixture struct {
	dir, lower, upper, work, merged string
}

// sharedImageTestSource is the test sharedImageLayerSource: container ID ->
// the fixture's snapshot mounts.
type sharedImageTestSource map[string]*sharedOverlayFixture

func (s sharedImageTestSource) RootfsMounts(_ context.Context, id string) (sharedImageRootfs, error) {
	f := s[id]
	if f == nil {
		return sharedImageRootfs{}, fmt.Errorf("container %s: no test snapshot", id)
	}
	return sharedImageRootfs{Snapshotter: sharedImageOverlaySnapshotter, Key: "test/" + id, Mounts: []sharedImageMount{{
		Type: "overlay", Source: "overlay",
		Options: []string{"index=off", "workdir=" + f.work, "upperdir=" + f.upper, "lowerdir=" + f.lower},
	}}}, nil
}

// sharedImageCopy copies a host file (and, for ELF files, its interpreter
// and needed libraries, recursively) into the lower at the same path.
func sharedImageCopy(t *testing.T, lower, path string, seen map[string]bool) {
	t.Helper()
	if seen[path] {
		return
	}
	seen[path] = true
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(real)
	if err != nil {
		t.Fatal(err)
	}
	to := filepath.Join(lower, path)
	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, raw, 0o755); err != nil {
		t.Fatal(err)
	}
	f, err := elf.Open(real)
	if err != nil {
		return // not ELF
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			interp, _ := io.ReadAll(p.Open())
			sharedImageCopy(t, lower, strings.TrimRight(string(interp), "\x00"), seen)
		}
	}
	libs, _ := f.ImportedLibraries()
	for _, lib := range libs {
		for _, dir := range []string{"/usr/lib64", "/lib64"} {
			if _, err := os.Stat(filepath.Join(dir, lib)); err == nil {
				sharedImageCopy(t, lower, filepath.Join(dir, lib), seen)
				break
			}
		}
	}
}

// newSharedImageFixture builds and mounts one overlay under base.
func newSharedImageFixture(t *testing.T, base, name, memfdHelper string) *sharedOverlayFixture {
	t.Helper()
	dir := filepath.Join(base, name)
	f := &sharedOverlayFixture{dir: dir, lower: filepath.Join(dir, "lower"), upper: filepath.Join(dir, "upper"), work: filepath.Join(dir, "work"), merged: filepath.Join(dir, "merged")}
	for _, d := range []string{f.lower, f.upper, f.work, f.merged, filepath.Join(f.lower, "tmp"), filepath.Join(f.lower, "proc"), filepath.Join(f.lower, "dev")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	seen := map[string]bool{}
	for _, bin := range []string{"/usr/bin/bash", "/usr/bin/true", "/usr/bin/cp", "/usr/bin/chmod"} {
		sharedImageCopy(t, f.lower, bin, seen)
	}
	// /bin, /lib64 as in the host userland; sh is bash.
	for link, target := range map[string]string{"bin": "usr/bin", "lib64": "usr/lib64", "usr/bin/sh": "bash"} {
		if _, err := os.Lstat(filepath.Join(f.lower, link)); err == nil {
			continue
		}
		if err := os.Symlink(target, filepath.Join(f.lower, link)); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	helper, err := os.ReadFile(memfdHelper)
	if err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string][]byte{
		"usr/bin/cu":         raw, // chmod'ed in the test: a full copy-up
		"usr/bin/hold-true":  raw, // the held interpreter
		"usr/bin/s0":         []byte("#!/usr/bin/hold-true\n"),
		"usr/bin/memfd-exec": helper,
	} {
		if err := os.WriteFile(filepath.Join(f.lower, path), body, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	opts := "lowerdir=" + f.lower + ",upperdir=" + f.upper + ",workdir=" + f.work + ",index=off"
	if err := unix.Mount("overlay", f.merged, "overlay", 0, opts); err != nil {
		t.Fatalf("mount overlay %s: %v", f.merged, err)
	}
	t.Cleanup(func() { _ = unix.Unmount(f.merged, unix.MNT_DETACH) })
	return f
}

// startSharedPipeInitImage is startSharedPipeInitShell chrooted into the
// fixture's overlay: the init's root mount is the container overlay.
func startSharedPipeInitImage(t *testing.T, cgroup, name string, f *sharedOverlayFixture) *sharedPipeInit {
	t.Helper()
	dir, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	cmd := exec.Command("/usr/bin/bash", "-c", sharedPipeInitScript)
	cmd.Args[0] = name
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Chroot: f.merged, Unshareflags: syscall.CLONE_NEWNS, UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", name, err)
	}
	p := &sharedPipeInit{cmd: cmd, in: in, out: bufio.NewReader(out), path: cgroup}
	var st unix.Stat_t
	if err := unix.Stat(cgroup, &st); err != nil {
		t.Fatal(err)
	}
	p.ino = st.Ino
	t.Cleanup(p.stop)
	return p
}

// sharedImageHold holds the first exec-open of path (fanotify
// FAN_OPEN_EXEC_PERM) until release.
type sharedImageHold struct {
	fd      int
	held    chan struct{}
	release chan struct{}
	done    chan error
}

func holdSharedImageExec(t *testing.T, path string) *sharedImageHold {
	t.Helper()
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC, unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		t.Fatalf("fanotify: %v", err)
	}
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_OPEN_EXEC_PERM, unix.AT_FDCWD, path); err != nil {
		t.Fatalf("fanotify mark %s: %v", path, err)
	}
	h := &sharedImageHold{fd: fd, held: make(chan struct{}), release: make(chan struct{}), done: make(chan error, 1)}
	// One event: held until release, then allowed. Closing the group fd
	// afterwards allows any later permission event.
	go func() {
		buf := make([]byte, 4096)
		n, err := unix.Read(fd, buf)
		if err != nil || n < 24 {
			h.done <- fmt.Errorf("fanotify read %d: %w", n, err)
			return
		}
		eventFD := binary.LittleEndian.Uint32(buf[16:])
		close(h.held)
		<-h.release
		resp := make([]byte, 8)
		binary.LittleEndian.PutUint32(resp, eventFD)
		binary.LittleEndian.PutUint32(resp[4:], unix.FAN_ALLOW)
		_, err = unix.Write(fd, resp)
		_ = unix.Close(int(eventFD))
		h.done <- err
	}()
	return h
}

// TestSharedNodeImageFactsAttached (G020 part 4): the target/actor image
// facts through StartNode and the product publisher's image index, on two
// containerd-free fixture containers (real overlay mounts, the real layer
// resolver and host attestation): A Strict and B Audit, policy "allow only
// a target from the image" (default deny). The image binary is allowed; a
// new upper file, a copied-up file are not from the image and a memfd is
// UNKNOWN for it (Strict denies, Audit allows); a binding with no image index refuses a
// FromImage policy at publish; a revision while an exec is held between its
// two passes keeps the image facts of the record the exec's reader holds.
// Each pass is checked in the witness ring. Isolated exact-kernel VM only
// (IG_SHARED_IMAGE_OBJECT: the witness twin; IG_SHARED_IMAGE_BASE: a
// directory on XFS or ext4; IG_SHARED_IMAGE_MEMFD_HELPER: the static helper).
func TestSharedNodeImageFactsAttached(t *testing.T) {
	object, base, helper := os.Getenv("IG_SHARED_IMAGE_OBJECT"), os.Getenv("IG_SHARED_IMAGE_BASE"), os.Getenv("IG_SHARED_IMAGE_MEMFD_HELPER")
	if object == "" {
		t.Skip("set IG_SHARED_IMAGE_OBJECT on an isolated exact-kernel VM")
	}
	root := os.Getenv("IG_SHARED_IMAGE_CGROUP_ROOT")
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(root), "ig15-g020-image") || base == "" || helper == "" {
		t.Fatal("root, a dedicated ig15-g020-image* cgroup root, IG_SHARED_IMAGE_BASE and IG_SHARED_IMAGE_MEMFD_HELPER required")
	}
	if err := checkSharedInitNamespaces(); err != nil {
		t.Fatalf("design 13.8: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	base, err := os.MkdirTemp(base, "ig15-g020-image-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	source := sharedImageTestSource{}
	fixtures := map[string]*sharedOverlayFixture{}
	for _, name := range []string{"A", "B"} {
		fixtures[name] = newSharedImageFixture(t, base, strings.ToLower(name), helper)
		source["ig15-g020-image-"+strings.ToLower(name)] = fixtures[name]
	}
	sharedTestQualification = func(q *SharedNodeQualification) { q.imageSource = source }
	t.Cleanup(func() { sharedTestQualification = nil })
	// The classifier's layout is this kernel's own, never a fake: the
	// exact kernel's source-verified layout from its live module BTF.
	digest, err := kernelBTFDigest()
	if err != nil {
		t.Fatal(err)
	}
	if layout, err := overlayLayoutReader(); err != nil || layout != sharedImageOverlayLayouts[sharedCandidateKernelBTF[digest]] {
		t.Fatalf("overlay layout %d (%v), want %s's %d", layout, err, sharedCandidateKernelBTF[digest], sharedImageOverlayLayouts[sharedCandidateKernelBTF[digest]])
	}
	node, gc, ctx := startSharedCandidateNode(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, nil)
	defer func() { _ = node.StopNode(context.WithoutCancel(ctx)) }()
	witness := sharedFactWitness(t, gc)
	modes := map[string]fullpolicy.Mode{"A": fullpolicy.Enforce, "B": fullpolicy.Audit}
	inits := map[string]*sharedPipeInit{}
	sessions := map[string]*BindingSession{}
	for _, name := range []string{"A", "B"} {
		cgroup := filepath.Join(root, strings.ToLower(name))
		if err := os.MkdirAll(cgroup, 0o755); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Remove(cgroup) })
		p := startSharedPipeInitImage(t, cgroup, "ig15-g020-image-init-"+strings.ToLower(name), fixtures[name])
		config := SharedBindingConfig{ContainerID: "ig15-g020-image-" + strings.ToLower(name)}
		config.CgroupID, config.InitHostPID, config.Acquire = p.ino, uint32(p.cmd.Process.Pid), p.acquire
		s, err := node.Bind(ctx, config)
		if err != nil {
			t.Fatalf("Bind %s: %v", name, err)
		}
		inits[name], sessions[name] = p, s
	}
	yes := true
	fromImage := fullpolicy.Rule{Name: "image", Action: fullpolicy.Allow, Target: fullpolicy.Target{FromImage: &yes}}
	revision := 0
	policyOf := func(name string) *fullpolicy.Policy {
		return &fullpolicy.Policy{ID: "g020-image-" + strings.ToLower(name), Revision: strconv.Itoa(revision), Mode: modes[name], RootRole: "app", Default: fullpolicy.Deny, Rules: []fullpolicy.Rule{fromImage}}
	}
	publish := func(label, name string) error {
		t.Helper()
		_, err := sessions[name].Publish(ctx, SharedBindingPolicy{Source: policyOf(name), Container: strings.ToLower(name)})
		if err != nil {
			return fmt.Errorf("%s: publish %s revision %d: %w", label, name, revision, err)
		}
		return nil
	}
	revision++
	for _, name := range []string{"A", "B"} {
		if err := publish("adoption", name); err != nil {
			t.Fatal(err)
		}
		if st := sessions[name].Inspect(); st.Fault != nil || !st.RoutePublished {
			t.Fatalf("%s after adoption: %+v", name, st)
		}
	}

	// runE runs command in the init of binding name (any goroutine).
	runE := func(name, command string) (int, error) {
		out, code, err := inits[name].run(ctx, command+"; echo rc=$?")
		if err != nil || code != 0 {
			return 0, fmt.Errorf("%q code %d: %w", out, code, err)
		}
		i := strings.LastIndex(out, "rc=")
		if i < 0 {
			return 0, fmt.Errorf("no status in %q", out)
		}
		return strconv.Atoi(strings.TrimSpace(out[i+3:]))
	}
	// classes is the classifier's reason witness (se_image_witness, per-CPU,
	// summed; SE_IMAGE_CLASS_* order), for a failure's diagnosis.
	classes := func() string {
		names := []string{"HIT", "UPPER", "NOT_OVERLAY", "FOREIGN_OVERLAY", "NO_INDEX", "AUTH", "NESTED", "READ_FAULT", "INSERT_UNCERTAIN", "DELETE_UNCERTAIN", "PREPARE_REFUSED", "WRITABLE_LAYER", "MEMFD"}
		value, _ := gc.GetVar(operators.MapPrefix + sharedImageWitnessMap)
		m, _ := value.(*ebpf.Map)
		if m == nil {
			return "no " + sharedImageWitnessMap
		}
		var cpus [][13]uint64 // struct se_image_class_witness (104 B)
		if err := m.Lookup(uint32(0), &cpus); err != nil {
			return fmt.Sprintf("%s: %v", sharedImageWitnessMap, err)
		}
		var out []string
		for i, name := range names {
			var n uint64
			for _, c := range cpus {
				n += c[i]
			}
			out = append(out, fmt.Sprintf("%s=%d", name, n))
		}
		layout, layoutErr := overlayLayoutReader()
		return fmt.Sprintf("%s; live layout %d (%v)", strings.Join(out, " "), layout, layoutErr)
	}
	run := func(label, name, command string) (int, []sharedFactRecord) {
		t.Helper()
		since := sharedFactHead(t, witness)
		rc, err := runE(name, command)
		if err != nil {
			t.Fatalf("%s %s: %v (classifier %s)", label, name, err, classes())
		}
		return rc, sharedFactRecords(t, witness, since)
	}
	// image returns the target image fact of the first pass whose target
	// is path ("" for a target path UNKNOWN, e.g. a memfd).
	image := func(label string, records []sharedFactRecord, path string) int32 {
		t.Helper()
		for _, r := range records {
			if r.target == path {
				return r.targetImage
			}
		}
		t.Fatalf("%s: no pass with target %q in %+v", label, path, records)
		return 0
	}
	cases := []struct {
		label, command, target string
		image                  int32
		strict, audit          int
	}{
		{"image binary", "/usr/bin/true", "/usr/bin/true", 1, 0, 0},
		{"new upper file", "cp /usr/bin/true /tmp/new-true && /tmp/new-true", "/tmp/new-true", 0, 126, 0},
		{"copied-up file", "chmod 0755 /usr/bin/cu && /usr/bin/cu", "/usr/bin/cu", 0, 126, 0},
		// A memfd is UNKNOWN for the image (user ruling: memfd from-image
		// -> UNKNOWN, SE_IMAGE_CLASS_MEMFD), never from image; its path is
		// UNKNOWN too (outside the task's root), the helper is. Strict
		// denies, Audit allows.
		{"memfd", "/usr/bin/memfd-exec /usr/bin/true", "", -1, 126, 0},
	}
	for _, c := range cases {
		for _, name := range []string{"A", "B"} {
			want := c.strict
			if name == "B" {
				want = c.audit
			}
			rc, records := run(c.label, name, c.command)
			got := image(c.label, records, c.target)
			if rc != want || got != c.image {
				t.Fatalf("%s %s: rc %d target image %d, want rc %d image %d (records %+v; classifier %s)", c.label, name, rc, got, want, c.image, records, classes())
			}
			if c.target != "/usr/bin/true" && image(c.label, records, "/usr/bin/bash") != 1 {
				t.Fatalf("%s %s: the init's own shell is not from the image (%+v)", c.label, name, records)
			}
			t.Logf("%s %s: rc %d target image %d", c.label, name, rc, got)
		}
	}

	// Revision while an exec is held between its two passes: the
	// interpreter pass classifies against the record its reader holds.
	for _, name := range []string{"A", "B"} {
		hold := holdSharedImageExec(t, filepath.Join(fixtures[name].merged, "usr/bin/hold-true"))
		type result struct {
			rc  int
			err error
		}
		since := sharedFactHead(t, witness)
		ran := make(chan result, 1)
		go func() {
			rc, err := runE(name, "/usr/bin/s0")
			ran <- result{rc, err}
		}()
		select {
		case <-hold.held:
		case <-time.After(30 * time.Second):
			t.Fatalf("%s: the interpreter open was never held", name)
		}
		revision++
		published := make(chan error, 1)
		go func() { published <- publish("revision while held", name) }()
		var revised error
		select {
		case revised = <-published:
		case <-time.After(20 * time.Second):
			revised = fmt.Errorf("still publishing after 20s")
		}
		close(hold.release)
		r := <-ran
		if r.err != nil {
			t.Fatalf("%s held script: %v", name, r.err)
		}
		records := sharedFactRecords(t, witness, since)
		if err := <-hold.done; err != nil {
			t.Logf("%s: fanotify reader: %v", name, err)
		}
		_ = unix.Close(hold.fd)
		if revised != nil {
			if err := <-published; err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
		if r.rc != 0 || image("held script", records, "/usr/bin/s0") != 1 || image("held script", records, "/usr/bin/hold-true") != 1 {
			t.Fatalf("%s held script: rc %d records %+v, want both passes from the image and rc 0", name, r.rc, records)
		}
		if st := sessions[name].Inspect(); st.Fault != nil {
			t.Fatalf("%s after the held revision: %+v", name, st)
		}
		t.Logf("%s: revision while held (%v first), interpreter pass from the image", name, revised)
	}
	health, err := node.FactHealth()
	t.Logf("fact health %+v (%v)", health, err)

	// No image index (the profile has two bindings: a fresh node): a
	// binding without a container ID refuses a FromImage policy at publish.
	if err := node.StopNode(context.WithoutCancel(ctx)); err != nil {
		t.Fatalf("StopNode: %v", err)
	}
	sharedTestQualification = nil
	node2, _, ctx2 := startSharedCandidateNode(t, object, "IG_SHARED_M4_HANDLER_SYMBOL", nil, nil)
	defer func() { _ = node2.StopNode(context.WithoutCancel(ctx2)) }()
	cgroup := filepath.Join(root, "c")
	if err := os.MkdirAll(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(cgroup) })
	pc := startSharedPipeInitShell(t, cgroup, "ig15-g020-image-init-c", "/usr/bin/bash")
	t.Cleanup(pc.stop)
	c, err := node2.Bind(ctx2, SharedBindingConfig{CgroupID: pc.ino, InitHostPID: uint32(pc.cmd.Process.Pid), Acquire: pc.acquire})
	if err != nil {
		t.Fatalf("Bind C: %v", err)
	}
	_, err = c.Publish(ctx2, SharedBindingPolicy{Source: &fullpolicy.Policy{ID: "g020-image-c", Revision: "1", Mode: fullpolicy.Enforce, RootRole: "app", Default: fullpolicy.Deny, Rules: []fullpolicy.Rule{fromImage}}, Container: "c"})
	if err == nil || !errors.Is(err, ErrSharedImageIndexUnavailable) {
		t.Fatalf("binding without an image index: %v, want ErrSharedImageIndexUnavailable", err)
	}
	t.Logf("no index: %v; status %+v", err, c.Inspect())
}
