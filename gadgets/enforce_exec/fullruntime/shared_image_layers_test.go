// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	testSnapRoot = "/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots"
	testBtrfs    = 0x9123683e
	testFUSE     = 0x65735546
)

func testSnapFS(id int) string { return fmt.Sprintf("%s/%d/fs", testSnapRoot, id) }

var (
	testUpper  = testSnapFS(46)
	testWork   = fmt.Sprintf("%s/46/work", testSnapRoot)
	testLowers = []string{testSnapFS(45), testSnapFS(44), testSnapFS(43)}
	testInit   = SharedInitIdentity{TGID: 4242, StartTicks: 987654, MountNS: 4026532901}
)

// testRootLine renders an AL2023 (kernel 6.1, containerd 2.x, SELinux)
// container root overlay mountinfo line.
func testRootLine(minor int, superOptions string) string {
	return fmt.Sprintf("1834 1650 0:%d / / rw,relatime master:841 - overlay overlay %s", minor, superOptions)
}

func testOverlaySuper(lowers []string, upper string) string {
	return "rw,seclabel,lowerdir=" + strings.Join(lowers, ":") + ",upperdir=" + upper + ",workdir=" + testWork
}

func testMountinfo(rootLine string) []byte {
	return []byte(strings.Join([]string{
		rootLine,
		"1835 1834 0:313 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw",
		"1836 1834 0:314 / /dev rw,nosuid - tmpfs tmpfs rw,seclabel,size=65536k,mode=755,inode64",
		"1840 1834 259:1 /var/lib/kubelet/pods/0b5c/etc-hosts /etc/hosts rw,noatime - xfs /dev/nvme0n1p1 rw,seclabel,attr2,inode64,logbufs=8,logbsize=32k,sunit=1024,swidth=1024,noquota",
		"1841 1834 0:315 / /sys ro,nosuid,nodev,noexec,relatime - sysfs sysfs ro,seclabel",
	}, "\n") + "\n")
}

type fakeImageSource struct {
	rootfs sharedImageRootfs
	err    error
}

func (f *fakeImageSource) RootfsMounts(context.Context, string) (sharedImageRootfs, error) {
	return f.rootfs, f.err
}

type fakeImageHost struct {
	view    sharedImageInitView
	viewErr error
	lowers  map[string]sharedImageLowerStat
}

func (f *fakeImageHost) InitView(SharedInitIdentity) (sharedImageInitView, error) {
	return f.view, f.viewErr
}

func (f *fakeImageHost) LowerRoot(path string) (sharedImageLowerStat, error) {
	st, ok := f.lowers[path]
	if !ok {
		return st, syscall.ENOENT
	}
	return st, nil
}

func testOverlayRootfs(options ...string) sharedImageRootfs {
	if options == nil {
		options = []string{"index=off", "workdir=" + testWork, "upperdir=" + testUpper, "lowerdir=" + strings.Join(testLowers, ":")}
	}
	return sharedImageRootfs{Snapshotter: "overlayfs", Key: "k8s.io/57/0123abcd", Mounts: []sharedImageMount{{Type: "overlay", Source: "overlay", Options: options}}}
}

type imageFixture struct {
	source *fakeImageSource
	host   *fakeImageHost
	quota  uint64
}

func newImageFixture() *imageFixture {
	lowers := map[string]sharedImageLowerStat{}
	for i, l := range testLowers {
		lowers[l] = sharedImageLowerStat{Magic: sharedXFSMagic, Dir: true, Key: SharedImageLayerKey{Ino: uint64(1000 + i), Major: 259, Minor: 1}}
	}
	lowers[testUpper] = sharedImageLowerStat{Magic: sharedXFSMagic, Dir: true, Key: SharedImageLayerKey{Ino: 2000, Major: 259, Minor: 1}}
	return &imageFixture{
		source: &fakeImageSource{rootfs: testOverlayRootfs()},
		host: &fakeImageHost{
			view: sharedImageInitView{
				StartTicks: testInit.StartTicks, EndTicks: testInit.StartTicks, MountNS: testInit.MountNS,
				Mountinfo: testMountinfo(testRootLine(312, testOverlaySuper(testLowers, testUpper))),
				RootMajor: 0, RootMinor: 312,
			},
			lowers: lowers,
		},
	}
}

func (f *imageFixture) resolver(t *testing.T) *sharedImageLayerResolver {
	t.Helper()
	r, err := newSharedImageLayerResolver(f.source, f.host, f.quota)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestSharedImageLayersDiscovery(t *testing.T) {
	type step int
	const (
		atResolve step = iota
		atKeys
		atReattest
	)
	tests := []struct {
		name string
		// mutate configures the fixture before Resolve; between mutates it
		// after Keys, before Reattest.
		mutate, between func(*imageFixture)
		fail            step
		kind            error
		reason          SharedImageReason
		expected        uint64
	}{
		{name: "happy path 3 lowers", fail: -1, expected: 3},
		{name: "duplicate lowers", fail: -1, expected: 2, mutate: func(f *imageFixture) {
			// The bottom lower aliases the middle one's root inode (a bind
			// mount of the same layer): one index cell.
			f.host.lowers[testLowers[2]] = f.host.lowers[testLowers[1]]
		}},
		{name: "duplicate lowerdir path", fail: -1, expected: 3, mutate: func(f *imageFixture) {
			lowers := append(append([]string(nil), testLowers...), testLowers[0])
			f.source.rootfs = testOverlayRootfs("workdir="+testWork, "upperdir="+testUpper, "lowerdir="+strings.Join(lowers, ":"))
			f.host.view.Mountinfo = testMountinfo(testRootLine(312, testOverlaySuper(lowers, testUpper)))
		}},
		{name: "compacted relative kernel lowerdir", fail: -1, expected: 3, mutate: func(f *imageFixture) {
			f.host.view.Mountinfo = testMountinfo(testRootLine(312, "rw,lowerdir=45/fs:44/fs:43/fs,upperdir="+testUpper+",workdir="+testWork))
		}},
		{name: "kernel lowerdir+ form", fail: -1, expected: 3, mutate: func(f *imageFixture) {
			f.host.view.Mountinfo = testMountinfo(testRootLine(312, "rw,lowerdir+="+testLowers[0]+",lowerdir+="+testLowers[1]+",lowerdir+="+testLowers[2]+",upperdir="+testUpper+",workdir="+testWork))
		}},
		{name: "not overlayfs snapshotter", fail: atResolve, kind: ErrSharedImageIndexUnsupported, reason: SharedImageReasonSnapshotter, mutate: func(f *imageFixture) {
			f.source.rootfs.Snapshotter = "soci"
		}},
		{name: "single layer bind mount", fail: atResolve, kind: ErrSharedImageIndexUnsupported, reason: SharedImageReasonMountType, mutate: func(f *imageFixture) {
			f.source.rootfs.Mounts = []sharedImageMount{{Type: "bind", Source: testUpper, Options: []string{"rw", "rbind"}}}
		}},
		{name: "metacopy snapshot", fail: atResolve, kind: ErrSharedImageIndexUnsupported, reason: SharedImageReasonMetacopy, mutate: func(f *imageFixture) {
			f.source.rootfs.Mounts[0].Options = append(f.source.rootfs.Mounts[0].Options, "metacopy=on")
		}},
		{name: "metacopy kernel default", fail: atResolve, kind: ErrSharedImageIndexUnsupported, reason: SharedImageReasonMetacopy, mutate: func(f *imageFixture) {
			f.host.view.Mountinfo = testMountinfo(testRootLine(312, testOverlaySuper(testLowers, testUpper)+",redirect_dir=on,metacopy=on"))
		}},
		{name: "metacopy off accepted", fail: -1, expected: 3, mutate: func(f *imageFixture) {
			f.source.rootfs.Mounts[0].Options = append(f.source.rootfs.Mounts[0].Options, "metacopy=off")
		}},
		{name: "data-only lowers", fail: atResolve, kind: ErrSharedImageIndexUnsupported, reason: SharedImageReasonDataOnlyLower, mutate: func(f *imageFixture) {
			f.source.rootfs = testOverlayRootfs("workdir="+testWork, "upperdir="+testUpper, "lowerdir="+testLowers[0]+"::"+testLowers[1])
		}},
		{name: "kernel datadir+", fail: atResolve, kind: ErrSharedImageIndexUnsupported, reason: SharedImageReasonDataOnlyLower, mutate: func(f *imageFixture) {
			f.host.view.Mountinfo = testMountinfo(testRootLine(312, testOverlaySuper(testLowers, testUpper)+",datadir+=/data"))
		}},
		{name: "relative snapshot lowerdir", fail: atResolve, kind: ErrSharedImageIndexUnsupported, reason: SharedImageReasonRelativeLowerdir, mutate: func(f *imageFixture) {
			f.source.rootfs = testOverlayRootfs("workdir="+testWork, "upperdir="+testUpper, "lowerdir=45/fs:44/fs:43/fs")
		}},
		{name: "unclean snapshot lowerdir", fail: atResolve, kind: ErrSharedImageIndexUnsupported, reason: SharedImageReasonRelativeLowerdir, mutate: func(f *imageFixture) {
			f.source.rootfs = testOverlayRootfs("workdir="+testWork, "upperdir="+testUpper, "lowerdir="+testSnapRoot+"/45/../44/fs")
		}},
		{name: "unresolvable kernel relative lowerdir", fail: atResolve, kind: ErrSharedImageIndexUnsupported, reason: SharedImageReasonRelativeLowerdir, mutate: func(f *imageFixture) {
			f.host.view.Mountinfo = testMountinfo(testRootLine(312, "rw,lowerdir=45/fs:99/fs:43/fs,upperdir="+testUpper+",workdir="+testWork))
		}},
		{name: "unknown snapshot option", fail: atResolve, kind: ErrSharedImageIndexUnsupported, reason: SharedImageReasonOverlayOption, mutate: func(f *imageFixture) {
			f.source.rootfs.Mounts[0].Options = append(f.source.rootfs.Mounts[0].Options, "lowerdir+=/x")
		}},
		{name: "over quota", fail: atResolve, kind: ErrSharedImageIndexUnsupported, reason: SharedImageReasonLowerQuota, mutate: func(f *imageFixture) {
			f.quota = 2
		}},
		{name: "btrfs lower", fail: atKeys, kind: ErrSharedImageIndexUnsupported, reason: SharedImageReasonLowerFilesystem, mutate: func(f *imageFixture) {
			st := f.host.lowers[testLowers[1]]
			st.Magic = testBtrfs
			f.host.lowers[testLowers[1]] = st
		}},
		{name: "FUSE lower", fail: atKeys, kind: ErrSharedImageIndexUnsupported, reason: SharedImageReasonLowerFilesystem, mutate: func(f *imageFixture) {
			st := f.host.lowers[testLowers[0]]
			st.Magic = testFUSE
			f.host.lowers[testLowers[0]] = st
		}},
		{name: "ext4 lower accepted", fail: -1, expected: 3, mutate: func(f *imageFixture) {
			for k, st := range f.host.lowers {
				st.Magic = sharedExt4Magic
				f.host.lowers[k] = st
			}
		}},
		{name: "upperdir mismatch", fail: atResolve, kind: ErrSharedImageAttestation, reason: SharedImageReasonRootMount, mutate: func(f *imageFixture) {
			f.host.view.Mountinfo = testMountinfo(testRootLine(312, testOverlaySuper(testLowers, testSnapFS(47))))
		}},
		{name: "kernel lower mismatch", fail: atResolve, kind: ErrSharedImageAttestation, reason: SharedImageReasonRootMount, mutate: func(f *imageFixture) {
			f.host.view.Mountinfo = testMountinfo(testRootLine(312, testOverlaySuper(testLowers[:2], testUpper)))
		}},
		{name: "root not overlay", fail: atResolve, kind: ErrSharedImageAttestation, reason: SharedImageReasonRootMount, mutate: func(f *imageFixture) {
			f.host.view.Mountinfo = testMountinfo("1834 1650 259:1 / / rw - xfs /dev/nvme0n1p1 rw")
		}},
		{name: "two root entries", fail: atResolve, kind: ErrSharedImageAttestation, reason: SharedImageReasonRootMount, mutate: func(f *imageFixture) {
			line := testRootLine(312, testOverlaySuper(testLowers, testUpper))
			f.host.view.Mountinfo = testMountinfo(line + "\n" + line)
		}},
		{name: "st_dev mismatch", fail: atResolve, kind: ErrSharedImageAttestation, reason: SharedImageReasonRootDevice, mutate: func(f *imageFixture) {
			f.host.view.RootMinor = 313
		}},
		{name: "init start ticks changed", fail: atResolve, kind: ErrSharedImageAttestation, reason: SharedImageReasonInit, mutate: func(f *imageFixture) {
			f.host.view.EndTicks++
		}},
		{name: "init mount namespace changed", fail: atResolve, kind: ErrSharedImageAttestation, reason: SharedImageReasonInit, mutate: func(f *imageFixture) {
			f.host.view.MountNS++
		}},
		{name: "init died before reattest", fail: atReattest, kind: ErrSharedImageAttestation, reason: SharedImageReasonInit, between: func(f *imageFixture) {
			f.host.viewErr = syscall.ESRCH
		}},
		{name: "st_dev changed before reattest", fail: atReattest, kind: ErrSharedImageAttestation, reason: SharedImageReasonRootDevice, between: func(f *imageFixture) {
			f.host.view.RootMinor = 400
		}},
		{name: "overlay remounted before reattest", fail: atReattest, kind: ErrSharedImageAttestation, reason: SharedImageReasonRootDevice, between: func(f *imageFixture) {
			f.host.view.Mountinfo = testMountinfo(testRootLine(400, testOverlaySuper(testLowers, testUpper)))
			f.host.view.RootMinor = 400
		}},
		{name: "lower key changed before reattest", fail: atReattest, kind: ErrSharedImageAttestation, reason: SharedImageReasonLowerIdentity, between: func(f *imageFixture) {
			st := f.host.lowers[testLowers[2]]
			st.Key.Ino++
			f.host.lowers[testLowers[2]] = st
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newImageFixture()
			if tt.mutate != nil {
				tt.mutate(f)
			}
			r := f.resolver(t)
			check := func(at step, err error) bool {
				t.Helper()
				if tt.fail != at {
					if err != nil {
						t.Fatalf("step %d: %v", at, err)
					}
					return false
				}
				var typed *SharedImageLayerError
				if !errors.Is(err, tt.kind) || !errors.As(err, &typed) || typed.Reason != tt.reason {
					t.Fatalf("step %d: got %v, want %v/%s", at, err, tt.kind, tt.reason)
				}
				return true
			}
			layers, err := r.Resolve(context.Background(), "0123abcd", testInit)
			if check(atResolve, err) {
				return
			}
			keys, err := r.Keys(layers)
			if check(atKeys, err) {
				return
			}
			if tt.between != nil {
				tt.between(f)
			}
			if check(atReattest, r.Reattest(context.Background(), layers)) {
				return
			}
			if layers.Expected != tt.expected || uint64(len(keys)) != tt.expected {
				t.Fatalf("expected %d keys, got %d (%+v)", tt.expected, layers.Expected, keys)
			}
			if layers.OverlayDev != 312 || layers.UpperDir != testUpper {
				t.Fatalf("layers %+v", layers)
			}
		})
	}
}

func TestSharedImageLayersHappyKeys(t *testing.T) {
	f := newImageFixture()
	r := f.resolver(t)
	layers, err := r.Resolve(context.Background(), "0123abcd", testInit)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := r.Keys(layers)
	if err != nil {
		t.Fatal(err)
	}
	want := []SharedImageLayerKey{{1000, 259, 1}, {1001, 259, 1}, {1002, 259, 1}}
	if fmt.Sprint(keys) != fmt.Sprint(want) || fmt.Sprint(layers.Lowers) != fmt.Sprint(testLowers) {
		t.Fatalf("keys %v lowers %v", keys, layers.Lowers)
	}
	if layers.Snapshotter != "overlayfs" || layers.SnapshotKey != "k8s.io/57/0123abcd" || layers.Init != testInit {
		t.Fatalf("layers %+v", layers)
	}
	if err := r.Reattest(context.Background(), &SharedImageLayers{}); err == nil {
		t.Fatal("reattest of unkeyed layers accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := r.Reattest(ctx, layers); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled reattest: %v", err)
	}
}

func TestSharedImageUpperAliasingLowerRefused(t *testing.T) {
	for _, lower := range testLowers {
		f := newImageFixture()
		f.host.lowers[testUpper] = f.host.lowers[lower]
		r := f.resolver(t)
		layers, err := r.Resolve(context.Background(), "0123abcd", testInit)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.Keys(layers); err == nil || !strings.Contains(err.Error(), "upperdir") {
			t.Fatalf("upper aliasing %s accepted: %v", lower, err)
		}
	}
	f := newImageFixture()
	delete(f.host.lowers, testUpper)
	r := f.resolver(t)
	layers, err := r.Resolve(context.Background(), "0123abcd", testInit)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Keys(layers); err == nil {
		t.Fatal("unstattable upperdir accepted")
	}
	// Reattest refuses an upper that comes to alias a lower after keying.
	f = newImageFixture()
	r = f.resolver(t)
	layers, _ = r.Resolve(context.Background(), "0123abcd", testInit)
	if _, err := r.Keys(layers); err != nil {
		t.Fatal(err)
	}
	f.host.lowers[testUpper] = f.host.lowers[testLowers[0]]
	if err := r.Reattest(context.Background(), layers); err == nil {
		t.Fatal("reattest accepted aliasing upper")
	}
}

func TestSharedImageLayerResolverConfig(t *testing.T) {
	f := newImageFixture()
	r := f.resolver(t)
	if r.quota != sharedImageLayersMax {
		t.Fatalf("default quota %d", r.quota)
	}
	if _, err := newSharedImageLayerResolver(f.source, f.host, sharedImageLayersMax+1); err == nil {
		t.Fatal("quota over the index ceiling accepted")
	}
	if _, err := newSharedImageLayerResolver(nil, f.host, 0); err == nil {
		t.Fatal("nil source accepted")
	}
	if _, err := r.Resolve(context.Background(), "", testInit); err == nil {
		t.Fatal("empty container ID accepted")
	}
	if _, err := r.Resolve(context.Background(), "c", SharedInitIdentity{TGID: 1}); !errors.Is(err, ErrSharedImageAttestation) {
		t.Fatalf("zero start ticks: %v", err)
	}
	f.source.err = errors.New("not found")
	if _, err := r.Resolve(context.Background(), "c", testInit); err == nil || errors.Is(err, ErrSharedImageIndexUnsupported) {
		t.Fatalf("source error: %v", err)
	}
}

func TestSharedImageQuotaBoundary(t *testing.T) {
	lowers := make([]string, sharedImageLayersMax+1)
	for i := range lowers {
		lowers[i] = testSnapFS(1000 + i)
	}
	opts := func(n int) []string {
		return []string{"workdir=" + testWork, "upperdir=" + testUpper, "lowerdir=" + strings.Join(lowers[:n], ":")}
	}
	if _, _, err := parseSharedImageSnapshot(testOverlayRootfs(opts(sharedImageLayersMax)...), sharedImageLayersMax); err != nil {
		t.Fatalf("128 lowers: %v", err)
	}
	if _, _, err := parseSharedImageSnapshot(testOverlayRootfs(opts(sharedImageLayersMax+1)...), sharedImageLayersMax); !errors.Is(err, ErrSharedImageIndexUnsupported) {
		t.Fatalf("129 lowers: %v", err)
	}
}

// TestSharedKernelDevEncoding pins the dev_t used for BPF: the kernel's
// MKDEV (major<<20|minor), not userspace new_encode_dev (unix.Mkdev).
func TestSharedKernelDevEncoding(t *testing.T) {
	for _, tc := range []struct {
		major, minor uint32
		want         uint32
	}{
		{0, 312, 312},
		{0, 0xfffff, 0xfffff},
		{259, 1, 259<<20 | 1},
		{8, 0x1234, 8<<20 | 0x1234},
	} {
		got, err := sharedKernelDev(tc.major, tc.minor)
		if err != nil || got != tc.want {
			t.Fatalf("%d:%d -> %#x %v, want %#x", tc.major, tc.minor, got, err, tc.want)
		}
		// Round trip through the userspace encoding stat(2) returns.
		st := unix.Mkdev(tc.major, tc.minor)
		if unix.Major(st) != tc.major || unix.Minor(st) != tc.minor {
			t.Fatalf("userspace round trip %d:%d", tc.major, tc.minor)
		}
	}
	// The encodings differ once the minor exceeds 8 bits or major is set.
	if st := unix.Mkdev(259, 0x1234); uint64(259<<20|0x1234) == st {
		t.Fatal("kernel and userspace dev_t unexpectedly equal")
	}
	if _, err := sharedKernelDev(1<<12, 0); err == nil {
		t.Fatal("13-bit major accepted")
	}
	if _, err := sharedKernelDev(0, 1<<20); err == nil {
		t.Fatal("21-bit minor accepted")
	}
	k, err := SharedImageLayerKey{Ino: 1, Major: 259, Minor: 3}.KernelDev()
	if err != nil || k != 259<<20|3 {
		t.Fatalf("key kernel dev %#x %v", k, err)
	}
}

func TestParseSharedMountinfo(t *testing.T) {
	// AL2023 EKS node (kernel 6.1, containerd 2.x, SELinux), 12 lowers.
	var al2023Lowers []string
	for i := 112; i > 100; i-- {
		al2023Lowers = append(al2023Lowers, testSnapFS(i))
	}
	al2023 := "2721 2490 0:388 / / rw,relatime master:1201 - overlay overlay rw,seclabel,lowerdir=" + strings.Join(al2023Lowers, ":") +
		",upperdir=" + testSnapFS(113) + ",workdir=" + testSnapRoot + "/113/work,uuid=on,nouserxattr"
	tests := []struct {
		name, line  string
		wantErr     bool
		major       uint32
		minor       uint32
		mountPoint  string
		fstype      string
		superOption string
	}{
		{name: "al2023 containerd root", line: al2023, minor: 388, mountPoint: "/", fstype: "overlay", superOption: "upperdir=" + testSnapFS(113)},
		{name: "no optional fields", line: "25 1 259:1 / / rw,noatime - xfs /dev/nvme0n1p1 rw,attr2", major: 259, minor: 1, mountPoint: "/", fstype: "xfs", superOption: "attr2"},
		{name: "escaped space and comma", line: `40 25 0:50 / /mnt/a\040b rw shared:1 - overlay overlay rw,upperdir=/u\054x\040y`, minor: 50, mountPoint: "/mnt/a b", fstype: "overlay", superOption: "upperdir=/u,x y"},
		{name: "multiple optional fields", line: "41 25 0:51 / /x rw shared:2 master:3 propagate_from:4 - tmpfs tmpfs rw", minor: 51, mountPoint: "/x", fstype: "tmpfs", superOption: "rw"},
		{name: "no separator", line: "41 25 0:51 / /x rw shared:2 tmpfs tmpfs rw", wantErr: true},
		{name: "trailing fields", line: "41 25 0:51 / /x rw - tmpfs tmpfs rw extra", wantErr: true},
		{name: "bad device", line: "41 25 051 / /x rw - tmpfs tmpfs rw", wantErr: true},
		{name: "bad major", line: "41 25 x:51 / /x rw - tmpfs tmpfs rw", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := parseSharedMountinfoLine(tt.line)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("accepted %+v", e)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, o := range e.SuperOptions {
				found = found || o == tt.superOption
			}
			if e.Major != tt.major || e.Minor != tt.minor || e.MountPoint != tt.mountPoint || e.FSType != tt.fstype || !found {
				t.Fatalf("parsed %+v", e)
			}
		})
	}
	root, err := parseSharedRootMount(testMountinfo(al2023))
	if err != nil {
		t.Fatal(err)
	}
	opts, err := parseSharedOverlayOptions(root.SuperOptions, false)
	if err != nil {
		t.Fatal(err)
	}
	if opts.upper != testSnapFS(113) || fmt.Sprint(opts.lowers) != fmt.Sprint(al2023Lowers) {
		t.Fatalf("al2023 options %+v", opts)
	}
	if _, err := parseSharedRootMount([]byte("garbage\n")); !errors.Is(err, ErrSharedImageAttestation) {
		t.Fatalf("garbage mountinfo: %v", err)
	}
	if got := unescapeSharedMountinfo(`a\134b\0`); got != `a\b\0` {
		t.Fatalf("unescape %q", got)
	}
}

func TestSharedImageLedger(t *testing.T) {
	if _, err := newSharedImageLedger(0, 10); err == nil {
		t.Fatal("zero per-binding quota accepted")
	}
	if _, err := newSharedImageLedger(11, 10); err == nil {
		t.Fatal("per-binding quota above pool accepted")
	}
	l, err := newSharedImageLedger(4, 6)
	if err != nil {
		t.Fatal(err)
	}
	steps := []struct {
		name string
		op   func() error
		ok   bool
	}{
		{"reserve slot1 gen1", func() error { return l.Reserve(1, 1, 3) }, true},
		{"reserve duplicate", func() error { return l.Reserve(1, 1, 1) }, false},
		{"reserve zero", func() error { return l.Reserve(1, 2, 0) }, false},
		{"slot1 gen2 over per-binding", func() error { return l.Reserve(1, 2, 2) }, false},
		{"slot1 gen2 fits", func() error { return l.Reserve(1, 2, 1) }, true},
		{"slot2 over pool", func() error { return l.Reserve(2, 1, 3) }, false},
		{"slot2 fits pool", func() error { return l.Reserve(2, 1, 2) }, true},
		{"present over reserved", func() error { return l.SetPresent(1, 1, 4) }, false},
		{"present unreserved", func() error { return l.SetPresent(3, 1, 1) }, false},
		{"present slot1 gen1", func() error { return l.SetPresent(1, 1, 3) }, true},
		{"present slot1 gen2", func() error { return l.SetPresent(1, 2, 1) }, true},
		{"present slot2 partial", func() error { return l.SetPresent(2, 1, 1) }, true},
	}
	for _, s := range steps {
		if err := s.op(); (err == nil) != s.ok || (err != nil && !errors.Is(err, ErrSharedImageLedger)) {
			t.Fatalf("%s: %v", s.name, err)
		}
	}
	if got := l.Binding(1); got != (SharedImageLedgerEntry{Reserved: 4, Present: 4}) {
		t.Fatalf("slot1 %+v", got)
	}
	if got := l.Totals(); got != (SharedImageLedgerEntry{Reserved: 6, Present: 5}) {
		t.Fatalf("totals %+v", got)
	}
	if e, ok := l.Entry(2, 1); !ok || e != (SharedImageLedgerEntry{Reserved: 2, Present: 1}) {
		t.Fatalf("slot2 entry %+v %v", e, ok)
	}
	if err := l.CheckKernel(1, 4); err != nil {
		t.Fatal(err)
	}
	if err := l.CheckKernel(2, 2); !errors.Is(err, ErrSharedImageLedger) {
		t.Fatalf("kernel mismatch: %v", err)
	}
	if err := l.Release(1, 1); err != nil {
		t.Fatal(err)
	}
	if err := l.Release(1, 1); !errors.Is(err, ErrSharedImageLedger) {
		t.Fatalf("double release: %v", err)
	}
	if err := l.Reserve(3, 1, 3); err != nil {
		t.Fatalf("released cells not returned to the pool: %v", err)
	}
	if got := l.Totals(); got != (SharedImageLedgerEntry{Reserved: 6, Present: 2}) {
		t.Fatalf("totals after release %+v", got)
	}
}

// TestSharedImageProcHostSelf exercises the live host reads against this
// test process; it asserts only host-independent facts.
func TestSharedImageProcHostSelf(t *testing.T) {
	host := sharedImageProcHost{}
	dir := t.TempDir()
	st, err := host.LowerRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	var want unix.Stat_t
	if err := unix.Stat(dir, &want); err != nil {
		t.Fatal(err)
	}
	if !st.Dir || st.Key != (SharedImageLayerKey{Ino: want.Ino, Major: unix.Major(want.Dev), Minor: unix.Minor(want.Dev)}) {
		t.Fatalf("lower root %+v, stat dev %#x ino %d", st, want.Dev, want.Ino)
	}
	if _, err := host.LowerRoot(dir + "/missing"); err == nil {
		t.Fatal("missing lower root accepted")
	}
	pid := uint32(unix.Getpid())
	view, err := host.InitView(SharedInitIdentity{TGID: pid})
	if err != nil {
		t.Fatal(err)
	}
	var root, ns unix.Stat_t
	if err := unix.Stat("/", &root); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat("/proc/self/ns/mnt", &ns); err != nil {
		t.Fatal(err)
	}
	if view.StartTicks == 0 || view.EndTicks != view.StartTicks || view.MountNS != ns.Ino ||
		view.RootMajor != unix.Major(root.Dev) || view.RootMinor != unix.Minor(root.Dev) || len(view.Mountinfo) == 0 {
		t.Fatalf("view %+v", view)
	}
	// Every line of a real mountinfo parses (the root itself may be
	// stacked on a dev host, so exactly-one-"/" is not asserted here).
	for _, line := range strings.Split(strings.TrimRight(string(view.Mountinfo), "\n"), "\n") {
		if _, err := parseSharedMountinfoLine(line); err != nil {
			t.Fatal(err)
		}
	}
}
