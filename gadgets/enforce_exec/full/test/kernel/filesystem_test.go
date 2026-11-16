// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

func loadFilesystemFixture(t *testing.T) *ebpf.Collection {
	t.Helper()
	if os.Getenv("IG_EXEC_FS_KERNEL_TEST") != "1" {
		t.Skip("requires explicit disposable kernel opt-in")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	b, err := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c").Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "vmlinux.h"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	source := os.Getenv("IG_EXEC_FS_BPF_SOURCE")
	if source == "" {
		source = "bpf/filesystem.bpf.c"
	}
	object := filepath.Join(tmp, "fs.bpf.o")
	if out, err := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-I"+tmp, "-c", source, "-o", object).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v %s", err, out)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024}})
	if err != nil {
		var v *ebpf.VerifierError
		if errors.As(err, &v) {
			t.Logf("%+v", v)
		}
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestFilesystemABI(t *testing.T) {
	c := loadFilesystemFixture(t)
	for _, name := range []string{"fs_track", "fs_check"} {
		attached, err := link.AttachLSM(link.LSMOptions{Program: c.Programs[name]})
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		attached.Close()
	}
	t.Log("anon-class inode storage marking and trusted exec inode lookup verified/load/attach; no classification proof yet")
}

func TestFilesystemKernel(t *testing.T) {
	c := loadFilesystemFixture(t)
	tmp := t.TempDir()
	binary, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	oldfd, err := unix.MemfdCreate("old-untracked", 0)
	if err != nil {
		t.Fatal(err)
	}
	old := os.NewFile(uintptr(oldfd), "old")
	defer old.Close()
	if _, err := old.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := old.Chmod(0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"fs_track", "fs_check"} {
		attached, err := link.AttachLSM(link.LSMOptions{Program: c.Programs[name]})
		if err != nil {
			t.Fatal(err)
		}
		defer attached.Close()
	}
	cgpath := fmt.Sprintf("/sys/fs/cgroup/ig-filesystem-%d", os.Getpid())
	if err := os.Mkdir(cgpath, 0o755); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := os.Remove(cgpath); err != nil {
			t.Errorf("cleanup cgroup: %v", err)
		}
	}()
	cg, err := os.Open(cgpath)
	if err != nil {
		t.Fatal(err)
	}
	defer cg.Close()
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(cg.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(tmp, "helper")
	if err := os.WriteFile(helper+".c", []byte(filesystemHelper), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-O2", helper+".c", "-o", helper).CombinedOutput(); err != nil {
		t.Fatalf("helper: %v %s", err, out)
	}
	open := func(path string) *os.File {
		t.Helper()
		f, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { f.Close() })
		return f
	}
	regular := filepath.Join(tmp, "regular")
	if err := os.WriteFile(regular, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(name string, file *os.File, required, wantMask, wantKnown uint32, wantExit int) {
		t.Helper()
		config := struct {
			Cgroup            uint64
			Enforce, Required uint32
		}{stat.Ino, 1, required}
		if err := c.Maps["fs_probe_config"].Put(uint32(0), config); err != nil {
			t.Fatal(err)
		}
		type result struct{ Mask, Known, Count uint32 }
		if err := c.Maps["fs_probe_result"].Put(uint32(0), result{}); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(helper)
		cmd.ExtraFiles = []*os.File{file}
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
		output, err := cmd.CombinedOutput()
		exit := 0
		if err != nil {
			var e *exec.ExitError
			if !errors.As(err, &e) {
				t.Fatalf("%s start: %v %s", name, err, output)
			}
			exit = e.ExitCode()
		}
		var got result
		if err := c.Maps["fs_probe_result"].Lookup(uint32(0), &got); err != nil {
			t.Fatal(err)
		}
		if got.Count < 2 || got.Mask != wantMask || got.Known != wantKnown || exit != wantExit {
			t.Fatalf("%s result%+v exit%d want mask%d known%d exit%d %s", name, got, exit, wantMask, wantKnown, wantExit, output)
		}
		t.Logf("%s mask=%d known=%d errno=%d", name, got.Mask, got.Known, exit)
	}
	run("regular", open(regular), 2, 0, 15, 0)
	// User-supplied name is irrelevant; pre-attachment memfd remains unknown.
	run("preexisting-memfd", old, 2, 1, 13, int(syscall.EOPNOTSUPP))
	fd, err := unix.MemfdCreate("definitely-not-a-prefix", 0)
	if err != nil {
		t.Fatal(err)
	}
	memfd := os.NewFile(uintptr(fd), "memfd")
	defer memfd.Close()
	if _, err := memfd.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := memfd.Chmod(0o755); err != nil {
		t.Fatal(err)
	}
	run("tracked-memfd", memfd, 2, 3, 15, int(syscall.EPERM))
	// Dedicated exec-capable tmpfs: do not depend on /dev/shm noexec options.
	shm := filepath.Join(tmp, "shm")
	if err := os.Mkdir(shm, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tmpfs", shm, "tmpfs", 0, "size=8m"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Unmount(shm, 0); err != nil {
			t.Errorf("tmpfs cleanup: %v", err)
		}
	}()
	spoof := filepath.Join(shm, "memfd:spoof")
	if err := os.WriteFile(spoof, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	spoofFile, err := os.Open(spoof)
	if err != nil {
		t.Fatal(err)
	}
	defer spoofFile.Close()
	run("tmpfs-positive", spoofFile, 1, 1, 13, int(syscall.EPERM))
	run("filename-not-memfd-proof", spoofFile, 2, 1, 13, int(syscall.EOPNOTSUPP))
	run("unknown-or-known-positive", spoofFile, 3, 1, 13, int(syscall.EPERM))
	deleted := filepath.Join(tmp, "deleted")
	if err := os.WriteFile(deleted, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	deletedFile := open(deleted)
	if err := os.Remove(deleted); err != nil {
		t.Fatal(err)
	}
	run("unlinked-dentry", deletedFile, 4, 4, 15, int(syscall.EPERM))
	lower, upper, work, merged := filepath.Join(tmp, "lower"), filepath.Join(tmp, "upper"), filepath.Join(tmp, "work"), filepath.Join(tmp, "merged")
	for _, dir := range []string{lower, upper, work, merged} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(lower, "target"), binary, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("overlay", merged, "overlay", 0, fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lower, upper, work)); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Unmount(merged, 0); err != nil {
			t.Errorf("overlay cleanup: %v", err)
		}
	}()
	overlay, err := os.Open(filepath.Join(merged, "target"))
	if err != nil {
		t.Fatal(err)
	}
	defer overlay.Close()
	run("overlay-positive", overlay, 8, 8, 15, int(syscall.EPERM))
	// The memfd class hook must also mark hugepage-backed memfds, even when
	// no hugepage pool is provisioned for executable content.
	hugefd, err := unix.MemfdCreate("hugetlb-class", unix.MFD_HUGETLB|unix.MFD_HUGE_2MB)
	if err != nil {
		t.Fatalf("hugetlb creation unsupported (not proof): %v", err)
	}
	huge := os.NewFile(uintptr(hugefd), "hugetlb")
	defer huge.Close()
	var marker uint64
	if err := c.Maps["fs_inode_origins"].Lookup(uint32(hugefd), &marker); err != nil || marker != 1 {
		t.Fatalf("hugetlb authoritative marker=%d err=%v", marker, err)
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(hugefd, &fs); err != nil || uint64(fs.Type) != 0x958458f6 {
		t.Fatalf("hugetlb backing: %+v %v", fs, err)
	}
	t.Log("MFD_HUGETLB authoritative inode marker and backing verified")
	if os.Getenv("IG_EXEC_FS_HUGETLB_EXEC") == "1" {
		freeBytes, err := os.ReadFile("/sys/kernel/mm/hugepages/hugepages-2048kB/free_hugepages")
		if err != nil {
			t.Fatal(err)
		}
		free, err := strconv.Atoi(strings.TrimSpace(string(freeBytes)))
		if err != nil || free < 1 {
			t.Fatal("hugetlb exec proof requires at least one free 2MiB hugepage in disposable guest")
		}
		if err := unix.Ftruncate(hugefd, 2<<20); err != nil {
			t.Fatal(err)
		}
		mapping, err := unix.Mmap(hugefd, 0, 2<<20, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED)
		if err != nil {
			t.Fatal(err)
		}
		copy(mapping, binary)
		if err := unix.Munmap(mapping); err != nil {
			t.Fatal(err)
		}
		if err := huge.Chmod(0o755); err != nil {
			t.Fatal(err)
		}
		run("hugetlb-memfd-exec", huge, 2, 2, 15, int(syscall.EPERM))
	} else {
		t.Log("hugetlb execution NOT PROVEN; opt in IG_EXEC_FS_HUGETLB_EXEC=1 with a preprovisioned hugepage")
	}
	// Exhaust finite lifetime credits without denying the global creation.
	for i := 0; i < 20; i++ {
		fd, err := unix.MemfdCreate("budget", 0)
		if err != nil {
			t.Fatalf("tracking must not deny unrelated creation: %v", err)
		}
		unix.Close(fd)
	}
	var diagnostics struct{ Credits, Faults uint64 }
	if err := c.Maps["fs_diagnostics"].Lookup(uint32(0), &diagnostics); err != nil {
		t.Fatal(err)
	}
	if diagnostics.Credits != 16 || diagnostics.Faults&1 == 0 {
		t.Fatalf("finite lifetime bound not enforced: %+v", diagnostics)
	}
	untrackedFD, err := unix.MemfdCreate("exhausted", 0)
	if err != nil {
		t.Fatal(err)
	}
	untracked := os.NewFile(uintptr(untrackedFD), "exhausted")
	defer untracked.Close()
	if _, err := untracked.Write(binary); err != nil {
		t.Fatal(err)
	}
	if err := untracked.Chmod(0o755); err != nil {
		t.Fatal(err)
	}
	run("budget-unknown-not-false", untracked, 2, 1, 13, int(syscall.EOPNOTSUPP))
	run("existing-marker-survives-exhaustion", memfd, 2, 3, 15, int(syscall.EPERM))
}

const filesystemHelper = `
#define _GNU_SOURCE
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
extern char **environ;
int main(void){char*args[]={"target",0};execveat(3,"",args,environ,AT_EMPTY_PATH);return errno;}
`
