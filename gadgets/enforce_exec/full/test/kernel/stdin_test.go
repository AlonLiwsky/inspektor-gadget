// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// TestStdinKernel establishes only the restricted sole-files-owner snapshot.
// It is not general shared-table support or full image readiness evidence.
func TestStdinKernel(t *testing.T) {
	if os.Getenv("IG_EXEC_STDIN_KERNEL_TEST") != "1" {
		t.Skip("requires explicitly selected disposable BPF-LSM host")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	header := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c")
	var diagnostic bytes.Buffer
	header.Stderr = &diagnostic
	b, err := header.Output()
	if err != nil {
		t.Fatalf("BTF: %v %s", err, diagnostic.String())
	}
	if err = os.WriteFile(filepath.Join(tmp, "vmlinux.h"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	source := os.Getenv("IG_EXEC_STDIN_BPF_SOURCE")
	if source == "" {
		source = "bpf/stdin.bpf.c"
	}
	object := filepath.Join(tmp, "stdin.bpf.o")
	out, err := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-I"+tmp, "-c", source, "-o", object).CombinedOutput()
	if err != nil {
		t.Fatalf("compile: %v\n%s", err, out)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 8 * 1024 * 1024}})
	if err != nil {
		var v *ebpf.VerifierError
		if errors.As(err, &v) {
			t.Logf("%+v", v)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	attached, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs["check_stdin"]})
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	cgroup := fmt.Sprintf("/sys/fs/cgroup/ig-stdin-%d", os.Getpid())
	if err = os.Mkdir(cgroup, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cgroup)
	cg, err := os.Open(cgroup)
	if err != nil {
		t.Fatal(err)
	}
	defer cg.Close()
	var stat syscall.Stat_t
	if err = syscall.Fstat(int(cg.Fd()), &stat); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(tmp, "target")
	binary, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(target, binary, 0o755); err != nil {
		t.Fatal(err)
	}
	targetEntry := struct {
		Cgroup uint64
		Path   [256]byte
	}{Cgroup: stat.Ino}
	copy(targetEntry.Path[:], target)
	if err = collection.Maps["targets"].Put(uint32(0), targetEntry); err != nil {
		t.Fatal(err)
	}
	helperSource := filepath.Join(tmp, "helper.c")
	helper := filepath.Join(tmp, "helper")
	if err = os.WriteFile(helperSource, []byte(stdinHelper), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err = exec.Command("cc", "-O2", "-pthread", helperSource, "-o", helper).CombinedOutput(); err != nil {
		t.Fatalf("helper: %v %s", err, out)
	}
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readPipe.Close()
	defer writePipe.Close()
	regular, err := os.Create(filepath.Join(tmp, "input"))
	if err != nil {
		t.Fatal(err)
	}
	defer regular.Close()
	fifoPath := filepath.Join(tmp, "fifo")
	if err = syscall.Mkfifo(fifoPath, 0o600); err != nil {
		t.Fatal(err)
	}
	fifo, err := os.OpenFile(fifoPath, os.O_RDWR|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fifo.Close()
	run := func(t *testing.T, mode string, stdin *os.File, want int32) {
		t.Helper()
		zero := struct {
			Value int32
			Count uint32
		}{}
		if err := collection.Maps["results"].Put(uint32(0), zero); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(helper, mode, target)
		cmd.Stdin = stdin
		cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
		output, err := cmd.CombinedOutput()
		exit := 0
		if err != nil {
			var e *exec.ExitError
			if !errors.As(err, &e) {
				t.Fatalf("start: %v %s", err, output)
			}
			exit = e.ExitCode()
		}
		var result struct {
			Value int32
			Count uint32
		}
		if err = collection.Maps["results"].Lookup(uint32(0), &result); err != nil {
			t.Fatal(err)
		}
		if result.Count != 1 {
			t.Fatalf("expected one target observation, got %+v exit=%d %s", result, exit, output)
		}
		if want == 2 {
			if result.Value != 1 && result.Value != -1 {
				t.Fatalf("count2->1 transition produced false: %+v", result)
			}
		} else if result.Value != want {
			t.Fatalf("stdin result %+v want%d exit%d %s", result, want, exit, output)
		}
		expectedExit := 0
		if result.Value == 1 {
			expectedExit = int(syscall.EPERM)
		} else if result.Value < 0 {
			expectedExit = int(syscall.EOPNOTSUPP)
		}
		if exit != expectedExit {
			t.Fatalf("kernel result%d expected exit%d got%d %s", result.Value, expectedExit, exit, output)
		}
	}
	for _, tc := range []struct {
		name, mode string
		stdin      *os.File
		want       int32
	}{{"pipe", "plain", readPipe, 1}, {"regular", "plain", regular, 0}, {"fifo", "plain", fifo, 1}, {"cloexec-pipe", "cloexec", readPipe, 0}, {"closed", "closed", readPipe, 0}, {"shared-table-refused", "shared", readPipe, -1}, {"joined-owner", "joined", readPipe, 1}} {
		t.Run(tc.name, func(t *testing.T) { run(t, tc.mode, tc.stdin, tc.want) })
	}
	t.Run("count-two-to-one", func(t *testing.T) {
		for range 50 {
			run(t, "race", readPipe, 2)
		}
	})
	if out, err := exec.Command("uname", "-a").Output(); err == nil {
		t.Logf("kernel: %s", out)
	}
	t.Log("restricted sole-owner stdin proof; shared tables remain unsupported")
}

const stdinHelper = `
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
static void *hold(void *arg){(void)arg;for(;;)pause();return 0;}
static void *leave(void *arg){(void)arg;return 0;}
int main(int argc,char**argv){if(argc!=3)return 99;
 pthread_t thread;
 if(!strcmp(argv[1],"cloexec")){if(fcntl(0,F_SETFD,FD_CLOEXEC)<0)return 99;}
 if(!strcmp(argv[1],"closed"))close(0);
 if(!strcmp(argv[1],"shared")){if(pthread_create(&thread,0,hold,0))return 99;}
 if(!strcmp(argv[1],"race")||!strcmp(argv[1],"joined")){if(pthread_create(&thread,0,leave,0))return 99;if(!strcmp(argv[1],"joined"))pthread_join(thread,0);}
 char *args[]={argv[2],0};execv(argv[2],args);return errno;
}`
