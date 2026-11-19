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
	"time"

	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

// TestImageOriginKernel is an isolated overlay-origin spike, not production readiness.
func TestImageOriginKernel(t *testing.T) {
	if os.Getenv("IG_EXEC_IMAGE_KERNEL_TEST") != "1" {
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
	source := os.Getenv("IG_EXEC_IMAGE_BPF_SOURCE")
	if source == "" {
		source = "bpf/image.bpf.c"
	}
	object := filepath.Join(tmp, "image.bpf.o")
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
	attached, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs["check_image"]})
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	cgroup := fmt.Sprintf("/sys/fs/cgroup/ig-image-%d", os.Getpid())
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
	binary, err := os.ReadFile("/usr/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	helperSource, helper := filepath.Join(tmp, "helper.c"), filepath.Join(tmp, "helper")
	if err = os.WriteFile(helperSource, []byte(imageHelper), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-O2", helperSource, "-o", helper).CombinedOutput(); err != nil {
		t.Fatalf("helper: %v %s", err, out)
	}
	for _, metacopy := range []string{"off", "on"} {
		t.Run("metacopy-"+metacopy, func(t *testing.T) {
			root := filepath.Join(tmp, metacopy)
			lower, upper, work, merged := filepath.Join(root, "lower"), filepath.Join(root, "upper"), filepath.Join(root, "work"), filepath.Join(root, "merged")
			for _, dir := range []string{lower, upper, work, merged} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{"untouched", "copy", "metadata", "fd", "before", "after", "writer"} {
				mode := os.FileMode(0o755)
				if name == "metadata" {
					mode = 0o644
				}
				if err := os.WriteFile(filepath.Join(lower, name), binary, mode); err != nil {
					t.Fatal(err)
				}
			}
			// Index ALL regular lower files, including metadata without execute bits.
			// Lower directory content remains immutable after this complete walk.
			if err := filepath.WalkDir(lower, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				var st unix.Stat_t
				if err = unix.Stat(path, &st); err != nil {
					return err
				}
				if st.Mode&unix.S_IFMT != unix.S_IFREG {
					return fmt.Errorf("nonregular lower")
				}
				key := struct {
					Inode        uint64
					Major, Minor uint32
				}{st.Ino, unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev))}
				return collection.Maps["origins"].Put(key, uint8(1))
			}); err != nil {
				t.Fatal(err)
			}
			// This kernel requires redirect_dir=on with metacopy=on. The
			// fixture creates no redirects; this does not prove redirected
			// lower paths safe for a production origin index.
			redirect := "nofollow"
			if metacopy == "on" {
				redirect = "on"
			}
			opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s,metacopy=%s,redirect_dir=%s,index=off", lower, upper, work, metacopy, redirect)
			if err := unix.Mount("overlay", merged, "overlay", 0, opts); err != nil {
				t.Fatalf("required overlay matrix unsupported (NOT proof): %v", err)
			}
			defer func() {
				if err := unix.Unmount(merged, 0); err != nil {
					t.Errorf("unmount exact fixture: %v", err)
				}
			}()
			if err := collection.Maps["ready"].Put(uint32(0), uint32(1)); err != nil {
				t.Fatal(err)
			}
			defer collection.Maps["ready"].Put(uint32(0), uint32(0))
			run := func(name, mode string, want int32, bound bool) {
				t.Helper()
				target := filepath.Join(merged, name)
				entry := struct {
					Cgroup uint64
					Path   [256]byte
				}{Cgroup: stat.Ino}
				copy(entry.Path[:], target)
				if len(target) >= len(entry.Path) {
					t.Fatal("target too long")
				}
				if err := collection.Maps["targets"].Put(uint32(0), entry); err != nil {
					t.Fatal(err)
				}
				zero := struct {
					Value int32
					Count uint32
				}{}
				if err := collection.Maps["results"].Put(uint32(0), zero); err != nil {
					t.Fatal(err)
				}
				cmd := exec.Command(helper, mode, target)
				if bound {
					cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
				}
				var output []byte
				var err error
				if mode == "pause-before" || mode == "pause-after" {
					phase := uint32(1)
					if mode == "pause-after" {
						phase = 2
					}
					type control struct{ When, Hold, Phase, Timedout uint32 }
					ctrl := control{When: phase, Hold: 1}
					if err := collection.Maps["pause_control"].Put(uint32(0), ctrl); err != nil {
						t.Fatal(err)
					}
					defer collection.Maps["pause_control"].Put(uint32(0), control{})
					type completion struct {
						out []byte
						err error
					}
					done := make(chan completion, 1)
					go func() { out, err := cmd.CombinedOutput(); done <- completion{out, err} }()
					deadline := time.Now().Add(3 * time.Second)
					for {
						if err := collection.Maps["pause_control"].Lookup(uint32(0), &ctrl); err != nil {
							t.Fatal(err)
						}
						if ctrl.Phase == phase {
							break
						}
						select {
						case result := <-done:
							t.Fatalf("child ended before pause: %v %s", result.err, result.out)
						default:
						}
						if time.Now().After(deadline) {
							t.Fatal("rendezvous scheduling timeout")
						}
						time.Sleep(50 * time.Microsecond)
					}
					// chmod can copy up metadata (or the full identical lower
					// contents with metacopy off) while open_exec owns denywrite.
					mutationErr := os.Chmod(target, 0o700)
					writer, writeErr := os.OpenFile(target, os.O_WRONLY, 0)
					if writer != nil {
						writer.Close()
					}
					if err := collection.Maps["pause_control"].Lookup(uint32(0), &ctrl); err != nil {
						t.Fatal(err)
					}
					timedout := ctrl.Timedout
					ctrl.Hold = 0
					if err := collection.Maps["pause_control"].Put(uint32(0), ctrl); err != nil {
						t.Fatal(err)
					}
					result := <-done
					output, err = result.out, result.err
					if mutationErr != nil {
						t.Fatalf("copy-up chmod: %v", mutationErr)
					}
					if timedout != 0 {
						t.Fatal("bounded rendezvous expired: NOT concurrency proof")
					}
					if !errors.Is(writeErr, syscall.ETXTBSY) {
						t.Fatalf("overlay writer while exec held must fail ETXTBSY, got %v", writeErr)
					}
					data, readErr := os.ReadFile(target)
					if readErr != nil || !bytes.Equal(data, binary) {
						t.Fatalf("copyup changed immutable data: %v", readErr)
					}
					t.Logf("phase%d copy-up concurrent with exec: writer ETXTBSY, contents unchanged", phase)
				} else {
					output, err = cmd.CombinedOutput()
				}
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
				if err := collection.Maps["results"].Lookup(uint32(0), &result); err != nil {
					t.Fatal(err)
				}
				expectedExit := 0
				if bound {
					if result.Count != 1 || result.Value != want {
						t.Fatalf("%s/%s result%+v want%d exit%d %s", name, mode, result, want, exit, output)
					}
					if want == 0 {
						expectedExit = int(syscall.EPERM)
					} else if want < 0 {
						expectedExit = int(syscall.EOPNOTSUPP)
					}
				} else if result.Count != 0 {
					t.Fatalf("unbound observed: %+v", result)
				}
				if exit != expectedExit {
					t.Fatalf("%s/%s exit%d want%d %s", name, mode, exit, expectedExit, output)
				}
				t.Logf("%s/%s bound=%v origin=%d exit=%d", name, mode, bound, result.Value, exit)
			}
			run("untouched", "plain", 1, true)
			if err := os.WriteFile(filepath.Join(merged, "created"), binary, 0o755); err != nil {
				t.Fatal(err)
			}
			run("created", "plain", 0, true)
			run("created", "plain", 0, false)
			if err := os.WriteFile(filepath.Join(merged, "copy"), binary, 0o755); err != nil {
				t.Fatal(err)
			}
			run("copy", "plain", 0, true)
			if err := os.Chmod(filepath.Join(merged, "metadata"), 0o755); err != nil {
				t.Fatal(err)
			}
			if metacopy == "on" {
				x := make([]byte, 256)
				if _, err := unix.Getxattr(filepath.Join(upper, "metadata"), "trusted.overlay.metacopy", x); err != nil {
					t.Fatalf("metadata-only copy not established: %v", err)
				}
				run("metadata", "plain", 1, true)
			} else {
				run("metadata", "plain", 0, true)
			}
			if err := os.WriteFile(filepath.Join(merged, "metadata"), binary, 0o755); err != nil {
				t.Fatal(err)
			}
			run("metadata", "plain", 0, true)
			// do_open_execat calls do_file_open even for AT_EMPTY_PATH:
			// exec gets a fresh file backed by current upper, not the old fd.
			run("fd", "copy-fd", 0, true)
			before := int32(-1)
			if metacopy == "on" {
				before = 1
			}
			run("before", "pause-before", before, true)
			run("after", "pause-after", 1, true)
			// A writer already open before open_exec is refused before LSM.
			writer, err := os.OpenFile(filepath.Join(merged, "writer"), os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(helper, "plain", filepath.Join(merged, "writer"))
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
			out, err := cmd.CombinedOutput()
			writer.Close()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != int(syscall.ETXTBSY) {
				t.Fatalf("preexisting writer must refuse exec: %v %s", err, out)
			}
			t.Log("preexisting overlay writer: exec ETXTBSY")
		})
	}
	if out, err := exec.Command("uname", "-a").Output(); err == nil {
		t.Logf("kernel: %s", out)
	}
}

const imageHelper = `
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
extern char **environ;
int main(int argc,char **argv){
 if(argc!=3)return 99;
 char *args[]={argv[2],0};
 if(!strcmp(argv[1],"copy-fd")){
  int fd=open(argv[2],O_RDONLY);if(fd<0)return 99;
  /* Copy up, preserve bytes, then close writer to avoid ETXTBSY. Keep the
     originally opened lower read fd and execute through it. */
  int writer=open(argv[2],O_WRONLY);if(writer<0)return 99;
  if(close(writer))return 99;
  execveat(fd,"",args,environ,AT_EMPTY_PATH);return errno;
 }
 execv(argv[2],args);return errno;
}
`
