// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

type (
	bootstrapSeed  struct{ Owner, UID, Role, Epoch uint64 }
	bootstrapState struct {
		Lock, Owned           uint32
		Role                  bootstrapSeed
		Child, OriginalCgroup uint64
		Slot, Padding         uint32
		TokenOwner            uint64
	}
)

type (
	bootstrapGate  struct{ Word, Faults, Credits, Admitted, Success, Failed, Late, IO, Exits, CompletionCgroup, Owner uint64 }
	bootstrapPause struct {
		Cgroup                         uint64
		Hold, Phase, Timedout, Padding uint32
	}
)

func bootstrapFixture(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	if os.Getenv("IG_EXEC_BOOTSTRAP_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel opt-in required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	header, err := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c").Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "vmlinux.h"), header, 0o600); err != nil {
		t.Fatal(err)
	}
	source := os.Getenv("IG_EXEC_BOOTSTRAP_BPF_SOURCE")
	if source == "" {
		source = "bpf/bootstrap_gate.bpf.c"
	}
	object := filepath.Join(tmp, "bootstrap.o")
	if out, err := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-I"+tmp, "-c", source, "-o", object).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v %s", err, out)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func bootstrapLoad(t *testing.T, spec *ebpf.CollectionSpec) *ebpf.Collection {
	t.Helper()
	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 8 * 1024 * 1024}})
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

func bootstrapAttach(t *testing.T, c *ebpf.Collection, name string) link.Link {
	t.Helper()
	var l link.Link
	var err error
	if name == "bg_admit" {
		l, err = link.AttachLSM(link.LSMOptions{Program: c.Programs[name]})
	} else {
		l, err = link.AttachTracing(link.TracingOptions{Program: c.Programs[name]})
	}
	if err != nil {
		t.Fatalf("attach %s: %v", name, err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func TestBootstrapGateABI(t *testing.T) {
	spec := bootstrapFixture(t)
	for _, name := range []string{"bg_admit", "bg_hold", "bg_newtask", "bg_copy_done", "bg_exit", "bg_io_done"} {
		t.Run(name, func(t *testing.T) {
			single := spec.Copy()
			for other := range single.Programs {
				if other != name {
					delete(single.Programs, other)
				}
			}
			c := bootstrapLoad(t, single)
			bootstrapAttach(t, c, name)
		})
	}
}

// TestBootstrapGateKernel demonstrates concrete hook/token lifetimes only:
// exact-owner drain on success/failure, closed refusal, direct io-thread path,
// pre-admission late attachment, and a scalar inherited role. It does not prove
// complete inventory, lineage authorization, PID reuse coverage, all allocation
// failure paths, or production readiness. Timeout is a failed race experiment.
func TestBootstrapGateKernel(t *testing.T) {
	spec := bootstrapFixture(t)
	tmp := t.TempDir()
	helper := filepath.Join(tmp, "helper")
	if err := os.WriteFile(helper+".c", []byte(bootstrapHelper), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-O2", "-pthread", helper+".c", "-o", helper).CombinedOutput(); err != nil {
		t.Fatalf("helper: %v %s", err, out)
	}
	for _, name := range []string{"open-fork", "closed-refusal", "failed-copy", "vfork", "clone-thread", "nonleader-exec", "migration-owned-token", "signal-interrupt", "late-preattachment", "accepted-role-not-reset", "io-thread"} {
		t.Run(name, func(t *testing.T) {
			c := bootstrapLoad(t, spec.Copy())
			for _, hook := range []string{"bg_hold", "bg_newtask", "bg_copy_done", "bg_exit", "bg_io_done"} {
				bootstrapAttach(t, c, hook)
			}
			if name != "late-preattachment" {
				bootstrapAttach(t, c, "bg_admit")
			}
			cgpath := fmt.Sprintf("/sys/fs/cgroup/ig-bootstrap-%d-%s", os.Getpid(), name)
			otherpath := cgpath + "-other"
			for _, path := range []string{cgpath, otherpath} {
				if err := os.Mkdir(path, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			defer func() {
				for _, path := range []string{cgpath, otherpath} {
					deadline := time.Now().Add(2 * time.Second)
					for {
						err := os.Remove(path)
						if err == nil {
							break
						}
						if !errors.Is(err, syscall.EBUSY) || time.Now().After(deadline) {
							t.Errorf("cgroup cleanup: %v", err)
							break
						}
						// Kill only descendants in this exact disposable fixture
						// if an assertion interrupted their IPC handshake.
						_ = os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0o600)
						time.Sleep(10 * time.Millisecond)
					}
				}
			}()
			cg, err := os.Open(cgpath)
			if err != nil {
				t.Fatal(err)
			}
			defer cg.Close()
			var st, other syscall.Stat_t
			if err := syscall.Fstat(int(cg.Fd()), &st); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Stat(otherpath, &other); err != nil {
				t.Fatal(err)
			}
			if err := c.Maps["bg_bindings"].Put(st.Ino, uint32(0)); err != nil {
				t.Fatal(err)
			}
			if err := c.Maps["bg_bindings"].Put(other.Ino, uint32(1)); err != nil {
				t.Fatal(err)
			}
			if err := c.Maps["bg_gates"].Put(uint32(0), bootstrapGate{Owner: 41}); err != nil {
				t.Fatal(err)
			}
			if err := c.Maps["bg_gates"].Put(uint32(1), bootstrapGate{Owner: 42}); err != nil {
				t.Fatal(err)
			}
			if name == "closed-refusal" || name == "late-preattachment" {
				if err := c.Maps["bg_gates"].Put(uint32(0), bootstrapGate{Word: 1 << 63, Owner: 41}); err != nil {
					t.Fatal(err)
				}
			}
			reader, childWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			childRead, writer, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			defer writer.Close()
			cmd := exec.Command(helper)
			cmd.ExtraFiles = []*os.File{childWrite, childRead}
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd()), Setpgid: true}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			childWrite.Close()
			childRead.Close()
			defer func() { unix.Kill(-cmd.Process.Pid, syscall.SIGKILL); cmd.Wait() }()
			input := bufio.NewReader(reader)
			line := func() string {
				t.Helper()
				reader.SetReadDeadline(time.Now().Add(5 * time.Second))
				s, err := input.ReadString('\n')
				if err != nil {
					t.Fatal(err)
				}
				return strings.TrimSpace(s)
			}
			pid, err := strconv.Atoi(line())
			if err != nil {
				t.Fatal(err)
			}
			pidfd, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pidfd)
			seed := bootstrapSeed{Owner: 41, UID: 7, Role: 13, Epoch: 5}
			if err := c.Maps["bg_seeds"].Put(uint32(pidfd), seed); err != nil {
				t.Fatal(err)
			}
			mode := byte('f')
			switch name {
			case "failed-copy":
				mode = 'b'
			case "vfork":
				mode = 'v'
			case "clone-thread":
				mode = 't'
			case "nonleader-exec":
				mode = 'e'
			case "io-thread":
				mode = 'i'
			}
			held := name == "migration-owned-token" || name == "late-preattachment" || name == "signal-interrupt"
			if held {
				pause := bootstrapPause{Cgroup: st.Ino, Hold: 1}
				if name == "migration-owned-token" {
					pause.Padding = 1
				}
				if err := c.Maps["bg_pauses"].Put(uint32(0), pause); err != nil {
					t.Fatal(err)
				}
			}
			writer.Write([]byte{mode})
			if held {
				deadline := time.Now().Add(3 * time.Second)
				var pause bootstrapPause
				for {
					if err := c.Maps["bg_pauses"].Lookup(uint32(0), &pause); err != nil {
						t.Fatal(err)
					}
					if pause.Phase == 1 {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("allocation hold not reached")
					}
					time.Sleep(50 * time.Microsecond)
				}
				var during bootstrapGate
				if err := c.Maps["bg_gates"].Lookup(uint32(0), &during); err != nil {
					t.Fatal(err)
				}
				switch name {
				case "migration-owned-token":
					if during.Word != 1 {
						t.Fatalf("admission not counted: %+v", during)
					}
					if err := os.WriteFile(filepath.Join(otherpath, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o600); err != nil {
						t.Fatal(err)
					}
				case "late-preattachment":
					if during.Admitted != 0 {
						t.Fatal("late case already counted")
					}
					bootstrapAttach(t, c, "bg_admit")
				}
				// copy_process tests fatal_signal_pending (SIGKILL), not arbitrary SIGTERM.
				if name == "signal-interrupt" {
					if during.Word != 1 {
						t.Fatalf("signal admission not counted: %+v", during)
					}
					if err := unix.Kill(pid, syscall.SIGKILL); err != nil {
						t.Fatal(err)
					}
				}
				if err := c.Maps["bg_pauses"].Lookup(uint32(0), &pause); err != nil {
					t.Fatal(err)
				}
				if pause.Timedout != 0 {
					t.Fatal("bounded hold timed out: no race proof")
				}
				pause.Hold = 0
				if err := c.Maps["bg_pauses"].Put(uint32(0), pause); err != nil {
					t.Fatal(err)
				}
			}
			result := ""
			if name == "signal-interrupt" {
				err := cmd.Wait()
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
					t.Fatalf("signal case termination: %v", err)
				}
			} else {
				result = line()
			}
			switch name {
			case "signal-interrupt":
				// No child becomes runnable after the interrupted copy.
			case "closed-refusal":
				if result != "E11" {
					t.Fatalf("closed fork: %s", result)
				}
			case "failed-copy":
				if result != "E14" {
					t.Fatalf("failed copy: %s", result)
				}
			case "io-thread":
				if result != "I0" {
					t.Fatalf("io_uring SQPOLL unavailable (not coverage proof): %s", result)
				}
				writer.Write([]byte{'x'})
				if line() != "D" {
					t.Fatal("io teardown")
				}
			default:
				child, err := strconv.Atoi(result)
				if err != nil {
					t.Fatalf("child result %q: %v", result, err)
				}
				childFD, err := unix.PidfdOpen(child, 0)
				if err != nil {
					t.Fatal(err)
				}
				var state bootstrapState
				err = c.Maps["bg_states"].Lookup(uint32(childFD), &state)
				unix.Close(childFD)
				if err != nil {
					t.Fatal(err)
				}
				if state.Role != seed || state.Owned != 0 || state.Child != 0 || state.TokenOwner != 0 {
					t.Fatalf("child inheritance/ownership: %+v", state)
				}
				if name == "nonleader-exec" {
					if child != pid {
						t.Fatal("nonleader exec did not replace leader identity")
					}
				} else {
					writer.Write([]byte{'x'})
					if line() != "D" {
						t.Fatal("fork completion")
					}
				}
				if name == "accepted-role-not-reset" {
					changed := seed
					changed.Role = 99
					if err := c.Maps["bg_seeds"].Put(uint32(pidfd), changed); err != nil {
						t.Fatal(err)
					}
					writer.Write([]byte{'f'})
					second, err := strconv.Atoi(line())
					if err != nil {
						t.Fatal(err)
					}
					fd, err := unix.PidfdOpen(second, 0)
					if err != nil {
						t.Fatal(err)
					}
					err = c.Maps["bg_states"].Lookup(uint32(fd), &state)
					unix.Close(fd)
					if err != nil || state.Role != seed {
						t.Fatalf("accepted role reset: %+v %v", state, err)
					}
					writer.Write([]byte{'x'})
					if line() != "D" {
						t.Fatal("second fork completion")
					}
				}
			}
			var gate, otherGate bootstrapGate
			if err := c.Maps["bg_gates"].Lookup(uint32(0), &gate); err != nil {
				t.Fatal(err)
			}
			if err := c.Maps["bg_gates"].Lookup(uint32(1), &otherGate); err != nil {
				t.Fatal(err)
			}
			if gate.Word&((1<<63)-1) != 0 || gate.Faults != 0 || otherGate.Word != 0 || otherGate.Admitted != 0 {
				t.Fatalf("leaked/transferred token: original=%+v other=%+v", gate, otherGate)
			}
			switch name {
			case "closed-refusal":
				if gate.Admitted != 0 || gate.Success != 0 {
					t.Fatal(gate)
				}
			case "failed-copy", "signal-interrupt":
				if gate.Admitted != 1 || gate.Failed != 1 || gate.Success != 0 {
					t.Fatal(gate)
				}
			case "late-preattachment":
				if gate.Admitted != 0 || gate.Late != 1 {
					t.Fatal(gate)
				}
			case "migration-owned-token":
				if gate.Success != 1 || gate.CompletionCgroup != other.Ino {
					t.Fatal(gate)
				}
			case "io-thread":
				if gate.IO == 0 || gate.Success == 0 {
					t.Fatalf("create_io_thread bypass not exercised: %+v", gate)
				}
			default:
				if gate.Success == 0 {
					t.Fatal(gate)
				}
			}
			if held {
				var pause bootstrapPause
				c.Maps["bg_pauses"].Lookup(uint32(0), &pause)
				if pause.Timedout != 0 {
					t.Fatal("hold timeout invalidates race proof")
				}
			}
			if name != "signal-interrupt" {
				writer.Write([]byte{'q'})
				if err := cmd.Wait(); err != nil {
					t.Fatal(err)
				}
			}
			t.Logf("admitted=%d success=%d failed=%d late=%d direct_io=%d drained", gate.Admitted, gate.Success, gate.Failed, gate.Late, gate.IO)
		})
	}
}

const bootstrapHelper = `
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/sched.h>
#include <linux/io_uring.h>
static char *self;
static int command(void){char c;if(read(4,&c,1)!=1)_exit(99);return c;}
static void fork_one(int vf){
 pid_t pid=vf?vfork():fork();
 if(pid<0){dprintf(3,"E%d\n",errno);return;}
 if(!pid){dprintf(3,"%d\n",getpid());command();_exit(0);}
 int status;waitpid(pid,&status,0);dprintf(3,"D\n");
}
static void *thread_fork(void*arg){(void)arg;fork_one(0);return 0;}
static void *thread_exec(void*arg){(void)arg;char*args[]={self,0};execv(self,args);_exit(98);}
int main(int argc,char**argv){
 (void)argc;self=argv[0];dprintf(3,"%d\n",getpid());
 for(;;){
  int c=command();if(c=='q')return 0;
  if(c=='f'||c=='v')fork_one(c=='v');
  else if(c=='b'){
   struct clone_args args={.flags=CLONE_PIDFD,.pidfd=1,.exit_signal=SIGCHLD};
   long ret=syscall(SYS_clone3,&args,sizeof(args));
   if(!ret)_exit(97);
   dprintf(3,"E%d\n",ret<0?errno:0);
  }else if(c=='t'||c=='e'){
   pthread_t thread;
   if(pthread_create(&thread,0,c=='e'?thread_exec:thread_fork,0))return 96;
   if(c=='e')for(;;)pause();
   pthread_join(thread,0);
  }else if(c=='i'){
   struct io_uring_params params={.flags=IORING_SETUP_SQPOLL,.sq_thread_idle=100};
   int fd=syscall(SYS_io_uring_setup,2,&params);
   dprintf(3,"I%d\n",fd<0?errno:0);
   if(fd>=0){command();close(fd);dprintf(3,"D\n");}
  }
 }
}
`

func TestBootstrapHelperCompiles(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}
	tmp := t.TempDir()
	source := filepath.Join(tmp, "helper.c")
	if err := os.WriteFile(source, []byte(bootstrapHelper), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-O2", "-pthread", source, "-o", filepath.Join(tmp, "helper")).CombinedOutput(); err != nil {
		t.Fatalf("helper compile: %v %s", err, out)
	}
}
