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

	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// TestRolesABI requires every proposed lock-bearing TASK_STORAGE hook to load.
// It attaches nothing and proves neither lifecycle correctness nor bootstrap.
func TestRolesABI(t *testing.T) {
	if os.Getenv("IG_EXEC_ROLES_KERNEL_TEST") != "1" {
		t.Skip("requires explicit disposable kernel opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	b, err := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c").Output()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(tmp, "vmlinux.h"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	source := os.Getenv("IG_EXEC_ROLES_BPF_SOURCE")
	if source == "" {
		source = "bpf/roles.bpf.c"
	}
	object := filepath.Join(tmp, "roles.bpf.o")
	if out, err := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-I"+tmp, "-c", source, "-o", object).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v %s", err, out)
	}
	base, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"role_check", "role_fork", "role_exec", "role_exit", "role_completion"} {
		t.Run(name, func(t *testing.T) {
			spec := base.Copy()
			for other := range spec.Programs {
				if other != name {
					delete(spec.Programs, other)
				}
			}
			collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 4 * 1024 * 1024}})
			if err != nil {
				var verifier *ebpf.VerifierError
				if errors.As(err, &verifier) {
					t.Logf("%+v", verifier)
				}
				t.Fatalf("required role ABI unavailable: %v", err)
			}
			collection.Close()
			t.Log("role lifecycle hook accepted, no attachment")
		})
	}
}

func TestRolesLifecycleKernel(t *testing.T) {
	if os.Getenv("IG_EXEC_ROLES_KERNEL_TEST") != "1" {
		t.Skip("requires explicit disposable kernel opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	b, err := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c").Output()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(tmp, "vmlinux.h"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	source := os.Getenv("IG_EXEC_ROLES_BPF_SOURCE")
	if source == "" {
		source = "bpf/roles.bpf.c"
	}
	object := filepath.Join(tmp, "roles.bpf.o")
	if out, err := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-I"+tmp, "-c", source, "-o", object).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v %s", err, out)
	}
	base, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	cgpath := fmt.Sprintf("/sys/fs/cgroup/ig-roles-%d", os.Getpid())
	if err := os.Mkdir(cgpath, 0o755); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(cgpath)
	cg, err := os.Open(cgpath)
	if err != nil {
		t.Fatal(err)
	}
	defer cg.Close()
	var cgstat syscall.Stat_t
	if err := syscall.Fstat(int(cg.Fd()), &cgstat); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(tmp, "launcher")
	if err := os.WriteFile(helper+".c", []byte(rolesHelper), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("cc", "-O2", "-pthread", helper+".c", "-o", helper).CombinedOutput(); err != nil {
		t.Fatalf("helper: %v %s", err, out)
	}
	binary, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	target, interp, script, bad := filepath.Join(tmp, "target"), filepath.Join(tmp, "interp"), filepath.Join(tmp, "script"), filepath.Join(tmp, "bad")
	for _, path := range []string{target, interp} {
		if err := os.WriteFile(path, binary, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(script, []byte("#!"+interp+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("not an executable\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	type entry struct{ UID, Roles uint64 }
	type seed struct {
		Revision uint64
		Entries  [16]entry
	}
	type transaction struct {
		Bprm, Cgroup, Generation      uint64
		Slot, Owned, Suppress, Checks uint32
		Pending                       [8]entry
	}
	type state struct {
		Lock, Initialized                      uint32
		Entries                                [16]entry
		Tx                                     transaction
		Commits, Failures, Inherited, Identity uint64
	}
	type config struct {
		Cgroup, UID, Actor, Grant, Inode, Interpreter, Generation uint64
		Limit, Audit, Deny, Conflict                              uint32
	}
	type totals struct{ Credits, Faults, Gate, Commits, Failures, Exits, Forks uint64 }
	for _, tc := range []struct {
		name, path            string
		deny, audit, conflict uint32
		seed                  bool
		want                  uint64
		errno                 int
		action                byte
	}{
		{"ELF-grant", target, 0, 0, 0, true, 2, 0, 'q'},
		{"ELF-deny", target, 1, 0, 0, true, 1, 1, 'q'},
		{"audit-suppresses-grant", target, 1, 1, 0, true, 1, 0, 'q'},
		{"ENOEXEC-no-grant", bad, 0, 0, 0, true, 1, int(syscall.ENOEXEC), 'q'},
		{"task-exit-fallback-injected", bad, 0, 2, 0, true, 1, int(syscall.ENOEXEC), 'q'},
		{"missing-state-not-root", target, 0, 0, 0, false, 0, 1, 'q'},
		{"shebang-repeat", script, 0, 0, 0, true, 2, 0, 'q'},
		{"shebang-conflict", script, 0, 0, 1, true, 1, 1, 'q'},
		{"fork-inherits", target, 0, 0, 0, true, 2, 0, 'f'},
		{"vfork-inherits", target, 0, 0, 0, true, 2, 0, 'v'},
		{"nonleader-exec", target, 0, 0, 0, true, 2, 0, 't'},
		{"allocation-refused", target, 0, 0, 0, true, 2, 0, 'b'},
		{"seed-preserves-existing-UID", target, 0, 0, 0, true, 2, 0, 'r'},
		{"retained-UID-capacity-refused", target, 0, 0, 0, true, 2, 0, 'u'},
	} {
		t.Run(tc.name, func(t *testing.T) {
			collection, err := ebpf.NewCollectionWithOptions(base.Copy(), ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 8 * 1024 * 1024}})
			if err != nil {
				var v *ebpf.VerifierError
				if errors.As(err, &v) {
					t.Logf("%+v", v)
				}
				t.Fatal(err)
			}
			defer collection.Close()
			for _, name := range []string{"role_check", "role_fork", "role_exec", "role_exit", "role_completion"} {
				var attached link.Link
				if name == "role_check" {
					attached, err = link.AttachLSM(link.LSMOptions{Program: collection.Programs[name]})
				} else {
					attached, err = link.AttachTracing(link.TracingOptions{Program: collection.Programs[name]})
				}
				if err != nil {
					t.Fatal(err)
				}
				defer attached.Close()
			}
			var st, ist syscall.Stat_t
			if err := syscall.Stat(tc.path, &st); err != nil {
				t.Fatal(err)
			}
			if err := syscall.Stat(interp, &ist); err != nil {
				t.Fatal(err)
			}
			cfg := config{Cgroup: cgstat.Ino, UID: 7, Actor: 1, Grant: 2, Inode: st.Ino, Interpreter: ist.Ino, Generation: 1, Limit: 4096, Deny: tc.deny, Audit: tc.audit, Conflict: tc.conflict}
			if tc.action == 'b' {
				cfg.Limit = 1
			}
			if err := collection.Maps["configuration"].Put(uint32(0), cfg); err != nil {
				t.Fatal(err)
			}
			read, childWrite, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			childRead, write, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer read.Close()
			defer write.Close()
			cmd := exec.Command(helper, "launch", tc.path)
			cmd.ExtraFiles = []*os.File{childWrite, childRead}
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			childWrite.Close()
			childRead.Close()
			defer func() { cmd.Process.Kill(); cmd.Wait() }()
			reader := bufio.NewReader(read)
			line := func() string {
				t.Helper()
				read.SetReadDeadline(time.Now().Add(5 * time.Second))
				s, err := reader.ReadString('\n')
				if err != nil {
					t.Fatalf("helper response: %v", err)
				}
				return strings.TrimSpace(s)
			}
			initial := line()
			pid, err := strconv.Atoi(initial)
			if err != nil {
				t.Fatalf("initial %q", initial)
			}
			fd, err := unix.PidfdOpen(pid, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(fd)
			if tc.seed {
				initialSeed := seed{Revision: 1}
				initialSeed.Entries[0] = entry{7, 1}
				if tc.action == 'u' {
					for i := 1; i < 16; i++ {
						initialSeed.Entries[i] = entry{uint64(7 + i), 1}
					}
				}
				if err := collection.Maps["seeds"].Put(uint32(fd), initialSeed); err != nil {
					t.Fatal(err)
				}
			}
			write.Write([]byte{'x'})
			outcome := line()
			if tc.errno != 0 {
				if outcome != fmt.Sprintf("E%d", tc.errno) {
					t.Fatalf("exec outcome %q want errno%d", outcome, tc.errno)
				}
			} else if outcome != strconv.Itoa(pid) {
				t.Fatalf("exec PID %q want%d", outcome, pid)
			}
			var got state
			if err := collection.Maps["roles"].Lookup(uint32(fd), &got); err != nil {
				t.Fatal(err)
			}
			expectedOwned := uint32(0)
			if tc.audit == 2 {
				expectedOwned = 1
			}
			if got.Entries[0].Roles != tc.want || got.Tx.Owned != expectedOwned {
				t.Fatalf("state %+v want role%d ownership0", got, tc.want)
			}
			var total totals
			if err := collection.Maps["totals"].Lookup(uint32(0), &total); err != nil {
				t.Fatal(err)
			}
			if total.Gate != uint64(expectedOwned) || total.Faults != 0 {
				t.Fatalf("gate/fault not drained: %+v", total)
			}
			expectedCommits := uint64(0)
			if tc.errno == 0 && tc.want == 2 {
				expectedCommits = 1
			}
			expectedFailures := uint64(1) - expectedCommits
			if expectedOwned != 0 {
				expectedFailures = 0
			}
			if got.Commits != expectedCommits || got.Failures != expectedFailures || total.Commits != expectedCommits || total.Failures != expectedFailures {
				t.Fatalf("completion counters state=%+v totals=%+v want commits%d failures%d", got, total, expectedCommits, expectedFailures)
			}
			if tc.path == script && got.Tx.Checks < 2 {
				t.Fatalf("script did not exercise repeat checks: %+v", got.Tx)
			}
			switch tc.action {
			case 'r', 'u':
				next := seed{Revision: 2}
				if tc.action == 'r' {
					next.Entries[0] = entry{7, 1}
					next.Entries[1] = entry{8, 1}
				} else {
					next.Entries[0] = entry{99, 1}
				}
				if err := collection.Maps["seeds"].Put(uint32(fd), next); err != nil {
					t.Fatal(err)
				}
				cfg.Actor = 2
				cfg.Grant = 4
				if err := collection.Maps["configuration"].Put(uint32(0), cfg); err != nil {
					t.Fatal(err)
				}
				write.Write([]byte{'r'})
				expected := strconv.Itoa(pid)
				if tc.action == 'u' {
					expected = "E1"
				}
				if result := line(); result != expected {
					t.Fatalf("reseed exec %q want %q", result, expected)
				}
				var merged state
				if err := collection.Maps["roles"].Lookup(uint32(fd), &merged); err != nil {
					t.Fatal(err)
				}
				if tc.action == 'r' {
					if merged.Entries[0].Roles != 4 || merged.Entries[1] != (entry{8, 1}) {
						t.Fatalf("reseed reset existing or lost new UID: %+v", merged)
					}
				} else if merged.Entries[0].Roles != 2 || merged.Commits != 1 {
					t.Fatalf("exhausted UID slots changed state: %+v", merged)
				}
				write.Write([]byte{'q'})
			case 'f', 'b', 'v', 't':
				if tc.action == 'v' || tc.action == 't' {
					cfg.Actor = 2
					cfg.Grant = 4
					if err := collection.Maps["configuration"].Put(uint32(0), cfg); err != nil {
						t.Fatal(err)
					}
				}
				write.Write([]byte{tc.action})
				child, err := strconv.Atoi(line())
				if err != nil {
					t.Fatal(err)
				}
				flags := 0
				if tc.action == 't' {
					flags = 128
				} // PIDFD_THREAD on pinned kernel
				cfd, err := unix.PidfdOpen(child, flags)
				if err != nil {
					t.Fatal(err)
				}
				defer unix.Close(cfd)
				var inherited state
				err = collection.Maps["roles"].Lookup(uint32(cfd), &inherited)
				if tc.action == 'b' {
					if !errors.Is(err, ebpf.ErrKeyNotExist) {
						t.Fatalf("budget must refuse child storage: %v %+v", err, inherited)
					}
					write.Write([]byte{'x'})
					if result := line(); result != "E1" {
						t.Fatalf("budget exec expected EPERM: %s", result)
					}
					write.Write([]byte{'q'})
				} else {
					if err != nil {
						t.Fatal(err)
					}
					expected := uint64(2)
					if tc.action == 'v' {
						expected = 4
					}
					if inherited.Entries[0].Roles != expected || inherited.Tx.Owned != 0 || inherited.Tx.Bprm != 0 || inherited.Inherited != 1 {
						t.Fatalf("inherited state %+v expected role%d", inherited, expected)
					}
					if tc.action == 't' {
						write.Write([]byte{'x'})
						if result := line(); result != strconv.Itoa(pid) {
							t.Fatalf("nonleader exec PID identity %q want%d", result, pid)
						}
						identityBefore := inherited.Identity
						err := collection.Maps["roles"].Lookup(uint32(cfd), &inherited)
						if err != nil {
							// de_thread exchanges PID identities; the old TID
							// pidfd can cease to resolve the surviving task.
							t.Logf("old thread PIDFD lookup after de_thread: %v", err)
							leaderFD, openErr := unix.PidfdOpen(pid, 0)
							if openErr != nil {
								t.Fatal(openErr)
							}
							err = collection.Maps["roles"].Lookup(uint32(leaderFD), &inherited)
							unix.Close(leaderFD)
							if err != nil {
								t.Fatalf("surviving process task storage: %v", err)
							}
						}
						if identityBefore == 0 || inherited.Identity != identityBefore {
							t.Fatal("nonleader task identity changed or storage replaced")
						}
						if inherited.Entries[0].Roles != 4 || inherited.Tx.Owned != 0 || inherited.Commits != 1 {
							t.Fatalf("nonleader committed state %+v", inherited)
						}
					}
					write.Write([]byte{'q'})
				}
			default:
				write.Write([]byte{'q'})
			}
			if err := cmd.Wait(); err != nil {
				t.Fatal(err)
			}
			if tc.audit == 2 {
				if err := collection.Maps["totals"].Lookup(uint32(0), &total); err != nil {
					t.Fatal(err)
				}
				if total.Gate != 0 || total.Faults != 0 || total.Exits != 1 || total.Failures != 1 {
					t.Fatalf("task-exit did not release exactly once: %+v", total)
				}
				t.Log("injected fexit omission: task-exit released genuine counted admission")
			}
			t.Logf("roles=%d commits=%d failures=%d checks=%d gate=%d", got.Entries[0].Roles, got.Commits, got.Failures, got.Tx.Checks, total.Gate)
		})
	}
}

const rolesHelper = `
#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <pthread.h>
static char *self;
static int waitcmd(void){char c=0;if(read(4,&c,1)!=1)_exit(99);return c;}
static void *thread_exec(void*unused){
 (void)unused;dprintf(3,"%ld\n",syscall(SYS_gettid));waitcmd();
 char*args[]={self,"actor",0};execv(self,args);dprintf(3,"E%d\n",errno);_exit(99);
}
int main(int argc,char**argv){
 self=argv[0];
 if(argc>2&&!strcmp(argv[1],"launch")){
  dprintf(3,"%d\n",getpid());waitcmd();
  char*args[]={argv[2],"actor",0};execv(argv[2],args);
  dprintf(3,"E%d\n",errno);waitcmd();return 0;
 }
 dprintf(3,"%d\n",getpid());
 int action=waitcmd();
 if(action=='r'){
  char*args[]={self,"actor",0};execv(self,args);dprintf(3,"E%d\n",errno);waitcmd();return 0;
 }
 if(action=='t'){pthread_t thread;if(pthread_create(&thread,0,thread_exec,0))return 99;for(;;)pause();}
 if(action=='f'||action=='b'||action=='v'){
  pid_t child=action=='v'?vfork():fork();if(child<0)return 99;
  if(!child){
   if(action!='v'){dprintf(3,"%d\n",getpid());waitcmd();}
   if(action=='b'||action=='v'){
    char*args[]={self,"actor",0};execv(self,args);dprintf(3,"E%d\n",errno);waitcmd();
   }
   _exit(0);
  }
  int status;waitpid(child,&status,0);return status;
 }
 return 0;
}
`

// Validate the actual bounded merge algorithm without privileged kernel calls.
// The kernel fixture separately proves verifier acceptance and hook ordering.
func TestRoleMergePure(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skip("C compiler unavailable")
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	source := filepath.Join(tmp, "merge.c")
	binary := filepath.Join(tmp, "merge")
	if err := os.WriteFile(source, []byte(`
#include <assert.h>
#include <stdint.h>
#include <string.h>
typedef uint64_t __u64;
typedef uint32_t __u32;
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
static long bpf_loop(__u32 n,long(*callback)(__u32,void*),void*ctx,unsigned long flags){
 (void)flags;for(__u32 i=0;i<n;i++)if(callback(i,ctx))return i+1;return n;
}
#include "roles.h"
#include "transaction.h"
int main(void){
 struct fr_merge_work w={};
 w.entries[0]=(struct fr_entry){7,2};
 w.seed.entries[0]=(struct fr_entry){7,1};
 w.seed.entries[1]=(struct fr_entry){8,1};
 assert(!fr_merge(&w)&&w.entries[0].roles==2&&w.entries[1].uid==8);
 w.seed.entries[2]=(struct fr_entry){8,4};
 assert(fr_merge(&w)==-1);
 memset(&w,0,sizeof(w));
 for(int i=0;i<FR_SLOTS;i++)w.entries[i]=(struct fr_entry){i+1,1};
 w.seed.entries[0]=(struct fr_entry){99,1};
 assert(fr_merge(&w)==-1&&fr_lookup(w.entries,99)==0);
 struct fr_transaction tx={};
 assert(!fr_propose(&tx,7,2));
 assert(!fr_propose(&tx,7,2));
 assert(fr_propose(&tx,7,4)==-1&&tx.suppress);
 fr_clear_pending(&tx);
 for(int i=0;i<FR_ACTIVE;i++)assert(!tx.pending[i].uid&&!tx.pending[i].roles);
 return 0;
}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-O2", "-I"+root, source, "-o", binary).CombinedOutput(); err != nil {
		t.Fatalf("compile: %v %s", err, out)
	}
	if out, err := exec.Command(binary).CombinedOutput(); err != nil {
		t.Fatalf("merge: %v %s", err, out)
	}
	helper := filepath.Join(tmp, "helper.c")
	if err := os.WriteFile(helper, []byte(rolesHelper), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(cc, "-O2", "-pthread", helper, "-o", filepath.Join(tmp, "helper")).CombinedOutput(); err != nil {
		t.Fatalf("helper compile: %v %s", err, out)
	}
}
