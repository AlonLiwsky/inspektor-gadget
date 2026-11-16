// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
)

// TestExecTraceLSMCoexistence checks the production execution hooks in both
// attachment orders. Only bprm_check_security is selected from trace_lsm: other
// hooks have their own signatures and are outside this execution regression.
func TestExecTraceLSMCoexistence(t *testing.T) {
	if os.Getenv("IG_EXEC_KERNEL_TEST") != "1" || os.Getenv("IG_EXEC_TRACE_LSM_OBJECT") == "" {
		t.Skip("requires disposable BPF LSM host, IG_EXEC_KERNEL_TEST=1 and IG_EXEC_TRACE_LSM_OBJECT")
	}
	require.Equal(t, 0, os.Geteuid(), "root required")
	require.NoError(t, rlimit.RemoveMemlock())
	require.NotEmpty(t, os.Getenv("IG_EXEC_BPF_OBJECT"))
	for _, order := range []string{"observer-first", "observer-last"} {
		for _, reporting := range []string{"enabled", "disabled", "filtered"} {
			t.Run(order+"/"+reporting, func(t *testing.T) {
				cgpath := fmt.Sprintf("/sys/fs/cgroup/ig-exec-coexist-%d", os.Getpid())
				require.NoError(t, os.Mkdir(cgpath, 0o755))
				t.Cleanup(func() { require.NoError(t, os.Remove(cgpath)) })
				cg, err := os.Open(cgpath)
				require.NoError(t, err)
				t.Cleanup(func() { cg.Close() })
				var st syscall.Stat_t
				require.NoError(t, syscall.Fstat(int(cg.Fd()), &st))

				enforceSpec, err := ebpf.LoadCollectionSpec(os.Getenv("IG_EXEC_BPF_OBJECT"))
				require.NoError(t, err)
				enforcement, err := ebpf.NewCollection(enforceSpec)
				require.NoError(t, err)
				t.Cleanup(enforcement.Close)
				observerSpec, err := ebpf.LoadCollectionSpec(os.Getenv("IG_EXEC_TRACE_LSM_OBJECT"))
				require.NoError(t, err)
				const hook = "trace_lsm_bprm_check_security"
				require.NotNil(t, observerSpec.Programs[hook])
				for name := range observerSpec.Programs {
					if name != hook {
						delete(observerSpec.Programs, name)
					}
				}
				require.NoError(t, observerSpec.Variables["trace_all"].Set(reporting != "disabled"))
				require.NoError(t, observerSpec.Variables["trace_bprm_check_security"].Set(false))
				if reporting == "filtered" {
					// The child calling exec has a different PID from the test process.
					require.NoError(t, observerSpec.Variables["targ_pid"].Set(uint32(os.Getpid())))
				}
				observer, err := ebpf.NewCollection(observerSpec)
				require.NoError(t, err)
				t.Cleanup(observer.Close)
				attach := func(program *ebpf.Program) {
					attached, err := link.AttachLSM(link.LSMOptions{Program: program})
					require.NoError(t, err)
					t.Cleanup(func() { require.NoError(t, attached.Close()) })
				}
				if order == "observer-first" {
					attach(observer.Programs[hook])
				}
				attach(enforcement.Programs["enforce_exec"])
				if order == "observer-last" {
					attach(observer.Programs[hook])
				}
				policy := enforcement.Maps["policy"]
				require.NoError(t, policy.Put(uint32(0), entry{Generation: 1, Mode: 2, DefaultDeny: 1}))
				require.NoError(t, policy.Freeze())
				require.NoError(t, enforcement.Maps["bindings"].Put(st.Ino, uint64(1)))
				execute := func(managed, denied bool) {
					cmd := exec.Command("/usr/bin/true")
					if managed {
						cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
					}
					err := cmd.Run()
					if denied {
						require.ErrorIs(t, err, syscall.EPERM)
					} else {
						require.NoError(t, err)
					}
				}
				execute(true, true)
				execute(false, false)
				require.NoError(t, enforcement.Maps["bindings"].Delete(st.Ino))
				execute(true, false)
				require.NoError(t, enforcement.Maps["bindings"].Put(st.Ino, uint64(1)))
				execute(true, true)
				require.NoError(t, enforcement.Maps["bindings"].Delete(st.Ino))
				execute(true, false)
			})
		}
	}
}
