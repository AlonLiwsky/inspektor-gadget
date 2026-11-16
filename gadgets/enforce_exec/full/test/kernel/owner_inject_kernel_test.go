// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
)

const (
	injectEvaluatorError = 1 // enforce_exec_test_inject_error bits (program.bpf.c)
	injectProposeError   = 2
	feInvalid            = 1 // FE_INVALID
)

// Byte offsets in struct event (program.bpf.c): generation, cgroup, deny,
// mode, path_result, host_pid, path[256], matched_rules[4], error.
const (
	eventDenyOffset  = 16
	eventModeOffset  = 20
	eventErrorOffset = 320
	ownerEventSize   = 324
)

// TestFullOwnerInjectedErrorKernel loads the legacy (non-ABI3) persistent owner
// with the test-only ENFORCE_EXEC_TEST_INJECT_ERROR switch and forces an
// evaluator or propose error after the real evaluation. Once the generation is
// classified, Audit never blocks: the exec runs, the fault is counted and the
// event is a would-deny operational error in mode 1. Strict and mixed deny.
func TestFullOwnerInjectedErrorKernel(t *testing.T) {
	if os.Getenv("IG_FULL_OWNER_KERNEL_TEST") != "1" {
		t.Skip("explicit disposable kernel opt-in required")
	}
	require.Zero(t, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	source := os.Getenv("IG_FULL_OWNER_BPF_SOURCE")
	require.NotEmpty(t, source)
	root := os.Getenv("IG_FULL_OWNER_REPO")
	require.NotEmpty(t, root)
	tmp := t.TempDir()
	header, e := exec.Command("bpftool", "btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c").Output()
	require.NoError(t, e)
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "vmlinux.h"), header, 0o600))
	obj := filepath.Join(tmp, "owner-inject.o")
	out, e := exec.Command("clang", "-target", "bpf", "-O2", "-g", "-D__TARGET_ARCH_x86", "-DENFORCE_EXEC_PERSISTENT_OWNER", "-DENFORCE_EXEC_TEST_INJECT_ERROR", "-Wno-missing-declarations", "-I"+tmp, "-I"+filepath.Join(root, "include"), "-I"+filepath.Join(root, "gadgets/enforce_exec/fullpolicy/bpf"), "-c", source, "-o", obj).CombinedOutput()
	require.NoError(t, e, string(out))
	workerTarget := filepath.Join(tmp, "worker-target")
	require.NoError(t, os.WriteFile(workerTarget+".c", []byte("int main(void){return 0;}"), 0o600))
	out, e = exec.Command("cc", "-O2", workerTarget+".c", "-o", workerTarget).CombinedOutput()
	require.NoError(t, e, string(out))
	helper := filepath.Join(tmp, "owner-helper")
	require.NoError(t, os.WriteFile(helper+".c", []byte("#define OWNER_WORKER_TARGET "+strconv.Quote(workerTarget)+"\n"+ownerExecHelper), 0o600))
	out, e = exec.Command("cc", "-O2", helper+".c", "-o", helper).CombinedOutput()
	require.NoError(t, e, string(out))

	cases := []struct {
		name   string
		modes  []fullpolicy.Mode
		inject uint32
		result int    // helper exit: 0 ran, 77 EPERM
		mode   uint32 // event mode: the binding class
		counts uint64 // count(2) per exec
	}{
		// An evaluator error counts twice: program.bpf.c counts it after
		// fe_evaluate, and eo_exec_propose then refuses the errored decision
		// (owner_roles.h, d->error => eo_data_fault, -1), counted again. A
		// forced propose error counts once.
		{"audit-evaluator-error", []fullpolicy.Mode{fullpolicy.Audit}, injectEvaluatorError, 0, 1, 2},
		{"audit-propose-error", []fullpolicy.Mode{fullpolicy.Audit}, injectProposeError, 0, 1, 1},
		{"strict-evaluator-error", []fullpolicy.Mode{fullpolicy.Enforce}, injectEvaluatorError, 77, 2, 2},
		{"strict-propose-error", []fullpolicy.Mode{fullpolicy.Enforce}, injectProposeError, 77, 2, 1},
		{"mixed-evaluator-error", []fullpolicy.Mode{fullpolicy.Audit, fullpolicy.Enforce}, injectEvaluatorError, 77, 2, 2},
		{"audit-no-error", []fullpolicy.Mode{fullpolicy.Audit}, 0, 0, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			spec, e := ebpf.LoadCollectionSpec(obj)
			require.NoError(t, e)
			require.NoError(t, spec.Variables["enforce_exec_test_inject_error"].Set(tc.inject))
			collection, e := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 16 * 1024 * 1024}})
			require.NoError(t, e)
			defer collection.Close()
			for name, program := range collection.Programs {
				if program.Type() == ebpf.Syscall {
					continue
				}
				var l link.Link
				if program.Type() == ebpf.LSM {
					l, e = link.AttachLSM(link.LSMOptions{Program: program})
				} else {
					l, e = link.AttachTracing(link.TracingOptions{Program: program})
				}
				require.NoError(t, e, name)
				defer l.Close()
			}
			require.NoError(t, collection.Maps["image_origins"].Freeze())
			require.NoError(t, collection.Maps["image_ready"].Freeze())
			require.NoError(t, collection.Maps["zero_observation"].Freeze())
			reader, e := ringbuf.NewReader(collection.Maps["events"])
			require.NoError(t, e)
			defer reader.Close()
			gates, e := fullruntime.NewGateMap(collection.Maps["eo_gates"])
			require.NoError(t, e)
			defer gates.Close()
			index, gate, e := gates.Allocate()
			require.NoError(t, e)
			slot, e := fullruntime.NewProgramSlot(gate, collection.Maps["eo_programs"], collection.Maps["eo_epochs"])
			require.NoError(t, e)
			defer slot.CloseAfterDetach()
			cgpath := fmt.Sprintf("/sys/fs/cgroup/ig-full-owner-inject-%d", os.Getpid())
			require.NoError(t, os.Mkdir(cgpath, 0o755))
			defer os.Remove(cgpath)
			cg, e := os.Open(cgpath)
			require.NoError(t, e)
			defer cg.Close()
			var cgstat syscall.Stat_t
			require.NoError(t, syscall.Fstat(int(cg.Fd()), &cgstat))
			process := exec.CommandContext(ctx, helper)
			process.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(cg.Fd())}
			input, e := process.StdinPipe()
			require.NoError(t, e)
			output, e := process.StdoutPipe()
			require.NoError(t, e)
			require.NoError(t, process.Start())
			defer func() {
				process.Process.Kill()
				process.Wait()
			}()
			scanner := bufio.NewScanner(output)
			require.True(t, scanner.Scan())
			require.Equal(t, "READY", scanner.Text())
			proc, e := os.Open(fmt.Sprintf("/proc/%d", process.Process.Pid))
			require.NoError(t, e)
			defer proc.Close()
			start := rootProcStart(t, proc)
			verify := func(context.Context) error {
				if rootProcStart(t, proc) != start {
					return fmt.Errorf("trusted init changed")
				}
				return nil
			}
			var policies []fullpolicy.Policy
			for i, mode := range tc.modes {
				policies = append(policies, fullpolicy.Policy{ID: fmt.Sprintf("p%d", i), Revision: "1", Mode: mode, RootRole: "agent", Default: fullpolicy.Allow, Rules: []fullpolicy.Rule{
					{Name: "worker", Action: fullpolicy.Allow, Target: fullpolicy.Target{Path: []string{workerTarget}}},
				}})
			}
			program, e := fullpolicy.CompileKernelWithRoleEpochs(policies, 1, "app", slot.Epochs())
			require.NoError(t, e)
			prepared, e := slot.Begin(ctx, program)
			require.NoError(t, e)
			control, e := fullruntime.NewOwnerControl(ctx, fullruntime.ControlConfig{Cookie: 0x91352abd, Cgroup: cgstat.Ino, InitHostPID: uint32(process.Process.Pid), TaskLimit: 4096, GateSlot: index, ABI: fullruntime.OwnerABI}, fullruntime.ControlResources{
				TaskIDs: collection.Maps["eo_task_ids"], ZeroTask: collection.Maps["eo_zero_task"], Configuration: collection.Maps["eo_configuration"], Commands: collection.Maps["eo_commands"], Health: collection.Maps["eo_health"], Phase: collection.Maps["eo_phase"], Rows: collection.Maps["eo_rows"], Admin: collection.Maps["eo_admin"], Tasks: collection.Maps["eo_tasks"], Work: collection.Maps["eo_work"], Anchor: collection.Maps["eo_anchor"], Births: collection.Maps["eo_birth_groups"], GenerationFaults: collection.Maps["eo_generation_faults"], Program: collection.Programs["eo_command"],
			}, gate)
			require.NoError(t, e)
			defer control.Close()
			require.NoError(t, control.ArmMovement(ctx, cgpath))
			inventory, e := control.Call(ctx, fullruntime.ControlCommand{Operation: fullruntime.OwnerInventory})
			require.NoError(t, e)
			rows, e := control.Rows(inventory.Count)
			require.NoError(t, e)
			var cookie uint64
			for _, row := range rows {
				if row.TID == uint32(process.Process.Pid) {
					cookie = row.Cookie
				}
			}
			require.NotZero(t, cookie)
			_, e = control.Call(ctx, fullruntime.ControlCommand{Operation: fullruntime.OwnerRootAuthorize, RootCookie: cookie})
			require.NoError(t, e)
			publisher, e := fullruntime.NewPublisher(slot, control, verify, prepared)
			require.NoError(t, e)
			result, e := publisher.Resume(ctx)
			require.NoError(t, e)
			require.True(t, result.Admitting)
			generation := slot.Generation()

			runOnce := func() {
				_, e := io.WriteString(input, "t")
				require.NoError(t, e)
				require.True(t, scanner.Scan())
				assert.Equal(t, fmt.Sprintf("RESULT %d", tc.result), scanner.Text())
			}
			observedCount := func() uint64 {
				var counts []uint64
				require.NoError(t, collection.Maps["counters"].Lookup(uint32(2), &counts))
				var observed uint64
				for _, c := range counts {
					observed += c
				}
				return observed
			}
			runOnce()

			reader.SetDeadline(time.Now().Add(5 * time.Second))
			var event []byte
			for event == nil {
				record, e := reader.Read()
				require.NoError(t, e)
				if len(record.RawSample) >= ownerEventSize && binary.LittleEndian.Uint64(record.RawSample) == generation {
					event = record.RawSample
				}
			}
			deny, mode, fault := binary.LittleEndian.Uint32(event[eventDenyOffset:]), binary.LittleEndian.Uint32(event[eventModeOffset:]), binary.LittleEndian.Uint32(event[eventErrorOffset:])
			faults, e := control.GenerationFault(generation)
			require.NoError(t, e)
			observed := observedCount()
			h, e := control.Health()
			require.NoError(t, e)
			t.Logf("event deny=%d mode=%d error=%d; count(2)=%d generation faults=%#x health faults=%#x", deny, mode, fault, observed, faults, h.Faults)
			// Independent checks: assert, so one mismatch never hides another.
			assert.Zero(t, h.Faults, "a classified fault never closes admission")
			assert.Equal(t, tc.counts, observed, "count(2) per exec")
			if tc.inject == 0 {
				assert.Zero(t, fault)
				assert.Zero(t, faults)
			} else {
				assert.Equal(t, uint32(feInvalid), fault, "operational error")
				assert.Equal(t, uint32(1), deny, "would-deny or deny")
				assert.Equal(t, tc.mode, mode, "the binding class, never a forced Strict")
				if tc.inject == injectEvaluatorError {
					assert.Equal(t, uint64(4), faults&4, "observation fault bit 4")
				}
			}
			// Admission stays open in the same generation: a second exec reaches
			// the evaluation again (an admission denial returns before count(2)).
			runOnce()
			h, e = control.Health()
			require.NoError(t, e)
			t.Logf("after second exec: count(2)=%d health faults=%#x", observedCount(), h.Faults)
			assert.Equal(t, 2*tc.counts, observedCount(), "second exec admitted and evaluated")
			assert.Zero(t, h.Faults, "still no owner-wide fault")
			_, e = io.WriteString(input, "q")
			require.NoError(t, e)
		})
	}
}
