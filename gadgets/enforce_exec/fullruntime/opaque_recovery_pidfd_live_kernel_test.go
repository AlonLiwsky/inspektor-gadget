// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// This opt-in, test-only cohort connects the actual recovered S/G/A physical
// transitions to a held proc-FD signal-0 task_kill callback. It does not yet
// publish a product TASK or prove bounded pool churn/reclamation.
func TestRecoveryPidfdLiveAuthorization(t *testing.T) {
	object := os.Getenv("IG_RECOVERY_PIDFD_WITNESS_OBJECT")
	cgroup := os.Getenv("IG_RECOVERY_PIDFD_WITNESS_CGROUP")
	targetBinary := os.Getenv("IG_RECOVERY_PIDFD_WITNESS_HELPER")
	if object == "" || cgroup == "" || targetBinary == "" {
		t.Skip("set witness object, isolated cgroup, and static target helper")
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 ||
		!filepath.IsAbs(targetBinary) ||
		!strings.HasPrefix(filepath.Base(cgroup), "ig15-g005-pidfd-witness-") {
		t.Fatal("requires root, amd64/Linux, isolated witness cgroup, absolute helper")
	}
	var cgstat unix.Stat_t
	if err := unix.Stat(cgroup, &cgstat); err != nil || cgstat.Ino == 0 {
		t.Fatalf("isolated cgroup stat: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	binary := os.Getenv("IG_RECOVERY_PIDFD_WITNESS_TOPOLOGY")
	if binary == "" {
		cc, err := exec.LookPath("cc")
		if err != nil {
			t.Fatal(err)
		}
		binary = filepath.Join(t.TempDir(), "recovery-live")
		build := exec.CommandContext(t.Context(), cc, "-std=gnu11", "-O2", "-Wall", "-Wextra", "-Werror",
			"-iquote", "../full", "testdata/shared_recovery_process_topology.c", "-o", binary)
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("compile live recovery fixture: %v\n%s", err, output)
		}
	} else if !filepath.IsAbs(binary) {
		t.Fatal("prebuilt topology fixture path must be absolute")
	}
	// This target is a disposable static process in a caller-created cgroup.
	// The product's target pin must instead come from BindingLease.InitProc.
	ctx, cancel := context.WithTimeout(t.Context(), 70*time.Second)
	defer cancel()
	target := exec.CommandContext(ctx, targetBinary, cgroup)
	input, err := target.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := target.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var targetErr bytes.Buffer
	target.Stderr = &targetErr
	if err := target.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if target.ProcessState == nil {
			_ = target.Process.Kill()
			_ = target.Wait()
		}
	}()
	reader := bufio.NewReader(output)
	if line, err := reader.ReadString('\n'); err != nil || line != "READY\n" {
		t.Fatalf("target readiness: %q %v stderr=%q", line, err, targetErr.String())
	}
	if _, err := input.Write([]byte{'M'}); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "IN_CGROUP\n" {
		t.Fatalf("target cgroup: %q %v stderr=%q", line, err, targetErr.String())
	}
	proc, err := os.Open(filepath.Join("/proc", strconv.Itoa(target.Process.Pid)))
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()

	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("live recovery verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	config := struct {
		Incarnation, Nonce uint64
		ABI, Scenario      uint32
		CloneFlags         uint64
	}{11, 13, 2, 0, 0x8011}
	if err := collection.Maps["se_rm_configuration"].Update(uint32(0), config, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["se_rm_configuration"].Freeze(); err != nil {
		t.Fatal(err)
	}
	request := struct {
		NodeCookie, AdminGeneration, TargetCgroup uint64
		TargetTGID, Enabled                       uint32
	}{11, 1, cgstat.Ino, uint32(target.Process.Pid), 1}
	if err := collection.Maps["recovery_pidfd_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["recovery_pidfd_request"].Freeze(); err != nil {
		t.Fatal(err)
	}
	var links []link.Link
	defer func() {
		for i := len(links) - 1; i >= 0; i-- {
			_ = links[i].Close()
		}
	}()
	for _, name := range []string{"recovery_pidfd_task_alloc", "recovery_pidfd_task_free", "recovery_pidfd_task_kill"} {
		attached, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs[name]})
		if err != nil {
			t.Fatalf("attach %s: %v", name, err)
		}
		links = append(links, attached)
	}
	// Exec.ExtraFiles duplicates the exact map/program handles into S, which
	// forks G and raw-clones A. G closes the target FD before cloning A; S
	// transfers it to A over SCM_RIGHTS only after verified COMMIT.
	descriptors := []int{
		collection.Programs["se_rm_guardian"].FD(),
		collection.Programs["se_rm_administrator"].FD(),
		collection.Maps["se_rm_guardian_request"].FD(),
		collection.Maps["se_rm_admin_request"].FD(),
		collection.Maps["se_rm_control"].FD(),
		collection.Maps["se_rm_guardian_receipt"].FD(),
		collection.Maps["se_rm_admin_receipt"].FD(),
		int(proc.Fd()),
		collection.Maps["recovery_pidfd_consumed"].FD(),
	}
	var files []*os.File
	for i, fd := range descriptors {
		dup, err := unix.Dup(fd)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, os.NewFile(uintptr(dup), fmt.Sprintf("recovery-fd-%d", i)))
	}
	defer func() {
		for _, file := range files {
			_ = file.Close()
		}
	}()
	live := exec.CommandContext(ctx, binary, "live")
	live.ExtraFiles = files
	result, err := live.CombinedOutput()
	if err != nil || !strings.Contains(string(result), "topology PASS mode=live") {
		var count uint32
		_ = collection.Maps["recovery_alloc_count"].Lookup(uint32(0), &count)
		t.Logf("G task_alloc observations=%d", count)
		start := uint32(0)
		if count > 8 {
			start = count - 8
		}
		for i := start; i < count; i++ {
			var observation struct {
				Current, Child, Flags, Guardian, Candidate uint64
				Prior, RecoveryPhase                       uint32
			}
			_ = collection.Maps["recovery_alloc_observation"].Lookup(i&31, &observation)
			t.Logf("G task_alloc[%d]=%+v", i, observation)
		}
		t.Fatalf("live recovered authorization fixture: %v\n%s", err, result)
	}
	var consumed uint32
	if err := collection.Maps["recovery_pidfd_consumed"].Lookup(uint32(0), &consumed); err != nil || consumed != 1 {
		t.Fatalf("no one-shot recovered authorization: consumed=%d err=%v output=%s", consumed, err, result)
	}
	var witness struct {
		Physical, Cgroup, Generation uint64
		TargetTGID, Observed         uint32
	}
	if err := collection.Maps["recovery_pidfd_result"].Lookup(uint32(0), &witness); err != nil ||
		witness.Observed != 1 || witness.Physical == 0 || witness.Cgroup != cgstat.Ino ||
		witness.Generation != 1 || witness.TargetTGID != uint32(target.Process.Pid) {
		t.Fatalf("wrong physical recovery witness: %+v err=%v output=%s", witness, err, result)
	}
	if _, err := input.Write([]byte{'X'}); err != nil {
		t.Fatal(err)
	}
	if err := target.Wait(); err != nil {
		t.Fatalf("target exit: %v stderr=%q", err, targetErr.String())
	}
	t.Logf("live recovered admin authorized exact signal-0 target; %s", strings.TrimSpace(string(result)))
}
