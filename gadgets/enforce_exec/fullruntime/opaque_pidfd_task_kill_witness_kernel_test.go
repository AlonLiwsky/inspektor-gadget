// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bufio"
	"bytes"
	"context"
	"errors"
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

// Proves only that a pidfd signal-0 reaches task_kill with the exact live
// target's physical task pointer and default-cgroup identity. The request is
// synthetic and the observer never enrolls a TASK or authorizes a role.
func TestOpaquePidfdTaskKillWitness(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_PIDFD_WITNESS_OBJECT")
	cgroup := os.Getenv("IG_OPAQUE_PIDFD_WITNESS_CGROUP")
	helper := os.Getenv("IG_OPAQUE_PIDFD_WITNESS_HELPER")
	if object == "" || cgroup == "" || helper == "" {
		t.Skip("set object, isolated cgroup and static helper")
	}
	if os.Geteuid() != 0 || !filepath.IsAbs(helper) ||
		!strings.HasPrefix(filepath.Base(cgroup), "ig15-g005-pidfd-witness-") {
		t.Fatal("root, isolated witness cgroup and absolute helper required")
	}
	var stat unix.Stat_t
	if err := unix.Stat(cgroup, &stat); err != nil || stat.Ino == 0 {
		t.Fatalf("witness cgroup: %v", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	if p := spec.Programs["opaque_pidfd_task_kill_witness"]; p == nil || p.Type != ebpf.LSM ||
		spec.Maps["opaque_pidfd_witness_request"] == nil ||
		spec.Maps["opaque_pidfd_witness_result"] == nil {
		t.Fatal("missing typed physical witness fixture")
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{
		"opaque_pidfd_task_kill_witness": spec.Programs["opaque_pidfd_task_kill_witness"],
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("pidfd witness verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, helper, cgroup)
	input, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	reader := bufio.NewReader(output)
	if line, err := reader.ReadString('\n'); err != nil || line != "READY\n" {
		t.Fatalf("helper readiness: %q %v stderr=%q", line, err, stderr.String())
	}
	if _, err := input.Write([]byte{'M'}); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "IN_CGROUP\n" {
		t.Fatalf("helper cgroup entry: %q %v stderr=%q", line, err, stderr.String())
	}
	// Stock Rocky 4.18 lacks pidfd_open but accepts a pinned /proc/<tgid>
	// directory FD in pidfd_send_signal. The product must use the already
	// authenticated BindingLease.InitProc rather than reopening a PID path.
	openSignalFD := func(pid int) (int, error) {
		fd, err := unix.PidfdOpen(pid, 0)
		if err == nil || !errors.Is(err, unix.ENOSYS) {
			return fd, err
		}
		return unix.Open(filepath.Join("/proc", strconv.Itoa(pid)),
			unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	}
	pidfd, err := openSignalFD(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pidfd)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	request := struct {
		Cgroup         uint64
		Target, Sender uint32
	}{stat.Ino, uint32(cmd.Process.Pid), uint32(unix.Gettid())}
	if err := collection.Maps["opaque_pidfd_witness_request"].Update(uint32(0), request, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["opaque_pidfd_witness_request"].Freeze(); err != nil {
		t.Fatal(err)
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs["opaque_pidfd_task_kill_witness"]})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	var result struct {
		Physical, Cgroup               uint64
		Target, TGID, Sender, Observed uint32
	}
	read := func() {
		t.Helper()
		if err := collection.Maps["opaque_pidfd_witness_result"].Lookup(uint32(0), &result); err != nil {
			t.Fatal(err)
		}
	}
	self, err := openSignalFD(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.PidfdSendSignal(self, 0, nil, 0); err != nil {
		unix.Close(self)
		t.Fatal(err)
	}
	unix.Close(self)
	read()
	if result.Observed != 0 {
		t.Fatalf("wrong pidfd was admitted: %+v", result)
	}
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		t.Fatal(err)
	}
	read()
	if result.Observed != 1 || result.Physical == 0 ||
		result.Cgroup != stat.Ino || result.Target != uint32(cmd.Process.Pid) ||
		result.TGID != result.Target || result.Sender != request.Sender {
		t.Fatalf("pidfd target witness mismatch: %+v request=%+v", result, request)
	}
	first := result.Physical
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		t.Fatal(err)
	}
	read()
	if result.Observed != 2 || result.Physical != first {
		t.Fatalf("live pidfd identity changed: %+v", result)
	}
	expectedObserved, lastPhysical := uint32(2), first
	if os.Getenv("IG_OPAQUE_PIDFD_DETHREAD") == "1" {
		// A proc-TGID FD pins struct pid, not the original physical task.
		// Rocky's de_thread copies the old leader's start_time to the new
		// leader, so a retained proc FD plus unchanged /proc stat cannot
		// establish exact physical-init continuity by itself.
		proc, err := os.Open(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid)))
		if err != nil {
			t.Fatal(err)
		}
		defer proc.Close()
		start, err := readPinnedInitStart(proc, uint32(cmd.Process.Pid))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := input.Write([]byte{'T'}); err != nil {
			t.Fatal(err)
		}
		if line, err := reader.ReadString('\n'); err != nil || line != "SWAPPED\n" {
			t.Fatalf("nonleader exec: %q %v stderr=%q", line, err, stderr.String())
		}
		after, err := readPinnedInitStart(proc, uint32(cmd.Process.Pid))
		if err != nil || after != start {
			t.Fatalf("proc starttime changed after de_thread: before=%q after=%q err=%v", start, after, err)
		}
		if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
			t.Fatal(err)
		}
		read()
		if result.Observed != 3 || result.Physical == 0 || result.Physical == first ||
			result.Target != request.Target || result.Cgroup != request.Cgroup {
			t.Fatalf("de_thread did not replace physical leader under same proc identity: %+v", result)
		}
		expectedObserved, lastPhysical = 3, result.Physical
		t.Logf("de_thread replaced physical leader %x -> %x while pinned proc starttime stayed %s", first, lastPhysical, start)
	}
	if _, err := input.Write([]byte{'X'}); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper exit: %v stderr=%q", err, stderr.String())
	}
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatalf("dead pidfd signal: %v", err)
	}
	read()
	if result.Observed != expectedObserved || result.Physical != lastPhysical {
		t.Fatalf("dead target produced a new witness: %+v", result)
	}
	t.Log("pidfd zero-signal carried exact target task pointer and cgroup; no signal delivered or TASK authority issued")
}
