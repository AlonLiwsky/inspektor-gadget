// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// This is a feasibility test for paired legacy return hooks, not an exec
// terminal or product lifecycle. The child enters an isolated cgroup and
// attempts failed and successful ELF/interpreter execs in fresh collections.
func TestOpaqueExecReturnPairProbe(t *testing.T) {
	if cgroup := os.Getenv("IG_OPAQUE_RETURN_PAIR_HELPER_CGROUP"); cgroup != "" {
		if err := os.WriteFile(filepath.Join(cgroup, "cgroup.procs"),
			[]byte(strconv.Itoa(os.Getpid())), 0o644); err != nil {
			t.Fatal(err)
		}
		mode := os.Getenv("IG_OPAQUE_RETURN_PAIR_HELPER_MODE")
		if mode == "success" || mode == "script-success" {
			fmt.Println("paired-helper-joined-cgroup")
			path := "/bin/true"
			if mode == "script-success" {
				path = os.Getenv("IG_OPAQUE_RETURN_PAIR_HELPER_SCRIPT")
			}
			if err := unix.Exec(path, []string{path}, os.Environ()); err != nil {
				t.Fatal(err)
			}
			return
		}
		path := os.Getenv("IG_OPAQUE_RETURN_PAIR_HELPER_SCRIPT")
		err := unix.Exec(path, []string{path}, os.Environ())
		if !errors.Is(err, unix.ENOENT) {
			t.Fatalf("expected failed exec ENOENT, got %v", err)
		}
		fmt.Println("paired-helper-exec=ENOENT")
		return
	}
	object := os.Getenv("IG_OPAQUE_RETURN_PAIR_OBJECT")
	cgroup := os.Getenv("IG_OPAQUE_RETURN_PAIR_CGROUP")
	if object == "" || cgroup == "" {
		t.Skip("set return-pair object and isolated cgroup2 path")
	}
	if os.Geteuid() != 0 ||
		!strings.HasPrefix(filepath.Base(cgroup), "ig15-g005-retpair-") {
		t.Fatal("root and dedicated ig15-g005-retpair-* cgroup required")
	}
	var stat unix.Stat_t
	if err := unix.Stat(cgroup, &stat); err != nil || stat.Ino == 0 {
		t.Fatalf("isolated cgroup stat: %v", err)
	}
	procs, err := os.ReadFile(filepath.Join(cgroup, "cgroup.procs"))
	if err != nil || bytes.Contains(append([]byte{'\n'}, procs...),
		[]byte("\n"+strconv.Itoa(os.Getpid())+"\n")) {
		t.Fatalf("controller must be outside test cgroup: %v", err)
	}
	for _, mode := range []string{"failure", "success", "script-success"} {
		t.Run(mode, func(t *testing.T) {
			runOpaqueExecReturnPairProbe(t, object, cgroup, stat.Ino, mode)
		})
	}
}

func runOpaqueExecReturnPairProbe(t *testing.T, object, cgroup string, cgroupID uint64, mode string) {
	t.Helper()
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	entry := spec.Programs["opaque_return_pair_enter"]
	leave := spec.Programs["opaque_return_pair_exit"]
	register := spec.Programs["opaque_return_pair_register"]
	execveFinal := spec.Programs["opaque_return_pair_execve_final"]
	execveatFinal := spec.Programs["opaque_return_pair_execveat_final"]
	commonEnter := spec.Programs["opaque_return_pair_common_enter"]
	commonFinal := spec.Programs["opaque_return_pair_common_final"]
	if entry == nil || entry.Type != ebpf.Kprobe ||
		leave == nil || leave.Type != ebpf.Kprobe ||
		register == nil || register.Type != ebpf.LSM ||
		register.AttachTo != "bprm_check_security" ||
		execveFinal == nil || execveFinal.Type != ebpf.Kprobe ||
		execveatFinal == nil || execveatFinal.Type != ebpf.Kprobe ||
		commonEnter == nil || commonEnter.Type != ebpf.Kprobe ||
		commonFinal == nil || commonFinal.Type != ebpf.Kprobe ||
		len(spec.Programs) != 7 || len(spec.Maps) != 6 {
		t.Fatalf("unexpected isolated pair cohort: maps=%d programs=%d entry=%+v exit=%+v register=%+v final=%+v/%+v/%+v/%+v",
			len(spec.Maps), len(spec.Programs), entry, leave, register,
			execveFinal, execveatFinal, commonEnter, commonFinal)
	}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("return-pair verifier log:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	gate := struct {
		Cgroup   uint64
		Armed    uint32
		Reserved uint32
	}{cgroupID, 1, 0}
	if err := collection.Maps["opaque_return_pair_gate"].Update(uint32(0), gate, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if err := collection.Maps["opaque_return_pair_gate"].Freeze(); err != nil {
		t.Fatal(err)
	}
	returnLink, err := link.Kretprobe("search_binary_handler", collection.Programs["opaque_return_pair_exit"], nil)
	if err != nil {
		t.Fatalf("stock-kernel search_binary_handler return attach: %v", err)
	}
	defer returnLink.Close()
	entryLink, err := link.Kprobe("search_binary_handler", collection.Programs["opaque_return_pair_enter"], nil)
	if err != nil {
		t.Fatalf("stock-kernel search_binary_handler entry attach: %v", err)
	}
	defer entryLink.Close()
	registerLink, err := link.AttachLSM(link.LSMOptions{
		Program: collection.Programs["opaque_return_pair_register"],
	})
	if err != nil {
		t.Fatalf("stock-kernel bprm_check_security attach: %v", err)
	}
	defer registerLink.Close()
	execveLink, err := link.Kretprobe("do_execve", collection.Programs["opaque_return_pair_execve_final"], nil)
	if err != nil {
		t.Fatalf("stock-kernel do_execve return attach: %v", err)
	}
	defer execveLink.Close()
	execveatLink, err := link.Kretprobe("do_execveat", collection.Programs["opaque_return_pair_execveat_final"], nil)
	if err != nil {
		t.Fatalf("stock-kernel do_execveat return attach: %v", err)
	}
	defer execveatLink.Close()
	commonLink, err := link.Kretprobe("do_execveat_common.isra.38", collection.Programs["opaque_return_pair_common_final"], nil)
	if err != nil {
		t.Fatalf("stock-kernel do_execveat_common.isra.38 return attach: %v", err)
	}
	defer commonLink.Close()
	commonEntryLink, err := link.Kprobe("do_execveat_common.isra.38", collection.Programs["opaque_return_pair_common_enter"], nil)
	if err != nil {
		t.Fatalf("stock-kernel do_execveat_common.isra.38 entry attach: %v", err)
	}
	defer commonEntryLink.Close()
	script := ""
	if mode == "failure" || mode == "script-success" {
		script = filepath.Join(t.TempDir(), "missing-interpreter")
		contents := []byte("#!/ig15/absent/interpreter\n")
		if mode == "script-success" {
			contents = []byte("#!/bin/sh\nexit 0\n")
		}
		if err := os.WriteFile(script, contents, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run", "^TestOpaqueExecReturnPairProbe$", "-test.v")
	cmd.Env = append(os.Environ(),
		"IG_OPAQUE_RETURN_PAIR_HELPER_CGROUP="+cgroup,
		"IG_OPAQUE_RETURN_PAIR_HELPER_MODE="+mode,
		"IG_OPAQUE_RETURN_PAIR_HELPER_SCRIPT="+script)
	output, err := cmd.CombinedOutput()
	if err != nil || (mode == "failure" &&
		!bytes.Contains(output, []byte("paired-helper-exec=ENOENT"))) ||
		(mode != "failure" &&
			!bytes.Contains(output, []byte("paired-helper-joined-cgroup"))) {
		t.Fatalf("%s exec helper: %v output=%s", mode, err, output)
	}
	var obs struct {
		Entries, Returns, Failed, Paired, Missing, Nested, LastBprm uint64
		LastReturn                                                  int64
		Registered, Finalized                                       uint64
	}
	if err := collection.Maps["opaque_return_pair_observations"].Lookup(uint32(0), &obs); err != nil {
		t.Fatal(err)
	}
	if obs.Entries < 1 || obs.Returns < 1 ||
		obs.Missing != 0 || obs.Registered != 1 {
		t.Fatalf("%s exec did not produce exact one-entry/one-return pair: %+v", mode, obs)
	}
	if mode != "script-success" &&
		(obs.Entries != 1 || obs.Returns != 1 || obs.Nested != 0) {
		t.Fatalf("%s exec unexpectedly nested or repeated its binary handler: %+v", mode, obs)
	}
	if mode == "failure" && (obs.Failed != 1 || obs.Paired != 1 ||
		obs.Finalized != 1 || obs.LastBprm == 0 || obs.LastReturn >= 0) {
		t.Fatalf("failed exec did not finalize only the exact receipt: %+v", obs)
	}
	if mode == "success" && (obs.Failed != 0 || obs.Paired != 0 ||
		obs.Finalized != 1) {
		t.Fatalf("successful exec must finalize only a success receipt: %+v", obs)
	}
	if mode == "script-success" && obs.Finalized != 1 {
		t.Fatalf("successful interpreter exec must finalize only a success receipt: %+v", obs)
	}
	var final struct {
		ExecveReturns   uint64
		ExecveReturn    int64
		ExecveatReturns uint64
		ExecveatReturn  int64
		CommonReturns   uint64
		CommonReturn    int64
		OuterEntries    uint64
		OuterMissing    uint64
	}
	if err := collection.Maps["opaque_return_pair_final_observation"].Lookup(uint32(0), &final); err != nil {
		t.Fatal(err)
	}
	wantReturn := int64(0)
	if mode == "failure" {
		wantReturn = -int64(unix.ENOENT)
	}
	if final.ExecveReturns != 0 || final.ExecveatReturns != 0 ||
		final.CommonReturns != 1 || final.CommonReturn != wantReturn ||
		final.OuterEntries != 1 || final.OuterMissing != 0 {
		t.Fatalf("%s exec did not reach one exact-build common final result: %+v", mode, final)
	}
	receipts := collection.Maps["opaque_return_pair_receipts"].Iterate()
	var physical uint64
	var receipt struct {
		Physical, Bprm  uint64
		Phase, Reserved uint32
	}
	wantPhase := uint32(2)
	if mode == "failure" {
		wantPhase = 3
	}
	if !receipts.Next(&physical, &receipt) || receipts.Err() != nil ||
		physical == 0 || physical != receipt.Physical ||
		receipt.Bprm == 0 || receipt.Phase != wantPhase ||
		receipt.Reserved != 0 || receipts.Next(&physical, &receipt) {
		t.Fatalf("%s exec did not preserve one source-owned receipt at expected phase: key=%#x receipt=%+v err=%v",
			mode, physical, receipt, receipts.Err())
	}
	if mode == "failure" && receipt.Bprm != obs.LastBprm {
		t.Fatalf("final failure receipt has wrong handler bprm: receipt=%+v obs=%+v", receipt, obs)
	}
	iter := collection.Maps["opaque_return_pair_entries"].Iterate()
	var key uint64
	var value [24]byte
	if iter.Next(&key, &value) {
		t.Fatalf("return left paired entry key=%d", key)
	}
	if err := iter.Err(); err != nil {
		t.Fatal(err)
	}
	outer := collection.Maps["opaque_return_pair_outer_entries"].Iterate()
	if outer.Next(&key, &value) {
		t.Fatalf("final return left outer entry key=%d", key)
	}
	if err := outer.Err(); err != nil {
		t.Fatal(err)
	}
	t.Logf("stock %s return pair: cgroup=%d bprm=%#x final_ret=%d phase=%d",
		mode, cgroupID, receipt.Bprm, final.CommonReturn, receipt.Phase)
}
