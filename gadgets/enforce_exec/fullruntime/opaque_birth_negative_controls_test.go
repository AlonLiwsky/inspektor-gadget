// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// Independent earlier LSM, deliberately scoped to the disposable cgroup.
// Attach after the reader so head-inserted trampoline order executes this first;
// never alter the candidate program or its prior retval.
func attachOpaqueBirthPriorDenial(t *testing.T, cgroup uint64) link.Link {
	t.Helper()
	if cgroup == 0 {
		t.Fatal("zero prior-denial scope")
	}
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "birth_prior", Type: ebpf.LSM, AttachType: ebpf.AttachLSMMac, AttachTo: "bprm_check_security", License: "GPL", Instructions: asm.Instructions{
		asm.LoadMem(asm.R6, asm.R1, 8, asm.DWord),
		asm.JNE.Imm(asm.R6, 0, "prior"),
		asm.FnGetCurrentCgroupId.Call(),
		asm.LoadImm(asm.R1, int64(cgroup), asm.DWord),
		asm.JNE.Reg(asm.R0, asm.R1, "allow"),
		asm.Mov.Imm(asm.R0, -int32(unix.EACCES)), asm.Return(),
		asm.Mov.Reg(asm.R0, asm.R6).WithSymbol("prior"), asm.Return(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("allow"), asm.Return(),
	}})
	if err != nil {
		t.Fatalf("independent prior LSM load: %+v", err)
	}
	t.Cleanup(func() { _ = program.Close() })
	attached, err := link.AttachLSM(link.LSMOptions{Program: program})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = attached.Close() })
	return attached
}

// Inject a stale receipt cookie with a short unattached BPF test-run program.
// Keep the map user-readonly. This is deliberate fault injection, NOT natural
// pointer reuse or source-issued stale identity evidence.
func injectOpaqueBirthStaleCookie(t *testing.T, receipts *ebpf.Map, key, cookie uint64, offset int) {
	t.Helper()
	info, err := receipts.Info()
	if err != nil || info.Type != ebpf.Hash || info.KeySize != 8 || info.ValueSize != 88 || info.Flags != 0 || key == 0 || cookie == 0 || offset < 0 || offset > 80 {
		t.Fatalf("invalid isolated receipt injection map: info=%+v err=%v", info, err)
	}
	// Kernel MapInfo strips descriptor-only access flags. Prove this actual
	// FD rejects userspace mutation rather than expecting BPF_F_RDONLY there.
	raw, err := receipts.LookupBytes(key)
	if err != nil || len(raw) != 88 {
		t.Fatalf("missing exact held receipt before injection: %v", err)
	}
	if err := receipts.Update(key, raw, ebpf.UpdateExist); !errors.Is(err, unix.EPERM) {
		t.Fatalf("receipt FD must reject even no-op userspace mutation: %v", err)
	}
	program, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "birth_stale", Type: ebpf.SchedCLS, License: "GPL", Instructions: asm.Instructions{
		asm.LoadImm(asm.R1, int64(key), asm.DWord), asm.StoreMem(asm.RFP, -8, asm.R1, asm.DWord),
		asm.LoadMapPtr(asm.R1, receipts.FD()), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -8), asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "missing"), asm.LoadImm(asm.R1, int64(cookie), asm.DWord), asm.StoreMem(asm.R0, int16(offset), asm.R1, asm.DWord),
		asm.Mov.Imm(asm.R0, 0), asm.Return(), asm.Mov.Imm(asm.R0, 1).WithSymbol("missing"), asm.Return(),
	}})
	if err != nil {
		t.Fatalf("stale receipt injector load: %+v", err)
	}
	defer program.Close()
	code, _, err := program.Test(make([]byte, 64))
	if err != nil || code != 0 {
		t.Fatalf("stale receipt injection: code=%d err=%v", code, err)
	}
}

func moveOpaqueBirthChild(t *testing.T, cgroup string, pid int) func() {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(cgroup)
	var fs unix.Statfs_t
	if err != nil || resolved != cgroup || !filepath.IsAbs(cgroup) || unix.Statfs(cgroup, &fs) != nil || fs.Type != unix.CGROUP2_SUPER_MAGIC || !strings.HasPrefix(filepath.Base(cgroup), "ig15-g005-reallive-") || pid <= 0 {
		t.Fatal("scope movement requires exact disposable cgroup2")
	}
	sibling := cgroup + "-birth-moved"
	if err := os.Mkdir(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		if err := os.WriteFile(filepath.Join(cgroup, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o600); err != nil {
			t.Errorf("restore held child scope: %v", err)
		}
		if err := os.Remove(sibling); err != nil {
			t.Errorf("remove empty sibling scope: %v", err)
		}
	}
	t.Cleanup(restore)
	if err := os.WriteFile(filepath.Join(sibling, "cgroup.procs"), []byte(strconv.Itoa(pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	members, err := os.ReadFile(filepath.Join(sibling, "cgroup.procs"))
	if err != nil || strings.TrimSpace(string(members)) != strconv.Itoa(pid) {
		t.Fatalf("moved exact child not exclusive: %q err=%v", members, err)
	}
	original, err := os.ReadFile(filepath.Join(cgroup, "cgroup.procs"))
	if err != nil {
		t.Fatal(err)
	}
	for _, member := range strings.Fields(string(original)) {
		if member == strconv.Itoa(pid) {
			t.Fatal("child remains in original exact scope")
		}
	}
	t.Logf("held child %d moved to distinct unbound sibling cgroup", pid)
	return restore
}
