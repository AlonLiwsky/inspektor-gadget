// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"encoding/binary"
	"io"
	"os/exec"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// Direct shebang ownership diagnostic only; no policy reevaluation or role grant.
func runOpaqueRealSameBprmAttached(t *testing.T, collection *ebpf.Collection,
	spec *ebpf.CollectionSpec, stdin io.Writer, cmd *exec.Cmd, physical, locator, before uint64,
	script, helper string, stderr *bytes.Buffer,
) {
	t.Helper()
	const name = "opaque_real_owner_continue_witness"
	witness := collection.Maps[name]
	mapSpec := spec.Maps[name]
	if witness == nil || mapSpec == nil {
		t.Fatal("same-bprm diagnostic witness missing")
	}
	structure, ok := btf.UnderlyingType(mapSpec.Value).(*btf.Struct)
	if !ok {
		t.Fatal("same-bprm witness requires exact BTF structure")
	}
	raw, err := witness.LookupBytes(uint32(0))
	if err != nil {
		t.Fatal(err)
	}
	read := func(root *btf.Struct, data []byte, path ...string) uint64 {
		t.Helper()
		offset, size := opaqueSourceField(t, root, path)
		if size != 8 || offset+size > len(data) {
			t.Fatalf("invalid u64 field %v", path)
		}
		return binary.LittleEndian.Uint64(data[offset : offset+size])
	}
	value := func(field string) uint64 { return read(structure, raw, field) }
	if value("physical") != physical || value("locator") != locator || value("bprm") == 0 || value("cookie") == 0 || value("scope") != 10 || value("generation") != 1 {
		t.Fatalf("continuation lost exact original identity: raw=%x", raw)
	}
	if value("continuations") < 1 {
		t.Fatal("no second same-bprm LSM iteration observed")
	}
	if value("invocation") != before+1 {
		t.Fatalf("continuation allocated another invocation: got=%d want=%d", value("invocation"), before+1)
	}
	var scriptStat, helperStat unix.Stat_t
	if err := unix.Stat(script, &scriptStat); err != nil {
		t.Fatal(err)
	}
	if err := unix.Stat(helper, &helperStat); err != nil {
		t.Fatal(err)
	}
	if scriptStat.Dev == helperStat.Dev && scriptStat.Ino == helperStat.Ino ||
		value("first_inode") != scriptStat.Ino || value("second_inode") != helperStat.Ino ||
		!opaqueKernelDevMatches(value("first_dev"), uint64(scriptStat.Dev)) ||
		!opaqueKernelDevMatches(value("second_dev"), uint64(helperStat.Dev)) {
		t.Fatalf("LSM iterations did not observe script then interpreter device/inode identities: raw=%x script=%d:%d/%d interpreter=%d:%d/%d", raw,
			unix.Major(uint64(scriptStat.Dev)), unix.Minor(uint64(scriptStat.Dev)), scriptStat.Ino,
			unix.Major(uint64(helperStat.Dev)), unix.Minor(uint64(helperStat.Dev)), helperStat.Ino)
	}
	if value("first_record") >= 2 || value("first_record") != value("continued_record") || value("first_serial") == 0 || value("first_serial") != value("continued_serial") {
		t.Fatalf("continuation changed original snapshot token: raw=%x", raw)
	}
	var taskType *btf.Struct
	if err := spec.Types.TypeByName("se_task_state", &taskType); err != nil {
		t.Fatal(err)
	}
	task, err := collection.Maps["se_opaque_payload"].LookupBytes(uint32(0))
	if err != nil {
		t.Fatal(err)
	}
	if read(taskType, task, "physical_cookie") != value("cookie") || read(taskType, task, "next_invocation") != before+1 {
		t.Fatal("terminal changed TASK identity or allocated extra invocation")
	}
	offset, size := opaqueSourceField(t, taskType, []string{"flags"})
	if size != 4 || offset+size > len(task) || binary.LittleEndian.Uint32(task[offset:offset+size]) != 5 {
		t.Fatal("interpreter continuation quarantined qualified TASK")
	}
	var metaType *btf.Struct
	if err := spec.Types.TypeByName("se_ol_meta", &metaType); err != nil {
		t.Fatal(err)
	}
	meta, err := collection.Maps["se_opaque_meta"].LookupBytes(uint32(0))
	if err != nil {
		t.Fatal(err)
	}
	offset, size = opaqueSourceField(t, metaType, []string{"active_leases"})
	if size != 4 || offset+size > len(meta) || binary.LittleEndian.Uint32(meta[offset:offset+size]) != 0 {
		t.Fatal("terminal retained lexical TASK lease")
	}
	account, err := collection.Maps["se_opaque_work_accounts"].LookupBytes(uint32(0))
	if err != nil || len(account) < 8 || binary.LittleEndian.Uint32(account[4:8]) != 1 {
		t.Fatalf("one exec terminal requires exactly one completion WORK: raw=%x err=%v", account, err)
	}
	runOpaqueRealSuccessSourceCompletionAttached(t, collection, spec, stdin, cmd, physical, locator, stderr)
	t.Log("direct shebang changed file inode across same-bprm iterations with one invocation and original snapshot; exact terminal refunds; no policy reevaluation claim")
}

// super_block.s_dev is kernel dev_t, not the userspace stat encoding.
// Linux 6.12/6.18 include/linux/kdev_t.h uses 20 low bits for the minor.
func opaqueKernelDevMatches(kernel, stat uint64) bool {
	return kernel <= uint64(^uint32(0)) && uint32(kernel>>20) == unix.Major(stat) &&
		uint32(kernel&((1<<20)-1)) == unix.Minor(stat)
}

func TestOpaqueKernelDevMatches(t *testing.T) {
	for _, tc := range []struct {
		name         string
		kernel, stat uint64
		want         bool
	}{
		{"zero", 0, unix.Mkdev(0, 0), true},
		{"block", 259<<20 | 3, unix.Mkdev(259, 3), true},
		{"large_minor", 8<<20 | 0xabcde, unix.Mkdev(8, 0xabcde), true},
		{"major_mismatch", 8<<20 | 1, unix.Mkdev(9, 1), false},
		{"minor_mismatch", 8<<20 | 1, unix.Mkdev(8, 2), false},
		{"overflow", 1 << 32, unix.Mkdev(0, 0), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := opaqueKernelDevMatches(tc.kernel, tc.stat); got != tc.want {
				t.Fatalf("device match=%v want=%v kernel=%#x stat=%#x", got, tc.want, tc.kernel, tc.stat)
			}
		})
	}
}
