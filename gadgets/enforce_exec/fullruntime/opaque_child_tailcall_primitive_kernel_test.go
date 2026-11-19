// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// Only an isolated, explicit cgroup may arm this always-denying primitive.
// It proves a populated LSM task_alloc tail-call edge and missing-target
// fallback, not any TASK/WORK/route authority transfer or policy verdict.
func TestOpaqueChildTailcallPrimitiveAttached(t *testing.T) {
	object := os.Getenv("IG_OPAQUE_CHILD_TAIL_PRIMITIVE_OBJECT")
	cgroup := os.Getenv("IG_OPAQUE_CHILD_TAIL_PRIMITIVE_CGROUP")
	if object == "" || cgroup == "" {
		t.Skip("set primitive object and disposable isolated cgroup2 path")
	}
	if os.Geteuid() != 0 || !strings.HasPrefix(filepath.Base(cgroup), "ig15-g005-childtail-") {
		t.Fatal("root and a dedicated ig15-g005-childtail-* cgroup are required")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(cgroup, &stat); err != nil || stat.Ino == 0 {
		t.Fatalf("isolated cgroup stat: %v", err)
	}
	procs, err := os.ReadFile(filepath.Join(cgroup, "cgroup.procs"))
	if err != nil || bytes.Contains(append([]byte{'\n'}, procs...),
		[]byte("\n"+strconv.Itoa(os.Getpid())+"\n")) {
		t.Fatalf("controller must stay outside isolated cgroup: %v", err)
	}
	for _, fallback := range []bool{false, true} {
		name := "populated-target"
		if fallback {
			name = "missing-target"
		}
		t.Run(name, func(t *testing.T) {
			testOpaqueChildTailcallPrimitiveCase(t, object, cgroup, stat.Ino, fallback)
		})
	}
}

func testOpaqueChildTailcallPrimitiveCase(t *testing.T, object, cgroup string, cgroupID uint64, fallback bool) {
	t.Helper()
	spec, err := ebpf.LoadCollectionSpec(object)
	if err != nil {
		t.Fatal(err)
	}
	const sourceName = "opaque_lifecycle_child_tail_source_probe"
	const targetName = "opaque_lifecycle_child_tail_target_probe"
	source, target := spec.Programs[sourceName], spec.Programs[targetName]
	if source == nil || target == nil {
		t.Fatal("missing both task_alloc primitive programs")
	}
	spec.Programs = map[string]*ebpf.ProgramSpec{sourceName: source, targetName: target}
	collection, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{LogSizeStart: 4 << 20},
	})
	if err != nil {
		var verifier *ebpf.VerifierError
		if errors.As(err, &verifier) {
			t.Logf("task_alloc primitive verifier:\n%+v", verifier)
		}
		t.Fatal(err)
	}
	defer collection.Close()
	gate := collection.Maps["opaque_lifecycle_gate"]
	targets := collection.Maps["opaque_lifecycle_child_tail_targets"]
	counters := collection.Maps["opaque_lifecycle_child_tail_counts"]
	if gate == nil || targets == nil || counters == nil ||
		targets.Type() != ebpf.ProgramArray || targets.MaxEntries() != 1 ||
		counters.ValueSize() != 24 {
		t.Fatal("missing or malformed primitive gate, target or counters")
	}
	gateValue := struct {
		CgroupID, Scope      uint64
		Incarnation, Enabled uint32
	}{cgroupID, 10, 1, 1}
	if err := gate.Update(uint32(0), gateValue, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	if !fallback {
		if err := targets.Update(uint32(0), collection.Programs[targetName], ebpf.UpdateAny); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range []*ebpf.Map{gate, targets} {
		if err := m.Freeze(); err != nil {
			t.Fatal(err)
		}
	}
	attached, err := link.AttachLSM(link.LSMOptions{Program: collection.Programs[sourceName]})
	if err != nil {
		t.Fatal(err)
	}
	defer attached.Close()
	// The shell is created outside the gate, moves only itself into the
	// disposable cgroup, and then attempts one background fork. The source
	// and target both deny; counters distinguish the actual tail-call edge.
	child := exec.Command("/bin/bash", "-c",
		`echo $$ > "$1/cgroup.procs" || exit 97; echo ENTERED; /bin/true & wait $!`,
		"ig15-child-tail-probe", cgroup)
	out, childErr := child.CombinedOutput()
	if !bytes.Contains(out, []byte("ENTERED")) || childErr == nil {
		t.Fatalf("isolated fork was not denied after entering cgroup: err=%v output=%q", childErr, out)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, err := counters.LookupBytes(uint32(0))
		if err != nil || len(raw) != 24 {
			t.Fatalf("primitive counters: %v %x", err, raw)
		}
		sourceCount := binary.LittleEndian.Uint64(raw[0:8])
		targetCount := binary.LittleEndian.Uint64(raw[8:16])
		fallbackCount := binary.LittleEndian.Uint64(raw[16:24])
		if sourceCount != 0 {
			if (!fallback && targetCount == sourceCount && fallbackCount == 0) ||
				(fallback && targetCount == 0 && fallbackCount == sourceCount) {
				t.Logf("task_alloc primitive: source=%d target=%d fallback=%d", sourceCount, targetCount, fallbackCount)
				return
			}
			t.Fatalf("unexpected tail-call counters source=%d target=%d fallback=%d", sourceCount, targetCount, fallbackCount)
		}
		if time.Now().After(deadline) {
			t.Fatalf("no gated task_alloc reached: output=%q counters=%x", out, raw)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
