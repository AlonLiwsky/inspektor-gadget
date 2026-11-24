// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullpolicy"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

// The executable-mapping gate of the product object (full/shared_exec_map.h):
// two programs in the pinned attach set (sharedCandidateAttachSet). README,
// "Executable-mapping gate".
const (
	// sharedExecMapMmap judges a new mapping with PROT_EXEC. The attach
	// canary waits for it: the kernel's ELF loader maps the canary's program
	// through security_mmap_file.
	sharedExecMapMmap = "em_mmap_file"
	// sharedExecMapMprotect judges an mprotect that adds PROT_EXEC to a file
	// mapping. A fork, exec and exit need not do that, so the attach canary
	// does not wait for it (runSharedAttachCanary); the start self-test
	// (verifySharedExecMap) proves it.
	sharedExecMapMprotect = "em_file_mprotect"
)

// SharedExecMap is the executable-mapping gate of one binding. It is carried
// in the snapshot metadata (se_snapshot_metadata.exec_map_flags), so the
// gate, the image handle and the policy change in one publish. The zero value
// is off. The binding's execution class decides what a judged mapping does:
// Strict denies a mapping that is not from the image, Audit allows it and
// reports it (would deny).
type SharedExecMap struct {
	// Judge judges every executable file mapping of the binding's tasks by
	// image provenance (FromImage, no path). It needs the binding's image
	// index: without one the publish is refused with
	// ErrSharedImageIndexUnavailable, and the caller decides whether to
	// publish the policy without the gate.
	Judge bool
	// DenyAnonymous also judges anonymous executable memory (a JIT, a
	// memfd, shared anonymous memory, SysV shm, /dev/zero) and a written
	// private file mapping as "not from image". Needs Judge.
	DenyAnonymous bool
}

// SE_EXEC_MAP_* of full/shared_snapshot.h.
const (
	sharedExecMapFlagJudge      = 1
	sharedExecMapFlagDenyAnon   = 2
	sharedExecMapFlagExeExempt  = 4
	sharedExecMapFlagsKnown     = sharedExecMapFlagJudge | sharedExecMapFlagDenyAnon | sharedExecMapFlagExeExempt
	sharedExecMapMetadataOffset = 408 // exec_map_flags in se_snapshot_metadata
)

func (m SharedExecMap) validate(source *fullpolicy.Policy) error {
	if m.DenyAnonymous && !m.Judge {
		return fmt.Errorf("executable-mapping gate: DenyAnonymous needs Judge")
	}
	if m.Judge && source == nil {
		return fmt.Errorf("executable-mapping gate: needs a source policy")
	}
	return nil
}

// sharedExecMapFlags is the metadata word for a publish. imageHandle is the
// binding's sealed image set (0: none). The program-file exemption is set
// only when the policy can allow a program that is not from the image: then
// the exec verdict may have allowed a non-image program, and its own file
// must still map.
func sharedExecMapFlags(m SharedExecMap, source *fullpolicy.Policy, imageHandle uint64) (uint32, error) {
	if err := m.validate(source); err != nil {
		return 0, err
	}
	if !m.Judge {
		return 0, nil
	}
	if imageHandle == 0 {
		return 0, fmt.Errorf("executable-mapping gate: %w: the binding has no sealed image set", ErrSharedImageIndexUnavailable)
	}
	flags := uint32(sharedExecMapFlagJudge)
	if m.DenyAnonymous {
		flags |= sharedExecMapFlagDenyAnon
	}
	if sharedPolicyMayAllowNonImage(source) {
		flags |= sharedExecMapFlagExeExempt
	}
	return flags, nil
}

// sharedPolicyMayAllowNonImage reports whether p can let an exec of a target
// that is not known to be from the image run: an allow default (or none
// authored), an allow rule without a target FromImage: true predicate, or
// anything in audit mode. A binding's class is the strongest mode of its
// policy and rules, so a Strict binding can still run a program that an
// audit default or an audit deny let through; the gate must then let that
// program map its own file (the kernel maps it after the point of no
// return, so a refusal would kill the task).
func sharedPolicyMayAllowNonImage(p *fullpolicy.Policy) bool {
	if p == nil || p.Default != fullpolicy.Deny || p.Mode != fullpolicy.Enforce || p.DefaultMode == fullpolicy.Audit {
		return true
	}
	for _, r := range p.Rules {
		if r.Mode == fullpolicy.Audit {
			return true
		}
	}
	for _, r := range p.Rules {
		if r.Action != fullpolicy.Allow {
			continue
		}
		if r.Target.FromImage == nil || !*r.Target.FromImage {
			return true
		}
	}
	return false
}

// Maps of the gate in the product object (full/shared_exec_map.h).
const (
	sharedExecMapFaultsMap        = "exec_map_faults"
	sharedExecMapProbeMap         = "exec_map_probe"
	sharedExecMapCountersMap      = "exec_map_counters"
	sharedExecMapEventCountersMap = "exec_map_event_counters"
	// SharedExecMapDataSource is the datasource of the gate's verdict
	// events (struct exec_map_event, ring exec_map_events): one event per
	// denied (Strict) or would-deny (Audit) mapping, on a ring of its own.
	SharedExecMapDataSource = "execmap"
)

// borrowSharedExecMapFaults reads exec_map_faults (route invariant faults
// and UNKNOWN results, summed over CPUs and cells) through the map handle
// the eBPF operator published.
func borrowSharedExecMapFaults(gc operators.GadgetContext) (sharedRootBarrierFaultRead, error) {
	m, err := sharedExecMapInstance(gc, sharedExecMapFaultsMap)
	if err != nil {
		return nil, err
	}
	return func() (uint64, error) {
		var total uint64
		for key := uint32(0); key < 2; key++ {
			var perCPU []uint64
			if err := m.Lookup(key, &perCPU); err != nil {
				return 0, fmt.Errorf("%s[%d]: %w", sharedExecMapFaultsMap, key, err)
			}
			for _, n := range perCPU {
				if total+n < total {
					return 0, fmt.Errorf("%s overflows", sharedExecMapFaultsMap)
				}
				total += n
			}
		}
		return total, nil
	}, nil
}

func sharedExecMapInstance(gc operators.GadgetContext, name string) (*ebpf.Map, error) {
	value, _ := gc.GetVar(operators.MapPrefix + name)
	m, _ := value.(*ebpf.Map)
	if m == nil {
		return nil, fmt.Errorf("shared candidate map %s was not published", name)
	}
	return m, nil
}

// sharedExecMapProbe is struct em_probe.
type sharedExecMapProbe struct {
	Armed, Denied uint32
	Nonce         [16]byte
}

// verifySharedExecMap is the gate's start self-test on a product node. It
// runs after the root barrier's check and before the attach canary. The
// agent's own cgroup has no route, so nothing the agent maps is judged; the
// probe entry (exec_map_probe) makes the gate judge one agent thread as
// Strict with no image index:
//   - mmap of a file with PROT_EXEC must be refused by em_mmap_file;
//   - mprotect(+PROT_EXEC) of a file mapping must be refused by
//     em_file_mprotect;
//   - anonymous memory and a memfd mapped PROT_EXEC must be allowed (the
//     anonymous class, P12 on this kernel).
//
// Each refusal must also be marked in the probe entry, so a refusal by
// another layer does not count. The file is the agent's own binary
// (/proc/self/exe): it is on an exec mount, so the kernel itself does not
// refuse it. Any failure is node NotReady (ErrSharedNodeNotReady).
func verifySharedExecMap(gc operators.GadgetContext) error {
	m, err := sharedExecMapInstance(gc, sharedExecMapProbeMap)
	if err == nil {
		err = sharedExecMapSelfTest(m)
	}
	if err != nil {
		return fmt.Errorf("%w: executable-mapping gate self-test: %w", ErrSharedNodeNotReady, err)
	}
	return nil
}

func sharedExecMapSelfTest(m *ebpf.Map) error {
	result := make(chan error, 1)
	go func() {
		// Never unlocked: the thread exits with this goroutine, so no
		// other goroutine runs on the renamed thread.
		runtime.LockOSThread()
		if unix.Gettid() == unix.Getpid() {
			inner := make(chan error, 1)
			go func() {
				runtime.LockOSThread()
				inner <- sharedExecMapSelfTestOnThread(m)
			}()
			err := <-inner
			runtime.UnlockOSThread()
			result <- err
			return
		}
		result <- sharedExecMapSelfTestOnThread(m)
	}()
	return <-result
}

func sharedExecMapSelfTestOnThread(m *ebpf.Map) error {
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		return err
	}
	entry := sharedExecMapProbe{Armed: 1}
	copy(entry.Nonce[:15], hex.EncodeToString(random))
	if err := unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(&entry.Nonce[0])), 0, 0, 0); err != nil {
		return fmt.Errorf("setting the probe thread name: %w", err)
	}
	if err := m.Put(uint32(0), entry); err != nil {
		return fmt.Errorf("writing %s: %w", sharedExecMapProbeMap, err)
	}
	errs := []error{sharedExecMapProbeRun()}
	var after sharedExecMapProbe
	if err := m.Lookup(uint32(0), &after); err != nil {
		errs = append(errs, fmt.Errorf("reading %s: %w", sharedExecMapProbeMap, err))
	} else {
		for _, hook := range []struct {
			bit  uint32
			name string
		}{{1 << 1, sharedExecMapMmap}, {1 << 2, sharedExecMapMprotect}} {
			if after.Denied&hook.bit == 0 {
				errs = append(errs, fmt.Errorf("%s did not mark its refusal", hook.name))
			}
		}
	}
	var clearErr error
	for i := 0; i < 3; i++ {
		if clearErr = m.Put(uint32(0), sharedExecMapProbe{}); clearErr == nil {
			break
		}
	}
	if clearErr != nil {
		errs = append(errs, fmt.Errorf("clearing %s: %w", sharedExecMapProbeMap, clearErr))
	}
	return errors.Join(errs...)
}

// sharedExecMapProbeRun runs the probe operations on the probe thread.
func sharedExecMapProbeRun() error {
	page := os.Getpagesize()
	var errs []error
	f, err := os.Open("/proc/self/exe")
	if err != nil {
		return fmt.Errorf("opening the agent binary: %w", err)
	}
	defer f.Close()
	fd := int(f.Fd())
	if b, err := unix.Mmap(fd, 0, page, unix.PROT_READ|unix.PROT_EXEC, unix.MAP_PRIVATE); err == nil {
		_ = unix.Munmap(b)
		errs = append(errs, fmt.Errorf("%s: an executable file mapping was not refused", sharedExecMapMmap))
	} else if !errors.Is(err, unix.EACCES) {
		errs = append(errs, fmt.Errorf("%s: an executable file mapping failed with %w, want EACCES", sharedExecMapMmap, err))
	}
	if b, err := unix.Mmap(fd, 0, page, unix.PROT_READ, unix.MAP_PRIVATE); err != nil {
		errs = append(errs, fmt.Errorf("mapping the agent binary to read: %w", err))
	} else {
		if err := unix.Mprotect(b, unix.PROT_READ|unix.PROT_EXEC); err == nil {
			errs = append(errs, fmt.Errorf("%s: mprotect(+PROT_EXEC) of a file mapping was not refused", sharedExecMapMprotect))
		} else if !errors.Is(err, unix.EACCES) {
			errs = append(errs, fmt.Errorf("%s: mprotect(+PROT_EXEC) failed with %w, want EACCES", sharedExecMapMprotect, err))
		}
		_ = unix.Munmap(b)
	}
	// The anonymous class stays allowed.
	if b, err := unix.Mmap(-1, 0, page, unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS); err != nil {
		errs = append(errs, fmt.Errorf("%s: anonymous executable memory was refused: %w", sharedExecMapMmap, err))
	} else {
		_ = unix.Munmap(b)
	}
	mfd, err := unix.MemfdCreate("em-probe", unix.MFD_CLOEXEC)
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("memfd_create: %w", err))...)
	}
	defer unix.Close(mfd)
	if err := unix.Ftruncate(mfd, int64(page)); err != nil {
		return errors.Join(append(errs, fmt.Errorf("memfd ftruncate: %w", err))...)
	}
	if b, err := unix.Mmap(mfd, 0, page, unix.PROT_READ|unix.PROT_EXEC, unix.MAP_SHARED); err != nil {
		errs = append(errs, fmt.Errorf("%s: a memfd mapped PROT_EXEC was refused (anonymous class): %w", sharedExecMapMmap, err))
	} else {
		_ = unix.Munmap(b)
	}
	return errors.Join(errs...)
}
