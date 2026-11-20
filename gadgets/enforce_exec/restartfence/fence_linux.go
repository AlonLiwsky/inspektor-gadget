// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Package restartfence manages the separately qualified exec restart fence.
// Closing a handle does not withdraw protection. Only explicit uninstall
// retires the fence; old pins survive refusal, agent crashes and ordinary stops.
package restartfence

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

// InstallRoot is the default path on the node. In a container use the same
// directory below the host bpffs mount.
const InstallRoot = "/sys/fs/bpf/kubescape/fence-v1"

const (
	execSection = 1
	retired     = math.MaxUint64
	registerOp  = 0x4b554246
)

var (
	ErrRetired = errors.New("exec restart fence retired by uninstall")
	ErrFenced  = errors.New("exec restart fence has no live ownership for this handle")
)

type Mode uint32

const (
	Strict Mode = 1
	Audit  Mode = 2
)

type identity struct {
	Incarnation   uint64
	StartBootTime uint64
	TGID          uint32
	Reserved      uint32
}

type challenge struct {
	Incarnation uint64
	Lo          uint64
	Hi          uint64
}

type binding struct {
	Owner          uint64
	PodUIDHash     uint64
	StrictSections uint32
	AuditSections  uint32
	BoundSections  uint32
	Reserved       uint32
}

// Totals are cumulative while a pod row exists. Lost covers observation
// failures and is never part of a verdict.
type Totals struct {
	Denied uint64
	Audit  uint64
	Lost   uint64
}

// Snapshot is a point-in-time fence observation, not attestation that any
// product generation is protected. Key zero holds infrastructure counters.
type Snapshot struct {
	LiveIncarnation uint64
	Owner           uint64
	Retired         bool
	PerCgroup       map[uint64]Totals
}

// Fence holds local descriptors to the attested versioned pin set.
type Fence struct {
	mu          sync.Mutex
	pins        *pinnedFence
	root        string
	incarnation uint64
}

// Open attests existing pins or creates a new empty fence. object must be the
// independently qualified fence ELF for this architecture, not the product ELF.
func Open(root string, object []byte) (*Fence, error) {
	if err := checkCgroupV2(); err != nil {
		return nil, err
	}
	pins, err := openPins(root, object)
	if err != nil {
		return nil, err
	}
	f := &Fence{pins: pins, root: root}
	err = f.locked(func(p *pinnedFence) error {
		state, err := readState(p)
		if err != nil {
			return err
		}
		if state == retired {
			return ErrRetired
		}
		return initTotals(p, 0)
	})
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	return f, nil
}

func (f *Fence) locked(action func(*pinnedFence) error) (err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pins == nil {
		return fmt.Errorf("exec restart fence handle is closed")
	}
	parent, err := lockPinRoot(f.root)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlockPinRoot(parent)) }()
	if err := checkPublishedFence(parent, f.pins); err != nil {
		return err
	}
	return action(f.pins)
}

// Close drops local descriptors only, leaving the pinned graph attached.
// The owner must explicitly Arm before withdrawing its product enforcement.
func (f *Fence) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	err := f.pins.Close()
	f.pins = nil
	return err
}

func readState(p *pinnedFence) (uint64, error) {
	var live uint64
	err := p.maps["fence_state"].Lookup(uint32(0), &live)
	return live, err
}

func readOwner(p *pinnedFence) (identity, error) {
	var id identity
	err := p.maps["fence_owner"].Lookup(uint32(0), &id)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return identity{}, nil
	}
	if err == nil && (id.Incarnation == 0 || id.Incarnation == retired || id.TGID == 0 || id.StartBootTime == 0 || id.Reserved != 0) {
		return identity{}, fmt.Errorf("invalid published fence owner")
	}
	return id, err
}

// Register proves one process incarnation through a one-shot challenge. A
// live owner cannot be superseded. A process armed by self-exec may not
// register itself again under the same kernel identity.
func (f *Fence) Register() (uint64, error) {
	var registered uint64
	err := f.locked(func(p *pinnedFence) error {
		live, err := readState(p)
		if err != nil {
			return err
		}
		if live == retired {
			return ErrRetired
		}
		if live != 0 {
			if live != f.incarnation {
				return fmt.Errorf("another fence incarnation is live")
			}
			id, err := readOwner(p)
			if err != nil {
				return err
			}
			if id.Incarnation != live {
				return ErrFenced
			}
			registered = live
			return nil
		}
		if f.incarnation != 0 {
			return ErrFenced
		}
		id, err := readOwner(p)
		if err != nil {
			return err
		}
		if id.Incarnation >= retired-1 {
			return fmt.Errorf("exec restart fence incarnation space exhausted")
		}
		var secret [16]byte
		if _, err := rand.Read(secret[:]); err != nil {
			return fmt.Errorf("generate fence nonce: %w", err)
		}
		req := challenge{
			Incarnation: id.Incarnation + 1,
			Lo:          binary.LittleEndian.Uint64(secret[:8]),
			Hi:          binary.LittleEndian.Uint64(secret[8:]),
		}
		if req.Lo == 0 && req.Hi == 0 {
			return fmt.Errorf("refusing zero registration challenge")
		}
		nonce := p.maps["fence_nonce"]
		if err := nonce.Put(uint32(0), req); err != nil {
			return err
		}
		// Unknown PRCTL has no default side effect. The tracing hook records
		// the authenticated identity; the syscall's return is not authority.
		_, _, errno := unix.Syscall6(unix.SYS_PRCTL, registerOp, uintptr(req.Lo), uintptr(req.Hi), uintptr(req.Incarnation), 0, 0)
		if err := nonce.Put(uint32(0), challenge{}); err != nil {
			return fmt.Errorf("clear fence challenge: %w", err)
		}
		id, err = readOwner(p)
		if err != nil {
			return err
		}
		live, err = readState(p)
		if err != nil {
			return err
		}
		if id.Incarnation != req.Incarnation || live != req.Incarnation {
			return fmt.Errorf("fence registration not attested (prctl errno %d)", int(errno))
		}
		f.incarnation, registered = live, live
		return nil
	})
	return registered, err
}

// Arm is idempotent for its own incarnation. On success there is no live
// owner, including if an exit or self-exec hook got there first.
func (f *Fence) Arm() error {
	return f.locked(func(p *pinnedFence) error {
		id, err := readOwner(p)
		if err != nil {
			return err
		}
		live, err := readState(p)
		if err != nil {
			return err
		}
		if live == retired {
			return ErrRetired
		}
		if f.incarnation == 0 || id.Incarnation != f.incarnation || (live != 0 && live != f.incarnation) {
			return ErrFenced
		}
		if live == 0 {
			return nil
		}
		if err := p.maps["fence_state"].Put(uint32(0), uint64(0)); err != nil {
			return err
		}
		live, err = readState(p)
		if err != nil {
			return err
		}
		if live != 0 {
			return fmt.Errorf("fence arming was not attested")
		}
		return nil
	})
}

func (f *Fence) ownerAction(action func(*pinnedFence) error) error {
	return f.locked(func(p *pinnedFence) error {
		live, err := readState(p)
		if err != nil {
			return err
		}
		if live == retired {
			return ErrRetired
		}
		id, err := readOwner(p)
		if err != nil {
			return err
		}
		if live == 0 || f.incarnation != live || id.Incarnation != live {
			return ErrFenced
		}
		return action(p)
	})
}

func makeBinding(mode Mode, podUIDHash uint64) (binding, error) {
	b := binding{PodUIDHash: podUIDHash}
	if podUIDHash == 0 {
		return binding{}, fmt.Errorf("zero pod UID fingerprint")
	}
	switch mode {
	case Strict:
		b.StrictSections = execSection
	case Audit:
		b.AuditSections = execSection
	default:
		return binding{}, fmt.Errorf("unknown exec fence mode %d", mode)
	}
	return b, nil
}

func f1Binding(b binding) bool {
	return b.PodUIDHash != 0 && b.Reserved == 0 &&
		b.StrictSections|b.AuditSections == execSection &&
		b.StrictSections&b.AuditSections == 0 && b.BoundSections&^execSection == 0 &&
		((b.Owner == 0) == (b.BoundSections == 0))
}

func initTotals(p *pinnedFence, cgroupID uint64) error {
	nCPU, err := ebpf.PossibleCPU()
	if err != nil {
		return err
	}
	err = p.maps["fence_counts"].Update(cgroupID, make([]Totals, nCPU), ebpf.UpdateNoExist)
	if errors.Is(err, ebpf.ErrKeyExist) {
		return nil
	}
	return err
}

// PodCgroupID resolves a cgroup-v2 directory descriptor to its full kernel
// ID. The caller must resolve the actual host pod directory, not a container
// leaf, namespaced PID, root or textual cgroup basename.
func PodCgroupID(podCgroup *os.File) (id uint64, err error) {
	if podCgroup == nil {
		return 0, fmt.Errorf("missing pod cgroup directory")
	}
	conn, err := podCgroup.SyscallConn()
	if err != nil {
		return 0, err
	}
	var opErr error
	err = conn.Control(func(raw uintptr) {
		fd := int(raw)
		var st unix.Stat_t
		var fs unix.Statfs_t
		if opErr = unix.Fstat(fd, &st); opErr != nil {
			return
		}
		if opErr = unix.Fstatfs(fd, &fs); opErr != nil {
			return
		}
		if st.Mode&unix.S_IFMT != unix.S_IFDIR || fs.Type != unix.CGROUP2_SUPER_MAGIC {
			opErr = fmt.Errorf("pod cgroup must be a host cgroup v2 directory")
			return
		}
		handle, _, handleErr := unix.NameToHandleAt(fd, "", unix.AT_EMPTY_PATH)
		if handleErr != nil {
			opErr = fmt.Errorf("get cgroup v2 file handle: %w", handleErr)
			return
		}
		if handle.Size() != 8 {
			opErr = fmt.Errorf("unexpected cgroup v2 file handle size %d", handle.Size())
			return
		}
		id = binary.NativeEndian.Uint64(handle.Bytes())
		if id == 0 {
			opErr = fmt.Errorf("zero kernel cgroup ID")
		}
	})
	return id, errors.Join(err, opErr)
}

func unifiedCgroupEntry(contents string) bool {
	line := strings.TrimSuffix(contents, "\n")
	return strings.HasPrefix(line, "0::/") && !strings.Contains(line, "\n")
}

func checkCgroupV2() error {
	var fs unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &fs); err != nil {
		return fmt.Errorf("stat cgroup mount: %w", err)
	}
	if fs.Type != unix.CGROUP2_SUPER_MAGIC {
		return fmt.Errorf("exec restart fence requires a unified cgroup v2 host")
	}
	membership, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return fmt.Errorf("read process cgroup membership: %w", err)
	}
	if !unifiedCgroupEntry(string(membership)) {
		return fmt.Errorf("exec restart fence refuses v1/hybrid cgroup membership")
	}
	return nil
}

// Bind marks the actual pre-resolved host pod cgroup. New and mode-changed
// rows are fenced until Move. Rebinding that same pod retains its counters.
func (f *Fence) Bind(podCgroup *os.File, mode Mode, podUIDHash uint64) error {
	cgroupID, err := PodCgroupID(podCgroup)
	if err != nil {
		return err
	}
	next, err := makeBinding(mode, podUIDHash)
	if err != nil {
		return err
	}
	return f.ownerAction(func(p *pinnedFence) error {
		m := p.maps["fence_cgroups"]
		var current binding
		err := m.Lookup(cgroupID, &current)
		switch {
		case err == nil:
			if !f1Binding(current) || current.PodUIDHash != podUIDHash {
				return fmt.Errorf("refusing to replace a different or non-exec-only pod record")
			}
			if current.StrictSections == next.StrictSections && current.AuditSections == next.AuditSections {
				return nil
			}
		case !errors.Is(err, ebpf.ErrKeyNotExist):
			return err
		}
		if err := initTotals(p, cgroupID); err != nil {
			return err
		}
		return m.Put(cgroupID, next)
	})
}

// Move hands exec back to the registered owner. The caller MUST have attested
// that the product backend protects this exact pod and committed generation,
// and must serialize engine publication/withdrawal against this transition.
func (f *Fence) Move(cgroupID uint64) error {
	return f.ownerAction(func(p *pinnedFence) error {
		m := p.maps["fence_cgroups"]
		var b binding
		if err := m.Lookup(cgroupID, &b); err != nil {
			return err
		}
		if !f1Binding(b) {
			return fmt.Errorf("invalid/non-exec-only pod record")
		}
		b.Owner = f.incarnation
		b.BoundSections = execSection
		return m.Update(cgroupID, b, ebpf.UpdateExist)
	})
}

// RemoveExited drops a stale exec-only row. The caller MUST prove that this
// host cgroup no longer exists; do not infer exit from a stale container row,
// policy change, process exit, or a failed protection/adoption attempt.
func (f *Fence) RemoveExited(cgroupID uint64) error {
	if cgroupID == 0 {
		return fmt.Errorf("zero pod cgroup ID")
	}
	return f.ownerAction(func(p *pinnedFence) error {
		m := p.maps["fence_cgroups"]
		var b binding
		err := m.Lookup(cgroupID, &b)
		if err == nil {
			if !f1Binding(b) {
				return fmt.Errorf("refusing to delete a shared/non-exec-only pod record")
			}
			if err := m.Delete(cgroupID); err != nil {
				return err
			}
		} else if !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		err = p.maps["fence_counts"].Delete(cgroupID)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil
		}
		return err
	})
}

func (f *Fence) Snapshot() (Snapshot, error) {
	result := Snapshot{PerCgroup: make(map[uint64]Totals)}
	err := f.locked(func(p *pinnedFence) error {
		nCPU, err := ebpf.PossibleCPU()
		if err != nil {
			return err
		}
		// Read-only, approximate across CPUs. Never clear the kernel's copy.
		var cgroupID uint64
		counts := make([]Totals, nCPU)
		it := p.maps["fence_counts"].Iterate()
		for it.Next(&cgroupID, &counts) {
			var sum Totals
			for _, cpu := range counts {
				sum = Totals{sum.Denied + cpu.Denied, sum.Audit + cpu.Audit, sum.Lost + cpu.Lost}
			}
			result.PerCgroup[cgroupID] = sum
		}
		if err := it.Err(); err != nil {
			return err
		}
		id, err := readOwner(p)
		if err != nil {
			return err
		}
		live, err := readState(p)
		if err != nil {
			return err
		}
		result.Owner = id.Incarnation
		result.Retired = live == retired
		if live != 0 && live != retired {
			if id.Incarnation != live {
				return ErrFenced
			}
			result.LiveIncarnation = live
		}
		return nil
	})
	if err != nil {
		return Snapshot{}, err
	}
	return result, nil
}

// OpenEvents opens the cumulative pinned event stream. The caller owns the
// reader and must close it. A ring buffer observation never changes a verdict.
func (f *Fence) OpenEvents() (reader *ringbuf.Reader, err error) {
	err = f.locked(func(p *pinnedFence) error {
		reader, err = ringbuf.NewReader(p.maps["fence_events"])
		return err
	})
	if err != nil && reader != nil {
		return nil, errors.Join(err, reader.Close())
	}
	return reader, err
}

// Lift is exclusively for authorized Helm pre-delete uninstall. A retired
// pin is a sticky tombstone: a racing ordinary start must not install a
// replacement while the release is being removed. Pins remain as evidence,
// and no ordinary Open or registration can clear retirement.
func Lift(root string, object []byte) (err error) {
	pins, err := openExistingPins(root, object)
	if err != nil {
		return err
	}
	f := &Fence{pins: pins, root: root}
	defer func() { err = errors.Join(err, f.Close()) }()
	return f.locked(func(p *pinnedFence) error {
		if err := p.maps["fence_state"].Put(uint32(0), uint64(retired)); err != nil {
			return err
		}
		live, err := readState(p)
		if err != nil {
			return err
		}
		if live != retired {
			return fmt.Errorf("fence retirement was not attested")
		}
		return nil
	})
}
