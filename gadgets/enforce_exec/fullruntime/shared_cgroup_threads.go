// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"

	"golang.org/x/sys/unix"
)

// sharedCgroupThreadsLimit bounds one cgroup.threads read: far above any
// binding's TASK quota (a larger listing fails the adoption, it is never
// truncated).
const sharedCgroupThreadsLimit = 1 << 20

// sharedCgroupThreads lists the tids of the cgroup a retained directory pin
// names, from its cgroup.threads file, in the reader's pid namespace (the
// agent's: init, design 13.8). A removed cgroup (its kernfs files gone) is
// errCgroupGone, i.e. empty; any other failure is an error, never empty.
func sharedCgroupThreads(dir *os.File) ([]uint32, error) {
	if dir == nil {
		return nil, fmt.Errorf("no cgroup pin")
	}
	fd, err := unix.Openat(int(dir.Fd()), "cgroup.threads", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) {
		return nil, errCgroupGone
	}
	if err != nil {
		return nil, fmt.Errorf("open cgroup.threads: %w", err)
	}
	f := os.NewFile(uintptr(fd), "cgroup.threads")
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, sharedCgroupThreadsLimit+1))
	if errors.Is(err, unix.ENODEV) {
		return nil, errCgroupGone
	}
	if err != nil {
		return nil, fmt.Errorf("read cgroup.threads: %w", err)
	}
	if len(raw) > sharedCgroupThreadsLimit {
		return nil, fmt.Errorf("cgroup.threads exceeds %d bytes", sharedCgroupThreadsLimit)
	}
	var tids []uint32
	for _, line := range bytes.Split(raw, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		tid, err := strconv.ParseUint(string(line), 10, 32)
		if err != nil || tid == 0 {
			return nil, fmt.Errorf("cgroup.threads entry %q", line)
		}
		tids = append(tids, uint32(tid))
	}
	return tids, nil
}
