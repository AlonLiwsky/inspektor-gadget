// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package fullruntime

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

func readPinnedProc(file *os.File, name string) ([]byte, error) {
	fd, err := unix.Openat(int(file.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	entry := os.NewFile(uintptr(fd), name)
	defer entry.Close()
	data, err := io.ReadAll(io.LimitReader(entry, 64*1024+1))
	if err != nil {
		return nil, err
	}
	if len(data) > 64*1024 {
		return nil, fmt.Errorf("oversized pinned proc entry")
	}
	return data, nil
}

func readPinnedInitStart(file *os.File, pid uint32) (string, error) {
	if file == nil || pid == 0 {
		return "", fmt.Errorf("exact pinned init required")
	}
	stat, err := readPinnedProc(file, "stat")
	if err != nil {
		return "", err
	}
	start, err := parsePinnedStat(stat, pid)
	if err != nil {
		return "", err
	}
	status, err := readPinnedProc(file, "status")
	if err != nil {
		return "", err
	}
	seen := false
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "Tgid:") {
			continue
		}
		if seen {
			return "", fmt.Errorf("duplicate pinned Tgid")
		}
		seen = true
		value, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "Tgid:")), 10, 32)
		if err != nil || value != uint64(pid) {
			return "", fmt.Errorf("pinned task is not the trusted init leader")
		}
	}
	if !seen {
		return "", fmt.Errorf("pinned Tgid missing")
	}
	return start, nil
}

func parsePinnedStat(data []byte, pid uint32) (string, error) {
	text := string(data)
	begin, end := strings.IndexByte(text, '('), strings.LastIndexByte(text, ')')
	if begin <= 0 || end < begin {
		return "", fmt.Errorf("malformed pinned stat")
	}
	actual, err := strconv.ParseUint(strings.TrimSpace(text[:begin]), 10, 32)
	if err != nil || actual != uint64(pid) {
		return "", fmt.Errorf("pinned proc PID mismatch")
	}
	fields := strings.Fields(text[end+1:])
	if len(fields) < 20 {
		return "", fmt.Errorf("incomplete pinned stat")
	}
	value, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || value == 0 {
		return "", fmt.Errorf("invalid pinned starttime")
	}
	return fields[19], nil
}
