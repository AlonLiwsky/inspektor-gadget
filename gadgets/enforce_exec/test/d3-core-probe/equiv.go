// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
)

// equivalence relocates every program of objects a and b against one kernel
// BTF file (offline: no kernel is touched) and compares the relocated
// instruction streams. It answers: are two objects compiled against
// different vmlinux.h the same programs on that kernel?
func equivalence(a, b, btfPath string) int {
	target, err := btf.LoadSpec(btfPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "target BTF %s: %v\n", btfPath, err)
		return 2
	}
	ra, err := relocated(a, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", a, err)
		return 2
	}
	rb, err := relocated(b, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", b, err)
		return 2
	}
	names := map[string]bool{}
	for n := range ra {
		names[n] = true
	}
	for n := range rb {
		names[n] = true
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	same, differ := 0, 0
	for _, n := range sorted {
		pa, oka := ra[n]
		pb, okb := rb[n]
		switch {
		case !oka || !okb:
			differ++
			fmt.Printf("DIFFER %s: present in a=%v b=%v\n", n, oka, okb)
		case pa.digest != pb.digest:
			differ++
			fmt.Printf("DIFFER %s: %d vs %d instructions, %d vs %d relocations, first difference at %d\n", n, len(pa.text), len(pb.text), pa.relocs, pb.relocs, firstDiff(pa.text, pb.text))
		default:
			same++
		}
	}
	total := 0
	for _, p := range ra {
		total += p.relocs
	}
	fmt.Printf("EQUIV target=%s a=%s b=%s: %d programs identical after relocation, %d differ; %d relocations applied in a\n", btfPath, a, b, same, differ, total)
	if differ != 0 {
		return 1
	}
	return 0
}

type relocatedProgram struct {
	digest string
	text   []string
	relocs int
}

func relocated(path string, target *btf.Spec) (map[string]relocatedProgram, error) {
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		return nil, err
	}
	out := map[string]relocatedProgram{}
	for name, p := range spec.Programs {
		insns := p.Instructions
		var relos []*btf.CORERelocation
		var at []int
		for i := range insns {
			if relo := btf.CORERelocationMetadata(&insns[i]); relo != nil {
				relos = append(relos, relo)
				at = append(at, i)
			}
		}
		if len(relos) != 0 {
			fixups, err := btf.CORERelocate(relos, []*btf.Spec{target}, spec.ByteOrder, func(btf.Type) (btf.TypeID, error) { return 1, nil })
			if err != nil {
				return nil, fmt.Errorf("program %s: %w", name, err)
			}
			for i := range fixups {
				if err := fixups[i].Apply(&insns[at[i]]); err != nil {
					return nil, fmt.Errorf("program %s: apply %v: %w", name, relos[i], err)
				}
			}
		}
		text := make([]string, len(insns))
		h := sha256.New()
		for i := range insns {
			ins := insns[i]
			// Opcode, registers, offset, constant and the symbolic reference
			// (map, subprogram, kfunc): everything the kernel will see, no
			// source line or BTF metadata.
			text[i] = fmt.Sprintf("%v dst=%v src=%v off=%d imm=%d ref=%s sym=%s", ins.OpCode, ins.Dst, ins.Src, ins.Offset, ins.Constant, ins.Reference(), ins.Symbol())
			h.Write([]byte(text[i] + "\n"))
		}
		out[name] = relocatedProgram{digest: hex.EncodeToString(h.Sum(nil)), text: text, relocs: len(relos)}
	}
	return out, nil
}

func firstDiff(a, b []string) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return min(len(a), len(b))
}

var _ = strings.TrimSpace
