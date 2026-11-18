// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// d3-core-probe (universal-kernel spike, direction D3) reports, for the
// running kernel, the runtime probes of the shared exec engine and, for each
// eBPF object given, its CO-RE relocations against the kernel BTF, its kfunc
// and attach-target imports, and the verifier result of loading it. It only
// loads: nothing is attached, so no exec is affected.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
)

type objectReport struct {
	Object   string
	Programs int
	Maps     int
	// CO-RE relocations of every program, resolved against vmlinux plus the
	// overlay module BTF.
	Relocations         int
	RelocationsByKind   map[string]int
	RelocationsPoisoned []string // "<program>: <relocation>": no target; dead code or a load failure
	RelocationError     string
	Kfuncs              map[string]bool // name -> present in kernel BTF
	AttachTargets       map[string]string
	// MapSizes are the max_entries of the profile-sized maps.
	MapSizes map[string]uint32
	// Load is the verifier result of the whole collection; LoadFailures the
	// programs that had to be dropped to load the rest (each with its error).
	Load         string
	LoadFailures map[string]string
	Loaded       int
	Constants    map[string]uint32
}

type report struct {
	Kernel  fullruntime.SharedKernelProbeReport
	Objects []objectReport
}

func main() {
	load := flag.Bool("load", true, "load each object (verifier pass), never attach")
	equiv := flag.String("equiv", "", "offline: A,B,KERNEL_BTF_FILE: relocate objects A and B against the BTF file and compare the instructions")
	flag.Parse()
	if *equiv != "" {
		parts := strings.Split(*equiv, ",")
		if len(parts) != 3 {
			fmt.Fprintln(os.Stderr, "-equiv wants A,B,KERNEL_BTF_FILE")
			os.Exit(2)
		}
		os.Exit(equivalence(parts[0], parts[1], parts[2]))
	}
	out := report{Kernel: fullruntime.ProbeSharedKernel()}
	_ = rlimit.RemoveMemlock()
	targets, terr := relocationTargets()
	for _, path := range flag.Args() {
		out.Objects = append(out.Objects, inspect(path, targets, terr, out.Kernel, *load))
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", " ")
	_ = enc.Encode(out)
}

func relocationTargets() ([]*btf.Spec, error) {
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return nil, err
	}
	targets := []*btf.Spec{kernel}
	if overlay, err := btf.LoadKernelModuleSpec("overlay"); err == nil {
		targets = append(targets, overlay)
	}
	return targets, nil
}

var kindRE = regexp.MustCompile(`^[a-z_0-9]+`)

func inspect(path string, targets []*btf.Spec, terr error, kernel fullruntime.SharedKernelProbeReport, load bool) objectReport {
	r := objectReport{Object: path, RelocationsByKind: map[string]int{}, Kfuncs: map[string]bool{}, AttachTargets: map[string]string{}, MapSizes: map[string]uint32{}, LoadFailures: map[string]string{}, Constants: map[string]uint32{}}
	spec, err := ebpf.LoadCollectionSpec(path)
	if err != nil {
		r.Load = "spec: " + err.Error()
		return r
	}
	r.Programs, r.Maps = len(spec.Programs), len(spec.Maps)
	for _, name := range []string{"se_tasks", "se_scratch", "se_opaque_keys", "se_exec_terminal_receipts", "se_failure_outer_frames", "se_image_keys", "opaque_real_verdict_events"} {
		if m := spec.Maps[name]; m != nil {
			r.MapSizes[name] = m.MaxEntries
		}
	}
	if terr != nil {
		r.RelocationError = terr.Error()
	}
	names := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		p := spec.Programs[name]
		if p.AttachTo != "" {
			r.AttachTargets[name] = fmt.Sprintf("%s %s", p.SectionName, attachStatus(p, targets))
		}
		var relos []*btf.CORERelocation
		iter := p.Instructions.Iterate()
		for iter.Next() {
			if relo := btf.CORERelocationMetadata(iter.Ins); relo != nil {
				relos = append(relos, relo)
			}
			if iter.Ins.IsKfuncCall() {
				r.Kfuncs[iter.Ins.Reference()] = false
			}
		}
		r.Relocations += len(relos)
		if len(relos) == 0 || terr != nil {
			continue
		}
		fixups, err := btf.CORERelocate(relos, targets, spec.ByteOrder, func(btf.Type) (btf.TypeID, error) { return 1, nil })
		if err != nil {
			r.RelocationsPoisoned = append(r.RelocationsPoisoned, fmt.Sprintf("%s: ERROR %v", name, err))
			continue
		}
		for i := range fixups {
			s := fixups[i].String()
			r.RelocationsByKind[kindRE.FindString(s)]++
			if strings.HasSuffix(s, "=poison") {
				r.RelocationsPoisoned = append(r.RelocationsPoisoned, fmt.Sprintf("%s: %v", name, relos[i]))
			}
		}
	}
	if terr == nil {
		for name := range r.Kfuncs {
			var fn *btf.Func
			r.Kfuncs[name] = targets[0].TypeByName(name, &fn) == nil
		}
	}
	if !load {
		return r
	}
	// The loader-set constants (.rodata feature flags).
	for name, value := range map[string]uint32{"se_image_ovl_layout": kernel.OverlayLayout, "se_image_fmode_backing": kernel.FmodeBacking} {
		if v := spec.Variables[name]; v != nil {
			if err := v.Set(value); err != nil {
				r.Load = fmt.Sprintf("constant %s: %v", name, err)
				return r
			}
			r.Constants[name] = value
		}
	}
	if v := spec.Variables["se_verdict_load_epoch"]; v != nil {
		_ = v.Set(uint64(1))
	}
	for attempt := 0; attempt <= len(names); attempt++ {
		c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{Programs: ebpf.ProgramOptions{LogSizeStart: 1 << 22}})
		if err == nil {
			r.Loaded = len(c.Programs)
			c.Close()
			if len(r.LoadFailures) == 0 {
				r.Load = "ok"
			} else {
				r.Load = fmt.Sprintf("FAILED: %d of %d programs rejected", len(r.LoadFailures), r.Programs)
			}
			return r
		}
		failed := failedProgram(spec, err)
		if failed == "" {
			r.Load = "FAILED: " + short(err)
			return r
		}
		r.LoadFailures[failed] = short(err)
		dropProgram(spec, failed)
	}
	r.Load = "FAILED: could not isolate the failing programs"
	return r
}

// attachStatus reports whether a BTF attach target exists.
func attachStatus(p *ebpf.ProgramSpec, targets []*btf.Spec) string {
	if len(targets) == 0 {
		return "unknown (no kernel BTF)"
	}
	var name string
	switch {
	case p.Type == ebpf.LSM:
		name = "bpf_lsm_" + p.AttachTo
	case p.Type == ebpf.Tracing && p.AttachType == ebpf.AttachTraceRawTp:
		var td *btf.Typedef
		if targets[0].TypeByName("btf_trace_"+p.AttachTo, &td) == nil {
			return "btf_trace_" + p.AttachTo + " present"
		}
		return "btf_trace_" + p.AttachTo + " MISSING"
	case p.Type == ebpf.Tracing:
		name = p.AttachTo
	default:
		return "(resolved at attach) " + p.AttachTo
	}
	var fn *btf.Func
	if targets[0].TypeByName(name, &fn) == nil {
		return name + " present"
	}
	return name + " MISSING"
}

var programRE = regexp.MustCompile(`program ([A-Za-z0-9_]+):`)

func failedProgram(spec *ebpf.CollectionSpec, err error) string {
	for _, m := range programRE.FindAllStringSubmatch(err.Error(), -1) {
		if _, ok := spec.Programs[m[1]]; ok {
			return m[1]
		}
	}
	return ""
}

// dropProgram removes a program and every program-array slot that names it.
func dropProgram(spec *ebpf.CollectionSpec, name string) {
	delete(spec.Programs, name)
	for _, m := range spec.Maps {
		if m.Type != ebpf.ProgramArray {
			continue
		}
		kept := m.Contents[:0]
		for _, kv := range m.Contents {
			if s, ok := kv.Value.(string); ok && s == name {
				continue
			}
			kept = append(kept, kv)
		}
		m.Contents = kept
	}
}

func short(err error) string {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		log := ve.Log
		if len(log) > 12 {
			log = log[len(log)-12:]
		}
		return strings.Split(err.Error(), "\n")[0] + " | " + strings.Join(log, " | ")
	}
	s := err.Error()
	if i := bytes.IndexByte([]byte(s), '\n'); i > 0 {
		s = s[:i]
	}
	if len(s) > 600 {
		s = s[:600]
	}
	return s
}

var _ = asm.Instruction{}
