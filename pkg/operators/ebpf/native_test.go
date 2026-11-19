// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func TestNativeManifestDoesNotRetainMutableSpecs(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	cfg := viper.New()
	cfg.Set("programs.hook.attach_to", disabledProgram)
	i := &ebpfInstance{config: cfg, collectionSpec: &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{"state": {Type: ebpf.Hash, KeySize: 8, ValueSize: 16, MaxEntries: 4}}, Programs: map[string]*ebpf.ProgramSpec{"hook": {Name: "hook", Type: ebpf.Tracing, AttachTo: "task_newtask", Instructions: asm.Instructions{asm.Return()}}}}}
	i.publishNativeResources(gc)
	v, _ := gc.GetVar(operators.NativeResourcesKey)
	r := v.(*operators.NativeResources)
	i.collectionSpec.Maps["state"].MaxEntries = 999
	i.collectionSpec.Programs["hook"].Instructions = nil
	i.collectionSpec = nil
	if r.Maps["state"].MaxEntries != 4 || r.Programs["hook"].Instructions != 2 || r.Programs["hook"].Target != disabledProgram {
		t.Fatal("manifest not independent or override ignored")
	}
}

func TestNativeAttachmentGuard(t *testing.T) {
	var err error
	info := &link.Info{ID: 9, Program: 7}
	check := nativeAttachmentCheck("hook", 9, info.Type, 7, func() (*link.Info, error) { return info, err })
	if got := check(); got != nil {
		t.Fatal(got)
	}
	info.ID = 10
	if check() == nil {
		t.Fatal("different link to the same program accepted")
	}
	info.ID = 9
	info.Type++
	if check() == nil {
		t.Fatal("different link type accepted")
	}
	info.Type--
	info.Program = 8
	if check() == nil {
		t.Fatal("replacement not detected")
	}
	info = nil
	if check() == nil {
		t.Fatal("missing info accepted")
	}
	err = errors.New("closed")
	if !errors.Is(check(), err) {
		t.Fatal("closed link not detected")
	}
}

type nativePinTestLink struct {
	link.Link
	info           *link.Info
	fd             int
	pinPath        string
	pinCalls       int
	pinned, closed bool
}

func (l *nativePinTestLink) Info() (*link.Info, error) { return l.info, nil }
func (l *nativePinTestLink) IsPinned() bool            { return l.pinned }
func (l *nativePinTestLink) Pin(path string) error {
	l.pinCalls++
	l.pinPath = path
	l.pinned = true
	return nil
}
func (l *nativePinTestLink) FD() int { return l.fd }
func (l *nativePinTestLink) Close() error {
	l.closed = true
	return nil
}

func TestNativeRecoveryPinReopensExactLink(t *testing.T) {
	want := &link.Info{ID: 11, Type: link.TracingType, Program: 7}
	original := &nativePinTestLink{info: want, fd: 41}
	reopened := &nativePinTestLink{info: &link.Info{ID: 11, Type: link.TracingType, Program: 7}, fd: 42}
	lease, err := nativePinAndVerifyLink(original, "se_task_alloc.link", "/test/pin", want,
		func(path string, opts *ebpf.LoadPinOptions) (link.Link, error) {
			if path != "/test/pin" || opts != nil || original.pinCalls != 1 {
				t.Fatal("reopen did not follow pin")
			}
			return reopened, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if original.pinPath != "/test/pin" || lease.PinName() != "se_task_alloc.link" || lease.FD() != 42 || lease.Check() != nil {
		t.Fatal("verified reopened lease missing exact identity")
	}
	if err := lease.Close(); err != nil || !reopened.closed || !original.pinned {
		t.Fatal("closing reopened FD lost pin or failed")
	}
	wrong := &nativePinTestLink{info: &link.Info{ID: 12, Type: link.TracingType, Program: 7}, fd: 43}
	original = &nativePinTestLink{info: want, fd: 41}
	if lease, err := nativePinAndVerifyLink(original, "se_task_alloc.link", "/test/pin", want,
		func(string, *ebpf.LoadPinOptions) (link.Link, error) { return wrong, nil }); err == nil || lease != nil || !wrong.closed || !original.pinned {
		t.Fatal("different pinned link to same program accepted or pin removed")
	}
	original = &nativePinTestLink{info: want, fd: 41}
	if lease, err := nativePinAndVerifyLink(original, "se_task_alloc.link", "/test/pin", want,
		func(string, *ebpf.LoadPinOptions) (link.Link, error) { return nil, errors.New("reopen failed") }); err == nil || lease != nil || !original.pinned {
		t.Fatal("ambiguous reopen error removed pin or returned lease")
	}
}

func TestNativeRecoveryPinRequiresPrivateBPFFSAndExactSelection(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	config := viper.New()
	config.Set("annotations.enforce-exec-shared-recovery", "1")
	want := &link.Info{ID: 11, Type: link.TracingType, Program: 7}
	for _, admitted := range []bool{false, true} {
		for _, name := range []string{"se_task_alloc", "se_task_free", "other"} {
			l := &nativePinTestLink{info: want, fd: 41}
			target := "task_alloc"
			if name == "se_task_free" {
				target = "task_free"
			}
			spec := &ebpf.ProgramSpec{Name: name, Type: ebpf.LSM, SectionName: "lsm/" + target, AttachTo: target}
			i := &ebpfInstance{config: config, recoveryTestRunSelected: true, recoveryTestRunAdmitted: admitted}
			if err := i.publishNativeAttachment(gc, name, spec, l); err != nil {
				t.Fatal(err)
			}
			receipt := i.nativeAttachments[name]
			if (receipt.PinAt != nil) != (admitted && name != "other") {
				t.Fatalf("unexpected pin capability: admitted=%v name=%s", admitted, name)
			}
			if receipt.PinAt != nil {
				dir, err := os.Open(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				if lease, err := receipt.PinAt(int(dir.Fd())); err == nil || lease != nil || l.pinCalls != 0 {
					t.Fatal("non-bpffs directory reached pin syscall")
				}
				_ = dir.Close()
			}
		}
	}
}

func TestNativeReceiptUnpublishDoesNotClearOtherOwner(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	mine, other := new(operators.NativeAttachment), new(operators.NativeAttachment)
	i := &ebpfInstance{nativeAttachments: map[string]*operators.NativeAttachment{"mine": mine, "other": mine}}
	gc.SetVar(operators.NativeAttachmentPrefix+"mine", mine)
	gc.SetVar(operators.NativeAttachmentPrefix+"other", other)
	i.unpublishNativeAttachments(gc)
	if v, _ := gc.GetVar(operators.NativeAttachmentPrefix + "mine"); v != nil {
		t.Fatal("own receipt remains")
	}
	if v, _ := gc.GetVar(operators.NativeAttachmentPrefix + "other"); v != other {
		t.Fatal("other receipt cleared")
	}
}

type nativeTargetTestLink struct {
	link.Link
}

func (nativeTargetTestLink) Info() (*link.Info, error) {
	return &link.Info{ID: 9, Program: 7}, nil
}

func TestNativeTargetsCannotBeOverriddenForLoadedBTFPrograms(t *testing.T) {
	for _, typ := range []ebpf.ProgramType{ebpf.LSM, ebpf.Tracing} {
		t.Run(typ.String(), func(t *testing.T) {
			gc := newResolverGadgetCtx(t, nil)
			cfg := viper.New()
			cfg.Set("programs.hook.attach_to", "required_hook")
			spec := &ebpf.ProgramSpec{Name: "hook", Type: typ, AttachTo: "actual_hook"}
			i := &ebpfInstance{config: cfg, collectionSpec: &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{"hook": spec}}}
			i.publishNativeResources(gc)
			value, _ := gc.GetVar(operators.NativeResourcesKey)
			if got := value.(*operators.NativeResources).Programs["hook"].Target; got != spec.AttachTo {
				t.Fatalf("manifest reports overridden target %q", got)
			}
			if err := i.publishNativeAttachment(gc, "hook", spec, nativeTargetTestLink{}); err != nil {
				t.Fatal(err)
			}
			value, _ = gc.GetVar(operators.NativeAttachmentPrefix + "hook")
			receipt := value.(*operators.NativeAttachment)
			if receipt.Target != spec.AttachTo {
				t.Fatalf("receipt reports overridden target %q", receipt.Target)
			}
			if receipt.LinkID != 9 || receipt.ProgramID != 7 {
				t.Fatalf("receipt lost exact link/program IDs: %+v", receipt)
			}
			if err := receipt.Check(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestNativeManifestRejectsMultipleCollections(t *testing.T) {
	for _, duplicateNames := range []bool{false, true} {
		t.Run(fmt.Sprint("duplicate-names=", duplicateNames), func(t *testing.T) {
			gc := newResolverGadgetCtx(t, nil)
			for layer := range 3 {
				name := fmt.Sprintf("map%d", layer)
				if duplicateNames {
					name = "map"
				}
				i := &ebpfInstance{collectionSpec: &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{name: {Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1}}}}
				i.publishNativeResources(gc)
				value, exists := gc.GetVar(operators.NativeResourcesKey)
				if !exists {
					t.Fatal("missing native manifest marker")
				}
				manifest, _ := value.(*operators.NativeResources)
				if (manifest != nil) != (layer == 0) {
					t.Fatalf("layer %d: multilayer invalidation lost", layer)
				}
				if err := i.validateNativeResources(gc); err != nil {
					t.Fatalf("ordinary image without native validator rejected: %v", err)
				}
			}
		})
	}
}

func TestNativeFinalResourceValidationPrecedesAllocation(t *testing.T) {
	const maxEntries = uint32(1 << 25) // 256 MiB with the 8-byte map entry.
	for _, source := range []string{"variable", "parameter", "context"} {
		t.Run(source, func(t *testing.T) {
			gc := newResolverGadgetCtx(t, nil)
			size := &ebpf.VariableSpec{Name: "state_max_entries"}
			if err := size.Set(maxEntries); err != nil {
				t.Fatal(err)
			}
			i := &ebpfInstance{
				logger:      gc.Logger(),
				params:      map[string]*param{ParamTraceKernel: {Param: &api.Param{Key: ParamTraceKernel, TypeHint: api.TypeBool, DefaultValue: "false"}}},
				paramValues: api.ParamValues{},
				collectionSpec: &ebpf.CollectionSpec{
					Maps:      map[string]*ebpf.MapSpec{"state": {Name: "state", Type: ebpf.Hash, KeySize: 4, ValueSize: 4, MaxEntries: 1}},
					Variables: map[string]*ebpf.VariableSpec{size.Name: size},
				},
			}
			if source != "variable" {
				if err := size.Set(uint32(1)); err != nil {
					t.Fatal(err)
				}
			}
			switch source {
			case "parameter":
				i.params[size.Name] = &param{Param: &api.Param{Key: size.Name, TypeHint: api.TypeUint32}, fromEbpf: true}
				i.paramValues[size.Name] = fmt.Sprint(maxEntries)
			case "context":
				i.vars = map[string]*ebpfVar{size.Name: {name: size.Name, refType: reflect.TypeOf(maxEntries)}}
				gc.SetVar(size.Name, maxEntries)
			}
			i.publishNativeResources(gc)
			value, _ := gc.GetVar(operators.NativeResourcesKey)
			if value.(*operators.NativeResources).Maps["state"].MaxEntries != 1 {
				t.Fatal("preflight must see original static size")
			}
			budgetExceeded := errors.New("native map budget exceeded")
			called := false
			gc.SetVar(operators.NativeResourceValidatorKey, func(r *operators.NativeResources) error {
				called = true
				m := r.Maps["state"]
				if m.MaxEntries != maxEntries || uint64(m.MaxEntries)*uint64(m.KeySize+m.ValueSize) <= 128<<20 {
					t.Fatalf("final map size missing: %+v", m)
				}
				return budgetExceeded
			})
			if err := i.Start(gc); !errors.Is(err, budgetExceeded) || !called {
				t.Fatalf("final preallocation validation not reached: called=%v err=%v", called, err)
			}
			if i.collection != nil {
				t.Fatal("collection allocated before rejection")
			}
		})
	}
}

func TestNativeManifestIncludesIndependentInnerMapTemplates(t *testing.T) {
	inner := &ebpf.MapSpec{Type: ebpf.Array, KeySize: 4, ValueSize: 8, MaxEntries: 1 << 25, Flags: 1}
	outer := &ebpf.MapSpec{Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1, InnerMap: inner}
	i := &ebpfInstance{collectionSpec: &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{"outer": outer}}}
	r := i.nativeResources()
	copied := r.Maps["outer"].InnerMap
	if copied == nil || copied.Type != uint32(ebpf.Array) || copied.KeySize != 4 || copied.ValueSize != 8 || copied.MaxEntries != 1<<25 || copied.Flags != 1 {
		t.Fatalf("inner map allocation lost from manifest: %+v", copied)
	}
	inner.MaxEntries = 1
	outer.InnerMap = nil
	if copied.MaxEntries != 1<<25 {
		t.Fatal("manifest retains mutable inner map spec")
	}
}

func TestNativeManifestBoundsInnerMapTemplates(t *testing.T) {
	for _, cyclic := range []bool{false, true} {
		t.Run(fmt.Sprint("cyclic=", cyclic), func(t *testing.T) {
			outer := &ebpf.MapSpec{Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1}
			if cyclic {
				outer.InnerMap = outer
			} else {
				for range 32 {
					outer = &ebpf.MapSpec{Type: ebpf.ArrayOfMaps, InnerMap: outer}
				}
			}
			i := &ebpfInstance{collectionSpec: &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{"outer": outer}}}
			r := i.nativeResources().Maps["outer"]
			depth := 0
			for r.InnerMap != nil {
				r = *r.InnerMap
				depth++
				if depth > 8 {
					t.Fatal("unbounded native template traversal")
				}
			}
			if depth != 8 || r.Type != uint32(ebpf.UnspecifiedMap) {
				t.Fatalf("invalid template truncated without rejection marker: depth=%d type=%d", depth, r.Type)
			}
		})
	}
}

func TestNativeMapPinningRejectedBeforeAllocation(t *testing.T) {
	for _, nested := range []bool{false, true} {
		for _, afterPreflight := range []bool{false, true} {
			t.Run(fmt.Sprintf("nested=%v/after-preflight=%v", nested, afterPreflight), func(t *testing.T) {
				gc := newResolverGadgetCtx(t, nil)
				state := &ebpf.MapSpec{Name: "state", Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1}
				root := state
				if nested {
					root = &ebpf.MapSpec{Name: "state", Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 1, InnerMap: state}
				}
				i := &ebpfInstance{
					logger:         gc.Logger(),
					params:         map[string]*param{ParamTraceKernel: {Param: &api.Param{Key: ParamTraceKernel, TypeHint: api.TypeBool, DefaultValue: "false"}}},
					collectionSpec: &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{"state": root}},
				}
				called := false
				gc.SetVar(operators.NativeResourceValidatorKey, func(*operators.NativeResources) error {
					called = true
					return nil
				})
				if afterPreflight {
					i.publishNativeResources(gc)
					if err := i.validateNativeResources(gc); err != nil || !called {
						t.Fatalf("unpinned preflight rejected: called=%v err=%v", called, err)
					}
					called = false
				}
				state.Pinning = ebpf.PinByName
				if !afterPreflight {
					if err := i.validateNativeResources(gc); err == nil || !strings.Contains(err.Error(), "automatic pinning") {
						t.Fatalf("automatic pinning passed native admission: %v", err)
					}
				}
				err := i.Start(gc)
				if err == nil || !strings.Contains(err.Error(), "state") || !strings.Contains(err.Error(), "automatic pinning") {
					t.Fatalf("expected named pinning rejection before allocation, got %v", err)
				}
				if called || i.collection != nil {
					t.Fatal("pinned map reached owner admission or collection allocation")
				}
			})
		}
	}
}

func TestNativeMapPinningGuardPreservesOrdinaryGadgets(t *testing.T) {
	gc := newResolverGadgetCtx(t, nil)
	m := &ebpf.MapSpec{Type: ebpf.Array, Pinning: ebpf.PinByName}
	i := &ebpfInstance{collectionSpec: &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{"ordinary": m}}}
	if err := i.validateNativeResources(gc); err != nil {
		t.Fatalf("ordinary gadget pinning rejected: %v", err)
	}
	if m.Pinning != ebpf.PinByName {
		t.Fatal("ordinary gadget pinning was silently stripped")
	}
}

func TestNativeMapPinningGuardBoundsMalformedTemplates(t *testing.T) {
	for _, malformed := range []string{"nil", "cycle", "deep"} {
		t.Run(malformed, func(t *testing.T) {
			var m *ebpf.MapSpec
			switch malformed {
			case "cycle":
				m = &ebpf.MapSpec{Type: ebpf.ArrayOfMaps}
				m.InnerMap = m
			case "deep":
				m = &ebpf.MapSpec{Type: ebpf.Array, Pinning: ebpf.PinByName}
				for range 32 {
					m = &ebpf.MapSpec{Type: ebpf.ArrayOfMaps, InnerMap: m}
				}
			}
			gc := newResolverGadgetCtx(t, nil)
			gc.SetVar(operators.NativeResourceValidatorKey, func(*operators.NativeResources) error {
				t.Fatal("malformed template reached owner admission")
				return nil
			})
			i := &ebpfInstance{collectionSpec: &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{"state": m}}}
			if err := i.validateNativeResources(gc); err == nil || !strings.Contains(err.Error(), "state") {
				t.Fatalf("malformed template not rejected: %v", err)
			}
		})
	}
}
