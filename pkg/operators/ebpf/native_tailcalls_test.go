// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ebpfoperator

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/spf13/viper"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

func tailCallInstance(calls []map[string]any) *ebpfInstance {
	cfg := viper.New()
	cfg.Set("programs.target.attach_to", disabledProgram)
	if calls != nil {
		cfg.Set("tail_calls", calls)
	}
	return &ebpfInstance{config: cfg, collectionSpec: &ebpf.CollectionSpec{
		Maps:     map[string]*ebpf.MapSpec{"targets": {Type: ebpf.ProgramArray, KeySize: 4, ValueSize: 4, MaxEntries: 1}},
		Programs: map[string]*ebpf.ProgramSpec{"target": {Name: "target", Type: ebpf.Kprobe, Instructions: asm.Instructions{asm.Return()}}},
	}}
}

// TestNativeTailCallDeclarations: the metadata tail_calls are part of the
// native manifest exactly as declared; a duplicate slot or a nameless entry
// is refused, and no declaration is no tail call.
func TestNativeTailCallDeclarations(t *testing.T) {
	i := tailCallInstance([]map[string]any{{"map": "targets", "index": 0, "program": "target"}})
	calls, err := i.nativeTailCalls()
	want := []operators.NativeTailCall{{Map: "targets", Index: 0, Program: "target"}}
	if err != nil || !reflect.DeepEqual(calls, want) {
		t.Fatalf("declarations %+v %v", calls, err)
	}
	if r := i.nativeResources(); !reflect.DeepEqual(r.TailCalls, want) {
		t.Fatalf("manifest tail calls %+v", r.TailCalls)
	}
	for name, bad := range map[string][]map[string]any{
		"duplicate slot": {{"map": "targets", "index": 0, "program": "target"}, {"map": "targets", "index": 0, "program": "target"}},
		"no program":     {{"map": "targets", "index": 0}},
		"no map":         {{"index": 0, "program": "target"}},
	} {
		if _, err := tailCallInstance(bad).nativeTailCalls(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if calls, err := tailCallInstance(nil).nativeTailCalls(); err != nil || calls != nil {
		t.Fatalf("no declaration: %+v %v", calls, err)
	}
}

// TestNativeTailCallInstallRefusesBadSlots: before touching the kernel the
// installer refuses a slot that is not an empty program array entry or a
// target that would also attach.
func TestNativeTailCallInstallRefusesBadSlots(t *testing.T) {
	for name, edit := range map[string]func(*ebpfInstance){
		"out of range": func(i *ebpfInstance) {
			i.config.Set("tail_calls", []map[string]any{{"map": "targets", "index": 1, "program": "target"}})
		},
		"not a program array": func(i *ebpfInstance) {
			i.collectionSpec.Maps["targets"].Type = ebpf.Array
		},
		"attached target": func(i *ebpfInstance) {
			i.config.Set("programs.target.attach_to", "")
			i.collectionSpec.Programs["target"].AttachTo = "do_exit"
		},
		"unknown target": func(i *ebpfInstance) {
			i.config.Set("tail_calls", []map[string]any{{"map": "targets", "index": 0, "program": "other"}})
		},
	} {
		i := tailCallInstance([]map[string]any{{"map": "targets", "index": 0, "program": "target"}})
		edit(i)
		i.collection = &ebpf.Collection{Maps: map[string]*ebpf.Map{}, Programs: map[string]*ebpf.Program{}}
		if err := i.installNativeTailCalls(); err == nil || !strings.Contains(err.Error(), "tail call") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestNativeTeardownDetachesBeforeCollectionClose pins the teardown order
// the frozen tail-call arrays rely on: a PROG_ARRAY is cleared when its last
// user reference goes away, so every link must be detached (Stop) before
// the collection's map FDs close (Close); otherwise attached hooks would
// reach empty slots (fail-closed, but a spurious refusal).
func TestNativeTeardownDetachesBeforeCollectionClose(t *testing.T) {
	raw, err := os.ReadFile("ebpf.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	closeAt := strings.Index(src, "func (i *ebpfInstance) Close(gadgetCtx operators.GadgetContext) error {")
	stopAt := strings.Index(src, "func (i *ebpfInstance) Stop(gadgetCtx operators.GadgetContext) error {")
	if closeAt < 0 || stopAt < 0 {
		t.Fatal("Stop/Close not found")
	}
	closeBody := src[closeAt:]
	if end := strings.Index(closeBody, "\n}\n"); end > 0 {
		closeBody = closeBody[:end]
	}
	stopCall, collectionClose := strings.Index(closeBody, "i.Stop(gadgetCtx)"), strings.Index(closeBody, "i.collection.Close()")
	if stopCall < 0 || collectionClose < 0 || stopCall > collectionClose {
		t.Fatal("Close must run Stop (detaching every link) before closing the collection")
	}
	stopBody := src[stopAt:]
	if end := strings.Index(stopBody, "\n}\n"); end > 0 {
		stopBody = stopBody[:end]
	}
	if !strings.Contains(stopBody, "for k := len(i.links) - 1; k >= 0; k-- {\n\t\t\tgadgets.CloseLink(i.links[k])") || strings.Contains(stopBody, "collection.Close()") {
		t.Fatal("Stop must close every link in reverse attach order and leave the collection open")
	}
}

// TestNativeTailCallInstallFailureCollectionClosed (review L4): Start
// assigns i.collection before installing the tail calls, so a failed
// install returns with the instance owning the collection, and Close (which
// the gadget context runs for every operator after a failed Start, see
// GadgetContext.Run) closes and drops it.
func TestNativeTailCallInstallFailureCollectionClosed(t *testing.T) {
	i := tailCallInstance([]map[string]any{{"map": "targets", "index": 0, "program": "other"}})
	i.bpfOperator = &ebpfOperator{}
	i.collection = &ebpf.Collection{Maps: map[string]*ebpf.Map{}, Programs: map[string]*ebpf.Program{}}
	if err := i.installNativeTailCalls(); err == nil {
		t.Fatal("bad tail call installed")
	}
	if i.collection == nil {
		t.Fatal("failed install dropped the collection without closing it")
	}
	if err := i.Close(nil); err != nil {
		t.Fatal(err)
	}
	if i.collection != nil {
		t.Fatal("Close after a failed tail-call install left the collection open")
	}

	raw, err := os.ReadFile("ebpf.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	assign, install := strings.Index(src, "\ti.collection = collection\n"), strings.Index(src, "if err := i.installNativeTailCalls(); err != nil {")
	if assign < 0 || install < 0 || assign > install {
		t.Fatal("Start must hand the collection to the instance (closed by Close) before installing tail calls")
	}
}
