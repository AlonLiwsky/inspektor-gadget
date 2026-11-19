// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package ocihandler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"testing"
	"time"

	specs "github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
)

type nativeLayerProbe struct{ calls int }

func (*nativeLayerProbe) Name() string { return "native-layer-probe" }
func (p *nativeLayerProbe) InstantiateImageOperator(operators.GadgetContext, oras.ReadOnlyTarget, ocispec.Descriptor, api.ParamValues) (operators.ImageOperatorInstance, error) {
	p.calls++ // Models initialization side effects, without loading guest code.
	return nil, nil
}

func TestNativeOwnerRejectsUnsafeLayersBeforeImageInitialization(t *testing.T) {
	const (
		ebpfMedia = "application/vnd.gadget.ebpf.program.v1+binary"
		wasmMedia = "application/vnd.gadget.wasm.program.v1+binary"
	)
	probe := &nativeLayerProbe{}
	for _, media := range []string{ebpfMedia, wasmMedia} {
		previous, exists := operators.GetImageOperatorForMediaType(media)
		operators.RegisterOperatorForMediaType(media, probe)
		t.Cleanup(func() {
			if exists {
				operators.RegisterOperatorForMediaType(media, previous)
			} else {
				// The registry has no unregister API. Leave an inert test handler,
				// never a callback retaining this test or its invocation counter.
				operators.RegisterOperatorForMediaType(media, &nativeLayerProbe{})
			}
		})
	}
	for _, tc := range []struct {
		name, declared, patched string
		layers                  []string
		native, reject          bool
	}{
		{name: "native request mixed", layers: []string{wasmMedia, ebpfMedia}, native: true, reject: true},
		{name: "native request single wasm", layers: []string{wasmMedia}, native: true, reject: true},
		{name: "declared mixed", declared: "2", patched: "2", layers: []string{wasmMedia, ebpfMedia}, reject: true},
		{name: "declared reverse mixed", declared: "2", patched: "2", layers: []string{ebpfMedia, wasmMedia}, reject: true},
		{name: "declared downgraded", declared: "2", layers: []string{wasmMedia, ebpfMedia}, reject: true},
		{name: "effective upgraded", patched: "2", layers: []string{wasmMedia, ebpfMedia}, reject: true},
		{name: "declared wasm only", declared: "2", patched: "2", layers: []string{wasmMedia}, reject: true},
		{name: "declared multiple ebpf", declared: "2", patched: "2", layers: []string{ebpfMedia, ebpfMedia}, reject: true},
		{name: "declared empty image", declared: "2", patched: "2", reject: true},
		{name: "declared extra unknown layer", declared: "2", patched: "2", layers: []string{ebpfMedia, "application/octet-stream"}, reject: true},
		{name: "native single ebpf", layers: []string{ebpfMedia}, native: true},
		{name: "declared single ebpf", declared: "2", patched: "2", layers: []string{ebpfMedia}},
		{name: "ordinary mixed", layers: []string{wasmMedia, ebpfMedia}},
		{name: "ordinary wasm", layers: []string{wasmMedia}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			probe.calls = 0
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			store := memory.New()
			push := func(media string, data []byte) ocispec.Descriptor {
				desc := content.NewDescriptorFromBytes(media, data)
				require.NoError(t, store.Push(t.Context(), desc, bytes.NewReader(data)))
				return desc
			}
			metadata := fmt.Sprintf(`annotations:
  enforce-exec-owner-abi: %q
params:
  custom:
    mode:
      defaultValue: unchanged
      values:
        unchanged:
          patch: {}
        selected:
          patch:
            annotations:
              enforce-exec-owner-abi: %q
`, tc.declared, tc.patched)
			config := push("application/vnd.gadget.config.v1+yaml", []byte(metadata))
			var layers []ocispec.Descriptor
			for n, media := range tc.layers {
				layers = append(layers, push(media, []byte(fmt.Sprint(n))))
			}
			manifest, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, Config: config, Layers: layers})
			require.NoError(t, err)
			desc := push(ocispec.MediaTypeImageManifest, manifest)
			desc.Platform = &ocispec.Platform{Architecture: runtime.GOARCH, OS: "linux"}
			index, err := json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{desc}})
			require.NoError(t, err)
			desc = push(ocispec.MediaTypeImageIndex, index)
			const image = "ghcr.io/inspektor-gadget/gadget/native-layer-test:latest"
			require.NoError(t, store.Tag(t.Context(), desc, image))
			handler := ocihandler.New()
			params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
			require.NoError(t, params.Set("verify-image", "false"))
			require.NoError(t, handler.Init(params))
			gc := gadgetcontext.New(ctx, image, gadgetcontext.WithDataOperators(handler), gadgetcontext.WithOrasReadonlyTarget(store))
			gc.SetVar(operators.NativeOwnerRequiredKey, tc.native)
			err = gc.Run(api.ParamValues{"custom.mode": "selected"})
			if tc.reject {
				require.ErrorContains(t, err, "native owner requires exactly one eBPF image layer")
				require.Zero(t, probe.calls, "image operator ran before native admission")
			} else {
				require.NoError(t, err)
				require.Equal(t, len(tc.layers), probe.calls)
			}
		})
	}
}
