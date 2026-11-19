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
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/memory"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
)

func TestBehaviorAdmissionBeforeCustomParameterPatches(t *testing.T) {
	for _, tc := range []struct {
		name, original, patched, wantError string
		allow                              bool
	}{
		{"mutator downgrade", "mutator", "observer", "requires operator.oci.allow-enforcement=true", false},
		{"invalid downgrade", "invalid", "observer", "unknown gadget behavior", true},
		{"null downgrade", "null", "observer", "gadget behavior must be a string", true},
		{"effective mutator", "observer", "mutator", "requires operator.oci.allow-enforcement=true", false},
		{"approved downgrade", "mutator", "observer", "", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			store := memory.New()
			push := func(media string, data []byte) ocispec.Descriptor {
				desc := content.NewDescriptorFromBytes(media, data)
				require.NoError(t, store.Push(ctx, desc, bytes.NewReader(data)))
				return desc
			}
			metadata := fmt.Sprintf(`behavior: %s
params:
  custom:
    mode:
      defaultValue: unchanged
      values:
        unchanged:
          patch: {}
        selected:
          patch:
            behavior: %s
`, tc.original, tc.patched)
			cfg := push("application/vnd.gadget.config.v1+yaml", []byte(metadata))
			manifest, err := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, Config: cfg})
			require.NoError(t, err)
			desc := push(ocispec.MediaTypeImageManifest, manifest)
			desc.Platform = &ocispec.Platform{Architecture: runtime.GOARCH, OS: "linux"}
			index, err := json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, Manifests: []ocispec.Descriptor{desc}})
			require.NoError(t, err)
			desc = push(ocispec.MediaTypeImageIndex, index)
			const image = "ghcr.io/inspektor-gadget/gadget/behavior-test:latest"
			require.NoError(t, store.Tag(ctx, desc, image))
			handler := ocihandler.New()
			params := apihelpers.ToParamDescs(handler.GlobalParams()).ToParams()
			require.NoError(t, params.Set("verify-image", "false"))
			require.NoError(t, params.Set("allow-enforcement", fmt.Sprint(tc.allow)))
			require.NoError(t, handler.Init(params))
			gadgetCtx := gadgetcontext.New(ctx, image, gadgetcontext.WithDataOperators(handler), gadgetcontext.WithOrasReadonlyTarget(store))
			err = gadgetCtx.Run(api.ParamValues{"custom.mode": "selected"})
			if tc.wantError != "" {
				require.ErrorContains(t, err, tc.wantError)
			} else {
				require.NoError(t, err)
				cfg, ok := gadgetCtx.GetVar("config")
				require.True(t, ok)
				require.Equal(t, tc.patched, cfg.(*viper.Viper).GetString("behavior"))
			}
		})
	}
}
