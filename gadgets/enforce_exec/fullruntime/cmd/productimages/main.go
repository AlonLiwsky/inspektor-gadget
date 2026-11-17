// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

// Command productimages packages the shared product objects that
// build-product.sh wrote (OBJECTS/<profile>-<6.12|6.18>.bpf.o) into an OCI
// image layout, one image per pinned kernel x profile
// (fullruntime.BuildSharedProductImage), tagged with its local reference,
// and fails unless every manifest and index digest equals
// fullruntime.SharedProductImagePins. It prints one OK or FAIL line per
// image with the built digests (a FAIL line also the pinned ones), so a pin
// rotation reads the new digests from its output. With -json it writes one
// entry per built image: {btf, release, profile, image, objectSha256,
// manifestDigest, indexDigest}.
//
// Usage: productimages [-json FILE] -objects DIR -layout DIR
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"oras.land/oras-go/v2/content/oci"

	"github.com/inspektor-gadget/inspektor-gadget/gadgets/enforce_exec/fullruntime"
)

type entry struct {
	BTF            string `json:"btf"`
	Release        string `json:"release"`
	Profile        string `json:"profile"`
	Image          string `json:"image"`
	ObjectSHA256   string `json:"objectSha256"`
	ManifestDigest string `json:"manifestDigest"`
	IndexDigest    string `json:"indexDigest"`
}

func main() {
	objects := flag.String("objects", "", "directory with the product objects (build-product.sh OUTDIR)")
	layout := flag.String("layout", "", "OCI image layout directory to write")
	out := flag.String("json", "", "write the built images as JSON to this file")
	flag.Parse()
	if *objects == "" || *layout == "" || flag.NArg() != 0 {
		flag.Usage()
		os.Exit(2)
	}
	if err := run(context.Background(), *objects, *layout, *out); err != nil {
		fmt.Fprintf(os.Stderr, "productimages: %v\n", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, objects, layout, out string) error {
	store, err := oci.New(layout)
	if err != nil {
		return err
	}
	pins := fullruntime.SharedProductImagePins()
	if len(pins) == 0 {
		return fmt.Errorf("no product image pins")
	}
	var built []entry
	fail := false
	for _, pin := range pins {
		// 6.12.113-138.209.amzn2023.x86_64 -> 6.12
		parts := strings.SplitN(pin.Release, ".", 3)
		path := filepath.Join(objects, pin.Profile+"-"+parts[0]+"."+parts[1]+".bpf.o")
		elf, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		got, err := fullruntime.BuildSharedProductImage(ctx, store, elf, pin.BTF, pin.Profile)
		switch {
		case errors.Is(err, fullruntime.ErrSharedProductImageMismatch):
			fmt.Printf("FAIL %s manifest %s index %s, pinned %s %s\n", got.Image, got.ManifestDigest, got.IndexDigest, pin.ManifestDigest, pin.IndexDigest)
			fail = true
		case err != nil:
			return fmt.Errorf("%s: %w", path, err)
		default:
			fmt.Printf("OK   %s manifest %s index %s\n", got.Image, got.ManifestDigest, got.IndexDigest)
		}
		built = append(built, entry{got.BTF, got.Release, got.Profile, got.Image, got.ObjectSHA256, got.ManifestDigest, got.IndexDigest})
	}
	if out != "" {
		data, err := json.MarshalIndent(built, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(out, append(data, '\n'), 0o644); err != nil {
			return err
		}
	}
	if fail {
		return fmt.Errorf("built image digests differ from fullruntime.SharedProductImagePins")
	}
	return nil
}
