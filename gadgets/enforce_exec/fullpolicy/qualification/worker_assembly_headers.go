// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"errors"
	"path/filepath"
)

// The supported linux/amd64 assembler searches GOROOT/pkg/include in addition
// to package-local inputs already captured by go list. Capture the entire
// builtin include tree conservatively, including headers unused on this profile.
// runtime's CGO0 assembly also includes the out-of-package cgo/abi_amd64.h.
// This is the reviewed static set, not a general preprocessor/include resolver.
// go_asm.h is compiler-generated from captured Go types and compiler inputs.
func workerAssemblyHeaderInputs(goroot string) (map[string]string, error) {
	inputs := map[string]string{}
	if err := workerTree(inputs, "toolchain/pkg/include", filepath.Join(goroot, "pkg/include")); err != nil {
		return nil, err
	}
	for _, name := range []string{"textflag.h", "funcdata.h", "asm_amd64.h"} {
		if !workerDigest(inputs["toolchain/pkg/include/"+name]) {
			return nil, errors.New("missing required selected assembler header")
		}
	}
	const abi = "src/runtime/cgo/abi_amd64.h"
	hash, err := workerRegularHash(goroot, abi)
	if err != nil {
		return nil, err
	}
	inputs["toolchain/"+abi] = hash
	return inputs, nil
}
