// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

func TestExecPolicyIsNativeStartupData(t *testing.T) {
	file := filepath.Join(t.TempDir(), "policy.yaml")
	require.NoError(t, os.WriteFile(file, []byte("version: 1\nbinding:\n  containers:\n    - runtime: docker\n      id: first\n    - runtime: docker\n      id: second\npolicy:\n  mode: enforce\n  exec:\n    default: deny\n"), 0o600))
	entries, targets, err := readExecPolicy(file, 72)
	require.NoError(t, err)
	require.Equal(t, uint64(72), entries[0].Generation)
	require.Len(t, targets, 2)
	_, _, err = readExecPolicy(file, 0)
	require.Error(t, err)
	cmd := newEnforceExecCommand(local.New())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	require.Nil(t, cmd.Flags().Lookup("exec-policy"), "compiled policy must not become a gadget parameter")
}

func TestExecCommandRejectsPolicyBeforeRootInitialization(t *testing.T) {
	file := filepath.Join(t.TempDir(), "process.yaml")
	require.NoError(t, os.WriteFile(file, []byte("version: 1\nbinding:\n  process:\n    hostPID: 42\n"), 0o600))
	cmd := newEnforceExecCommand(local.New())
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{"image", "--policy", file})
	require.ErrorContains(t, cmd.Execute(), "field process not found")
}
