// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package containerd

import (
	"testing"

	containerd "github.com/containerd/containerd/v2/client"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
)

func TestProcessStatusStateToRuntimeClientState(t *testing.T) {
	for _, tt := range []struct {
		status containerd.ProcessStatus
		want   string
	}{
		{containerd.Created, runtimeclient.StateCreated},
		{containerd.Running, runtimeclient.StateRunning},
		{containerd.Stopped, runtimeclient.StateExited},
		{containerd.ProcessStatus("unknown"), runtimeclient.StateUnknown},
	} {
		if got := processStatusStateToRuntimeClientState(tt.status); got != tt.want {
			t.Errorf("status %q: got %q, want %q", tt.status, got, tt.want)
		}
	}
}
