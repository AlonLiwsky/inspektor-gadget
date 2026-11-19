// Copyright 2026 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package kernel_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"
)

// TestExecRestrictedCRI validates the actual containerd CRI exec path. NODE
// networking avoids a CNI dependency; PID and mount namespaces remain isolated.
// This is not a Kubernetes cluster or a node-agent CRD integration test.
func TestExecRestrictedCRI(t *testing.T) {
	if os.Getenv("IG_EXEC_KERNEL_TEST") != "1" || os.Getenv("IG_EXEC_CRI_TEST") != "1" {
		t.Skip("requires disposable containerd CRI BPF LSM host and explicit opt-in")
	}
	require.Equal(t, 0, os.Geteuid())
	require.NoError(t, rlimit.RemoveMemlock())
	endpoint := os.Getenv("IG_EXEC_CRI_ENDPOINT")
	if endpoint == "" {
		endpoint = "unix:///run/containerd/containerd.sock"
	}
	prefix := []string{"--runtime-endpoint", endpoint, "--image-endpoint", endpoint}
	invoke := func(args ...string) (string, error) {
		cmd := exec.Command("crictl", append(append([]string(nil), prefix...), args...)...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return string(out) + stderr.String(), err
		}
		return strings.TrimSpace(string(out)), nil
	}
	command := func(args ...string) string {
		t.Helper()
		out, err := invoke(args...)
		require.NoError(t, err, out)
		return out
	}
	command("info")
	command("pull", "docker.io/library/alpine:3.21")
	dir := t.TempDir()
	logdir := filepath.Join(dir, "logs")
	require.NoError(t, os.Mkdir(logdir, 0o755))
	namespaceOptions := map[string]int{"network": 2, "pid": 1, "ipc": 0}
	sandbox := map[string]interface{}{"metadata": map[string]interface{}{"name": "ig-restricted", "namespace": "default", "uid": fmt.Sprintf("ig-restricted-%d", os.Getpid()), "attempt": 0}, "log_directory": logdir, "linux": map[string]interface{}{"security_context": map[string]interface{}{"namespace_options": namespaceOptions}}}
	write := func(name string, data interface{}) string {
		t.Helper()
		b, err := json.Marshal(data)
		require.NoError(t, err)
		p := filepath.Join(dir, name)
		require.NoError(t, os.WriteFile(p, b, 0o600))
		return p
	}
	sandboxFile := write("sandbox.json", sandbox)
	pod := command("runp", sandboxFile)
	t.Cleanup(func() { command("stopp", pod); command("rmp", pod) })
	create := func(name string) execContainer {
		spec := map[string]interface{}{"metadata": map[string]interface{}{"name": name, "attempt": 0}, "image": map[string]string{"image": "docker.io/library/alpine:3.21"}, "command": []string{"sleep", "600"}, "log_path": name + ".log", "linux": map[string]interface{}{"security_context": map[string]interface{}{"privileged": false, "no_new_privs": true, "capabilities": map[string]interface{}{"drop_capabilities": []string{"ALL"}, "add_capabilities": []string{"SYS_CHROOT"}}, "namespace_options": namespaceOptions, "seccomp": map[string]int{"profile_type": 1}, "apparmor_profile": "unconfined"}}}
		id := command("create", pod, write(name+".json", spec), sandboxFile)
		t.Cleanup(func() { command("stop", id); command("rm", id) })
		command("start", id)

		execFn := func(args ...string) (string, error) {
			return invoke(append([]string{"exec", "--sync", "--timeout", "10", id}, args...)...)
		}
		out, err := execFn("mkdir", "-p", "/tmp/approved")
		require.NoError(t, err, out)
		for _, p := range []string{"/tmp/busybox", "/tmp/approved/busybox", "/runc"} {
			out, err := execFn("cp", "/bin/busybox", p)
			require.NoError(t, err, out)
		}
		var inspected struct {
			Info struct {
				PID int `json:"pid"`
			} `json:"info"`
		}
		require.NoError(t, json.Unmarshal([]byte(command("inspect", id)), &inspected))
		require.NotZero(t, inspected.Info.PID)
		pid := fmt.Sprint(inspected.Info.PID)
		c := execContainer{identity: containerIdentity(t, "containerd", id, pid), pid: pid, exec: execFn}
		return c
	}
	target, control := create("target"), create("control")
	exerciseRestrictedRuntime(t, target, control, os.Getenv("IG_EXEC_EXPECT_RUNC_HELPER") == "1")
}
