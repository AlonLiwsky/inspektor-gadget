// Copyright 2019-2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ig

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/command"
)

func TestNodeReadinessBlocksWorkload(t *testing.T) {
	r := newNodeReadiness([]string{"node-a", "node-b"})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	exited := make(chan struct{})
	workload := make(chan error, 1)
	go func() { workload <- r.wait(ctx, exited, func() error { return nil }) }()
	for _, line := range []string{
		`time="now" level=debug msg="running..."` + "\n",
		`time="now" level=debug msg="wrong-node | running..."` + "\n",
		`time="now" level=debug msg="node-a | running..."` + "\n",
		`time="now" level=debug msg="node-a | running..."` + "\n",
		`time="now" level=debug msg="node-b | running... not yet"` + "\n",
	} {
		_, err := r.Write([]byte(line))
		require.NoError(t, err)
	}
	select {
	case err := <-workload:
		t.Fatalf("workload unblocked before second node: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	_, err := r.Write([]byte(`time="now" level=debug msg="node-b      | run`))
	require.NoError(t, err)
	select {
	case err := <-workload:
		t.Fatalf("partial marker unblocked workload: %v", err)
	default:
	}
	_, err = r.Write([]byte("ning...\"\n"))
	require.NoError(t, err)
	require.NoError(t, <-workload)
}

func TestNodeReadinessFailure(t *testing.T) {
	for _, cause := range []string{"cancel", "deadline", "exit-success", "exit-error"} {
		t.Run(cause, func(t *testing.T) {
			r := newNodeReadiness([]string{"node-b", "node-a"})
			_, _ = r.Write([]byte("level=debug msg=\"node-a | running...\"\n"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			var exitErr error
			switch cause {
			case "cancel":
				cancel()
			case "deadline":
				var c context.CancelFunc
				ctx, c = context.WithTimeout(ctx, time.Millisecond)
				defer c()
			case "exit-success":
				close(done)
			case "exit-error":
				exitErr = errors.New("failed startup")
				close(done)
			}
			err := r.wait(ctx, done, func() error { return exitErr })
			require.ErrorContains(t, err, "node-b")
			require.NotContains(t, err.Error(), "node-a")
			if exitErr != nil {
				require.ErrorIs(t, err, exitErr)
			}
		})
	}
}

func TestNodeReadinessConcurrentWrites(t *testing.T) {
	nodes := make([]string, 20)
	for i := range nodes {
		nodes[i] = fmt.Sprintf("node-%d", i)
	}
	r := newNodeReadiness(nodes)
	for _, node := range nodes {
		go func() { _, _ = fmt.Fprintf(r, "level=debug msg=\"%s | running...\"\n", node) }()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, r.wait(ctx, make(chan struct{}), func() error { return nil }))
}

func TestGadgetNodes(t *testing.T) {
	pods := []runtime.Object{
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "a", Namespace: "daemon", Labels: map[string]string{"k8s-app": "gadget"}}, Spec: corev1.PodSpec{NodeName: "node-a"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "a-rollout", Namespace: "daemon", Labels: map[string]string{"k8s-app": "gadget"}}, Spec: corev1.PodSpec{NodeName: "node-a"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "b", Namespace: "daemon", Labels: map[string]string{"k8s-app": "gadget"}}, Spec: corev1.PodSpec{NodeName: "node-b"}},
		&corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "other", Namespace: "daemon"}, Spec: corev1.PodSpec{NodeName: "wrong-node"}},
	}
	client := fake.NewClientset(pods...)
	for _, tc := range []struct {
		name     string
		selected []string
		want     []string
		err      string
	}{
		{name: "all including not yet ready pods", want: []string{"node-a", "node-b"}},
		{name: "selection", selected: []string{"node-b"}, want: []string{"node-b"}},
		{name: "missing", selected: []string{"missing"}, err: "missing"},
		{name: "duplicate selection", selected: []string{"node-a", "node-a"}, err: "duplicate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := gadgetNodes(context.Background(), client, "daemon", tc.selected)
			if tc.err != "" {
				require.ErrorContains(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.want, got)
			}
		})
	}
	_, err := gadgetNodes(context.Background(), client, "workload", nil)
	require.ErrorContains(t, err, "no gadget pods")
	client.PrependReactor("list", "pods", func(action ktesting.Action) (bool, runtime.Object, error) {
		return true, nil, errors.New("discovery failed")
	})
	_, err = gadgetNodes(context.Background(), client, "daemon", nil)
	require.ErrorContains(t, err, "discovery failed")
}

func TestGadgetNamespace(t *testing.T) {
	client := fake.NewClientset()
	ns, err := gadgetNamespace(context.Background(), client)
	require.NoError(t, err)
	require.Equal(t, "gadget", ns)
	for _, namespace := range []string{"custom", "second"} {
		_, err = client.AppsV1().DaemonSets(namespace).Create(context.Background(), &appsv1.DaemonSet{ObjectMeta: metav1.ObjectMeta{Name: "gadget", Labels: map[string]string{"k8s-app": "gadget"}}}, metav1.CreateOptions{})
		require.NoError(t, err)
		ns, err = gadgetNamespace(context.Background(), client)
		if namespace == "custom" {
			require.NoError(t, err)
			require.Equal(t, "custom", ns)
		} else {
			require.ErrorContains(t, err, "multiple gadget namespaces")
		}
	}
}

func TestKubernetesRunnerWaitsAndFreezesTargets(t *testing.T) {
	var discoveryPaths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		discoveryPaths = append(discoveryPaths, req.URL.Path)
		require.Equal(t, "k8s-app=gadget", req.URL.Query().Get("labelSelector"))
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"apiVersion":"v1","kind":"PodList","items":[{"metadata":{"name":"a","namespace":"daemon"},"spec":{"nodeName":"node-a"}},{"metadata":{"name":"b","namespace":"daemon"},"spec":{"nodeName":"node-b"}}]}`)
	}))
	defer server.Close()
	dir := t.TempDir()
	config := filepath.Join(dir, "config")
	require.NoError(t, os.WriteFile(config, []byte(fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: selected
  cluster:
    server: %s
contexts:
- name: selected
  context:
    cluster: selected
    user: selected
    namespace: ignored
current-context: selected
users:
- name: selected
  user: {}
`, server.URL)), 0o600))
	t.Setenv("KUBECONFIG", filepath.Join(dir, "must-not-be-used"))
	script := filepath.Join(dir, "gadget")
	marker := filepath.Join(dir, "second-ready")
	require.NoError(t, os.WriteFile(script, []byte(fmt.Sprintf(`#!/bin/sh
printf 'level=debug msg="running..."\n' >&2
printf 'level=debug msg="node-a | running..."\n' >&2
sleep 0.05
touch '%s'
printf '{"event":"retained"}\n'
printf 'level=debug msg="node-b | running..."\n' >&2
exec sleep 60
`, marker)), 0o700))
	r := &runner{path: script, image: "test", outputMode: "json", flags: []string{
		"--kubeconfig=" + config, "--context=selected", "--cluster=selected", "--user=selected",
		"-n=workload", "--gadget-namespace=daemon", "--node=node-b,node-a",
	}}
	WithKubernetesReady(time.Second)(r)
	r.ValidateOutput = func(t *testing.T, output string) { require.JSONEq(t, `{"event":"retained"}`, output) }
	r.Start(t)
	t.Cleanup(func() { r.Stop(t) })
	_, err := os.Stat(marker)
	require.NoError(t, err, "workload cannot start before second node")
	require.Equal(t, []string{"/api/v1/namespaces/daemon/pods"}, discoveryPaths)
	require.Contains(t, r.Cmd.Args, "--node=node-a,node-b")
	require.NotContains(t, r.Cmd.Args, "--node=node-b,node-a")
	require.Contains(t, r.Cmd.Args, "--gadget-namespace=daemon")
	require.Contains(t, r.Cmd.Args, "--verbose")
	require.Contains(t, r.Cmd.Args, "-n=workload")
}

func TestNodeReadinessRejectsEmptySet(t *testing.T) {
	require.ErrorContains(t, newNodeReadiness(nil).wait(context.Background(), nil, func() error { return nil }), "no expected gadget nodes")
}

func TestNodeReadinessProcessExit(t *testing.T) {
	for _, status := range []string{"0", "7"} {
		t.Run(status, func(t *testing.T) {
			ready := newNodeReadiness([]string{"node-a", "node-b"})
			c := &command.Command{Name: "exits-before-ready", Cmd: exec.Command("sh", "-c", `printf 'level=debug msg="node-a | running..."\n' >&2; exit `+status), StdErrWriter: ready, ObserveExit: true}
			c.Start(t)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err := ready.wait(ctx, c.Exited(), c.ExitError)
			require.ErrorContains(t, err, "node-b")
			require.NotContains(t, err.Error(), "node-a")
			select {
			case <-c.Exited():
			default:
				t.Fatal("process has not been reaped")
			}
		})
	}
}

func TestReadinessRejectsImplicitClusterOverrides(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("context: other-cluster\n"), 0o600))
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.String("context", "", "")
	require.ErrorContains(t, rejectImplicitTargetConfig(flags, path), "explicit --context")
	require.NoError(t, flags.Set("context", "selected"))
	require.NoError(t, rejectImplicitTargetConfig(flags, path))
	t.Setenv("INSPEKTOR_GADGET_CLUSTER", "other-cluster")
	require.ErrorContains(t, rejectImplicitTargetConfig(flags, path), "explicit --cluster")
	require.Error(t, rejectImplicitTargetConfig(flags, filepath.Join(dir, "missing")))
}

func TestReadinessConfigNamespacePrecedenceAndUnrelatedSettings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte("operator:\n  oci:\n    verify-image: false\n"), 0o600))
	flags := pflag.NewFlagSet("test", pflag.ContinueOnError)
	flags.String("gadget-namespace", "gadget", "")
	require.NoError(t, rejectImplicitTargetConfig(flags, path))
	t.Setenv("INSPEKTOR_GADGET_RUNTIME_GADGET_NAMESPACE", "other-daemon")
	require.ErrorContains(t, rejectImplicitTargetConfig(flags, path), "explicit --gadget-namespace")
	require.NoError(t, flags.Set("gadget-namespace", "daemon"))
	require.NoError(t, rejectImplicitTargetConfig(flags, path))
}

func TestNodeReadinessRejectsTerminatedSelectedNode(t *testing.T) {
	for _, result := range []string{"rpc error: code = Unavailable", "<nil>"} {
		t.Run(result, func(t *testing.T) {
			r := newNodeReadiness([]string{"node-a", "node-b"})
			_, err := fmt.Fprintln(r, `level=debug msg="node-a | running..."`)
			require.NoError(t, err)
			_, err = fmt.Fprint(r, `level=debug msg="node-a | done from ser`)
			require.NoError(t, err)
			_, err = fmt.Fprintf(r, "ver side (%s)\"\n", result)
			require.NoError(t, err)
			_, err = fmt.Fprintln(r, `level=debug msg="node-b | running..."`)
			require.NoError(t, err)
			// A repeated readiness marker must not erase the terminal result.
			_, err = fmt.Fprintln(r, `level=debug msg="node-a | running..."`)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			err = r.wait(ctx, make(chan struct{}), func() error { return nil })
			require.ErrorContains(t, err, "node-a")
			require.ErrorContains(t, err, "done from server side")
			require.ErrorContains(t, err, result)
		})
	}
}

func TestNodeReadinessIgnoresUnselectedTermination(t *testing.T) {
	r := newNodeReadiness([]string{"node-a", "node-b"})
	_, err := fmt.Fprint(r, "level=debug msg=\"node-a | running...\"\nlevel=debug msg=\"other | done from server side (<nil>)\"\nlevel=debug msg=\"node-b | running...\"\n")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	require.NoError(t, r.wait(ctx, make(chan struct{}), func() error { return nil }))
}

func TestNodeReadinessFailsBeforeRemainingNodesStart(t *testing.T) {
	r := newNodeReadiness([]string{"node-a", "node-b"})
	_, err := fmt.Fprint(r, "level=debug msg=\"node-a | running...\"\nlevel=debug msg=\"node-a | done from server side (<nil>)\"\n")
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err = r.wait(ctx, make(chan struct{}), func() error { return nil })
	require.ErrorContains(t, err, "node-a")
	require.ErrorContains(t, err, "node-b")
	require.NotErrorIs(t, err, context.DeadlineExceeded)
}

// Realistic logrus-formatted stderr lines (non-TTY text formatter).
const (
	// Bare marker emitted by the local runtime, and also by the client itself for the gRPC
	// runtime (LoadGadgetInfo with run=true). logrus does not quote the message as it has no
	// spaces (verified against real `ig run -v` output).
	bareMarker = `time="2026-07-08T12:00:00Z" level=debug msg=running...`
	// Node-prefixed markers forwarded from remote nodes by the gRPC runtime
	// (fmt.Sprintf("%-20s | %s", node, "running...")).
	nodeAMarker = `time="2026-07-08T12:00:01Z" level=debug msg="gke-node-a           | running..."`
	nodeBMarker = `time="2026-07-08T12:00:02Z" level=debug msg="gke-node-b           | running..."`
	// Client-side "dispatched to node" lines (one per target, see runGadgetOnTargets). These
	// tell the gate how many node readiness markers to expect.
	dispatchAMarker = `time="2026-07-08T12:00:00Z" level=debug msg="running gadget on node \"gke-node-a\""`
	dispatchBMarker = `time="2026-07-08T12:00:00Z" level=debug msg="running gadget on node \"gke-node-b\""`
)

func TestParseReadyNode(t *testing.T) {
	nA, isNodeA := parseReadyNode(nodeAMarker)
	assert.True(t, isNodeA)
	assert.Equal(t, "gke-node-a", nA)

	nB, isNodeB := parseReadyNode(nodeBMarker)
	assert.True(t, isNodeB)
	assert.Equal(t, "gke-node-b", nB)

	// Distinct nodes yield distinct identifiers; the same line is stable.
	assert.NotEqual(t, nA, nB)
	nA2, _ := parseReadyNode(nodeAMarker)
	assert.Equal(t, nA, nA2)

	// A bare marker is not a node marker.
	_, isNode := parseReadyNode(bareMarker)
	assert.False(t, isNode)
}

func TestReadinessWatcher_LocalMode(t *testing.T) {
	w := newReadinessWatcher()

	// Not ready before any marker.
	assert.False(t, w.ready(false))

	// A dispatch line does not make the local runtime ready.
	w.observe(dispatchAMarker)
	assert.False(t, w.ready(false))

	// A bare marker makes it ready in local (non-node) mode.
	w.observe(bareMarker)
	assert.True(t, w.ready(false))
}

func TestReadinessWatcher_NodeMode(t *testing.T) {
	w := newReadinessWatcher()

	// The client's own bare marker must NOT count towards node readiness, and with no
	// dispatch seen yet the gate is not ready.
	w.observe(bareMarker)
	assert.False(t, w.ready(true))

	// Two nodes are dispatched to.
	w.observe(dispatchAMarker)
	w.observe(dispatchBMarker)
	assert.False(t, w.ready(true))

	// First node ready: still waiting for the second.
	w.observe(nodeAMarker)
	assert.False(t, w.ready(true))

	// Duplicate marker from the same node must not advance readiness.
	w.observe(nodeAMarker)
	assert.False(t, w.ready(true))

	// Second distinct node makes all dispatched nodes ready.
	w.observe(nodeBMarker)
	assert.True(t, w.ready(true))
}

func TestReadinessWatcher_NodeReadyNeedsDispatch(t *testing.T) {
	// A node marker without a preceding dispatch line (which cannot happen in practice, since a
	// node is always dispatched before it reports ready) must not by itself satisfy the gate:
	// readiness requires at least one dispatched node.
	w := newReadinessWatcher()
	w.observe(nodeAMarker)
	assert.False(t, w.ready(true))
}

func TestReadinessWatcher_SomeReady(t *testing.T) {
	// Node mode: only a node marker counts as "some ready", not the client's bare marker or a
	// dispatch line.
	w := newReadinessWatcher()
	assert.False(t, w.someReady(true))
	w.observe(bareMarker)
	w.observe(dispatchAMarker)
	assert.False(t, w.someReady(true))
	w.observe(nodeAMarker)
	assert.True(t, w.someReady(true))

	// Local mode: the bare marker is enough.
	wl := newReadinessWatcher()
	assert.False(t, wl.someReady(false))
	wl.observe(bareMarker)
	assert.True(t, wl.someReady(false))
}

func TestReadinessWatcher_UpdatedSignal(t *testing.T) {
	w := newReadinessWatcher()

	w.observe(nodeAMarker)
	select {
	case <-w.updated:
	default:
		t.Fatal("expected an update signal after a new node marker")
	}

	// A duplicate must not produce a new signal.
	w.observe(nodeAMarker)
	select {
	case <-w.updated:
		t.Fatal("did not expect an update signal for a duplicate marker")
	default:
	}
}

func TestIsDebugLine(t *testing.T) {
	assert.True(t, isDebugLine(bareMarker))
	assert.True(t, isDebugLine(nodeAMarker))
	assert.False(t, isDebugLine(`time="2026-07-08T12:00:00Z" level=warning msg="something"`))
}

// Both a partial-ready timeout and process exit can be selectable at once. The
// timeout must not release the workload after the gadget has been reaped.
func TestDefaultReadinessTimeoutRejectsKnownExit(t *testing.T) {
	watcher := newReadinessWatcher()
	watcher.observe(`level=debug msg="running gadget on node node-a"`)
	watcher.observe(`level=debug msg="running gadget on node node-b"`)
	watcher.observe(nodeAMarker)
	exited := make(chan struct{})
	close(exited)
	for _, exitErr := range []error{nil, errors.New("exited with failure")} {
		for range 100 {
			partial, err := waitForReadiness(watcher, true, 0, exited, func() error { return exitErr })
			require.False(t, partial)
			require.ErrorContains(t, err, "exited before it started capturing")
			if exitErr != nil {
				require.ErrorIs(t, err, exitErr)
			}
		}
	}
}

func TestDefaultReadinessPartialTimeoutKeepsLiveProcess(t *testing.T) {
	watcher := newReadinessWatcher()
	watcher.observe(`level=debug msg="running gadget on node node-a"`)
	watcher.observe(`level=debug msg="running gadget on node node-b"`)
	watcher.observe(nodeAMarker)
	partial, err := waitForReadiness(watcher, true, 0, make(chan struct{}), func() error { return nil })
	require.NoError(t, err)
	require.True(t, partial)
}
