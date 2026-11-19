# enforce_exec kernel validation

Run only on a disposable Linux amd64 or arm64 host with root, cgroup v2, BPF LSM enabled,
kernel BTF, `bpf_path_d_path`, Clang, libbpf headers and bpftool. Kernel version
alone does not establish support. Nothing attaches without `IG_EXEC_KERNEL_TEST=1`.

```sh
case "$(uname -m)" in
  x86_64) bpf_arch=x86; gadget_arch=amd64 ;;
  aarch64|arm64) bpf_arch=arm64; gadget_arch=arm64 ;;
  *) echo "unsupported architecture" >&2; exit 1 ;;
esac
export CC=clang # Go's race detector requires cgo and a host C compiler.
clang -O2 -g -target bpf -D__TARGET_ARCH_${bpf_arch} \
  -Iinclude/gadget/${gadget_arch} -Iinclude \
  -c gadgets/enforce_exec/program.bpf.c -o /tmp/enforce-exec.bpf.o
clang -O2 -g -target bpf -D__TARGET_ARCH_${bpf_arch} \
  -Iinclude/gadget/${gadget_arch} -Iinclude \
  -c gadgets/trace_lsm/program.bpf.c -o /tmp/trace-lsm.bpf.o
IG_EXEC_KERNEL_TEST=1 \
IG_EXEC_BPF_OBJECT=/tmp/enforce-exec.bpf.o \
IG_EXEC_METADATA="$PWD/gadgets/enforce_exec/gadget.yaml" \
IG_EXEC_TRACE_LSM_OBJECT=/tmp/trace-lsm.bpf.o \
  go test -race -v -count=3 -timeout=5m ./gadgets/enforce_exec/test/kernel
```

For `TestExecKernel`, the wrapper source and `include/` must also be available.
Set `IG_EXEC_BPF_SOURCE` and `IG_EXEC_INCLUDE` if running a compiled test binary
outside the source checkout. Tests can be built with `go test -c` and copied to
the VM along with objects, metadata, wrapper and headers. No WASM artifact is used.

## Coverage

- `TestExecKernel`: real path/cgroup decisions, audit/enforce/off, mixed rule modes,
  128 expanded paths (including last-rule allow/deny), scripts,
  reporting saturation, immutable-map write rejection, live membership changes,
  and sampled continuous denial across repeated overlapping replacements.
- `TestExecTraceLSMCoexistence`: both attachment orders with tracing enabled,
  disabled and filtered. The production enforcement object is used.
- `TestExecRuntime`: actual OCI/BPF/native control through the instance manager;
  startup bindings, frozen policy, synchronous bind/unbind, failed-candidate
  retention, explicit overlap (both conflicting policies deny), new revision,
  old cleanup and final release. Container-cache input is synthetic so the test
  isolates lifecycle and map control from discovery installation.

Local race tests cover manager startup/cleanup/cancellation, controller binding
errors and capacity, stale deletions, concurrent churn, compiled map validation,
and cache replay ordering. These replace the removed parameter-handshake and
process/launcher tests.

A runtime or overlap test does not establish first-container-exec protection,
crash persistence or exhaustive scheduling coverage. The maintainer-run validation below covers amd64; the separately reported arm64
results identify their author and environment.

## Validation on 2026-10-22

The complete privileged suite passed three consecutive times with Go's race
detector on Debian 13, amd64, kernel `6.12.111+deb13-amd64`, with BPF LSM enabled.
A separate native CLI check used two real Docker containers: the selected
container was denied, the control container remained unaffected, verdicts carried
revision 71, and stopping IG released enforcement. Production BPF objects also
compiled for amd64 and arm64.

## Docker bootstrap regression

Build the host CLI and local gadget image using the gadget README. On a disposable
BPF LSM host with Docker, Python 3 and access to `alpine:3.21`, run:

```sh
sudo env IG_EXEC_KERNEL_TEST=1 python3 gadgets/enforce_exec/test/kernel/docker-bootstrap.py \
  --ig /tmp/ig-enforce-exec --image enforce_exec:spike --runtime runc
```

The test creates and removes two containers. It checks default-deny in audit and
enforce modes, an allowed command, a copied executable outside allowed folders,
an unaffected control, revision-tagged workload verdicts and release on shutdown.
A workload-owned `/runc` must also remain denied in enforce mode.
Other denied paths are printed separately as possible bootstrap activity, so a
successful runtime fallback does not conceal helper denials. Their identity is
not inferred from the path. An absent workload verdict fails the test even if
Docker failed for another reason. Repeat with each configured Docker runtime
(e.g. `--runtime crun`); this does not validate Kubernetes/CRI exec paths.

## External arm64 validation

[Alon reported](https://github.com/kubescape/inspektor-gadget/pull/15#issuecomment-6399479960)
three complete race-enabled kernel-suite passes at `20cc8d4`, with no skips or
races, on Apple Silicon/Lima, Debian 13, kernel
`6.12.111+deb13-cloud-arm64`, BPF LSM enabled, Docker 26.1.5, containerd 2.4.1
and runc 1.5.2. His two-container CLI check covered allowed system binaries, a
denied copied `/tmp/busybox`, audit verdicts, revision and release on shutdown.
He also observed `/runc` denials while Docker exec succeeded. These are externally
reported results, not runs of the new regression script above.

## Host capability checks

Check `/sys/kernel/security/lsm` for `bpf`, kernel BTF for `bpf_path_d_path`,
cgroup v2 and successful program load/attachment. Neither a distribution name
nor a version number alone proves support. Alon's Ubuntu 24.04 GA kernel
`6.8.0-142-generic` lacked that BTF function and did not enable BPF LSM by default;
he did not attempt loading there. Such a host needs a kernel with the required
capability and boot-time LSM configuration before testing.

The new Docker regression script has passed Python syntax and CLI checks, but
has not yet been executed on a disposable host. The earlier kernel and CLI
results above do not validate this new script.

## Restricted-binding integration

The production OCI image, native controller and actual instance manager are
exercised by `TestExecRestrictedDocker` and `TestExecRestrictedCRI`. Both create
restricted workload and control containers, corroborate init credentials, replay
bindings through a native startup owner, and test:

- Strict runtime-helper denial, followed by its absence after the host-namespace
  exception is enabled. Set `IG_EXEC_EXPECT_RUNC_HELPER=1` when testing runc 1.5.2
  to require reproduction; other runtime versions may not attempt that helper exec.
- Failed owner admission retaining the old instance; strict-to-restricted
  create-before-remove replacement with conflicting rule sets during overlap.
- Workload denial including a workload-owned `/runc`, revision-tagged verdicts,
  caller namespace FDs closed after admission, child namespace enforcement, live
  binding churn and final release.

After building the objects and setting the ordinary kernel variables above, add:

```sh
IG_EXEC_KERNEL_TEST=1 IG_EXEC_DOCKER_TEST=1 IG_EXEC_CRI_TEST=1 \
IG_EXEC_EXPECT_RUNC_HELPER=1 \
IG_EXEC_CRI_ENDPOINT=unix:///run/containerd/containerd.sock \
IG_EXEC_BPF_OBJECT=/tmp/enforce-exec.bpf.o \
IG_EXEC_METADATA="$PWD/gadgets/enforce_exec/gadget.yaml" \
IG_EXEC_TRACE_LSM_OBJECT=/tmp/trace-lsm.bpf.o \
  go test -race -v -count=3 -timeout=8m ./gadgets/enforce_exec/test/kernel
```

Docker needs access to `alpine:3.21`. The CRI case requires crictl (tested v1.32.0),
containerd with its CRI plugin enabled, and access to Alpine and its configured
sandbox image. It uses host networking to avoid a CNI installation; PID/mount
namespaces remain separate. CRI container profiles explicitly use unconfined
seccomp/AppArmor only for this disposable test. The owner controls creation and
all test exec requests; it does not infer the future-entry contract from init.

For the tested containerd 1.7.24 CRI exec path,
[the implementation reuses the configured process specification](https://github.com/containerd/containerd/blob/88bf19b2105c8b17560993bee28a01ddc2f97182/pkg/cri/server/container_execsync.go#L132-L163).
The test also reads `/proc/self/status` through a real CRI exec to corroborate
capabilities and `no_new_privs`. This is not a Kubernetes cluster or node-agent
CRD integration test, and does not establish the contract for arbitrary runtimes.

The new 128-path and mixed-mode cases require a fresh isolated-kernel run; the
historical validation above does not establish these extensions.
