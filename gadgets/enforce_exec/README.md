# enforce_exec

This page describes the **simple path-only engine**. The separate experimental
[full engine and legacy per-binding `Owner`](fullruntime/README.md) add richer
predicates and role history, with different admission, reload and failure
behavior. The simple engine's kernel baseline and `BindRestricted` support do
**not** establish full-engine support: the legacy owner currently admits only two
exact custom amd64 kernel artifacts, not stock kernels or arm64. Its isolated
proofs do not qualify the unfinished [shared-node replacement](fullruntime/README.md#shared-node-implementation-status-and-api-contracts),
whose `NodeEnforcer.Ready` never reports Ready.

The shared-node Go compiler/worker accounting and source-checking tools are
implemented only within the [conditional worker qualification scope](fullruntime/README.md#conditional-shared-worker-qualification).
They do not produce complete worker evidence or qualify native activation; the
legacy proofs and simple-engine behavior below do not fill those gaps.

Container execution enforcement using BPF LSM. The gadget image contains a fixed
BPF program; a native Go controller supplies compiled rules and manages container
membership. No WASM, policy parameter updates, request IDs or acknowledgement
protocol are involved. Process enforcement is deferred.

## Architecture

```text
CLI policy / node-agent CRD adapter
  -> shared Go compiler
  -> immutable policy map, populated and frozen before binding
  -> native container binding controller
  -> BPF LSM decisions and bounded verdict reporting
```

Each instance has two ordinary maps:

- `policy`: 129 array entries (one revision/header and 128 expanded path rules).
  Native code fills it once and freezes it. `BPF_F_RDONLY_PROG` also prevents BPF
  writes. Rules never change while this instance runs.
- `bindings`: up to 1,024 cgroup-v2 identities. Adding/removing a container is a
  synchronous map operation serialized by the native controller. A zero value
  selects strict cgroup scope; an owner-admitted restricted binding instead stores
  the pinned host mount namespace inode. Membership can change without restarting
  or changing policy.

Rule changes create a new instance. Both programs enforce during replacement;
there is no map-of-maps publication protocol or writable standby rule map.

## Try it

Requires root, cgroup v2, kernel BTF, BPF LSM enabled and `bpf_path_d_path`.
Linux 6.12 is the tested baseline; successful loading/attachment is the capability
check. Use a host binary built from this branch:

```sh
go build -o /tmp/ig-enforce-exec ./cmd/ig
sudo /tmp/ig-enforce-exec image build --local -t enforce_exec:spike gadgets/enforce_exec
```

Edit `examples/enforce.yaml` with the actual runtime and full container ID, then:

```sh
sudo /tmp/ig-enforce-exec enforce-exec enforce_exec:spike \
  --allow-enforcement --verify-image=false \
  --policy gadgets/enforce_exec/examples/enforce.yaml --revision 1
```

`--verify-image=false` is for unsigned local development. Keep verification and
approved signed images in production. Host behavior consent and BPF admission
restrictions still apply. Verdicts are printed as JSON; stderr reports native
startup readiness and the number of currently bound containers.

`--allow-enforcement` grants **host-operator consent**, defaulting to false. The
embedding equivalent is the global `operator.oci.allow-enforcement` setting.
An image declares its behavior; that declaration cannot grant consent or override
the host setting. Consent is separate from image signature verification and does
not prove that a policy or runtime binding is safe.

This command uses the existing IG container cache and discovery settings, such as
`--runtimes docker`. No Kubescape component is required. Generic `ig run` cannot
supply the typed native policy; use this command or the embedded interface below.

## Policy

```yaml
version: 1
binding:
  containers:
    - runtime: containerd
      id: full-container-id
policy:
  mode: enforce
  exec:
    default: deny
    rules:
      - name: approved-executables
        target:
          path: ["/usr/bin/**", "/opt/app/bin/**"]
        action: allow
      - name: deny-default-shell
        target:
          path: ["/usr/bin/dash"]
        action: deny
```

The singular `binding.container` spelling also works. Use exactly one spelling.
`binding.process` is unsupported. This file is CLI/compiler input, not a gadget
parameter or a file watched by a daemon.

Rules support exact clean absolute paths or trailing `/**` directory patterns,
allow/deny default, and audit/enforce/off mode. Denies override matching allows.
Rule modes may inherit the policy mode or override it with audit/enforce. A matching
enforced deny wins over audited denies and allows, independent of rule order.
Defaults apply only when no rule matches; off policies cannot contain overrides.
Unsupported predicates, duplicate selectors, oversized input or excess rules fail before loading.

Paths refer to resolved executable destinations. Check `readlink -f /usr/bin/sh`
inside the target container before adapting the shell example. Renaming an
executable can change its path permission. Scripts and interpreters are checked
separately; allowing an interpreter does not constrain the code it interprets.
Resolution failures deny if the policy or any rule is enforce; audit-only
policies permit. Off permits without ordinary verdict reporting.

Rebuild the gadget image and native owner together: the expanded policy map has
129 entries. The owner rejects older nine-entry images rather than truncating
the new policy. Individual entries retain the 288-byte layout.

## Runtime bootstrap compatibility

Binding selects a cgroup, including runtime helpers temporarily executing there.
A default-deny policy can therefore deny a runtime helper before the requested
workload starts, potentially breaking `docker exec` or `kubectl exec`. Successful
commands do not prove that no helper was denied.

[Alon's arm64 test](https://github.com/kubescape/inspektor-gadget/pull/15#issuecomment-6399479960)
observed `/runc` denials followed by successful workload execution. In
[runc v1.5.2](https://github.com/opencontainers/runc/blob/v1.5.2/libcontainer/process_linux.go),
`startWithCgroupFD` retries a failed start without `CLONE_INTO_CGROUP`, and
`setnsProcess.start` subsequently adds the process to the cgroup. This supports
the fallback explanation; the verdict alone does not establish the exact
sequence. Other runtimes/versions may behave differently.

Strict bindings have no helper exemption. Neither the gadget nor node-agent should
blindly allow `/runc`: a path does not authenticate a host runtime binary. See
[the bootstrap investigation](test/kernel/runtime-bootstrap.md) for the safe
identification requirements and remaining work. Validate your runtime using the
[Docker regression](test/kernel/README.md#docker-bootstrap-regression) before
using default-deny. The native opt-in interface below resolves the observed helper denial for an
explicitly restricted workload scope. It is not a general runtime-helper
identity mechanism.

## Embedded owner

The compiler and native controller are ordinary IG Go packages:

```go
entries, err := execpolicy.CompileKernel(document, revision)
// Check err before constructing an instance.
config := execruntime.Config{
    Entries: entries,
    Targets: document.Binding.Targets(),
}
err = manager.StartGadget(ctx, instance,
    execruntime.WithConfig(config),
)
```

Import `gadgets/enforce_exec/runtime` and include its registered native operator
alongside the existing OCI and container-cache operators. The owner controls
`instance.Id` and supplies a nonzero revision. All required operators must start
successfully before `StartGadget` returns. Initial discovery and binding errors
fail startup instead of being accepted as readiness.

`GetBindings(gadgetContext)` returns the per-instance controller. Its
`Bind(ContainerIdentity)` and `Unbind(ContainerIdentity)` methods return the map
operation result synchronously; `Status()` returns revision, bound count,
readiness, restricted-binding count and the latest binding error. Startup errors remain sticky until the
final readiness check, even if another binding operation succeeds. Identities include runtime, full ID,
nonzero cgroup ID and clean non-root cgroup-v2 path. Stale deletions cannot remove
a newer identity. Map handles remain private and writes are rejected after stop.

Choose one input owner. CLI discovery uses `Targets` with the IG container cache.
An embedded cache owner can use empty `Targets`, `InitialBindings`, and direct
`Bind`/`Unbind`. For a cache outside IG, provide a native startup operator after
the binding controller (priority 1): subscribe before taking the snapshot, replay
it and drain queued lifecycle changes through `Bind` before returning from
`Start`, and unsubscribe on stop. Manager readiness follows **all** operator
startup, so this adapter participates in the replacement barrier. An initial
snapshot alone is insufficient while the cache changes concurrently.

The Kubescape SandboxPolicy CRD adapter belongs in node-agent. It owns CRD
watching, translation, policy merging and controller status. IG stays independent
of that CRD and Kubescape packages. This PR adds no ConfigMap/file policy watcher
or public policy RPC. Existing upstream stores retain their normal operation.

## Opt-in restricted bindings

`Bind` and `ig enforce-exec` keep strict cgroup scope. An embedded trusted owner
can opt a binding into the host mount namespace exception with `BindRestricted`:

```go
err := bindings.BindRestricted(identity, execruntime.RestrictedWorkload{
    HostMountNamespace: hostMountNS, // actual node namespace, authenticated by owner
    MountNamespace:     workloadMountNS,
    UserNamespace:      workloadUserNS,
    Credentials: execruntime.WorkloadCredentials{
        NoNewPrivileges: true,
        Effective: effectiveMask, Permitted: permittedMask,
        Inheritable: inheritableMask, Ambient: ambientMask, Bounding: boundingMask,
    },
    OwnerContract: execruntime.RestrictedWorkloadContract{
        AllWorkloadEntriesRestricted: true,
        NoHostDelegation:             true,
    },
})
```

These contract fields are **trusted-owner commitments**, not facts IG can infer
from an init snapshot. Only set them when the owner controls subsequent workload
exec privileges and excludes host process/service delegation. In particular,
`docker exec --privileged` violates the contract. The credential masks describe
final workload privileges; the API rejects privileged workloads, missing
`no_new_privs`, and `SYS_ADMIN` or `SYS_PTRACE` in any capability set.

Pass open namespace files, not inode numbers or arbitrary paths. The API validates
namespace types using namespace ioctls, requires a distinct workload mount
namespace, and checks that the workload user namespace and both mount namespace
owners are the same supported host user namespace. Rootless/remapped initial
layouts are rejected. The owner must authenticate the actual host and associate
the supplied workload namespaces with the exact container; IG cannot authenticate
that association from a cgroup ID or caller-supplied descriptors alone.

The controller duplicates and retains both mount namespace references. The caller
may close its originals after the call. References are released after successful
map deletion; a failed deletion retains them until the framework's post-stop phase
after BPF detachment. Each restricted binding uses two owned namespace FDs, in
addition to ordinary map resources. Image metadata must advertise
`annotations.enforce-exec-host-namespace`; older images reject the request.

The BPF exception applies **only** when the executing task is in the recorded host
mount namespace. Tasks in the workload namespace or a newly created namespace
remain subject to the policy. Existing LSM denials are preserved. Exempted helper
execs do not produce ordinary policy verdicts. This is a scope boundary, not
proof that an executable is a trusted runtime binary.

Use a native startup operator after the binding controller to replay owner-admitted
bindings before readiness. Leave `Config.Targets` empty when the owner supplies
restricted bindings; built-in discovery performs strict `Bind` calls. Strict and
restricted scopes cannot silently replace one another: an incompatible live bind
returns an error and preserves the existing binding. Prefer instance replacement
for a gapless scope change. Explicit unbind/rebind intentionally has a gap.

`Status().RestrictedBindings` exposes the current count. Rejected eligibility
returns `ErrRestrictedWorkload` and never removes an existing strict binding.
The [admission contract](test/mntns-spike/admission-contract.md) and
[integration evidence](test/kernel/README.md#restricted-binding-integration)
describe the supported prototype boundary. No CLI flag asserts this contract on
the user's behalf, and there is no Kubescape dependency. The node-agent adapter
must supply its own verified runtime facts and entry guarantees.

## Rule replacement

```go
err := manager.ReplaceGadget(ctx, oldInstanceID, candidate,
    execruntime.WithConfig(newConfig),
)
```

The candidate must have a distinct instance ID and a new revision:

1. Start it while retaining the old instance.
2. Load/attach BPF, freeze its rules, replay current bindings and apply concurrent
   container changes. A failed binding fails preparation.
3. Wait for every startup operator to succeed.
4. Stop the old instance and wait for its cleanup.

Startup failure discards the candidate and retains the old instance. Once the
candidate starts, it is committed: cancellation while waiting for old cleanup
leaves the candidate active; the returned error identifies it, and `StopGadget`
can finish waiting for the old ID. Manager lifecycle operations are serialized.

For a target covered by both enforcing instances, overlap allows an exec only
when both policies allow it. Temporary overblocking is deliberate. This is a
handoff guarantee for established bindings, not an atomic node-wide policy
transition or a guarantee about a container's first exec before discovery.

The verdict `generation` field carries the immutable revision; correlate it with
the instance ID.
Reporting can drop and an earlier LSM denial can skip later programs, so events
are not readiness acknowledgements. Native startup/binding results are authority.

## Limits and lifecycle

128 expanded paths, 255 path bytes, 1,024 live bindings and 64 KiB authoring input
bound this prototype. The 129 policy values total 37,152 bytes per instance, even with fewer configured
rules, plus map overhead. Replacement overlap holds 74,304 bytes of policy values
alone, plus both instances' other resources. Each
instance has a 4 KiB reporting ring and a per-CPU limit of 100 report attempts per
second; saturation loses reports while enforcement continues. Overlap temporarily
loads both instances and their resources. These are explicit map/rule limits,
not a total memory budget.

Every BPF trampoline accepts at most 38 links on both exact AL2023 kernels,
shared by fentry, fexit and LSM programs and by every BPF consumer on the node
(one stock link already sits on `file_open`). Enforcement families attach
all-or-nothing, may use at most 8 links per hook (the exec family needs at
most 3) and leave 8 free for third parties. On exhaustion the whole family
refuses with an error naming the hook, stays NotReady and retries
automatically (by default) once capacity frees. The legacy per-cgroup owner
does not retry, refuses at once and is capped at 2 per node. There is no support claim for owner
concurrency. See [attach capacity](fullruntime/README.md#attach-capacity-readiness-and-the-owner-cap-g009).

No programs or maps are pinned. Stopping or killing the owning IG/node-agent
releases enforcement; workloads continue. Removing a binding intentionally
removes protection for that cgroup. Container scope is exact, excluding descendant
cgroups. Enrichment/discovery is not a pre-exec admission mechanism.

See [privileged validation](test/kernel/README.md) for reproducible tests and
coverage limits. Broader kernel/architecture validation, executable integrity,
execveat/memfd/deleted-file coverage, crash persistence and production CRD
integration remain outside this prototype.
