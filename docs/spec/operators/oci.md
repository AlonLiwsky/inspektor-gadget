---
title: oci
sidebar_position: 0
---

The OCI operator handles Gadgets images. It pulls images from the OCI registries
and invokes the different layer operators according to the
[layers](../oci.md#image-layers-and-media-types) present on the image.

## Priority

-1000

## Global Parameters

### `authfile`

Path of the authentication file. This overrides the `REGISTRY_AUTH_FILE`
environment variable. If the default file doesn't exist,
`$HOME/.docker/config.json` is used as a fallback.

Default: `/var/lib/ig/config.json`

### `pull-secret`

[Kubernetes Secret](https://kubernetes.io/docs/concepts/configuration/secret/)
to use when pulling the gadget image. The Kubernetes namespace for the Secret
is not configurable and is hardcoded to "gadget".

Fully qualified name: `operator.oci.pull-secret`

### `verify-image`

Verify image using the provided public key. Check [Verify image-based
gadgets](../../reference/verify-gadgets.mdx) to learn more.

Default: `true`

### `allow-enforcement`

Allow administrator-approved gadgets declaring `generator` or `mutator` behavior.
The host checks the declaration before instantiating any image operator. The
supported top-level `behavior` values in gadget metadata are:

- `observer`: observes activity.
- `generator`: generates activity.
- `mutator`: changes or blocks activity, including execution enforcement.

Declared generators and mutators require explicit host opt-in. Observers and
legacy gadgets without a declaration keep working with the default setting.
Unknown or malformed declarations are rejected.

Default: `false`

Fully qualified name: `operator.oci.allow-enforcement`

For a local run, use the generated CLI flag `ig run --allow-enforcement=true`.
For a daemon, set the host configuration or start it with
`ig daemon --allow-enforcement=true`. A client request cannot override a daemon's
setting. The Helm value is `config.operator.oci.allow-enforcement`:

```yaml
config:
  operator:
    oci:
      allow-enforcement: true
```

Behavior declarations express the intent of trusted, administrator-approved
code; they are not a sandbox that prevents an incorrectly declared gadget from
changing the system. Continue using image signature verification and a digest
allow list to select approved gadgets. See `verify-image` and `allowed-gadgets`.

### `public-keys`

Public keys used to verify the gadgets. Check [Verify image-based
gadgets](../../reference/verify-gadgets.mdx) to learn more.

Default: [Inspektor Gadget public
key](https://github.com/inspektor-gadget/inspektor-gadget/blob/%IG_BRANCH%/pkg/resources/inspektor-gadget.pub).

### `allowed-gadgets`

List of allowed gadgets. If a gadget is not part of it, execution will be
denied. By default, all digests are allowed. Check [Restricting
Gadgets](../../reference/restricting-gadgets.mdx) to get more details.

### `insecure-registries`

List of registries to access over plain HTTP. Check [Insecure
Registries](../../reference/insecure-registries.mdx) to learn more.

### `disallow-pulling`

Disallow pulling gadgets from registries. Check [Disallow pulling
Gadgets](../../reference/disallow-pulling.mdx) to learn more.

Default: `false`

## Instance Parameters

### `validate-metadata`

Validate the gadget metadata before running the gadget

Fully qualified name: `operator.oci.validate-metadata`

Default: `true`

### `pull`

Specify when the gadget image should be pulled
Possible Values:

- `always`: Always pull the gadget image.
- `missing`: Pull the gadget image only if missing.
- `never`: Never pull the gadget image.

Fully qualified name: `operator.oci.pull`

Default: `missing`

### `annotate`

Add annotations to datasources or fields. Use a comma-separated list in the formats:

- `datasource:annotation=value` to add an annotation to a datasource
- `datasource.field:annotation=value` to add an annotation to the field of a datasource

Fully qualified name: `operator.oci.annotate`

### Host BPF admission policy

`allow-enforcement` permits declared generator/mutator gadgets. Administrators can
add independent restrictions through `operator.ebpf.policy` in the **host process
configuration**. Image metadata, annotations and remote instance parameters cannot
replace this policy. Each instance snapshots the policy before analysis and checks
it again immediately before kernel loading.

This uses the program-type and helper policy from upstream
[PR #5796](https://github.com/inspektor-gadget/inspektor-gadget/pull/5796), with an
additional `kfuncs` category. Each category supports `add` and `drop` string lists:

- An absent category or empty lists is unrestricted, preserving legacy gadgets.
- Named `add` entries form an allowlist; other entries are denied.
- Named `drop` entries deny those entries; drop wins an overlap.
- `drop: [all]` denies everything, except named `add` entries.
- `add: [all]` permits everything except named exclusions. Combining it with
  `drop: [all]` is invalid.
- `readonly` is an optional `add` preset for helpers and program types. It is not
  supported for kfuncs. Helper readonly also rejects all kfunc calls.

For example, this configuration permits declared enforcement and limits BPF
programs to LSM and tracing programs, and kfunc calls to the path resolver. Helpers
remain unrestricted in this example; administrators can additionally enumerate the
helpers needed by their approved gadget images.

```yaml
operator:
  oci:
    allow-enforcement: true
  ebpf:
    policy:
      programTypes:
        add: [lsm, tracing]
      kfuncs:
        add: [bpf_path_d_path]
```

Supply this file with `ig --config=host-policy.yaml` or
`kubectl gadget deploy --daemon-config=host-policy.yaml`. With Helm, place the
same `operator` mapping beneath `config`. The daemon policy applies to every
image it runs, including observers and legacy images; allow the union required by
all approved images. Restart the daemon to apply an edited host policy file. Each instance snapshots
the loaded host configuration; the checks do not revoke already attached programs.

Program and helper names are case-insensitive; helpers use `bpf_` names.
Kfunc names are case-sensitive ELF symbols. An unnamed kfunc is rejected whenever
kfunc restrictions are configured. A misspelled kfunc allowlist entry grants
nothing; kernel/module availability is checked by the BPF loader. Empty lists
**do not deny all**: use `drop: [all]` for that purpose.

The checks include linked BPF functions and callbacks. BPF-to-BPF calls are not
classified as builtin helpers. Helper checks also account for the loader's legacy
probe-read substitutions. This controls loaded instructions, not every possible
side effect: external tail-call targets, runtime-supplied programs, shared map
contents and BPF attachment behavior require separate trust. The `readonly` preset
is a bounded observability selection, not a sandbox; it still permits map writes,
sensitive reads and resource use. Trusted, administrator-approved gadget code
remains the trust model.

### Native enforcement control

`enforce_exec` uses native, host-owned compiled map data and immutable rules per
instance. `ig enforce-exec` provides the standalone CLI; an embedded owner can
use the shared compiler, native binding controller and instance manager. Rule
changes use create-before-remove replacement with startup and cleanup waits.
There is no policy parameter update protocol, ConfigMap/file update reconciler,
public policy RPC or process binding in this implementation. Ordinary upstream
stores retain their existing behavior. See the [gadget guide](../../../gadgets/enforce_exec/README.md)
for the control interface and replacement contract.
