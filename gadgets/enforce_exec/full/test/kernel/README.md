# Experimental full exec image fixture

Run **only in a disposable BPF-LSM-enabled VM**. This test attaches the actual
sleepable image program, but binds only a newly created cgroup. It does not prove
native OCI lifecycle integration, persistent role state, image origin, filesystem
classification, or arbitrary shared descriptor-table stdin classification.

```
IG_FULL_EXEC_KERNEL_TEST=1 \
IG_FULL_EXEC_BPF_SOURCE=/source/full/program.bpf.c \
IG_FULL_POLICY_INCLUDE=/source/fullpolicy/bpf \
IG_EXEC_INCLUDE=/source/include \
./sandbox-full-exec-kernel.test -test.run '^TestFullExecKernel$' -test.v -test.timeout=5m
```

Requires clang, bpftool, libbpf headers, cgroup v2 and a kernel exposing the
sleepable `bpf_copy_from_user_mm_str` kfunc plus task/file/path kfuncs. An older
kernel is an unsupported candidate, not grounds for falling back to syscall
argument snapshots or path-only enforcement. The fixture prints full verifier
logs on rejection.

Assertions include predicate positive and negative controls, audit nonblocking,
multiple-policy default deny-wins, unbound controls, immutable-map rejection,
and per-exec scratch cleanup. A deny caused by an observation/evaluator fault is
**not** counted as predicate success: the sticky fault map must remain zero.
The current artifact advertises only the subset proved by the attached-image tests.

## Restricted stdin capability

The integrated reader classifies post-exec FD0 only on x86 when the current task
is the sole owner of its descriptor table. Anonymous pipes and named FIFOs are
pipes; a CLOEXEC FD0 does not survive exec and is classified as not a pipe.
Shared tables, unsupported architectures, and failed reads are unknown, not
false. If another condition is known false, the rule cannot match, even with
an unknown stdin observation. If no condition is known false and the rule
still needs the observation, Strict fails closed, sets the sticky full fault
map and causes native readiness to become NotReady while retaining installed
enforcement. This can disrupt helpers using shared descriptor tables.

The combined fixture includes pipe, regular-file and negated-pipe controls.
CLOEXEC, named FIFO and shared-table/race cases are separately exercised by the
standalone stdin kernel proof; that proof does not replace combined-image proof.
The runtime requires the explicit `stdin` image feature before admitting stdin
predicates. The current artifact advertises `path,uid,argv,actor-path,ancestor,stdin,image`; roles and filesystem
classification remain unsupported. Image predicates require the trusted-owner
attestation described below; capability alone cannot make an incomplete owner Ready.

## Native OCI ownership proof

`TestFullExecRuntime` consumes explicit local artifact bytes, packages them into
an in-memory OCI store, and uses the real local runtime, OCI handler and instance
manager. Set `IG_FULL_EXEC_BPF_OBJECT` to the compiled full image object and
`IG_FULL_EXEC_METADATA` to its `gadget.yaml`, alongside the disposable-kernel
opt-in, then select `-test.run '^TestFullExecRuntime$'`.

This isolated fixture disables registry signature lookup only for its explicitly
supplied trusted local artifact store. Production arbitrary-image signature
verification is unchanged. Assertions cover readiness, immutable maps, failed
candidate retention, replacement, withdrawal/rebind and operational fault
NotReady with protection retained. This is not proof of persistent role state or
of the node-agent controller's complete replacement orchestration.

## Trusted image-origin input

`runtime.Config.ImageOrigins` is a trusted-owner attestation, never policy input.
It must enumerate **all regular files** in validated immutable lower roots, with
complete root/mount identity validation, no mutable lowers, redirects, data-only
layers, nested overlays or unsupported mount matrix. IG validates structural
bounds and freezes both index and readiness maps before binding; IG does not
establish the owner's root/index guarantees. Complete empty indexes are valid;
missing or incomplete indexes cannot admit `fromImage` policies. Backing changes
or missing observations remain unknown, not false.

Combined image predicate cases use controlled synthetic backing-inode membership
to test reader/evaluator plumbing; they do not prove the trusted owner's complete
lower-root construction. Separate overlay/metacopy/copy-up proofs complement but
do not replace end-to-end owner validation. The image capability is supported only with the explicit owner attestation;
node-agent lower-root discovery and validation are not implemented by this slice.

`TestFullExecRuntimeImage` additionally injects `image` into only the trusted test
metadata, supplies controlled backing identities, and verifies missing/incomplete
index rollback plus frozen origin/readiness maps through the native owner. Use
the same artifact environment as `TestFullExecRuntime`. Its synthetic membership
still does not establish production immutable-lower/root validation.

## Recorded isolated proof (2026-10-26)

Kernel: `7.3.0-sandbox-exec+`, x86_64. Combined attached-image tests passed all
23 cases. `TestFullExecRuntimeImage` passed in 2.23s, including missing/incomplete
index rollback, frozen maps, replacement, withdrawal and fault readiness.
Independent overlay proof covered metacopy on/off and controlled copy-up races.
These are bounded kernel/matrix proofs, not arbitrary-kernel support or completed
node-agent owner integration. Logs/artifacts were retained under
`/tmp/sandbox-policy-cloud` by the isolated VM proof owner.

SHA-256 evidence identifiers:

| Artifact | SHA-256 |
| --- | --- |
| `full-nativeimage-fixture/source.tgz` (also combined source) | `28d1575bc2bb7f6d6fc4a6334cb8ba96dc99b2220e06a1033ec1880eb8e2f589` |
| `full-nativeimage-fixture/sandbox-full-exec-kernel.test` | `9c1ae73bbbf9c17b2a3bfe1ebd66864116f52cdd06cee6aad9dd9f6e5af3e744` |
| `full-imagecombined-fixture/sandbox-full-exec-kernel.test` | `d1fc495e3765a52bd2e807963c922ab34a061dd7f83d30ac9f2030ed4f90d966` |
| `full-nativeimage-custom.log` | `065b3969d564e345458ebd40da1f4b056db3e175a768127dbf519617ba2499d9` |
| `full-imagecombined-custom.log` | `6864d8e4a16513320a897585c73d78c5c963d6dbda597f1f2af14c67469b49ae` |
| `image-custom-metacopy.log` | `2f49c2d89961c2f17db8999a736ff9ee8a820972cb1db2103413cd18c58d9a69` |
