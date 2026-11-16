# AL2023 current-layout route-pin verifier fixture (default off)

This **test-only** standalone fixture includes the actual
`../../full/shared_route.h`, with
`ENFORCE_EXEC_SOURCE_MODE_PIN_CANDIDATE=1`. Its dedicated ARRAY value is the
104-byte, 20-member source-pin route layout, not the older 88-byte layout.
No existing Makefile or product image selects it.

Three separately compiled variants:

* `HOOKS=control` (build default): fentry/fexit `__x64_sys_getpgid`.
* `HOOKS=exec`: fentry `security_bprm_creds_for_exec` and fexit `bprm_execve`.
  Both are non-sleepable `BPF_PROG_TYPE_TRACING`, **not LSM enforcement**.
* `HOOKS=publication`: fentry/fexit `cgroup_kn_lock_live`. Entry requires a
  non-null kernfs node and `drain_offline=true`; exit additionally requires a
  successful cgroup pointer. This is **not** the product publication producer.

Each hook acquires the actual route spinlock, acquires a lexical route claim,
calls the actual source-pin acquire/release helpers synchronously, releases the
claim, and unlocks. Counters are updated after unlock. Synthetic identities and
stack-local owners intentionally exercise helper/verifier feasibility only:
there is **no cross-hook lifetime, physical-source authentication, migration,
publication, terminal recovery, or policy-authority proof**. The exec variant
uses the intended hook names but is not the source capsule implementation.
It never overrides a return value or denies exec. Maps are private, never pinned;
closing the process releases links/maps. Target PID/TID starts at zero (inert).

## Host-only build and review

From repository root, provide the exact target header directory and an external
artifact directory. Clang 19 and libbpf development headers are sufficient:

```sh
D="$HOME/.local/state/sandbox-policy-recovery/g005-route-pin-verifier-20261109"
mkdir -p "$D"
P=gadgets/enforce_exec/test/al2023-route-pin-verifier
for v in 6.12 6.18; do
  for mode in control exec publication; do
    HOOKS="$mode" \
      VMLINUX_DIR="$HOME/.local/state/sandbox-policy-recovery/g020-phase-live-20261109/$v" \
      OUTPUT="$D/$mode-$v.bpf.o" "$P/build.sh"
    ROUTE_PIN_OBJECT="$D/$mode-$v.bpf.o" \
      ROUTE_PIN_KERNEL_BTF="/var/lib/ig15-al2023-kvm-20261109/btf-$v" \
      GOWORK=off go test -tags routepinintegration -count=1 -v "./$P/runner"
  done
done
GOWORK=off go test -count=1 "./$P/runner" # ordinary prototype unit tests
GOWORK=off go vet "./$P/runner"
GOWORK=off go vet -tags routepinintegration "./$P/runner"
GOWORK=off go build -o "$D/route-pin-verifier" "./$P/runner"
"$D/route-pin-verifier" -object "$D/exec-6.12.bpf.o" # inspect only, no BPF syscall
```

Object-dependent tests require the explicit `routepinintegration` build tag.
That dedicated lane fails if `ROUTE_PIN_OBJECT` is absent; it never silently
skips. Publication objects also require `ROUTE_PIN_KERNEL_BTF` to inspect the
actual target hook prototype. Ordinary tests remain independent of external
build artifacts.

No object path defaults; no live execution without `-run-isolated`. Inspection
fails closed on old/missing/mismatched layout, unexpected maps, pinning, flags,
program type, or target. Negative unit controls exercise these cases and bad
prototype shape. Compilation without the source-pin macro must fail. Object
BTF assertions cover every member name, offset, size and lock type. Live
preflight additionally requires exact amd64 kernel release and kernel BTF hash,
and the actual kernel hook prototype (`int(struct linux_binprm *)` for exec).
Unknown kernels/prototypes are rejected rather than guessed.

The publication prototype must be
`struct cgroup *(struct kernfs_node *, bool)` with a one-byte BTF BOOL. The
runner creates a fresh empty child under the guest's `/sys/fs/cgroup` only
after exact-kernel preflight and explicit live opt-in. It checks cgroup-v2,
opens that child's `cgroup.subtree_control` without truncation, writes exactly
one newline on the targeted OS thread, and requires the full one-byte write,
exactly one successful pair of hooks, unchanged empty controller mask, and
empty `cgroup.procs`/`cgroup.threads`. It never moves a task, enables a
controller, or uses `cgroup.kill`. Close/removal errors fail the run; it will
not kill an unexpected occupant to force cleanup.

This trigger follows the exact vendor source archives preserved at
`g005-capsule-source-research-20261109/{6.12,6.18}/srpm/`: base
`kernel/cgroup/cgroup.c` lines 3449–3542 (6.12.113) and 3544–3637 (6.18.56).
Whitespace produces zero enable/disable masks, calls
`cgroup_kn_lock_live(of->kn, true)` once, and exits before mask mutation.
The two 6.12 vendor patches touching this file affect pressure/file-release
paths, not this handler; no 6.18 patch touches it. The true-drain hook can
drain offlining CSSes, so this is not described as globally side-effect-free.
A fresh empty child bounds the test, and any unexpected result fails.

## Deferred isolated kernel test (independent review required first)

This fixture has **not** been loaded or attached as part of host validation.
On an independently reviewed disposable exact-kernel VM only:

```sh
sudo ./route-pin-verifier -object ./exec-6.12.bpf.o -run-isolated
# Separate publication-hook feasibility gate, not implied by the exec result:
sudo ./route-pin-verifier -object ./publication-6.12.bpf.o -run-isolated
```

The exec trigger creates an invalid-format temporary executable (0700), calls
`execve` directly with no shell fallback, and requires `ENOEXEC`. It must run on
an exec-enabled temporary filesystem; `noexec`/LSM denials or missing hooks fail,
not count as proof. The control calls `getpgid(0)` once. Only the runner's locked
OS thread is selected while triggering. Both variants require exactly one
acquire/release pair per hook, zero failures, next pin sequence 2, and zero
remaining source pins/early claims/unresolved sources. A mismatch is failure;
there is no retry or suppression. All live outcomes remain unproved until run.
Publication load/attach/trigger remains unproved until separately reviewed and
executed. Its synthetic lock operations do not establish product publication
atomicity, administrative authorization, withdrawal, or source ownership.

The prior fexit completion evidence used an **88-byte default-off route**; its
success must not be relabeled as proof for these new fields/helpers. Likewise,
a successful getpgid control does not replace actual exec-hook validation.
