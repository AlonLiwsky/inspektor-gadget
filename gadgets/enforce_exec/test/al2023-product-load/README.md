# AL2023 product object-load run (G035)

Loads the 4 shared product objects (`g19pkg{64,128,256,512}.bpf.o`; stage 1:
one CO-RE object per profile for every kernel) on the two pinned AL2023
kernels and runs the product node tests there, then judges the result. The pass rule is strict: every expected row has exactly
one PASS, and a skip, a missing row, a duplicate, an unexpected test, or an
infrastructure error turns the run red.

**Lanes (D2, decided):** the EC2 lane is the gate of record (pinned AMIs on
Nitro: kernel and AMI parity); the QEMU lane is a pre-check on PRs (kernel
parity only: the same vmlinuz, BTF and build-id on KVM). **QEMU evidence
does not satisfy the EC2/AMI acceptance** of the plan (steps 2 and 4); only
an EC2 run on the pinned AMIs does.

| File | Role |
|---|---|
| `env.sh` | Pins (release, BTF, build-id, symbols, vmlinuz, kernel RPM, AMIs) and the open decisions |
| `expected.tsv` | The rows of a full run (`kernel step test profile`), rebuilt from the test sources |
| `judge/` | `judge check` (the verdict), `judge row`/`judge end` (harness checks as test2json) |
| `host.sh` | `build`, `run <lane> <tag>`, `judge`, `all` |
| `guest.sh` | Runs as root on the machine: identity, raw load, Ready per profile, restart child, negatives, hygiene |
| `lanes/qemu.sh` | Lane C: local or CI KVM. Implemented |
| `lanes/ec2.sh` | Lane A: ephemeral EC2. Refuses until the AWS setup exists (plan step 3) |
| `qemu/vm-run.sh`, `qemu/uk-driver.sh` | KVM runner, copied from the universal-kernel harness (KVM only, never TCG) |
| `qemu/build-image.sh` | Base AL2023 KVM qcow2 (by sha256) and the derived images with the pinned kernel RPM (by sha256) |
| `../../fullruntime/shared_product_layout_build_test.go` | The tag-only OCI layout builder (`-tags enforce_exec_shared_qualification`) |

## Run

```sh
export AL2023_PROFILES="64 128 256 512"   # PENDING D4: or "128"
export AL2023_NEG_SET=seam                # PENDING D5 (stage 1: other-kernel is no longer a negative)
export G035_QEMU_IMAGE_DIR=/path/images G035_QEMU_STATE=/path/state
make enforce-exec-al2023-product-load ENFORCE_EXEC_AL2023_RUN=/path/run-1
# or step by step:
host.sh build /path/run-1
host.sh run /path/run-1 qemu 6.12     # and 6.18, unpinned
AL2023_PARTIAL=1 AL2023_JUDGE_KERNELS=build,6.12 host.sh judge /path/run-1
```

A full run judges every group (`build,6.12,6.18,unpinned`) and all four
profiles, and must hold exactly 153 rows (`host.sh` passes `-rows 153`).
Anything narrower (`AL2023_JUDGE_KERNELS`, a profile subset, or tags given
to `all`) is refused unless `AL2023_PARTIAL=1`, and the verdict line and
`results.tsv` header name the judged kernels and profiles. `all` stops after a
failed build. `AL2023_BURNIN=skip-kill|plant-warning|plant-se-pin` exists
only for fail-closed burn-ins: it adds an unexpected stream, so such a run is
always red.

The tagged package build (`go test -tags enforce_exec_shared_qualification
./gadgets/enforce_exec/fullruntime`) fails by design without
`IG_ENFORCE_EXEC_PRODUCT_OBJECTS` and `IG_SHARED_PRODUCT_LAYOUT_OUT`: the
layout builder never skips. Run other tagged tests with `-run`.

`build` needs Docker (the pinned trixie container of `build-product.sh`) and
Go. The QEMU lane needs a read-write `/dev/kvm`, `qemu-system-x86_64` and
`genisoimage`, and `G035_QEMU_IMAGE_DIR` holding `al2023.qcow2`,
`derived/al2023-k612.qcow2` and `derived/al2023-k618.qcow2`
(`qemu/build-image.sh base|6.12|6.18`). A run directory is never reused:
evidence is never overwritten.

## What a run checks

- **build** (no special kernel): `build-product.sh --check` (8 pin rows), the
  layout builder (built twice in-process, then a second process must produce
  an identical layout), and the three userspace object tests with
  `IG_ENFORCE_EXEC_PRODUCT_OBJECTS`.
- **6.12, 6.18** (root, exact pinned build): the bundle manifest and the
  identity rows (`uname -r`, BTF sha256, build-id from `/sys/kernel/notes`,
  `bpf` LSM, `ftrace_enabled`, no livepatch taint (stage 1: no kallsyms
  failure-frame symbol is needed), and the platform: the vmlinuz sha256 on
  QEMU, `/etc/image-id` on EC2). An
  identity failure stops the kernel's run.
  Then `verdict-load` on all 4 objects, and for each profile in
  `AL2023_PROFILES`:
  - `TestSharedProductNodeReadyAttached` with two fresh cgroups; it never
    toggles ftrace and its node must stop clean;
  - the restart child under `unshare -m`: READY; a positive control that
    the leftover probe sees its programs and new links while it lives;
    SIGKILL; no program left; then a child that reaches READY and exits;
  - `TestSharedProductNodeNegativesAttached` (`AL2023_NEG_SET=seam`): the
    product StartNode refuses the qualification seam before any host run.
    Stage 1 images of both kernels carry the same qualified object, so the
    other kernel's image is no longer a negative; the per-object refusals
    are unit tests.

  Then, once per kernel on profile 128 and on its own node,
  `TestSharedProductNodeFtraceNegativeAttached`: Ready goes NotReady naming
  ftrace while `kernel.ftrace_enabled=0`, Strict 126 is back after restore,
  Ready stays NotReady with the latched kernel witness (stage 1: tasks of the
  window are untracked until the agent restarts), and StopNode reports the
  witness with at most stale exit credit (frees missed while ftrace was off).
  The test logs `product-ftrace-outcome: witness-latched (...)`; anything
  else fails.

  Evidence rows check the logs, so a dropped env var cannot pass silently:
  Strict 126 and Audit 0, the in-test restart, the refusal of the
  qualification seam, ftrace NotReady, 126 after restore and the logged ftrace outcome.
  Last come the hygiene rows: no
  `se_*` pins (bpffs must be mounted), no enforce_exec programs (full names
  or their 15-byte kernel truncation), no new BPF links, no test cgroups, and
  no `BUG:`, `WARNING:`, `Oops` or lockdep in the kernel log (saved and
  cleared at the start; a `dmesg` or `grep` error fails the row).
- **unpinned** (the AL2023 image's default 6.1 kernel on QEMU; the runner's
  own kernel on EC2): the kernel is unpinned, then
  `TestSharedProductNodeNegativesAttached` with `IG_SHARED_PRODUCT_UNPINNED=1`
  must log that the product gate admitted it as probed and that StartNode
  reached the host ("unpinned-probed: tier probed ... StartNode reached the
  host").

Each group also has an `infra.tsv` (build commands, lane preflight, VM, guest
exit, fetch, teardown, absence proof). A missing record, or any nonzero code
in it, is red.

## Not covered

- The EC2 lane (the gate of record). It needs the AWS account, the OIDC role, private AMI
  copies and an access path (plan step 3; D3 and D8).
- The diagnostic twins as negatives (D5). They are not buildable from the
  repository.
- EKS AMI parity (D9).
- The QEMU lane proves kernel parity only (same vmlinuz, BTF and build-id),
  not AMI parity.
