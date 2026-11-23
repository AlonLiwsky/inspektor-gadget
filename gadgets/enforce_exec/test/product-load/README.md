# Product object-load run

Loads the 4 shared product objects (`g19pkg{64,128,256,512}.bpf.o`: one
CO-RE object per profile, for every kernel) on a disposable test machine
with any kernel (for example a DigitalOcean droplet), runs the product node
tests there, then judges the result. The pass rule is strict: every expected
row has exactly one PASS, and a skip, a missing row, a duplicate, an
unexpected test, or an infrastructure error turns the run red.

The run proves what it observes on the machine's own kernel: the product
kernel gate admits it, the objects load, the node gets Ready and enforces,
restarts clean, refuses the qualification seam, goes NotReady with ftrace
off, and leaves nothing behind. It does not prove anything for another
kernel.

| File | Role |
|---|---|
| `common.sh` | Profiles, object and image names (no kernel settings) |
| `expected.tsv` | The rows of a full run (`group step test profile`), rebuilt from the test sources |
| `judge/` | `judge check` (the verdict), `judge row`/`judge end` (harness checks as test2json) |
| `host.sh` | `build`, `remote <ssh-target>`, `judge`, `all` |
| `guest.sh` | Runs as root on the test machine: identity, raw load, Ready per profile, restart child, negatives, ftrace negative, hygiene |
| `verdict-load/` | Loads (never attaches) an object and prints its programs |
| `../../fullruntime/shared_product_layout_build_test.go` | The tag-only OCI layout builder (`-tags 'enforce_exec_shared_qualification enforce_exec_product_layout'`) |

## Run on a droplet

The test machine must be amd64 with BTF, `bpf` in the active LSM list
(`lsm=...,bpf` on the kernel command line), `kernel.ftrace_enabled=1`, no
livepatch, cgroup v2 and bpffs at `/sys/fs/bpf`. Treat it as disposable: the
run loads BPF LSM programs and toggles ftrace.

```sh
# On the workstation (needs Docker for build-product.sh's pinned container, and Go):
export PRODUCT_LOAD_PROFILES="64 128 256 512"   # the default; must include 128
host.sh build  /path/run-1
host.sh remote /path/run-1 root@<droplet-ip>     # scp bundle, guest.sh as root, fetch results/kernel
host.sh judge  /path/run-1
# or all three:
make enforce-exec-product-load ENFORCE_EXEC_PRODUCT_LOAD_RUN=/path/run-1 ENFORCE_EXEC_PRODUCT_LOAD_TARGET=root@<droplet-ip>
```

Without ssh access from the workstation, do `remote` by hand: copy
`/path/run-1/bundle` to the machine, run
`PRODUCT_LOAD_RUN=<run-id> bundle/guest.sh bundle out` as root, copy
`out/kernel` back to `/path/run-1/results/kernel` and write its `infra.tsv`
(`name<TAB>exit-code<TAB>detail` per step, e.g. `guest	0	guest.sh exit`)
before `host.sh judge`.

A full run judges both groups (`build,kernel`) and all four profiles, and
must hold exactly 77 rows (`host.sh` passes `-rows 77`). Anything narrower
(`PRODUCT_LOAD_JUDGE_GROUPS` or a profile subset) is refused unless
`PRODUCT_LOAD_PARTIAL=1`, and the verdict line and `results.tsv` header name
the judged groups and profiles. `all` stops after a failed build.
`PRODUCT_LOAD_BURNIN=skip-kill|plant-warning|plant-se-pin` exists only for
fail-closed burn-ins: it adds an unexpected stream, so such a run is always
red. A run directory is never reused: evidence is never overwritten.

The tagged package build (`go test -tags 'enforce_exec_shared_qualification
enforce_exec_product_layout' ./gadgets/enforce_exec/fullruntime`) fails by
design without `IG_ENFORCE_EXEC_PRODUCT_OBJECTS` and
`IG_SHARED_PRODUCT_LAYOUT_OUT`: the layout builder never skips.

## What a run checks

- **build** (the workstation): `build-product.sh --check` (4 object pin
  rows, `fullruntime/testdata/shared_product_objects.tsv`), the layout
  builder (one image per profile, `local/shared-product:pkg<N>`; built twice
  in-process, then a second process must produce an identical layout), and
  the three userspace object tests with `IG_ENFORCE_EXEC_PRODUCT_OBJECTS`.
- **kernel** (the test machine, as root): the bundle manifest, then the
  identity rows. `uname -r`, the BTF sha256 and the build-id from
  `/sys/kernel/notes` are recorded (no pinned build is compared); `bpf` LSM,
  `ftrace_enabled` and no livepatch taint are required, as the product
  kernel gate requires them. An identity failure stops the run. Then
  `verdict-load` on all 4 objects (each must first match its pinned
  sha256), and for each profile in `PRODUCT_LOAD_PROFILES`:
  - `TestSharedProductNodeReadyAttached` with two fresh cgroups (Strict 126
    in A, Audit 0 in B, an in-test restart); it never toggles ftrace and its
    node must stop clean. It logs the identity the product gate admitted
    (`product-kernel-admitted: ...`), which must be this machine's;
  - the restart child under `unshare -m`: READY; a positive control that
    the leftover probe sees its programs and new links while it lives;
    SIGKILL; no program left; then a child that reaches READY and exits;
  - `TestSharedProductNodeNegativesAttached`: the product StartNode refuses
    the qualification seam before any host run (the per-object refusals
    are unit tests).

  Then, once on profile 128 and on its own node,
  `TestSharedProductNodeFtraceNegativeAttached`: Ready goes NotReady naming
  ftrace while `kernel.ftrace_enabled=0`, Strict 126 is back after restore,
  Ready stays NotReady with the latched kernel witness (tasks of the window
  are untracked until the agent restarts), and StopNode reports the witness
  with at most stale exit credit. The test logs
  `product-ftrace-outcome: witness-latched (...)`; anything else fails.

  Evidence rows check the logs, so a dropped env var cannot pass silently.
  Last come the hygiene rows: no `se_*` pins (bpffs must be mounted), no
  enforce_exec programs (full names or their 15-byte kernel truncation), no
  new BPF links, no test cgroups, and no `BUG:`, `WARNING:`, `Oops` or
  lockdep in the kernel log (saved and cleared at the start; a `dmesg` or
  `grep` error fails the row).

Each group also has an `infra.tsv` (build commands; remote copy, guest exit
and fetch). A missing record, or any nonzero code in it, is red.

## Not covered

- A deny self-test at node startup: a test binding would hold one of the
  node's two route slots.
- The diagnostic twins as negatives: they are not buildable from the
  repository.
