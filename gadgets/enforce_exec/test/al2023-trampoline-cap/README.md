# AL2023 trampoline link cap probe (G009, test only)

Measures how many BPF trampoline links each G009 attach target accepts on the
exact AL2023 kernels. No product image, Makefile or Ready path selects it.

## Design

**Fillers.** `filler.bpf.c` has three no-op programs: `filler_lsm`,
`filler_fentry` and `filler_fexit`. Each is `r0 = 0; exit`, and the inspect
mode checks that. The runner retargets a program by setting `AttachTo` and
loads one fresh instance per link, because the kernel refuses to link the same
program twice to a trampoline (`EBUSY`).

None of them can deny:
* The LSM filler returns 0. A BPF LSM program runs only when every earlier
  fmod_ret/LSM program on the trampoline returned 0, so 0 is also the prior
  result.
* The kernel ignores fentry/fexit return values.

**Probes.** Each probe attaches fillers in rotation until an attach fails or
`-max` (default 128) is reached:

| target | kind | trampoline |
|---|---|---|
| bprm_check_security, task_alloc, task_free, file_open, socket_connect, inode_init_security_anon | lsm | `bpf_lsm_<hook>` |
| bprm_execve, cgroup_migrate, copy_process | fentry, then fexit | the function |
| bprm_execve | mixed: fentry, fexit | `bprm_execve` |
| bprm_check_security | mixed: lsm, fentry, fexit | `bpf_lsm_bprm_check_security` |

After each probe, the runner closes every link and program. It then walks the
bpf link IDs with `BPF_LINK_GET_NEXT_ID` for up to 10 s, until none of the
probe's link IDs remain and the link count equals the pre-probe baseline. The
links are FD-owned and never pinned, so a killed runner also releases them.

**Output.** One line per probe:

```
CAP kernel=<rel> target=<t> kind=<lsm|fentry|fexit|mixed> cap=<n> errno=<e> baseline_restored=<bool> preexisting=<n> phase=<attach|load|none> limit=<tramp_links|other|not_reached>
```

* `cap` counts only this probe's links. `preexisting` counts the links already
  on the same trampoline, matched by kernel BTF ID through link info. An
  example is systemd's BPF LSM programs.
* `limit=tramp_links` means `E2BIG` at attach with
  `preexisting + cap == 38`, which is `BPF_MAX_TRAMP_LINKS` on x86_64 and
  shared by the fentry, fexit and fmod_ret/LSM lists.
* Any other failure is `other`. That includes `E2BIG` from the one-page
  trampoline image limit (`arch_bpf_trampoline_size() > PAGE_SIZE`).
* The run fails if any probe errors or leaves links behind.

## Build and run

```sh
D="$HOME/.local/state/sandbox-policy-recovery/g009-capacity-20261110"
P=gadgets/enforce_exec/test/al2023-trampoline-cap
for v in 6.12 6.18; do
  VMLINUX_DIR="$HOME/.local/state/sandbox-policy-recovery/g020-phase-live-20261109/$v" \
    OUTPUT="$D/filler-$v.bpf.o" "$P/build.sh"
done
CGO_ENABLED=0 GOWORK=off go build -o "$D/trampoline-cap-runner" "./$P/runner"
"$D/trampoline-cap-runner" -object "$D/filler-6.18.bpf.o"   # inspect only
# On an isolated exact AL2023 guest, as root:
./trampoline-cap-runner -object filler-6.18.bpf.o -run-isolated
```

`$D/build-cap.sh` runs these steps with the pinned clang-21 toolchain and
records the host sha256s. `$D/run-cap.sh` drives the exact-kernel VM on
127.0.0.1:2231: 6.18 first, then 6.12.

Live mode first checks three things, as the exec-capsule fixture does:
* the exact kernel release;
* the kernel BTF sha256;
* that BPF LSM is active.

## Accuracy limits

* **One page.** The cap is measured with two-instruction fillers. Each link
  adds a fixed-size call sequence to the trampoline image, whatever the
  program size. Under the one-page image limit, a trampoline on a function
  with many arguments, or one with many fmod_ret/LSM links, could fail before
  38. Such a failure shows as `limit=other`.
* **Concurrent attaches.** The cap is what was free at probe time. Another
  process that attaches or detaches on the same trampoline during the probe
  shifts it, and can also make `baseline_restored` false.
* **Kernel BTF.** LSM hooks with a void return (`task_free`) link as fexit
  internally. They still count against the same 38.
* **Not a coexistence proof.** This probe does not prove that the fillers
  coexist with product programs. That is G009 step 5.

## Transaction and readiness modes (G009 steps 3 and 4)

`-mode txn` and `-mode ready` (with `-candidate g19pkg128-<k>.bpf.o` or
another object carrying `real_owner_capsule_free`, and `-run-isolated`) load
the exec candidate's steady-state attach set (the 8-link product shape,
`task_free` 2; see `candidateAttachSet` in `runner/txn.go`; the G009
`g25final128` objects lack the capsule death retire and are refused) and
attach it through
`pkg/operators/ebpf/nativeattach`, the transaction of the eBPF operator's
native path.

* `txn` pre-fills `-target` (default `bprm_execve`, family need 3) with
  fillers. With `need+R-1` free the capacity hint must refuse before any
  attach; with `need-1` free and no hint, the attach must fail with `E2BIG`
  mid-transaction and roll back. Both must return `ErrAttachCapacity` naming
  the target, leave none of the candidate's links, and leave every filler link
  ID on its program. After the fillers are freed, a retry must succeed.
  Output: `TXN kernel=... case=hint|authority|retry ...`.
* `ready` attaches the set, removes the `bprm_check_security` link outside the
  transaction (`BPF_LINK_DETACH` through a separate FD from its ID, or, when
  the link type has no detach, by closing the owning FD) and requires
  `CheckPresent` to return `NotReady` naming `bpf_lsm_bprm_check_security`.
  A link that stays present is reported as `STALE`, never as Ready.

`~/.local/state/sandbox-policy-recovery/g009-capacity-20261110/run-txn.sh`
builds the runner and drives both modes on the exact-kernel VM.

## Retry, coexistence and hold modes (G009 retry and step 5)

All three use the same candidate attach set and no-op fillers.

* `retry` pre-fills `-target` so the capacity hint refuses, then starts the
  family through `nativeattach.Retry` (200ms doubling to 2s) and frees the
  fillers after `-free-after` (default 3s). Every refused attempt must report
  NotReady naming the target with none of the candidate's links present. The
  family must then attach all 7 links and report Ready once, and leave no link
  behind. A second case cancels the context instead: it must return
  `context.Canceled` plus `ErrAttachCapacity`, with no link of ours and every
  filler unchanged. Output: `RETRY kernel=... case=freed|cancel ...`.
* `coex` runs, for every hook of the attach set, `F` in
  `{0, 10, 20, 38-R-K-pre, 38-R-K-pre+1}` pre-attached fillers (`pre` is the
  number of links already on the hook; with `pre = 0` this is
  `{0, 10, 20, 30-K, 31-K}` at the default `R = 8`). The family must attach
  iff `pre+F+K+R <= 38` and otherwise refuse with `ErrAttachCapacity` naming
  the hook, with no leftover link and every filler unchanged. Output:
  `COEX kernel=... target=... K=... R=... F=... expected=... result=...`.
* `hold` attaches the boundary `F` (`38-R-K-pre`) on every hook of the attach
  set at once and holds it until SIGTERM/SIGINT or `-hold-timeout`. On
  release every filler must still be on its program and then disappear.
  It is the filler pre-step of the functional smoke.

`~/.local/state/sandbox-policy-recovery/g009-capacity-20261110/run-txn.sh`
also runs `retry`. `run-coex.sh` in the same directory runs `coex` and then,
while `hold` keeps the fillers attached, the unchanged attached verdict test
binary (`TestOpaqueRealPolicyVerdictAttached` c2-r1: Strict allow and deny;
c1-r1: Audit nonblocking).
