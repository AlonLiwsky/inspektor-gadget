# v4 — failure-only diagnostic, not a behavioral fix

## Archived observation

Run7 original/core passed with v3. The subsequent original/missed-entry case
failed `zero owned counts do not qualify prefix or history` before `refuse()` or
`PX_DIAG_RELEASE`. No preexec or k8s result is inferred.

Unmodified archive:
`/home/mbertschy/ig15-gatea-proof-20261029-run7-prefix-shapes/proof/original-prefix-attempt1.tar.gz`
SHA-256: `e2a88585a1e384d43b3f953abd62b894e4fb84bf7208d89a01bb0f3fd9b1bc5b`.
Member: `proof/original-prefix-attempt1/missed-entry/runner.log`.

The log records a successful copy_thread entry witness, actual missing-link
attachment, observer enablement, fresh authenticated barrier, completed initial
inventory, and both existing worker rows UNKNOWN/unqualified. It then records
only the compound assertion failure, without the state values. Three successful
row reads during one worker lookup suggest an additional row existed by that
lookup, but do not identify its creation time or which conjunct failed.

## Ranked hypotheses (not proved)

1. The bounded diagnostic stall expired during attachment/setup; an unowned child
   became CSS-visible in time for the initial inventory, increasing its counts.
   This is consistent with the additional row and the multi-step setup after
   the entry witness. The log has no final diagnostic_timeout/exit fields, so
   neither expiry nor inventory==3 is established.
2. Another relevant lifecycle/accounting condition changed between the entry
   witness and the already-read state snapshot (including a sticky observer
   error). The failing conjunction also checks inflight/allocs/births/errors;
   these values are missing, so this cannot be excluded from the log alone.

No definite new source bug is established. Therefore v4 changes no BPF behavior,
expected counts, task creation, bounds, loop mechanism or qualification rules.

## Instrumentation boundary

The original short-circuit conjunction is evaluated once with identical operands
and ordering against the same existing `struct px_state s=state()` snapshot.
Only when false does `px_dump_initial_failure(stderr,&s)` emit one JSON record,
then the existing require fails. The formatter performs no map, clock or other
kernel-state reads and does not mutate the snapshot. There is no added success-
interval logging or map read. The dump includes every original conjunct, its
exact expected value, serial/writers/receipt state, and diagnostic entry, exit,
timeout, release, CPU and physical identity fields. Values are explicitly cast
from the existing u64 fields to unsigned long long for `%llu` formatting.

`format_test.c` plus `test-format.py` verify the exact JSON dictionary, all field
names, full-width uint64 formatting, and byte-identical input state. Existing
Clang21/static-analysis, host regression, both archived BTF and emitted-bytecode
checks still pass. The rebuilt BPF object is **byte-identical to v3**:
`4622e66a216709cedd52bdb709b2aad154ada2659a39613cb56d03dbaf937f09`.

The 65,536-iteration AND 10-ms diagnostic limits remain unchanged. v3 and run7
artifacts remain untouched. v4 is diagnostic-only and has not been loaded or run
as BPF; independent review precedes any diagnostic retry. This is not a claimed
fix, full prefix qualification, or G018 closure.
