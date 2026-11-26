# Exec engine: runtime entries are ENTRY, and their refused exec is reported

A task can enter a selected cgroup after its birth, for example the process
that `kubectl exec` (runc exec) puts into a container. It has no TASK in the
exec engine, so the engine cannot follow its lineage. A Strict route refuses
its forks and execs; an Audit route leaves them unevaluated. This is the
intended outcome, not an engine fault.

## Fail-closed rate

- An exec or a fork on an owned route by a task with no TASK key
  (`se_opaque_keys`) counts in the ENTRY cell (`FailClosedRateEntry`).
- ENTRY is reported apart and never added to Total, so it never makes the node
  Degraded or NotReady.
- A failed parent open while a TASK exists stays a fault in Total: open-parent
  for an exec, source refusal for a fork.

Before this change only the exec was ENTRY. The fork counted as a source
refusal, so one `kubectl exec` that forked could push the node's rate over
0.1% and make every binding NotReady for the 5-minute window.

## Verdict event

An owned exec pass that never reaches a policy program (ENTRY, a failed open
or reader begin, a pending or terminal fault, a failed transfer) emits one
fault event from `bprm_check_security`: Strict `deny 1 mode 2 error 1`, Audit
`deny 1 mode 1 error 1`, pass unknown. It usually has no exec receipt, so its
`generation` and `scope` are 0; the consumer attributes it by `cgroup`. It
carries the exec file's resolved path when known (best effort: absolute, at
most 255 bytes, from the exec'ing task's root, not checked against the
binding's root like the pass facts), else `path_result` -1. A fork refusal
emits no event.

Details: `gadgets/enforce_exec/fullruntime/README.md` (fail-closed rate and
verdict events).
