# Attach canary for other BPF LSM programs

The exec engine proves at start that every attached program runs: it turns on
BPF run statistics, runs a child, and requires each program's run count to
rise (`gadgets/enforce_exec/fullruntime/shared_kernel_witness.go`).

`fullruntime.RunAttachCanary(ctx, receipts, canaryCmd)` makes the same check
available to programs outside the engine. node-agent's privilege, network and
file sections use it with their own child, which passes through each of their
hooks.

- `receipts` are the IG ebpf operator's attach receipts (program ID, target).
- `canaryCmd` is the child; it must reach every receipt's hook and change
  nothing on the node. `nil` runs this binary with the exec canary
  environment (a fork, an exec and an exit).
- The child is repeated until every program ran, within a 5-second budget.

Result:

- `nil`: every program ran.
- `ErrAttachCanarySilent`, with `*AttachCanarySilentError` naming the silent
  programs: at least one program is attached but never ran.
- Any other error (run statistics, an unreadable program, a failed child, a
  deadline before the first sample) says nothing about the hooks and is not
  marked silent.
