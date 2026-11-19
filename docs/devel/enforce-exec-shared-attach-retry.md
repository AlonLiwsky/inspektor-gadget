# enforce_exec: shared attach capacity retry

The shared enforce_exec node attaches native trampoline programs that share a
limited number of kernel slots. When the slots are full, the attach is refused
with a typed capacity error (`*nativeattach.ErrAttachCapacity`).

## Where the retry runs

`StartNode` retries the whole host start, with a bounded budget: 8 attempts,
backoff from 500 ms doubling to 5 s, at most 30 s in total. The ebpf
operator's Start does not retry (`NativeAttachRetryKey` is `false` for the
shared node), so a refusal fails `StartGadget` at once and the instance
manager releases its lifecycle lock. Each attempt is torn down before the next
backoff, so no wait holds the lock and two attempts never coexist. A stop or
replace that frees slots can therefore run during the backoff.

When the retry runs out or is canceled during a wait, `StartNode` returns
`ErrSharedNodeNotReady` wrapping the last refusal. `SharedNodeConfig.AttachState`
receives every refusal, and nil once it no longer applies.

## Host contract

- `Run` may be called again for the same gadget ID once its `stop` returned nil.
- `stop` must treat a missing instance as success (return nil).
- The host must not run two `StartNode` calls for the same gadget ID at once.

Details: `gadgets/enforce_exec/fullruntime/README.md`, "Attach capacity,
readiness and the owner cap".
