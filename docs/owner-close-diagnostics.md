# Owner close timeout diagnostics

The synthetic owner collector retains its two-second close timeout. When that
timeout fires, it freezes a small observation before issuing cancellation. It
then cancels, closes its pipes and joins the owned child as before. Only after
cleanup does it deliver the frozen record to an already installed diagnostic
callback. Capture uses atomic loads and a nonblocking channel sample; it does
not call the callback, wait, take a lock or read process files before cancelling.

The record has this fixed shape:

```text
owner close timeout close_cancel=not_issued supervisor=pending phase=entered exit=unavailable operation=wait_peek child=stop_observed
```

| Field | Closed values | Meaning |
|---|---|---|
| `close_cancel` | `not_issued`, `issued` | Whether this close method had issued cancellation at capture; external context cancellation is not observed by this field. |
| `supervisor` | `pending`, `returned`, `unavailable` | Nonblocking observation of the session's completion channel, retained only with a stable, valid, available lifecycle observation. A missing channel is `unavailable`. |
| `phase` | `unavailable`, `starting`, `supervising`, `entered`, `terminal`, `joining`, `joined` | Last progress published by the tracing supervisor: before launch, launched, challenge acknowledged, terminal status observed, before consuming wait, or wait returned an actual normal exit or signal death. |
| `exit` | `unavailable`, `zero`, `nonzero`, `signaled` | Exit class from the consumed terminal process state, available only with `phase=joined`. |
| `operation` | `unavailable`, `start`, `started_callback`, `bootstrap_receive`, `bootstrap_ack`, `notification`, `entry_receive`, `entry_ack`, `task_inventory`, `wait_peek`, `terminal_peek`, `birth_read`, `stop_consume`, `resume`, `trace_options`, `exec_read`, `identity`, `ready_callback`, `challenge`, `membership`, `terminate`, `final_wait`, `refusal_cleanup`, `waited_callback`, `pause` | Last entered supervisor operation, without its arguments; does not prove a syscall is blocked. |
| `child` | `unavailable`, `started`, `stop_observed`, `terminal_observed`, `wait_returned` | Last separately observed owned-child progress. A stop or terminal peek is not a completed wait. |

A wait result becomes `joined` only for a normal exit (`ProcessState.Exited()`)
or an actual signal death (the platform status explicitly reports `Signaled()`).
A negative `ExitCode()` alone is insufficient: a ptrace stop also returns `-1`.
Stopped, continued, unknown and nil results clear phase, exit and child evidence;
they do not publish `joined`. While the subsequent `Waited(nil)` callback is
entered, `operation=waited_callback` remains visible with `supervisor`, `phase`,
`exit` and `child` all `unavailable`, even if the completion channel was sampled
as returned. The operation clears when that callback returns. No other operation
is valid with an unavailable phase. This changes diagnostic classification only. The
supervisor's actual tracing, wait, Stop and qualification decisions are separate.

Phase, exit, operation and child are published as one atomic word. If that word
changes around the completion-channel sample, all five observation fields
(`supervisor`, `phase`, `exit`, `operation`, `child`) become `unavailable`.
An absent origin, zero word or malformed observation also clears all five.
A stable unavailable-phase `waited_callback` retains only the known operation.
A valid joined observation has an actual exit class, operation `unavailable` or
`waited_callback`, and child `unavailable` or `wait_returned`. `wait_returned`
is forbidden outside `joined`. The local cancellation field is independent.
The record contains no process identifiers, paths, arguments, environment,
payloads or arbitrary error text. It adds no qualification artifact or wire field.

These observations can become stale immediately. A phase is the last published
progress, not the child's current OS state or an exit timestamp. A joined zero
exit does not establish complete origin evidence, a valid Stop certificate or
qualification success. Missing evidence still refuses, including when the
eventual child exit is zero. This diagnostic does not reproduce or establish
the cause of any earlier CI timeout. PR #62 is a diagnostic mitigation; Issue #63
remains open. These controls establish neither its root cause nor a reduction in
its frequency.

Run the focused controls with the repository's pinned Go toolchain and a fresh
short test-owned `TMPDIR`:

```sh
GO="$CURATOR_GO" GOTOOLCHAIN=local GOMAXPROCS=2 SWARMA_TEST_UNPRIVILEGED=1 \
  "$CURATOR_GO" test -p 1 -count=1 ./internal/qualify ./internal/egress \
  -run '^Test(OwnerClose.*|OriginDiagnosticSnapshot|OriginObservation.*|Waited.*|ReviewObserveWait.*|ObserveWait.*|OriginStopTerminalTransition|OriginOvertakenCloneStrictRefusal|OriginMissingTaskLeaderTransition)$'

GO="$CURATOR_GO" GOTOOLCHAIN=local GOMAXPROCS=2 SWARMA_TEST_UNPRIVILEGED=1 \
  "$CURATOR_GO" test -race -p 1 -count=1 ./internal/qualify ./internal/egress \
  -run '^Test(OwnerClose.*|OriginDiagnosticSnapshot|OriginObservation.*|Waited.*|ReviewObserveWait.*|ObserveWait.*|OriginStopTerminalTransition|OriginOvertakenCloneStrictRefusal|OriginMissingTaskLeaderTransition)$'
```

The real timeout fixture exercises the unchanged two-second branch, real origin
entry, cancellation and sole child join. Clean exit and ordinary cancellation
are nearby controls. A separate controlled incomplete-ledger plant after an
actual joined zero exit checks refusal preservation; it is not a reproduction
of an observed CI schedule. The concurrent atomic-word control can also run
under `-race`. Fixture files live only under the test-owned temporary root;
capture command logs in private scratch and honor the host's serialized test
slot rules.

The real-stop regression retains `TestReviewObserveWaitStopState` and its normal
zero-exit control `TestReviewObserveWaitExitControl`. The stopped tracee is killed
and reaped on every fixture path. `TestObserveWaitRealExitClasses` adds consumed
normal-nonzero and actual SIGKILL controls; `TestObserveWaitNilUnavailable` checks
that a missing result cannot retain an earlier terminal observation.

`TestOwnerCloseSnapshotRacing` and `TestOwnerCloseObservationCoherence` check
changed observations, including operation-only and child-only changes.
`TestOwnerCloseWaitedUnknownObservation` covers the unavailable-phase callback.
`TestOwnerCloseObservationInterleaving` uses a temporary Go source overlay to
force a transition between the two real `Observation()` reads in `closeSnapshot`.
It checks the exact UNKNOWN diagnostic, unchanged execution record, report and
error, no execution credit and no authority facts, beside a stable joined
positive. A known-bad overlay bypassing coherence must fail the diagnostic
assertion while the stable positive still passes. The overlay never edits the
source checkout or adds a production hook. This deterministic interleaving is
regression evidence, not a production schedule or Issue #63 root-cause witness.
`TestOwnerCloseOperationInterleaveOverlay` changes only operation between those
reads, and `TestOwnerCloseUnknownCallbackOverlay` retains a stable unavailable-phase
callback through both reads with either a pending or returned completion channel.

Nested diagnostic overlays automatically inherit `-race` from the parent test
build via the Go `race` build tag; no environment opt-in is required. The only
optional overlay knob is `OWNER_CLOSE_OVERLAY_DIR`, an absolute, test-owned
directory that retains the `valid` and `known-bad` overlays and their manifests
for inspection. Without it, overlays use `t.TempDir()`. Source, probe and manifest
hashes are logged by the parent test. Nested commands receive only an allowlisted
build environment with networking for module acquisition disabled, and have a
five-minute compilation/run deadline plus a 45-second test-binary timeout.

`TestOriginStopTerminalTransition` pairs non-strict overtaken thread recovery
with strict FORK/VFORK refusal. `TestOriginOvertakenCloneStrictRefusal` adds real
CLONE events for both a thread and a separate raw-clone process, each beside a
matching non-strict recovery positive. When a birth event read is overtaken and
returns ESRCH, strict mode refuses CLONE, FORK and VFORK alike: without the birth
identity, even CLONE does not prove thread membership. Loss of strict
thread-overtake recovery is intentional; non-strict recovery is unchanged.
`TestOriginMissingTaskLeaderTransition` uses a separate
test-only overlay, always under `-race`, to pair direct and overtaken terminal
leader paths with missing-task refusals. These bounded fixtures retain strict
process-birth admission and cannot excuse a previously seen missing task.
