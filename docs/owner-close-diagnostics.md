# Owner close timeout diagnostics

The synthetic owner collector retains its two-second close timeout. When that
timeout fires, it freezes a small observation before issuing cancellation. It
then cancels, closes its pipes and joins the owned child as before. Only after
cleanup does it deliver the frozen record to an already installed diagnostic
callback. Capture uses atomic loads and a nonblocking channel sample; it does
not call the callback, wait, take a lock or read process files before cancelling.

The record has this fixed shape:

```text
owner close timeout close_cancel=not_issued supervisor=pending phase=entered exit=unavailable
```

| Field | Closed values | Meaning |
|---|---|---|
| `close_cancel` | `not_issued`, `issued` | Whether this close method had issued cancellation at capture; external context cancellation is not observed by this field. |
| `supervisor` | `pending`, `returned`, `unavailable` | Nonblocking observation of the session's completion channel. |
| `phase` | `unavailable`, `starting`, `supervising`, `entered`, `terminal`, `joining`, `joined` | Last progress published by the tracing supervisor: before launch, launched, challenge acknowledged, terminal status observed, before consuming wait, or wait returned an actual normal exit or signal death. |
| `exit` | `unavailable`, `zero`, `nonzero`, `signaled` | Exit class from the consumed terminal process state, available only with `phase=joined`. |

A wait result becomes `joined` only for a normal exit (`ProcessState.Exited()`)
or an actual signal death (the platform status explicitly reports `Signaled()`).
A negative `ExitCode()` alone is insufficient: a ptrace stop also returns `-1`.
Stopped, continued, unknown and nil results clear the diagnostic to unavailable;
they do not publish `joined`. This changes diagnostic classification only. The
supervisor's actual tracing, wait, Stop and qualification decisions are separate.

Phase and exit are published as one atomic word. If that word changes around
the completion-channel sample, all three observation fields are unavailable.
An absent origin, completion channel or malformed word also reports unavailable
for the affected observation. The local cancellation field is independent.
The record contains no process identifiers, paths, arguments, environment,
payloads or arbitrary error text. It adds no qualification artifact or wire field.

These observations can become stale immediately. A phase is the last published
progress, not the child's current OS state or an exit timestamp. A joined zero
exit does not establish complete origin evidence, a valid Stop certificate or
qualification success. Missing evidence still refuses, including when the
eventual child exit is zero. This diagnostic does not reproduce or establish
the cause of any earlier CI timeout.

Run the focused controls with the repository's pinned Go toolchain and a fresh
short test-owned `TMPDIR`:

```sh
GO="$CURATOR_GO" GOTOOLCHAIN=local GOMAXPROCS=2 SWARMA_TEST_UNPRIVILEGED=1 \
  "$CURATOR_GO" test -p 1 -count=1 ./internal/qualify ./internal/egress \
  -run '^Test(OwnerCloseTimeoutSnapshot|OwnerCloseDiagnosticUnavailable|OriginDiagnosticSnapshot)$'
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

`TestOwnerCloseSnapshotRacing` directly checks the coherence helper's rejection
of changed scalar observations. It does not force a word change between the two
reads in the production capture. Bypassing that helper call can still survive
the current tests. This integration-coverage bound remains explicit; no blocking
callback or test-only behavior is added to the pre-cancellation path to force it.
