# Inactive U05 service journal

## Authority and boundary

This is an inactive construction implementation of C0 I05/I07 and implementation
unit U05, not an activated installation or an engineering/specification acceptor
verdict. The source contracts are the [construction seam sheet](assembly-v0-construction-contract.md),
operator-and-activation-v0 section 4.2 (service journal, retention and narrowing
capacity), and its enrollment recovery paragraph. The plan already records the
book dispositions for Operator and interfaces and OS user per agent and network;
this unit introduces no new ceremony, installation, principal or authority path.

All points in the [applicability register](assembly-v0-applicability.md) remain
open, especially O-01/O-19. Unresolved integration must stop at its named O-point,
not infer acceptance from a passing synthetic test. Enrollment results and
intent reconciliation remain U19/O-07. Production custody role, constructor and
catalog integration remain the later units and O-08/O-19. Nothing here imports
into the daemon or existing service constructors, installs files, obtains live
material, or changes the default stopped-owner behavior.

## Shared gate and injection

`statev0.NewGate` implements the frozen `Gate.With` callback signature. It issues
an exact-pointer token with nonzero-sized runtime state. Zero, copied, foreign,
cancelled and returned-callback tokens refuse. The gate releases even on panic;
cancelled waiters do not enter. `statev0.Check` and `Use` let later storage and
release consumers use that same token without reacquiring the state gate.
Operations are synchronous; recursive gate/Use acquisition is forbidden. An
attempt to acquire an already held gate waits only until its context deadline
and never enters a second callback. Callers must supply bounded contexts and
must not start escaped work with a token.

`servicev0.JournalAccount.Locked` creates a call-scoped `service.Account` bridge;
`ForLeaseLocked` additionally pins the exact recorded lease for material release.
It does not create another mutex or silently acquire the gate per account method.
The final delivery rechecks the current journal, hold, lease, binding, context
and expiry under the same gate. The existing service engine is not wired to this
bridge: later assembly must inject one shared gate around all relevant mutation
and release paths, preserving configuration/managed/state ordering. Merely
wrapping the existing private service mutex would not satisfy this contract.

## Explicit versioned storage

`statev0.Journal` depends on the narrow `ServiceRecords` backend and never imports
`service`, its bridge, or the physical store. `servicev0.Records` uses the existing
protected `store.Account` publication primitive: canonical size check, file sync,
same-directory rename, directory sync and expected revision. The only added
primitive in the existing store is `Account.HasRecords`, a name-only, early-exit
census. Fresh initialization never opens unrelated material or accepts any
pre-existing or pending record as an empty account.

- `InitializeLocked` is an explicit fresh-empty-store construction operation,
  not a lookup fallback, migration or enrollment admission proof. Its caller
  must already own fresh-install/enrollment authority. A nonempty store refuses.
- A new journal instance starts unsettled. `ReconcileLocked` validates a complete
  existing record and durably republishes it at the next revision before use.
  Missing, corrupt, old-version or exhausted state cannot be reconciled as empty.
- `LoadLocked` requires exact canonical `/2` bytes, all required members and
  arrays, sum-aware receipts, installation/account/revision pins, closed service
  method metadata and valid record shapes. `/1` is never cast or adopted.
- `CommitLocked` checks revision CAS and retains all prior operation bytes,
  bindings, leases and holds. Removed bindings require their matching retained
  removal outcome. Nullable operation time is preserved; `at:null` never advances
  the wall-time watermark. A historical receipt is not reauthenticated against
  current terminal pins; only new receipts use the configured construction pins.
- Physical publication uncertainty fences only that journal account until
  explicit healthy reconciliation. It is never a refused method outcome or an
  acknowledged success. A new instance also needs reconciliation; reading a
  renamed record is not by itself proof of directory durability.
- `ReplayLocked` returns the original recorded operation/result without a write;
  different canonical arguments conflict. It is not new authority or a material
  replay permit. Unknown intents are not a published record form.

The bridge keeps `/2` as its explicit in-memory kind and projects the existing
binding/lease/hold values unchanged. Existing operations retain their closed
receipt separately from the legacy method projection. A zero projected method
time represents original `at:null`, not a fabricated timestamp; writing the
projection restores the original null and receipt. New operator outcomes need a
bound receipt. This is not permission to pass nullable `/2` history to an
unchanged `/1` constructor and claim integration. Binding/hold records retain
their existing required timestamp rules. This unit does not choose the runtime
provenance or assignment of those fields during time-untrusted narrowing:
integration must stop at O-19 rather than fabricate timestamps. Tests supply
inert known record timestamps and separately exercise nullable operation time;
they do not qualify a runtime timestamp-assignment policy.

## Full-record reserve

Reservation serializes a complete prospective future journal, rather than
subtracting an estimated constant from 1 MiB. It includes:

- Every existing record and required operation outcome, without eviction.
- Each active binding converted to its maximal removal tombstone and a complete
  unbind outcome, including the largest configured terminal pin, full BOOTTIME
  receipt, maximal safe numeric fields, time and bounded principal fields.
- Remaining active lease terminal-state growth and maximal revision/watermark
  encoding.
- A full account hold and its method outcome when an active hold is not already
  durable. Lifting a hold must reserve the next hold again.

Both reserve preflight and commit enforce the bound before physical mutation.
Narrowing replaces the corresponding reservation with retained real evidence;
the remaining bindings and eligible hold keep their headroom. The pins bound
future storage only; they are not a protected configuration reader or proof of
an authenticated operator. A later integration cannot supply arbitrary larger
receipt identities and claim the old reservation covered them.

## Acceptance evidence

| Plan row | Named witnesses | Bound |
| --- | --- | --- |
| JOURNAL-VERSION | `TestServiceJournalVersion`, `TestJournalVersionedStoreBoundary`, `TestJournalAccountVersionProjection` | Exact landed nonempty UTC/BOOTTIME vectors, closed negative neighbors, explicit fresh `/2`, no `/1` adoption. |
| ENROL-JOURNAL | `TestEnrollmentServiceJournalInitialization`, `TestJournalVersionedStoreBoundary`, `TestServiceJournalDurabilityAndReconciliation` | Missing committed state is unavailable; only explicit fresh initialization. Complete enrollment-intent authority/reconciliation is U19/O-07, not claimed here. |
| NARROW-RESERVE | `TestServiceNarrowingReserveFullRecord`, `TestServiceNarrowingPreservesHold` | Near-ceiling nonempty history, bindings, leases, every reserved removal and a full hold; no eviction. Authority newest-64 summaries are U04, not service-journal history. |
| NARROW-OWN-STATE | `TestServiceNarrowingOwnState`, `TestServiceNarrowingPreservesHold`, `TestServiceJournalDurabilityAndReconciliation` | Honest missing/unreadable/unwritable/uncertain state, CAS and watermark refusals; adjacent healthy same removal. |
| RETRY-COMMITTED | `TestCommittedServiceRetry`, `TestServiceJournalDurabilityAndReconciliation` | Original complete result, no equal-retry write; unequal/duplicate/extension/rewrite/unknown cannot become success. |
| I05 shared boundary | `TestSharedGateTokenLifetime`, `TestSharedGateSerialization`, `TestSharedServicePublicationBoundary`, `TestServicePublicationCancellation` | Gate scope and real inactive store/release serialization; no daemon or native qualification claim. |

The brief has no attack-surface table; this is a declared brief gap, not a waiver.
All previous reviewer tests retain their original names. The import-boundary
instrument now permits only the inactive bridge to consume construction values
and still rejects daemon/runtime wiring and reverse storage imports, with
adjacent positive controls and explicit forbidden-import plants.

## Tools and remaining gates

Run `gofmt` on the changed Go files, `go vet ./...`, and
`go test -race ./...` only after sourcing the assigned private Go environment,
with the assigned absolute temporary directories and `GOFLAGS=-p=2`. Export
`GO="$(command -v go)"` as an absolute executable: existing qualification/egress
tests build subprocess fixtures and refuse an unset `GO`. On the unprivileged
host, the documented `SWARMA_TEST_UNPRIVILEGED=1` mode skips only fixtures whose
host prerequisites are unavailable; report their named skip reasons, never
count them as qualification. Focused
checks are `go test -race ./internal/statev0 ./internal/servicev0 ./internal/store ./internal/assemblyv0`.
Keep exact command statuses and logs in task-owned `.temp/`; the external task
handoff contains the run evidence and plant verdicts. PL-SERVICE-RESERVE must
fail `TestServiceNarrowingReserveFullRecord` at the actual reservation assertion,
with a passing unplanted full-record control. An unapplied or crashing plant is
not a kill. No test here qualifies power-loss recovery, bounded production
publication, current proof provenance, native installation or activation.
