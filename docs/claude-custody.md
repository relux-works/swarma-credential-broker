# Claude secret-free service source slice

This inactive source slice follows the landed 0.13
[secret-free service dialect v0](../spec/secret-free-service-v0.md).
The implementation changes no specification and grants no activation.

The architecture references remain `book/ru/09-uchetnye-dannye.md`, sections
"Режим без секретов у агента" and "Растяжка утечки", [mode §§2–5,10](../spec/secret-free-mode.md),
[gateway §§2,6,7](../spec/secret-free-gateway.md), and
[adapters §3](../spec/secret-free-adapters.md). The dialect refines those rules.
Secret-free selection is protected policy per account and kind, covering every
launch using that account. Failed admission never selects an exposed fallback.

## Custody and authority

`internal/claude.Account` owns fresh, opaque fixture enrollment, optional exact
vendor expiry, metadata-only status and protected material publication. It has
no refresh, native-login import, export command or worker delivery path. The
standalone daemon still installs no service controller or accepting provider.

`internal/service.Authority` separates protected managed identity and operator
acts (`WithIdentity`) from current use authority (`WithCurrent`). Both acquire
external evidence before the broker state lock; their `View` methods read only
settled local evidence. No synchronous platform-service call runs under that
lock. The current view must hold service generation, caller binding/chain,
revocations, selected account policy and trusted time stable through the actual
bounded publication callback. Admission classes and local placement belong to
that protected evidence. Static UID, request fields and placeholder possession
supply none of it. No production provider is supplied.

An explicit activation gate is that the provider enforces spec §2.2
(service-account record, disjoint roles): a user-manager service-account
record, never an agent or workplace record, admitted local placement, a class
other than untrusted, and disjoint service and agent roles (§5.1 step 3,
negative-table row 10). A role label alone does not discharge this gate.

`View.Caller` returns the originating `binding_id` and exclusive authority
expiry. The broker records it on issue and compares it on renewal and replay.
Replacing the binding for the same uid and generation refuses renewal with
`lease_unbound`; the poll reports `revoked`. A fresh service lease resolves the
new binding, and no old record is retargeted. Service-binding removal followed
by a fresh bind similarly inherits no old renewal authority.

An operator act needs both the admitted operator principal and
`View.OperatorAct` evidence for the exact method and canonical arguments. Bind
and lift require content-confirmed widening acts; unbind requires narrowing-act
authentication. The same operator can be the account owner. Bare owner/operator
UIDs do not grant an act. Native command confinement, authentication and content
confirmation remain installation gates; the fixtures grant synthetic acts only.

## Protocol and durable state

The existing listener accepts the standard `broker/1` versions-only hello and
returns the fixed service triple without a profile member. Existing internal
profile clients retain their selector; the static refresher path is unchanged.
The listener carries the closed fields of accepted
sections 5 and 6: operation IDs, flat caller members, `service_binding_id`,
`service_lease_id`, `{kind,value}` payload, nullable vendor expiry, and
`authorized_until`. The payload reaches only the authenticated service result.
The new refusal codes retain their exact spelling through `wire.Refuse`.

Service bindings are separate random identities. Duplicate active tuples refuse;
unbind retains a tombstone and closes registered connections of that uid and
generation. Different gateway triples may bind the same account. Each lease
records its service binding and originating agent binding. Release is durable
and idempotent; typed reports affect lease evidence only.

The protected `claude-service-journal/1` transaction envelope contains the closed
binding, lease and hold records, canonical nonsecret operation arguments and
metadata outcomes, revision and consumed-time watermark. It uses existing
atomic replacement, file sync, directory sync and CAS protection. No payload,
placeholder or derivation of material enters it. Recovery re-confirms journal
durability before replay can acknowledge an interrupted write. Lease identities,
removed bindings, operation outcomes and holds survive broker replacement.
There is no legacy volatile-record adoption or migration: this source was never
activated. Unreadable or incompatible state refuses construction.

Equal operation retries preserve identities and recorded renewal limits;
different arguments refuse `service_operation_conflict`. Material replay
repeats current authority, state, expiry and hold checks. Expired or released
leases return `lease_not_active`, without another material delivery or extension.
A lost/partial transport reply preserves the durable outcome for reconciliation.

The configured lifetime defaults to 900 seconds. A smaller integral positive
value is admitted; a value above 900 refuses construction rather than clamping.
Issue and renewal take the earliest caller-authority, known vendor and configured
bounds. Consumed time never decreases within the controller, and its watermark
is retained in durable transactions. The default clock projects elapsed
monotonic time from its consumed-time anchor so a wall-clock step back cannot
extend an in-process lease. An injected clock owns that same progression
contract. This is source-level rollback containment;
qualified time, boot/restore continuity and installation of the real time reader
remain mandatory independent gates.

The revocation poll returns `{verdict,revocation_sequence}`. Explicit originating
binding or caller-chain revocation and an active hold report `revoked`;
unreadable evidence reports `unavailable`. The provider supplies the baseline
sequence representation, including its still-unpublished unavailable encoding
(accepted section 10); the broker invents no second encoding. The numeric
sequence in tests is a fixture, not a publication of that open format.

Requests follow baseline method deadlines: 30 seconds for issue, 8 for renewal,
2 for other calls; typed refusal writes have a fresh bounded 2-second budget.
An idle service-protocol connection closes after 30 seconds. Socket capacity
remains bounded; this does not qualify denial-of-service resistance. There is
no arbitrary 256-lease limit or eviction of durable retry evidence; the existing
protected record-size ceiling fails closed on exhaustion. Production retention
and resource admission are explicit activation gates: a durable account hold
must remain placeable at exhaustion, with protected hold headroom. There is no
retention or reserved hold capacity in this source slice.

An unrelated journal-write failure currently fences the whole controller.
Only an identical retry of its pending hold can reconcile in-process; other
holds can be unavailable until restart. Account-scoped failure isolation and
hold availability during degradation remain open integration work.

## Whole-account containment

`account.hold` uses only fixed service identity, its own recorded lease, lease
state and time, exact account match and the closed reason `leak_match`, in that
order. It does not recheck caller grants, caller binding currentness, use-authority
availability or vendor expiry. A service's recently ended lease also qualifies
through the inclusive configured lifetime window: expiry uses its recorded
`authorized_until`, and release uses the durable transition time. Missing end
evidence or a stale window refuses `lease_not_active`. Revoked transitions are
not synthesized; an unreadable revocation end time grants no window.

A hold has a random identity and is durable before its reply. Persistence
uncertainty returns `account_hold_unknown`; the gateway must stay closed and
retry the same operation. An identical retry reconciles the protected journal
and re-confirms durability even without a broker restart. Retry returns the
recorded hold without creating a second hold. Hold placement changes neither account state nor lease records;
issue and renewal refuse `account_hold_active`, and the poll reports `revoked`
for every principal leasing that account. A known hold is listed to the existing
owner/operator/observer read roles as typed metadata only. Lift requires the
account owner, a confirmed operator act and that exact active hold ID; absent or
mismatched holds refuse `account_hold_not_found`. Lift revives no ended lease.

The shipped legacy manager implements only Codex external-token accounts and
refuses the Claude harness. It supplies no exposed Claude path to interlock or
fall back to. Any future exposed Claude implementation must apply accepted
section 1 at initial and final admission; this slice introduces no speculative
policy encoding or new account mode member to claim that integration.

## Worker fixture and remaining gates

`internal/claudeworker.Profile` is an inert environment fixture. Its prefix and
variable spelling are fixture choices; accepted section 7 leaves production
placeholder creation, format, delivery, mapping and disposal to the gateway.
The process test plants a synthetic credential source in the actual parent
environment and proves the child sees only the constructed fixture environment.
It does not qualify a real Claude release or prove absence of native login
files, config sources, arbitrary argv or inherited descriptors. Production
pre-exec inspection and containment remain separate gateway/executor work.

Broker hold, consumer-use closure, session stop, alert and vendor invalidation
are separate outcomes. This source grants no live enrollment, account access,
deployment, gateway matcher, native stop controller or vendor action. Production
requires the protected user-manager and authority readers, trusted-time and
restore fences, operator command, gateway listener/mapping, matcher inventory,
exact harness/vendor qualification and service isolation. Serialization/runtime
string copies are not claimed to be cryptographically erased.

## Validation tools

Source the task's private Go environment before each Go command. HOME, cwd,
configuration and caches must be physical absolute task-owned paths. Set
`TMPDIR` and `GOTMPDIR` to the authorized task scratch, unset `GOTELEMETRYDIR`,
and capture standalone command output and real exits under `.temp/`.
Set `GO` to the same absolute executable used for the commands: fixture helper
builds invoke that variable directly. This task uses `GO=/usr/bin/go`:


```sh
gofmt -w internal/service internal/claude internal/claudeworker internal/server/services.go internal/server/services_linux_test.go internal/wire/service.go internal/wire/types.go
go vet ./...
go build ./...
go test -v -p=1 -count=1 -timeout=20m ./...
go test -race -v -p=1 -count=1 -timeout=20m ./internal/service ./internal/claude ./internal/server ./internal/wire ./internal/claudeworker
```

The fix-round handoff maps every changed finding to commits, named positive and
negative controls and narrowing source-overlay plants. Plants must fail at a
named assertion; compilation or setup failures receive no kill credit. Fixture
success supplies no production activation or native qualification evidence.
