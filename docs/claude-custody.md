# Claude secret-free service source slice

Core's binding S3a decisions resolve the two earlier STOPs. For a launch whose
machine policy selects secret-free, material reaches only the current gateway
service principal. A worker receives `ANTHROPIC_BASE_URL` and a placeholder;
readable-token lanes require their own explicit selection and qualification.
Failed secret-free admission never selects an exposed fallback.

The architecture references remain `book/ru/09-uchetnye-dannye.md`, sections
"Режим без секретов у агента" and "Растяжка утечки", [mode §§2–5,10](../spec/secret-free-mode.md),
[gateway §§2,6,7](../spec/secret-free-gateway.md), and
[adapters §3](../spec/secret-free-adapters.md). The implementation follows Core's
`CORE-S3A-DECISIONS.md` delivered with the task while Core publishes
`spec/secret-free-service-v0.md`. This source slice does not activate a deployed
service or revise those specifications. Every unresolved choice is explicitly
marked `SPEC-PENDING` in code and summarized below.

## Custody and authority

`internal/claude.Account` owns a protected account store: fresh opaque enrollment,
optional exact vendor expiry, metadata-only status, durable account hold and
owner-gated lift primitives. It has no refresh, native-login import, account
export command, agent home file or material environment path.

`internal/service.Broker` consumes this custody and a mandatory `Authority`.
The latter resolves the kernel-observed UID to a current managed principal,
checks the gateway's service generation/account/kind/policy authority and
**independently** checks the originating agent generation/launch/account's
current narrowing authority and machine-selected secret-free local lane.
`Authority.WithCurrent` must keep all facts, revocations, policy and qualified
time evidence stable through its callback, including the actual socket write;
replacement must exclude or interrupt ongoing writes before settling. A static
UID, request field, placeholder or a past observation is not this provider.
There is no accepting production reader or automatic activation. Integrators
must implement the protected user-manager contract and qualify that settlement.

The source controller implements:

- Operator-only `service.bind`/`service.unbind` for `credential-gateway`, current
  managed UID/generation, account, `claude-oauth-token` and policy digest.
  Protected CAS records retain removal tombstones. Rebinding revokes old leases.
- `service.lease.request` with originating account, agent UID/generation and
  launch ID. Issue and renewal check both authorities and account state before
  entering material custody. `V0LeaseCeiling` is **900 seconds**; the exclusive
  deadline is also bounded by each authority and any known vendor expiry.
- Gateway-only publication inside both the authority gate and account lock.
  Material is never returned by `Call`; only its transport callback receives
  the lease. A cancelled, expired, held or stale request refuses before release.
  A partial/failed write revokes that lease locally; no retry success is inferred.
- `service.revocation.check` is a metadata-only poll. `not_revoked` is a
  point-in-time observation; unavailable evidence remains `unavailable`, never
  permission. Explicitly ended or expired leases report `revoked`.
- `account.hold` accepts only the current lessee service with `leak_match`.
  All account leases close, protected hold publication finishes durably, then
  acknowledgment is constructed. Persistence failure is UNKNOWN with no success
  reply. Only the authenticated account owner can lift; lift revives no old ID.

The existing `server.Server` listener and framing carry `broker/1`; no second
socket or deployment UID is introduced. Hello takes no client role. The fixed
connection principal is revalidated on every call, so recycling its UID or
replacing its generation inherits nothing. The legacy Codex profile remains
separate. The standalone daemon installs no service controller until protected
reader/installation/qualification are supplied; its existing closed owner is
unchanged. This is source and synthetic boundary evidence, not installed use.

## SPEC-PENDING choices

The following details are chosen provisionally and marked at their code sites:

1. Hello profile spelling `broker/1`, JSON object/field layout, material response
   `token` string, `authorized_until` RFC3339Nano representation, renewal/release
   names and `account.hold.lift`; no placeholder field is accepted by the broker.
2. Opaque generation strings, lowercase 64-hex policy digests, principal record
   shape, operator/owner record integration and owner act/confirmation format.
3. Protected user-manager and independent-authority reader, qualified-time
   evidence and final-publication settlement contract. The interface is a
   mandatory closed integration seam, not a substitute record reader.
4. Local binding/tombstone schema and revisions; each accepted bind, even an
   identical rebind, creates a successor and ends all prior account leases.
5. Volatile lease records: process replacement restores no leases. Random
   128-bit IDs, capacity 256 including ended tombstones, and uncertain-write
   recovery stay conservative until publication; capacity exhaustion refuses.
6. Existing fixed refusal-code reuse and poll result vocabulary
   `not_revoked`/`revoked`/`unavailable`.
7. Serial calls per service connection, a two-second call/material budget and
   a fresh two-second bound for a typed refusal write after a failed call.

## Worker environment and containment limits

The earlier `internal/claudeworker.Profile` still constructs only fresh
nonsecret placeholder environments with exact final-composition validation. Its
Linux child fixture inspects actual argv/environment/output and rejects a
material-bearing candidate before spawn. The broker neither generates nor
observes a placeholder mapping. Gateway listener authentication, routing,
matcher inventory and response filtering belong to the gateway contract.

A broker hold, consumer-use closure, session stop, alert and vendor invalidation
are separate outcomes. This slice implements broker lease denial and polling,
not a gateway matcher, native stop controller or vendor action. Exact Claude
release, subscription billing, kernel isolation, protected installation and
production time/current-generation settlement require separate qualification.
Fixture tokens have an obvious fake prefix; no real token/account is used.
Go byte buffers are cleared; serialization/runtime string copies are not claimed
to be cryptographically erased.

## Validation

Source the task's private Go environment before any Go command, with physical
absolute HOME/cwd and private caches. Set both `TMPDIR` and `GOTMPDIR` to the
authorized absolute task scratch and unset `GOTELEMETRYDIR`. Capture standalone
commands and real exit codes under `.temp/`:

```sh
gofmt -w internal/service internal/claude internal/server/services.go internal/server/services_linux_test.go internal/server/server.go internal/wire/service.go
go build ./...
go vet ./...
go test -v -p=1 -count=1 -timeout=20m ./...
go test -race -v -p=1 -count=1 -timeout=20m ./internal/service ./internal/claude ./internal/server ./internal/wire ./internal/claudeworker ./internal/store ./internal/qualify
```

The named refusal/control fixtures cover roles, binding/generation replacement,
each authority independently, deadlines, lease revocation, non-lessee hold and
non-owner lift, durable-before-reply hold, final publication exclusion and
non-gateway process/environment secrecy. Source-overlay plants independently
weaken each authority, the ceiling, role permission and hold ordering; the task
handoff records their exact tests, exit codes and bounds. None supplies live
vendor, installed reader or production-release qualification.
