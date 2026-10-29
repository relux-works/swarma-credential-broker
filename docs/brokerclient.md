# Importable v0 clients and static allowlist observation

Linux consumers import
`github.com/relux-works/swarma-credential-broker/brokerclient`.
This exports the existing `codex-refresher-v0` version 1 worker contract and the
finite `allowlist.check` extension. It is not signed-grant evaluation,
`revocation.check`, `effect.observe` or the proposed secret-free dialect. The
production qualified release set remains empty.

## Separate roles

Protected configuration can explicitly set `policy.observer_uids`. Absent means
no observers. Existing protected-file ownership/mode and closed JSON validation
apply. Observer kernel UIDs must be unique and distinct from the broker UID and
**every** account's `allowed_uids`, including disabled accounts. Collision
refuses configuration load/replacement. Worker admission and the manager also
exclude observers before any lease lookup or queue insertion, including
renewal/release with a known worker lease ID.

The dispatcher receives static-policy metadata only. Acquisition, renewal and
release stay with the worker under its kernel UID. There is no generic
privileged forwarding API or reusable launch permission. Existing `status` is
metadata-only; an observer sees no worker account inventory there.

## Public Go API

`DialObserver(ctx, socketPath, expectedBrokerUID) (*Observer, error)` dials,
verifies the actual Unix `SO_PEERCRED` server UID **before protocol bytes**, then
negotiates hello. These steps share a two-second overall deadline, shortened by
the caller's context. `Observer` exposes only:

```go
Check(context.Context, AllowlistRequest) (AllowlistResult, error)
Close() error
```

Each check has a two-second maximum including gate wait, transport and result
validation. Earlier context cancellation/deadline wins; `Close` interrupts calls.
Nil/zero observers refuse. Failed/partial exchanges close the stream, with no
automatic retry. Errors return a zero result. Request ID, complete tuple,
decision, expected generation and negotiated hello generation must all match.

`DialWorker(ctx, socketPath) (Worker, error)` exports the existing consumer:

```go
VerifyServer(context.Context, uint32) error
Hello(context.Context, HelloRequest) (HelloResult, error)
Request(context.Context, LeaseRequest) (Lease, error)
Renew(context.Context, RenewRequest) (Lease, error)
Release(context.Context, string) error
Close() error
```

Dial is bounded to two seconds and sends no bytes. Required order:
`VerifyServer` using the protected expected broker UID, `Hello` with
`Versions: []int{1}`/`Profile: ProtocolProfile`, then lease operations. Supply a
bounded context to verification too. Existing ceilings remain: hello two
seconds, request thirty seconds, renewal 8.5 seconds including transport
(daemon renewal eight seconds from arrival), release two seconds. Cancellation
can shorten each. Existing account/profile/binding, `launch_id`, null-network
and `credential-injection/1` executor constraints remain. No method is routed
through the dispatcher or bypasses worker admission/final delivery.

Exported types: `Binding`, `HelloRequest`, `HelloResult`, `LeaseRequest`,
`Executor`, `RenewRequest`, `Lease`, `Refusal`, `AllowlistRequest`,
`AllowlistResult`. They reuse existing types and transport. `Lease.Token` is
caller-owned bytes; call `Lease.Erase()` on terminal paths and before replacing
old material. It clears those bytes and drops material-bearing account/plan
metadata. Caller copies, immutable strings and Go runtime copies cannot be
proven erased by it. Never log/serialize lease payloads through the dispatcher.

## Closed wire shapes

Frames retain the four-byte big-endian length and maximum 65536-byte canonical
JSON object, with existing hello and request ID semantics. The schema below
uses placeholders, not actual binding values:

```text
request = {
  "method": "allowlist.check", "request_id": <ASCII string, 1..64 bytes>,
  "params": {
    "target_uid": <uint32>, "account": <local account label>,
    "profile": <profile>, "harness": "codex_cli", "channel": "external-token",
    "credential_binding": {
      "digest": <exact protected tuple digest>, "harness": "codex_cli",
      "profile": <profile>, "account": <local account label>,
      "channel": "external-token", "endpoint": <protected endpoint>,
      "executable_sha256": <protected executable digest>,
      "policy_generation": <served generation>
    },
    "expected_policy_generation": <served generation>
  }
}
success = {
  "request_id": <same ID>,
  "result": {"tuple": <complete exact params>,
             "policy_generation": <actual served generation>, "decision": "allow"}
}
refusal = {
  "request_id": <same ID, or null for existing terminal peer/framing refusal>,
  "error": {"code": <closed profile code>, "message": "request refused", "details": {}}
}
```

Every tuple/binding member is required. Nulls, unknown members, duplicate keys,
malformed frames/JSON, missing/both result/error, unexpected decision, wrong ID
or generation refuse or close. Closure is a typed client error, never allow.
Success has no lease ID, token, vendor-account ID or credential payload. The
binding digest is the existing **static tuple** digest, not a credential hash.

| New code | Meaning |
|---|---|
| `allowlist_not_authorised` | Peer is not an explicitly configured observer |
| `allowlist_generation_mismatch` | Expected generation differs from served policy |
| `allowlist_tuple_mismatch` | Target UID/account/profile/harness/channel or exact binding is not admitted |
| `allowlist_unavailable` | Static source is not ready/readable/equal, or client exchange/result is untrusted |

Existing closed v0 codes can also occur, including terminal
`peer_identity_unavailable`, `role_not_permitted`, `frame_too_large`,
`version_unsupported`, `server_identity_mismatch`, `request_deadline_exceeded`,
`lease_not_authorised` and `lease_owner_unavailable`. Client decoding retains the
existing finite v0 code vocabulary, fixed message and empty-details requirement;
unknown codes/raw diagnostics become sanitized failure. `*Refusal` exposes only
`Code` and process `Status`, never raw socket or source errors.

## Served generation and the observation-to-use race

The manager compares `expected_policy_generation` to its immutable **served
static snapshot**, checks target admission, exact binding/harness/channel and
configured release/qualification reference. Binding and result contain that
same generation; the client additionally matches the hello epoch.

For every observation the standalone daemon re-reads protected configuration,
requiring its entire policy/socket/store configuration to equal the served
snapshot. Unreadable, malformed, unprotected or different source refuses. This
does **not** auto-reload it: existing SIGHUP publishes a validated strictly newer
generation and closes old connections. Invalid reload leaves the old snapshot;
the per-check source comparison prevents observing it as equal to a changed or
unreadable file. Manager transition/failed generation persistence refuses.
After source I/O the manager rechecks generation; response publication uses the
existing generation cancellation fence without holding state locks across I/O.

Internal embedders with mutable file-backed policy must install `ObservePolicy`.
Nil means an immutable in-memory static source and makes no disk-freshness
claim. Neither form reads account material, invokes refresh, creates/changes a
lease or evaluates mutable grants/revocation. Owner/store runtime health and
network enforcement are not established by static admission.

Policy or disk can change after observation or its last source read. A success
is not a permit or proof a later lease can be acquired. The dispatcher rechecks
and journals intent at its launch join; actual worker acquisition and final
delivery keep their independent current checks. Unknown/unsupported tuple or
generation never becomes allow through absence or cached observation.

## Focused validation

Run changed observer/client tests with the selected Go executable:

```sh
"$CURATOR_GO" test ./brokerclient ./internal/policy ./internal/lease ./internal/server ./internal/runner ./cmd/swarma-credential-broker -run '^(TestAllowlist|TestObserver|TestExternalBrokerConsumer)'
```

Use the required host resource wrapper for multi-package checks. Fixtures use
synthetic owners/policies and isolated sockets. Short isolated test roots avoid
Unix socket pathname limits and preserve the production directory checks.
Positive caller-UID cases use a declared peer seam; real kernel server pinning
and ordinary-worker refusal are separate tests. No cross-UID deployment or
provider qualification follows. Complete logs/control evidence remain private.
