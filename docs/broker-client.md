# Runner broker client and protected authority

The existing worker contract is now importable through
[`brokerclient`](brokerclient.md), alongside its separate read-only static-policy
observer. That observer cannot acquire, renew or release a worker lease.

> **Proposed secret-free mode (inactive):** This legacy client receives real payloads under static policy. A future agent client receives only placeholders; credential-holding services need separate protected policy and their own lease plus the original caller authority. Closed validation/cleanup remain; no new wire fields are admitted here.
> See [the separate contract](../spec/secret-free-mode.md#4-two-current-authorities-per-use).

The Linux runner uses `SocketClient` for the profile's Unix transport and
`ProtectedDependencies` for static policy. The standalone command reads
`/etc/swarma-credential-broker/config.json`; it has no policy, UID, socket or
qualification selector in its command line or environment. Embedders choose
that operator-owned file when constructing dependencies. It is the same
`policy.Config` loaded by the daemon, with the same broker-owned regular 0600,
no-final-symlink and closed-member checks. The current reader supports the
same-user R2 deployment. An unreadable dedicated-service policy refuses; this
slice creates no public copy or weaker file permissions.

Each authority resolution rereads that file, derives the requesting UID from
the kernel process identity, checks the account/profile allowlist and computes
the binding with `policy.Binding`. It uses the policy's executable/digest,
endpoint, vendor account ID, broker UID and generation. Connect rereads the
configuration and requires equality with the resolved snapshot before using its
socket path. The runner retains its post-lease authority/configuration recheck.
Regular-file reads cannot establish a bound on a stalled filesystem; contexts
are checked before and after them.

The production qualified set comes from the protected list and evidence beside
static configuration, through the common daemon/runner reader. A nonempty
`qualification_id` does not qualify anything. Current version, schema, applied
properties and model-catalog observers are unavailable, so production still
refuses `lease_harness_unqualified` (69) before a lease request or start of the
runner's leased application session. During resolution, the common reader may
run native candidate measurements, beginning with `--version`, before reading
the published qualification list, provided the protected repository root and lock
are
accessible and no admission fence is present. These isolated measurements may
include schema helpers and a catalog app-server process
(`app-server --listen stdio://`), even if another unavailable measurement
ultimately causes qualification to refuse. The runner's separate version
probe follows successful qualification; the lease request follows broker
admission, and starting the runner's leased application session requires both
qualification and admission. The isolated measurement processes do not establish
admission for that session. See [qualification](qualification.md) for the exact
record, publication and observer contract. Fixture observers and constructors
exist only in tests; the command cannot select them. The shipped owner remains stopped independently.

## Wire validation

Framing, canonical bytes and structural decoding all reuse `internal/wire`.
There is no second CCJ-1 implementation. The connection is close-on-exec, and
`SO_PEERCRED` must match the protected broker UID before any protocol write.
One exchange at a time owns the socket; queued callers share their original
call deadline. IDs increase monotonically and cannot collide among outstanding
calls. Close interrupts both socket I/O and queued callers. A partial frame,
EOF, correlation failure, malformed response or cutoff closes the uncertain
stream; it is never retried on that connection. If a write fails, the same
exchange reads one frame within its existing deadline and wire size bound. Only
a complete, canonical null-ID terminal error can retain its code on that path;
all other responses keep the phase's transport refusal. The stream then closes,
without retry or reconnect.

| Response | Required members and semantic checks |
|---|---|
| Envelope | Exactly `request_id` and one of `result` or `error`; string ID must match the outstanding request; no null result/error |
| Terminal envelope | Only a null-ID error with `peer_identity_unavailable`, `role_not_permitted` or `frame_too_large`; at most 512 bytes; closes the client connection |
| Error | Exactly `code`, `message`, `details`; a closed profile code, fixed `request refused` message and empty object details; all non-null |
| Hello | Exactly `version: 1`, `profile: codex-refresher-v0`, `principal: {uid}` matching the client's kernel UID, and positive `policy_generation` |
| Request/renew lease | `lease_id`, `account`, `harness: codex_cli`, `channel: external-token`, `payload`, `token_expires_at`, `authorized_until`, `renewable: true`; nonempty ASCII ID up to 128 bytes; request account or renewed lease ID must match |
| Lease payload | `channel: external-token`, nonempty `access_token`, nonempty `chatgpt_account_id`; optional string `plan_type`, never null |
| Times | RFC 3339 UTC whole seconds with `Z`; offsets and fractional seconds refused |
| Release | Exactly the requested `lease_id` and `state: released` |

Unknown, duplicate, missing, incorrectly typed and null members are refused,
including nested members. The runner additionally checks expiry, exact vendor
account identity and unchanged lease/account/authorization limit on renewal.
Token bytes transfer to the runner; the adapter keeps no material cache and
clears owned response buffers and unsuccessful results. The wire reader clears
its mutable body allocation before returning a partial-read or canonical-parse
failure. Runtime/JSON immutable copies prevent a physical memory-erasure claim.

## Refusal and deadline mapping

All codes below preserve their typed code; the phase determines the exit status.
No response message, details or raw frame is printed. Unknown codes fail
validation, rather than being translated into a known daemon refusal.

| Profile refusal codes | Hello/request | Renew/release |
|---|---|---|
| `peer_identity_unavailable`, `server_identity_mismatch`, `role_not_permitted`, `frame_too_large`, `version_unsupported`, `request_deadline_exceeded` | 69 | 75 |
| `account_exists`, `account_unknown`, `account_duplicate`, `account_store_keyring_refused`, `enrol_material_invalid` | 69 | 75 |
| `lease_not_authorised`, `lease_account_unknown`, `lease_harness_mismatch`, `lease_account_revoked`, `lease_reauth_required`, `lease_owner_unavailable` | 69 | 75 |
| `lease_channel_unsupported`, `lease_harness_unqualified`, `lease_binding_mismatch`, `lease_network_enforcement_unavailable`, `lease_not_owner`, `lease_not_active` | 69 | 75 |
| `renew_not_current`, `renew_timeout`, `renew_failed`, `external_token_init_failed`, `credential_source_conflict`, `credential_injection_unavailable` | 69 | 75 |
| Malformed/unknown response or transport loss | `credential_injection_unavailable`, 69 | `renew_failed` or `lease_owner_unavailable`, 75 |
| Local renewal cutoff | — | `renew_timeout`, 75 |

The runner's own observed execution stop still follows the normative status
precedence in [runner.md](runner.md#normative-exit-classification). Local adapter
deadlines do not create an execution deadline status.

Hello has two seconds, request thirty seconds and release two seconds, each
shortened by the caller's context and including gate wait. Renewal uses the
runner's 8.5-second callback transport cutoff, preserving the daemon's independent
eight-second budget from arrival and the runner's nine-second reply bound.
The existing total cleanup budget can shorten release further. No method
reconnects or repeats an uncertain request. Repeated release on a healthy
connection sends the same lease ID and validates the daemon's durable receipt.

A timed-out owner operation may remain unresolved in the daemon. In that state
the cleanup release can itself receive `renew_timeout`; the runner reports
`lease_release_failed` (75), preserves old output and leaves the original bounded
lease. A client cannot invent a release receipt or start a second refresh.

## Validation

The ordinary runner tests cover the real daemon/lease engine with a synthetic
owner and the existing fake app-server, completed refresh/release, the stopped
owner, deadline refusal and failed cleanup. They check durable lease state,
process absence, token redaction, child argv/environment and inherited sockets.
Wire tests pair structural/semantic failures with positive responses, cover every
closed refusal, cancellation, earlier cutoffs, default renewal cutoff,
connection loss in each phase, and serialized concurrent IDs. Full race-run
logs are also scanned for the fixture canaries, including daemon stdout/stderr.
These fixtures grant no production release qualification.

The separate configured-identity gate uses the README's protected
`BROKER_TEST_PEER_CONFIG` format and the same helper installation rules:

```sh
"$CURATOR_GO" test -c -race -tags=peeraccounts -o "$TMPDIR/client-peercheck" ./internal/runner/peercheck
"$TMPDIR/client-peercheck" -test.run '^TestConfiguredClientPins$' -test.v
```

Run provisioning and execution through the installation's shared heavy slot.
The allowed peer is a genuine distinct process connecting to the real daemon.
A separately configured foreign peer serves a socket: a wrong broker UID pin
must send no bytes, while the correct pin negotiates successfully. Missing
configuration or unusable identities return 69/PENDING; assertion failures
return 1. Numeric identities and helper locations stay in private evidence.
Same-UID R2 is covered separately by the ordinary daemon/runner integration.
