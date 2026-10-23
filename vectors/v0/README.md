# Codex refresher profile vectors

These are declarative contract fixtures for the proposed
[profile](../../spec/v0-codex-refresher.md#7-profile-specific-broker1-subset).
They are not implementation test results or vendor-release qualification.
Every token and identity is synthetic. No real login or endpoint is used.

Each `.json` file is exactly one CCJ-1 canonical object, UTF-8, with **no trailing
newline**. It is an artifact, not a socket frame. For a request, serialize its
`request` object canonically and prefix its byte length as unsigned uint32
big-endian; never send the fixture wrapper, `setup` or `expect` over the socket.
An envelope has no `sig` field. Consult
[broker §13.1](../../spec/broker.md#131-transport) for the transport and the
[CCJ-1 definition](https://github.com/relux-works/curator-spec/blob/main/protocol/registry.md#1-curator-canonical-json-1)
for rejection and string/number rules.

`fixtures.json` defines `base`, the protected fake policy/lease/store context,
and a complete `lease_request`. Every case begins with a fresh copy of base;
`setup` overrides the listed facts only. Fields describing events instruct the
fixture driver, never the broker. For `request` cases, a prior successful hello
is assumed except for hello/transport cases. Each negative case's `control`
references the adjacent positive case; all expected verdicts come from the
profile, not agreement between implementations.

The known `other_account` exists but is not allowlisted to the base peer.
`other_peer_is_policy_admitted` admits the mismatching peer to a different
account so ownership, rather than connection admission, is exercised.
`request_account` is already expanded in request bytes. Authorization cases
intentionally fail before binding digest validation. `concurrent_requests`
means distinct lease IDs, each with the same initial last-delivered token;
`request` is their template, not duplicate requests for one lease. The
qualification target is many launches sharing **one account**. The load-overflow
fixture holds the current attempt open until all 65 arrivals are counted, so the
64-operation queue boundary is deterministic; concurrency alone cannot force overflow. `queued_waiters` counts distinct pending
lease operations; duplicate response waiters are separately capped at two per
operation.

`expect.error_code` is a daemon refusal: response must be
`{request_id, error: {code, message, details}}`, with matching code and correlation,
fixed sanitized message and empty details. `local_code` means the runner or
administrative procedure refuses before any lease call. `result` gives exact
successful result members; `result_kind: "lease"` requires every success member
in profile §7, the requested account, synthetic payload and unchanged limit on
renewal. Other expected fields assert instrumented post-state/counters. No
refusal may contain a payload. Terminal failures MUST also leave the recorded
post-state; an arbitrary crash or timeout is not the expected rejection.

| File / cases | Claim and observable limits |
|---|---|
| [fixtures.json](fixtures.json) | Closed baseline, matching executable and binding digest; synthetic tokens and finite authorization. This contains no real credential. |
| [admission.json](admission.json): peer-denied / peer-allowed | Kernel UID drives authorization; no request identity can substitute. Refusal creates no lease/writer. |
| admission: account-denied / account-allowed; account-unknown / account-known | Per-account allowlist and unknown-label refusal; no fallback or account creation. |
| admission: release-unqualified / release-qualified | Absent release qualification blocks admission even for matching version text. |
| admission: source-conflict / source-clean; home-auth-present / home-auth-absent | Runner refuses reserved sources and a credential path/link before any broker call; no file read and no silent overwrite. Positive external login leaves the credential path absent. |
| [renewal.json](renewal.json): renew-unknown-digest / renew-superseded | Arbitrary digest is rejected; a previously delivered but superseded token receives the newer owner token with zero refreshes. |
| renewal: renew-contention / renew-single | Eight rejected leases cause exactly one rotation and equal renewed payloads; positive control handles one caller. No universal concurrency proof is claimed. |
| renewal: renew-late / renew-in-budget | 8001 ms returns one timeout, no late payload/callback, runner interrupts; 100 ms yields one correlated answer. Boundary scheduling and 10-second vendor behavior require separate executable probes. |
| renewal: queue-full / queue-slot | 64-waiter bound; overflow starts no writer; one available slot joins existing work. |
| renewal: load-overflow / load-at-bound; fifo-starvation / fifo-progress | 65 arrivals against 64 held slots produce one overflow; 64 admitted callers share one refresh; earlier waiters are not displaced by later arrivals or proactive work. |
| renewal: lease-capacity / lease-capacity-available; many-lease-release / many-lease-independent | 256 active-record bound and no cross-lease release/renew mutation for many same-account launches. |
| renewal: owner-mismatch / owner-match; lease-ended / lease-live; release-idempotent | Lease ownership, terminal renewal refusal, unchanged authorization limit, duplicate release. |
| renewal: time-untrusted / time-trusted | Untrusted time cannot advance watermark or deliver material; trusted baseline permits a finite lease. |
| [lifecycle.json](lifecycle.json): daemon-death / normal-stop; replacement-contention / resolved-replacement | Replacement cannot outrun a surviving child/descendant or unresolved attempt; all writers remain serialized. |
| lifecycle: rotation-crash / rotation-committed | External rotation before persistence is ambiguous despite process absence; only durable correlated success admits active state. |
| lifecycle: cleanup-interrupted / cleanup-confirmed; absence-unreadable / absence-complete | Kill without confirmation and partial/denied reads remain unknown; complete same-attempt observations permit reconciliation. |
| lifecycle: store-missing / store-current; store-rollback / store-reconciled | Missing or stale state cannot yield stale-token success or blind retry; independent freshness evidence is required after restore. |
| lifecycle: transient-ambiguous / transient-safe | Timeout is not safe non-rotation; positive absence, reload and conclusive failure permit transient backoff. |
| lifecycle: reenrol-unresolved / reenrol-resolved; duplicate-account / distinct-account | New login waits for writer resolution; one vendor account has one active broker mapping. |
| lifecycle: cutover-old-writer-live / cutover-old-writer-absent | New enrolment waits for old refreshers to be confirmed absent while the old native login remains untouched. |
| [transport.json](transport.json): frame-oversized / frame-valid; profile-unsupported / profile-v0; status-scoped | Length is checked before body read; profile negotiation cannot silently change authority model; status exposes only admitted metadata. |

Lifecycle vectors require a fixture driver with a fake vendor endpoint and
controlled durable-store/service-manager faults. They do not require real
accounts. The device ceremony, actual rotation, policy fetch, effective source,
child inheritance and selected release/platform remain pending live
qualification under profile §8. Additional negative pairs (initialization and
thread resume, complete framing/parser rejection corpus, release after expiry,
store-loss variants) are specified in §9; this small corpus is not exhaustive.

For syntax only, from the repository root:

```sh
python3 -c 'import glob,json; [json.load(open(p)) for p in glob.glob("vectors/v0/*.json")]'
```

The delivery check additionally compares exact bytes with strict CCJ-1 encoding,
rejects duplicate keys and invalid numbers/Unicode, verifies fixture/control
references and binding digest, and plants known duplicate/noncanonical inputs to
check its own rejection path. Passing those artifact checks proves the vectors
are well formed; it does not run the proposed daemon, runner or lifecycle.
