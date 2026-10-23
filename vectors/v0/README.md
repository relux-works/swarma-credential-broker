# Codex refresher profile vectors

These are declarative contract fixtures for the proposed
[profile](../../spec/v0-codex-refresher.md#7-profile-specific-broker1-subset).
They are not implementation test results or vendor-release qualification.
Tokens are synthetic; identity roles resolve through private test configuration.
No real login or endpoint is used.

Each `.json` file is exactly one CCJ-1 canonical object, UTF-8, with **no trailing
newline**. It is an artifact, not a socket frame. For a request, serialize its
instantiated `request` object canonically and prefix its byte length as unsigned
uint32 big-endian; never send the fixture wrapper, `setup` or `expect` over the socket.
An envelope has no `sig` field. Consult
[broker §13.1](../../spec/broker.md#131-transport) for the transport and the
[CCJ-1 definition](https://github.com/relux-works/curator-spec/blob/main/protocol/registry.md#1-curator-canonical-json-1)
for rejection and string/number rules.

`fixtures.json` defines `base`, the protected fake policy/lease/store context,
and a `lease_request` **template**. Every case begins with a fresh copy of base;
`setup` overrides only the listed facts. These wrappers are canonical artifacts,
not ready-to-send wire bytes. Fields describing events instruct the driver,
never the broker. Each negative case's `control` names its positive control;
expected verdicts come from the profile, not implementation agreement.

Identity roles `broker`, `allowed_peer` and `foreign_peer` resolve from protected
test configuration, through the OS account database. There are no shipped UID
numbers, account names or UID-bound hashes. Require foreign_peer to differ from
both other UIDs; broker and allowed_peer may coincide only in declared same-user
R2 mode. Verify each launched process runs as its configured account. Missing,
forbidden aliasing or unusable accounts produce **PENDING**, no qualification
credit and qualification exit 69, never skipped-as-pass. Genuine peer tests connect client
processes started as the configured allowed/foreign accounts to the candidate's
Unix socket and assert the kernel-derived `SO_PEERCRED` behavior (§8.1). A
model-only role run cannot qualify that behavior. Do not publish the account
mapping or resolved UID values, and do not create substitute accounts or weaken
socket permissions for tests.

Instantiation is explicit and performed only in private test setup:

1. Resolve `broker_role`, `peer_role` and `allowed_peer_roles` into the driver's
   numeric context. Replace each exact `{resolve_uid: "allowed_peer"}` marker
   in expected hello results with that role's resolved integer UID.
2. For each binding object containing `{derive: "binding_sha256"}` as `digest`,
   form the §7 tuple from that binding's other members plus `uid` resolved from
   the case's `peer_role`. Serialize that tuple as CCJ-1 UTF-8 with no newline;
   compute SHA-256 and replace the marker with 64 lowercase hex. Do this for
   baseline and each request binding independently after all setup overrides.
3. Only then serialize the request object and frame it. No role, resolver or
   derivation marker may reach the socket. Recompute the expected digest
   independently from the resolved UID and complete §7 tuple; publishing a
   model digest does not establish a genuine peer test.

Base has a fresh connection and `prior_hello_success: false`. A request case's
`setup.handshake` states its reachable entry path: `hello_then_request` first
completes a new allowed hello, then sends the listed request; `request_is_hello`
sends that hello as the first frame. `peer-denied` uses `connect_only`, as the
foreign account absent from every enabled policy entry, with no client bytes
or prior hello. It expects an accept-time terminal null-ID refusal, zero reads,
zero processed requests and no lease/material/writer. `peer-allowed` completes
hello then leases. Header/raw-first-frame cases start fresh without hello;
runner/lifecycle cases model local procedures, not an authenticated socket.
`header_only` writes the advertised uint32 length without a body; `partial_header`
decodes `header_hex` and then half-closes if specified. `raw_first_frame` sends
UTF-8 `raw_payload` with its actual byte length, without canonicalizing the
intentionally malformed bytes. No vector inherits successful admission contrary
to its overridden policy.

The known `other_account` exists but is not allowlisted to allowed_peer.
For `owner-mismatch`, `other_peer_is_policy_admitted` explicitly admits
foreign_peer to that other account/profile; its fresh hello therefore succeeds,
while the original lease remains owned by allowed_peer. `request_account` is
already expanded in the template. Authorization cases intentionally fail before
binding digest validation. `concurrent_requests`
means distinct lease IDs, each with the same initial last-delivered token;
`request` is their template, not duplicate requests for one lease. The
qualification target is many launches sharing **one account**. The load-overflow
fixture holds the current attempt open until all 65 arrivals are counted, so the
64-operation queue boundary is deterministic; concurrency alone cannot force overflow. `queued_waiters` counts distinct pending
lease operations; duplicate response waiters are separately capped at two per
operation.

`expect.error_code` is a daemon refusal. For a validated request it requires
`{request_id, error: {code, message, details}}` with the same validated ID.
An explicit `expect.request_id: null` requires the §7 connection-level terminal
frame, empty details, at most 512 payload bytes and close within 2 seconds;
no correlation is obtained by reading client input. A reading fixture client
must receive that complete frame. This covers accept-time denied/unavailable
peer identity and header-only oversized length. Zero length, truncated input
and malformed first frames instead expect `response_frames: 0` and close;
apparent IDs in malformed bytes are never reflected. All messages are fixed
sanitized text. `local_code` is a runner/administrative refusal before a lease.
`result` gives exact successful result members; `result_kind: "lease"` requires every success member
in profile §7, the requested account, synthetic payload and unchanged limit on
renewal. Other expected fields assert instrumented post-state/counters. No
refusal may contain a payload. Terminal failures MUST also leave the recorded
post-state; an arbitrary crash or timeout is not the expected rejection.

| File / cases | Claim and observable limits |
|---|---|
| [fixtures.json](fixtures.json) | Closed baseline, matching executable and privately derived binding digest; synthetic tokens and finite authorization. This contains no real credential. |
| [admission.json](admission.json): peer-denied / peer-allowed | Configured foreign process is refused at accept with no reads; allowed process completes hello and leases. Model runs alone do not qualify kernel identity. |
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
| [transport.json](transport.json): frame-oversized / frame-valid; profile-unsupported / profile-v0; status-scoped | Oversize length is checked before body read, with null-ID terminal error; profile negotiation cannot silently change authority model; status exposes only admitted metadata. |
| transport: frame-zero-length / frame-valid; frame-truncated-header / frame-valid; frame-malformed-first / frame-valid | Invalid first input closes without response or request effects; valid hello returns its ID. |
| transport: peer-identity-unavailable / frame-valid | Injected missing kernel identity fails at accept with null ID and no input reads; available identity permits hello. Injection is model-only. |

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
references and private binding derivation, and plants known duplicate/noncanonical
inputs to check its own rejection path. Passing those artifact checks proves the vectors
are well formed; it does not run the proposed daemon, runner or lifecycle.
