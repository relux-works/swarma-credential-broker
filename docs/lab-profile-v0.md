# Lab profile v0: capped Anthropic API key on colony1

**Status: PROPOSED. Design for review, not an executable release or an activation approval.**

**DECLARED CONFLICT — LAB ONLY, NEVER PRODUCTION.** Ivan's decision of
2026-11-20 selects a manual-root lab route instead of the production assembly.
This profile deliberately does **not** satisfy broker section 14's authenticated,
content-signed operator ceremony or `spec/operator-and-activation-v0.md`'s
DN-01–DN-08 implementation. It also takes DN-09 **option C**, not production A.
It replaces those operator mechanisms with commands Ivan runs in his own root
SSH session. It never enables the production daemon, accepts a production
activation document, imports a subscription token, or claims Curator Core
acceptance. The production path remains separate and closed pending its own
acceptance and qualification. Basis: `B:spec/broker.md:880`,
`B:spec/operator-and-activation-v0.md:1373`,
`B:spec/operator-and-activation-v0.md:1737`.

All new command names, schemas, build tags and test names below are **proposed
interfaces to implement**, not commands available at the inspected pins. Sections
6–8 become an execution runbook only after the listed units, released bytes,
native preflight and Ivan's in-person approval exist. This documentation unit
runs no root command, credential operation, release, or Q check.

## 1. Authority, sources and book disposition

The newer decision supersedes the supplied qualification plan's subscription
login and snapshot-reset steps **for this lab only**. The account is a dedicated
Anthropic **API key with an owner-set spend cap**, never Ivan's subscription or
`claude setup-token` output. Ivan creates and enrolls it himself. The six Q
requirements remain those in `I:colony1-real-token-qualification-plan.md:35`.

Evidence notation is `alias:repository-relative-file:first-line`; citations
resolve at these immutable inspected commits, not at an older runbook's pins:

| Alias | Source | Inspected revision |
| --- | --- | --- |
| B | swarma-credential-broker | `00e24b83ece1257bc85f988d5c8dda288aeec77d` |
| G | swarma-chain-lab | `87e8a7e41a073f6fb3b6ff2d09299162ee16deb3` |
| M | swarma-user-manager | `7c5e9eebbaf859246d4e5adc600a6727e5773e34` |
| D | swarma-docs | `bc1132c9d9be60864ef7195efa83215357ad3011` |
| I | supplied inputs, retained with the review packet | the six named Markdown inputs, not release authority |

Read together: qualification plan; `RUNBOOK-colony1-qualification.md`;
`RUNBOOK-GAPS-HANDOFF.md`; `BROKER-IMPLEMENTATION-PLAN-v0.md`;
`DECISION-claude-gateway-launch-contract-v1.md`; and
`DECISION-managed-identity-projection-v1.md`. Their historical STOPs and estimated
states are inputs, not current implementation findings.

Book-first dispositions:

- **Same:** OS-user isolation, managed generations and narrow privileged entries:
  chapter **OS user and network**, `D:book/ru/05-polzovatel-i-set.md:7` and
  `D:book/ru/05-polzovatel-i-set.md:27`; secret custody, separate service/caller
  authority and revocation: chapter **Credentials**,
  `D:book/ru/09-uchetnye-dannye.md:101` and
  `D:book/ru/09-uchetnye-dannye.md:140`.
- **Conflict, explicitly scoped:** manual-root enrollment/bind/lift instead of
  **Operator's phone**, `D:book/ru/12-interfeysy.md:49`, broker section 14 and
  the production operator contract. This is not a refinement or a reusable
  production exception. The lab contract review records the exact deviation;
  any adoption beyond this lab requires its own book/specification decision.
- **New, lab-only:** API-key custody kind, root-control record and activation
  marker below. Publish their closed fixtures before implementation; do not add
  them to production schemas or silently amend production documents.

## 2. Three parties and the API-key boundary

| Party | Custody and authority |
| --- | --- |
| Broker | Dedicated nonlogin system user `swarma-lab-broker`; only durable key store, protected 0700/0600. Releases material only to the current managed `credential-gateway` UID/generation. Leases last at most 900 seconds. Root control is a separate lab boundary, never a worker lease route. |
| Gateway | Managed trusted local service account from the manager. Holds leased material in memory only; fixed TLS upstream `https://api.anthropic.com`; generation-specific Unix HTTP listener. Validates the exact managed worker and approved execution before every use. |
| Worker | Exactly one managed worker generation at a time. Pinned Claude Code **2.1.328** through the approved executor and launcher; placeholder only; unix-only seccomp and descriptor scrubbing before exec and in children. No native login, API-key file, direct provider route or inherited authentication. |

The broker's unmanaged lab system user is an explicit lab exception to the
production managed-broker bootstrap. The gateway and worker are **not** created
with ad-hoc account commands or hand-written manager journals. The manager's lab
setup unit owns bootstrap and the existing authenticated helper invocations.
The operational three-party split does not exclude trusted kernel/root/SSH from
the threat model: root can already read either holder. This profile trusts Ivan's
root session; it does not prove a UID-0 process is Ivan rather than another root
actor. Worker and gateway UIDs have no root-control or hold-lift authority.

### 2.1 What already works, and what does not

The launcher mapping is now landed: its closed values fix
`ANTHROPIC_UNIX_SOCKET`, `ANTHROPIC_BASE_URL=http://api.anthropic.com` and
`CLAUDE_CODE_OAUTH_TOKEN=ssh-placeholder`; it never sets `ANTHROPIC_API_KEY` or
`ANTHROPIC_AUTH_TOKEN`. See `M:internal/launch/mapping_linux.go:152` and
`M:internal/launch/mapping_linux.go:186`. The filter allows AF_UNIX, rejects other
socket families and io_uring, and sets NoNewPrivs:
`M:internal/launch/confinement_linux.go:12`.

**The managed gateway does not already support an API-key lease.** Distinguish:

- The generic model-proxy credential abstraction already has `api-key` and
  `oauth-bearer`: `G:experiments/model-proxy/credential.go:17` and
  `G:experiments/model-proxy/credential.go:233`. That is not permission to use
  its development/file credential mode in this lab.
- The older `service.Claude` adapter declares `claude-oauth-token` and attaches
  bearer authorization: `G:experiments/model-proxy/service/adapter_linux.go:115`
  and `G:experiments/model-proxy/service/adapter_linux.go:159`.
- The **actual step-2 intake** also requires `scheme == "oauth-bearer"`, attaches
  `Authorization`, and copies `Anthropic-Beta` unchanged:
  `G:experiments/model-proxy/service/intake_linux.go:272`,
  `G:experiments/model-proxy/service/intake_linux.go:308` and
  `G:experiments/model-proxy/service/intake_linux.go:355`.
- Its client/source require `claude-oauth-token`:
  `G:experiments/model-proxy/service/client_linux.go:355` and
  `G:experiments/model-proxy/service/source_linux.go:38`. The broker also fixes
  that kind in both custody and service validation:
  `B:internal/claude/account_linux.go:16`,
  `B:internal/claude/account_linux.go:118`,
  `B:internal/service/broker.go:19` and `B:internal/service/broker.go:710`.

Therefore this is a **bounded gateway change plus a broker lab-kind change**,
not an already-supported header setting and not a bearer-token relabeling. The
lab kind is `anthropic-api-key-lab/1`; the managed source scheme is `api-key`.
The lease payload, account metadata, bind record and gateway must agree on that
kind. Never store an API key under `claude-oauth-token` or invent an OAuth
expiry/refresh flow. Reuse custody mechanisms, not false OAuth metadata.

### 2.2 Exact downstream-to-upstream transformation

Retain the measured launch contract (`I:DECISION-claude-gateway-launch-contract-v1.md:15`)
and step-2 intake admission (`G:experiments/model-proxy/service/intake_linux.go:96`):

1. Only HTTP/1.1 on the qualified Unix socket. Match SO_PEERCRED to the approved
   worker tuple; the placeholder is not authority. Admit exactly
   `POST /v1/messages` with one `Authorization: Bearer ssh-placeholder` and no
   other credential header, or credential-free `GET /api/claude_code/policy_limits`.
   Reject duplicate/case-colliding credentials, other paths/methods and any
   worker-supplied key **before forwarding**. Scan URI, headers and body before
   injection and again after loading the current issued-version inventory.
2. Construct a new upstream request, not a mutated worker header map. Preserve
   the admitted path, query, Messages JSON and incremental SSE behavior. Pin TLS
   host/SNI to `api.anthropic.com`; no proxy environment, redirects or arbitrary
   endpoint. Copy only the reviewed protocol-header allowlist.
3. **Never forward downstream Authorization.** Remove Authorization,
   Proxy-Authorization, Cookie and every recognized credential header; install
   exactly one `x-api-key` from the current API-key lease. Preserve the approved
   `anthropic-version` and content type. Neither placeholder nor leased key may
   appear in a URL or another header.
4. **Strip the entire downstream `Anthropic-Beta` header for this minimal lab
   profile**, including `oauth-2025-04-20` and Claude-Code/OAuth feature flags.
   Send no replacement beta header. The selected model/request profile must
   work without beta-only body semantics. Native exact-client qualification is
   mandatory; if it requires a beta, revise the reviewed API-compatible profile
   and fixtures first, never forward an OAuth profile with an API key or silently
   delete body features. Removing only Authorization would be insufficient.
5. The policy-limits GET follows the same fixed upstream and API-key policy.
   Preserve the vendor's real status/error; **do not synthesize a successful
   policy-limits response**. Qualification must show the pinned client tolerates
   that route's actual result and completes Messages inference. Otherwise the
   release remains blocked; a different launch mapping is a contract revision,
   not a runtime fallback to subscription login.
6. Clear both Authorization and x-api-key from holder-owned request objects on
   every terminal path; the current `Drop` only deletes Authorization
   (`G:experiments/model-proxy/service/adapter_linux.go:181`). No headers,
   request/response bodies, key fingerprints or transport objects in logs/errors.

G1's paired tests must inspect the actual managed HTTP path, not only the unused
adapter: valid API-key injection versus bearer leakage, retained OAuth beta,
duplicate header, wrong kind/scheme, proxy/redirect and cleanup plants. Tests
also cover status/error and SSE preservation and policy-limits non-fabrication.

## 3. Lab authority, state and retained enforcement

### 3.1 An activation no production reader accepts

Build the broker lab command only with `linux && broker_lab`, and the gateway
lab command only with `linux && gateway_lab`. Use separate executable names,
unit names, state roots and records. No environment or production CLI switch
selects the lab. Untagged builds must retain the stopped production owner:
`B:cmd/swarma-credential-broker/main_linux.go:76` and
`B:cmd/swarma-credential-broker/main_linux.go:87`.

The root-owned activation is `/etc/swarma/lab/activation.json`, root:root 0644,
regular/single-link, maximum 16 KiB; root-protected ancestors. Its closed members:

```text
format = swarma-broker-lab-activation/1
profile = LAB_ONLY_NOT_PRODUCTION
enabled = true | false
installation_id, machine_id, vm_identity_digest, release_set_sha256
qualification_revision, qualification_expires_at
account, credential_kind = anthropic-api-key-lab/1, test_api_key = true
authority_sha256, fence_sha256, service_lease_max_lifetime_seconds
```

All digest fields bind complete canonical bytes; IDs and expiry are release/
owner-approved inputs, never worker input. The one lifetime selector is a JSON
integer 1..900, explicitly 900 for the ceiling check; no clamping or second CLI/
environment ceiling. An absent or valid disabled marker never permits material use. Root enrollment
and bind may proceed only under the separately approved **preparation** record;
that record cannot authorize issue/renewal. A present malformed, expired or
mismatched marker closes widening even with a preparation record. Diagnostics
and independently admitted narrowing remain available.

The lab loader accepts no production format/continuity, and the production
loader accepts no lab marker, even if copied to its production path. Test both
directions and mixed/extra/null fields. The current production loader explicitly
requires the production format, OAuth kind and `{kind:production}`, rejecting
`test-c`: `B:internal/activationv0/activation.go:104` and
`B:internal/activationv0/activation.go:115`. Do not modify that acceptance set.
The root manifest must refuse simultaneous enabled production/lab units or
using an existing production store; labeling a production document "lab" fails.

### 3.2 Concrete authority instead of permissive fixture facts

`/etc/swarma/lab/authority.json` is root:broker 0640, under a root-owned 0750
directory. It binds one API account, its owner root UID, exact gateway managed
UID/generation, worker managed UID/generation, execution ID/epoch/plan and
executor digests, current manager journal head, per-use authorization expiry,
fixed upstream, poll bound, operation budget and the dedicated capped-key marker.
All duplicate facts in operational config must equal these pins or refuse.
The lab root approval replaces production signed delegation **only in this
explicitly conflicting closed lab schema**. It is not a fabricated production
grant, operator receipt or dispatcher chain.

The control socket `/run/swarma-lab/control.sock` is broker-owned 0600 in a
broker-owned 0700 root-installed directory; both ends verify kernel peers.
Root-control requests require UID 0 and `swarma-broker-lab-root/1`, closed verbs,
canonical arguments and durable operation IDs. Neither a JSON UID nor a generic
RPC client manufactures the root act. The service socket
`/opt/swarma/run/lab-broker/broker.sock` is 0666 with protected ancestors so Q3
can exercise real broker authorization, not just a filesystem denial. The lab
server exposes service methods only; legacy worker-material methods refuse.

Compose root-control authority separately from managed-service authority.
`ManagedAuthority.Principal` is service-only, not an operator/worker resolver:
`B:internal/service/managed_linux.go:358`. For gateway service calls reuse that
current protected projection/journal check. Verify active worker kind, generation,
local placement/class, manager launch receipt/debit and the root-approved execution
separately before `Caller` succeeds. Acquire root configuration lock, then managed
locks, then service state lock; collect time before final state locks. A callback
must recheck its deadlines and exact facts at material publication. No arbitrary
`time.Now` callback or `OperatorAct=true` fixture enters the lab factory.

Retained contracts and qualifications:

- **Lease:** reuse the service engine's 900-second constructor check and earliest
  authority/vendor-expiry bounding; issue and renew use the sole lab selector.
  An API key has no invented vendor expiry; null means unknown, not infinite
  broker authority. Same-ID retries reconcile the same result, never extend it.
  See `B:internal/service/broker.go:211` and
  `B:internal/service/broker.go:1045`.
- **Identity:** exact gateway kernel UID plus active managed service generation,
  binding, trusted class/local placement and disjoint role. Worker service and
  legacy lease attempts refuse with no material, no lease and no custody effect.
  A stale service closes its broker connection, not just its next request.
- **Hold:** any leak match immediately blocks local forwarding and durably
  requests whole-account `account.hold` with reason `leak_match`. Lost ack keeps
  local use blocked and retries the **same operation ID**, including redial.
  Existing step-2 `scan` only cancels locally and is **not** this bridge:
  `G:experiments/model-proxy/service/intake_linux.go:181`. Response filtering
  currently redacts without durable hold
  (`G:experiments/model-proxy/service/intake_linux.go:364`); request, response
  and Q2-scanner matches must all enter the same durable hold path, not silently
  redact and continue. Only Ivan's root
  `hold-lift` with the exact active hold ID may lift; lifting never revives an
  ended lease or unbound service. No `clear_block` substitute.
- **Revocation:** select `service.unbind` as the root revoke act. New issue/renew
  refuses at durable publication. Qualified total propagation bound is **1 s**:
  250 ms check cadence + at most 250 ms RPC + at most 500 ms scheduling/closure.
  A one-second monotonic watchdog since the last successful current check closes
  use on unavailable/timeout/connection loss too. Include in-flight upstream
  cancellation, downstream connections, old listener and old broker connection;
  invalidated generations cannot reconnect automatically. The landed constants
  are only source evidence, not native timing proof:
  `G:experiments/model-proxy/cmd/model-proxy/managed_linux.go:35`.
- **Finite state:** renew from the actual `authorized_until`, not on every poll.
  The current holder schedules renewal at no more than 0.5 s regardless of a
  900-second lease (`G:experiments/model-proxy/cmd/model-proxy/managed_linux.go:170`).
  G1 must avoid that journal churn while continuing 250 ms checks. The approved
  lab plan bounds operations/leases; B1 reserves serialized capacity for hold,
  unbind and reconciliation before admitting further widening. Exhaustion fails
  closed, never deletes replay/hold/tombstone evidence.

### 3.3 Reuse and deliberately unassembled production pieces

| Landed component | Lab use / limit |
| --- | --- |
| U00/U01 declarations, strict CCJ-1 parser/frames and construction vectors | Reuse canonical parsing/protected-file policy concepts and negative vectors; lab formats remain separate closed types. See `B:docs/assembly-v0-construction-contract.md:11`, `B:internal/assemblyv0/ports.go:1`, `B:internal/wire/frame.go:1`. |
| U03 activation/lifetime | Reuse the proven range/refusal contract and tests, not its production-only loader as a lab opt-in. Its production reader stays unchanged. |
| U05 shared gate and `/2` journal/reserve | Reviewed as available, **not a ready daemon assembly**. Its bridge requires shared-gate integration and production receipt shapes. The shortest lab path retains the existing service engine's serialized durable state through an explicit lab-record adapter, with finite-plan narrowing reserve; it does not cast `/1` to `/2`, invent a production terminal receipt or wrap a second mutex and claim U05 integration. See `B:docs/assembly-v0-service-journal.md:36` and `B:docs/assembly-v0-service-journal.md:77`. |
| `store.Account`, Claude custody lifecycle and existing service controller | Reuse safe store publication, orphan refusal, held-account behavior and lease arithmetic. Add a narrowly parameterized lab credential/record family, available only to the tagged constructor; unchanged default constructors still require OAuth. No copied second lease engine. See `B:internal/claude/account_linux.go:85`, `B:internal/service/broker.go:206`, `B:internal/store/store_linux.go:1`. |
| Server Unix framing, peer credentials and service routing | Reuse transport/peer checks; add lab control routing and explicit worker/legacy refusal. `B:internal/server/services.go:1`, `B:internal/server/peer_linux.go:1`. |
| Managed service provider; manager identities and launch mapping | Reuse protected managed evidence and native launcher/confinement. No static UID allowlist replaces current generations. `B:internal/service/managed_linux.go:358`, `M:internal/launch/mapping_linux.go:152`. |
| Gateway steps 1 and 2; release templates | Reuse managed holder, memory-only source, Unix intake, SSE and metering. Add the API-key kind path, durable hold/recovery and total teardown guarantees above; do not use the development credential source. `G:experiments/model-proxy/cmd/model-proxy/intake_linux.go:21`. |

Existing broker assemblies remain inactive by their own applicability register
(`B:docs/assembly-v0-applicability.md:12`); C1 authorizes no activation
(`B:docs/assembly-v0-construction-contract-c1.md:19`). No account material is an
`owner.Owner` adapter for the legacy exposed lane. Before enrollment the lab
control plane runs without constructing `service.NewWithLifetime` with an empty
map, which currently refuses. After verified durable enrollment, initialize the
fresh lab service journal once and construct the controller from that committed
account. Crash/orphan/uncertain writes stay unavailable; no missing-as-empty
reinitialization. This bounds the bootstrap work without claiming U30 landed.

## 4. DN-09 C: NTS, no restore and accepted residual

This lab takes the C semantics, with API-key-specific lab markers rather than a
false test-subscription declaration. It does not make the older C proposal
production-accepted. Source: `B:spec/operator-and-activation-v0.md:1137`,
`B:spec/operator-and-activation-v0.md:1190`,
`B:spec/operator-and-activation-v0.md:1238` and
`B:spec/operator-and-activation-v0.md:1266`.

On colony1 this means all of the following, not merely "chrony is synchronized":

1. Infra supplies the protected complete chrony source/configuration inventory,
   NTS certificate/bootstrap and authenticated-source evidence. Every selected
   source is an approved NTS source; plain NTP, unlisted/dynamic source, missing
   evidence or stale uncertainty closes widening/use. Reuse `timeconf.Production`
   collection and policy (`B:docs/time-policy.md:16`, `B:docs/time-policy.md:79`).
2. B2 supplies and natively qualifies a **lab-only** local durable witness and
   consumer path, including fsync/CAS, settlement, boot/monotonic predicates and
   sticky incident/hold/watermark continuity. NTS alone does not supply this:
   `NewConsumer` currently installs `ClosedWitness` and has no qualified production
   path (`B:timeconf/consume_linux.go:66`, `B:timeconf/consume_linux.go:84`).
   Neither `NewFixtureConsumer`, a sample-only adapter nor `time.Now` is a lab
   credential-use authority. New lab construction is behind `broker_lab`;
   production `ClosedWitness` remains unchanged.
3. Before **every manual start**, root compares exact final heads and the manager
   consumer high-water with an owner-kept off-VM record, checks an independent
   off-VM clock against the fixed qualification expiry, then publishes a new
   one-use start fence outside the broker home. Its lab-format record pins the
   installation, machine/VM evidence, qualification revision/expiry, start
   generation, state, revocation sequence and all authority/service/time/floor
   heads. First start is explicitly fresh; later starts require acknowledged
   orderly-stop heads. Missing/crash/unknown evidence never gets blessed by
   copying the guest's current heads.
4. Persist the manager journal count/head in broker custody **before** material
   publication, requiring exact prefix extension, not merely head equality with
   a current projection. Preserve it and time watermark/holds over restart and
   reboot. Missing/corrupt/nonextending history refuses; no observed-state reset.
   A fenced diagnostics-only startup and identity-only unbind/hold remain possible.
5. **No restore:** do not snapshot/revert a credential-bearing lab or restore a
   VM, store, manager state or authority file to resume qualification. Detected
   clone/restore/regression burns the installation. Ivan vendor-revokes the old
   API key; Infra retires the installation/time scope off-VM and reprovisions;
   use a new never-reused installation and scope, fresh authority and fresh key.
   Import no old lease/grant/hold/checkpoint. An ordinary time incident is not
   permission to erase history, release a sticky hold or extend the time-box.
6. **Ivan accepts the live whole-VM snapshot/rollback residual for this lab**, as
   directed in this assignment. A live revert can roll back daemon, outside-home
   fence, store, high-water and time witness together and revive removed authority
   until vendor key revocation; local NTS and matching guest bytes do not detect
   that. Off-VM stop/start records help at the next manual boundary only. Preserve
   this explicit risk, the exact reviewed revision/VM/account and time-box in
   Ivan's off-VM approval. No production promotion of any C result or witness.

The protected `test_api_key=true` marker, independently verified colony1 VM
identity and qualification expiry are mandatory at enrollment, bind, issue,
renewal and final use. Other accounts/VMs/revisions refuse. No hard-coded hostname
or locally self-asserted machine-id alone proves the qualified VM.

## 5. Acceptance rows and implementation ownership

These are lab acceptance rows, not a supplied attack-surface-catalog table or a
claim of product test coverage. Before implementation handoff, each brief must
map its actual surfaces to named tests/plants and record exact source/environment.

| Row | Required valid and forbidden outcomes | Unit |
| --- | --- | --- |
| A01 | Tagged lab binary + protected lab marker works; production/lab cross-read, default import/activation or existing production-store adoption refuses. | C0, B1, B5 |
| A02 | True API-key kind reaches exactly x-api-key on managed intake; OAuth-kind masquerade, bearer/beta leakage, header ambiguity, redirects and fake policy-limits success fail. | C0, B1, G1 |
| A03 | Current kernel gateway + managed service/caller execution works; worker, stale/reused UID/generation, wrong class/placement, root JSON spoof and legacy material route refuse. | B1, M1, G1 |
| A04 | Owner terminal delivers bounded bytes only to broker custody; echo/argv/env/staging/log spill, non-TTY/nonroot input, residue/successor and uncertain replay refuse. | B3, B4 |
| A05 | Fresh committed account/journal survives orderly restart; orphan adoption, missing-as-empty, contradictory retry and capacity without narrowing reserve refuse. | B1, B3, B4 |
| A06 | Qualified NTS/settlement/fence/floor/VM/time-box admits use; plain NTP, fixture/ClosedWitness, rewind, missing off-VM start evidence or expired qualification closes use. | B2, B5, B4 |
| A07 | Issue/renew respects 1..900 and earliest authority deadline; >900, stale/expired lease, same-ID extension/retarget and unknown-outcome duplication refuse. | B1, G1, B4 |
| A08 | Same matcher leak causes durable sticky whole-account hold; local-only block, ack-loss reopening, nonowner lift and ended-lease resurrection fail. | B1, G1, B3, B4 |
| A09 | Current control works; unbind/stale generation/unavailable closes all affected use and connections within 1 s under the qualified load bound. | B1, G1, M1, B4 |
| A10 | Approved Claude launch gets placeholder/Unix route; inherited auth, other socket families, io_uring, inherited network FDs and unapproved executor/mapping refuse. | M1, B4 |
| A11 | Owner-approved aggregate plus identical second build installs; unapproved digest, unsafe member/link/mode, substitution and missing cgo NSS closure refuse before activation. | B5, RB, RG, RM |
| A12 | Complete lifecycle/surface evidence passes; controlled public-canary plants are detected, incomplete scans and leaked verifier/raw bytes fail. | B4 |

The unit plan and dependency/LU table are in the accompanying `HANDOFF.md`.
Every unit remains inactive until the aggregate lab gate. Native platform/API
incompatibility is a stop with evidence, not a reason to add permissive flags,
mock-only success or a production fallback.

## 6. Release set: approve bytes, not source claims

As of source inspection, broker tag `v0.1.0` is at `d6350aa2b2c00fa4015189f24d34450e37789908`
and manager tag `v0.1.1` at `b61b1eadc7cc7ef9fcd4e8e94b254f5766317f2b`;
there is no gateway `v*` tag. Those are **not** a usable lab release: they do not
contain the proposed lab assembly and the manager tag predates the inspected
launch mapping. Never substitute these tags or inspected source HEADs for an
approved future set. Release API observations are retained in the review packet.

Proposed reserved labels, to be created only by the separately authorized release
units after their changes land, are broker **v0.1.0-lab.1**, gateway
**v0.1.0-lab.1**, manager **v0.1.2-lab.1**. These labels do not yet identify any
artifact. If a label is already occupied when cut, select a new reviewed label;
never move it. Fill tag object IDs, full source commits and hashes from real builds.

| Product / unit | Build and install inventory |
| --- | --- |
| Broker / RB | Explicit `broker_lab` release target: `swarma-credential-broker-lab_linux_<ARCH>` and `swarma-lab-qualify_linux_<ARCH>`, disabled lab units, canonical schemas/fixtures and bounded root install/control runbook. Default release scripts do not magically build tagged commands. Install commands under `/opt/swarma/lab/bin/`. |
| Gateway / RG | Explicit `gateway_lab` target of model-proxy with the service module, packaged as a lab archive containing `credential-gateway/bin/credential-gateway-lab`, lab unit template and nonsecret config schema. Extend main-owned input policy, not a downloaded/tag-owned script. |
| Manager / RM | Manager, launcher and **native cgo NSS probe** for the selected Linux architecture, plus the isolated `manager_lab` setup command and pinned bounded Claude executor. No second allocator or altered production helper authorization. Include source-approved deployment/skeleton/NSS closure and the Claude artifact pin. |

Build with the templates' pinned **Go 1.26.10** and the native cgo toolchain/
libc/NSS closure for the probe, not a pure-Go substitute. The gateway's source
policy currently builds a platform-root tarball; broker/manager use flat complete
sets: `G:.github/release/gateway-inputs.json:1`,
`G:.scripts/release-build.sh:17`, `B:docs/releasing.md:87` and
`M:docs/releasing.md:240`. The lab aggregate deliberately supports these reviewed
member layouts instead of pretending to be a full installer-v0 set.

Each product has its own `SHA256SUMS`, provenance and `release-set.json` fragment;
include **all** product digests in `swarma-lab-release-set/1`, including hashes of
checksum files/fragments, unit/config/schema/helper/executor assets and every
archive member's mode/target. Include Claude Code 2.1.328's exact vendor artifact,
source/origin verification and digest as an approved dependency of the manager
set; a version string is not an executable pin. Pin the colony1 OS/architecture,
libc/NSS backend, chrony/NTS source policy and exact native preflight evidence.
No real host pins or artifact digests are supplied by this document.

Use the templates' main-owned admitted signed-tag workflow and independent second
build; compare complete bytes and checksums. Two release reads and required
checks remain gates. Signatures are consistency evidence, **not Ivan's approval**:
`B:docs/releasing.md:10`, `B:docs/releasing.md:33`,
`M:docs/releasing.md:104` and `M:docs/releasing.md:111`.

**Before any root artifact step**, Ivan reviews in person and records off-VM:
exact aggregate bytes and SHA-256, bootstrap binary SHA-256, all product tags/
commits/checksums, second-build comparisons and reviews, installed paths/modes,
VM/OS/NTS inputs, lab-conflict text, API account/spend cap, model/total cost and
inference limits, qualification revision/expiry and the C rollback residual.
No blank field, floating tag/model, unverified asset or source build on colony1
is accepted. No agent creates a key, supplies approval, tags or publishes this
planning checkout.

## 7. Proposed exact root runbook

**Execution preconditions:** C0/B1/B2/B3/G1/M1/B4/B5 and RB/RG/RM accepted;
all A rows green in the native **inert-key** preflight; Infra T2 phase A attested;
Ivan present; approved digest and bootstrap digest recorded off-VM. API-key
vendor validity is established only by owner-sitting Q1, never by inert preflight.
Use the selected released architecture, not a guessed uname mapping. All uppercase
`REPLACE_...` strings below are **nonsecret placeholders that must be replaced**;
validators refuse them. Never substitute a credential into any shell command.

### 7.1 Host tools and bootstrap, Ivan as root

Start in a fresh, nonrecording SSH session owned by Ivan, not an agent/multiplexer.
No session recording, tracing, core dumps or swap/hibernation. Host tools below
are the already trusted OS tools; no downloaded script executes as root.

```sh
set -eu
set +x
set +o history
umask 077
ulimit -c 0
test "$(id -u)" -eq 0
SOURCE='/REPLACE_APPROVED_DOWNLOAD_DIRECTORY'
ARCH='REPLACE_APPROVED_ARCH'
SET_SHA256='REPLACE_APPROVED_AGGREGATE_SHA256'
BOOTSTRAP_SHA256='REPLACE_APPROVED_BOOTSTRAP_SHA256'
STAGE='/var/lib/swarma-lab/bootstrap-REPLACE_FRESH_INSTALLATION_ID'
test ! -e /var/lib/swarma-lab && test ! -L /var/lib/swarma-lab
install -d -o root -g root -m 0700 -- /var/lib/swarma-lab
test -d /var/lib/swarma-lab && test ! -L /var/lib/swarma-lab
test "$(stat -c %u:%g:%a /var/lib/swarma-lab)" = 0:0:700
mkdir -m 0700 -- "$STAGE"
cp --no-dereference -- "$SOURCE/broker/swarma-credential-broker-lab_linux_$ARCH" "$STAGE/lab-bootstrap"
test -f "$STAGE/lab-bootstrap" && test ! -L "$STAGE/lab-bootstrap"
test "$(stat -c %h "$STAGE/lab-bootstrap")" -eq 1
printf '%s  %s\n' "$BOOTSTRAP_SHA256" "$STAGE/lab-bootstrap" > "$STAGE/bootstrap.sha256"
sha256sum --strict --check "$STAGE/bootstrap.sha256"
chmod 0500 -- "$STAGE/lab-bootstrap"
"$STAGE/lab-bootstrap" install-set --source "$SOURCE" --set-sha256 "$SET_SHA256" --bootstrap-sha256 "$BOOTSTRAP_SHA256" --fresh-installation 'REPLACE_FRESH_INSTALLATION_ID'
```

The clean T2 phase A baseline must already exclude a substituted ancestor or
pre-existing lab path; the bootstrap refuses an existing staging leaf, rather
than copying through a destination link. B5 must implement exactly this command
contract. It first checks root-owned,
single-link, non-symlink ancestors/files and fresh destination, compares the
owner-approved aggregate, then makes **its own protected copies and rehashes
those copies**, including every archive member and manifest relationship. Source
races or unsafe links/modes refuse, not become installed authority. It stages
atomically and records an install receipt; neither verifies by executing source
scripts nor auto-starts anything. Root manually checks the bootstrap digest before
its first execution. Reused/nonempty staging fails; do not repair it recursively.

Installed layout: manager/launcher/probe in `/opt/swarma/libexec/`; gateway at the
archive member path in section 6; lab commands in `/opt/swarma/lab/bin/`; root
config/preparation in `/etc/swarma/lab/`; broker state in
`/opt/swarma/services/swarma-lab-broker/` (0700 broker custody); evidence in
`/var/lib/swarma-lab/evidence/` (root 0700/0600). Binaries root:root 0755, units
root:root 0644. All literal unit names below are lab-only and initially disabled,
`Restart=no`; no `enable --now` and no production activation file.

### 7.2 Qualify manager, create identities and prepare control plane

```sh
/opt/swarma/libexec/swarma-user-manager-lab-setup prepare --plan /etc/swarma/lab/install-plan.json
/opt/swarma/libexec/swarma-user-manager-lab-setup qualify --plan /etc/swarma/lab/install-plan.json
/opt/swarma/libexec/swarma-user-manager-lab-setup create-identities --plan /etc/swarma/lab/install-plan.json
/opt/swarma/libexec/swarma-user-manager-lab-setup verify-identities --plan /etc/swarma/lab/install-plan.json
/opt/swarma/lab/bin/swarma-credential-broker-lab prepare --plan /etc/swarma/lab/install-plan.json
systemctl daemon-reload
systemctl start swarma-credential-broker-lab.service
/opt/swarma/lab/bin/swarma-credential-broker-lab status --expect control-only
```

M1's setup is a **new root installation entry**, not a claim the normal helper
accepts root. It provisions reviewed nonlogin broker/control-caller accounts,
closed policy/skeletons, native NSS/qualification/bootstrap and the one-start
launch gate using manager-owned format writers. No hand-authored identities or
generation journal. The normal helper rejects bare root
(`M:cmd/swarma-user-manager/main.go:71`); setup invokes it with genuine verified
sudo provenance through its separately pinned operator/dispatcher users, exact
no-argv rule, bounded stdin and dropped capabilities. It must not spoof SUDO_UID.

Existing gateway-create request remains exactly
`{"args":{"kind":"service","label":"credential-gateway"},"op":"user.create","request_id":"REPLACE_PERSISTED_REQUEST_ID","v":1}`;
worker creation is the corresponding approved `kind:"agent"` request from the
configured dispatcher. Persist request identities before invoking; same request
on uncertainty. Only the manager writes identities.json. Read back the returned
UID/GID/generation, active trusted/local service record and current journal-head
join (`I:DECISION-managed-identity-projection-v1.md:11`). The approved worker
placement/class and root:S home custody remain the manager's, not an installer
chmod workaround.

Manager qualification keeps the existing CAP_NET_ADMIN-excluding native entry,
current-boot qualification unit/readback and matching pins; no `qualified:true`
flip without it. `prepare` creates only the separately approved lab account plan,
fresh empty store and disabled marker. The broker starts **control-only**, with
no material-serving controller. No lease can be issued by these steps.

### 7.3 Enroll from Ivan's terminal, with no transfer file

Ivan first creates the dedicated capped API key in his own vendor account. No
agent/browser session sees it. After metadata-only preparation/readback, use a
**new dedicated root SSH session with no parent server-side successor shell**:

```sh
set +x
set +o history
umask 077
ulimit -c 0
exec /opt/swarma/lab/bin/swarma-credential-broker-lab enrol --account lab/anthropic --stdin-tty --preparation /etc/swarma/lab/preparation.json
```

Only **after the command's no-echo prompt** does Ivan enter the key on stdin.
Do not paste it as a shell line, use shell `read`, command substitution, a pipe,
heredoc, environment variable, file, password manager CLI or a key-bearing flag.
`exec` retires that remote shell; no subsequent shell may read residue. If the
SSH/sudo stack cannot guarantee channel/TTY retirement, enrollment refuses before
prompt and the native lab entry must be corrected, not claimed safe by ancestry.

B3 verifies a root peer, approved preparation/VM/account, genuine terminal FD0,
no recorder, bounded raw no-echo capture (1..4096 printable ASCII bytes, a single
line), nondumpability, locked sensitive buffers and configured memory limits.
It authenticates the broker peer **before capture**, sends one bounded request
to the root-control socket, zeroes owned buffers, discards queued input and
retires the SSH channel on success/failure/interruption. No automatic token retry
or unsafe successor after uncertain completion. B4 must exercise success, echo,
multiline paste, EOF/signals/death, broker failure and residue controls using
public inert data on the exact native SSH stack. Complete native cleanup and
OS swap/coredump exclusions are gates, not a Go memory-erasure claim.

No intake bytes enter argv, environment, a staging file, history or logs. The
**only intended durable secret file** is the broker's protected custody record;
"no files" here excludes transport/staging/worker/gateway files, not that required
broker store. Reply/evidence exposes account, kind, committed revision and result
only, never a key hash/prefix. A lost reply is UNKNOWN: the next root session
queries metadata with the same operation ID and never resubmits the key blindly.
After committed enrollment the lab controller may be built; material use remains
closed until bind and activation.

### 7.4 Bind, fence, activate and start gateway

Reconnect in Ivan's root session. All arguments/files below are nonsecret:

```sh
/opt/swarma/lab/bin/swarma-credential-broker-lab status --expect enrolled-inactive
/opt/swarma/lab/bin/swarma-credential-broker-lab bind --account lab/anthropic --service credential-gateway --identity /etc/swarma/lab/gateway-identity.json --authority /etc/swarma/lab/authority.json
/opt/swarma/lab/bin/swarma-credential-broker-lab verify-start --off-vm-approval /etc/swarma/lab/start-approval.json
/opt/swarma/lab/bin/swarma-credential-broker-lab activate --decision /etc/swarma/lab/owner-decision.json
systemctl start credential-gateway-lab.service
/opt/swarma/lab/bin/swarma-credential-broker-lab status --expect ready-for-one-launch
/opt/swarma/libexec/swarma-user-manager-lab-setup verify-launch --plan /etc/swarma/lab/launch-plan.json
systemctl show swarma-credential-broker-lab.service credential-gateway-lab.service --no-pager --property=User,Group,ExecStart,ActiveState,SubState,Result,Restart,LimitCORE,NoNewPrivileges,CapabilityBoundingSet,RestrictAddressFamilies
```

Account enrollment precedes service.bind because bind requires a committed
account. B3 translates only the verified root act to the existing service bind
engine using the API-key lab kind and exact policy digest. A plan row is not an
account and a service bind grants no worker use. Root confirmation displays
exact account, tuples, aggregate/revision/expiry and lab conflict, but no key.
`verify-start` uses a copied, authenticated **off-VM** approval; it cannot generate
that approval from guest state. `activate` writes only the root lab marker/fence
under the permanent root lock and requires every pin to match current bytes.
No production activation is written or read as lab authority.

The gateway listener is
`/opt/swarma/run/credential-gateway/<GATEWAY_GENERATION>/gateway.sock`; generation
is the manager-returned value. Gateway-owned directory 0750, socket 0660;
root installs a narrowly scoped ACL for only the approved worker's traversal/
connect access, without changing its managed primary/supplementary groups.
No old-generation path reuse. Units have no capabilities, no core dumps, no
restart and minimal paths; broker AF_UNIX only, gateway required AF_UNIX/INET/
INET6 for the fixed TLS upstream, no real key in LoadCredential or environment.
Verify actual peer/listener/ACL/effective sandbox, not just unit text. AF_UNIX
seccomp is not a universal air gap: Infra must exclude reachable Unix forwarding
services and inherited network FDs. Manager mapping publication waits for the
real socket; the gateway waits for the durable worker launch receipt before its
first lease, resolving the planned-execution/listener ordering without a dummy
launch receipt.

Every new boot/start needs a new off-VM-approved fence. Keep units disabled.
`systemctl restart` without the stop/start seal protocol is not a recovery route.

## 8. Q1–Q6: concrete command contracts, controls and evidence

The **proposed** installed driver is `/opt/swarma/lab/bin/swarma-lab-qualify` (B4).
It reads only `/etc/swarma/lab/qualification-plan.json` and retains a resumable
metadata session under `/var/lib/swarma-lab/evidence/`. It is not a shell runner.
It invokes the approved manager launcher/executor for worker actions, with a
real worker kernel peer; root/gateway probes never claim to be worker probes.
Its launch input uses an already persisted execution ID/epoch and the real
one-start gate (`M:internal/launch/gate.go:30`). After a one-start generation is
consumed it must stop/retire it and obtain the next exact owner-approved plan,
not refill a debit. Approved extra generations are sequential, never parallel.

All commands run standalone; no `tee` or exit-hiding pipelines. Command result
JSON is a fixed **metadata-only verdict**, not raw stdout/stderr or HTTP traces.
Exit contract: **0** means the named acceptance assertion was fully demonstrated;
**1** means its assertion failed; **2** means setup/evidence incomplete or UNKNOWN.
For negative cases the driver reports the underlying refusal/detection and
underlying exit too: driver exit 0 means it observed the **specified refusal and
no forbidden effect**, not that the rejected operation succeeded. An unrelated
error, inaccessible socket, dead daemon or skipped plant never passes a negative.

Use a fresh approved fixture store/transport for synthetic cases, same exact
released code/configuration and public noncredential canaries. Never plant a real
key. Fixture results are labeled separately from the real-token run; they cannot
stand in for Q1 vendor validity, live peer refusal or native one-second timing.
Every invasive control is confined to the lab's owned units/accounts/scratch.

### Q1 — bounded real inference via Unix gateway

```sh
/opt/swarma/lab/bin/swarma-lab-qualify q1 --case wrong-placeholder
/opt/swarma/lab/bin/swarma-lab-qualify q1 --case wrong-caller
/opt/swarma/lab/bin/swarma-lab-qualify q1 --case valid-inference
```

Negatives: actual worker uses wrong placeholder or an unapproved caller mapping;
refusal before material release/upstream inference, with zero lease/inference
counter change. Valid: approved Claude executor completes one bounded Messages
inference, streamed over its generation Unix socket and the fixed API upstream.
The valid-inference command arms the Q2 lifecycle collector **before launch**
and refuses to start without it; Q2 later verifies its retained metadata. A
bounded, pinned worker-side executor supervisor remains available for the
closed Q3/Q5 peer probes until the approved stop deadline. It exposes no shell
or arbitrary execution endpoint and does not keep Claude doing extra inference.
The executor pins model, prompt, no tool use, turn/token/time and total USD bounds;
no arbitrary worker command or inherited auth. Key remains broker/gateway custody.
The real API-key policy-limits result and client continuation are part of this
valid control; an incompatible client/vendor response is a blocking failure.

**Evidence:** `q1.json` with set/executor/mapping/plan digests, kernel peer/managed
and execution tuples, refusal stages, material/upstream counters, upstream status,
completion/stream verdict and bounded usage/cost. No prompt/body/header/key bytes.

### Q2 — no key on worker surfaces or gateway logs

```sh
/opt/swarma/lab/bin/swarma-lab-qualify q2 --case scanner-plants
/opt/swarma/lab/bin/swarma-lab-qualify q2 --case complete-clean-lifecycle
```

Negative control: individually plant a **public noncredential** marker in inert
worker environment, argv, file, worker-log and gateway-log fixtures. The same
scanner/configuration must detect each at its intended surface, then detect no
match after owned cleanup; an unreadable/missing/oversized fixture must return
incomplete, never clean. Valid: collect the complete declared Q1 lifecycle before,
at exec/during, and after, including children, every worker writable home/state/
work/tmp surface and actual gateway/worker logs. Raw bytes stream through the
protected broker-side matcher; real-key matchers never leave holder custody.
A root-owned lifecycle collector uses verified process identity and exec/stop
observation; an after-exit scan alone is not complete environment/argv evidence.
Sensitive scan buffers never enter an agent process or output file. A real match
halts the run and takes the same account-hold path as Q5.

**Evidence:** `q2.json`, closed surface inventory, scanner/config digests,
per-surface count/completeness/no-match verdicts, observation boundaries and
plant/detection/cleanup records. No universal no-leak claim beyond these bounded
surfaces/encodings/run. Missing visibility is exit 2, not a passing scan.

### Q3 — real worker refused by broker

```sh
/opt/swarma/lab/bin/swarma-lab-qualify q3 --case gateway-valid
/opt/swarma/lab/bin/swarma-lab-qualify q3 --case worker-service-lease
/opt/swarma/lab/bin/swarma-lab-qualify q3 --case worker-legacy-lease
```

Valid: current gateway obtains a service lease inside holder custody with current
worker authority. Negatives: actual worker connects to the reachable broker
socket and attempts service and legacy material leases. Require
`principal_ledger_mismatch` at identity admission or `role_not_permitted` at
role dispatch, with the exact stage recorded; no material, lease/custody/state
mutation or alternate mode. A permission-denied connect alone fails this test.

**Evidence:** `q3.json` with real SO_PEERCRED observation, request class/refusal
code/stage and before/after material-publication and durable-state counters;
valid gateway proof without its lease payload.

### Q4 — durable unbind, unavailable and stale-generation closure

```sh
/opt/swarma/lab/bin/swarma-lab-qualify q4 --case current-control
/opt/swarma/lab/bin/swarma-lab-qualify q4 --case fixture-unavailable
/opt/swarma/lab/bin/swarma-lab-qualify q4 --case fixture-delayed-check
/opt/swarma/lab/bin/swarma-lab-qualify q4 --case arm-live-observer
/opt/swarma/lab/bin/swarma-credential-broker-lab unbind --account lab/anthropic --binding-file /etc/swarma/lab/current-binding.json
/opt/swarma/lab/bin/swarma-lab-qualify q4 --case observe-live-unbind
/opt/swarma/libexec/swarma-user-manager-lab-setup retire-gateway --plan /etc/swarma/lab/retire-plan.json
/opt/swarma/lab/bin/swarma-lab-qualify q4 --case observe-stale-generation
```

Valid: current poll is `not_revoked` and a bounded affected use/connection is
observable. Negatives: durable root service.unbind, synthetic unavailable and
missed-check controls. Require all affected key use/in-flight streams and old
broker/downstream connections/listener closed within **1 s** of durable removal
or the last successful current check, as appropriate. Record the scheduler/load
bound and independent monotonic observation; a stream already ended before the
fault gives no in-flight credit. Any additional real inference must fit the
owner-approved total budget. Retiring the managed gateway tests stale-generation
teardown separately from unbind. No cached lease or later good poll resurrects it.
The observer started by `arm-live-observer` is a task-owned child whose exact PID
and start identity are recorded and reaped by the driver, not a shared daemon.

**Evidence:** `q4.json`, target binding/generation, durable publication/ack and
independent last-use/connection/stream/listener monotonic times, measured maximum
and poll/watchdog configuration; unavailable/delay control verdicts. Source
constants, a process name kill, or merely seeing `revoked` is insufficient.

Q4 deliberately ends authority. To continue, Ivan approves the next exact
transition off-VM and executes:

```sh
/opt/swarma/libexec/swarma-user-manager-lab-setup prepare-next --plan /etc/swarma/lab/next-qualification-plan.json
/opt/swarma/libexec/swarma-user-manager-lab-setup create-identities --plan /etc/swarma/lab/next-qualification-plan.json
/opt/swarma/libexec/swarma-user-manager-lab-setup verify-identities --plan /etc/swarma/lab/next-qualification-plan.json
/opt/swarma/lab/bin/swarma-credential-broker-lab prepare-next --plan /etc/swarma/lab/next-qualification-plan.json
```

These entries require acknowledged stop/retirement of affected old generations,
retain all custody/hold/revocation/time history, publish the new approved tuples
and closed one-start gate, and never reset a consumed debit or initialize an
existing store. Ivan then repeats section 7.4's bind/start/activation checks with
new operation/binding identities; no old binding is reopened. B5 must enumerate
the sequential Q4-to-Q5 and post-lift Q5-to-Q6 plans in the approved install plan.
The driver cannot approve or improvise either widening transition.

### Q5 — same-detector public plant, durable account hold, owner-only lift

```sh
/opt/swarma/lab/bin/swarma-lab-qualify q5 --case clean-control
/opt/swarma/lab/bin/swarma-lab-qualify q5 --case public-canary-match
/opt/swarma/lab/bin/swarma-lab-qualify q5 --case hold-ack-loss
/opt/swarma/lab/bin/swarma-lab-qualify q5 --case held-redial-and-restart
/opt/swarma/lab/bin/swarma-lab-qualify q5 --case nonowner-lift
/opt/swarma/lab/bin/swarma-credential-broker-lab hold-lift --account lab/anthropic --hold-file /etc/swarma/lab/current-hold.json
/opt/swarma/lab/bin/swarma-lab-qualify q5 --case owner-lift-readback
```

Valid clean control admits the intended use without a hold. Root's reviewed
qualification plan adds a **public test marker** as an extra detector needle;
it is not the key, a replacement matcher or a forced "return hold" flag. Actual
worker bytes containing it traverse the real scanner and durable hold bridge,
with no upstream forwarding. Real issued-version matchers remain enabled.
Require durably acknowledged whole-account hold, issue/renew refusal and existing
leases revoked. Ack-loss is an isolated transport fault; local use stays blocked
while the same ID reconciles. The controlled restart uses off-VM orderly stop/
start sealing, never an unsealed `systemctl restart`; a genuinely uncertain crash
burns the installation rather than claiming successful recovery. Worker/gateway
lift attempts and wrong hold IDs refuse. Ivan's root command alone lifts the
current hold after reviewing exact content; no ended lease/binding is revived.
Remove only the public plant/extra needle after evidence, then recheck clean.

**Evidence:** `q5.json`, public plant ID, same matcher/code identity, no-forward
counter, durable hold ID/revision/account, ack-loss retry ID, restart/redial
readback, nonowner/wrong-ID refusals and root lift result. Never report local
model-proxy `clear_block` or a fixture-only ledger as broker hold evidence.

### Q6 — ceiling, renewal, replay and expiry

```sh
/opt/swarma/lab/bin/swarma-lab-qualify q6 --case fixture-lifetime-901
/opt/swarma/lab/bin/swarma-lab-qualify q6 --case fixture-lifetime-900
/opt/swarma/lab/bin/swarma-lab-qualify q6 --case fixture-lifetime-1
/opt/swarma/lab/bin/swarma-lab-qualify q6 --case fixture-expiry-and-replay
/opt/swarma/lab/bin/swarma-lab-qualify q6 --case live-issue-renew
```

Negatives: an isolated **901-second activation** refuses before listener/material
creation; expired/retargeted/revoked/held/wrong-owner renewal refuses and clears
cached use. Replay and lost replies neither extend the recorded deadline nor
mint duplicate effects. Paired valid fixtures select 900 and a smaller lifetime,
exercise issue **and** renew through the real lab constructor, with the earliest
caller/binding/qualification/vendor bound. Run actual short-lifetime expiry on
an isolated native monotonic clock, never change colony1's clock. Valid live
control observes issue/renew metadata inside gateway custody, with duration at
most 900 and no later than every current authority bound. This is not vendor
key refresh. Fixtures with injected time are separately labeled and cannot
claim native elapsed-time expiry.

**Evidence:** `q6.json`, protected selector digest/value, constructor verdict,
trusted time/uncertainty and authority bounds, issue/renew operation/lease IDs,
recorded exclusive deadlines, replay/no-effect and native expiry observations;
no material payload. Unknown vendor expiry remains explicit null.

### 8.1 Stop, export and burn rather than restore

```sh
/opt/swarma/lab/bin/swarma-credential-broker-lab quiesce --account lab/anthropic
/opt/swarma/libexec/swarma-user-manager-lab-setup stop-worker --plan /etc/swarma/lab/stop-plan.json
systemctl stop credential-gateway-lab.service
/opt/swarma/lab/bin/swarma-credential-broker-lab seal-stop --off-vm-receipt /etc/swarma/lab/stop-ack.json
systemctl stop swarma-credential-broker-lab.service
/opt/swarma/lab/bin/swarma-lab-qualify export-evidence --destination /var/lib/swarma-lab/evidence/export
```

`seal-stop` requires an authenticated off-VM acknowledgment of exact final heads;
missing acknowledgment means not sealed and no restart. Verify no worker
processes under the manager's quiet-period rule, no old listeners/connections and
no remaining material use; active/exited service status alone proves none of
these. Export schema-validated metadata, release/approval/config/source pins,
real exits, timing/load bounds, completeness and SHA256SUMS; never raw logs or
secret verifiers. Ivan stores and reviews it off-VM. Ivan vendor-revokes the API
key in his own account; Infra retires the installation and rebuilds or destroys
the lab under its own approved procedure. **There is no snapshot restore command.**
The original plan's Opus review and Muse second evidence read remain required;
this producer neither performs them nor substitutes self-review for them.

## 9. G01–G19 disposition

"Closed by simplification" below means the **production dependency is removed
from this proposed design**, not that a replacement command is implemented or
qualified. Every named implementation/release gate still applies before execution.
The gap definitions are `I:RUNBOOK-GAPS-HANDOFF.md:9` through
`I:RUNBOOK-GAPS-HANDOFF.md:27`; the older runbook's source pins are not reused as
current proof. Steps 1/2, release templates, the cgo profile and launcher mapping
are now source-landed where section 2/6 says so, not installed-qualified.

| Gap | Lab disposition and remaining closure | Unit |
| --- | --- | --- |
| G01 | Still required: actual three-product tags/assets/sums, aggregate/bootstrap approval, second builds and release reviews. No real release identity supplied by this plan. | RB, RG, RM; Ivan |
| G02 | Closed by simplification for the full-installer archive/profile mismatch: lab aggregate supports reviewed flat broker/manager sets and gateway archive. Native NSS and gateway templates are landed; actual complete bytes remain G01. | B5, RB, RG, RM |
| G03 | Still required: safe root-owned copy/rehash, aggregate/member verifier and installed-byte receipt; source SHA checks alone insufficient. | B5 |
| G04 | Still required: manager genesis/deployment/qualification and launcher-enabled one-start profile, not a Boolean bypass. | M1; Infra |
| G05 | Still required: exact root setup, dedicated broker/control callers, managed gateway/worker, ranges/home custody and authentic helper invocation. Production terminal-provenance roles are replaced, not claimed implemented. | M1, B1 |
| G06 | Still required: lab daemon/unit/config plus real accepting custody/service/facts/time assembly; stopped production main remains unchanged. | B1, B2, B3, B5 |
| G07 | Closed by simplification of the production operator command: root lab `bind`, only after committed enrollment; its exact wrapper still must be built/tested. | B3 |
| G08 | Still required: bounded no-echo owner-terminal API-key receiver, peer authentication, no spill and safe UNKNOWN handling. Subscription setup-token ceremony is not needed. | B3, B4 |
| G09 | Partly source-closed: step-2 parent wiring is landed. Still required: true API-key kind/headers, durable hold bridge, UNKNOWN/recovery, final-use and total teardown qualification. | G1, B1, B4 |
| G10 | Still required: lab member placement/config/unit hardening, per-worker socket ACL and effective native readback; no guessed production executable symlink. | B5, G1, M1 |
| G11 | Partly source-closed: Claude mapping and seccomp are landed. Still required: approved native executor/artifact pin, bounded invocation, actual socket/FD and environment qualification. | M1, B4, RM |
| G12 | Still required: real bounded inference and exact caller/placeholder negatives with metadata-only effect readback. | B4, G1 |
| G13 | Still required: holder-custody matcher, lifecycle/surface inventory and complete scans; public plants prove the instrument without leaking the key. | B4 |
| G14 | Still required: genuine worker-kernel-peer service/legacy refusal and valid gateway control, not chmod-denied connect. | B4, B1 |
| G15 | Still required: root unbind, managed generation retirement, one-second native timing and independent stream/listener/connection observation. | B3, M1, G1, B4 |
| G16 | Still required: public match through real durable account-hold bridge, same-ID ack reconciliation, restart persistence and root-only lift. | G1, B1, B3, B4 |
| G17 | Still required: sole lab selector-to-constructor path, issue/renew/replay/expiry and isolated >900 refusal with actual exits. | B1, B2, B4 |
| G18 | Not needed for Q1–Q6: snapshot creation/restore/reset. DN-09 C explicitly forbids restore; orderly-stop/off-VM seals, vendor revoke and fresh-install retirement remain required. | B2, B5; Ivan, Infra |
| G19 | Closed by simplification: separate API-key-only qualification aggregate/root sequence replaces the stale full-platform/other-account installer chain; no claim to run or fix that production installer. | C0, B5 |

## 10. Review packet and present limits

The handoff contains the implementation DAG, acceptance/LU allocation and owner/
Infra sequence. The exact new lab byte schemas/closed root verb arguments and
compatibility fixtures must be frozen by C0 before parallel implementation; this
proposal does not masquerade as those implemented codecs.

Current result of **every Q1–Q6: NOT RUN**. No Go product change, default behavior,
reviewer test, live account, host, unit, store, key, release or activation was
modified by this unit. This documentation can be ready for review while all
execution gates above remain open. Missing native time/SSH/API compatibility
must be resolved with real evidence, not a passing mock. The production assembly,
its Curator Core acceptance, hosted review/checks and eventual landing remain
separate work; push/publication is disabled for this task.
