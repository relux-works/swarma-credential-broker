# Lab profile v0: capped Anthropic API key on the dedicated lab VM

**Status: PROPOSED. Design for review, not an executable release or an activation approval.**

**DECLARED CONFLICT — LAB ONLY, NEVER PRODUCTION.** The owner's decision of
2026-11-20 selects a manual-root lab route instead of the production assembly.
This profile deliberately does **not** satisfy broker section 14's authenticated,
content-signed operator ceremony or `spec/operator-and-activation-v0.md`'s
DN-01–DN-08 implementation. Its DN-09 **option C** proposal also conflicts with
`docs/time-contract.md` and `docs/qualified-time-api.md`; C's own opening
conditions in section 4 remain mandatory. Production A is not changed.
It replaces those operator mechanisms with commands the owner runs in the owner's own root
SSH session. It never enables the production daemon, accepts a production
activation document, imports a subscription token, or claims Curator Core
acceptance. The production path remains separate and closed pending its own
acceptance and qualification. Basis: `B:spec/broker.md:880`,
`B:spec/operator-and-activation-v0.md:1373`,
`B:spec/operator-and-activation-v0.md:1737`.

All new command names, schemas, build tags and test names below are **proposed
interfaces to implement**, not commands available at the inspected pins. Sections
6–8 become an execution runbook only after the listed units, released bytes,
native preflight and the owner's in-person approval exist. This document authorizes no root execution, credential operation, release
publication or Q check before its execution gates are met.

## 1. Authority, sources and book disposition

The newer decision supersedes the supplied qualification plan's subscription
login and snapshot-reset steps **for this lab only**. The account is a dedicated
Anthropic **API key with an owner-approved spend cap**, never the owner's subscription or
`claude setup-token` output. The owner creates and enrolls it personally. The six Q
requirements are reproduced in section 8; its controls remain mandatory. The
cap belongs to the vendor workspace/project or other enforcing billing object,
not the key bytes: record that object, its hard limit, period, effective readback
and ownership; an advisory alert or an unverified cap is insufficient.

Evidence notation is `alias:repository-relative-file:first-line`; citations
resolve at these immutable inspected commits, not at an older runbook's pins:

| Alias | Source | Inspected revision |
| --- | --- | --- |
| B | swarma-credential-broker | `00e24b83ece1257bc85f988d5c8dda288aeec77d` |
| G | swarma-chain-lab | `87e8a7e41a073f6fb3b6ff2d09299162ee16deb3` |
| M | swarma-user-manager | `7c5e9eebbaf859246d4e5adc600a6727e5773e34` |
| D | swarma-docs | `bc1132c9d9be60864ef7195efa83215357ad3011` |
| W | `docs/lab-wire-profile-v0.md` in this revision | exact-binary synthetic wire/body observation, 2026-11-20; repository reproduction limit stated there |

Historical qualification and implementation plans are background only. All
load-bearing Q requirements, gap definitions, unit allocations and source pins
are reproduced here; an unpublished input is not an acceptance authority.

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
the threat model: root can already read either holder. This profile trusts the owner's
root session; it does not prove a UID-0 process is the owner rather than another root
actor. Worker and gateway UIDs have no root-control or hold-lift authority.

**No privileged agent reach is an enrollment precondition for the entire key
life, through confirmed vendor revocation.** Establish the exclusion **before
vendor key creation**, not merely before enrollment. Infra enumerates and attests all
effective guest root/sudo/SSH principals, privileged groups/capabilities and
indirect elevation routes, console/rescue users, hypervisor admins and
snapshot/backup/restore delegation. It checks both guest authorization and the
external control planes. No agent identity, agent-held credential, automation
session or agent-controlled elevation path may hold root, sudo, console,
hypervisor or snapshot authority. The repository owner verifies Infra's complete
roster and human/operator attribution, approves it off-VM **before key creation**
and controls the window until vendor revocation. The enforced order is fresh
access verification, authenticated prompt, then vendor creation, all inside that
window; no pre-prompt check claims to know a future creation instant. After
enrollment or abort, the owner records the actual creation instant and window
off-VM. An agent's unprivileged worker UID is not privileged access.

The same `swarma-broker-lab-access-attestation/1` has two mandatory off-VM
sections, approved by the owner rather than inferred from guest UID checks:

- **Owner endpoint, every owner root session through vendor revocation:** the owner attests
  a nonrecording endpoint and vendor-console browser profile and terminal with
  no agent process, browser automation or extension with page access, screen
  capture, remote desktop, screen-control or computer-use session. Clipboard
  history and sync are disabled. No password manager, notes, transfer file or
  other interim holder is used; only the immediate transient transfer from the
  one-time display to the authenticated no-echo prompt is allowed. Clear the
  clipboard and close the one-time display immediately after input or abort.
  A key exposed to, displayed in or reachable from an agent context is
  **ineligible and vendor-revoked**, never admitted after cleanup. After enrollment,
  each root session remains inside this trusted boundary; re-attest it before
  activation, each Q group and every later widening act. The production
  endpoint exclusion and ineligible-credential rules remain the basis:
  `B:spec/operator-and-activation-v0.md:304` and
  `B:spec/operator-and-activation-v0.md:621`.
- **Vendor organisation for the whole key life:** the owner inventories effective
  principals and delegated credentials/sessions able to administer the lab
  workspace, its enforcing cap/limit, or its keys, including create, re-scope,
  disable and limit-change rights. No agent identity, agent-controlled session
  or agent-held admin key is allowed, even behind a human principal's name.
  Read back the complete roster and cap **before creation and before each Q
  group**; compare with the owner-approved roster, workspace and limit. Any
  change invalidates admission and quiesces use. Missing visibility or doubt
  means no creation/use, or revoke and recreate after exclusion is re-established.
  The owner freezes changes and reviews the vendor organisation's audit log
  off-VM from the approved baseline through revocation, detecting grants or cap
  changes made and reverted between readbacks. A gap in audit coverage is
  incomplete admission, not proof that no change occurred.

B3/B4 admission fixtures pair an owner-only endpoint and vendor roster valid
control with **endpoint-agent-reachable** and **vendor-agent-admin** negatives
(and missing/stale/changed readbacks). Each must refuse before capture or key
use, with no credential/lease effect; use public inert data, never expose a real
key to test a forbidden endpoint. A04 and A12 carry both negatives.

`verify-access` compares all three attested surfaces: native guest/external
control-plane readback, owner endpoint exclusion, and owner-obtained complete
vendor roster/cap readback. It runs before creation/enrollment, activation and
each Q group; the owner performs and approves the off-VM readbacks. A local
Boolean cannot substitute for those observations or remotely prove endpoint
cleanliness. Its metadata records their scope, digest, freshness and window.
Missing external visibility is incomplete, not absence of access. Freeze access
changes during the window and audit them off-VM; any change invalidates admission,
quiesces use and requires owner review/vendor revocation if exclusion is lost.
Every root command below, including every qualification/scanner/export command,
runs only in the owner's own root session. Agents receive only the schema-checked
sanitized export, never root, raw scan streams or an interactive matcher.

### 2.1 What already works, and what does not

The existing **OAuth** launcher mapping is landed: its closed values fix
`ANTHROPIC_UNIX_SOCKET`, `ANTHROPIC_BASE_URL=http://api.anthropic.com` and
`CLAUDE_CODE_OAUTH_TOKEN=ssh-placeholder`; it never sets `ANTHROPIC_API_KEY` or
`ANTHROPIC_AUTH_TOKEN`. See `M:internal/launch/mapping_linux.go:152` and
`M:internal/launch/mapping_linux.go:186`. The filter allows AF_UNIX, rejects other
socket families and io_uring, and sets NoNewPrivs:
`M:internal/launch/confinement_linux.go:12`.

The lab does not convert an OAuth client into an API-key client on the wire.
M1 adds a `manager_lab`-only closed mapping kind `claude-api-key-lab-v0`, retaining
the socket, HTTP base and seccomp but setting only
`ANTHROPIC_API_KEY=ssh-placeholder`; both `CLAUDE_CODE_OAUTH_TOKEN` and
`ANTHROPIC_AUTH_TOKEN` are unset, as are all inherited authentication variables.
The production mapping is unchanged. Build the manager and every launch-mapping
consumer with `manager_lab` for this VM; an untagged reader refuses the new kind.
This is the measured API-key row:
`W:docs/lab-wire-profile-v0.md:19` and
`W:docs/lab-wire-profile-v0.md:34`. A caller cannot select arbitrary environment.

**The managed gateway does not already support an API-key lease.** Distinguish:

- The generic model-proxy credential abstraction already has `api-key` and
  `oauth-bearer`: `G:experiments/model-proxy/credential.go:17` and
  `G:experiments/model-proxy/credential.go:233`. That is not permission to use
  its development/file credential mode in this lab.
- The older `service.Claude` adapter declares `claude-oauth-token` and attaches
  bearer authorization: `G:experiments/model-proxy/service/adapter_linux.go:115`
  and `G:experiments/model-proxy/service/adapter_linux.go:159`.
- The **actual step-2 intake** also requires `scheme == "oauth-bearer"`, attaches
  `Authorization`, applies the closed `pricedBetaProfile` gate, then copies
  the admitted `Anthropic-Beta`:
  `G:experiments/model-proxy/service/intake_linux.go:274`,
  `G:experiments/model-proxy/service/intake_linux.go:309` and
  `G:experiments/model-proxy/service/intake_linux.go:358`.
- Its client/source require `claude-oauth-token`:
  `G:experiments/model-proxy/service/client_linux.go:355` and
  `G:experiments/model-proxy/service/source_linux.go:44`. The broker also fixes
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

Freeze the **API-key-mode** eleven-token profile, not the OAuth profile.
The landed gate is `G:experiments/model-proxy/service/intake_linux.go:126`, its
fourteen-token OAuth set is at
`G:experiments/model-proxy/service/intake_linux.go:138`, its use at `G:experiments/model-proxy/service/intake_linux.go:283`, and
header copying at `G:experiments/model-proxy/service/intake_linux.go:359`. That gate is useful machinery but is not the lab API-key allowlist.
The API-key wire row and body-field table are committed in
`W:docs/lab-wire-profile-v0.md:34` and `W:docs/lab-wire-profile-v0.md:50`.
The set is exactly:

```text
claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,thinking-token-count-2026-05-13,mid-conversation-system-clear-at-2026-08-21,effort-2025-11-24,thinking-binding-controls-2026-08-01,cache-diagnosis-2026-04-07
```

1. Only HTTP/1.1 on the qualified Unix socket. Match SO_PEERCRED to the approved
   worker tuple; the placeholder is not authority. Admit exactly
   `POST /v1/messages?beta=true` with one `x-api-key: ssh-placeholder` and no
   Authorization, or credential-free `GET /api/claude_code/policy_limits`.
   Reject duplicate/case-colliding credential headers, other paths/methods and
   any worker-supplied real key before forwarding. Scan before injection and
   after loading the complete current issued-version inventory.
2. Construct a fresh upstream request. Preserve the admitted path/query, Messages
   JSON bytes and incremental SSE. Fixed TLS host/SNI is `api.anthropic.com`;
   no proxy environment, redirects or arbitrary endpoint. Copy only the reviewed
   protocol-header allowlist; `anthropic-version` is `2023-06-01` for this pin.
3. Remove all worker authentication. **POST only:** install exactly one
   `x-api-key` from the current API-key lease. **Policy-limits GET:** forward
   credential-free, with neither x-api-key nor Authorization. Never forward
   Proxy-Authorization, Cookie or another credential. Neither placeholder nor
   real key enters a URL, error or another header.
4. Parse the beta comma-list, trim ASCII whitespace, require exact lowercase
   tokens, reject empty/duplicate/case-variant tokens and multiple header fields,
   and reject any token outside the eleven-token set. Retain every admitted
   non-OAuth token, canonicalized in the order above; require the measured set
   for the frozen invocation. **Do not strip all beta flags.** OAuth-specific
   `oauth-*` flags never reach upstream: this API-key mapping emits none, and
   receiving one refuses the request instead of silently converting its mode.
   `tool-provenance-2026-10-26` and `extended-cache-ttl-2025-04-11` are absent from
   the measured API-key row, not classified as OAuth-only; receiving either
   refuses. No body fields are silently deleted to fit another mode.
5. Preserve beta/body coupling: `cache_control.scope:global` requires the scope
   flag; `context_management` requires context-management; diagnostics requires
   cache-diagnosis; top/per-message effort keeps effort/per-turn-control.
   Keep thinking and other measured flags even when one bounded turn does not
   exercise their features. Reject a beta-dependent field without its required
   flag, including a one-hour TTL under this no-extended-TTL profile. The landed
   **OAuth** fixture at
   `G:experiments/model-proxy/cmd/model-proxy/testdata/claude-code-2.1.328-messages.json:11`
   has both scope and `ttl:1h`; it is a negative against API-key-mode substitution,
   not evidence that the plain API-key client sends that TTL.
6. Policy-limits GET keeps the fixed upstream and current admission checks,
   **not credential injection**: the measured API-key client sends it without
   credentials (`W:docs/lab-wire-profile-v0.md:31`). Do not reuse the landed OAuth
   intake's bearer attachment (`G:experiments/model-proxy/service/intake_linux.go:309`).
   Preserve the genuine status/error, including authentication/unsupported
   errors; never synthesize successful restrictions. Pair credential-free GET
   as the valid control with a worker-supplied key/Authorization on GET refused
   before forwarding. Native Q1 must show the pinned invocation tolerates that
   genuine result; local wire success is not vendor authorization.
7. Clear Authorization and x-api-key from holder-owned objects on every terminal
   path; the current Drop removes only Authorization
   (`G:experiments/model-proxy/service/adapter_linux.go:181`). No headers/bodies,
   key fingerprints or transport objects in logs/errors.

C0 freezes the exact model, output/cost bounds and invocation before release;
the probe's observed default `max_tokens:128000` is **not** a live budget approval.
G1 must not reuse the landed single-value beta check: it checks only
`values[0]` at `G:experiments/model-proxy/service/intake_linux.go:283`, while
copying every value at `G:experiments/model-proxy/service/intake_linux.go:359`.
`TestLabAPIKeyDuplicateBetaFields` must reject two Anthropic-Beta fields before
forwarding beside the valid single-field measured request; A02 owns this case.
G1/M1 tests pair the valid measured API-key request, all eleven flags retained
and coupled fields preserved, with OAuth-mode input/flag forwarding, unknown or
duplicate/case-variant beta, missing required beta, one-hour TTL, wrong marker,
kind/scheme, redirect/proxy and failed cleanup. Test the actual managed path,
not merely the older adapter. Upstream errors/status and SSE remain faithful.

## 3. Lab authority, state and retained enforcement

### 3.1 An activation no production reader accepts

Build the broker lab command only with `linux && broker_lab`, and the gateway
lab command only with `linux && gateway_lab`. Use separate executable names,
unit names and broker state roots/records. No environment or production CLI switch
selects the lab. API-key kinds, custody metadata, service records and constructors
exist only in `broker_lab`-selected files or lab-only packages, never untagged
production packages. Extend `TestInactiveImportGraphBuildTagControls` in
`B:internal/assemblyv0/importgraph_test.go:326`: a default importer of lab code
and a tag-selected forwarder into a production entry must be detected by named
negative plants, beside the valid lab command graph. Untagged builds retain the
stopped production owner:
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
environment ceiling. The gateway's existing `max_lifetime_seconds`
(`G:experiments/model-proxy/cmd/model-proxy/managed_linux.go:30`) must equal this
selector byte-for-value or refuse startup; it is not a second source of authority.
A mismatch fixture refuses before listener/material creation. An absent or valid disabled marker never permits material use. Root enrollment
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
Cross-read tests cover every closed lab record in section 5.2, including custody
metadata against `B:internal/claude/account_linux.go:145` and the service journal,
with valid own-format controls, not activation alone.

The manager/launcher/NSS deployment remains in `/opt/swarma/libexec`; manager
identities/journal keep their existing production format, and the gateway socket
remains under `/opt/swarma/run/credential-gateway/<generation>/`. Only broker
state is separate. This dedicated VM is lab-tainted until permanent retirement;
its manager state and installed lab bytes are never promoted to production.

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
  redact and continue. Only the owner's root
  `hold-lift` with the exact active hold ID may lift; lifting never revives an
  ended lease or unbound service. No `clear_block` substitute.
- **Revocation:** one-second end-to-end bound, not merely a one-second poll
  constant. The lab sets 250 ms cadence + **200 ms RPC timeout**, strictly
  below the 500 ms watchdog, leaving 50 ms scheduling margin; cancellation/closure
  takes at most another 500 ms under qualified load. The landed defaults are
  250 ms/250 ms (`G:experiments/model-proxy/cmd/model-proxy/managed_linux.go:36`
  and `G:experiments/model-proxy/cmd/model-proxy/managed_linux.go:37`),
  so G1 must change the timeout rather than claim the defaults have margin. Independently arm a **500 ms**
  watchdog from the last successful current check; watchdog closure must finish
  within another 500 ms, hence at most 1 s from that check. Measure both paths.
  Unavailability, missed deadline, stale generation or hold cancels in-flight
  upstream use, closes every affected downstream/broker connection and retires
  the old listener; no cached permit or automatic stale-generation redial.
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
`owner.Owner` adapter for the legacy exposed path. Before enrollment the lab
control plane runs without constructing `service.NewWithLifetime` with an empty
map, which currently refuses. After verified durable enrollment, initialize the
fresh lab service journal once and construct the controller from that committed
account. Crash/orphan/uncertain writes stay unavailable; no missing-as-empty
reinitialization. This bounds the bootstrap work without claiming U30 landed.

## 4. DN-09 C: opening decisions, NTS and no restore

C is a proposed exception, not an already-open profile. Its own opening rule is
`B:spec/operator-and-activation-v0.md:1137`: the repository, time-contract and
user-manager owners must explicitly accept the **exact amendment bytes**, joined
start/high-water rules and dedicated machine/account/revision/expiry.
Accepting only the residual cannot open C
(`B:spec/operator-and-activation-v0.md:1143`). Section 9 still says C is
not in force (`B:spec/operator-and-activation-v0.md:1756`). This document does not
amend production acceptance or infer missing owner decisions from root access.

### 4.1 Dated lab decision record and open conditions

| Record / condition | Dated act and scope | Present status |
| --- | --- | --- |
| OD-LAB-2026-11-20 | On 2026-11-20 the repository owner selected lab path B for the dedicated lab VM, a dedicated capped API key enrolled personally, NTS/no restore, and accepted the live whole-VM snapshot/rollback residual for this lab. This paragraph records that owner act. | Recorded lab direction and residual acceptance only; not a release/activation approval. |
| C-OPEN-OWNERS | Repository, time-contract and user-manager owners accept the exact API-key variant in 4.2, qualified-time API text, joined start/high-water rules, protected VM/account/revision/expiry and residual. A single act may cover roles only if it explicitly names authority for each; an override must explicitly establish that authority and scope. | **Not recorded** by OD-LAB-2026-11-20; mandatory before B2's live construction/qualification or any enrollment/use. |
| C-OPEN-JOINS | Every-start outside-home fence and off-VM clock/final-head approval; exact manager journal prefix persisted before release, never observed-state reset. | Specified below; implementation/native evidence still required. |
| C-OPEN-PROTECTION | Complete guest/control-plane exclusion for the key life, owner-endpoint exclusion for every owner root session through vendor revocation, and agent-free vendor-organisation workspace/cap/key administration roster, read back before creation and every Q group. The owner approves those observations, cap readback, exact release/invocation/VM identity and fixed expiry off-VM; any change invalidates admission. | Required execution inputs, not supplied by this proposal. |

C0 freezes a `swarma-broker-lab-owner-decision/1` record naming all three owner
roles, the amendment/API/join digests and installation, independently verified
VM/account, qualification revision and expiry. Its approval record is kept
off-VM and copied through the reviewed root verifier; self-asserted guest bytes
are not approval. B2 implementation depends on accepted C0; its **live
construction/qualification additionally waits for C-OPEN-OWNERS**. B5 and the
enrollment/activation commands refuse without that record. Unknown or expired
acceptance is closed. The dated residual act does not invent an amendment,
qualification revision, expiry or another owner's consent.

### 4.2 Exact proposed API-key time-contract/API exception

The following is C0's lab-scoped amendment text adapted from
`B:spec/operator-and-activation-v0.md:1285`; the API clarification follows
`B:spec/operator-and-activation-v0.md:1349`.
It is proposed for the lab only, with `test_api_key=true` replacing the
subscription marker. All three owners must accept these exact bytes and their
digests; neither published production document is modified by this exception.

> For LAB PROFILE v0 under explicitly accepted DN-09 C only, a witness sharing
> the whole-VM rollback domain with its history may qualify consumption solely
> for the dedicated capped API-key account on the independently verified qualified
> VM, within the protected qualification revision and expiry. Home-level restore
> remains fenced; any restore requires fresh-install recovery. Undetected live
> whole-VM snapshot revert is an explicitly owner-accepted residual, not detected
> rollback protection. This exception never qualifies production consumption,
> another VM/account, or an unaccepted/expired revision.
>
> C1 fresh-install recovery, including after a detected restore, permanently
> retires the burned installation and its enrolled time scope. The old history
> must never be consumed again. C1 means section 4.3 of
> spec/operator-and-activation-v0.md at the accepted qualification_revision;
> recovery requires restore, clone or regression evidence recorded off-VM,
> not an ordinary time hold or a wish to reset history. This exception is only
> for the dedicated capped API-key account on the qualified VM within the protected
> revision and expiry. The authority/clock scope has no consumer other than
> that broker lab installation. Another consumer sharing it refuses C1:
> retirement cannot partition the shared history or admit another consumer
> through the new scope (time-contract.md:204-205 and :218-219 at the source pin).
> Only after vendor revocation of the old API key
> and replacement of every old root, grant and binding may an installer enroll
> a fresh, initially empty history for a new never-reused installation_id and
> consumer/continuity scope bound to that installation on the same qualified
> VM. Record old-scope retirement and old/new identities off-VM before enabling
> the new scope; retain the recovered old time history and surviving records
> off-VM as evidence, without claiming lost high-water or holds recovered.
> No old lease, grant, binding, watermark or hold is imported into, or used to
> admit, the new history, revived or released. Any recoverable retired W or
> hold bound, and the off-VM retirement instant, act only as refusal floors for
> the new scope's first consumption and time-box predicate; they never admit
> anything or initialize the new checkpoint/watermark. The first trusted
> interval's lower bound must be strictly beyond each applicable floor; a
> missing required comparison refuses. Expiry is checked against the maximum
> of trusted now, the new watermark and those floors; reaching the protected
> qualification_expires_at refuses. C1 is not a hold-release route: a retired
> scope's unreleased sticky hold or unresolved time incident prevents
> consumption from the same source until the protected recovery policy
> qualifies it under the current or a newly accepted qualification revision;
> a new revision alone does not release the source. Off-VM pre-start approval
> also checks the unchanged
> qualification_expires_at against an off-VM clock and these refusal floors;
> reaching expiry or unknown/untrusted clock evidence refuses approval.
> The new authoritative checkpoint and broker
> watermark are established from fresh qualified NTS evidence under their
> respective settlement rules before consumption, never from retired history.
> This is not migration, a hold release or a repair of the old scope by a good
> report; that scope remains permanently closed. Without this exact accepted
> C1 exception, replacement or empty-history rebinding still refuses.
>
> Within each admitted history, and everywhere outside these explicit C-only
> exceptions, all settlement, authenticated-time, watermark and sticky-hold
> rules remain mandatory. Restart/reboot within a scope retains its high-water
> and holds; neither reinstall nor a new operation extends the accepted
> qualification expiry or admits production. The ordinary
> production consumer remains closed; fixtures alone qualify no backend.

> DN-09 C qualification requires its separately accepted machine-bound lab
> implementation and deployment evidence. Existing fixture constructors or test
> tags do not select that profile or qualify it, and no C result activates or
> qualifies the ordinary production consumer.

### 4.3 Joined start, high-water and native obligations

On the dedicated lab VM this means all of the following, not merely "chrony is synchronized":

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
   clone/restore/regression burns the installation. The owner vendor-revokes the old
   API key; Infra retires the installation/time scope off-VM and reprovisions;
   use a new never-reused installation and scope, fresh authority and fresh key.
   Import no old lease/grant/hold/checkpoint. An ordinary time incident is not
   permission to erase history, release a sticky hold or extend the time-box.
6. **The owner accepted the live whole-VM snapshot/rollback residual for this lab
   on 2026-11-20**, recorded as OD-LAB-2026-11-20 below. A live revert can roll back daemon, outside-home
   fence, store, high-water and time witness together and revive removed authority
   until vendor key revocation; local NTS and matching guest bytes do not detect
   that. Off-VM stop/start records help at the next manual boundary only. Preserve
   this explicit risk, the exact reviewed revision/VM/account and time-box in
   the owner's off-VM approval. No production promotion of any C result or witness.

The protected `test_api_key=true` marker, the dedicated lab VM's independently
verified identity and qualification expiry are mandatory at enrollment, bind, issue,
renewal and final use. Other accounts/VMs/revisions refuse. No hard-coded hostname
or locally self-asserted machine-id alone proves the qualified VM.

## 5. Acceptance allocation and unit plan

Both directions below are one canonical allocation: every listed unit carries
every listed row, cell for cell. C0 freezes contracts, B4 verifies integrated
rows and Q gathers native owner-run evidence; none substitutes for a producing
unit's named tests. These are lab acceptance rows, not a claim that product
coverage or native qualification already exists.

| Row | Required valid and forbidden outcomes | Units |
| --- | --- | --- |
| A01 | Tagged lab records/build graph work; production/lab activation, authority, custody, journal, fence and floor cross-read/import or production-store adoption refuses. | C0, B1, B2, B3, G1, M1, B5, B4, RB, RG, RM, Q |
| A02 | Measured API-key mapping injects exactly x-api-key and retains all eleven non-OAuth flags/required body fields; OAuth/unknown/duplicate/case-variant flag, two beta header fields, missing beta, wrong scheme, redirect and fake policy success refuse; credential-free policy-limits GET works, worker-supplied authentication on GET refuses. | C0, B1, G1, M1, B4, RG, Q |
| A03 | Current kernel gateway and managed caller execution work; worker/stale or reused UID, wrong class/placement, root JSON spoof and legacy material route refuse. | C0, B1, B3, G1, M1, B4, Q |
| A04 | Owner-only no-echo bounded capture with clean endpoint and unchanged human-only vendor roster works; endpoint-agent-reachable, vendor-agent-admin or changed roster, privileged agent reach, interim copy, spill, non-TTY/nonroot input, successor residue and second prompt for spent/committed/UNKNOWN operation refuse; prompt expiry and abort with no forwarded bytes conclusively close the spent ID without enrollment, beside timely committed input and read-only reconciliation controls. | C0, B3, M1, B5, B4, Q |
| A05 | Fresh committed account/journal and exact-ID status reconcile; orphan/missing-as-empty, contradictory retry, UNKNOWN replay and lost narrowing reserve refuse. | C0, B1, B3, B4, Q |
| A06 | Accepted exact C opening record plus native NTS/fence/prefix floor admits enrollment/activation/use; missing owner role/amendment/join decision, plain NTP, fixture witness, rewind or expired approval closes use; fresh post-bind access readback admits activation, while stale or changed readback after bind refuses activation without a marker/fence write or gateway start. | C0, B2, B3, M1, B5, B4, Q |
| A07 | Issue/renew obeys 1..900 and earliest deadline; gateway ceiling mismatch, >900, stale/replayed/retargeted or UNKNOWN duplicate effect refuses. | C0, B1, B2, G1, B4, Q |
| A08 | Whole-needle leak match durably holds the account; local-only/ack-loss reopening, nonowner or wrong-ID lift and ended-lease resurrection fail. | C0, B1, B3, G1, B4, Q |
| A09 | Root unbind/current control works; poll removal closes all affected streams/connections/listener within 1 s, and 500-ms watchdog plus closure within another 500 ms is independently measured; slow in-time current checks do not trigger teardown. | C0, B1, B3, G1, M1, B4, Q |
| A10 | Approved closed API-key lab mapping/Unix launch works; inherited auth, production OAuth mapping substitution, other families/io_uring/network FDs and unapproved executor refuse. | C0, M1, B5, B4, RM, Q |
| A11 | Approved complete lab aggregate/second build installs; production/lab tag confusion, unapproved digest, unsafe member/link/mode, substitution or missing native NSS closure refuses. | C0, M1, B5, B4, RB, RG, RM, Q |
| A12 | Owner-run complete lifecycle/surface scan and full guest/endpoint/vendor access attestation work; owner-only endpoint/roster is the valid control beside endpoint-agent-reachable and vendor-agent-admin/changed-roster negatives; missing real needle/version, partial-needle oracle, inaccessible surface, privileged agent access or raw evidence export refuses. | C0, M1, B5, B4, Q |

### 5.1 Unit-to-row plan, graph and LU

| Unit | Repository | Bounded implementation scope | Dependencies | Acceptance rows | LU |
| --- | --- | --- | --- | --- | --- |
| C0 | swarma-credential-broker | Freeze section 5.2 byte surfaces and API-key-mode/body fixtures once, with published reproducible probe artifacts; review the lab conflict and exact C amendment/join/owner-decision record. No inferred production acceptance. | none | A01,A02,A03,A04,A05,A06,A07,A08,A09,A10,A11,A12 | 0.5 |
| B1 | swarma-credential-broker | Tagged lab daemon and committed-account bootstrap; narrowly parameterized API-key custody/service record family; real managed gateway/caller facts; worker/legacy refusal; durable operation/hold/state and finite-plan narrowing reserve. Reuse service arithmetic/store, not a second lease engine or invented production receipt. | C0 | A01,A02,A03,A05,A07,A08,A09 | 1.5 |
| B2 | swarma-credential-broker | Tagged qualified NTS consumer/local C witness, settlement and sticky watermark/hold continuity; root off-home per-start fence, off-VM head/expiry join and persisted manager-prefix floor; burned-install/no-restore path. No production witness/default change. Live construction/qualification additionally waits for C-OPEN-OWNERS. | C0 | A01,A06,A07 | 1.5 |
| B3 | swarma-credential-broker | Root-only lab control protocol/CLI: prep/enroll/bind/activate/unbind/lift; authenticated broker peer before bounded no-echo stdin capture, no spill and native session retirement; per-operation UNKNOWN reconciliation. No signed production operator ceremony. | B1 | A01,A03,A04,A05,A06,A08,A09 | 1.0 |
| G1 | swarma-chain-lab | Tagged API-key managed source/intake with the exact eleven-flag API-key-mode profile; reject OAuth/unknown flags and unsupported coupled fields; preserve errors/SSE. Durable hold/recovery, deadline renewal, 500-ms watchdog and full one-second teardown. | C0 | A01,A02,A03,A07,A08,A09 | 1.5 |
| M1 | swarma-user-manager | Tagged closed API-key lab mapping with only ANTHROPIC_API_KEY=ssh-placeholder; preserve production mapping/seccomp. Format-owned setup and genuine helper/one-start executor; approved bounded invocation and no-privileged-agent access readback. | C0 | A01,A02,A03,A04,A06,A09,A10,A11,A12 | 1.5 |
| B5 | swarma-credential-broker | Root bootstrap/aggregate copy verifier and atomic placement; exact disabled unit/config/ACL/native-readback plan; off-VM preparation/next-plan/stop seals; source-owned lab bundle manifest. Not a full-platform installer or a root source build. Verify owner-role/access/cap records and generate persisted nonsecret operation envelopes after each predecessor commits and before its own invocation. | B2,B3,G1,M1 | A01,A04,A06,A10,A11,A12 | 1.0 |
| B4 | swarma-credential-broker | Tagged native qualification driver and protected lifecycle scanner; complete Q1–Q6 valid/negative/public-plant commands, actual worker peers, timing/stream observation, immutable metadata-only pack and bounded fixture cleanup. Native inert preflight precedes real-key use. In-custody needle attestation and root-only whole-needle matcher; owner executes every live Q command. | B1,B2,B3,G1,M1,B5 | A01,A02,A03,A04,A05,A06,A07,A08,A09,A10,A11,A12 | 1.5 |
| RB | swarma-credential-broker | Main-owned lab build/release profile and expected inventory, future signed broker tag, independent second build, checksums/provenance/fragment and release review. Production admission rejects lab tags; lab admission builds lab-only targets. | B4 | A01,A11 | 0.5 |
| RG | swarma-chain-lab | Main-owned gateway lab archive/input policy and future signed tag; correct tagged binary/members/unit plus independent rebuild/review/checksums. Disjoint lab tag admission/provenance; cut only after B4 integrated verification. | B4 | A01,A02,A11 | 0.5 |
| RM | swarma-user-manager | Future signed manager tag including native cgo NSS probe, launcher, isolated setup/executor and exact Claude dependency; native closure and independent rebuild/review/checksums. Disjoint lab tag admission/provenance; cut only after B4 integrated verification. | B4 | A01,A10,A11 | 0.5 |
| Q | swarma-credential-broker | Owner-run Q1–Q6 on the dedicated lab VM with sanitized evidence, independent record review and second evidence read. No credential or privileged host access by an agent. | RB,RG,RM; owner/Infra gates | A01,A02,A03,A04,A05,A06,A07,A08,A09,A10,A11,A12 | 0.5 |

Total estimated effort is **12 LU**. The precedence-only critical path is
**6.5 LU**: C0 → B1 → B3 → B5 → B4 → RB → Q. The implementation graph is:
C0 → {B1, B2, G1, M1}; B1 → B3; {B2, B3, G1, M1} → B5;
{B1, B2, B3, G1, M1, B5} → B4 → {RB, RG, RM};
{RB, RG, RM} → Q. C-OPEN-OWNERS additionally gates B2 live construction/qualification;
owner/Infra/release acceptance gates remain prerequisites, not invented duration.

At planned parallel width **3**, this feasible resource-constrained schedule is
**7 LU**; width is an assumption, not a claim about available workers:

| LU window | Slot 1 | Slot 2 | Slot 3 |
| --- | --- | --- | --- |
| 0–0.5 | C0 | — | — |
| 0.5–2 | B1 | B2 | G1 |
| 2–3.5 | M1 | B3 until 3 | — |
| 3.5–4.5 | B5 | — | — |
| 4.5–6 | B4 | — | — |
| 6–6.5 | RB | RG | RM |
| 6.5–7 | Q | — | — |

One LU includes bounded implementation, review, a fix round and accepted landing.
These estimates are provisional: no measured unit durations were supplied. The
reference is the bounded scope in this table and the landed broker, manager
mapping and gateway step-2 mechanisms cited in sections 2–3, not an unpublished
full-path estimate or a measured velocity claim. B1/B4 are broad; if splitting is needed, preserve these acceptance
obligations and recompute the graph/estimate before changing the plan.

Separately unestimated: all owner-role C decisions, key/cap setup, digest/risk
approval, Infra T2 phase A and access exclusion, native SSH/NTS windows, CI/review
availability and vendor compatibility. Production Curator Core acceptance is
separate and cannot be inferred from any lab result.

### 5.2 C0's closed byte inventory and consumer joins

C0 freezes fields, canonical encoding, domain/version IDs, failure/UNKNOWN
semantics and shared positive/negative fixtures for every surface below before
parallel implementation. The lab format IDs are intentionally disjoint. Every
broker row has `TestLabProductionCrossRead<Surface>` in both directions with
valid own-format controls; production acceptance is never widened to pass it.
Existing manager-owned production records are the explicit exception in 3.1.

| Byte surface / lab format | Writer → readers |
| --- | --- |
| `swarma-broker-lab-activation/1`, `swarma-broker-lab-authority/1`, `swarma-broker-lab-preparation/1` | B3/B5 → B1/B2/G1/M1/B4 |
| `swarma-broker-lab-owner-decision/1`, `swarma-broker-lab-off-vm-approval/1`, `swarma-broker-lab-access-attestation/1` | Owner/Infra through B5 verifier → B1/B2/B3/M1/B4 |
| `swarma-broker-lab-start-fence/1`, `swarma-broker-lab-consumer-high-water/1`, `swarma-broker-lab-time-checkpoint/1` | B2/B5 → B1/B2/G1/B4 |
| `swarma-broker-lab-custody/1`, `swarma-broker-lab-account/1`, `swarma-broker-lab-service-journal/1` | B1 → B1/B2/B3/G1/B4; production metadata/journal readers must refuse |
| `swarma-broker-lab-install-plan/1`, `swarma-broker-lab-launch-plan/1`, `swarma-broker-lab-retire-plan/1`, `swarma-broker-lab-next-plan/1`, `swarma-broker-lab-stop-plan/1` | B5/M1 → M1/B1/B3/B4; bind exact manager request IDs and receipts |
| `anthropic-api-key-lab/1` lease kind and `api-key` source scheme, exact API-key mapping/header/beta/body fixtures | B1/M1 ↔ G1; B4 verifies; no OAuth relabeling |
| `swarma-broker-lab-hold/1`: `leak_match`, account, caller, durable operation ID and same-ID result | G1/root matcher → B1; B3 lift and B4 observe |
| `swarma-broker-lab-operation/1`, `swarma-broker-lab-root-control/1`: root verbs, request/result, exits and reconciliation | B3/B5 ↔ B1/B4; no payload/fingerprint in results |
| `swarma-broker-lab-match/1`: root-only whole-needle request/verdict and issued-version attestation | B4/root collector ↔ B1; verdict only, durable hold on match |
| `swarma-broker-lab-q-evidence/1`: all Q rows, real command exits, effect/completeness/encoding bounds | B4 → Q and independent evidence readers |
| `swarma-lab-release-set/1`: all product/tag/asset/digest/mode/provenance and second-build comparisons | RB/RG/RM/B5 → root verifier/B1/G1/M1/B4 |

Root mutating requests carry `operation_id` (fresh 128-bit identifier), method,
installation/account, qualification revision, exact nonsecret input digests and
expected authority heads in a root-owned, immutable operation envelope. B5
generates each envelope **after its predecessor commits**, from the returned
committed heads and available exact inputs; the owner approves it off-VM
**before its own invocation**. Apart from already executed install/prepare acts,
only the enrol envelope precedes key entry. Bind/activate, Q4 unbind, Q5 lift,
next-generation, quiesce and stop-seal envelopes are not pre-generated with
unknown heads or hold IDs.
For enrollment the envelope binds preparation, never a public key hash. IDs are
not session identifiers or credentials and are never reused for another act.

All mutation verbs, including install/prepare/enrol/bind/activate/unbind/lift,
next/quiesce/stop sealing, take `--operation-from FILE`. The enrollment CLI
records attempted use durably before prompting and refuses a second prompt for
that ID after attempted, conclusively aborted, committed or UNKNOWN state. Unknown delivery is not
absence; status never initializes state. The concrete read-only command is
`status --operation-from FILE`: exit 0 means the exact act is committed, exit 2
means UNKNOWN/incomplete/not-started and grants no authority; definitive refusal
returns exit **1**, including a durably fenced `not_committed:enrol_no_forward`
result after an enrollment abort with conclusively zero bytes forwarded. That
result closes and spends the old ID; it is not authority to retry it. Invalid syntax returns **64**, authorization/closed admission
returns **69**. All outcomes retain their real command exits. Contradictory same-ID content refuses without mutation or prompt. Only
conclusive reconciliation and a separately approved recovery/next operation can
advance; retyping a key to resolve UNKNOWN is forbidden.

The Q2 matcher is a new **root-only**, bounded streaming interface, not a worker
or gateway substring oracle. It matches each complete current issued-version
needle under the closed encodings: raw bytes, JSON-escaped string, standard and
URL-safe base64 (padded/unpadded), and strict percent encoding (hex case variants).
For a needle embedded in a longer base64 run, the matcher internally derives
**all three byte-offset alignments (0, 1, 2)** and excludes partial boundary
sextets affected by adjacent bytes. These are holder-derived matching variants,
never caller-supplied partial needles. If an alignment has no nonempty stable
interior, scanning is incomplete, not clean. `scanner-plants` covers every
alignment for standard/URL-safe and padded/unpadded encodings, beside cleanup
clean controls; matching only offset 0 must fail.
Malformed or unscannable input is incomplete. It never accepts a caller-supplied
partial needle, returns offsets/prefixes/snippets, or reveals needle bytes/hashes.
Its result is only clean/match/incomplete; match invokes the same durable hold
path before acknowledgment. A protected attestation records nonzero current
issued-version count/IDs and complete per-encoding matcher initialization. An
empty/missing real needle is exit 2 even if public-marker controls pass.

## 6. Release set: approve bytes, not source claims

As of source inspection, broker tag `v0.1.0` is at `d6350aa2b2c00fa4015189f24d34450e37789908`
and manager tag `v0.1.1` at `b61b1eadc7cc7ef9fcd4e8e94b254f5766317f2b`;
there is no gateway `v*` tag. Those are **not** a usable lab release: they do not
contain the proposed lab assembly and the manager tag predates the inspected
launch mapping. Never substitute these tags or inspected source HEADs for an
approved future set. Release API observations are retained in the review packet.

Proposed reserved labels, to be created only by the separately authorized release
units after their changes land, are broker **lab-v0.1.0.1**, gateway
**lab-v0.1.0.1**, manager **lab-v0.1.2.1**. These labels do not yet identify any
artifact. If a label is already occupied when cut, select a new reviewed label;
never move it. Fill tag object IDs, full source commits and hashes from real builds.
Production tag admission must reject `-lab` labels as well as non-`v` labels;
lab admission requires exactly `^lab-v[0-9]+\.[0-9]+\.[0-9]+\.[1-9][0-9]*$`,
triggers only the lab workflow and builds only tagged lab targets. The existing
production grammar at `B:.scripts/release-admit.sh:6` admits `v...-lab...`, so it
must be tightened, not reused. The aggregate verifier requires lab provenance
for every product and refuses a production/default build even with matching
checksums. Lab labels do not sort as pre-releases of an existing stable tag.

| Product / unit | Build and install inventory |
| --- | --- |
| Broker / RB | Explicit `broker_lab` release target: `swarma-credential-broker-lab_linux_<ARCH>` and `swarma-lab-qualify_linux_<ARCH>`, disabled lab units, canonical schemas/fixtures and bounded root install/control runbook. Default release scripts do not magically build tagged commands. Install commands under `/opt/swarma/lab/bin/`. |
| Gateway / RG | Explicit `gateway_lab` target of model-proxy with the service module, packaged as a lab archive containing `credential-gateway/bin/credential-gateway-lab`, lab unit template and nonsecret config schema. Extend main-owned input policy, not a downloaded/tag-owned script. |
| Manager / RM | Explicit `manager_lab` manager and launcher, plus the **native cgo NSS probe** for the selected Linux architecture, plus the isolated `manager_lab` setup command and pinned bounded Claude executor. No second allocator or altered production helper authorization. Include source-approved deployment/skeleton/NSS closure and the Claude artifact pin. |

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
set; a version string is not an executable pin. Pin the dedicated lab VM's OS/architecture,
libc/NSS backend, chrony/NTS source policy and exact native preflight evidence.
No real host pins or artifact digests are supplied by this document.

Use the templates' main-owned admitted signed-tag workflow and independent second
build; compare complete bytes and checksums. Two release reads and required
checks remain gates. Signatures are consistency evidence, **not the owner's approval**:
`B:docs/releasing.md:10`, `B:docs/releasing.md:33`,
`M:docs/releasing.md:104` and `M:docs/releasing.md:111`.

**Before any root artifact step**, the owner reviews in person and records off-VM:
exact aggregate bytes and SHA-256, bootstrap binary SHA-256, site installation
operation SHA-256 and every nonsecret operation input, all product tags/
commits/checksums, second-build comparisons and reviews, installed paths/modes,
VM/OS/NTS inputs, lab-conflict text, planned lab account, vendor workspace and
cap-enforcing object/limit/period/readback, complete guest/control-plane/vendor
rosters and owner-endpoint exclusion, model/total cost and
inference limits, qualification revision/expiry and the C rollback residual.
No blank field, floating tag/model, unverified asset or source build on the dedicated lab VM
is accepted. No agent creates a key, supplies approval, tags or publishes this
planning checkout. **This approval records the workspace and cap object, not
a key. No key exists yet.** Key creation waits for section 7.3's completed 7.2
readback, fresh `verify-access` and authenticated prompt.

## 7. Proposed exact root runbook

**Execution preconditions:** C0/B1/B2/B3/G1/M1/B4/B5 and RB/RG/RM accepted;
C-OPEN-OWNERS records the repository/time-contract/user-manager approvals of
4.2 and joined start/high-water rules for this exact VM/account/revision/expiry;
all A rows pass native inert-key preflight; Infra T2 phase A and the complete
guest/control-plane, owner-endpoint and vendor-organisation access sections
are attested and verified by the owner, including current roster/cap readback;
cap-enforcing object/readback and aggregate/bootstrap digests are approved off-VM.
A dated residual acceptance alone satisfies none of the missing C-opening rows.
Only the owner runs sections 7–8.1, including every `swarma-lab-qualify` command.
Vendor validity is established by the owner-run Q1, never by inert preflight.
Use the selected released architecture, not a guessed uname mapping. All uppercase
`REPLACE_...` strings below are **nonsecret placeholders that must be replaced**;
validators refuse them. Never substitute a credential into any shell command.

The **Infra baseline (T2 phase A, already assigned to Infra)** means a fresh
dedicated lab VM with approved OS/kernel/architecture, native authenticated NTS
readback, protected owner SSH with recording/forwarding excluded, no Unix
forwarders or inherited network FDs, swap/hibernation/core-dump exclusion and
externally verified VM/control-plane identity. Section 2 adds the complete
access window; section 7.2 still owns the product-specific manager/NSS setup.
The phase label alone proves none of these preconditions.

### 7.1 Host tools and bootstrap, owner as root

Start in a fresh, nonrecording SSH session owned by the owner, not an agent/multiplexer.
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
test ! -e /var/lib/swarma-lab
test ! -L /var/lib/swarma-lab
install -d -o root -g root -m 0700 -- /var/lib/swarma-lab
test -d /var/lib/swarma-lab
test ! -L /var/lib/swarma-lab
test "$(stat -c %u:%g:%a /var/lib/swarma-lab)" = 0:0:700
mkdir -m 0700 -- "$STAGE"
cp --no-dereference -- "$SOURCE/broker/swarma-credential-broker-lab_linux_$ARCH" "$STAGE/lab-bootstrap"
test -f "$STAGE/lab-bootstrap"
test ! -L "$STAGE/lab-bootstrap"
test "$(stat -c %h "$STAGE/lab-bootstrap")" -eq 1
printf '%s  %s\n' "$BOOTSTRAP_SHA256" "$STAGE/lab-bootstrap" > "$STAGE/bootstrap.sha256"
sha256sum --strict --check "$STAGE/bootstrap.sha256"
chmod 0500 -- "$STAGE/lab-bootstrap"
"$STAGE/lab-bootstrap" install-set --source "$SOURCE" --set-sha256 "$SET_SHA256" --bootstrap-sha256 "$BOOTSTRAP_SHA256" --fresh-installation 'REPLACE_FRESH_INSTALLATION_ID' --operation-from "$SOURCE/lab-install-operation.json" --operation-sha256 REPLACE_APPROVED_INSTALL_OPERATION_SHA256
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
set -eu
/opt/swarma/libexec/swarma-user-manager-lab-setup prepare --plan /etc/swarma/lab/install-plan.json
/opt/swarma/libexec/swarma-user-manager-lab-setup qualify --plan /etc/swarma/lab/install-plan.json
/opt/swarma/libexec/swarma-user-manager-lab-setup create-identities --plan /etc/swarma/lab/install-plan.json
/opt/swarma/libexec/swarma-user-manager-lab-setup verify-identities --plan /etc/swarma/lab/install-plan.json
```

After the manager returns committed identity/journal heads, B5 generates the
`prepare.json` envelope from that readback and the owner approves it off-VM.
Then continue; no key has been created:

```sh
set -eu
/opt/swarma/lab/bin/swarma-credential-broker-lab prepare --plan /etc/swarma/lab/install-plan.json --operation-from /etc/swarma/lab/operations/prepare.json
/opt/swarma/lab/bin/swarma-credential-broker-lab status --operation-from /etc/swarma/lab/operations/prepare.json
systemctl daemon-reload
systemctl start swarma-credential-broker-lab.service
/opt/swarma/lab/bin/swarma-credential-broker-lab status --expect control-only
/opt/swarma/lab/bin/swarma-lab-qualify verify-access --attestation /etc/swarma/lab/access-attestation.json
```

M1's setup is a **new root installation entry**, not a claim the normal helper
accepts root. It provisions reviewed nonlogin broker/control-caller accounts,
closed policy/skeletons, native NSS/qualification/bootstrap and the one-start
launch gate using manager-owned format writers. No hand-authored identities or
generation journal. The normal helper rejects bare root
(`M:cmd/swarma-user-manager/main.go:72`); setup invokes it with genuine verified
sudo provenance through its separately pinned operator/dispatcher users, exact
no-argv rule, bounded stdin and dropped capabilities. It must not spoof SUDO_UID.

Existing gateway-create request remains exactly
`{"args":{"kind":"service","label":"credential-gateway"},"op":"user.create","request_id":"REPLACE_PERSISTED_REQUEST_ID","v":1}`;
worker creation is the corresponding approved `kind:"agent"` request from the
configured dispatcher. Persist request identities before invoking; same request
on uncertainty. Only the manager writes identities.json. Read back the returned
UID/GID/generation, active trusted/local service record and current journal-head
join (`B:internal/service/managed_linux.go:358`). The approved worker
placement/class and root:S home custody remain the manager's, not an installer
chmod workaround.

Manager qualification keeps the existing CAP_NET_ADMIN-excluding native entry,
current-boot qualification unit/readback and matching pins; no `qualified:true`
flip without it. `prepare` creates only the separately approved lab account plan,
fresh empty store and disabled marker. The broker starts **control-only**, with
no material-serving controller. No lease can be issued by these steps. After
committed preparation/readback, B5 persists only the next `enrol.json` envelope
under `/etc/swarma/lab/operations/`: fresh `operation_id`, `method:enrol`, account
`lab/anthropic`, exact preparation digest and committed expected heads. The
owner approves its nonsecret bytes off-VM before key entry. Generate each later
envelope only after its immediate predecessor commits and its inputs exist:
bind after enrollment, activate after bind, unbind after the current binding,
lift after the current hold ID, and next/stop acts after their exact predecessor
heads. Each has a different ID/file and a new off-VM approval before invocation.
The owner-approved site packet includes `lab-install-operation.json` for the
first step; its SHA-256 is independently approved off-VM. Immutable product
releases contain its schema/template, not a pre-used installation ID. The
bootstrap checks `--operation-sha256` before persisting this act;
no operation file contains a credential or a digest derived from one.

### 7.3 Enroll from the owner's terminal, with no transfer file

No key is created during release approval, bootstrap or preparation. Complete
7.2's metadata-only readback and the current endpoint/vendor/guest
`verify-access` inside the attested window. Use a **new dedicated root SSH
session with no parent server-side successor shell** and wait for the
authenticated no-echo prompt below. Only then does the owner create the
dedicated capped key in the owner's own vendor browser session and paste it
**immediately from the one-time display at that prompt**. There is no interim
copy or holder: no file, notes, password manager, clipboard history/sync or open
key display across approval/preparation steps. Clear the transient clipboard and
close the display immediately after input or abort. Any key created but not
entered because of timeout, refusal or abort is vendor-revoked, even without
suspected exposure; it is never saved for a later prompt. If the prompt/channel,
endpoint exclusion or vendor roster is uncertain, do not enter it; vendor-revoke
any newly created key and recreate only after exclusion is verified.

```sh
set -eu
set +x
set +o history
umask 077
ulimit -c 0
/opt/swarma/lab/bin/swarma-lab-qualify verify-access --attestation /etc/swarma/lab/access-attestation.json
exec /opt/swarma/lab/bin/swarma-credential-broker-lab enrol --account lab/anthropic --stdin-tty --preparation /etc/swarma/lab/preparation.json --operation-from /etc/swarma/lab/operations/enrol.json
```

Only **after the command's authenticated no-echo prompt** does the owner enter the key on stdin.
Do not paste it as a shell line, use shell `read`, command substitution, a pipe,
heredoc, environment variable, file, password manager CLI or a key-bearing flag.
`exec` retires that remote shell; no subsequent shell may read residue. If the
SSH/sudo stack cannot guarantee channel/TTY retirement, enrollment refuses before
prompt and the native lab entry must be corrected, not claimed safe by ancestry.

B3 verifies a root peer, approved preparation/VM/account, genuine terminal FD0,
no recorder, bounded raw no-echo capture (1..4096 printable ASCII bytes, a single
line), nondumpability, locked sensitive buffers and configured memory limits.
The authenticated prompt has one absolute monotonic **300 s** wait/capture bound,
shortened by preparation or attestation-window expiry; input never resets it.
Timeout/abort discards queued input and retires the channel. B3 must durably
fence the operation against future delivery before classifying a zero-forward
abort as `not_committed:enrol_no_forward`; merely losing the CLI is not proof.
`TestLabEnrollmentPromptDeadline` pairs expiry/no effect with timely valid input;
`TestLabEnrollmentNoForwardAbort` pairs conclusive zero-forward closure with an
uncertain partial/delivered request that stays UNKNOWN. B3/B4 own these A04/A05
controls; B5 owns the separately approved next-envelope path.
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
The envelope's persisted `operation_id` is the concrete reconciliation handle,
not a newly generated retry ID. In a new owner root session after disconnect:

```sh
set -eu
/opt/swarma/lab/bin/swarma-credential-broker-lab status --operation-from /etc/swarma/lab/operations/enrol.json
```

Exit 0 plus `state:committed` for that exact ID/account/preparation allows the
next metadata step. Exit 2/UNKNOWN/incomplete does not permit re-running enrol,
retyping the key, initializing an empty record or starting a new preparation.
A second enrol on committed or UNKNOWN input refuses **before a prompt**; pair
that negative with committed status as the valid A04/A05 control. Persist the
attempt before capture so a lost reply cannot masquerade as a fresh request.
Exit 1 with `not_committed:enrol_no_forward` is the ordinary conclusive-abort
path: after any created key is vendor-revoked and that act is recorded off-VM,
B5 may issue a fresh enrollment envelope from current committed preparation
heads for separate owner approval. The spent ID never prompts again. A new key
is created only at the next authenticated prompt. Every other ambiguous result
stays UNKNOWN and requires explicit owner recovery, never re-entry to discover
whether the old key was committed.
After committed enrollment the lab controller may be built; material use stays
closed until bind and activation.

**Owner-endpoint paste residual:** a refusal or early SSH exit before the prompt
can leave a paste in the owner's local shell/history. Server-side retirement
does not prevent that DN-04 residual
(`B:spec/operator-and-activation-v0.md:1751`). The owner checks the prompt/channel
before entering anything; if spill is suspected, revoke the key from the vendor
session and follow endpoint cleanup. Never describe remote no-echo/exec as
protection against pasting into the wrong endpoint.

### 7.4 Bind, fence, activate and start gateway

Reconnect in the owner's root session. All arguments/files below are nonsecret.
Reconcile committed enrollment before bind; reconcile each mutating result before
advancing. After committed enrollment, B5 generates the generation-specific
`bind.json` from those committed heads and the owner approves it off-VM.
UNKNOWN/status exit 2 stops this block and authorizes no retry:


```sh
set -eu
OPS='/etc/swarma/lab/operations/REPLACE_APPROVED_START_GENERATION'
/opt/swarma/lab/bin/swarma-credential-broker-lab status --expect enrolled-inactive
/opt/swarma/lab/bin/swarma-credential-broker-lab status --operation-from /etc/swarma/lab/operations/enrol.json
/opt/swarma/lab/bin/swarma-lab-qualify verify-access --attestation /etc/swarma/lab/access-attestation.json
/opt/swarma/lab/bin/swarma-credential-broker-lab bind --account lab/anthropic --service credential-gateway --identity /etc/swarma/lab/gateway-identity.json --authority /etc/swarma/lab/authority.json --operation-from "$OPS/bind.json"
/opt/swarma/lab/bin/swarma-credential-broker-lab status --operation-from "$OPS/bind.json"
```

After bind commits, B5 generates `activate.json` from its returned authority
heads and the owner approves it off-VM, together with the joined start approval.
B3 owns `activate`; no activation envelope exists with guessed pre-bind heads.
Re-attest the current endpoint and vendor roster/audit after this off-VM pause.
B3 refuses activation without a fresh `verify-access` result bound to the
current approved window, generation and unchanged three-surface observations,
rechecked before any activation effect. The pre-bind result is insufficient.
A06's `TestLabActivationAccessWindow` pairs fresh post-bind admission with stale
or changed access during approval: refusal leaves the lab marker/fence and
gateway state unchanged. Then run:

```sh
set -eu
OPS='/etc/swarma/lab/operations/REPLACE_APPROVED_START_GENERATION'
/opt/swarma/lab/bin/swarma-lab-qualify verify-access --attestation /etc/swarma/lab/access-attestation.json
/opt/swarma/lab/bin/swarma-credential-broker-lab verify-start --off-vm-approval /etc/swarma/lab/start-approval.json
/opt/swarma/lab/bin/swarma-credential-broker-lab activate --decision /etc/swarma/lab/owner-decision.json --operation-from "$OPS/activate.json"
/opt/swarma/lab/bin/swarma-credential-broker-lab status --operation-from "$OPS/activate.json"
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

Each approved start/next plan names a new immutable operation directory for
its manager generation. Replace `REPLACE_APPROVED_START_GENERATION` with that
exact generation, never a previous one. The new bind/activate envelopes have new
IDs; status for an old committed act does not authorize a changed act. The owner
reads the input-file ID and matches the status result's same ID/method/digest.

## 8. Q1–Q6: concrete command contracts, controls and evidence

The six qualification requirements are self-contained here:

| Check | Required outcome |
| --- | --- |
| Q1 | A worker request through the gateway succeeds: one bounded inference. |
| Q2 | Worker environment, argv, files and logs hold no key; scan worker surfaces and gateway logs. |
| Q3 | A worker asking the broker for the key directly is refused with no material. |
| Q4 | Revocation stops gateway use within the poll interval and closes the stale generation's connection. |
| Q5 | A planted leak match causes a durable hold; only the account owner lifts it. |
| Q6 | The 900-second lease ceiling and renewal behave as specified. |

All commands in this section run in the owner's root SSH session, never an
agent session. The driver drops to the genuine managed worker for worker-peer
controls; it does not grant that worker or an agent root. Before each Q group,
run `swarma-lab-qualify verify-access --attestation /etc/swarma/lab/access-attestation.json`.
The owner verifies guest/control-plane readback, the endpoint attestation and
the complete current vendor-organisation roster/cap readback; a changed roster
invalidates admission before the next group, even if guest bytes are unchanged.
Agents may read only the sanitized export after the owner approves its contents.

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
set -eu
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
set -eu
/opt/swarma/lab/bin/swarma-lab-qualify q2 --case scanner-plants
/opt/swarma/lab/bin/swarma-lab-qualify q2 --case missing-real-needle
/opt/swarma/lab/bin/swarma-lab-qualify q2 --case complete-clean-lifecycle
```

Negative control: individually plant a **public noncredential** marker in inert
worker environment, argv, file, worker-log and gateway-log fixtures. Include
standard/URL-safe base64, padded/unpadded, with the public marker at all three
byte offsets inside a longer encoded run; the matcher derives its own variants
and excludes partial boundary sextets. Offset-0-only matching is a failing
control. Pair each planted match with clean after owned cleanup. The same
scanner/configuration must detect each at its intended surface, then detect no
match after owned cleanup; an unreadable/missing/oversized fixture must return
incomplete, never clean. Valid: collect the complete declared Q1 lifecycle before,
at exec/during, and after, including children, every worker writable home/state/
work/tmp surface and actual gateway/worker logs. Raw bytes stream through the
protected broker-side matcher; real-key matchers never leave holder custody.
A root-owned lifecycle collector uses verified process identity and exec/stop
observation; an after-exit scan alone is not complete environment/argv evidence.
Sensitive scan buffers never enter an agent process or output file. A real match
halts the run and takes the same account-hold path as Q5. Before declaring clean,
require the protected nonzero issued-version count/IDs and every encoding's
whole-needle initialization attestation from 5.2. An isolated missing-real-needle
fixture must produce underlying exit 2/incomplete even with public plants green;
its paired valid control has initialized real needles and complete clean surfaces.
The root-only collector calls `match --operation-from FILE --inventory FILE`
through bounded stdin on the lab root socket; the closed result is only
clean/match/incomplete. No agent/worker can call it and no query accepts a prefix.
Root matcher operation IDs and hold acknowledgments are persisted like other
mutations; UNKNOWN never yields clean.

**Evidence:** `q2.json`, closed surface inventory, scanner/config digests,
current issued-version count/IDs, complete encoding initialization,
per-surface count/completeness/no-match verdicts, observation boundaries and
plant/detection/cleanup records. No universal no-leak claim beyond these bounded
surfaces/encodings/run. Missing visibility is exit 2, not a passing scan.

### Q3 — real worker refused by broker

```sh
set -eu
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
set -eu
/opt/swarma/lab/bin/swarma-lab-qualify q4 --case current-control
/opt/swarma/lab/bin/swarma-lab-qualify q4 --case fixture-slow-current-check
/opt/swarma/lab/bin/swarma-lab-qualify q4 --case fixture-unavailable
/opt/swarma/lab/bin/swarma-lab-qualify q4 --case fixture-delayed-check
/opt/swarma/lab/bin/swarma-lab-qualify q4 --case arm-live-observer
/opt/swarma/lab/bin/swarma-credential-broker-lab unbind --account lab/anthropic --binding-file /etc/swarma/lab/current-binding.json --operation-from /etc/swarma/lab/operations/unbind-q4.json
/opt/swarma/lab/bin/swarma-credential-broker-lab status --operation-from /etc/swarma/lab/operations/unbind-q4.json
/opt/swarma/lab/bin/swarma-lab-qualify q4 --case observe-live-unbind
/opt/swarma/libexec/swarma-user-manager-lab-setup retire-gateway --plan /etc/swarma/lab/retire-plan.json
/opt/swarma/lab/bin/swarma-lab-qualify q4 --case observe-stale-generation
```

Valid: current poll is `not_revoked` and a bounded affected use/connection is
observable. `fixture-slow-current-check` schedules 250 ms cadence and a slow
190 ms successful response under the 200 ms RPC timeout: its next success is
within 450 ms plus less than 50 ms qualified scheduling margin, so the 500 ms
watchdog must not fire or close a valid stream. G1 owns
`TestLabWatchdogSlowCurrentCheck` and B4 observes the same valid control.
Negatives: durable root service.unbind, synthetic unavailable and
missed-check controls. Require all affected key use/in-flight streams and old
broker/downstream connections/listener closed within **1 s** of durable removal
for the poll path. For unavailable/delayed-check paths require watchdog firing
by 500 ms from the last successful current check and complete closure within
another 500 ms. The source watchdog is currently 1 s
(`G:experiments/model-proxy/cmd/model-proxy/managed_linux.go:166`); G1 must change
and qualify it, not claim that current constant proves the tighter path.
Record the scheduler/load
bound and independent monotonic observation; a stream already ended before the
fault gives no in-flight credit. Any additional real inference must fit the
owner-approved total budget. Retiring the managed gateway tests stale-generation
teardown separately from unbind. No cached lease or later good poll resurrects it.
The observer started by `arm-live-observer` is a qualification-owned child whose exact PID
and start identity are recorded and reaped by the driver, not a shared daemon.

**Evidence:** `q4.json`, target binding/generation, durable publication/ack and
independent last-use/connection/stream/listener monotonic times, measured maximum
and poll/watchdog configuration; unavailable/delay control verdicts. Source
constants, a process name kill, or merely seeing `revoked` is insufficient.

Q4 deliberately ends authority. To continue, the owner approves the next exact
transition off-VM and executes:

```sh
set -eu
/opt/swarma/libexec/swarma-user-manager-lab-setup prepare-next --plan /etc/swarma/lab/next-qualification-plan.json
/opt/swarma/libexec/swarma-user-manager-lab-setup create-identities --plan /etc/swarma/lab/next-qualification-plan.json
/opt/swarma/libexec/swarma-user-manager-lab-setup verify-identities --plan /etc/swarma/lab/next-qualification-plan.json
```

After the manager returns committed identity/journal heads, B5 generates
`next-after-q4.json` from those heads and the owner approves it off-VM.
Only then run the broker transition; no envelope predates that predecessor:

```sh
set -eu
/opt/swarma/lab/bin/swarma-credential-broker-lab prepare-next --plan /etc/swarma/lab/next-qualification-plan.json --operation-from /etc/swarma/lab/operations/next-after-q4.json
/opt/swarma/lab/bin/swarma-credential-broker-lab status --operation-from /etc/swarma/lab/operations/next-after-q4.json
```

These entries require acknowledged stop/retirement of affected old generations,
retain all custody/hold/revocation/time history, publish the new approved tuples
and closed one-start gate, and never reset a consumed debit or initialize an
existing store. The owner then repeats section 7.4's bind/start/activation checks with
new operation/binding identities; no old binding is reopened. B5 must enumerate
the sequential Q4-to-Q5 and post-lift Q5-to-Q6 plans in the approved install plan.
The driver cannot approve or improvise either widening transition.

### Q5 — same-detector public plant, durable account hold, owner-only lift

```sh
set -eu
/opt/swarma/lab/bin/swarma-lab-qualify q5 --case clean-control
/opt/swarma/lab/bin/swarma-lab-qualify q5 --case public-canary-match
/opt/swarma/lab/bin/swarma-lab-qualify q5 --case hold-ack-loss
/opt/swarma/lab/bin/swarma-lab-qualify q5 --case held-redial-and-restart
/opt/swarma/lab/bin/swarma-lab-qualify q5 --case nonowner-lift
```

After the current hold and its exact ID are committed and read back, B5
generates `hold-lift-q5.json`; the owner approves that nonsecret envelope
off-VM before the following act. No future hold ID is guessed:

```sh
set -eu
/opt/swarma/lab/bin/swarma-lab-qualify verify-access --attestation /etc/swarma/lab/access-attestation.json
/opt/swarma/lab/bin/swarma-credential-broker-lab hold-lift --account lab/anthropic --hold-file /etc/swarma/lab/current-hold.json --operation-from /etc/swarma/lab/operations/hold-lift-q5.json
/opt/swarma/lab/bin/swarma-credential-broker-lab status --operation-from /etc/swarma/lab/operations/hold-lift-q5.json
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
lift attempts and wrong hold IDs refuse. The owner's root command alone lifts the
current hold after reviewing exact content; no ended lease/binding is revived.
Remove only the public plant/extra needle after evidence, then recheck clean.

**Evidence:** `q5.json`, public plant ID, same matcher/code identity, no-forward
counter, durable hold ID/revision/account, ack-loss retry ID, restart/redial
readback, nonowner/wrong-ID refusals and root lift result. Never report local
model-proxy `clear_block` or a fixture-only ledger as broker hold evidence.

Before Q6, the owner approves the distinct post-lift transition and runs:

```sh
set -eu
/opt/swarma/libexec/swarma-user-manager-lab-setup prepare-next --plan /etc/swarma/lab/next-after-q5-plan.json
/opt/swarma/libexec/swarma-user-manager-lab-setup create-identities --plan /etc/swarma/lab/next-after-q5-plan.json
/opt/swarma/libexec/swarma-user-manager-lab-setup verify-identities --plan /etc/swarma/lab/next-after-q5-plan.json
```

After the manager returns committed identity/journal heads, B5 generates
`next-after-q5.json` from those heads and the owner approves it off-VM.
Only then run the broker transition; no envelope predates that predecessor:

```sh
set -eu
/opt/swarma/lab/bin/swarma-credential-broker-lab prepare-next --plan /etc/swarma/lab/next-after-q5-plan.json --operation-from /etc/swarma/lab/operations/next-after-q5.json
/opt/swarma/lab/bin/swarma-credential-broker-lab status --operation-from /etc/swarma/lab/operations/next-after-q5.json
```

Then repeat 7.4 with that plan's **new generation-specific** bind/activate
operation directory. Preserve all custody/hold/time/revocation history and consumed
debits. Neither the old next-plan ID nor a successful lift reopens old authority.

### Q6 — ceiling, renewal, replay and expiry

```sh
set -eu
/opt/swarma/lab/bin/swarma-lab-qualify q6 --case fixture-gateway-ceiling-mismatch
/opt/swarma/lab/bin/swarma-lab-qualify q6 --case fixture-lifetime-901
/opt/swarma/lab/bin/swarma-lab-qualify q6 --case fixture-lifetime-900
/opt/swarma/lab/bin/swarma-lab-qualify q6 --case fixture-lifetime-1
/opt/swarma/lab/bin/swarma-lab-qualify q6 --case fixture-expiry-and-replay
/opt/swarma/lab/bin/swarma-lab-qualify q6 --case live-issue-renew
```

Negatives: a gateway max-lifetime value unequal to the activation selector
refuses before listener/material creation; an isolated **901-second activation** refuses before listener/material
creation; expired/retargeted/revoked/held/wrong-owner renewal refuses and clears
cached use. Replay and lost replies neither extend the recorded deadline nor
mint duplicate effects. Paired valid fixtures select 900 and a smaller lifetime,
exercise issue **and** renew through the real lab constructor, with the earliest
caller/binding/qualification/vendor bound. Run actual short-lifetime expiry on
an isolated native monotonic clock, never change the dedicated lab VM's clock. Valid live
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
set -eu
/opt/swarma/lab/bin/swarma-credential-broker-lab quiesce --account lab/anthropic --operation-from /etc/swarma/lab/operations/quiesce.json
/opt/swarma/lab/bin/swarma-credential-broker-lab status --operation-from /etc/swarma/lab/operations/quiesce.json
/opt/swarma/libexec/swarma-user-manager-lab-setup stop-worker --plan /etc/swarma/lab/stop-plan.json
systemctl stop credential-gateway-lab.service
```

After committed quiescence and manager stop readback, B5 generates `seal-stop.json`
from the exact final heads; the owner approves it and the off-VM stop acknowledgment
before invocation:

```sh
set -eu
/opt/swarma/lab/bin/swarma-credential-broker-lab seal-stop --off-vm-receipt /etc/swarma/lab/stop-ack.json --operation-from /etc/swarma/lab/operations/seal-stop.json
/opt/swarma/lab/bin/swarma-credential-broker-lab status --operation-from /etc/swarma/lab/operations/seal-stop.json
systemctl stop swarma-credential-broker-lab.service
/opt/swarma/lab/bin/swarma-lab-qualify export-evidence --destination /var/lib/swarma-lab/evidence/export
```

`seal-stop` requires an authenticated off-VM acknowledgment of exact final heads;
missing acknowledgment means not sealed and no restart. Verify no worker
processes under the manager's quiet-period rule, no old listeners/connections and
no remaining material use; active/exited service status alone proves none of
these. Export schema-validated metadata, release/approval/config/source pins,
real exits, timing/load bounds, completeness and SHA256SUMS; never raw logs or
secret verifiers. The owner stores and reviews it off-VM. The owner vendor-revokes the API
key in the owner's own account; Infra retires the installation and rebuilds or destroys
the lab under its own approved procedure. **There is no snapshot restore command.**
Independent record review and a second evidence read remain required; no
self-review or local wire fixture substitutes for those execution gates.

## 9. G01–G19 disposition

"Closed by simplification" below means the **production dependency is removed
from this proposed design**, not that a replacement command is implemented or
qualified. Every named implementation/release gate still applies before execution.
The original gap meanings are reproduced in the second column; historical
runbook source pins are not reused as current proof. Steps 1/2, release templates, the cgo profile and launcher mapping
are now source-landed where section 2/6 says so, not installed-qualified.

| Gap | Original gap definition | Lab disposition | Required unit / owner |
| --- | --- | --- | --- |
| G01 | Actual three-product tags/bytes/digests, aggregate, independent rebuild/review and in-person approval. | Still required: actual three-product tags/assets/sums, aggregate/bootstrap approval, second builds and release reviews. No real release identity supplied by this plan. | RB, RG, RM; the owner |
| G02 | Deployable packaging closure: flat sets versus archives, native NSS probe and gateway artifact. | Closed by simplification for the full-installer archive/profile mismatch: lab aggregate supports reviewed flat broker/manager sets and gateway archive. Native NSS and gateway templates are landed; actual complete bytes remain G01. | B5, RB, RG, RM |
| G03 | Implemented aggregate/root-copy verifier, member map, comparison encoding and exact placement. | Still required: safe root-owned copy/rehash, aggregate/member verifier and installed-byte receipt; source SHA checks alone insufficient. | B5 |
| G04 | Host-specific manager policy/skeleton/NSS/journal bootstrap, writer exclusion and native launch gate. | Still required: manager genesis/deployment/qualification and launcher-enabled one-start profile, not a Boolean bypass. | M1; Infra |
| G05 | Managed service/worker and authenticated helper bootstrap, identity requests and home/range reconciliation. | Still required: exact root setup, dedicated broker/control callers, managed gateway/worker, ranges/home custody and authentic helper invocation. Production terminal-provenance roles are replaced, not claimed implemented. | M1, B1 |
| G06 | Installable broker unit/configuration and accepting custody/controller/operator/use-facts assembly. | Still required: lab daemon/unit/config plus real accepting custody/service/facts/time assembly; stopped production main remains unchanged. | B1, B2, B3, B5 |
| G07 | Installed bind act and accepted account/enrollment/control-start/gateway-start ordering. | Closed by simplification of the production operator command: root lab `bind`, only after committed enrollment; its exact wrapper still must be built/tested. | B3 |
| G08 | Owner-only enrollment receiver, authenticated no-echo transport and nonrecording stdin ceremony. | Still required: bounded no-echo owner-terminal API-key receiver, peer authentication, no spill and safe UNKNOWN handling. Subscription setup-token ceremony is not needed. | B3, B4 |
| G09 | Managed gateway wiring, authority/listener/matcher/hold/final-use and recovery integration. | Partly source-closed: step-2 parent wiring is landed. Still required: true API-key kind/headers, durable hold bridge, UNKNOWN/recovery, final-use and total teardown qualification. | G1, B1, B4 |
| G10 | Gateway members/config/schema/modes/socket routing, start/readback and native hardening. | Still required: lab member placement/config/unit hardening, per-worker socket ACL and effective native readback; no guessed production executable symlink. | B5, G1, M1 |
| G11 | Pinned approved Claude executor, bounded invocation, endpoint mapping and placeholder-only environment. | Partly source-closed: Claude mapping and seccomp are landed. Still required: approved native executor/artifact pin, bounded invocation, actual socket/FD and environment qualification. | M1, B4, RM |
| G12 | Q1 native inference driver with valid/invalid binding controls and metadata-only effects. | Still required: real bounded inference and exact caller/placeholder negatives with metadata-only effect readback. | B4, G1 |
| G13 | Q2 in-custody scanner, complete surface/encoding inventory, safe plants and exact exits. | Still required: holder-custody matcher, lifecycle/surface inventory and complete scans; public plants prove the instrument without leaking the key. | B4 |
| G14 | Q3 genuine worker peer refusal, gateway valid control and no material/effect readback. | Still required: genuine worker-kernel-peer service/legacy refusal and valid gateway control, not chmod-denied connect. | B4, B1 |
| G15 | Q4 authenticated removal/generation transition, timing budget and independent full closure observation. | Still required: root unbind, managed generation retirement, one-second native timing and independent stream/listener/connection observation. | B3, M1, G1, B4 |
| G16 | Q5 synthetic leak, durable broker hold bridge/readback, owner-only lift and cleanup. | Still required: public match through real durable account-hold bridge, same-ID ack reconciliation, restart persistence and root-only lift. | G1, B1, B3, B4 |
| G17 | Q6 lifetime selector, issue/renew/expiry/replay/trusted-time controls and over-900 refusal. | Still required: sole lab selector-to-constructor path, issue/renew/replay/expiry and isolated >900 refusal with actual exits. | B1, B2, B4 |
| G18 | Snapshot/reset coverage, authorized stop, restore fences, baseline and token-lifecycle decisions. | Not needed for Q1–Q6: snapshot creation/restore/reset. DN-09 C explicitly forbids restore; orderly-stop/off-VM seals, vendor revoke and fresh-install retirement remain required. | B2, B5; the owner, Infra |
| G19 | Reconcile full-platform/other-account installer prerequisites with this bounded API-key profile. | Closed by simplification: separate API-key-only qualification aggregate/root sequence replaces the stale full-platform/other-account installer chain; no claim to run or fix that production installer. | C0, B5 |

## 10. Review and execution limits

Sections 5 and 9 carry the full unit graph, acceptance/LU allocation and gap
basis; section 8 contains all six Q requirements. No unpublished review is
needed to reconstruct the plan. C0 must freeze the listed byte schemas and
compatibility fixtures before parallel implementation; this proposal is not an
implemented codec or an approval of missing C-opening decisions.

Current result of **every Q1–Q6: NOT RUN**. No lab product implementation, live
account, key, host activation or release is established by this document. Local
synthetic wire/body evidence only corrects the client profile. Native time/SSH/
API compatibility and all required independent evidence reviews remain gates.
The production assembly and Curator Core acceptance stay separate. This document
authorizes no release publication or production activation.
