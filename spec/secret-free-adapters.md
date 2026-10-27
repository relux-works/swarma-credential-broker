# Secret-free credential and request adapters

**Document revision 1 — PROPOSED, inactive.** This is the provider-agnostic
adapter contract for [secret-free mode](secret-free-mode.md) and its separate
[gateway](secret-free-gateway.md). It defines responsibilities and qualification
inputs, not an implementation, plugin API, wire version or enabled provider.
GitHub, GitLab and Gitea/Forgejo are equal profiles. None supplies a universal
authentication, permission, lifetime or repository-publication model.

## 1. Contract and evidence status

Each admitted combination has two adapter halves and a separate action-service
integration:

| Half | Owner, trust and work |
|---|---|
| Credential lifecycle adapter | Broker side: protected person-completed enrollment, custody, minting/refresh, expiry and separately authorized invalidation/recovery |
| Request adapter | Gateway side: exact recipients, authentication attachment, semantic operation/resource/effect classification, narrow scope mapping and safe response/matcher behavior |
| Action-service integration | Separate trusted writer: its own service lease, current caller authority, exact effect/target binding, acceptance/CAS and outcome recovery; never a gateway write exception |

These are logical responsibilities, not permission for dynamic plugins in the
minimal broker. Adapters cannot add a network listener or request forwarding to
it. A request adapter cannot read a native store, run a lifecycle ceremony,
refresh independently or mint a credential in response to an agent-selected
URL. An action adapter cannot turn a caller's generic write grant into
credential-administration authority.

**No provider-specific capability is qualified by this revision.** The equal
profiles in §6 are concrete required admission records; their vendor-dependent
claims remain **TO QUALIFY**. Exact current primary-source evidence and
independent review must precede capability selection; account/API tests and
exact runtime witnesses are separate later authority. An unsupported capability
is refused, not implemented by a broader credential or a best-effort fallback.
Absence of evidence is not proof that a provider universally lacks a capability.

## 2. Common declaration

Every profile must publish the following semantic facts. These are required
concepts, **not assigned wire/config fields or callable methods**. Encoding,
permissions, refusal mapping and compatible broker/grant dialect remain
publication gates.

| Required fact | Closed meaning and qualification boundary |
|---|---|
| Identity | Provider, actual instance/edition/API version, adapter release/digest, auth kind, enrolled account/tenant/billing identity; display names and host spelling alone are insufficient |
| Kind and holders | Static key/token, OAuth access/refresh material, application signing/minting material, installation credential and deploy credential are distinct; declare what remains broker-only and what may be leased to which service |
| Enrollment | Exact human ceremony, protected inputs and binding checks; no imported native login or agent-home adoption |
| Issuance and renewal | Supported mint/refresh operation, single owner, real rejected-material identity, lifetime/expiry evidence, rotation overlap and unknown-outcome behavior; explicit unsupported capability |
| Invalidation | What provider action invalidates which current/old versions, required authority, actual confirmation evidence and residual validity/re-enrollment; never inferred from local release |
| Destination | Credential recipient names/ports/server identity, TLS/API/auth scheme, resource namespace and actual dial guard; no client-selected recipients |
| Operations/resources | Complete supported semantic operations, effects and immutable/current resource identity mapping, including multiplex/batch/secondary targets and redirects; unknown form refuses |
| Vendor scope | Narrowest supported resource/permission restriction and evidence; broker/caller narrowing must be expressible and checked independently at every use |
| Safe response | All supported response/error/stream channels, credential reflection boundary, decoding and forwarding bounds; unsafe or unclassifiable responses remain closed |
| Matcher | Required issued-version inventory, supported encodings/overlap, limits and refusal on missing/stale/exhausted state; outside-gateway custody is not implied |
| Effects | Stable action identity/parameters/target/expected head, supported recipient idempotency, definitive outcome versus UNKNOWN and reconciliation ownership |
| Signing | Accepted commit/tag object and trusted signer/algorithm verification, signature custody and provider display/API evidence limits; no agent token or signing key exposure |
| Qualification | Exact harness/channel/mode/profile/model/platform/topology/service/served policy and account tuple; current primary URLs/date/version plus independent disposition and separate runtime evidence |
| Closure/recovery | Lease/use/queue/stream/action revocation, account hold, writer/store/time and restart fences; durable per-consumer closure and actual vendor outcome remain distinct |

A vendor credential's scope is an upper bound on possible vendor authority, not
the caller grant. If the required restriction cannot be expressed or enforced by
the published scope/resource contract, deny the use. Do not substitute a group,
organization, instance, repository or account-wide credential to make a narrow
request work. Nor does possession of a narrowly scoped token authorize an
operation outside the caller's current chain.

## 3. Broker-side lifecycle

Enrollment remains fresh and person-completed into protected broker custody.
No copying of an existing login, keyring/native-store export, weakened file
permissions or agent-home adoption. Static credentials, OAuth, application
signing/minting credentials and deploy credentials retain separate ownership,
rotation and validity contracts. An auth-scheme name establishes none of them.

For every rotating account retain **exactly one refresh/minting owner across
replacement**, with durable intent before external work, retained attempt and
writer identity, qualified containment, writer/descendant absence, protected
store reload and durable outcome reconciliation. Preserve the
[contained-owner contract](../docs/auth-owner.md) and its retained-chain,
time-confidence, watermark and scheduling rules. Queues, deadlines and fairness
remain bounded; cancellation of a response waiter does not erase an admitted
attempt or authorize a second writer. No state lock spans synchronous service
I/O. A changed policy/daemon/authority or hold during I/O is rechecked at final
release; a late result cannot reopen admission.

A request adapter reports a real upstream rejection only under its qualified
error classification. It binds the rejected real credential version to the
same enrolled account over protected IPC; an agent placeholder or invented
issue timestamp supplies no version identity. Reload current material first
and reconcile existing work. Concurrent rejections cannot start parallel
rotations. Releasing renewed material repeats current service authority,
retained originating caller authority where applicable, binding, time,
revocation, restore, stop and whole-account hold checks.

No refresh is invented for a static credential. Unknown expiry remains unknown;
enrollment time is not minting time. Unknown vendor lifetime prevents guessed
matcher retirement. Safe transient retry requires conclusive prior nonrotation,
writer absence and store/outcome reconciliation; process death, a zero exit,
unchanged file, local release or a lost response is not proof. Ambiguous minting,
rotation or invalidation keeps the account unavailable until the qualified
reconciliation or explicit re-enrollment-after-absence path resolves it.

A **possible** leak requests a durable whole-account hold and local/service
closure, not automatic rotation. A **confirmed** leak additionally requires the
separately qualified vendor rotation/invalidation operation for the exact kind
and affected versions. Confirmation criteria remain OPEN and cannot default to
“matcher fired.” Lack of supported invalidation leaves a held account with an
honest UNKNOWN/unsupported vendor outcome; it does not authorize pretending a
new local lease invalidated old material. Rotation of a parent signing/refresh
credential is not by itself evidence about every previously issued child token.
Only declared, source-supported semantics and actual confirmation can establish
that relationship. The owner alone lifts the hold; all other gates still apply.

## 4. Gateway-side request adapter

The request adapter must implement a closed mapping from the supported request
to semantic service class, operation, effects and all actual resources. It must
reject unknown extensions, ambiguous encodings/framing, unexpected query/body
members, secondary targets and mixed operations rather than forward
unclassified bytes. It cannot rely on GET/POST, REST/GraphQL, “read-only” names
or UI labels as an effect proof. Classify every multiplexed/batched member
before any forwarding; one write or unknown member rejects the whole request.

The only initial gateway classes are model providers and code hosting. Every
external shared-state write is action-service-only; neither an auth profile nor
a model endpoint creates an exception. Persistent model resources, repository
updates and administrative/credential operations do not become inference/read
merely because they share a URL. The exact qualified inference contract must
state storage/retention, billing identity and effects; unknown behavior stays
TO QUALIFY. A generic extension cannot add a third service class.

Credential recipients and scheme come from protected policy. Authenticate the
actual upstream server, resolve and guard the dialed address inside the
gateway, and revalidate redirects before attachment. Client Host/SNI/URL,
forwarded headers, alternate auth and supplied material never select the
recipient. No unrestricted CONNECT, private-target routing or direct-provider
fallback. Parse and validate the placeholder only on its qualified launch-owned
listener; a TCP connection alone provides no UID/generation authority.

For **each use**, independently retain the current admitted service identity,
generation/binding and own live lease **and** the originating owner/delegation/
agent-generation/launch/profile/account/operation/resource chain. Narrowing is
checked on every edge. Recheck at enqueue, dequeue, post-wait attachment,
submission, redirect, renewal/final delivery and continued use/effect boundaries,
or prove an equivalent closed interval under the
[gateway boundary table](secret-free-gateway.md#4-both-authorities-at-every-use).
A credential cache, current service lease or placeholder never replaces the
second authority. Cross-account/tenant/project/provider substitution refuses.

Inspect agent-originated plaintext before legitimate injection, and protect
responses against reflected material before release. Keep all issued
still-vendor-valid versions for the account matchable, including superseded and
locally released versions. Declare finite encoding, overlap/stream buffering and
resource limits; missing/stale/unknown inventory or exhausted scanning closes
forwarding. This is defense in depth, never a proof against arbitrary encoding,
splitting, encryption, compression or unrelated secret material. Never forward
raw credential values, credential hashes, matcher inventories or raw requests
to messaging, agent, bridge or LLM. Alerts contain closed sanitized metadata and
cannot delay containment. Outside-gateway matcher custody remains OPEN.

The adapter must preserve distinct outcomes: local block, durable whole-account
hold acknowledgment, each consumer's use closure, authorized session stop,
owner notification and actual vendor invalidation. Broker/alert loss remains
blocked/UNKNOWN, not a false acknowledgment. Existing signed bytes are blocked
rather than rewritten. A detector has narrowly authenticated account-hold
trigger authority only after compatible dialect publication, not general
operator power or owner hold-lift authority.

## 5. Action-service integration and revocation

An action-service integration independently applies the two-authority and
current account/resource/destination/scope checks, durable account hold and all
revocation/time/stop/restore gates. The agent receives neither the service's
vendor credential nor an API capable of choosing arbitrary credential-bearing
requests. A gateway refusal is not automatically converted to an action.

Mutations need stable effect identity bound to fixed parameters, actual target
and expected state, durable intent/outcome and final authority revalidation.
Recipient-supported idempotency is action-specific; do not assume support from
a header name or local effect ID. A lost or ambiguous response, expired caller
or partial stream cannot authorize a blind retry, duplicate action or new
credential writer. Reconcile with the recipient under the qualified mechanism
or require a person, preserving actual UNKNOWN until resolved.

Repository publication/landing additionally requires the board-authorized
accepted exact candidate, repository signing policy and actual expected-head
CAS. Check accepted candidate/tree/object and head, not a producer's assertion,
branch name, signature alone or vendor verification badge. Commit/tag signing,
verification/trusted signer, transport authentication, write permission and
conditional reference updates are separate capabilities. Nothing requires an
agent-held provider token; a trusted holder performs only the accepted effect.
If the exact provider/kind cannot support the required operation/verification/
conditional-update contract, that action stays unavailable, not broadened or
implemented with a race-prone check-then-write substitute.

Gateway and action service are revocation consumers of the inherited
**max(S + A, F)** bound from signed publication. Parameter definitions and
measurement obligations remain those of the owning revocation contract,
retained in [mode §9](secret-free-mode.md#9-use-fences-effects-and-recovery).
This chooses no numeric deadline or new clock policy. Per-consumer completion
requires durable closure or expiry of **all earlier authority**, not broker
intake or material-publication acknowledgment. Include queues, leases/caches,
listeners, sessions, pooled connections, in-flight requests/actions and streams.
A safe-to-interrupt action stops; otherwise reconcile its actual outcome.
Closure cannot retract a remote effect and does not invalidate vendor material.

Freeze, retirement, account hold and all-stop fence new and late uses. Restart,
restore and replacement stay closed until durable authority/closure/hold/effect,
writer/store/time and independent stop evidence reconcile. Old queues and IDs
cannot reopen use or target replacement bindings. Existing external
surviving-history restore fences and independent service parts remain; one
component's recovery is not whole-system recovery or session restart authority.

## 6. Equal provider profiles

The following profiles are equally subject to §§1–5 and §7. Each profile must
instantiate the same declaration table and supply exact primary documentation,
retrieval date, supported instance/edition/API/auth-kind versions and bounded
claims. A source citation is not an executed account witness. **All capability
selections and runtime witnesses are TO QUALIFY / UNRUN in this revision.** No
provider inherits another profile's endpoint, token scope, refresh behavior,
revocation semantics, verification signal or default permissions.

### 6.1 GitHub

| Admission item | Required GitHub-specific determination; current status |
|---|---|
| Identity and kinds | Distinguish selected hosted/enterprise instance and API version; assess application/installation, fine-grained/static and OAuth candidates separately; TO QUALIFY |
| Lifecycle and scope | Pin actual issuer, leaseable versus broker-only material, account/installation/repository binding, narrow read/write permissions, expiry and refresh/rotation overlap per kind; TO QUALIFY |
| Request semantics | Pin supported read/inference-independent code-host operations and all resources, including multiplexing/batching; exclude every shared-state mutation and credential endpoint from gateway; TO QUALIFY |
| Destination and responses | Pin exact recipients/TLS/auth attachment and redirects, account/resource readback, reflection/error/stream and matcher bounds; TO QUALIFY |
| Action and signatures | Determine actual accepted-object signing/verification and expected-head conditional update/idempotency mechanisms, without agent token exposure; TO QUALIFY |
| Confirmed leak and evidence | Determine invalidation of each issued version, residual validity, necessary re-enrollment and actual outcome evidence; current primary sources/independent review and runtime witnesses pending |

Application enrollment is not itself an installation credential, and a
fine-grained or OAuth label is not evidence for any entry above. No GitHub API,
permission vocabulary, token lifetime or verification badge is the common
contract's default.

### 6.2 GitLab

| Admission item | Required GitLab-specific determination; current status |
|---|---|
| Identity and kinds | Distinguish selected hosted/self-managed instance, edition/version and API; assess project, group, deploy and OAuth/static candidates separately; TO QUALIFY |
| Lifecycle and scope | Pin actual issuer, leaseable versus broker-only material, project/group/account binding, narrow read/write permissions, expiry and refresh/rotation overlap per kind; TO QUALIFY |
| Request semantics | Pin supported read operations and exact resources, including project/group inheritance, multiplexing and batch forms where supported; no inferred cross-project rights or gateway mutations; TO QUALIFY |
| Destination and responses | Pin exact recipients/TLS/auth attachment and redirects, account/resource readback, reflection/error/stream and matcher bounds; TO QUALIFY |
| Action and signatures | Determine actual accepted-object signing/verification and expected-head conditional update/idempotency mechanisms, without agent token exposure; TO QUALIFY |
| Confirmed leak and evidence | Determine invalidation of each issued version, residual validity, necessary re-enrollment and actual outcome evidence; current primary sources/independent review and runtime witnesses pending |

A project, group or deploy credential is not interchangeable by name. Permission
to fetch a repository does not establish permission for an arbitrary API, to
publish, or to impersonate the originating caller. Every supported route and
kind needs its own source-backed selection.

### 6.3 Gitea and Forgejo

| Admission item | Required Gitea/Forgejo-specific determination; current status |
|---|---|
| Identity and kinds | Pin Gitea or Forgejo separately, actual instance/release/API and enabled auth kinds; similarity/compatibility claims supply no equivalence; TO QUALIFY |
| Lifecycle and scope | Pin actual issuer, leaseable versus broker-only material, account/organization/repository binding, narrow read/write permissions, expiry and refresh/rotation overlap per kind; TO QUALIFY |
| Request semantics | Pin supported read operations, all resource identities and instance-specific extensions/batch forms; no assumed GitHub or GitLab operation/effect mapping; TO QUALIFY |
| Destination and responses | Pin exact recipients/TLS/auth attachment and redirects, account/resource readback, reflection/error/stream and matcher bounds; TO QUALIFY |
| Action and signatures | Determine actual accepted-object signing/verification and expected-head conditional update/idempotency mechanisms, without agent token exposure; TO QUALIFY |
| Confirmed leak and evidence | Determine invalidation of each issued version, residual validity, necessary re-enrollment and actual outcome evidence; current primary sources/independent review and runtime witnesses pending |

An installation being self-hosted does not establish safe destination, API
semantics or narrower authority. Gitea and Forgejo version changes require their
own qualification identities rather than a shared accepting compatibility flag.
No application-token or vendor-rotation support is presumed.

### 6.4 Model providers and generic HTTP extension

A new HTTP profile uses the same table, evidence and refusal rules; HTTP is a
transport, not a service class or permission. The extension is limited to an
already admitted model-provider or code-hosting class. Model profiles separately
pin provider, auth kind, harness/channel/model, account/subscription/API billing,
configured endpoint acceptance, real rejection/renewal and stream semantics,
startup/background/child routes, reflection and retention/effect boundaries.
No OAuth or minted-key behavior follows from generic bearer authentication.

Codex, Claude and Muse retain their distinct baseline kinds and open
qualification. Claude's exposed setup-token lane retains re-enroll/restart;
Muse's proposed minted provider key remains distinct from OAuth tokens and the
API-key lane, with billing/lifetime/rotation unknowns. Those existing baseline
facts grant no secret-free endpoint capability or actual account authority.
A harness without qualified configured-endpoint support refuses; interception,
foreign service classes and an exposed/native fallback remain closed.

## 7. Publication and qualification

Before activation, publish and implement compatible service-principal/binding/
lease/use-through-service and narrow hold-trigger semantics, grant predicates,
encodings, method permissions, refusal mappings and observation/recovery rules.
The current v0 grammar does not acquire these concepts through this document;
unknown/unexpressible scope or resource predicates refuse. Preserve existing
operator custody, per-act authentication, widening confirmation, agent-session
refusal and read-only observer separation. Owner decisions already fixed in
[mode §13](secret-free-mode.md#13-publication-and-activation-gates) remain fixed.

Source acceptance must identify exact current primary URLs/date/revision,
relevant passages, product version/edition/auth kind, unsupported claims and
independent disposition. Qualification additionally binds exact API/adapter/
harness releases and digests, auth kind/source/channel/mode, profile/model,
platform/topology, service generation/policy/listener/served policy and actual
account/billing identity. Every changed or unknown member is closed until
qualified. No page, token label, version/help, fake-503, synthetic v0 result or
HTTP success alone proves the combination.

API keys and dedicated test subscriptions are first; personal subscription
use remains closed until test-subscription qualification. Provider source
research is not permission to mint, call, rotate or enroll an account. Protected
installation, listener/kernel caller mapping, no network/IPC/store bypass,
budgets/disposal, finite issued-version inventory, outside-gateway matcher
custody, confirmed-leak criteria and alert-route ownership remain activation
gates. Missing a capability keeps only the applicable profile/action closed;
no mandatory provider or GitHub dependency is introduced. Local-only first
scope and donor B/C closure remain. No M0 gate is added.

## 8. Documentary neighbors

All rows are prospective **runtime UNRUN** witnesses, not executed tests or
killed mutants. Each nearby positive is conditional on actual exact published
capability and qualification. A refusal before submission preserves no material
attachment/forbidden effect; after uncertain submission, preserve UNKNOWN and
prevent duplicate/reopened use instead of claiming remote absence.

| Negative neighbor | Required invariant/outcome | Nearby valid control |
|---|---|---|
| Another provider/instance/kind's token, permissions or refresh semantics borrowed as default | No issuance/use; no cross-provider or kind substitution | Exact selected profile with independently established kind/scope/recipient |
| Broad service token plus unexpressible or stale caller resource predicate | Refuse before attachment/effect; no widening to make a request work | Independently current service and caller authority for expressible actual resources |
| Project/group/organization or account confused by alias, redirect or secondary target | No cross-account/project/tenant use | Actual canonical resource/tenant identity matches both chains and destination |
| Static/deploy credential assumed refreshable, missing lifetime treated as enrollment-plus-TTL | No invented refresh or matcher expiry; remain closed/unknown | Exact supported kind-specific lifecycle and known validity or conservative retained inventory |
| Concurrent rejection, refresh completion after hold/revocation, or lost refresh outcome | One retained owner; no late delivery/second writer/blind rotation retry | Conclusive prior attempt/store/absence plus final current authority/hold checks |
| Nominal read or inference request contains hidden mutation/batch member | Whole gateway request refused, no partial forwarding or automatic action | Complete supported read/inference classification; separate admitted writer action |
| Agent-selected alternate auth/recipient or reflected real material | No recipient injection or credential-bearing response to agent | Exact protected recipient/scheme and qualified response protection |
| Superseded/released but still-valid encoded material missed by current-only matcher | Forwarding closed, account hold requested; no false scan success | Complete required account inventory and supported encoded near-match control |
| Missing/stale matcher or bounded decoder/buffer exhaustion | No forwarding or universal secrecy assertion | Current supported inventory within qualified overlap and resource budgets |
| Possible leak auto-rotates; confirmed leak has unsupported vendor invalidation | Possible: block/hold only; confirmed: remain held/UNKNOWN vendor outcome, no pretend invalidation | Separately confirmed and qualified kind/version invalidation with actual outcome |
| Broker/hold/alert unavailable or non-owner attempts lift | Block persists; independent outcomes UNKNOWN; no new/reopened lease/use or alert-gated containment | Durable account hold/consumer closure, independent alert result, explicit owner lift with all other gates |
| Grant/signature alone offered for publication; stale head or unsupported CAS | No reference update or race-prone check-then-write substitute | Board-authorized accepted exact signed object and qualified recipient expected-head CAS |
| Lost action response/replayed ID or changed parameters | Preserve original effect/outcome and UNKNOWN; no duplicate mutation | Supported same-effect recipient reconciliation with fixed arguments and current authority |
| Revoked queue/stream restored by restart or cache, one consumer closure missing | Affected scope stays closed until durable closure/earlier-authority expiry and recovery | Conclusive pre-fence completion or fresh admitted post-reconciliation operation |
| Unseen source result, unqualified API release or v0 evidence used to mark profile active | Reject capability/qualification claim; no runtime activation | Exact independently reviewed primary findings plus separately authorized tuple witnesses |

Documentary approval opens no service, account, new dialect or runtime entry.
