# Secret-free credential mode

**Document revision 1 — PROPOSED, inactive.** This is a separate target
contract for the broker, credential lifecycle adapters, a separate injecting
gateway and its request adapters. It specifies responsibilities and activation
gates; it supplies no implementation, release qualification or live-account
permission. The document revision is not a protocol version. The compatible
wire dialect, grant extension, encodings and refusal mappings are unselected.

The separate [gateway specification](secret-free-gateway.md) and
[provider-agnostic adapter specification](secret-free-adapters.md) refine these
responsibilities. Both are PROPOSED/inactive; provider capabilities and exact
runtime qualification remain open.

## 1. Modes and admission

In an admitted, qualified secret-free launch, the agent account, harness, home,
bridge and LLM receive no vendor-valid credential. The harness receives only a
placeholder usable through its own qualified gateway listener. This guarantee
depends on the qualified custody, network and IPC boundaries below; a random
placeholder without enforced isolation does not establish it.

The readable-token contracts in [the broker baseline](broker.md) and
[the Codex refresher v0 profile](v0-codex-refresher.md) remain unchanged:
Claude environment tokens, Codex external access tokens, the proposed Muse
minted-key channel and native per-home authentication are explicit exposed
lanes. The machine owner selects and qualifies each mode per profile and
harness. Status must identify the selected mode and its exposure. Failure to
qualify secret-free mode never selects or qualifies an exposed fallback. If the
selected lane is unqualified, the launch refuses.

Changing mode never silently migrates homes, copies a native login, changes
provider, account or billing identity, or substitutes API billing for a
subscription. Initial qualification uses API keys and dedicated test
subscriptions. Personal subscriptions remain closed until the mode is qualified
on test subscriptions. Permission to use an owner's actual provider account is
a separate lease and approval question; this proposal grants none.

The first delivery covers local stations only. Donor variants B and C remain
closed, separate later publication and qualification steps. Variant C would need
its own sandbox, store and IPC boundary; the project kernel cannot authenticate
a donor process as a local principal. Variant A has no separate OS boundary and
is outside this guarantee. Donor holder custody and consent are not transferred
to the project. Project workplaces retain zero egress and no broker lease.
R-UNTRUSTED, admission class, placement and positive role requirements remain
independent; circle membership supplies none of them.

## 2. Processes and custody

| Component | Proposed responsibility and permitted custody |
|---|---|
| Minimal broker, own service account | Enrollment, durable credential custody, account binding, leases, renewal, revocation and recovery; single refresh owner. Unix-socket protocol only; no network listener, plugins or provider HTTP forwarding. |
| Credential lifecycle adapter, broker side | Vendor enrollment completed by a person, minting, refresh, expiry and separately specified vendor invalidation; no agent HTTP request handling. |
| Injecting gateway, separate service account | Its own service lease, caller authorization, request classification, credential injection and upstream connection; holds only the material it leases. |
| Request adapter, gateway side | Declared credential recipients, authentication scheme, semantic operations/resources, effect class, safe responses and match forms. |
| Action service, separate service account | Protocol's trusted effect executor in Runtime; leases credentials for authorized external shared-state writes, with acceptance and effect recovery. |
| Harness and agent-side client | Placeholder and protected nonsecret launch metadata only in this mode; no refresh token, real access token, linked native store or credential file. |
| Messaging service | Existing carrier credentials only; no model/service token or raw matcher inventory. |

The broker, gateway and action service are credential-holding trusted-base
members. Compromise exposes the credentials each holds or leases. Separate UID
custody does not protect against captured host root. Matcher custody outside
the gateway's own traffic remains open (§10); it is not added to the trusted
base by implication. Board runners and session hosts retain their dispatcher
launch boundary; this proposal does not turn them into broker clients.

Build and test runners stay secret-free. R-EXEC, R-VERIFY, workspace export,
deterministic import and the existing trusted-runner contract remain separate
from permission to spend credentials or publish an accepted candidate.

## 3. Principals, connections and bindings

Before activation, the compatible dialect must publish service principals,
service binding creation/removal and ownership, service lease admission,
request/record semantics and method permissions. An operator-approved service
identity must be tied to its current kernel-authenticated identity and service
generation, admitted placement/class, installation policy and account scope.
A configured name, a caller-selected role or a static UID allowance is
insufficient. Missing, conflicting, retired or unknown generation/placement
evidence closes admission and use.

Each broker client establishes a fresh authenticated connection, pins the
server UID before sending and has a fixed role for that connection. Broker
descriptors are close-on-exec and are neither inherited nor passed. Socket
reachability is not authorization. Agent caller identification at the gateway
requires a qualified kernel routing rule binding listener ownership,
generation, launch and served policy generation; a TCP listener alone cannot
identify a caller UID.

Service credential bindings and originating caller bindings are distinct. A
binding replacement or service-generation replacement ends the old leases and
requires fresh authority. Old IDs cannot renew through a replacement binding;
retirement, recycled UIDs and repeated names inherit nothing. Preserve removal
tombstones, original effect identity and current-state reconciliation. Unknown
replacement/removal outcome stays closed. No seamless handoff is inferred from
the legacy park/restart boundary.

## 4. Two current authorities per use

Every credential use requires both independently verified authorities:

1. The service itself is currently admitted and has its own live credential
   lease for the account under its service identity and generation.
2. The original caller's live narrowing chain authorizes the actual use:
   account owner, retained delegations, agent generation, launch, profile,
   account, semantic operation and actual resource/target.

The service grant, a request, account selector or placeholder cannot supply
missing caller authority. A service holding two accounts/projects never lets a
caller of one reach the other. Narrowing is preserved on every edge, through
renewal and at every use/effect boundary. Expired, revoked, unavailable or stale
authority, policy, lease, binding or trusted-time evidence refuses use. A
point-in-time admission verdict is not continuing authority.

Operations and target predicates must be expressible in the published grant
dialect. Unknown or unexpressible predicates refuse, with no silent
translation. These requirements are semantic publication gates, not additions
to the current v0 grant grammar or its agent-only lease methods.

## 5. Material, placeholders and lifetimes

The broker leases vendor-valid material only to an admitted credential-spending
service. Its persistent lease metadata does not contain the payload. The
agent-side client receives a random placeholder per lease, bound to one
generation, launch and account, accepted only on that generation's qualified
listener. It is useless outside the gateway and refuses on another listener,
generation, launch, account or stale served policy. Reused listener ports do
not inherit authorization. The exact mapping, authentication and disposal
contract must be published before activation; no format is assigned here.

Credential lifetime, service lease lifetime, caller authority lifetime,
placeholder lifetime and vendor validity are separate facts. Local release
ends its lease; it does not prevent a fresh lease unless a current account hold
or other admission fence does. Disconnect is not release. Local lease release,
service-use closure, whole-generation/session stop and vendor invalidation are
separate outcomes. Copies from an exposed lane, a leak or holder compromise
remain vendor-valid until actual expiry or confirmed vendor invalidation.

Every issued vendor-valid version remains in the matchable inventory (§10)
through that vendor lifetime, including superseded versions after renewal and
versions whose lease ended. Replacement does not erase their exposure.

## 6. Credential lifecycle adapters

The broker-side lifecycle half preserves fresh owner enrollment, protected
storage and one internal refresh owner per rotating account. It never imports
an existing login, exports a keyring item or adopts an agent home. A person
completes the vendor ceremony. Dedicated service-account installation and
client policy remain prerequisites, not permission weakening.

Refresh retains the [contained auth-owner contract](../docs/auth-owner.md):
durable intent before launch, single account writer across daemon replacement,
qualified containment, writer/descendant absence, durable store/outcome
reconciliation, bounded queues, deadlines and fairness. No state lock spans
synchronous platform-service I/O; retained ownership and final revalidation
fence late results. Safe transient backoff requires conclusively resolved prior
writer and outcome. Unknown rotation cannot be retried merely because the child
died; remain unavailable or require explicit re-enrollment after absence.

The gateway sees a real upstream token rejection and requests renewal using
that rejected real credential's identity. The broker reloads current material
and remains the single refresh owner. Concurrent rejection does not create
multiple refresh writers. A placeholder digest never substitutes for real-token
identity without a separately published mapping. The gateway verifies the
renewed account is unchanged and repeats both authorities and all fences before
use. There is no account or native-login fallback.

Claude's exposed setup-token lane retains re-enroll/restart rather than assumed
refresh. Muse's proposed minted provider key is distinct from OAuth tokens and
from the API-key lane: refresh trigger, rotation, lifetimes and subscription
billing remain unknown. Re-minting may revoke a prior key. No common adapter
contract supplies missing per-kind evidence.

## 7. Request adapters and upstream routing

Initial gateway classes are model providers and code hosting only. Machine
policy selected by the admitted profile grants the usable classes; callers
cannot choose or widen them. Provider-only defaults, web-off defaults and
explicit trusted-circle opt-in remain. Dependency fetching remains with the
runner's admitted fetch phase; repository publication remains with the action
service. Existing credential-free CONNECT destinations are not widened.

**All external shared-state writes through the gateway are closed.** Every
such write goes through the action service, including an operation whose HTTP
method or endpoint name appears read-like. Adapters resolve the actual semantic
operation, effect class and resources of multiplexed endpoints, rather than
trusting the method name. Unknown operations/targets, unexpressible predicates,
credential list/create/reveal endpoints, conflicting classes/sources and unsafe
credential reflection refuse. Unadmitted service classes remain closed.

The request adapter declares names and ports permitted to receive its
credential, the authentication scheme and narrowest vendor scope, operation and
resource mapping, response protection, leak encodings and exact adapter/API
qualification identity. Client Host, SNI, URL, alternate auth configuration or
supplied credentials never select the credential recipient. Agent-supplied
real credentials refuse; the declared placeholder is checked before injection.

The gateway resolves upstream names itself, applies a dial guard to the address
actually dialed and authenticates the upstream server with TLS. No agent
resolver route or direct-provider bypass is allowed. Every redirect/reroute is
validated afresh as a destination before attaching a credential; an unchecked
or private target refuses. Per-generation budgets survive restart. Logs contain
typed metadata, never raw bodies, headers, tokens or URLs. A response capable of
reflecting credentials must be safely handled or the adapter remains closed.

Each token-using MCP server or connector receives a machine-selected endpoint,
not a token; existing consent remains. A connector name or operator declaration
alone does not prove routing. Each client and authentication mode needs its own
qualification. Network and IPC isolation must deny direct provider routes,
holder stores/private pipes and other launches' listeners.

## 8. Harness endpoint and renewal qualification

Only a qualified configured provider endpoint is admitted. **TLS interception
and its trust material are closed**, not a fallback. A harness without endpoint
support uses an explicitly selected, separately qualified exposed lane or
refuses. No guessed login acceptance, warning-only launch or copied native
login may substitute.

Qualification must establish that the exact harness accepts the placeholder
through its selected channel and that all credentialed traffic, including
startup, account, status, policy, background calls and child/MCP/hook/tool
traffic, uses the admitted route. Identity-dependent features must work or have
an explicitly recorded unsupported scope. Children receive at most the
placeholder. A version/help measurement or a local fake HTTP 503 demonstrates
neither successful login nor secrecy, containment or live provider behavior.

For Codex, placeholder acceptance in external-token mode, the gateway's real
rejection/renewal path and any app-server local refresh callback are separate
qualification obligations. Qualification must settle whether rejection reaches
the app-server, what its callback means, how the original correlation is
answered within its deadline, and how renewal failure closes the turn. No late,
uncorrelated or real-token callback to the agent is allowed. The gateway never
retries a request with uncertain upstream outcome or after its stream began.

Codex, Claude and Muse are distinct per auth kind, harness release/digest,
source policy, channel, mode, adapter/API version, platform, topology, model and
policy identity. Pin the full qualified combination, including gateway,
installation/custody and listener policy. Unknown releases or changed inputs
refuse until qualified. Existing static qualification records gain no new
fields or credit here; a compatible schema/publication contract is required.

## 9. Use fences, effects and recovery

The gateway and action service are revocation consumers. From signed
publication, the existing propagation bound is **max(S + A, F)**. Its parameters
retain the owning revocation contract's definitions and measurement obligations;
this document does not redefine them or choose numeric bounds. Snapshot
freshness, consumer observation and fail-closed authority expiry must be
qualified against that bound. No effect is promised before signed publication.
This composition selects no clock policy and does not activate a time provider.
Existing trusted time, watermark, not-before, expiry and monotonic destruction
rules remain.

Revocation completion is separate: for each affected service consumer, either
that consumer has durably acknowledged closure or all its earlier authority
has expired. An intake acknowledgment or broker material-publication fence is
not proof of gateway use closure or a completed external action.

Queues, cached leases, listener sessions, in-flight uses and open streams are
inside the fence. Revocation, generation freeze, retirement and all-stop close
the affected gateway listener sessions, streams and queue and the action
service's queued actions, with durable closure records. Operator reopening
must reconcile those closures before new use; it cannot revive old queued
work. A started action is interrupted where safe, otherwise completed with its
actual outcome recorded. Stop progress never waits for alert delivery.

Each mutating action retains current authority, epoch and stop checks at
execution, a stable effect identity with fixed parameters, and recipient
idempotency only where supported. Repository publication/landing additionally
requires the board-authorized accepted exact candidate and compare-and-swap
head; a producer signature and grant do not replace acceptance. Record success,
rejection or UNKNOWN. A lost response, ambiguous upstream outcome or partially
begun stream is UNKNOWN, never permission for blind retry/replay. Reconcile
with the recipient or ask a person. Code-hosting write examples belong to this
action path, not a future exception to the gateway's write prohibition.

Crash/restore/replacement resumes only through closed reconciliation of durable
authority, stop, account-hold, effect and writer evidence. Preserve the broker's
external surviving-history restore fence and independent R-ALLSTOP parts;
partial or unknown results stay closed. Restart, process absence, stale cache
or operator recovery of one component cannot reopen another. Durable
reopening/restart authorization remains separate from lifting a use fence.

## 10. Leak matching and whole-account containment

Leak matching is defense in depth; secrecy relies on keeping vendor-valid
material outside the agent account. The gateway inspects agent-originated
plaintext request line, headers and body before legitimate credential
injection, and prevents reflected credential material in responses from
reaching the agent. Its injected authentication must not trigger its detector.

All issued vendor-valid credential versions stay matchable until actual vendor
expiry or confirmed invalidation, including old versions after refresh or
release. The broker's issued-version inventory determines the required set,
not only active leases or the current token. Missing or stale matcher state
closes forwarding. Adapters declare raw, base64/base64url, hex, percent-encoded,
JSON-escaped and scheme-specific forms. Matching spans request/response chunks
with bounded retained overlap, window and resource budgets; exact limits and
coverage are publication and qualification inputs. No finite matching claim
covers arbitrary splitting/compression/encryption/slow leaks or opaque CONNECT.
No scan proves a message, response or home free of secrets.

A possible leak immediately blocks forwarding and requests a durable protected
hold on the **whole account**, covering every generation and launch. The
compatible broker contract must publish a narrowly authenticated detector
trigger and its admission, durability, correlation and replay rules. It grants
no general operator power. Existing v0 lease release/report methods cannot
express this authority: release affects a lease and a report cannot change the
account. Under the broker state lock, every lease and renewal, including final
post-refresh delivery, checks the hold. Reconnect/restart/new launch cannot
bypass it. Gateway and action-service uses close in the account scope; sessions
stop through the existing authorized credential-failure path.

Record local block, durable account hold, service-use closure, session stop and
vendor invalidation as separate outcomes/acknowledgments. An unreachable broker
keeps forwarding closed and the hold outcome unknown; it is not reported as
recorded. Only the owner lifts the hold. Local hold does not itself invalidate
the vendor credential or require re-enrollment.

A **confirmed** leak additionally requires provider rotation/invalidation under
its separately published lifecycle contract. A possible leak permits block and
hold only, never automatic vendor action. Confirmation criteria remain open;
no match is confirmed by default. Vendor invalidation may require
re-enrollment; Claude retains its vendor-side revocation boundary.

Matcher custody outside the gateway's own traffic remains open. No raw values
go to the bridge, messaging account or an LLM classifier; no chosen matching
API/backend is specified here. The bridge claims no leased-value matching
until that boundary is approved and qualified. Existing signed message bytes
are blocked rather than rewritten, and detector failure stops posting.

Owner-visible notification requires a separately owned, enabled alert route,
closed typed schema, effect correlation, durable acknowledgment/failure,
storage/rate and retry bounds. No raw values, token hashes, frames or bodies
appear in alerts. Notification conveys no operator authority. Unavailable
delivery must never delay, undo or falsely complete containment.

## 11. Operator and installation boundaries

Operator custody, fresh per-act authentication, exact confirmation for widening,
agent-session refusal and read-only observer separation remain. Enrollment and
status must distinguish mode, real holders, selected account/kind, qualification
identity, hold and per-component closure/outcome without exposing material.
Account hold, local release, generation/session stop and provider invalidation
are separate operator concepts. This document invents no CLI command.

Installation must separately qualify service identities/generations, protected
store/client policy, listener ownership/served policy, IPC and network routing,
TLS server authentication, budgets and teardown. The broker retains no network
listener. Existing broker service egress for lifecycle operations is not a
credential-injecting request gateway. No interception certificate is installed.
Concrete paths, launch units, material/matcher disposal, transaction formats and
revocation observation mechanisms remain publication/qualification gates.
Uninstall closes admission/use, reconciles queues/streams/effects, stops and
confirms holders/writers absent and preserves required durable evidence;
unknown cleanup defers removal. It does not claim secure erasure or vendor
invalidation. Existing installation, store, time and cleanup primitives are not
redefined here.

## 12. Qualification witnesses

Every row below needs a nearby valid control and the exact admitted tuple of
§8. **All are prospective and UNRUN** for this mode. Documentary examples are
not runtime tests or killed mutants; existing synthetic, v0, native and
historical results retain their original scope.

| Required negative witness | Required outcome | Nearby valid control |
|---|---|---|
| Qualified service lease, but revoked/expired caller or different project/account/target | Refuse actual use; no credential attached or effect | Same live service and caller authorities for the declared resource |
| Service generation replaced/retired, wrong listener owner, reused port or stale policy | Old lease/placeholder and queued use refuse | Own current admitted generation/listener/policy |
| Unknown semantic operation, unexpressible predicate, credential reveal endpoint or shared-state write disguised as read | Refuse; gateway never performs the write | Declared permitted read; separately authorized action-service write |
| Correct producer signature for unaccepted repository candidate | No publication or landing | Board-authorized exact accepted candidate and current head CAS |
| Class, web opt-in, placement or source conflict | Refuse; no fallback billing/login/route | Admitted local class/profile and nonconflicting endpoint/source |
| Direct provider route, holder store/private IPC or another launch's listener accessible to agent | Isolation fails; mode remains closed | Own endpoint reachable, permitted upstream succeeds only through gateway |
| Redirect/reroute to unchecked/private destination or client-selected Host/SNI recipient | Refuse before attaching credential | Newly validated declared recipient with authenticated TLS |
| Placeholder fails local login, or startup/status/policy/background/child request bypasses gateway | Tuple remains unqualified | Exact release accepts placeholder and all required traffic follows route |
| Real rejection during concurrent uses, account changes or late/local callback | Single refresh owner; changed account/late/material-bearing callback refuses | Resolved same-account renewal and qualified correlated placeholder callback |
| Queue/cache/stream crosses revocation, freeze, retirement or all-stop | Close within published composed bound; durable per-consumer record | Use conclusively completed before fence; fresh admitted use after explicit reconciliation |
| Effect response lost, partial stream or ambiguous refresh/rotation, then retry | UNKNOWN; no blind replay or replacement writer | Recipient-supported idempotent same-effect reconciliation; resolved safe transient refresh |
| Old still-valid issued token, supported encoded form or bounded split echo | Block and whole-account hold; reflected response never delivered | Ordinary injected authentication and near-match without hold |
| Matcher missing/stale or overlap/budget exhausted | Close; no claimed complete scan | Complete current inventory within qualified bounds |
| Possible leak followed by reconnect/restart/new generation on same account | No lease/use until owner lifts hold; no automatic vendor action | Unrelated account unaffected; authorized owner release with independent gates |
| After a leak, broker/alert acknowledgment unavailable; or crash/restore with partial stop evidence | Blocked use stays closed, unknown outcomes honest; alert failure cannot delay containment or imply its completion | Durable reconciled closure and separately authorized recovery, with alert outcome recorded independently |
| Existing v0/synthetic/503/version evidence offered as new-mode qualification | Reject credit and remain inactive | Exact new-mode test-subscription, adapter, isolation and harness witnesses |

Donor B/C, interception and new gateway service classes are closed scopes, not
omitted passing rows. Donor A and exposed lanes are outside the secrecy claim.
Matcher coverage limitations are explicit residual limits, not universal leak
detection promises. No new prerequisite is imposed on an independently
authorized owner-account window by these prospective witnesses.

## 13. Publication and activation gates

The following dispositions are settled: API keys/test subscriptions first;
endpoint mode only with interception closed; lifecycle in the minimal broker
and requests in a separate gateway, action service as trusted effect executor;
gateway initially model providers/code hosting with every shared-state write
only in the action service; possible leak means whole-account hold lifted only
by the owner, confirmed leak additionally vendor rotation; local-only first
with donor B/C separate closed steps. They are not unresolved design choices.

Activation still requires an approved compatible broker/grant dialect with
service-principal, service-binding, service-lease and use-through-service
semantics, method permissions and narrow hold authority. Its wire version,
formats, fields, grant grammar and refusal mappings must be published and
implemented together; this proposal assigns none to `broker/1`, `lease/1` or
the closed v0 profile. Unsupported/missing dialect means refusal.

Also open: actual gateway/request-adapter contracts and implementations,
protected installation/custody/client policy, authenticated caller/listener and
revocation-consumer evidence, finite matcher inventory/budgets, outside-gateway
matcher custody/ownership, confirmed-leak criteria, alert route and all exact
harness/auth-kind/adapter/topology qualification. Existing live release,
owner-account, writer lifecycle, time, stop, restore and cleanup gates remain;
documentation approval alone opens none. No secret-free production entry is
qualified, no v0 evidence is promoted, and no operational authority is granted.
