# Secret-free gateway

**Document revision 2 — PROPOSED, inactive.** This specifies the request gateway
for [secret-free mode](secret-free-mode.md), alongside the separate
[adapter contract](secret-free-adapters.md). It is not an implementation,
qualified release, deployment recipe or permission to use an account. The
revision is not a wire version. No new method, field, code or service role is
added to the existing broker dialect. All runtime witnesses below are **UNRUN**.

## 1. Scope and trust boundary

The gateway is a separate credential-holding service, with its own protected
identity and generation. It serves only admitted **model-provider and
code-hosting** operations. Policy selects those classes per launch; a client
cannot turn it into a general proxy, dependency fetcher, browser or credential
manager. Existing provider-only and web-off defaults and explicit trusted-circle
opt-in remain. Dependency fetching stays with its admitted runner phase.

**The gateway performs no external shared-state writes. Every such write goes
through the separate action service.** Classification is semantic: method,
endpoint name, transport verb and a provider's label are insufficient. Model
inference is not permission to create persistent conversations, files, jobs,
indexes, repository objects, administrative state or credentials. Only a
separately qualified inference operation with a declared effect boundary may
use the gateway. Unknown persistence or side effects leave that operation
closed. This does not promise that model processing has no billing, metering or
provider retention; their account and data-policy consequences must be declared
in the exact profile, not hidden by calling an operation inference.

The action service is a trusted effect executor, not a forwarding option chosen
by the gateway after a refusal. It has independent admission, both authorities
per use, effect recovery and repository acceptance requirements (§8). A write
refusal never forwards the original request, redirects it to a writer or grants
a new action. Broker-owned enrollment/minting/refresh remains the separate
protected [credential lifecycle](secret-free-adapters.md#3-broker-side-lifecycle)
contract; it is not an agent-accessible credential-management route.

The minimal broker retains its Unix protocol and lifecycle responsibilities; it
gains no network listener, request plugins or provider HTTP forwarding. The
gateway and action service are additional trusted-base holders. Compromise can
expose the material they hold; host root remains trusted. Build/test runners,
agent accounts, homes, bridge and LLM receive no vendor-valid credential in this
mode. Board and session hosts retain their dispatcher launch boundary.

## 2. Qualified entry and launch binding

Initial admission is **local stations only**. Donor variants B/C and donor
sandbox/store/IPC integration remain closed, separately published scopes. A
project-side kernel identity is not a donor identity. Untrusted workplaces
retain zero egress and no broker lease; class, placement, circle membership and
review-role admission remain independent predicates.

Only an exactly qualified configured-endpoint harness may enter this mode.
**TLS interception and installation of interception trust material are closed,
including as a fallback.** An unsupported endpoint mode refuses the selected
launch. An exposed lane requires its own explicit selection and qualification;
failed secret-free admission cannot silently select it, native login, another
account/provider or different billing.

The launch receives only a random placeholder and protected nonsecret metadata.
Its mapping binds one launch, agent generation, account, service generation,
listener owner and current served policy. It must expire or close with the
relevant authority, and cannot authenticate at a provider or another listener.
A reused port, socket pathname, process name or UID inherits no old mapping.
Generation replacement ends old leases and placeholders; no seamless handoff
is inferred. The format, disposal and authentication mechanism require a
published compatible dialect before activation.

A qualified kernel-enforced routing and custody boundary binds the actual
caller to that mapping. TCP, an IP address, a request header and possession of
a placeholder do not identify an OS UID. A kernel UID observation alone also
does not establish current generation, placement, launch or served policy.
Missing, stale, conflicting or unreadable evidence refuses before use.

Agent-side isolation must exclude direct provider traffic, other launches'
listeners, holder stores, private lifecycle/broker IPC, alternate credentials,
inherited connected descriptors and unadmitted connectors. A proxy environment
variable alone is not enforcement. The exact platform, startup, background,
child, hook, MCP and tool paths belong to qualification. A token-using connector
receives only a machine-selected endpoint; existing consent remains necessary.

## 3. Semantic classification

Before upstream credential attachment, the request adapter must completely
classify the supported request into the declared service class, operation,
resources, account/tenant and effects. Parsing and classification are bounded;
unknown encoding, framing ambiguity, conflicting recipients, resource
ambiguity, unsupported extension or exhausted budget refuses. No unclassified
prefix or opaque tunnel may be forwarded speculatively.

| Semantic class | Gateway disposition |
|---|---|
| Declared code-hosting read with exact resources | Eligible only after all authorities, destination and response gates |
| Qualified model inference within its declared persistence/data/billing boundary | Eligible only for the exact model/auth-kind/profile tuple; inference does not authorize adjacent mutations |
| External shared-state mutation, including a read-like request with a mutation effect | Refuse before credential attachment or upstream submission; separately authorized action service only |
| Credential list/create/reveal, account administration or auth-source switching | Refuse as gateway traffic; no delegation of broker lifecycle authority |
| Unknown, mixed, multiplexed or batched operations | Classify every member and resource; any forbidden or unknown member rejects the entire request before forwarding |
| Unadmitted service class or opaque forwarding | Refuse; a generic adapter is not permission to add classes |

A nominal read can trigger a write through query variables, batch members,
provider extensions or secondary resources. An adapter must either prove the
exact supported semantics or refuse that form. A broad vendor scope cannot
replace this classifier. A correctly classified operation still needs both
current authorities and destination binding; it is not permission by itself.

## 4. Both authorities at every use

The gateway independently establishes:

1. **Service authority:** its current protected identity and generation,
   admission/class/placement, service binding and live account-specific lease,
   qualification and installation policy.
2. **Caller authority:** the original owner's current narrowing chain through
   retained delegations, caller and agent generation, launch, profile, account,
   semantic operation and actual resource. Every edge narrows, including time
   and delegation ceilings. Service and caller chains are not concatenated.

A service's lease never supplies the caller's missing right. Neither a request,
placeholder, account selector nor cached successful admission supplies either
chain. A service holding multiple accounts/projects cannot lend one caller
another account, tenant, repository or billing identity. Provider and instance
identity are part of the resource binding, not just a display label.

| Boundary | Required fresh decision |
|---|---|
| Intake/enqueue | Authenticate the launch mapping, parse/classify complete supported operation/resources and validate both authorities before admitting work |
| Dequeue | Repeat current lease, caller, account-hold, policy, generation, time and revocation checks; stale queued work acquires no authority |
| After resolution/connection waits, immediately before attaching a credential and submitting upstream | Bind actual destination/TLS peer, exact operation/resources and current material to both authorities and a registered revocable use fence |
| Redirect, reroute, connection reuse or subsequent operation on a stream/session | Repeat destination and operation checks, current authority and use registration; no authority inheritance from the earlier request |
| Renewal and final post-refresh use/delivery | Reconcile the broker-owned outcome, same account and current inventory; repeat both authorities and all independent fences after the last blocking step |
| Response/stream continuation and closure | Retain current use/response fences, supported leak/reflection checks and bounded authority; close on loss, revocation or expiry and record the actual outcome |

An equivalent closed boundary is allowed only if qualification proves it
preserves current authority, binding, served policy and revocation/time bounds
through the entire operation. A cache TTL, polling loop or connection lifetime
is not that proof. Unexpressible predicates, unsupported dialect, expired,
revoked, stale or unavailable evidence deny before new attachment/effect.
Ongoing traffic is fenced under §9; already sent bytes cannot be recalled.

Do not hold a broker/service state lock across synchronous service, resolver,
socket, vendor or filesystem I/O. Retain fixed intent/arguments and ownership,
perform bounded I/O, then revalidate under the relevant current fences before
publishing material or use. A late result may resolve history but cannot reopen
admission. The [existing request lifecycle](../docs/request-lifecycle.md) owns
broker framing, response and writer resources; its publication acknowledgment
is not an outbound-use acknowledgment.

## 5. Recipient binding, injection and responses

Protected policy and the exact adapter select credential recipients, ports,
authentication scheme, API version, resource namespace and narrow vendor scope.
Client Host, SNI, URL, redirect targets, custom auth fields, forwarded headers or
supplied credentials cannot choose or widen a recipient. The declared
placeholder is validated and consumed only in its qualified slot. Supplied
vendor-valid material and conflicting auth sources refuse; they are never
adopted or used as a fallback.

The gateway resolves names itself, checks the address actually dialed with its
dial guard and authenticates the declared server using TLS. Private, local,
unchecked or unadmitted recipients refuse. A fresh redirect or reroute requires
complete destination, TLS, operation/resource and authority validation **before
any credential is attached there**. No automatic cross-origin credential
forwarding, agent DNS route, bypass listener or unrestricted CONNECT is admitted.
Connection pooling must retain recipient/account/policy separation and repeat
per-use authority; prior TLS success does not authorize a new resource.

Before injection, inspect the agent-originated plaintext request line, headers
and body under §7. Then inject only the leased current credential in the declared
scheme, inside the holder boundary. The legitimate inserted value must not
trigger the agent-origin detector. Adapter rewriting cannot weaken accepted
operation/resource binding or rewrite existing signed bytes to evade a block.

Every response channel, including headers, error metadata, bodies, trailers and
stream frames, needs the declared safety policy before release to the agent.
Credential-reflecting operations remain closed unless qualified protection
prevents supported material forms from crossing that boundary. Bounded stream
buffering/overlap must prevent a supported matching value from escaping in
pieces before a verdict. Unsupported encodings or exhausted buffers close; no
universal secret-absence proof is claimed. The scanner cannot retract bytes
already released, so retrospective detection alone does not qualify prevention.

Logs/status contain closed typed metadata only, with no raw headers, bodies,
URLs, protocol frames, credential values or token hashes. Error classification
preserves UNKNOWN where authentication, permission and quota failures cannot be
distinguished. A provider error is not automatically a refresh trigger.

## 6. Renewal and upstream uncertainty

Only the broker-side lifecycle owner may mint/refresh/reconcile material. An
adapter-declared real upstream rejection can request renewal for the rejected
**real credential identity** over protected service IPC. A placeholder digest
is not a substitute. The dialect must publish that binding; no new v0 field is
assigned here. Concurrent rejections join bounded single-owner work rather than
create new writers. Final renewal/use rechecks the unchanged account, both
authorities, account hold, inventory and policy after broker reconciliation.

A renewed credential does not authorize replay. Lost response, uncertain
upstream acceptance, partially started response/stream, interrupted refresh or
unknown rotation is **UNKNOWN**. Never automatically resend with a new token,
fall back to another account or infer safe nonrotation from process death,
unchanged files or an HTTP status alone. Any safe retry needs conclusively
resolved prior outcome and exact recipient-supported semantics. Correlation,
callback deadline and placeholder-only callback behavior are separately
qualified per harness; no real token reaches an agent callback.

## 7. Leak tripwire and account containment

Leak matching is defense in depth, not the custody boundary or universal
secrecy proof. The protected issued-version inventory covers every issued
still-vendor-valid credential version for each account the service may use,
including superseded and locally released versions, until actual vendor expiry or
confirmed invalidation. New material cannot be used before the required
inventory/matcher state is current. Current-token-only matching is insufficient.
Missing, stale, incomplete or ambiguously bound matcher state closes use.

Each qualified adapter declares raw, base64/base64url, hex, percent-encoded,
JSON-escaped and scheme-specific forms, decoding rules, maximum lengths,
chunk-overlap/window bounds, total budgets and behavior on exhaustion. It must
cover its supported request and response forms. Arbitrary encryption,
compression, splitting, opaque tunnels, slow leaks and unknown secrets are not
covered by a finite matching claim. Unsupported forms refuse instead of being
reported scanned. Per-generation resource budgets survive restart.

A **possible leak** immediately blocks the local forwarding/response path and
requests a durable protected **whole-account hold**. The authenticated detector
trigger must have narrowly published account binding, replay/correlation,
durability and admission rules. It conveys no general operator authority.
Uncertain account attribution is UNKNOWN and forwarding stays blocked; the
gateway cannot invent a cross-account hold target or report an unrecorded hold.

The account hold covers all generations, launches, new leases, service uses and
renewals, including final delivery after asynchronous refresh. The broker
checks it at final release under its state fence. Gateway and action-service
consumers close account-scoped queue/cache/listener/session/stream/action use;
sessions stop through the already authorized credential-failure path. A lease
release or event report cannot implement that whole-account authority.

| Outcome | Meaning; never inferred from another outcome |
|---|---|
| Local block | This local path no longer forwards/releases the suspected material |
| Durable account hold | Broker has durably recorded the account-wide admission/delivery fence |
| Service-use closure | Each affected consumer has durably closed its account-scoped work, or its earlier authority has expired under §9 |
| Session stop | The authorized session/generation stop path has its own actual result |
| Vendor invalidation | The provider has invalidated the specified versions under a qualified lifecycle contract; local stop/release proves none of this |
| Owner notification | The separately owned alert route has its own acknowledgment/failure; notification grants no recovery power |

Broker/hold acknowledgment unavailable means local use remains blocked and the
hold outcome is UNKNOWN, not recorded. Reconnect, restart, a fresh generation or
service replacement cannot clear it. **Only the account owner lifts the hold**;
that act cannot clear independent revocation, restore, stop, time or restart
fences. An unacknowledged closure is never silently reopened after a timeout.

A possible leak does **not** authorize automatic vendor action. A **confirmed
leak additionally requires separately qualified vendor rotation/invalidation**
for the actual auth kind and affected versions. Confirmation criteria are OPEN;
a detector match is not confirmed by default. Unsupported or ambiguous vendor
invalidation leaves the account held with UNKNOWN vendor outcome, not a fake
success or local-only rotation claim. A qualified protective lifecycle operation
must retain single-writer/outcome fences and cannot deliver usable material
through the hold. Re-enrollment requirements remain kind-specific.

Outside-gateway matching custody and its API/owner remain OPEN; no raw material,
matcher inventory or chosen matching API is exported to a bridge, messaging
service or LLM classifier. Existing signed message bytes are blocked rather than
rewritten. An alert needs its own enabled owner, closed typed schema, durable
correlation/acknowledgment and retry/storage/rate limits. It contains no raw
requests, values or token hashes. Alert failure cannot delay, undo or falsely
complete containment.

## 8. Separate action service

The action service independently leases material as itself and retains the
originating caller's narrowing authority for the exact action, account and
resources. It applies the same hold, time, policy, revocation and final-use
checks. Neither a gateway classification nor possession of a service token
supplies permission to write. Credential administration is not a generic
agent action; protected lifecycle ownership is unchanged.

Before a mutating action, durably bind one stable effect identity to fixed
parameters and target, expected state, caller/service authority and relevant
stop/policy epochs. Revalidate before execution and each authority-creating
continuation, without state locks across external I/O. Recipient idempotency
may be used only for the exact supported action; a local correlation ID is not
recipient deduplication. Record actual success, rejection or UNKNOWN and
reconcile lost responses without blind replay or duplicate effects.

Repository publication/landing additionally requires the board-authorized
**accepted exact candidate**, configured signing/verification policy and an
actual expected-head compare-and-swap. A producer signature, verification badge,
service grant or matching branch name does not replace acceptance. Signatures
on commits/tags, signer trust and accepted object identity remain separate from
permission to move a reference. Provider-specific signing and conditional-update
mechanisms stay closed until their exact capabilities are qualified in the
[adapter profile](secret-free-adapters.md#6-equal-provider-profiles). No
GitHub-specific API or default is universal. Unknown remote effect/CAS result
cannot be retried as a new write or called landed.

The [sourced provider profiles and object-preservation rule](secret-free-adapters.md#6-equal-provider-profiles)
distinguish documentary API facts from target qualification. A source-head field
or guard alone does not establish an atomic target-head/check/review condition.
Qualify the exact admitted method and original signed-object policy, or disable/
refuse landing. No direct-push, force-merge or protection-bypass workaround is
authorized when the provider cannot express the required accepted effect.

## 9. Revocation, stop and restart

Gateway and action service are revocation consumers. From signed publication,
the inherited propagation bound is **max(S + A, F)**, with exactly the owning
revocation contract's parameter definitions and measurement obligations, as
retained by [secret-free mode §9](secret-free-mode.md#9-use-fences-effects-and-recovery).
No parameters or numeric bounds are chosen here, no pre-publication effect is
promised, and a cache timeout alone proves no bound.

For each affected consumer, completion requires its durable closure
acknowledgment **or expiry of all its earlier authority**. Broker intake,
revocation publication or a material-delivery fence is not gateway use closure
or an action outcome. Qualify current snapshot freshness, consumer observation
and earlier-authority expiry against the inherited bound. Unsupported or unknown
freshness closes admission; existing trusted-time confidence, watermarks,
not-before/expiry and monotonic destruction rules remain independent.

The fence covers queued requests/actions, cached leases/material, listener
sessions, pooled connections, in-flight uses and streams. Register uses before
attachment/submission; close affected work and preserve durable records on
revocation, hold, generation freeze, retirement and all-stop. Close a stream on
loss rather than serve from a stale cache. An already started action is
interrupted where safe, otherwise its actual outcome is reconciled; already
sent bytes/effects are not erased by a local close. Unknown upstream outcome
remains UNKNOWN even when local closure is confirmed.

Crash, restore and service replacement start closed. Reconcile durable closure,
account hold, accepted authority, effect/attempt history, writer absence and
store/time evidence before new use; old queued work is not revived by restart.
Retain tombstones and original effect identity across binding replacement.
Surviving-history restore and every independent R-ALLSTOP service part remain
required. One component's recovery, process absence, owner hold-lift or broker
freeze clearance cannot reopen another or grant session restart authority.
Unknown/partial/unreadable evidence keeps the affected scope closed.

## 10. Qualification and publication

Activation requires publication and implementation of compatible broker/grant
service-principal, service-binding, service-lease, use-through-service and
narrow detector-hold semantics with ownership, encodings, permissions, refusal
mappings and revocation observations. Existing `broker/1`, `lease/1`, v0 static
UID policy and agent-only lease/report methods express none of this by default.
Wire/schema selection remains OPEN; these semantic requirements add no active
configuration or enum.

The qualification identity binds exact API/version/instance/auth kind, adapter
release/digest, harness release/digest/channel, profile/model, platform/topology,
account/billing identity, service and installation/custody policy, listener and
served-policy identity, mode and network/IPC boundary. A changed or unknown
member refuses until separately qualified. Test API keys and dedicated test
subscriptions come first; personal subscriptions remain closed until those
witnesses pass. Existing v0/static/synthetic/version/help/schema/fake-503 evidence
does not qualify successful login, placeholder renewal or enforced isolation.

Prove configured endpoint acceptance and all credentialed startup/account/status,
policy/background/child/hook/tool/connector traffic. Identity-dependent features
must work or be explicitly unsupported. No operational command, new endpoint,
interception trust, account or shared primitive is installed by these documents.
No new prerequisite is imposed on a separately authorized account window or M0.

## 11. Documentary witnesses

Every row is a prospective contract witness, **runtime UNRUN**, with a nearby
valid control. Both controls need the exact qualified tuple and independent
expected outcomes; paper agreement is not a test or killed mutant. Refusal
before submission means no credential attachment or forbidden external effect;
for an already submitted use preserve actual UNKNOWN and prevent duplicate or
reopened use, rather than claiming the earlier effect did not happen.

| Negative neighbor | Required invariant/outcome | Nearby valid control |
|---|---|---|
| Read-like request or model endpoint hides persistence/admin mutation; one batch member writes | Entire request refused before forwarding, no write or automatic action dispatch | Fully classified read/inference within admitted effects; separately authorized action-service write |
| Live service lease, stale/revoked caller chain or changed target at dequeue | No attachment/effect; stale queue cannot reopen | Both independently current authorities for the exact resource at final use |
| Current caller, replaced/retired service generation or stale lease | No use by old service or inherited lease | Fresh admitted service identity/generation/binding and own live lease |
| Wrong listener, reused port, stale served policy or cross-account placeholder | No resource/account/provider substitution or credential disclosure | Own qualified launch/listener/policy and unchanged account |
| Agent Host/SNI/URL, alternate auth or redirect chooses another/private recipient | Refuse before attachment there; no credential forwarding | Machine-selected recipient freshly dial-guarded/TLS-authenticated with current authorities |
| Direct-provider, holder-store/private-IPC or foreign-listener bypass succeeds | Tuple remains unqualified; placeholder is not claimed a boundary | Own endpoint succeeds and all forbidden routes are independently denied |
| Reflected credential in response header/error/body or bounded split frame | No matching supported material reaches agent; stream closes before release of unsafe bytes | Safe classified response and near-match under qualified buffering bounds |
| Old superseded/released still-valid version in declared encoded/chunked form | Local block plus account-wide hold request; no forwarding or new lease via another generation | Near-match and normal legitimate injection do not trigger account hold |
| Stale/missing matcher inventory or overlap/decoder/resource exhaustion | Forwarding closes; no complete-scan claim | Current complete supported inventory within qualified budgets |
| Broker unavailable during possible leak, or alert delivery fails | Local use blocked, hold/alert outcomes independently UNKNOWN; containment does not wait | Durable hold and per-consumer closure with separately recorded alert outcome |
| Non-owner hold lift, reconnect/restart or fresh launch after leak | Hold persists; no reopened/new use | Explicit owner lift plus every independent admission/restart fence satisfied |
| Possible leak treated as confirmed; confirmed leak with unsupported invalidation | No automatic vendor mutation on possible leak; confirmed case stays held/UNKNOWN without qualified invalidation | Separately confirmed leak and qualified kind/version-specific vendor action with actual outcome |
| Revocation/freeze/retirement/all-stop during queued use, refresh or stream | Fence queue/final delivery/stream, durable per-consumer closure or earlier-authority expiry; no stale result reopens | Use conclusively completed before fence; fresh admitted use only after authorized reconciliation |
| Lost upstream response/partial stream or ambiguous refresh, then renewed-token retry | UNKNOWN; no blind replay, new writer or duplicate effect | Conclusive safe prior outcome and exact supported same-effect reconciliation |
| Accepted-looking branch with unaccepted candidate, wrong signer/object or stale expected head | Action refuses publication; no reference update | Board-authorized accepted exact signed candidate and qualified expected-head CAS |
| Restored old cache/hold/closure evidence or one service recovered alone | Closed/UNKNOWN until independent durable histories reconcile; no old queue revival | Explicit authorized recovery with every affected part reconciled |
| Unsupported dialect, auth kind, scope predicate, tuple or endpoint harness | Refuse selected mode; no exposed/native/account fallback | Published dialect and independently qualified exact combination |

Donor/interception/new-class operations are closed scope, not omitted successful
witnesses. Holder/root compromise and finite matcher limitations remain explicit
residual trust limits. Documentation acceptance opens no production entry.
