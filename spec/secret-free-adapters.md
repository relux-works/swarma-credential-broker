# Secret-free credential and request adapters

**Document revision 2 — PROPOSED, inactive.** This is the provider-agnostic
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
profiles in §6 distinguish dated, version-scoped documentary facts from proposed
service rules and **TO QUALIFY** target capabilities. Exact primary-source
evidence and independent review must precede capability selection; account/API
tests and exact runtime witnesses are separate later authority. An unsupported capability
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

The same six admission dimensions apply to every profile below, in addition to
§§1–5. **Documentary source baseline: 2026-10-27 UTC.** The linked primary
sources support the stated facts within their named versions; current upstream
pages do not identify an installed target. Proposed service restrictions are
labelled as rules. Actual deployment capability, configuration, role/scope
combinations, residual validity and runtime witnesses remain **TO QUALIFY /
UNRUN**. No token family inherits another provider's semantics.

### 6.1 GitHub

Source scope: current GitHub Cloud documentation; REST examples use API version
2026-03-10. Enterprise Server parity and the selected deployment remain TO
QUALIFY. Installation, App-user OAuth and fine-grained PAT are distinct profiles.

| Dimension | Documented fact; proposed restriction and remaining qualification |
|---|---|
| Bootstrap, mint and refresh | An installed App uses its protected signing key to produce an App JWT, then POST `/app/installations/{id}/access_tokens`; successor minting is not OAuth refresh. Explicit repository/permission selection cannot exceed the installation/App grant; omitted permissions inherit the App grant. App-user authorization uses `/login/oauth/authorize` and `/login/oauth/access_token`, with App/user access intersection. Fine-grained PAT bootstrap is the user Settings UI; do not infer unattended PAT mint/refresh from App routes. **Rule:** broker owns bootstrap/renewal and always selects explicit minimal resources/permissions. Owner installation approval, SAML/user authorization and PAT approval policy are TO QUALIFY. [Installation tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app), [App-user tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-user-access-token-for-a-github-app), [fine-grained PATs](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens). |
| Endpoint, role and resource scope | For the selected authenticated token profiles, GET `/repos/{owner}/{repo}/contents/{path}?ref={oid}` uses Contents-read. Single-PR GET `/repos/{owner}/{repo}/pulls/{n}` accepts Pull-requests-read **or Contents-read**; the former is a valid selection, not the exclusive alternative. PR POST/PATCH requires Pull-requests-write; PUT `.../pulls/{n}/merge` requires Contents-write. Actor access and selected repository still constrain these permissions. Fine-grained PATs can also read public repositories beyond their selected set. **Rule:** exact broker destination/resource binding remains mandatory even when vendor authority is broader; all POST/PATCH/merge effects here are action-service-only. [Contents](https://docs.github.com/en/rest/repos/contents), [pull requests](https://docs.github.com/en/rest/pulls/pulls), [PAT access limits](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens). |
| Expiry, revoke and residual reach | Installation access lasts one hour; DELETE `/installation/token` invalidates that authenticating token, while successor minting does not revoke another token. The expiring App-user flow documents eight-hour access/six-month refresh; opt-out, history and old-access/refresh invalidation require their own profile. App client-owner token/grant deletion is separate. PAT expiry is user/organization-policy dependent, not a universal duration. Cache, session, in-flight and derived-credential reach remain TO QUALIFY. [Installation revoke](https://docs.github.com/en/rest/apps/installations), [user refresh](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/refreshing-user-access-tokens), [app token/grant deletion](https://docs.github.com/en/rest/apps/oauth-applications), [PAT lifecycle](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens). |
| Confirmed leak response | Under §3, a possible leak blocks/holds without vendor mutation. Confirmed response must select the actual kind's supported owner path: installation-token revoke, App-user token/grant deletion or PAT deletion/replacement. POST `/credentials/revoke` lists PAT/OAuth/App-user/refresh kinds, not installation tokens; its accepted response does not prove complete invalidation. Compromised App root key/client secret additionally needs separately authorized replacement/removal. Automatic public-leak handling is not comprehensive detection or drain. Affected-version enumeration and outcome reach are TO QUALIFY. [Credential revoke](https://docs.github.com/en/rest/credentials/revoke), [expiration/revocation](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/token-expiration-and-revocation), [App security practices](https://docs.github.com/en/apps/creating-github-apps/about-creating-github-apps/best-practices-for-creating-a-github-app). |
| Git object signing and trust | The guide describes GPG, SSH and S/MIME commit/tag signatures, with account key/email or certificate prerequisites; SSH needs Git 2.34+, S/MIME Git 2.19+. Persistent verification can outlive key revocation/expiry or account departure within a repository network. A verification badge is not current authority, accepted content or green checks. **Rule:** separate signing custody/trusted-object verification; an API token signs nothing by itself. Target key/trust policy remains TO QUALIFY. [Signature verification](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification). |
| Exact-head action-service landing | Merge `sha` mismatch is documented as 409; asynchronous merge can be 202/enqueued before protection evaluation. Documented PR modes are merge/squash/rebase, **not a fast-forward-only PR option**. Protection can require checks/reviews/signatures and permit bypass, with plan/configuration differences. **Rule:** bind accepted source/target/object identity and actual applicable checks; qualify the admitted expected-head method and signed-object policy (§6.6), not just the presence of `sha`. If none satisfies them, disable/refuse landing; no direct-push/bypass workaround follows. [Merge API](https://docs.github.com/en/rest/pulls/pulls), [merge methods](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/configuring-pull-request-merges/about-merge-methods-on-github), [branch protection](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-protected-branches/about-protected-branches). |

### 6.2 GitLab

Source scope: current GitLab documentation with endpoint feature history, not a
chosen installed release. Project/group access tokens are resource-associated
bots with distinct bootstrap authority. Deploy tokens are a separate family.
GitLab.com project/group tokens require Premium/Ultimate; Self-Managed/Dedicated
allow any license. The documented trial permits one project token and no group
token. Deploy-token availability is broader. Pin edition/plan and actual policy
rather than inferring parity. [Project tokens](https://docs.gitlab.com/user/project/settings/project_access_tokens/),
[group tokens](https://docs.gitlab.com/user/group/settings/group_access_tokens/),
[deploy tokens](https://docs.gitlab.com/user/project/deploy_tokens/).

| Dimension | Documented fact; proposed restriction and remaining qualification |
|---|---|
| Bootstrap, mint and refresh | Project token creation at POST `/projects/:id/access_tokens` requires a PAT and project Maintainer/Owner authority. Group creation at POST `/groups/:id/access_tokens` requires group Owner and separately qualified bootstrap authentication; a group resource token cannot be assumed to mint other resource/PAT credentials. Set the bot role explicitly. Deploy creation/deletion is through project/group `/deploy_tokens` under project Maintainer/Owner or group Owner. Neither family supplies a universal OAuth refresh. **Rule:** protected manager authority stays separate; no self-bootstrap or administrator fallback. [Project lifecycle](https://docs.gitlab.com/api/project_access_tokens/), [group lifecycle](https://docs.gitlab.com/api/group_access_tokens/), [deploy management](https://docs.gitlab.com/api/deploy_tokens/). |
| Endpoint, role and resource scope | Under `/api/v4`, GET `/projects/:id/repository/files/:file_path?ref={oid}` admits `read_repository` (also broader `read_api`); The selected narrow MR GET scope is `read_api`, plus visibility; broader `api` is not a least-permission substitute. MR POST, PUT and PUT `.../merge_requests/:iid/merge` need `api` among these resource-token scopes plus actual actor/target rights. `write_repository` permits Git writes, not arbitrary MR API writes. Developer is a baseline for ordinary same-project work, not a universal lowest role. Internal-user-created project/group tokens may reach Internal projects outside nominal selection. **Rule:** explicit project/resource/endpoint binding even for group bots; gateway only declared reads. Deploy `read_repository` supports clone; registry/package scopes authorize their specific operations, **not general MR API**, so deploy-token MR work refuses. [Scopes](https://docs.gitlab.com/security/tokens/access_token_scopes/), [file API](https://docs.gitlab.com/api/repository_files/), [MR API](https://docs.gitlab.com/api/merge_requests/), [roles](https://docs.gitlab.com/user/permissions/), [project visibility caveat](https://docs.gitlab.com/user/project/settings/project_access_tokens/), [group visibility caveat](https://docs.gitlab.com/user/group/settings/group_access_tokens/), [deploy limits](https://docs.gitlab.com/user/project/deploy_tokens/). |
| Expiry, revoke and residual reach | Resource-token expiry depends on instance/version/policy; the guides' 365-day default and 17.6's conditional 400-day extension are not universal constants. Record actual returned expiry. Project/group `.../access_tokens/:token_id/rotate` revokes old and returns new; other-token rotation requires PAT `api`, self-rotation `api` or `self_rotate` (introduced 17.9). DELETE the corresponding resource token revokes it. **Replaying a revoked ancestor can revoke active descendants**; lost rotation response is UNKNOWN, held and reconciled, never blindly replayed. Deploy tokens default to no expiry, with optional midnight-UTC expiration; supported atomic rotation/native refresh is TO QUALIFY, not invented. In-flight/cache/session reach is also TO QUALIFY. [Project lifecycle](https://docs.gitlab.com/api/project_access_tokens/), [group lifecycle](https://docs.gitlab.com/api/group_access_tokens/), [scope history](https://docs.gitlab.com/security/tokens/access_token_scopes/), [project expiry](https://docs.gitlab.com/user/project/settings/project_access_tokens/), [deploy lifecycle](https://docs.gitlab.com/user/project/deploy_tokens/). |
| Confirmed leak response | Under §3, suspicion only blocks/holds. A separately qualified uncompromised manager must rotate/revoke the actual resource token or revoke/replace the deploy token, with all still-valid old versions retained in containment until actual invalidation. Replacement does not lift the hold. Automatic secret response depends on recognized token formats, tier/offering and configuration; do not assume resource/deploy coverage or active-transfer drain. Unknown descendant state after rotation loss remains held/UNKNOWN. [Project revoke/rotate](https://docs.gitlab.com/api/project_access_tokens/), [group revoke/rotate](https://docs.gitlab.com/api/group_access_tokens/), [deploy management](https://docs.gitlab.com/api/deploy_tokens/), [automatic response](https://docs.gitlab.com/user/application_security/secret_detection/automatic_response/), [incident guidance](https://docs.gitlab.com/security/responding_to_security_incidents/). |
| Git object signing and trust | GPG commits/tags require enrolled account key and matching verified committer email. SSH requires Git 2.34+/OpenSSH 8.1+ with the documented broken 8.7 signing caveat; SSH-tag verification moved from 18.3 feature flag to 19.1 GA. Key revoke/delete have different historical-verification effects. X.509 verification has Self-Managed/Dedicated trust/CRL prerequisites; do not infer GitLab.com parity. Deploy credentials do not sign objects or authorize arbitrary Git push. Exact algorithm/tag/trust/enforcement is TO QUALIFY independently of API auth. [GPG](https://docs.gitlab.com/user/project/repository/signed_commits/gpg/), [SSH](https://docs.gitlab.com/user/project/repository/signed_commits/ssh/), [X.509](https://docs.gitlab.com/user/project/repository/signed_commits/x509/). |
| Exact-head action-service landing | MR merge documents reviewed `sha` with mismatch 409; actual source/destination project IDs, existing source branch, MR identity and target are required. Approvals, pipelines, merge trains and actual actor rules remain separate. `Allowed to push and merge` also grants MR merge, and overlapping protection can be permissive. Fast-forward exists but a separate **required-squash setting still rewrites objects**. **Rule:** qualify exact checks/rule precedence/queue cancellation/source-and-target preconditions and preserving mode; otherwise refuse, never widen or bypass. [MR API](https://docs.gitlab.com/api/merge_requests/), [branch rules](https://docs.gitlab.com/user/project/repository/branches/protected/), [merge/squash methods](https://docs.gitlab.com/user/project/merge_requests/methods/). |

Deploy registry/package writes are documented capability limits, not gateway
admission of those service classes. An actual operation must remain within the
separately admitted action-service class/resource contract; general HTTP support
adds no class. A deploy-token MR refusal cannot automatically dispatch using a
broader resource token; that requires separate current authorization.

### 6.3 Gitea

Source scope: current upstream narrative and the [generated API index](https://docs.gitea.com/api/)
labelled 28.2.0 as reviewed on the source-baseline date. These are documentation
identities, not an installed release or enterprise policy assertion.

| Dimension | Documented fact; proposed restriction and remaining qualification |
|---|---|
| Bootstrap, mint and refresh | Settings/Applications creates PATs. The narrative describes POST `/api/v1/users/{username}/tokens` as special Basic username/password bootstrap with `X-Gitea-OTP` for 2FA, while the generated page lists generic auth alternatives. **The discrepancy remains TO QUALIFY**; neither establishes PAT successor-mint authority. Registered OAuth uses authorization-code/PKCE and `/login/oauth/authorize`, `/login/oauth/access_token`; do not import Forgejo behavior. [API narrative](https://docs.gitea.com/development/api-usage/), [generated token creation](https://docs.gitea.com/api/operations/user-create-token/), [OAuth guide](https://docs.gitea.com/development/oauth2-provider/). |
| Endpoint, role and resource scope | Under `/api/v1`, GET contents at `ref={oid}` maps to `read:repository`; PR POST/PATCH and POST `.../pulls/{index}/merge` map to `write:repository`, with actual code/PR rights. Issue operations have separate scopes. Granular OAuth scopes exist since 1.23, but OIDC-only and unknown-scope cases can fall back to full access. **Rule:** select known granular scopes, refuse unexpected/broad fallback and retain actual repository/caller binding; gateway never admits those write routes. Actor minimum/fork rights and target behavior are TO QUALIFY. [OAuth scopes](https://docs.gitea.com/development/oauth2-provider/), [contents](https://docs.gitea.com/api/operations/repo-get-contents/), [create PR](https://docs.gitea.com/api/operations/repo-create-pull-request/), [edit PR](https://docs.gitea.com/api/operations/repo-edit-pull-request/), [merge PR](https://docs.gitea.com/api/operations/repo-merge-pull-request/). |
| Expiry, revoke and residual reach | DELETE `/users/{username}/tokens/{token}` is documented. Reviewed create schema has no expiry input; this proves neither immortality nor refresh/atomic rotation. OAuth defaults are access 3600 seconds/refresh 730 hours, `INVALIDATE_REFRESH_TOKENS=false`; these are configuration defaults, not PAT lifetimes or deployed behavior. Actual deletion authority, grant revocation, refresh/replay and cache/session/in-flight reach remain TO QUALIFY. [Create](https://docs.gitea.com/api/operations/user-create-token/), [delete](https://docs.gitea.com/api/operations/user-delete-access-token/), [OAuth configuration](https://docs.gitea.com/administration/config-cheat-sheet/). |
| Confirmed leak response | Under §3, possible leak only blocks/holds. A qualified trusted user/manager replacement and old-PAT deletion may resolve a confirmed incident; no automatic leak response, OAuth revoke endpoint or atomic replacement is presumed. Unknown invalidation leaves the account held with actual UNKNOWN/unsupported outcome. Exact owner authority, old versions and residual reach need qualification. [Token deletion](https://docs.gitea.com/api/operations/user-delete-access-token/), [token lifecycle](https://docs.gitea.com/development/api-usage/). |
| Git object signing and trust | The guide covers GPG/SSH commit verification and configured instance-generated commit/merge signing; it says verification does not check key expiry/revocation. Thus a badge cannot establish current trusted authority. Hosted signed-tag verification, other algorithms, client minimums and instance key/custody policy remain TO QUALIFY. API tokens and signing keys stay separate. [Signing guide](https://docs.gitea.com/administration/signing/). |
| Exact-head action-service landing | Merge schema has `head_commit_id`, `force_merge`, deferred merge and `fast-forward-only` among its modes. **A head field is not qualified atomic enforcement.** Documented API/Git/web protection is not proof of actual checks/review/bypass settings or deferred cancellation. **Rule:** qualify current source-and-target guards, applicable rules and original-object preservation; refuse if unsupported. Never enable force/deferred/bypass as compensation. [Merge schema](https://docs.gitea.com/api/operations/repo-merge-pull-request/), [protected branches](https://docs.gitea.com/usage/access-control/protected-branches/). |

### 6.4 Forgejo — independently sourced

Source scope: Forgejo v17.0 documentation with latest navigator v17.0.1 and its
[official v17.0.1 tagged schema](https://codeberg.org/forgejo/forgejo/raw/tag/v17.0.1/templates/swagger/v1_json.tmpl).
Its selected paths/definitions are Forgejo evidence; Gitea similarity provides
no equivalence. Pin the actual target release, enabled API and configuration.

| Dimension | Documented fact; proposed restriction and remaining qualification |
|---|---|
| Bootstrap, mint and refresh | Forgejo's own Settings/Applications and Basic-special-case POST `/api/v1/users/{username}/tokens`/`X-Forgejo-OTP` sources govern PAT bootstrap. Tagged creation schema has `repositories` and `scopes`, no expiry input. OAuth code/PKCE/refresh examples are separate; v17 OAuth scopes are explicitly **not implemented**, so OAuth is not evidence of narrow repository scope. Exact mint/delete authority, expiry and refresh/replay support remain TO QUALIFY. [API usage](https://forgejo.org/docs/latest/user/api/usage/), [v17 OAuth](https://forgejo.org/docs/v17.0/user/authentication/oauth2-provider/), [tagged schema](https://codeberg.org/forgejo/forgejo/raw/tag/v17.0.1/templates/swagger/v1_json.tmpl). |
| Endpoint, role and resource scope | Own scoped PAT rules and tagged schema support contents/PR reads with `read:repository` and PR create/edit/merge with `write:repository` plus actual owner/actor rights. Paths under `/api/v1` include GET contents, GET/POST pulls, GET/PATCH pull index and POST merge. Selected repositories still permit other public reads and exclude administrative operations. **Rule:** exact commissioned destination/resource binding; no Gitea OAuth-scope inheritance or gateway writes. Actor/fork rights and target scope behavior remain TO QUALIFY. [PAT scope rules](https://forgejo.org/docs/latest/user/authentication/token-scope/), [tagged endpoints](https://codeberg.org/forgejo/forgejo/raw/tag/v17.0.1/templates/swagger/v1_json.tmpl). |
| Expiry, revoke and residual reach | Tagged DELETE `/users/{username}/tokens/{token}` is a PAT route, not generic OAuth/integration revocation. OAuth defaults are access 3600 seconds/refresh 730 hours, `INVALIDATE_REFRESH_TOKENS=true`, distinct from Gitea and from PATs. Missing PAT expiry input is not immortal-token evidence. PAT rotation/deletion reach, OAuth refresh replay/grant revocation and active sessions/caches remain TO QUALIFY. [Schema](https://codeberg.org/forgejo/forgejo/raw/tag/v17.0.1/templates/swagger/v1_json.tmpl), [configuration](https://forgejo.org/docs/latest/admin/config-cheat-sheet/), [OAuth](https://forgejo.org/docs/v17.0/user/authentication/oauth2-provider/). |
| Confirmed leak response | Under §3, possible leak only blocks/holds. Confirmed PAT response needs separately qualified owner replacement/deletion. Authorized Integrations are a **separate privileged option**: configured external JWT issuer/audience/claim/capability rules, HTTPS issuer metadata and same-host HTTPS JWKS, acting as integration owner. They are neither Git signing nor implemented OAuth scopes. Integration enable/disable/revoke, JWT validity, JWKS rollover/cache and compromised-issuer recovery require qualification; do not invent an endpoint or call a hold complete vendor invalidation. [PAT management](https://forgejo.org/docs/latest/user/api/usage/), [Authorized Integrations](https://forgejo.org/docs/latest/user/api/authorized-integrations/). |
| Git object signing and trust | Forgejo documents instance GPG/SSH commit signing, SSH prerequisites Git 2.34+/ssh-keygen 8.2p1+, and an instance-key rotation limitation. Safe rollover/historical trust, hosted tag-signature verification and other algorithms remain TO QUALIFY. Tag creation/update protection does not prove tag-signature verification; API auth and integration JWT keys do not automatically grant Git signing authority. [Signing](https://forgejo.org/docs/latest/admin/advanced/signing/), [branch/tag protection](https://forgejo.org/docs/latest/user/repository/protection/). |
| Exact-head action-service landing | Tagged merge options include `head_commit_id`, `fast-forward-only`, force/deferred and rewriting modes. These are schema facts, **not atomic precondition or configured enforcement proof**. Actual actor/check/review/protection and source-and-target race guarantees remain TO QUALIFY independently of Gitea. **Rule:** exact accepted signed objects and an admitted conditional method or refuse; no check-then-merge/force/bypass workaround. [Tagged merge schema](https://codeberg.org/forgejo/forgejo/raw/tag/v17.0.1/templates/swagger/v1_json.tmpl), [protection](https://forgejo.org/docs/latest/user/repository/protection/). |

### 6.5 Model providers and generic HTTP extension

HTTP is a transport, not a service class. An extension still serves only an
already admitted model-provider or code-hosting class. Model profiles pin
provider/auth kind, harness/channel/model, account/subscription/API billing,
configured endpoints, rejection/renewal/stream behavior, startup/background/child
routes and reflection/retention/effects. Codex, Claude and Muse retain their
baseline distinctions: Claude's exposed setup-token lane retains re-enroll/
restart; Muse's proposed minted key is separate from OAuth and API keys with
billing/lifetime/rotation unknowns. None grants secret-free endpoint capability.

Source scope: the named OAuth RFCs below, including RFC 9700's security BCP,
reviewed at the documentary baseline date; no actual service/API/version is
selected. Non-Git services do not acquire Git-host capabilities through OAuth.

| Dimension | Documented fact; proposed restriction and remaining qualification |
|---|---|
| Bootstrap, mint and refresh | RFC 6749 describes user consent/authorization grants and prearranged confidential-client authority; registration and refresh issuance are service-specific/optional. Use current BCP/PKCE where supported. **Rule:** actual registered issuer/client/service endpoints only; no guessed `/token`, password grant, imported login or administrator fallback. [OAuth framework](https://www.rfc-editor.org/rfc/rfc6749.html), [security BCP](https://www.rfc-editor.org/rfc/rfc9700.html). |
| Endpoint, role and resource scope | OAuth/bearer auth supplies no universal repository/document API, scope vocabulary or role. Resource indicators require issuer support and policy. **Rule:** map actual service endpoint/effect/resource plus role and both current authorities; gateway only admitted reads/inference, action service alone for admitted writes. Broader vendor token cannot replace destination narrowing or missing predicates. [Bearer use](https://www.rfc-editor.org/rfc/rfc6750.html), [resource indicators](https://www.rfc-editor.org/rfc/rfc8707.html). |
| Expiry, revoke and residual reach | Metadata registration/revocation fields are optional; endpoint absence is not permission to guess `/revoke`. RFC 7009's 200 can mean successful revoke **or already-invalid token**, with propagation delay/policy-dependent cascades; it is not global session/cache drain. Actual refresh/expiry/revoke/metadata trust and residual reach are TO QUALIFY. [Metadata](https://www.rfc-editor.org/rfc/rfc8414.html), [revocation](https://www.rfc-editor.org/rfc/rfc7009.html). |
| Confirmed leak response | Under §3, suspicion only blocks/holds. Confirmed action uses the actual issuer's supported owner-authorized kind/version invalidation path with truthful outcomes, or stays held/UNKNOWN. No universal revoke/rotate API or local-release substitute. Client authentication and public/confidential-client differences follow the actual registered contract. [Revocation protocol](https://www.rfc-editor.org/rfc/rfc7009.html), [OAuth security](https://www.rfc-editor.org/rfc/rfc9700.html). |
| Git object signing and trust | OAuth authenticates API use; it supplies no Git signature, key enrollment or badge contract. For an actual Git-host extension qualify commit/tag algorithms, signing custody/trust and verification; for a non-Git resource, Git signing is inapplicable. No credential kind is automatically a signing key. [OAuth bearer boundary](https://www.rfc-editor.org/rfc/rfc6750.html). |
| Exact-head action-service landing | Actual registered service operations must publish supported conditional writes/idempotency, roles and resource/version semantics. A Git-host extension additionally needs real PR/MR/protection/check/object-preservation and exact-head contracts. **Rule:** unsupported capability stays disabled/refused, not an invented endpoint or broader token. A non-Git service is not required to emulate repository landing. [Framework limits](https://www.rfc-editor.org/rfc/rfc6749.html), [service metadata](https://www.rfc-editor.org/rfc/rfc8414.html). |

### 6.6 Signed objects and supported landing methods

[Git's object model](https://git-scm.com/docs/git-merge) distinguishes a true
fast-forward, which moves a ref to existing objects, from a normal merge, which
preserves source commits but creates a new merge object. Squash/rebase create
replacement objects; the original signatures do not certify those replacements.
This object distinction is separate from a provider's signing badge or merge API.

**Proposed service rule:** preserve the accepted original signed objects. Any
admitted creation of an additional merge/tag object needs its own explicitly
accepted object/signing policy and separately authorized signing custody; do not
silently substitute a rewritten object or choose new signing authority. API
credentials, author/merge/tag keys, trusted verification roots and acceptance
are separate. A valid historical signature is not current caller/service power.

The exact target method must satisfy accepted checks, current source and target
bindings, actual expected-head conditional update, and the chosen original-object
policy. Provider source-head guards do not by themselves prove an atomic target
ref/check/review transaction. Qualify that mechanism and queue/revocation behavior
on the exact target. An absent supported method disables/refuses that capability;
never add direct push, force merge, bypass or a race-prone preliminary-read
substitute to compensate. No method is authorized to run by these documents.

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

### Target-qualification queue

These source-derived rows retain qualification work, **not new authority or a
reopening of settled platform decisions**. Every operational witness is UNRUN.
A row can close only on separately authorized evidence for its exact tuple.

| Row | Evidence still TO QUALIFY |
|---|---|
| Q01 — every profile | Actual host, version, edition/plan, API/endpoint enablement and selected schema/configuration against the dated documentary source baseline. |
| Q02 — bootstrap/custody | Actual owner-authorized service, App installation/PAT/Owner/UI bootstrap, protected issuer/refresh/root secrets and separately authorized author/merge/tag signing custody. |
| Q03 — least permission | Endpoint-by-endpoint valid/refusal controls for exact role, scope, resources, aliases/forks/transfers and inherited/Internal/public visibility; no administrator or broader-token fallback. |
| Q04 — GitHub | App-user expiry opt-in/history, SAML/PAT approval, installation root recovery, actual protection/bypass/queue/check rules and supported original-signed-object-preserving landing. |
| Q05 — GitLab resource tokens | Returned expiry and bot authority, recognized leak-token coverage, lost-rotation/ancestor-reuse reconciliation, MR approval/check/train/rule precedence, source/target guards and separate squash setting. |
| Q06 — GitLab deploy | Exact clone/registry/package auth and admitted class/resource, replacement-manager authority, supported rotation if any, active-transfer/cache invalidation; general MR work remains refused. |
| Q07 — Gitea | Narrative/generated bootstrap auth discrepancy, PAT expiry/rotation, OAuth scope fallback/refresh/revoke, atomic head enforcement, actor/protection/check/signing/tag-verification behavior. |
| Q08 — Forgejo | Exact v17 schema versus target, scoped PAT selection/actor/deletion/expiry, OAuth grant/refresh behavior without implemented scopes, integration/JWT/JWKS disable/rollover/cache, head enforcement and signing/tag/key rollover. |
| Q09 — generic HTTP | Actual registered service/issuer/client/consent/auth/grant, trusted metadata, role/resource/scope, refresh/expiry/revoke/resource-indicator support, supported conditional effects and non-Git inapplicability. |
| Q10 — shared use/incident/landing | Qualify mechanisms implementing **both current authorities each use**, immediate possible-leak block plus durable whole-account owner-only-lift hold, confirmed-only qualified vendor mutation, all still-valid issued-version matcher coverage, inherited max(S+A,F), per-consumer closure-or-earlier-authority-expiry, final renewal fences and UNKNOWN/no replay. Also qualify queue/in-flight/session/cache residuals, exact source/target/check/object guarantees, signing custody and evidence retention. Those platform rules are fixed; leak-confirmation criteria and outside-gateway matcher custody remain OPEN, not implicitly selected here. |

## 8. Documentary neighbors

All rows are prospective **runtime UNRUN** witnesses, not executed tests or
killed mutants. Each nearby positive is conditional on actual exact published
capability and qualification. A refusal before submission preserves no material
attachment/forbidden effect; after uncertain submission, preserve UNKNOWN and
prevent duplicate/reopened use instead of claiming remote absence.

| Negative neighbor | Required invariant/outcome | Nearby valid control |
|---|---|---|
| Another provider/instance/kind's token, permissions or refresh semantics borrowed as default | No issuance/use; no cross-provider or kind substitution | Exact selected profile with independently established kind/scope/recipient |
| Read-only vendor credential offered for write, or broad service token plus unexpressible/stale caller resource predicate | Refuse before attachment/effect; no permission escalation or widening to make a request work | Required vendor permission plus independently current service and caller authority for expressible actual resources |
| Project/group/organization or account confused by alias, redirect or secondary target | No cross-account/project/tenant use | Actual canonical resource/tenant identity matches both chains and destination |
| Static/deploy credential assumed refreshable, missing lifetime treated as enrollment-plus-TTL | No invented refresh or matcher expiry; remain closed/unknown | Exact supported kind-specific lifecycle and known validity or conservative retained inventory |
| Concurrent rejection, refresh completion after hold/revocation, or lost refresh outcome | One retained owner; no late delivery/second writer/blind rotation retry | Conclusive prior attempt/store/absence plus final current authority/hold checks |
| Nominal read or inference request contains hidden mutation/batch member | Whole gateway request refused, no partial forwarding or automatic action | Complete supported read/inference classification; separate admitted writer action |
| Agent-selected alternate auth/recipient or reflected real material | No recipient injection or credential-bearing response to agent | Exact protected recipient/scheme and qualified response protection |
| Superseded/released but still-valid encoded material missed by current-only matcher | Forwarding closed, account hold requested; no false scan success | Complete required account inventory and supported encoded near-match control |
| Missing/stale matcher or bounded decoder/buffer exhaustion | No forwarding or universal secrecy assertion | Current supported inventory within qualified overlap and resource budgets |
| Possible leak auto-rotates; confirmed leak has unsupported vendor invalidation | Possible: block/hold only; confirmed: remain held/UNKNOWN vendor outcome, no pretend invalidation | Separately confirmed and qualified kind/version invalidation with actual outcome |
| Broker/hold/alert unavailable or non-owner attempts lift | Block persists; independent outcomes UNKNOWN; no new/reopened lease/use or alert-gated containment | Durable account hold/consumer closure, independent alert result, explicit owner lift with all other gates |
| Grant/token/signature or historical badge alone offered for publication; stale head, missing checks/bypass ambiguity or schema-only CAS | No substituted signing authority, reference update or check-then-write/force/bypass workaround | Board-authorized accepted exact signed object, current separate authorities/checks and qualified recipient expected-head CAS |
| Lost action response/replayed ID or changed parameters | Preserve original effect/outcome and UNKNOWN; no duplicate mutation | Supported same-effect recipient reconciliation with fixed arguments and current authority |
| Revoked queue/stream restored by restart or cache, one consumer closure missing | Affected scope stays closed until durable closure/earlier-authority expiry and recovery | Conclusive pre-fence completion or fresh admitted post-reconciliation operation |
| Unseen source result, unqualified API release or v0 evidence used to mark profile active | Reject capability/qualification claim; no runtime activation | Exact independently reviewed primary findings plus separately authorized tuple witnesses |
| Lost GitLab rotation response followed by revoked-ancestor replay | Retain one attempt and UNKNOWN/hold; no blind retry that could revoke active descendants | Supported current-token rotation with conclusive outcome and final currentness/hold revalidation |
| Deploy clone credential offered for general MR API or unadmitted registry/package class | Refuse that operation; no automatic broader-token dispatch or new class | Declared clone within scope, or separately admitted action and credential kind with both authorities |
| Unknown Gitea scope yields full access; Forgejo v17 OAuth assumed to implement Gitea scopes | Refuse narrowed-capability claim/use; no fallback or cross-provider semantics | Exact known supported granular Gitea scope or separately qualified scoped Forgejo PAT/resource contract |
| Squash/rebase/required-squash result substituted for accepted original signed objects | Refuse preserving-landing claim; no replacement object or silently invented signing custody | Qualified admitted method preserving accepted originals; any additional object separately accepted/signed under explicit policy |
| Guessed token/revoke/registration route when service capability is missing | No credential-bearing call or password/admin fallback; capability disabled/UNKNOWN as applicable | Actual registered supported issuer/service route under the exact qualified contract |
| Async 202/enqueued or revocation 200 offered as terminal landing/global drain | Record only actual acceptance/response meaning; retain pending/UNKNOWN effect or residual closure | Independently established terminal effect/object identity and per-consumer closure/earlier expiry plus actual vendor outcome |

Documentary approval opens no service, account, new dialect or runtime entry.
