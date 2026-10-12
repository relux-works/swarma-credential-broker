# swarma-credential-broker: specification

- **Status:** draft v0.8 (2026-10-12). Nothing is implemented.
- **Normative language:** MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119.
- **Companions:** [swarma-user-manager](https://github.com/relux-works/swarma-user-manager) (per-agent OS users, the launcher that starts processes under them, and per-UID firewall rules), [curator-network-profiles](https://github.com/relux-works/curator-network-profiles) (egress profiles), curator-spec CIP-0010 and CIP-0011 (the Curator side: credential sources, the protected credential binding, the executor capability, the launch-plan extension).

### Revision 0.8

- Applies accepted F-23 with the owner amendment and R-OPERATOR: `swarma-operator` is the no-harness operator/account owner and v0 software-root custodian; `swarma-observer` admits confirmation-free reads (§4, §13–§15).
- Adds the phone-held operator device key and phone-signed operator acts through the forced operator command, with password-authenticated terminal fallback, per-act widening confirmation and agent-session refusal (§4.3, §14–§15). Existing Ed25519 broker envelopes stay unchanged; unpublished operator formats and phone-key lifecycle remain open (§18.15).
- Aligns enrolment, revocation, launch/renewal, recovery, component, record-state and storage figures with operator custody and authentication.

### Revision 0.7

- Applies accepted cycle-2 findings: R-REBIND binding replacement with old-binding removal evidence and no lease carry-over (§7–§8); R-TIME durable watermark and elapsed-time destruction gate (§6.2, §7.2, §8.3, §9.4, §15–§16).
- Adds R-OUTCOME bind/unbind tables, keeps unbind with dispatcher/operator and admits no helper principal (§7, §13); states R-SVC-EGRESS proxy-only broker egress and its v1 qualification/dependency boundary (§3, §9, §12.3, §15.2).
- References R-GEN component restore procedures, R-FATE process fate, R-NETBIND machine-owned network policy and R-LOCK wait/lock discipline; aligns figures and records unpublished activation gates (§18). R-SESSION retains dispatcher-only physical starts; cross-account repositories follow the standalone-repository decision.

### Revision 0.6

- Applies the accepted review findings: fenced local restoration and `revocation.check` (§4.3, §6.4–§6.5, §8, §12.4, §13, §15–§16); receiver-owned `effect.observe` for bind/unbind and retained removal evidence (§7, §13); single vendor-refresh ownership across daemon replacement (§3, §9.4–§9.6, §15–§16).
- Adds requester-delegation and recovery qualification vectors, keeps the existing issuer/parent-subject rule (§6.2), and requires the dispatcher socket service from slice 0 with no dispatcher sudo entry (§16).
- Aligns figures and the threat-model retirement boundary with home deletion and restricted service-generated metadata export (§12.1–§12.2); privileged starts remain dispatcher-owned (§3.1). Unpublished formats and platform mechanisms remain activation gates (§18).

### Revision 0.5

- Removes the impossible executor release after `exec`, distinguishes launch-time lease lifetimes by delivery channel (§8.4–§8.5, §9.3), and records the unpublished cleanup policy (§18.7). Launch, recovery, renewal, component and record-state figures use the same process boundary.

### Revision 0.4

- Aligns the provider/source/channel phases and CIP-0003 disposition with the platform contract table (§5.2), keeps the readable-token exception explicit (§12.1), and records the remaining provider decisions (§18).
- Names `curator-run` under the agent account as the first broker consumer, with caller-side composition and a narrow, versioned execution mode (D-EXECUTOR, 2026-10-11; §3.1, §16).
- Separates key classes and the general-grant adapter boundary (§4.3, §6.6), fixes the helper ledger locator (§4.2), and adopts the standalone CLI name (§14).
- Applies D-WIRE-NAMES (2026-10-11): signed domain tags are `swarma-credential-broker grant/1` and `swarma-credential-broker revocation/1`. Nothing has shipped, so no migration is needed. The body discriminators `grant/1` and `revocation/1` and transport `broker/1` remain distinct from those signing domains.
- Corrects the existing registration, launch, renewal and revocation sequences; module component, recovery, record-state and storage figures document the same design boundaries (Appendix B).

These are documentation contracts, not evidence of implementation, supported vendor releases or live qualification. The platform contract table at `relux-works/curator` commit `177cb554` is the baseline; the supplied owner decisions of 2026-10-10/11/12 override its open choices where explicitly decided.

### Revision 0.3

- A binding carries the **caller's authorization** as a dependency: the chain of the caller who asked the dispatcher for the agent, and the exact intersection granted. The broker verifies it at bind and on every lease and renewal, so revoking a caller cuts its agents at once (owner decision 2026-10-10; dispatcher review F2) (§7.1, §8.2).
- The action vocabulary is frozen for v0 (`credential.lease`, `agent.spawn`), and the dispatcher's chain has a constructible shape (§6.2).
- Paths and names follow the platform root `/opt/swarma` and the service account `swarma-credential-broker`; the dispatcher is relux-works/swarma-dispatcher (§15, §16).

### Revision 0.2

An architecture review on 2026-10-09 kept the design and asked for tighter contracts. This revision:

- treats an authenticated socket as a capability with a bounded lifetime and states the rules for privileged clients (§4.1);
- keys every managed principal by UID, generation and active state, and names agent leaves by their account generation instead of a reusable label (§4.2, §6.3, §7);
- freezes a non-circular grant format with domain-separated hashing and signing, verifies every delegation edge including the leaf, and closes the v0 grammar (§6);
- gives local revocation a publication point and fail-closed reads (§6.4);
- binds every lease to its owner and repeats authorisation on renewal (§8);
- implements CIP-0010's protected credential binding for broker mode (§8.2, §12.2);
- removes the per-turn token-only Codex home: Codex personal plans are served only through app-server external tokens (§8.4, §9);
- completes the external-token contract (account identity, initialisation, deadlines) and the auth owner's enrolment ceremony and failure states (§9);
- keeps networking explicitly cooperative until the helper publishes trusted applied state (§5.5);
- reorders delivery so that the first slice is one protected Claude launch (§16).

## 1. Purpose

Agent systems run many harness processes (Claude Code, Codex, Muse, and others) on behalf of a few people. Each harness needs the credential of a person's subscription or API account. Today every managed home keeps its own login, which costs a browser login per home and, for refresh-token logins, lets parallel copies invalidate each other.

The broker is a small service that:

1. holds each account's credential once, under its own OS user, in its own store;
2. hands a credential only to a launch that is authorised for it, identifying the launching process by its OS user through the kernel;
3. decides authority from signed grants that chain to a configured root key, so that orchestrators can delegate narrower rights to the agents they start;
4. serialises refresh for accounts whose credentials rotate (Codex personal plans), so that exactly one process refreshes and launches receive short-lived access tokens;
5. can require that an account is used only through a named network profile.

### 1.1 Non-goals

- The broker does not run harnesses, compose launch plans or manage homes (Curator does).
- It does not create OS users or start processes under them (swarma-user-manager does) and does not decide who may start an agent (the dispatcher does).
- It does not authenticate to model vendors on its own behalf, bypass a vendor's login flow, or intercept model traffic. Enrolment always uses the vendor's own flow, completed by a person.
- It does not make a credential non-extractable. A credential delivered into a harness process is readable by that process (§12.1).
- It does not multiply one person's subscription across people. One account belongs to one person.

## 2. Terms

| Term | Meaning |
|---|---|
| account | One credential of one person for one harness family, for example a Claude subscription token or a Codex ChatGPT login. Identified by an account id such as `owner/claude/personal`. |
| owner | The person an account belongs to, identified by the OS account that enrolled it (§4.2). |
| principal | A participant the broker authorises: an operator, a dispatcher, an account owner, or an agent. |
| generation | The fresh random 128-bit, never-reused identifier that swarma-user-manager assigns when it creates an OS account (its ledger, helper §4.5). |
| grant | A signed statement that a key or an agent generation may lease named accounts for named harnesses and profiles in a time window (§6). |
| binding | The broker's record that an agent OS account (UID and generation) currently acts as one agent, with the grant chain it uses (§7). |
| dispatcher | relux-works/swarma-dispatcher, running under its own service account: it asks swarma-user-manager for an OS account, binds it in the broker, and starts processes under it through the helper's launcher. Curator's `agent-user` commands are its clients (CIP-0011). |
| lease | One authorised use of an account's credential by one binding for one launch (§8). |
| auth owner | The broker-side component that alone refreshes a rotating account (§9). |
| executor | The final executor of a launch: the trusted process that runs under the agent's OS account, verifies a caller-composed plan and its protected credential binding, requests the lease and starts the harness. The first consumer is `curator-run` (§3.1). |

## 3. Components

Figure [M-CB1 — broker components](../diagrams/components.puml) shows the process identities, internal components, persistent-state owners and phase boundaries defined here and in §4–§9.

| Component | Runs as | Job |
|---|---|---|
| broker daemon | its own unprivileged service user (`swarma-credential-broker` by default) | listens on the broker socket; keeps accounts, grants, revocations, bindings and leases; runs auth owners; writes the audit log |
| account store | files owned by the broker user | account records and their secret material (§5.3) |
| grant store | files owned by the broker user | signed grants and the revocation state (§6.4) |
| auth owners | inside the daemon, one per rotating account | refresh with at most one live vendor writer per account across daemon replacement (§9.4) |
| client library (`pkg/client`) | inside executors, dispatchers and the CLI | the socket protocol, delivery of material to a harness, renewal |
| CLI front end | the calling person or component | requests the admitted operation through `curator broker …` or the standalone `swarma-credential-broker` binary (§14) |
| operator command | `swarma-operator`, never a harness/session UID | forced narrow entry for phone-signed or terminal-authenticated owner/operator acts; custody of the v0 root (§4.3, §14) |
| read-only client | `swarma-observer` | status, accounts, grants and bindings without confirmation (§13.2, §14) |

The broker opens no network listener. Its only interface is a Unix-domain socket. **R-SVC-EGRESS:** the broker reaches the network only through the proxy, including approved vendor children under its UID. The user manager's §8 owns the v1 service-profile matrix: the broker has its own profile and proxy listener; kernel egress permits only that destination, and the proxy allowlist carries qualified vendor names. The dispatcher and session host have deny-all egress. Service-profile enforcement and resolver isolation are v1/slice-2 capabilities, not claims about cooperative v0 or a new slice-0 prerequisite (§15.2). Daemon-local ownership and an account lock alone do not establish single vendor-refresh ownership after a daemon crash: vendor children do not honour that lock. Slice 1 MUST preserve at most one live vendor refresh writer per account across replacement, using durable attempt intent and qualified service-manager containment, kill-and-confirm and recovery (§9.4, §15).

### 3.1 First consumer and execution boundary

Owner decision D-EXECUTOR (2026-10-11) selects **`curator-run` under the agent account** as the first broker consumer and approves a versioned, narrow one-shot amendment to Decision 0021. Curator composes and resolves profiles on the caller's side. Under the agent account, `curator-run` MUST NOT compose or resolve profiles: it verifies and executes the supplied plan, checks the destination-local protected binding (§12.2), opens a fresh broker connection and obtains the lease. This execution mode makes no network calls except to the broker; the harness's traffic follows the launch's network contract (§5.5).

The dedicated entry (such as `curator-run exec --plan-fd N`) is an intended intake shape, not an already published command grammar. R-LR1 owns its versioned launcher/Decision 0021 publication, immutable plan intake and typed refusals. The privileged `swarma-user-launcher` remains a separate binary: it checks the approved executor, passes the plan on FD3 and writes the start receipt before dropping to the agent UID (helper §7). The plan and receipt carry no credential material. The approved design uses one shared launch library with `swarma-session-runner`; a separate minimal executor binary is a later option.

D-PATH fixes the launch-scoped PATH order: (1) the protected tool directory of this launch (CIP-0007), (2) the admitted base PATH of this user in its existing order, (3) one protected manager dispatcher directory that runs project commands only after checks. A repository `.agents/bin` is never executed in a managed launch. The resolved PATH is recorded in the launch plan and covered by its digest; the executor verifies that plan rather than recomposing PATH.

Only the dispatcher invokes the privileged launcher for agent execution starts; the session host requests an admitted start through the dispatcher (`host_start`, R-START). There is no launch ticket, host sudo authority or helper host role. R-SESSION makes the **host admission permit** session-scoped for one `logical_session_id`; the owner's admitted start may explicitly authorise successors through its **session lifecycle authorisation**, with its member format unpublished. Each physical start retains its own `(execution_id, controller_epoch, op_id)` claim, fence and receipt interlock. A successor `host_start` is admissible only under that authorisation, is idempotent per `(logical_session_id, op_id)` and requires confirmed absence of the previous claim. Only the configured session-host principal may request `host_stop` in `dispatch-op/1` for an execution under its permit; this uses the journaled E-stop path (`exec.stop`, confirmed absence), is host-requested and distinct from owner `cancel`, and confers no start authority. The dispatcher owns the permit and claim/effect/root-receipt reconciliation; the dispatcher and session-host specs own their joint publication and qualification. This reference does not claim those integrations are activated.

The **board runner and session host do not embed broker clients**. They request execution from `swarma-dispatcher`, which launches through `curator-run`. The board is an optional caller, not a broker or session-host dependency. Later session-runner integration owns the agent-side PTY or per-session app-server transport and lease renewal; the session-host service owns durable session metadata. This does not assert SH2 activation or change the first consumer.

## 4. Identities and trust

### 4.1 Peer identity and connections

On every connection the broker MUST obtain the peer's effective UID from the kernel (`getpeereid` or `LOCAL_PEERCRED` on macOS and BSD, `SO_PEERCRED` on Linux) and MUST refuse the connection if the platform cannot provide it. A UID supplied in a request is never trusted.

The kernel reports the credentials of the process that **connected**, not of whoever writes later on that descriptor. An authenticated connection is therefore a capability, and the following rules apply:

1. Clients MUST open broker connections close-on-exec and MUST NOT pass them to another process (`SCM_RIGHTS`) or let them be inherited. A trusted caller that deliberately passes a descriptor delegates its own authority; this specification treats that as the caller's act.
2. Operators and dispatchers SHOULD use one connection per operation. A process that changes credentials (for example a dispatcher starting an agent) MUST close its broker connections before the transition; the agent's executor opens a fresh connection afterwards.
3. The broker associates each connection with the principal it authenticated at connect time (§4.2) and closes every connection of a UID when that UID's binding is removed or its account generation is retired.
4. Clients MUST check that the server's peer UID is the configured broker service UID before sending anything (`server_identity_mismatch`).
5. Lease methods accept only bound agent principals; administrative methods admit only the roles listed in §13.2, including the read-only observer. A connection never changes role.

The socket lives in its own directory outside the broker's data tree (§15.2). Qualification covers a connection opened before a credential change, inherited and passed descriptors, and substitution of the socket path (§16).

### 4.2 Principals

The broker's configuration (owned by the broker user, §15) names `swarma-operator` as its configured operator and account owner, `swarma-observer` as its mandatory read-only principal, and the configured dispatchers. `swarma-operator` MUST NOT host a harness session. A person's interactive account is not the operator or account owner; its sessions have no operator authority. The user manager's `operator` UID is this same `swarma-operator` account. Each principal is recorded as follows:

- **Managed principals** (accounts created by swarma-user-manager: agents, and dispatchers or services that run under helper-created service accounts) are keyed by `(uid, generation)` and are valid only while the helper ledger shows that generation as `active` for that UID. The broker reads the ledger file directly (helper §4.5); a missing, ambiguous, retired, malformed or unreadable entry refuses (`principal_ledger_mismatch`). The check is repeated on bind, lease and renew.
- **Unmanaged principals** (dedicated operator/observer accounts when not represented by a helper-managed generation) are pinned at configuration by UID plus the account's directory identity (on macOS the account's `GeneratedUID`; on Linux the user name and home path). A change refuses until an operator re-pins the principal (`principal_identity_changed`).
- Every enrolled subscription/API account has `swarma-operator` as its **owner**. The person performing the vendor ceremony does not acquire owner authority through their interactive UID. Helper-created operator/observer service accounts use the managed-principal checks above; other installations pin their directory identity. Neither account hosts a harness session.

The root helper is a ledger publisher, not a broker principal: root privilege grants no broker bind, unbind or observation role. Cross-account child workspaces use standalone repositories with their own `.git`, configuration and hooks (F-16); Worktrees within one account and the current board workflow stay unchanged; linked worktrees across isolated accounts are forbidden. Workspace materialisation belongs to the launcher/workspace contract, not the broker.

The helper ledger's default locator is **`/opt/swarma/lib/user-manager/ledger.json`** (helper §4.0, §4.5). It is root-owned, mode 0644, in a root-owned directory; the helper publishes it by atomic replacement with file flush, rename and directory flush. It contains one record per generation and no secrets; `user.list` returns those same records. Its readability is not authority. The locator follows the helper's configured installation root when it differs from `/opt/swarma`; the broker MUST use that configured locator, never search an agent home or fall back after a read failure.

### 4.3 Trust root and key classes

Grants are verified against one or more configured **root public keys** (Ed25519). In v0 the root is a local software key held only by `swarma-operator`, mode 0600 in its protected account storage, never in an account that runs agent sessions. Grant issuance through the **operator command** signs the existing v0 envelope with that root after the operator act is admitted (§14). v0 remains a local broker authorisation format with an Ed25519 software trust root; the phone key does not replace it or change its algorithm.

Four key classes have different owners and phases:

| Key class | Custody and role | Phase |
|---|---|---|
| Dispatcher caller key (Ed25519) | Generated in the orchestrator agent home; registered by that UID against `(uid, generation)`; signs caller requests to the dispatcher (dispatcher §3.3) | Current dispatcher design; not a keeper identity key |
| Broker operator software root (Ed25519) | Protected `swarma-operator` account storage, mode 0600; signs the broker's v0 grants and anchors their verification; no harness runs under this UID | Broker v0 |
| Operator device key (hardware-backed, presence-gated) | Private key remains in the phone's Secure Enclave or StrongBox and is usable only after biometric confirmation; signs canonical operator records, verified against the pinned phone key | Phone-first operator path; operator format publication required (§18.15) |
| Keeper-derived agent identity key | Private key retained inside the keeper, with a root-signed identity certificate and generation-aware identity registration | Architectural target; adapter and activation are later work |

`swarma-operator` holds the operator signing authority and protected operator records for `team/1`, standing retirement, maintenance authority, explicit home retention and standing re-grants. Where a companion spec already names a signed operator record (`team/1`, standing retirement), the operator device key is one admitted signer. An operator act is a signed operator record over its canonical content; its signature domain and canonical bytes are unpublished (§18.15). This record is distinct from the broker's existing `grant/1` and `revocation/1` envelopes. The operator command verifies the phone record before using the account-held authority; no broker wire field or signature-algorithm change is implied. Protected binaries and configuration prevent agent accounts from replacing that command or its pins.

A claim that every agent key stays inside the keeper does not apply to the caller-key or software-root phases. Broker peer identity is still kernel UID plus the active helper generation, not possession of any one of these keys.

A later key keeper (platform architecture §7.2) changes more than the configured root: keeper-derived keys need a root-signed identity certificate, roles need a mapping, old grants need reissue, and revocations must survive. Migration is an explicit procedure: certify or replace keys, map roles, run old and new roots side by side for a transition window, reissue grants and replace bindings under the new root, preserve and reconcile the acknowledged revocation history against evidence outside any restored failure domain (§6.4), then retire the old root. A transition window MUST NOT reopen old authority whose history is unavailable; in that case old roots are invalidated and rights explicitly reissued under replacement roots (§15.4). The broker gains a versioned verification adapter for the keeper's formats; this specification does not promise that the v0 verifier stays unchanged.

For keeper integration, account retirement and identity revocation remain separate operations (D-IDENTITY). The dispatcher may revoke only identities it registered with the one-shot flag, and only after the account is retired. Standing orchestrator/team identities survive account retirement; only the operator revokes them with a signed record. Neither broker unbind nor helper retirement implicitly revokes every identity. This is a future keeper boundary, not a broker v0 identity API.

## 5. Accounts

### 5.1 Record

Figure [M-CB3 — record states](../diagrams/record-states.puml) separates account states from binding, lease and grant validity, including the recovery gaps left unspecified in §9.4.

```
account/1
{ id:           "owner/claude/personal",       // owner-chosen, unique in the broker
  harness:      "claude_code",                // claude_code | codex_cli | muse | gemini | qwen | …
  kind:         "claude-oauth-token",          // §5.2
  owner:        principal reference,           // §4.2
  vendor_account: string | null,               // the vendor's account identifier where one exists (Codex: chatgpt_account_id)
  enrolled_at:  "2026-10-09T10:00:00Z",
  issued_at:    "2026-10-09T09:58:00Z" | null, // only when the owner stated it
  expires_at:   "2027-10-09T09:58:00Z" | null, // computed from issued_at and the kind's lifetime, else null
  network:      { profile_ref, profile_digest, assurance: "cooperative" | "enforced" } | null,   // §5.5
  state:        "active" | "refresh_failed_transient" | "reauth_required" | "owner_unavailable" | "revoked",
  last_refusal: optional { at, code } }
```

The record never contains secret material.

### 5.2 Kinds

| Kind | Material | Refresh | Delivery channels (§8.4) |
|---|---|---|---|
| `claude-oauth-token` | the one-year token printed by `claude setup-token` | none: a new token and a restart | environment `CLAUDE_CODE_OAUTH_TOKEN` |
| `codex-chatgpt` | a Codex ChatGPT login held by the auth owner | the auth owner only (§9) | Codex app-server external tokens only |
| `codex-access-token` | a Business or Enterprise access token | none in the broker (admin-issued) | environment `CODEX_ACCESS_TOKEN`; later, outside the first release |
| `api-key` | a vendor API key (`ANTHROPIC_API_KEY`, `CODEX_API_KEY`, `META_API_KEY`, `GEMINI_API_KEY`, …) | none | environment, or stdin where the harness supports it |
| `muse-account` | reserved: Muse subscription login | to be researched (§10.2) | reserved |

The following table separates **provider, source, channel and phase**. Source-policy v1/v2 are CIP-0010 policy versions, not broker release numbers. A specified channel remains subject to per-harness executor qualification; no row proves implementation or current vendor support.

| Provider | Source | Channel and launch-home boundary | Phase / disposition |
|---|---|---|---|
| All providers | `per-home` native store | Provider-native authentication stays local according to admitted `isolation`; no broker lease implied | Retained lane. Source-policy v1 defaults here when an entry is absent; v2 requires an explicit entry and migrates existing logins to explicit `per-home` |
| Claude subscription | Explicit node or broker account: enrolled `claude-oauth-token` from `setup-token` | `env`: `CLAUDE_CODE_OAUTH_TOKEN` at harness exec; no launch credential file or native fallback; never combined with `--bare` | First protected broker provider launch, slice 0. No refresh: re-enrol and restart on expiry/auth failure |
| Codex personal plan | Explicit node/auth owner or broker `codex-chatgpt` account; one refresher per account | `external-token`: access token + account ID to a private per-session app-server; no launch `auth.json`, shared file or copy; no broker-mode `codex exec` | Broker slice 1, after Claude; named supported-release evidence required. Remaining adoption/qualification decision is open (§18.4) |
| Codex Business/Enterprise | Explicit token node or broker `codex-access-token` | `env`: `CODEX_ACCESS_TOKEN`; no broker refresh or launch `auth.json` | Later lane, excluded from the first release |
| Claude API | Explicit API-key node/helper/broker source | Provider API-key channel (`ANTHROPIC_API_KEY` for env); Claude `apiKeyHelper` is a separate API-key lane, never subscription login export | Retained helper lane; node/broker delivery requires executor qualification; no automatic substitution for the subscription source |
| Codex API | Explicit API-key node/helper/broker source | Provider API-key env (`CODEX_API_KEY`); stdin only where the harness supports it | Explicit API-key lane; qualified delivery only, never fallback from a personal-plan lease |
| Muse API | Explicit API-key node/helper/broker source | `META_API_KEY` env or `exec --api-key-stdin`; no account login in the launch home | Specified API-key lane; actual pass-through/executor admission remains a prerequisite |
| Gemini / agy / qwen API | Explicit API-key node/helper/broker source | Provider API-key env; stdin only where supported; exact channel admitted per harness | Specified API-key lanes; qualification required, no automatic channel substitution |
| Muse subscription | Future owned `muse-account` source | Store, refresh and channel reserved for research | Open: prioritize subscription qualification and choose a channel from evidence, or defer (§18.5). API-key support stays separate |
| Provider proxy injection | Research source / traffic-side injection | No qualified alternate authentication channel defined | Research only; no authentication-equivalence or shipped-route claim (§18.6) |

Source selection is **user-owned**. Node, helper and broker sources require an explicit entry; `isolation` remains the separate native-store sharing axis. An absent entry under source-policy v1 means `per-home`; an unreadable or malformed entry is a failure, not absence and not permission to fall back. Existing homes adopt a new source only through `inspect → plan → apply` with a coordinated marker revision. Explicit token enrolment never authorises native-login copying or export.

CIP-0003 is accepted only in its narrowed CIP-0010 C6 disposition:

| Earlier CIP-0003 clause | Operative disposition |
|---|---|
| `per-home` and defaults | Retained; source-policy v1 default, explicit in v2 |
| `token` with opaque `source_ref` | Node mode with protected binding and executor gates; first store is a 0600 file, not Keychain |
| `helper` | Retained for API keys |
| `shared-file` | Replaced by the node. The legacy Linux linked-file path remains historical with unqualified refresh safety, not an endorsed sharing strategy |
| Configuration precedence, protected-store read order, no fallback, legacy Linux handling and migration | Retained; `credential_source` replaces the earlier `credential_sources` spelling |
| Refuse token/helper for tracked runs until final-executor lookup | Retained as `credential_injection_unavailable`; lifted per executor only after protected-binding and effective-source/child-inheritance qualification |
| Decision 0017 Q4 / Q7 | Q4 keyring-per-home claim remains source inspection pending the live probe; Q7 no-copy remains unchanged, with no stripped-copy option |

The superseded default/Keychain recommendations and “no acceptance decision” wording are historical, not competing defaults. Enterprise-token delivery is outside the first release; provider priority and release-specific preconditions that remain undecided are listed in §18.

### 5.3 Secret store

Figure [M-CB4 — storage layout](../diagrams/storage-layout.puml) distinguishes secret files, metadata, the broker-owned Codex home and the external runtime socket (§12.4, §15).

Material is kept behind a secret-store interface (`put`, `get`, `delete`, `describe`). **v0 ships one backend: a file with mode 0600 in a 0700 directory owned by the broker user**, on macOS and Linux alike, written by atomic replacement in its own directory. Keychain or Secret Service backends MAY be added later; a backend that can prompt a person MUST NOT be used for launches that cannot answer a prompt.

### 5.4 Enrolment

Enrolment is always performed by a person through the vendor's own flow and the operator command as `swarma-operator`, with authentication and exact content confirmation (§14); it is refused from inside an agent session. The vendor browser ceremony alone is not operator authentication:

- **Claude:** the person runs `claude setup-token` and pipes the printed token to `curator broker enrol claude_code --account <id> --token-stdin [--issued-at <date>]`.
- **Codex personal plan:** a ceremony run by the broker under its own user (§9.2): the broker starts the vendor's device login in a fresh broker-owned Codex home and relays the verification address and code to the person's CLI; the person completes the login in a browser. No existing login is imported, no other user's home is adopted, and no keyring item is exported.
- **Business access tokens and API keys:** `--access-token-stdin` or `--api-key-stdin`.

Material travels over the socket once and is written to the secret store. Enrolling a deliberately supplied token is not permission to extract an existing native login, and the broker never reads another user's harness stores.

### 5.5 Network requirement

An account MAY require a network profile: `{ profile_ref, profile_digest, assurance }`, using the identifiers of curator-network-profiles.

- **Cooperative (v0).** The caller composes the launch's network profile with curator-network-profiles. The executor verifies its destination-local network binding from that plan without resolving profiles (§3.1) and passes the resulting record in the lease request. The broker checks `profile_ref` and `profile_digest` against the account's requirement and records the result as **declared**. The record proves only what the requesting process asserted; network profiles in this version set proxy settings that a process can ignore.
- **Enforced (later).** An account that requires `assurance: "enforced"` is refused (`lease_network_enforcement_unavailable`) until swarma-user-manager v1 publishes trusted applied state for the agent's `(uid, generation)`: the profile digest, the proxy listener identity and the firewall generation. The broker then matches leases and renewals against that state, not against the request, and refuses drift.

R-NETBIND: the machine owns the policy binding a child's network profile to its granted Curator profile; the user manager's §8 publishes its protected location and operator lifecycle. The dispatcher pins that policy/digest at admission. `fw.apply` checks that the listener actually serves the policy whose digest was applied, including listener/service-generation binding; broker enforced checks reference that trusted applied state. Policy reload or listener reuse cannot silently broaden existing allocations. The network-profiles/proxy contracts own digest relations and re-apply/session invalidation publication. This adds no grant dimension; v0 remains declared/cooperative only.

### 5.6 One person, one subscription

An account belongs to the person who enrolled it. The broker MUST NOT issue a lease for an account unless the grant chain's root authorises that account (§6). Bounds on concurrent use are not part of v0; grants that state them are refused rather than ignored (§6.2).

## 6. Grants

### 6.1 Format

A grant is an envelope with a body, the body's identifier and a signature:

```
grant envelope
{ body: {
    type:       "grant/1",
    issuer:     "ed25519:<base64url, 32 bytes, unpadded>",
    subject:    "ed25519:<…>"           // a delegating key
              | "agent:<generation>",    // a leaf only: one agent account generation (§6.3)
    actions:    ["credential.lease"],
    accounts:   ["owner/claude/personal"],   // exact account ids
    harnesses:  ["claude_code"],
    profiles:   ["dev", "review"],          // Curator profiles a lease may serve
    not_before: "2026-10-09T10:00:00Z",
    expires_at: "2026-10-10T10:00:00Z",
    depth:      0,                          // remaining delegation depth
    parent:     "sha256:<hex>" | null },
  id:   "sha256:<hex>",
  sig:  "<base64url, 64 bytes, unpadded>" }
```

- The preimage is the domain tag `swarma-credential-broker grant/1` followed by a newline and the CCJ-1 canonical bytes of `body`. `id = "sha256:" + lowercase hex of SHA-256(preimage)`; `sig` is the Ed25519 signature of the issuer over the same preimage. Neither `id` nor `sig` is part of the body, so there is no circular preimage.
- A verifier recomputes `id` from `body` and refuses a mismatch (`grant_id_mismatch`).
- CCJ-1's rejection rules apply: duplicate keys, invalid Unicode, floating-point numbers, integers outside the safe range, negative zero and unknown members refuse (`grant_malformed`). Times are RFC 3339 UTC with a `Z` suffix.
- The repository publishes canonical byte vectors and negative vectors for every rule.

### 6.2 Chain verification

A request carries the full chain as envelopes, leaf first. The broker accepts it only when all of the following hold:

1. The chain is between 1 and 4 envelopes long, contains no repeated id and no record that is not part of the chain (`grant_chain_malformed`).
2. Every envelope is well formed and its signature verifies (`grant_malformed`, `grant_id_mismatch`, `grant_signature_invalid`).
3. For **every** adjacent pair `(child, parent)`, starting with the leaf and its parent: `child.parent == parent.id`; `child.issuer == parent.subject`, which therefore must be a key; and the child narrows the parent (`grant_chain_broken`, `grant_not_narrowing`).
4. The last envelope is the root: `parent` is null and its `issuer` is a configured root key (`grant_root_unknown`).
5. Narrowing means: actions, accounts, harnesses and profiles are subsets of the parent's; `[not_before, expires_at]` lies within the parent's window; `child.depth < parent.depth`.
6. Only the leaf may have an `agent:` subject, and a leaf with an `agent:` subject has `depth: 0` and the single action `credential.lease` (`grant_subject_invalid`). The v0 action vocabulary is `credential.lease` and `agent.spawn`; role subjects, wildcards, other actions and other conditions are not part of v0 and refuse (`grant_unsupported`).
7. A dispatcher's own chain ends at the dispatcher key with depth ≥ 1 and is at most 3 envelopes long, so that an agent leaf fits within the 4-envelope bound; the broker refuses to configure a dispatcher whose chain cannot construct a leaf (`grant_unconstructible`).
8. No envelope, issuer key or subject key is revoked (§6.4), and every window passes R-TIME: expiry is evaluated at `max(now, watermark)`, and `not_before` at `min(now, watermark)` (§15.1) (`grant_revoked`, `grant_expired`, `grant_not_yet_valid`).

The verifier's test suite includes a valid chain and mutants that skip each rule, including one that skips only the leaf edge.

### 6.3 Agent leaves

An agent is named in a grant by its helper account generation, `agent:<generation>`. R-GEN generations are fresh random 128-bit values and never reused, so a grant cannot be reused by a later agent that happens to get the same label, user name or UID. Generation values in examples are illustrative random 128-bit identifiers; their wire encoding remains owned by the user manager, not defined here. Display labels are kept in the binding for people to read and play no part in authorisation.

### 6.4 Revocation

Figures [M-CB2 — lease recovery](../diagrams/lease-recovery.puml) and [M-CB3 — record states](../diagrams/record-states.puml) show the durable publication boundary, refusal after unreadable state and the limits of recovery specified here.

A revocation is an envelope of the same construction with the domain tag `swarma-credential-broker revocation/1`:

```
revocation body
{ type: "revocation/1",
  revokes: { grant: "sha256:<hex>" } | { key: "ed25519:<…>" },
  by:   "ed25519:<…>",
  at:   time,
  reason: optional string }
```

- A grant may be revoked by its issuer, by a root key or by an operator's key. A key may be revoked only by a root key or an operator's key; a revoked key invalidates every envelope it issued and every envelope whose subject it is.
- **Publication.** In v0 the broker keeps one authoritative local revocation state `{ seq, records }`. A revocation is admitted under the broker's state lock, which also serialises lease issuance and renewal: the broker writes the new state to a temporary file, flushes it, renames it over the old one, flushes the directory, updates its memory, and only then acknowledges. Every lease and renewal checks the chain against the state current under the same lock immediately before releasing material.
- **Fail closed.** If the revocation state cannot be read or does not parse, or restoration is fenced, the broker refuses bind, lease issuance and renewal (`revocation_state_unavailable`) until current authority is reconciled; it never starts from an empty set after a failed read. `revocation.check` answers `unavailable` while fenced (§13.2).
- **Local restoration.** A readable, correctly owned old `{ seq, records }` snapshot is not proof of current authority. Supported restoration is an explicit fenced operator procedure (§15.4): close issuance and renewal, disable service auto-start and durably mark the restore before replacing state. The restore mark and start-check evidence MUST survive outside the restored failure domain; a checkpoint inside the service home cannot witness its own rollback. An ordinary restart or an in-snapshot sequence cannot detect restoration of a valid old snapshot.
- **History recovery.** Reconstruct all acknowledged revocations against trustworthy surviving journal/checkpoint evidence outside that failure domain and establish its completeness through the latest acknowledgement. If that evidence is missing, expired, unreadable or incomplete, authorization remains unavailable, or the operator invalidates the old configured roots and explicitly reissues rights from new decisions. Old grants and bindings MUST NOT be automatically repopulated as current authority from the stale snapshot. An optional monotonic witness is usable only if it survives that failure domain and is durable before revocation acknowledgement; its concrete format is unpublished (§18.8).
- **Admission verdict.** Configured dispatchers use `revocation.check` at `prepare`, `dequeue` and `start`. It reads the sole broker-owned current state under the state lock. The dispatcher refuses `revoked` and `unavailable`; a prior `not_revoked` answer cannot replace final bind, lease or renewal checks.
- A revocation stops new leases and renewals. It cannot erase an access token that a harness already holds; that ends with the token's expiry or with revocation at the vendor (§12.1).

### 6.5 Registry

Where grants and revocations live beyond one machine is open: a git journal, a registry service with signed snapshots, carrier room state, or a hybrid with local verified caches. Because chains travel with requests, the choice mainly affects revocation and discovery. Any remote form MUST provide authenticated freshness and rollback protection for revocation snapshots before a broker relies on it. The local restore fence (§6.4, §15.4) already applies in v0; it is not deferred to a registry. No registry service or hardware witness is required by the fenced manual procedure.

### 6.6 Relation to the trust design

curator-trust (capabilities, delegation verification) and waggle (signed envelopes and keys) define the platform's long-term forms. The general architectural `grant/1` language includes roles, actions, targets, conditions, human-presence requirements, delegation ceilings and nondelegable rules. It is **not the broker v0 envelope**, despite the shared `grant/1` body discriminator.

| Contract | Scope and verification |
|---|---|
| General platform grants | Architectural trust language; broader predicates and identity/certificate model owned by curator-trust/waggle |
| Broker v0 envelope | Exact accounts/harnesses/profiles/time windows/depth; only `credential.lease` and `agent.spawn`; key subjects or generation-bound agent leaves; §6.1–§6.4 signatures and revocations |
| Adapter or shared policy layer | Versioned reconciliation before 1.0; must preserve caller binding, narrowing and revocation semantics and explicitly translate or refuse unsupported predicates |

Broker lease grants are not board capabilities. Broker v0 MUST refuse roles, wildcards, human-presence conditions or other unsupported general predicates rather than silently weaken them (§6.2). No adapter is published or implemented here. Where platform forms differ, they take precedence through a versioned adapter or shared policy layer, and the broker format gains a version (§4.3); the v0 verifier is not promised to stay unchanged.

## 7. Bindings

### 7.1 Record

Figure [M-CB3 — record states](../diagrams/record-states.puml) shows binding admission and removal separately from account and lease states.

```
binding/1
{ binding_id:   random 128-bit identifier, never reused,
  uid:          30412,
  generation:   "4a91c5e03b2d4788a649d70fc62e15bd", // illustrative helper generation, §4.2
  label:        "dev-7f3",                // for people; not used for authorisation
  profiles:     ["dev"],
  chain:        [leaf id, …, root id],    // leaf subject = "agent:4a91c5e03b2d4788a649d70fc62e15bd"
  caller:       { chain: [caller leaf id, …, root id],   // the authorization of whoever asked for the agent
                  intersection: { accounts, harnesses, profiles, not_before, expires_at } },
  created_by:   principal reference of the dispatcher,
  request_id:   the dispatcher's bind effect id (receiver idempotency),
  created_at, expires_at,
  state:        "active" | "removed" }
```

The receiver retains the original caller principal, effect `request_id`, operation, canonical-argument digest, intent, outcome and target identity/state as journal evidence for bind and unbind (§7.2). These are semantic journal requirements, not added `binding/1` wire members. Removal retains a tombstone linked to the removed binding's UID/generation and its bind and removal effects, including binding replacement; deleting the active index does not delete that evidence.

### 7.2 Creating and removing

- `bind` MUST come from a dispatcher principal (§4.2) and MUST name a UID whose ledger entry is an active **agent** account of that generation, created by the same dispatcher (or by an operator). The chain MUST verify (§6.2) with leaf subject `agent:<generation>`.
- The `caller.chain` MUST verify separately (§6.2): its leaf subject is the caller's key, it allows `agent.spawn` and `credential.lease`, and the binding's leaf MUST lie within `caller.intersection`, which MUST lie within the caller chain. The two chains are never concatenated.
- **R-REBIND binding replacement.** Dispatcher **E-rebind** re-signs the leaf under the current dispatcher and caller chains and replaces the binding for the same `(uid, generation)` without re-creating the account. Each E-rebind has a distinct effect ID and fresh `revocation.check` with context `prepare`; the broker independently repeats current authority, ledger, time and restore checks before committing. The renewing principal MUST already sit in the chain being renewed; a dispatcher signature alone is not renewal authority. The new leaf is the intersection of the current chains with the originally admitted request: no added accounts, harnesses or profiles. Widening needs a new dispatcher `provision`, not E-rebind. The receiver durably removes the old binding, ends its leases, closes its connections and retains its removal tombstone before publishing a fresh, never-reused `binding_id`. Replacement never has two active bindings for the tuple. A crash between removal and publication leaves no authority until fresh checks and receiver reconciliation resolve the same replacement effect; an uncertain outcome never authorises another replacement. Exact replacement intake, argument binding and transaction ordering would need publication (§18.11); no new broker method or wire member is assigned.
- Renew-ahead requires current authorised chains; an expired chain needs explicit renewal by its authorised principal. A revoked envelope or key is never reissued by a sweep: it needs a new explicit operator decision. A renewed requester delegation identifies the existing allocations it reauthorises, and each replacement retains ancestor authority in its caller chain. Old bind/unbind replays never affect the replacement.
- R-OUTCOME bind/unbind outcome tables in §13.2 govern rejection, unfinished work, terminal replay and transport uncertainty. Bind and unbind effects are serialized with the broker's receiver journal. Pre-admission rejection records no receiver intent; a retry must pass fresh admission. Intent and the caller/effect/argument binding MUST be durable before mutation; outcome and current target state MUST be durably recoverable before acknowledgement. Interrupted admitted work remains `pending` until receiver reconciliation resolves it. A bind or replacement that would create authority must repeat fresh checks before any authority-creating step; pending intent is no permission cache. Unbind continuation only narrows authority (§13.2, R-OUTCOME). No new mutation is authorized by an uncertain outcome.
- A bind with a `request_id` already used by the same dispatcher returns the recorded result and the existing binding's current state if the arguments are equal and refuses otherwise (`bind_request_conflict`). A removed binding is not reactivated by replay.
- An unbind retry retains its original effect ID and canonical arguments. The broker returns its recorded result and current removal state; it never interprets replay as a new effect on a replacement binding. Argument/operation conflicts refuse; their exact unbind error mapping is unpublished (§18.9).
- `unbind` comes from the dispatcher that created the binding or from an operator. It ends the binding's leases and closes the UID's connections. Expired bindings are immediately unusable at `max(now, watermark)`, even if their records are retained. Expiry-driven removal additionally requires trusted time and durable boot-inclusive monotonic elapsed time of at least the binding lifetime from activation (§15.1); a wall-clock jump alone cannot remove a binding. Explicit authorised unbind and replacement do not wait for expiry. Removal retains authoritative tombstone evidence and the recorded result; it does not erase the bind or unbind journal.
- A UID with no active binding receives `lease_unbound` for every lease request.
- `effect.observe` is a read, not a mutation replay or authority renewal (§13.2). Only the original caller principal or an operator may observe the matching effect. Grant expiry does not prevent this read by an otherwise authenticated original principal; an operator resolves evidence when that principal can no longer authenticate (§4.2).
- Journal and tombstone retention MUST cover all admissible retries and reconciliation for those effects. Evidence may be reclaimed only once its identities are permanently inadmissible for mutation; time-based result-cache expiry alone is insufficient. The bounded retention/admission mechanism is unpublished (§18.9) and is required before activation. Missing, expired, partial or unreadable evidence yields `unavailable`, never `not_recorded`; a list miss or removed active record cannot prove absence.

The root caller's `request_id` is correlation for one caller-scoped dispatch request. The broker receives a distinct **bind effect ID** in its `request_id`; create, bind, launch, stop, unbind and retire effects have different IDs and retries reuse the same effect ID. Dispatcher §4.5 owns the derivation: first 32 hexadecimal characters of SHA-256 over `swarma-dispatcher effect/1` followed by CCJ-1 `{caller principal, request_id, record id, component, operation, attempt}` (no added newline). The broker does not equate this key with `binding_id`, account generation, dispatcher `run_id`/`execution_id`, board run/attempt IDs or the correlation-only lease `launch_id`.

### 7.3 Ephemeral agents

For an ephemeral agent, binding `expires_at` bounds task authority; finite credential authority also bounds standing and kept allocations without changing their account lifetime. The dispatcher removes a task's binding when the task ends and before ordinary OS retirement. The broker never implicitly extends an existing binding; R-REBIND supplies a fresh binding under explicit current authority (§7.2). Replacement ends old leases: seamless running continuation is not promised (§8.5).

Unbind stays with the creating dispatcher or a configured operator; the broker admits no helper principal. Direct operator retirement may establish local quiescence while the broker is unavailable or restore-fenced. It leaves unconfirmed binding cleanup as an explicit durable dispatcher/operator obligation; ledger retirement or process death is not a broker unbind receipt. Later reconciliation uses the original unbind effect and retained evidence. Retiring generations cannot lease or renew (§7.4), and recycled UIDs inherit no authority.

### 7.4 Account reuse

UIDs are recycled when OS accounts are deleted, and labels can repeat. Neither carries authority: bindings, grants and leases are keyed by the generation, and every lease and renewal re-reads the ledger (§4.2). A generation that the ledger shows as retiring or removed is refused (`principal_ledger_mismatch`).

## 8. Leases

### 8.1 Request

```
lease.request/1
{ harness:   "claude_code",
  profile:   "dev",                       // the Curator profile of the launch
  account:   "owner/claude/personal",      // the account the user-owned configuration names
  channel:   "env" | "stdin" | "external-token",
  credential_binding: {                   // CIP-0010 C3.4, resolved by the executor before exec
    digest, harness, profile, account, channel,
    endpoint, executable_sha256, policy_generation },
  network:   { profile_ref, profile_digest, assurance } | null,
  launch_id: string,                      // correlation only (plan digest or run id)
  executor:  { capabilities: ["credential-injection/1"], version } }
```

### 8.2 Checks, in order

1. The peer is the agent principal of an active binding whose `expires_at` has not been reached at `max(now, watermark)` (§7.2, §15.1) (`lease_unbound`, `principal_ledger_mismatch`).
2. The binding's chain **and** its caller chain verify now against the current revocation state (§6.2, §6.4); a revoked envelope or key in either refuses (`lease_grant_revoked`, `lease_caller_revoked`).
3. The leaf covers `credential.lease` on the account, the harness and the profile, and the profile is one of the binding's profiles (`lease_not_authorised`).
4. The account exists, its harness equals the requested harness, it is `active`, and any known account expiry has not been reached at `max(now, watermark)` (`lease_account_unknown`, `lease_harness_mismatch`, `lease_account_revoked`, `lease_reauth_required`, `lease_owner_unavailable`).
5. The channel is valid for the kind (`lease_channel_unsupported`), and the harness release is qualified for this kind and channel (`lease_harness_unqualified`).
6. The credential binding's fields equal the request's, its endpoint is one the broker's configuration approves for the kind, and its executable digest is on the broker's approved list for the harness (`lease_binding_mismatch`).
7. The account's network requirement is met as described in §5.5 (`lease_network_mismatch`, `lease_network_enforcement_unavailable`).

Binding/time validity and checks 2 to 7 run under the state lock immediately before the material is released. The restore fence is checked under that lock before any material release, including after an asynchronous refresh. Bind independently checks current revocations and the restore fence under the same lock (§6.4, §7.2); a dispatcher verdict cannot waive these checks.

### 8.3 Response and lease record

Figure [M-CB3 — record states](../diagrams/record-states.puml) lists every lease state without inventing transition or persistence-order rules absent from this section.

```
lease/1
{ lease_id,
  account, harness, channel,
  payload: { channel: "env", variable: "CLAUDE_CODE_OAUTH_TOKEN", value }
         | { channel: "stdin", value }
         | { channel: "external-token", access_token, chatgpt_account_id, plan_type? },
  token_expires_at: time | null,        // the vendor token's expiry when known
  authorized_until: time,               // the broker's own limit: earliest of grant, binding and account expiry
  renewable: bool }
```

The payload appears only in this response and in renewal responses, never in logs. The broker persists the lease without material:

`(lease_id, uid, generation, binding_id, account, harness, profile, channel, credential_binding digest, launch_id, policy generation, authorized_until, state: active | released | expired | revoked)`.

R-TIME checks `authorized_until`, binding expiry, known account expiry and every chain expiry at `max(now, watermark)`; `not_before` uses `min(now, watermark)` (§6.2, §15.1). Untrusted time refuses issuance and renewal; watermark durability precedes release. R-REBIND does not rewrite a lease's `binding_id` or `authorized_until`: all leases of the old binding end, and a fresh lease needs current admission.

### 8.4 Delivery channels

The client library delivers material only into the process the executor starts:

- `env`: the variable is set in the harness process environment at exec, never in the parent, argv, files or logs.
- `stdin`: for harnesses that read a key from stdin.
- `external-token`: for a Codex app-server in external-token mode (§9.3).

Conflicting sources are refused, never replaced (§12.2). There is no channel that writes a credential file for a launch.

The launch-time lease lifetime and remaining cleanup questions differ by channel (§8.5, §18.7).

### 8.5 Renewal, release and reports

Figure [M-CB2 — lease recovery](../diagrams/lease-recovery.puml) covers admission refusals, reconnecting, current-authority renewal and Codex failure branches (§9.3–§9.4). The main paths remain in [lease-at-launch](../diagrams/lease-at-launch.puml) and [codex-renewal](../diagrams/codex-renewal.puml).

- `lease.renew`, `lease.release` and `event.report` name a `lease_id` and are accepted only from the lease's own `(uid, generation, binding_id)` (`lease_not_owner`).
- Renewal is refused when `max(now, watermark)` reaches `authorized_until` or once the lease is released, expired or revoked. It repeats checks 1 to 7, including the caller chain, before releasing new material, including after an asynchronous refresh (§9).
- Release is idempotent and ends renewal.
- A report affects only the reporting lease's record. A client report never changes an account's state; account states change by the owner's command or by the auth owner's own refresh results (§9.4).
- Binding replacement ends every old-binding lease; reconnecting under the new binding cannot renew an old lease. A fenced fresh-lease handoff for a qualified live holder would need publication and qualification (§18.11). Until then continuity requires explicit park and restart that keeps the account; neither env executions nor app-server renewal have a seamless continuation promise. Already copied env tokens keep only their vendor lifetime (§12.1).
- Leases are not tied to connections; a disconnected executor can renew from a new connection of the same principal.

Successful `exec` replaces the executor with the harness; it does not return when the harness exits. Broker connections are close-on-exec (§4.1), and closing them is not `lease.release`. The env-channel harness does not talk to the broker. No executor broker client remains to renew, report or release after successful `exec`.

| Launch channel | Lease holder and end of broker authority |
|---|---|
| `env` | The executor receives the payload before `exec` and then ceases to exist as a broker client. Renewal is refused when `max(now, watermark)` reaches `authorized_until`; revocation stops new leases and renewals (§6.4), and unbind ends the binding's leases (§7.2). No release on harness exit is specified. Whether to release before exec or retain the record until the authorization limit is open (§18.7). |
| `stdin` | Delivery of a key through stdin alone does not specify whether the executor survives as a client. A surviving holder of the same lease principal can release under this section; a replaced executor cannot. The process model and release point are unpublished (§18.7). The authorization limit, revocation and unbind rules still apply. |
| `external-token` | The live agent-side executor or later session runner starts a private app-server and remains its client for renewal (§3.1, §9.3); it does not exec-replace itself with that server. This holder can call `lease.release` when ending its execution, as the lease's own principal. Exact teardown timing and failure cleanup are unpublished (§18.7). Without release, renewal is still bounded by `authorized_until`, revocation and unbind. |

These are broker-authority limits, not a promise to erase a delivered credential or stop the harness: a copied token remains usable until token expiry or vendor revocation (§12.1). The precise automatic transition to the persisted `expired` or `revoked` states, scheduling and cleanup are not specified by §8.3–§8.5. Reaching `authorized_until` does not establish a process-exit cleanup mechanism.

## 9. Codex auth owner

### 9.1 Why

A Codex ChatGPT login rotates its refresh token on every refresh. Several processes refreshing one login race and can log the subscription out. One component per account must refresh.

### 9.2 Enrolment ceremony

1. A person requests `curator broker enrol codex_cli --account <id>` through the operator command as `swarma-operator`, after authentication and exact content confirmation (§14), outside any agent session.
2. The broker creates a fresh Codex home for the account inside its own store, configured for file credential storage, and runs the approved Codex executable (pinned path and digest) with a sanitised environment to start the vendor's device login. Under the v1 service profile, the broker explicitly supplies proxy variables to the vendor executable and its network-using children; inheritance is not assumed. Login, policy-fetch and refresh routes need separate approved endpoint-set, proxy-use and no-direct-fallback qualification (§15.2). The `credential_binding` endpoint list does not establish authentication endpoints.
3. The broker relays the verification address and code to the person's CLI. The person completes the login in a browser.
4. The broker reads the vendor account identifier from the new login and refuses if another broker account already maps to it (`account_duplicate`).
5. The auth owner starts and the account becomes `active`.

The broker never adopts an existing home, imports another login or exports a keyring item.

### 9.3 External-token mode

- The agent-side executor starts a private `codex app-server` for this execution, remains alive as its client and lease holder (§8.5), initialises it with the experimental capability that external-token login requires, and logs in with `account/login/start { type: "chatgptAuthTokens", accessToken, chatgptAccountId }` from the lease payload. A failed initialisation refuses the launch (`external_token_init_failed`); lease cleanup after this refusal is open (§18.7).
- When the app-server receives a 401 it asks its client with `account/chatgptAuthTokens/refresh`. The executor calls `lease.renew { lease_id, rejected_sha256 }`, verifies that the renewed payload names the same `chatgpt_account_id`, and answers with the new token and account id.
- The app-server waits only a bounded time for that answer (about ten seconds in the vendor's documentation at the time of writing). The broker answers `lease.renew` within a configured deadline below that bound (default 8 seconds) or returns `renew_timeout`; the executor then answers the app-server with an error and the turn fails. No late or uncorrelated answer is sent, and nothing falls back to another login. Proactive refresh (§9.4) makes a 401-triggered refresh rare; it does not guarantee that every turn continues.
- The launch home contains no `auth.json`; `cli_auth_credentials_store = ephemeral` is pinned. Broker-mode `codex exec`, shared-file logins and stripped copies are not delivery paths.

### 9.4 Refresh and states

Figures [M-CB2 — lease recovery](../diagrams/lease-recovery.puml) and [M-CB3 — record states](../diagrams/record-states.puml) distinguish transient refresh failure, rejected refresh tokens and a stopped owner; unspecified recovery transitions remain visible notes.

- **Single writer across replacement.** At most one live vendor refresh writer may exist for an account, including after daemon death. The auth owner holds a stable lock beside the Codex home through read, refresh and reload; the vendor does not honour it. Before launch, the broker MUST durably persist account-scoped attempt intent; it MUST retain qualified attempt/process identity evidence across launch and recovery. Intent proves an attempt was planned, not that an external rotation committed or failed. Record layout and platform process identity remain unpublished (§18.10).
- **Contained lifecycle.** The approved executable runs inside qualified service-manager containment on both platforms (§15.2–§15.3). Daemon death or replacement MUST close refresh admission, contain and stop the previous writer, and confirm its complete process absence through the service manager. Reacquiring the daemon's released lock, a reusable PID, a timeout or a missing process read is not proof of absence. No replacement refresh may start until the previous writer's lifecycle is resolved; no extra guardian service is introduced.
- **Resolve before retry.** Recover the previous attempt and reload the durable vendor home before deciding whether another refresh is safe. Confirmed child absence alone does not prove an external rotation failed. A crash after vendor rotation but before local store/result persistence is ambiguous: no blind retry. Unknown writer, store or prior-outcome evidence keeps the account unavailable (`owner_unavailable`), or requires re-enrolment (`reauth_required`) after writer absence is confirmed. Re-enrolment MUST NOT run concurrently with an unresolved previous writer.
- **Time and proxy dependencies.** Refresh scheduling uses the R-TIME confidence policy and watermarked expiry (§15.1); scheduling never extends grant, binding, lease or vendor-token authority. An untrusted clock holds new leases/renewals; refresh scheduling cannot certify token validity; final material release repeats the time checks after refresh. In v1 the proxy is a refresh dependency: conclusively safe proxy/network failure sets `refresh_failed_transient` with backoff only under the prior-writer/outcome rules. Proxy outage never permits direct fallback; an ambiguous rotation remains unresolved, not a safe transient retry.
- **R-FATE.** The user manager's §7 owns the per-process-class **fate table**, next to R-FD3: broker daemon and vendor enrolment/refresh writers reference its stop, crash and replacement containment and old-writer fence. Those rows must be qualified per platform; a process tree or service default is not evidence (§15.2).
- When the current access token expires within the refresh window (48 hours in the reference implementation), the owner refreshes by running the approved Codex executable once; it never reimplements the vendor's token exchange. Requests queue for the owner with a bound; a full queue returns `renew_timeout`. The lifecycle gate above applies to proactive and request-triggered refresh alike.
- `lease.renew { rejected_sha256 }` refreshes only if the rejected token is still the current one; N launches rejected with the same token cause one refresh. Durable attempt recovery also prevents replacement contention from producing another writer.
- States: a conclusively transient failure (network, vendor error) sets `refresh_failed_transient` and permits backoff retry while the token is valid only after the previous writer is resolved and evidence establishes retry safety. A timeout alone cannot establish that no rotation occurred. A rejected refresh token sets `reauth_required`; a stopped or unresolved owner sets `owner_unavailable`; leases are refused. Re-enrolment follows the writer-absence gate. The refresh token never leaves the broker store; there is no fallback to a harness login.

### 9.5 Other consumers

Every consumer of an enrolled Codex account on the machine uses the broker and the same account-scoped lifecycle gate, including maintenance, daemon replacement and re-enrolment. No alternate local consumer may bypass unresolved attempt evidence or start another writer. A person who also runs Codex by hand with the same vendor account on the same machine is outside the owner's guarantee; `status` reports the account's single-owner rule. Using one vendor account on several machines needs a separate ownership design and is not supported.

### 9.6 Qualification

The mechanism is measured in relux-works/remote-worker-harness (`internal/authowner`: eight concurrent callers near expiry cause one refresh; five rejected tenants cause one renewal) and was live-accepted on Codex 0.155.1 in that historical reference. These are pinned historical observations, not fresh qualification by this specification. Codex 0.158 added a fetch of an application network policy; the reference tests run only on 0.155.x. A Codex release is qualified only when the real login, policy fetch, 401 renewal, renewal failure, owner contention and slow renewal pass with the approved executable and configuration; a skipped test is not a pass. Until then the broker refuses `codex-chatgpt` leases for that release (`lease_harness_unqualified`). Historical 0.155.x evidence does not settle the remaining CIP-0010 personal-plan adoption precondition (§18.4), nor qualify single-writer recovery across daemon replacement. Slice 1 MUST stay inactive until the following rows pass on each supported platform with the selected service-manager containment and approved vendor release. These are required qualification cases, not executed results.

| Qualification case | Required evidence / refusal |
|---|---|
| Daemon death during refresh; vendor child survives | Replacement remains closed; service manager contains, kills and confirms absence of the prior writer before any replacement refresh |
| Concurrent replacement and rejected-token callers | Durable attempt identity and account gate yield at most one live refresh writer, including descendants |
| External rotation succeeds before store/result persistence; daemon crashes | Child absence does not trigger retry; unresolved outcome/store keeps account unavailable or requires re-enrolment after absence confirmation |
| Interrupted cleanup or restart after kill but before confirmation | Replacement refresh remains closed until lifecycle, attempt and durable vendor-home evidence are reconciled |
| Process identity/absence read fails, is partial or contradictory | Unknown is not absence; account unavailable, no new writer |
| Vendor-home/store or prior-outcome evidence missing, unreadable or rolled back | No stale-token success or blind retry; account unavailable or re-enrolment after writer absence |
| Confirmed safe transient failure and durable reload | Backoff may retry only after prior writer resolution and evidence that no ambiguous rotation remains |

## 10. Other harnesses

### 10.1 Claude Code

A `claude-oauth-token` has no refresh. A surviving agent-side client can report a harness authentication failure on its lease (`credential_error`, §11). The env launch's exec-replaced executor cannot report after exec (§8.5); that path has no specified live reporter (§18.7). The account moves to `reauth_required` only on the owner's command. Recovery is re-enrolment and a restart; Claude Code resumes its transcript with `--resume`. Vendor-side revocation happens only in the vendor's web interface.

### 10.2 Muse

A Muse subscription login is required, not only API keys. Its store, refresh behaviour and concurrency are researched in parallel with the first slices; if it rotates like Codex, it gets an auth owner of its own. Until then only the `api-key` lane with `META_API_KEY` or `exec --api-key-stdin` is specified for Muse, subject to executor qualification. Subscription channel and priority remain open (§18.5).

## 11. Events

| Event | When | v0 surface |
|---|---|---|
| `lease_expiring` | a token with a known expiry expires within 5 minutes, or a Claude token with a stated issue date within 3 days | `status`, audit log |
| `lease_expired` | the expiry passed | same |
| `credential_error { class: auth \| permission \| quota \| unknown }` | an executor reports a harness failure on its own lease; `unknown` when a 401 or 403 cannot be told apart | same |
| `reauth_required` | the owner marked the account, or the auth owner's refresh was rejected | same |

Events carry typed metadata only. Later versions deliver them to the session host and the message bridge, so that a session is parked and a person is asked to re-enrol from their phone.

## 12. Security

### 12.1 What a compromised agent can do

It can read the credential leased to it and copy it within its OS account; this trusted-process posture is a scoped, owner-approved departure from the stronger secret-free agent model of curator-trust. It cannot obtain accounts outside its grants, cannot bind itself, cannot forge its UID, cannot read the broker's store, and cannot refresh a Codex account. A revocation stops new leases and renewals; a token already copied lives until it expires or is revoked at the vendor. Stronger non-extraction (injection at an egress proxy, or a credential the process cannot read) is a separate design.

Operator custody is a slice-0 boundary: no harness session runs as `swarma-operator`, and agent accounts cannot read its mode-0600 root or replace its protected command/configuration. Widening authority requires the authenticated, content-confirmed operator path (§14), which refuses widening from an agent session. The phone key remains hardware-backed and presence-gated; terminal fallback cannot reuse a cached sudo ticket. `swarma-observer` reads confer no mutation or secret access. These are required design boundaries, not measured isolation claims.

Because a compromised agent can encode a copied token in arbitrary content, names or links, token scanning and path declarations cannot prove its home secret-free. Ordinary retirement quiesces the generation, performs declared-key cleanup and deletes the home (owner decision 2026-10-12); only service-generated metadata in a closed schema without agent-controlled strings, names, links or bodies may be exported. Keeping a home requires a separate explicit operator operation stating that confidentiality is not guaranteed, with authentication and exact content confirmation through `swarma-operator`; the operator CLI refuses it from inside an agent session (§14). Code/results follow their separate git/acceptance policy; git does not establish secret absence. The user manager owns this retirement procedure, not the broker.

### 12.2 Protected binding and conflicting sources

Broker mode implements CIP-0010's protected credential binding (`credential_binding/1`). The executor, running under the agent's account before exec, verifies the caller-composed plan and resolves the protected tuple destination-locally without composing or resolving profiles (§3.1): peer identity, profile, harness, account, channel, vendor endpoint, approved executable digest and policy generation. It checks the tuple before requesting the lease and again immediately before exec, and refuses on any change.

The required plan extension `works.relux.curator.credential/1` carries metadata only, never material. `credential-injection/1` is an admission gate, not authority supplied by an executor claim: the protected binding, current grant chains and qualified executable must all match. Destination binding checks do not grant new source-selection authority to the agent. An unqualified executor refuses `credential_injection_unavailable`.

The executor MUST refuse to exec when the inherited environment, a harness settings or configuration file the launch would read, a native credential store selector, or a configured helper already supplies a credential for the same harness (`credential_source_conflict`). It never replaces a conflicting source silently.

Enrolment time is not token issue time: when `issued_at` is absent, `expires_at: null` means unknown (§5.1); status MUST preserve that uncertainty and cannot emit expiry events from an invented mint date. Errors keep the typed `unknown` class when auth, permission and quota failures cannot be distinguished (§11).

Only an executor whose harness tuple has been qualified to keep the credential out of child processes it does not control (MCP servers, hooks, tool subprocesses), and to use the leased source as the effective source, may declare `credential-injection/1`. A clean environment at exec does not by itself control what a harness passes to its children, so this is part of each harness release's qualification.

The broker's binding check (§8.2 step 6) keeps configuration consistent; it is not a boundary against a compromised agent, which can already read and encode copies of its own lease (§12.1). It cannot establish secret absence in a retirement export or justify arbitrary-home archival.

### 12.3 The broker itself

The broker holds every enrolled credential, so it stays minimal: one service user, no network listener, no plugins, no shell-outs except the approved Codex executable for enrolment and refresh, an append-only audit log, and rate limits per principal. R-SVC-EGRESS permits network only through the dedicated proxy listener (§3, §15.2); allowed vendor destinations may still carry data, so the allowlist reduces uncontrolled egress without proving store non-exfiltration. Resolver-mediated paths require their own qualification, since per-UID packet rules alone do not constrain a privileged resolver. The audit log records who, which account, which launch and which outcome as typed metadata; it never records material, raw protocol frames, secret-bearing errors or token hashes.

### 12.4 Files

Figure [M-CB4 — storage layout](../diagrams/storage-layout.puml) shows ownership, modes, atomic state replacement and the append-only audit boundary (§12.3).

All broker files are owned by the broker user; directories are 0700. Every state file (configuration, accounts, grants, revocations, leases) is replaced atomically within its own directory. The broker refuses to start if its store or configuration, or any parent directory, is writable by another user. Durable receiver intent, results and removal tombstones (§7) and refresh attempt evidence (§9.4) obey the same protected storage boundary; their concrete layouts remain unpublished. Atomic replacement and readable ownership do not establish freshness after restore. The restore mark and surviving reconciliation evidence MUST be outside the restored failure domain (§6.4, §15.4), not another file rolled back with this home. No new v0 namespace field is introduced.

## 13. Socket protocol `broker/1`

### 13.1 Transport

A Unix-domain stream socket. Frames are a 4-byte big-endian length followed by a CCJ-1 canonical JSON object; the broker rejects frames over 64 KiB before reading them. The first exchange is `hello { versions: [1] }`; an unknown version closes the connection. Each request carries a client-chosen `request_id`; every response echoes it. Requests have deadlines: 2 seconds for administrative reads, 8 seconds for `lease.renew` (§9.3), 30 seconds for lease requests that wait for the auth owner.

**R-LOCK:** never hold its state lock across a synchronous call to another platform service. Ownership is tracked by a per-record in-flight marker: fix intent/arguments and record ownership under the lock, release it for bounded I/O, then revalidate record versions, restore/time fences and daemon-instance ownership under the lock before recording the result or releasing material. Late stale results may resolve history but never reopen admission or delivery. Per-record ownership serializes work; unrelated records and diagnostic reads remain available. Singleton and account writer-ownership locks retain their separate lifecycle; this rule does not weaken §9.4.

The broker's wait/lock graph is:

| Held lock / marker | Wait or call | Rule |
|---|---|---|
| Broker state-transition lock | Local journal, revocation, binding and lease transitions; final material-release checks | No synchronous platform-service call |
| Per-record in-flight marker, state lock released | Service-manager containment, stop/absence or qualified vendor launch; proxy-dependent vendor I/O | Bounded I/O; reacquire state lock and revalidate before delivery |
| Account refresh ownership lock, state lock released | Vendor read/refresh/reload and lifecycle resolution | Preserves one writer; No state-lock holder waits for this ownership lock; no cross-account ownership wait |
| Broker state-transition lock | Direct root-owned ledger file read | Local file access, not a user-manager RPC; failure refuses |

No wait edge carries the broker state-transition lock into the user manager, dispatcher, session host, service manager or proxy. The dispatcher → broker administrative call does not trigger a callback into a waiting dispatcher. This graph and the shared R-LOCK graphs must remain acyclic; concrete concurrency bounds, marker/fence encoding and platform mechanisms would need publication (§18.13).

### 13.2 Methods

| Method | Accepted from | Purpose |
|---|---|---|
| `hello` | any authenticated peer | version negotiation; returns the peer's principal |
| `account.enrol`, `account.describe`, `account.revoke`, `account.mark` | the account's owner | §5, §9.2 |
| `account.list` | owners (their own), operators, `swarma-observer` | §5 |
| `grant.put`, `revocation.put` | operators through the operator command, and key holders for records they signed | §6; operator authentication/confirmation rules in §14 |
| `grant.list` | operators, `swarma-observer`, and key holders for records they signed | §6 |
| `bind` | configured dispatchers | §7, including authorised binding replacement |
| `unbind` | creating dispatcher, operators | §7; no helper principal |
| `binding.list` | dispatchers (their own), operators, `swarma-observer` | §7 |
| `effect.observe` | original effect caller principal, operators | read bind/unbind effect evidence and current target state (§7, below) |
| `revocation.check` | configured dispatchers | point-in-time revocation verdict for exact chains and context (§6.4, below) |
| `lease.request` | the agent principal of an active binding | §8 |
| `lease.renew`, `lease.release`, `event.report` | the lease's own principal and binding | §8.5 |
| `status` | owners (their accounts), operators, `swarma-observer` | accounts, owners, leases, events |

**Operator admission (R-OPERATOR).** Every operator-only method and every use of the owner role reaches the broker through the operator command running as `swarma-operator`, after a phone-signed or terminal-authenticated act (§14). A bare interactive UID or knowledge of the operator UID is not an admitted path; direct operator-UID calls such as `account.enrol` and `unbind` are confined to that command boundary even where the broker method requires no root signature. `swarma-observer` may read `status`, `account.list`, `grant.list` and `binding.list` without authentication prompts or content confirmation, but may not mutate state, lease material, or acquire an owner/operator role. These are broker-wide metadata reads; no secret-store or private operator-storage access is granted. Existing dispatcher methods, original-caller observations and valid signed key-holder submissions retain their bounded authority and do not become operator acts.

**`revocation.check` (R-VERDICT).** Takes the exact chain or chains being checked and check context `prepare`, `dequeue` or `start`. Only a configured dispatcher authenticated under §4.1–§4.2 may call it; this does not grant operator status or private-directory access. Under the broker state lock, it answers exactly `not_revoked`, `revoked` or `unavailable`, together with the broker's revocation sequence at that check's publication point. `not_revoked` requires a complete current read; unavailable, stale or restoring evidence yields `unavailable`. While restore is fenced, it always answers `unavailable`; no fresh sequence may be claimed from unreadable or untrusted restored state. Representation of an unavailable sequence is unpublished (§18.8). The answer is tied to those exact inputs and is point-in-time evidence, never a grant, transferable authority or permit for a future start. The dispatcher still authenticates callers, verifies signatures/chains and applies spawn/quota/capacity policy; it refuses `revoked` and `unavailable` and rechecks at each declared admission point. Final broker bind, lease and renewal checks remain mandatory.

**`effect.observe` (R-OBS).** Takes the original effect's `request_id` (the effect ID), operation (`bind` or `unbind`) and digest of its canonical arguments. The broker authenticates the original caller principal or an operator, checks the full input binding and serializes this read with its receiver journal. It performs no mutation and requires no fresh mutation grant for observation. A conflicting input cannot disclose another effect's result; exact refusal mapping and wire encoding remain unpublished (§18.9). It answers exactly one of these states:

| Observation state | Meaning | Dispatcher observation class |
|---|---|---|
| `recorded` | Recorded result plus current target state, including binding identity/generation and current removal state | present or absent according to that current state |
| `pending` | Durable intent exists; outcome remains unresolved | unknown |
| `rolled_back` | Authoritative receiver evidence proves this attempt was rolled back | known absent for this effect only |
| `not_recorded` | Complete authoritative evidence proves the effect was never recorded | known absent for this effect only |
| `unavailable` | Evidence missing, expired, partial or unreadable; never absence | unknown |
| `contradictory` | Receiver evidence conflicts | contradictory |

**R-OUTCOME: bind outcomes** (including R-REBIND binding replacement). These are semantic outcome classes mapped to R-OBS, not new wire states or refusal codes.

| Receiver outcome | R-OBS state | Replay / admission rule |
|---|---|---|
| Pre-admission rejection; no durable intent | `not_recorded` only if complete authoritative evidence proves it; otherwise `unavailable` | Retry is fresh admission with current principal, chain, expiry, revocation and restore checks; a refusal is not admitted work |
| Durable admitted intent; result unresolved | `pending` | Reconcile same effect and immutable arguments; repeat fresh checks before creating authority; never promote uncertainty into another bind |
| Terminal bind result, including later removal/replacement | `recorded` | Replay result plus current target state; removed binding never reactivates |
| Proven rollback of this attempt | `rolled_back` | No automatic replacement; fresh authority needed for new bind |
| Transport timeout/lost reply; evidence missing, partial, expired or unreadable | `unavailable` when observation cannot resolve it | Caller uncertainty is unknown, never inferred `pending`; observe authoritative receiver evidence first |
| Conflicting receiver evidence | `contradictory` | Hold and reconcile; no new authority |

**R-OUTCOME: unbind outcomes.**

| Receiver outcome | R-OBS state | Replay / continuation rule |
|---|---|---|
| Pre-admission rejection; no durable intent | `not_recorded` only with complete authoritative proof; otherwise `unavailable` | Fresh authenticated admission; no helper role or implied removal |
| Durable admitted intent; forward removal unfinished | `pending` | Continue original effect with identical canonical arguments; only narrows authority, never targets a replacement binding |
| Terminal removal and retained tombstone/result | `recorded` | Replay result and current removal state; no further effect on a new binding |
| Proven rollback of this attempt | `rolled_back` | Proves only this attempt's rollback, not present binding absence |
| Transport uncertainty or missing/expired/partial/unreadable evidence | `unavailable` when observation cannot resolve it | Unknown, not inferred pending or absence; reconcile original effect |
| Conflicting receiver evidence | `contradictory` | Hold and reconcile; do not claim cleanup |

An authenticated original principal whose grant lapsed may continue its own admitted unbind, never use that lapse exception for bind or replacement. Every continuation keeps its original operation and full canonical arguments; changed arguments remain a conflict. The receiver owns classification; the dispatcher handles unfinished admitted work as pending, not terminal refusal. Pre-admission failures and terminal replay never become fresh pending mutations merely because a caller retries (§7.2). No additional response fields are specified.

`rolled_back` and `not_recorded` never authorize automatic new creation. Unbind observes its own recorded result and retained removal tombstone; bind observation reports the target's current removed state even if bind succeeded earlier. A partial list, refused read, timeout or cache miss cannot establish `not_recorded`. Retention and loss rules are in §7.2. These method descriptions freeze names and semantics, not additional wire members, signature domains or error values (§18.8–§18.9).

Every refusal is a typed error `{ code, message, details }`; codes are listed in Appendix A. Errors never contain material.

## 14. Command line

The standalone binary is **`swarma-credential-broker <verb>`**; through Curator's provider mechanism the same operations are available as `curator broker <verb>`. Repository, binary and service-account naming agree. `curator-broker` was the earlier design spelling, not a shipped compatibility alias. Nothing has shipped, so no CLI or signed-data migration is required.

D-WIRE-NAMES explicitly replaces the earlier signing domains with `swarma-credential-broker grant/1` and `swarma-credential-broker revocation/1` (§6.1, §6.4). This is the owner-approved pre-release wire decision, separate from CLI naming. The peer-authenticated `broker/1` transport defines no broker request-signature domain (§13).

**Phone-first path.** The phone app reaches the machine by SSH over the tailnet into `swarma-operator`, using only the pinned operator device key. SSH provides no shell: a forced, narrow **operator command** accepts operator acts only. The app shows each act's exact content (who, which actions, until when), then biometric confirmation enables signing on the phone. The machine verifies the signature against the pinned phone key and binds it to that one act's canonical content; it cannot be reused for another act. Revocation takes a single biometric confirmation, with no additional content-confirmation step. SSH login alone never authorizes an unsigned operator act.

**Terminal fallback.** From a computer, the person uses password-authenticated `sudo` into `swarma-operator` to invoke the operator command. Every act requires authentication: no `NOPASSWD`, and `timestamp_timeout=0` prevents cached-ticket reuse. The terminal fallback works without the phone; no additional hardware or signature-algorithm change is required. It grants no general operator shell or harness entry.

**Act confirmation.** Widening acts require authentication plus confirmation of exact content: grant issue, subscription enrolment, `team/1`, standing retirement or re-creation, explicit home retention, maintenance stop authority and renewal of standing grants. The operator CLI MUST refuse these from inside an agent session on either path. Narrowing acts (revocation, disabling an account and unbind) require authentication only. Automatic narrowing and service acts already admitted under existing authority remain available without a person; automatic re-grants may only be bounded, non-widening and explicitly pre-authorised within a published existing delegation. There is no inferred infinite renewal or maintenance authority. Classification and confirmation for other explicit operator procedures, including time reset and restore/reopen, would need publication (§18.15).

**Read-only path.** `curator broker accounts`, `bindings`, `status` and the `grant.list` read use `swarma-observer` with no confirmation or password prompt. The observer cannot perform operator acts. Its entry-point spelling and the operator command's binary name, wire format, signed-record domain and canonical bytes are unpublished (§18.15); the front-end examples below do not define that mapping or bypass it. The phone record authorizes the act; existing broker Ed25519 grant/revocation envelopes retain their own signing domains (§4.3).

Front-end examples (mutations through the operator command; reads through `swarma-observer`):

```
curator broker enrol claude_code --account owner/claude/personal --token-stdin [--issued-at 2026-10-09]
curator broker enrol codex_cli   --account owner/codex/personal
curator broker accounts
curator broker grant --to-key <dispatcher key> --account owner/claude/personal --profile dev --harness claude_code --depth 1 --until 2026-10-10T00:00Z
curator broker revoke <grant id | key>
curator broker bindings
curator broker status
```

Agent leaves (`agent:<generation>`) are issued by the dispatcher when it binds an agent (CIP-0011).

## 15. Installation and lifecycle

### 15.1 Service user and time

The broker runs as the dedicated unprivileged service user `swarma-credential-broker`, created by swarma-user-manager (`user.create { kind: "service" }` from the installer principal); its home is `/opt/swarma/services/swarma-credential-broker`. The platform installer installs the binary, the service user and the service unit together.

**Operator and observer installation (R-OPERATOR).** Installation MUST create the separate `swarma-operator` and `swarma-observer` accounts under the service naming rule and pin their principals (§4.2); neither may host harness sessions. `swarma-operator` is the configured broker operator, every account's owner and the user manager's `operator` UID. Protect its mode-0600 v0 root and operator records, the operator command binaries/configuration and the phone-key pin from agent accounts. The installer configures SSH over the tailnet into `swarma-operator` using only the pinned phone key and a forced narrow operator command, with no shell. It installs password-authenticated terminal sudo rules into that account with `timestamp_timeout=0`, no cached tickets and no `NOPASSWD` for operator acts, including the helper's operator role. `NOPASSWD` stays only for the dispatcher service account's helper and launcher rules; the dispatcher itself has no caller sudo entry. Install the mandatory observer's confirmation-free read path without granting mutation or secret access. Concrete account provisioning, command confinement and phone-key pin storage would need publication (§18.15). Phone-key enrolment, rotation and loss remain open there, with terminal re-enrolment under this fallback as the proposal.

**R-TIME installation and confidence.** The installer MUST require an authenticated or operator-controlled time source (for example NTS). One platform time-confidence policy is reused by every service; tolerances and concrete source/start integration would need publication (§18.12). Detect-and-hold and time-confidence validation precede authority evaluation and watermark advancement. Compare wall and monotonic deltas only within one boot epoch; this cannot validate the initial RTC or slow drift. Backward steps or forward steps beyond tolerance raise an incident and hold time-based evidence reclamation. After boot, destructive time effects and watermark advances beyond tolerance hold until authenticated sync or operator confirmation establishes confidence. While time is untrusted, bind/replacement, leases and renewals refuse; explicit stops and authenticated unbind/operator retirement remain available.

The broker keeps its own durable time **watermark**, independent of the dispatcher's. Expiry is evaluated at `max(now, watermark)` and `not_before` at `min(now, watermark)`. The watermark advances only on trusted time and is persisted before authority is released; it never advances on untrusted time. Clock steps can only narrow authority. A forward watermark remains sticky after clock correction until real time catches up or the operator explicitly resets it. Reset is an explicit operator act after confirming the clock; it preserves evidence of genuinely expired authority, which MUST NOT revive. Restore must reconcile this evidence against surviving state outside the rollback domain before reopening (§15.4).

Expiry-driven binding removal also requires boot-inclusive monotonic elapsed time of at least the lifetime, counted from activation (`CLOCK_BOOTTIME` on Linux, continuous time on macOS). Accumulate elapsed time durably at each sweep across boot epochs; downtime is not counted, and missing or untrusted elapsed evidence defers destruction. A wall-clock expiry alone makes the binding unusable but cannot delete it. This is the same dual gate the dispatcher applies to expiry-driven home deletion; explicit authorised cleanup is unaffected. Storage, lifetime accounting and reset evidence would need publication (§18.12), without new `binding/1` fields.

### 15.2 Paths

Figure [M-CB4 — storage layout](../diagrams/storage-layout.puml) shows these paths and the uninstall retention boundary (§15.3); logical record boxes do not introduce new file basenames.

| What | macOS | Linux |
|---|---|---|
| data (store, grants, revocations, bindings/effect tombstones, leases, refresh attempts, time watermark/elapsed evidence, config, audit) | the service user's home, 0700 | the service user's home, 0700 |
| socket | `/opt/swarma/run/credential-broker/`, owned by the broker user, mode 0755, every ancestor root-owned and not writable by others; socket mode 0666 (authorisation is by peer principal, §4) | same |
| service | a LaunchDaemon with `UserName` set to the broker user | a systemd system unit with `User=` |

Startup MUST check the operator-controlled restore mark and reconciliation evidence before auto-start can open authorization. A set mark, unavailable check, or interrupted reopen keeps leasing/renewal closed and `revocation.check` unavailable; parseable state alone cannot clear it. The restore procedure below controls service-manager auto-start separately from optional fenced diagnostic operation.

R-SVC-EGRESS v1 service rows are owned by the user manager's §8. The broker's dedicated profile/listener is a proxy dependency for vendor login and refresh. Before writing its allowlist, qualify those routes (including policy fetch) with the approved executable: observed authentication endpoints, explicitly supplied proxy variables for children, proxy honoured and no direct fallback. The listener resolves names; qualify denial of local resolver bypass (macOS resolver Mach/XPC paths and Linux resolver sockets), rather than treating per-UID rules as DNS evidence. The user manager owns start-time and scheduled service-row/parent-anchor re-verification, its schedule and incident response. Missing/drifted rows drop affected service readiness; periodic checking has a detection window and does not promise continuous enforcement. Proxy outage follows §9.4; no alternate direct route is admitted. Service-row API, profile/listener policy and per-OS resolver mechanisms would need publication (§18.14); this v1 dependency does not disable the software-root slice 0.

R-FATE references the user manager §7 **fate table**, next to R-FD3, for the broker daemon and each vendor writer class on stop, crash and replacement, including the fence against writers left over from a replaced daemon. Unresolved lifecycle evidence keeps replacement closed. For slice 1, LaunchDaemon/systemd configuration MUST qualify containment of the approved vendor process and all refresh-writer descendants, teardown on daemon death, and kill-and-confirm before replacement refresh. Platform-specific unit settings and process/attempt evidence are unpublished (§18.10); generic service-manager defaults are not qualification.

### 15.3 Removal

Uninstall closes new lease/refresh admission, disables auto-start, stops the service and uses the qualified service manager to contain, kill and confirm absence of every active vendor writer. Unknown or interrupted cleanup keeps replacement refresh closed and removal deferred; it is not evidence of process absence. Resolve attempt evidence and durable vendor-home state before later replacement (§9.4); stop/absence alone does not authorize a rotation retry. End leases and bindings while retaining effect/removal evidence (§7.2), and leave the store unless the operator asks to destroy it. Store destruction does not authorize blind refresh of an ambiguous vendor account.

### 15.4 Fenced local restore and reopen

R-GEN companion procedures are owned by the [user manager's state-loss/restore contract](https://github.com/relux-works/swarma-user-manager/blob/main/spec/helper.md) and the [dispatcher's state-loss/restore contract](https://github.com/relux-works/swarma-dispatcher/blob/main/spec/dispatcher.md) (user manager §§4.5–4.6, dispatcher §7.1 and installation/recovery sections). Their ledger and allocation/effect records must reconcile with the broker's current bindings, tombstones and process receipts. A restored active ledger entry is not proof of generation freshness; missing history is unavailable, never absence. Keep affected authorization closed until all owning components reconcile, or explicitly retire/recreate under fresh random 128-bit generations and reissue authority. The broker does not reconstruct or reopen another component's state on its behalf.

This is the supported manual operator procedure, not automatic stale-snapshot repair. The **restore mark** is durable operator-controlled evidence that authorization is closed. Its location, encoding and start-check integration would need publication before activation (§18.8); it MUST survive outside the state/failure domain being restored, persist across interruption and be checked by every supported service-start path. No broker namespace field or additional service is prescribed.

1. **Fence before restore.** Close bind, lease issuance and renewal under the broker state lock; disable service-manager auto-start and publish the durable restore mark before replacing any state. Stop the broker; for Codex, contain, kill and confirm previous vendor-writer absence (§9.4, §15.3). An interrupted or unknown stop leaves restoration/replacement closed.
2. **Restore while closed.** Install the snapshot with protected ownership and atomic-file rules, retaining the restore mark outside its rollback domain. Starting a fenced diagnostic broker MUST NOT open authorization: `revocation.check` answers `unavailable`; bind, lease and renewal refuse. No command fallback or parse-only readiness is allowed.
3. **Reconcile authority.** Establish the complete acknowledged revocation history against trustworthy surviving journal/checkpoint evidence outside the restored failure domain, including the latest acknowledgement; reconstruct and durably publish current state under the sole broker revocation owner. If completeness cannot be established, stay unavailable, or invalidate all old configured broker roots, replace them and explicitly reissue grants and bindings from new operator decisions. Do not retain a transition root that would admit stale authority. D-IDENTITY is unchanged: broker authorization-root replacement does not revoke standing identity keys.
4. **Reconcile other state.** Reconcile the time watermark, trusted expiry/reset evidence and elapsed accounting (§15.1), and the companion ledger/dispatcher restore obligations above; never reset time from a stale snapshot. Resolve bindings/effects and their removal evidence; missing evidence remains `unavailable`, never absence (§7). Resolve refresh attempt/process/store evidence independently (§9.4); revocation recovery does not establish safe vendor retry. Any account with unresolved rotation remains unavailable or requires re-enrolment after writer absence.
5. **Reopen last.** Durably record the reconciliation result and operator reopen decision outside the restored failure domain, then clear the restore mark only after that result is committed. Run the service-start check against this evidence and the reconciled state, start/recover the service, publish readiness, and only then open bind, leasing/renewal and dispatcher verdicts. Re-enable automatic service start last. Interruption before this order is satisfied leaves authorization closed; every subsequent start repeats the check. If all surviving history was lost, only explicit root replacement/reissue can permit this reopen.

A same-home sequence, audit file or checkpoint cannot certify its own rollback. The optional external witness requires durability before each revocation acknowledgement (§6.4); selecting one is separate from the fenced manual procedure. Already delivered provider tokens keep their documented vendor lifetime (§12.1).

## 16. Delivery order

1. **Formats.** `grant/1`, `revocation/1` and the `broker/1` frames are frozen with canonical and negative vectors; the verifier ships with its mutant suite (§6.2).
2. **Slice 0: one protected Claude launch.** swarma-user-manager v0 and its launcher; installed `swarma-operator`/`swarma-observer` and qualified operator-command admission/custody (§4, §14–§15, §18.15); the broker daemon with the file store, local grants and revocation state, the fenced restore/start check, bind and unbind with retained observation evidence, R-OUTCOME tables, R-REBIND binding replacement, durable R-TIME watermark and elapsed-removal gate, `effect.observe`, `revocation.check`, lease request and release, the `env` channel, protected binding and conflict refusal, audit; the broker client in `curator-run` under the agent account (§3.1, D-EXECUTOR). **The dispatcher is an unprivileged Unix-socket service from this first slice**, using the broker connection and framing rules (§4.1, §13.1); `curator agent-user` is its client. There is no dispatcher sudo entry, command mode, `SUDO_UID` dispatcher branch, detached-command bootstrap, external sweep timer or command-to-daemon conversion. Dispatcher-to-root user-manager/launcher rules remain. Recovery and readiness precede admission; an absent/unready dispatcher refuses with no command fallback. Initial capacity closure refuses; queueing, events, long waits and advanced integrations come later behind capability gates on this same transport. The board runner and session host call the dispatcher rather than embedding broker clients. Direct worker launches and operator-enrolled orchestrators form the first slice; recursive orchestrator provisioning stays refused until the requester-signed bootstrap is published and qualified (R-DELEG). Hosted-runner acceptance exercises the deployed socket service, caller signatures, fresh principal/generation checks, server-UID verification, descriptor restrictions, durable effects/receipts and process-absence reconciliation. The dispatcher creates the account, binds with caller authorization and invokes the launcher; the executor leases and runs Claude. It MUST refuse another UID, retired generation, account/profile mismatch, expired/revoked grant, unavailable revocation evidence, fenced restore, conflicting source and unqualified harness. The token appears in no file, argv, log or child process the qualification covers. Required negative/recovery rows are below; publication gaps in §18 remain gates, not qualification claims.
3. **Slice 1: Codex.** The enrolment ceremony, auth owner, external tokens with renewal and deadlines, supported-release qualification and **single-writer ownership across daemon replacement** (§9.4–§9.6, §15). Activation requires every replacement/rotation row in §9.6 on both platforms; a daemon-local lock or historical renewal evidence alone is insufficient.
4. **Slice 2: enforced networking.** Helper v1 firewall rules, R-SVC-EGRESS service rows/proxy and resolver qualification, and R-NETBIND machine-owned binding with served-policy verification; trusted applied state; accounts that require enforced profiles become serviceable (§5.5).

### 16.1 Required negative and recovery qualification

The §6.2 rule already enforces `child.issuer == parent.subject` on every edge, including the leaf, with exact parent IDs and decreasing depth; it is unchanged. R-DELEG requires requester C to sign new orchestrator O's caller delegation after generation-bound key registration; dispatcher D verifies and records it, never signs it. When O creates worker W, the separate caller chain retained in W's binding MUST still include C. Key registration alone activates no spawn authority. The dispatcher owns bootstrap authentication, replay/rotation rules and depth/chain-length preflight; broker `broker/1` adds no `register_key` method.

These required vectors must drive dispatcher admission/activation and the broker's real bind/lease/renew paths where applicable. The R-OPERATOR vectors drive installation and the real operator command and observer entry points; their unpublished integration remains gated by §18.15. Publication of vectors here is not evidence they have run.

| Vector / recovery case | Required result |
|---|---|
| Attempt to configure an interactive/harness UID as operator/owner, or place the root in that account | Refuse installation/admission; `swarma-operator` owns the root and operator authority and never hosts harnesses |
| Unsigned/forged phone act, unpinned key, altered canonical content or reuse for a different act | Operator command refuses; SSH login alone cannot authorize the act; no operator mutation |
| Widening without exact content confirmation, or enrol/grant/standing renewal attempted inside an agent session on either path | Refuse before mutation; valid authentication alone cannot widen |
| Terminal operator act using NOPASSWD or a cached sudo ticket | No admission; each act needs password authentication with timestamp_timeout=0; phone absence still permits authenticated fallback |
| Revocation through phone or terminal | Single biometric confirmation on phone or fresh terminal password; no extra content-confirmation step; existing revocation signature/durability checks still apply |
| Observer attempts enrol, grant publication, revocation, unbind or secret/lease access | Refuse mutation/material access; status, account.list, grant.list and binding.list remain confirmation-free reads |
| C ≠ D; D signs O's delegation attached to C's leaf | Refuse wrong issuer/parent-subject edge. Control: C-signed narrowed delegation retains C and verifies independently of D's lease chain |
| Wrong issuer at any edge, including leaf; mutate continuity check | Refuse even if signatures individually verify; no re-parenting that drops C |
| Insufficient remaining depth or fifth envelope | Refuse before provisioning/activation; narrowing depth and four-envelope bound remain mandatory |
| Replay pre-key registration, or rotate/reuse a generation's key without the published bootstrap rules | Dispatcher refuses replay/implicit activation; registered O has no spawn authority without valid C-signed delegation; broker never treats registration as a grant |
| Revoke C before O creates W | Dispatcher refuses prepare/dequeue/start before new effects; broker bind independently refuses the revoked caller chain |
| Revoke C after O creates W | W's next lease and renewal refuse through its retained caller chain; copied tokens are not erased and denial does not prove execution absence |
| Revoke before `prepare`, `dequeue` or `start`; reuse old `not_revoked` verdict | Current `revocation.check` refuses admission on `revoked`; stale answer never permits a future start; final broker checks still refuse |
| Broker unavailable; revocations missing, malformed, unreadable or stale | Admission refuses on `unavailable`; no empty-set substitute or independent dispatcher revocation database |
| Correctly owned valid old snapshot after acknowledged revocation | Restore mark/start check keeps bind, leases/renewals and auto-start closed; `revocation.check` is `unavailable` until surviving history is reconciled |
| All external freshness evidence lost | Stay unavailable, or explicitly invalidate old roots and reissue rights; old snapshot cannot resurrect authority |
| Interruption during restore, reconciliation, mark clearing or readiness publication | Every start remains closed until durable reconciliation/reopen evidence and the prescribed order are verified |
| Keeper migration with revocations preserved | Current acknowledged revocations survive/reconcile through root transition; missing history cannot reopen old grants |
| Bind/unbind crash before intent, during mutation, after result persistence or before acknowledgement | `effect.observe` reports authoritative journal state; complete evidence alone permits `not_recorded`; pending/missing evidence stays unknown |
| Bind rolled back; completed bind later removed; unbind reply lost | `rolled_back` never creates replacement; recorded bind reports current removal; same unbind effect returns retained result/tombstone without targeting a new binding |
| Observation after caller grant expiry; evidence/tombstone retention expiry; wrong observer or mismatching arguments | Authenticated original principal/operator can read without mutation authority; expired evidence is `unavailable`; unauthorized/conflicting observation refuses |
| R-REBIND races revocation, lapses or crashes after old removal before new publication | No widening or account recreation; fresh prepare verdict and final broker checks; old leases end; old tombstone survives; replay cannot reactivate or affect replacement |
| Bind pre-admission refusal then authority revoked before retry; pending bind with lapsed authority | No intent on rejection; fresh retry/recovery checks refuse new authority; uncertainty is not automatically pending |
| Unbind interrupted after intent; caller grant lapses; replacement now exists | Same-effect same-argument continuation removes only original target; terminal replay cannot remove replacement |
| Forward step beyond lifetime, backward step across expiry, VM resume or wrong RTC at boot | No revived lease/not_before window; hold untrusted time; no expiry removal before monotonic lifetime; watermark never advances untrusted |
| Reboot, stale time restore or operator watermark reset | Durable accounting and genuinely expired authority survive; downtime only delays destruction; missing evidence keeps admission/destruction closed |
| Proxy outage/bypass, vendor child ignores proxy, local resolver path or service-row drift (v1) | No direct fallback; safe refresh failure backoff only after writer/outcome resolution; missing row drops readiness; qualification measures detection window |
| Slow lifecycle call or late result after broker replacement/restore fence (R-LOCK) | State lock is released during cross-service I/O; unrelated reads remain available; stale completion cannot deliver material |
| Direct operator retirement while broker refuses/is unavailable/restore-fenced | Local quiescence does not claim unbind; durable cleanup obligation remains; retired generation and reused UID get no old authority |
| Socket dispatcher absent/unready, invalid server UID, inherited/passed authenticated descriptor or attempted caller sudo/command fallback | Refuse; recovery/readiness and fresh connections remain mandatory; no dispatcher sudo route exists |

## 17. Later

- a key keeper as the trust root and agent identities as keys (§4.3);
- grants and revocations from a shared registry (§6.5);
- roles, wildcards and further grant conditions, including bounds on concurrent use per account;
- events delivered to the session host and a person's phone (approve a lease, re-enrol);
- a Muse auth owner, if Muse rotates;
- Windows.

## 18. Open questions

The following broker/provider choices and publication gates remain open here. D-EXECUTOR resolves the launcher amendment direction and first consumer; D-WIRE-NAMES resolves the signing domains. Publication of the narrow executor intake remains R-LR1 work, not a new consumer-choice question.

1. Registry for grants and revocations beyond the local state (§6.5).
2. Whether Claude tokens should also be issued per launch by an owner once vendors offer short-lived subscription tokens.
3. Ownership of one Codex vendor account across several machines (§9.5).
4. **OWNER DECISION NEEDED — Codex personal-plan adoption/qualification (contract C4, CIP-0010 open question 2).** Options: adopt the single auth owner and external-token lane with named supported-release evidence (including the proposed 0.159.0 race-test precondition), or defer that provider lane. The broker slice-1 design and historical 0.155.x reference do not decide the current supported release or satisfy that precondition.
5. **OWNER DECISION NEEDED — Muse subscription channel and priority (contract C7).** Options: prioritize subscription qualification and choose a supported channel from measured store/refresh evidence, or defer subscription support while retaining the separately qualified API-key lane. No subscription channel, refresh owner or parity claim is invented.
6. **Open research — provider proxy injection (audit A10.6).** Options: continue separate provider/channel qualification research, or defer traffic-side injection and retain the explicit harness-readable delivery model. No proxy path is an admitted substitute for native or broker authentication.
7. **OPEN — launch-time lease cleanup by channel (§8.4–§8.5, §9.3).** For `env`, choose between release by the owning executor before exec (and define whether release permits use of the already delivered payload), or retaining the lease until `authorized_until` / revocation / unbind (and define record transitions and reclamation). Successful exec leaves no executor broker client; disconnect and harness exit are not release. For `stdin`, publish whether a client survives delivery and its release point. For runner-held `external-token`, publish teardown/release ordering and cleanup on initialisation failure or runner loss. Also specify post-lease pre-exec refusal cleanup and whether a live client reports env-harness failures. No post-exec callback, inherited broker descriptor, exit watcher or new wire mechanism is specified here.
8. **OPEN — restore/start and verdict publication (§6.4, §13.2, §15.4).** Would need the operator restore-mark location/encoding, trusted start-check and durable reconciliation/reopen evidence integration outside the restored failure domain; completeness rules for surviving journal/checkpoint evidence; any optional witness's pre-ack durability; and `revocation.check` exact request/response encoding, including how an unavailable sequence is represented. The three verdicts, contexts and access rule are fixed by R-VERDICT. No new refusal code or namespace field is assigned.
9. **OPEN — receiver observation and retention publication (§7, §13.2).** Would need exact `effect.observe` wire encoding (including original effect ID versus the read's transport correlation), canonical-argument digest construction, protected journal/tombstone layout and recovery transaction ordering, unbind/conflict refusal mappings, and a bounded retry/admission rule that makes discarded identities permanently inadmissible before evidence reclamation. The six states and original-caller/operator access are fixed by R-OBS. Missing evidence must remain `unavailable`; these gaps gate activation.
10. **OPEN — refresh lifecycle publication (§9.4–§9.6, §15).** Would need platform-qualified LaunchDaemon/systemd containment, full writer/descendant kill-and-confirm, durable attempt/process identity and recovery records, vendor-home/outcome reconciliation and bounded teardown ordering. Unit defaults, PID checks and child absence alone cannot prove safe retry after ambiguous external rotation. This publication and the §9.6 qualification rows gate slice 1.
11. **OPEN — R-REBIND publication and fresh-lease handoff (§7–§8).** Would need exact replacement intake through existing bind semantics, immutable argument/provenance binding, original-request narrowing evidence, removal/publication recovery ordering and observation correlation. A fenced fresh-lease handoff would need a qualified surviving holder, old/new binding fence, teardown and failure semantics. Until published, use explicit park/restart; no seamless env or app-server continuation is claimed. No new wire fields, method or refusal code is assigned.
12. **OPEN — R-TIME publication (§6.2, §7.2, §8.3, §15).** Would need the shared confidence policy/tolerances, authenticated/operator-controlled source integration, durable watermark and trusted-expiry/reset evidence outside restore rollback, boot-inclusive elapsed accumulation and lifetime anchoring. Reset must preserve genuinely expired authority; missing elapsed evidence delays destruction. The max/min checks and dual destructive gate are fixed, not open choices.
13. **OPEN — R-LOCK publication (§13.1).** Would need concrete per-record in-flight marker/version/daemon fencing, bounded I/O/concurrency and late-result recovery mechanisms that implement the acyclic wait/lock graph without holding state locks across platform-service calls.
14. **OPEN — R-SVC-EGRESS/R-NETBIND v1 integration (§3, §5.5, §9, §15.2).** Would need the user manager's service-profile API/matrix, start and scheduled re-verification owner/response, broker profile/listener authentication allowlist based on qualified login/refresh/policy-fetch endpoints, explicit vendor-child proxy configuration, resolver isolation and served-digest relations/re-apply fencing. These gates accompany v1 enforcement; no new grant dimension or authentication endpoint guess is introduced.

15. **OPEN — R-OPERATOR publication and phone-key lifecycle (§4.2–§4.3, §13.2, §14–§15).** Would need the operator command binary name and wire format, operator-record signature domain and canonical bytes, exact content display/confirmation and per-act/replay verification, hardware-backed phone-key/SSH integration and pin storage, agent-session detection/refusal, protected command-only terminal/SSH admission and account provisioning, observer read entry point, and classification/confirmation of time reset and restore/reopen. Key enrolment, rotation and loss of the phone remain open; the proposal is terminal re-enrolment through password-authenticated fallback with `timestamp_timeout=0`. Would need recovery/re-pinning and revocation rules that preserve the no-harness custody boundary; loss of the operator account or root follows §15.4 root replacement/reissue, never key restoration into a session account. Existing signed broker envelopes, shared method names and refusal codes are unchanged; no operator wire fields or algorithm are assigned here.

## Appendix A. Refusal codes

`peer_identity_unavailable`, `server_identity_mismatch`, `principal_ledger_mismatch`, `principal_identity_changed`, `role_not_permitted`, `frame_too_large`, `version_unsupported`, `request_deadline_exceeded`, `account_exists`, `account_unknown`, `account_duplicate`, `account_store_keyring_refused`, `enrol_material_invalid`, `grant_malformed`, `grant_id_mismatch`, `grant_signature_invalid`, `grant_chain_malformed`, `grant_chain_broken`, `grant_not_narrowing`, `grant_root_unknown`, `grant_subject_invalid`, `grant_unsupported`, `grant_revoked`, `grant_expired`, `grant_not_yet_valid`, `revocation_not_authorised`, `revocation_state_unavailable`, `bind_not_dispatcher`, `bind_target_invalid`, `bind_request_conflict`, `lease_unbound`, `lease_grant_revoked`, `lease_not_authorised`, `lease_account_unknown`, `lease_harness_mismatch`, `lease_account_revoked`, `lease_reauth_required`, `lease_owner_unavailable`, `lease_channel_unsupported`, `lease_harness_unqualified`, `lease_binding_mismatch`, `lease_network_mismatch`, `lease_network_enforcement_unavailable`, `lease_not_owner`, `lease_not_active`, `lease_caller_revoked`, `grant_unconstructible`, `renew_not_current`, `renew_timeout`, `renew_failed`, `external_token_init_failed`, `credential_source_conflict`, `credential_injection_unavailable`.

## Appendix B. Diagrams

PlantUML sources describe draft contracts, not runtime qualification. Each module figure links its defining sections and labels phases, process identities, state custody and refusal/recovery boundaries. Where the spec is silent, a visible note records the gap.

| Audit B4 figure | Source | Defining sections |
|---|---|---|
| M-CB1 — components | [components.puml](../diagrams/components.puml) | §3–§4, §6.4, §7–§9, §13, §15–§16 |
| M-CB2 — lease recovery | [lease-recovery.puml](../diagrams/lease-recovery.puml) | §4.1–§4.2, §6.4, §8–§9, §12.2, §15.4 |
| M-CB3 — record states | [record-states.puml](../diagrams/record-states.puml) | §5.1, §6.4, §7.1–§7.4, §8.3–§8.5, §9.4, §13.2, §15.4 |
| M-CB4 — storage layout | [storage-layout.puml](../diagrams/storage-layout.puml) | §5.3, §12.3–§12.4, §15 |

Main sequences: [enrolment](../diagrams/enrol.puml), [agent registration](../diagrams/agent-registration.puml), [lease at launch](../diagrams/lease-at-launch.puml), [Codex renewal](../diagrams/codex-renewal.puml), [binding replacement](../diagrams/binding-replacement.puml), and [revocation/unbind](../diagrams/revoke-and-unbind.puml). Launch, renewal and revocation link to M-CB2 for refusal/recovery detail.
