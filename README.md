# swarma-credential-broker

A credential broker for agent systems. It runs under its own OS user, holds subscription and API credentials in its own store, and leases them to authorised agent launches over a Unix socket whose peer it identifies through the kernel (`getpeereid` / `SO_PEERCRED`).

**Status: design in progress.** Nothing is implemented yet. The specification is [`spec/broker.md`](spec/broker.md); diagrams are in [`diagrams/`](diagrams/).

## What it is for

- One person, one subscription: a subscription is enrolled once and handed to the launches that person authorised, instead of a separate login per managed home.
- Agents run as separate OS users; a launch asks the broker for a lease for its profile and harness, and receives the credential only in the launched process.
- Authority is a signed grant (`credential.lease` on an account, for a profile, until a time), verifiable down to a root key; delegation can only narrow.
- An account may require a network profile, so its traffic leaves only through a named egress.
- Codex personal plans: a single auth owner refreshes the account with a required writer-lifecycle gate across daemon replacement; launches receive external access tokens and never hold a refresh token.

The configured operator and every subscription/API account's owner are `swarma-operator`, a separate account that never hosts agent sessions and holds the v0 Ed25519 software root. The main path uses a phone-held, hardware-backed **operator device key**: biometric confirmation signs each exact operator act, SSH over the tailnet reaches a forced **operator command** with no shell, and the machine verifies the pinned phone key. Terminal fallback uses password-authenticated sudo into `swarma-operator`, no `NOPASSWD` and `timestamp_timeout=0`. Widening acts need content confirmation and are refused inside agent sessions; revocation needs authentication only. Mandatory `swarma-observer` reads status, accounts, grants and bindings without confirmation. [Operator custody and acts](spec/broker.md#43-trust-root-and-key-classes) are design requirements; [operator format and phone-key lifecycle publication](spec/broker.md#18-open-questions) remain open.

The broker's v0 trusted-process exception is explicit: the harness can read and copy its leased token. Revocation stops new leases and renewals; a copied token remains usable until expiry or vendor revocation. See [the exposure limits](spec/broker.md#121-what-a-compromised-agent-can-do) and [the required injection qualification](spec/broker.md#122-protected-binding-and-conflicting-sources).

## How it fits

- Curator composes the plan on the caller's side. The first broker consumer is [curator-run under the agent account](spec/broker.md#31-first-consumer-and-execution-boundary): its narrow one-shot mode verifies and executes that plan, obtains the lease and starts the harness (owner decision D-EXECUTOR, 2026-10-11). The board runner and session host ask swarma-dispatcher to launch through curator-run; they do not embed broker clients.
- swarma-user-manager creates the per-agent OS users the broker identifies.
- curator-network-profiles names the egress an account may require.
- curator-trust and waggle define the long-term grant and signature forms. Broker v0 verifies its closed local envelope; a versioned adapter reconciles the forms before 1.0.

Accepted cycle-2 contracts add [binding replacement](spec/broker.md#72-creating-and-removing) for the same UID/generation with no widening or lease carry-over, [durable time watermark and monotonic destruction gates](spec/broker.md#151-service-user-and-time), and receiver-owned [bind/unbind outcome tables](spec/broker.md#132-methods). The root helper has no broker principal; unconfirmed cleanup after direct retirement remains a dispatcher/operator obligation. [Broker proxy-only egress](spec/broker.md#152-paths) is a v1 service-profile capability requiring qualification; login/refresh and resolver routes remain publication gates. The machine owns the child network binding, and the user manager owns the shared process fate table. [R-LOCK](spec/broker.md#131-transport) forbids holding the state lock across synchronous platform-service calls.

The dispatcher is a Unix-socket service from the first slice, with no caller sudo entry. Configured dispatchers use `revocation.check` for current admission evidence; bind/unbind reconciliation uses receiver-owned `effect.observe`. [Fenced local restoration](spec/broker.md#154-fenced-local-restore-and-reopen) keeps authorization and auto-start closed until acknowledged revocations are recovered against evidence outside the restored failure domain, or old authorization roots are replaced and rights explicitly reissued. [Publication and qualification gates](spec/broker.md#18-open-questions) remain open; these are design requirements.

The first protected provider launch is Claude with an explicitly enrolled `setup-token`; Codex personal-plan external tokens follow in slice 1. The [provider × source × channel × phase table](spec/broker.md#52-kinds) distinguishes those targets from retained per-home authentication and later or unresolved lanes. Source-policy v1 keeps `per-home` when no entry is configured; v2 requires an explicit entry and migrates existing logins to explicit `per-home`. The first node and broker stores use protected 0600 files on macOS and Linux; Keychain and Secret Service backends are later work.

The repository, standalone binary and service account are named `swarma-credential-broker`; `curator broker` is the Curator front end. The earlier `curator-broker` CLI spelling is historical design text, with no shipped alias or migration. Signed domain tags are `swarma-credential-broker grant/1` and `swarma-credential-broker revocation/1`; `broker/1` remains the peer-authenticated transport. The [grant dialect boundary](spec/broker.md#66-relation-to-the-trust-design) and [key classes](spec/broker.md#43-trust-root-and-key-classes) distinguish this v0 design from the future keeper model. Managed identity checks read the root-owned ledger at `/opt/swarma/lib/user-manager/ledger.json` ([§4.2](spec/broker.md#42-principals)). These are design contracts, not runtime qualification claims.

The [registration](diagrams/agent-registration.puml), [launch](diagrams/lease-at-launch.puml), [enrolment](diagrams/enrol.puml), [Codex renewal](diagrams/codex-renewal.puml) [binding replacement](diagrams/binding-replacement.puml) and [revocation](diagrams/revoke-and-unbind.puml) sequences describe the intended flows. The module figures below show their component, recovery, state and storage boundaries. All are design contracts; visible “unspecified in spec” notes preserve gaps rather than supply implementation decisions.

[Launch-time lease lifetimes](spec/broker.md#85-renewal-release-and-reports) distinguish an env launcher replaced by exec from a live external-token client that can renew and release. The [cleanup policy remains open](spec/broker.md#18-open-questions) where the design does not publish a release point or record-reclamation rule.

| Figure | PlantUML source | Defining specification |
|---|---|---|
| M-CB1 — v0 components and process identities | [components.puml](diagrams/components.puml) | [§3 Components](spec/broker.md#3-components), [§3.1 First consumer](spec/broker.md#31-first-consumer-and-execution-boundary), [§4 Identities](spec/broker.md#4-identities-and-trust) |
| M-CB2 — lease refusal and recovery | [lease-recovery.puml](diagrams/lease-recovery.puml) | [§6.4 Revocation](spec/broker.md#64-revocation), [§8 Leases](spec/broker.md#8-leases), [§9 Codex auth owner](spec/broker.md#9-codex-auth-owner), [§15.4 Fenced restore](spec/broker.md#154-fenced-local-restore-and-reopen) |
| M-CB3 — account, binding, lease and grant states | [record-states.puml](diagrams/record-states.puml) | [§5.1 Account record](spec/broker.md#51-record), [§6.4 Revocation](spec/broker.md#64-revocation), [§7 Bindings](spec/broker.md#7-bindings), [§13.2 Observations and verdicts](spec/broker.md#132-methods), [§8.3 Lease record](spec/broker.md#83-response-and-lease-record) |
| M-CB4 — owned storage, socket and removal | [storage-layout.puml](diagrams/storage-layout.puml) | [§5.3 Secret store](spec/broker.md#53-secret-store), [§12.4 Files](spec/broker.md#124-files), [§15 Installation and lifecycle](spec/broker.md#15-installation-and-lifecycle) |

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
