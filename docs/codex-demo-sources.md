# Codex demo source claims and review boundaries

This map accompanies [the design note](codex-demo-design.md). Facts describe
inspected public source, not a successful account, VM or qualification run.
No native authentication store, real lease or private key was inspected.

## Broker source: fixed base

Repository: `relux-works/swarma-credential-broker`, main resolved to
`90338be1dacfee9f2a4e6c51cb1fa75da953a93b` before the design branch was made.
All line references in this table refer to that base, not a later main.

| Claim | Exact source | What it establishes / limit |
| --- | --- | --- |
| The daemon cannot currently issue through an active owner | [`main_linux.go:62`](https://github.com/relux-works/swarma-credential-broker/blob/90338be1dacfee9f2a4e6c51cb1fa75da953a93b/cmd/swarma-credential-broker/main_linux.go#L62), [`owner.go:46`](https://github.com/relux-works/swarma-credential-broker/blob/90338be1dacfee9f2a4e6c51cb1fa75da953a93b/internal/owner/owner.go#L46) | `owner.Stopped` is constructed; `Snapshot`/`Refresh` are real library seams |
| Contained refresh exists as a library | [`engine_linux.go:51`](https://github.com/relux-works/swarma-credential-broker/blob/90338be1dacfee9f2a4e6c51cb1fa75da953a93b/internal/authowner/engine_linux.go#L51), [owner documentation](auth-owner.md) | Constructor requires containment and confidence; documentation explicitly defers enrolment and activation |
| Refresh reaches the managed vendor, then reloads private state | [`vendor_linux.go:44`](https://github.com/relux-works/swarma-credential-broker/blob/90338be1dacfee9f2a4e6c51cb1fa75da953a93b/internal/authowner/vendor_linux.go#L44), [`vendor_linux.go:182`](https://github.com/relux-works/swarma-credential-broker/blob/90338be1dacfee9f2a4e6c51cb1fa75da953a93b/internal/authowner/vendor_linux.go#L182) | Protected reload and actual `account/read` request exist; this is not proof of native release qualification |
| Fresh-home check is not shipped enrolment | [`engine_linux.go:351`](https://github.com/relux-works/swarma-credential-broker/blob/90338be1dacfee9f2a4e6c51cb1fa75da953a93b/internal/authowner/engine_linux.go#L351), [profile §3](../spec/v0-codex-refresher.md#3-enrolment-and-existing-logins) | Lifecycle prerequisite versus specified future operator ceremony; an example command in a spec is not executable functionality |
| Kernel UID supplies caller identity | [`peer_linux.go:11`](https://github.com/relux-works/swarma-credential-broker/blob/90338be1dacfee9f2a4e6c51cb1fa75da953a93b/internal/server/peer_linux.go#L11) | `SO_PEERCRED`, not JSON; no roster generation integration is present here |
| Static policy and worker/observer separation exist | [`policy.go:16`](https://github.com/relux-works/swarma-credential-broker/blob/90338be1dacfee9f2a4e6c51cb1fa75da953a93b/internal/policy/policy.go#L16), [public clients](brokerclient.md) | UID/account/profile tuple and observer role; neither grants nor a full managed-principal ledger |
| Service isolation exposes a runner integration gap | [protected runner authority](broker-client.md), [socket rules](socket-permissions.md) | Existing runner reads broker-owned 0600 config; reachability/peer identity cannot make that readable or qualify the service |
| Real access material is memory/pipe-only in the Codex profile | [profile §2.1](../spec/v0-codex-refresher.md#21-interim-run-identity), [runner](runner.md) | Private metadata file proposal must not become a credential-file channel without an explicit contract amendment |
| One-shot caller/dispatcher/executor division is specified | [broker §3.1](../spec/broker.md#31-first-consumer-and-execution-boundary) | Platform consumer is `curator-run`; suggested intake grammar is explicitly not published |
| Owner-close diagnostics are observational | [diagnostic contract](owner-close-diagnostics.md), [CI](linux-ci.md) | Frozen observations are not absence certificates or evidence of the cause of a historical timeout |

## Pinned Codex provider source

Repository: `openai/codex`, tag `rust-v0.163.0`; tag object
`129b8ec7ee6f4511557a4856279f529025c25af4` peels to commit
`83086188ae0614bd882818ff1aa23f3194962012`. Source inspection did not execute
Codex, contact an auth endpoint or verify a deployed binary's identity.

| Claim | Exact public source | Limit |
| --- | --- | --- |
| Managed account reads can request refresh | [`account_processor.rs:1103`](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/app-server/src/request_processors/account_processor.rs#L1103), [`workspace_routing.rs:174`](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/app-server/src/request_processors/account_processor/workspace_routing.rs#L174) | External mode skips this refresh; account response is not token issuance output |
| Native refresh uses the provider authority and persists replacements | [`manager.rs:1627`](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/login/src/auth/manager.rs#L1627), [`manager.rs:2845`](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/login/src/auth/manager.rs#L2845), [`manager.rs:3089`](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/login/src/auth/manager.rs#L3089) | A guarded reload may find an already changed token; successful account metadata alone is not durable nonrotation evidence |
| External token login consumes supplied material | [`account.rs:86`](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/app-server-protocol/src/protocol/v2/account.rs#L86) | Explicit unstable/internal-use warning remains; no admission inferred from source availability |
| External renewal delegates to host | [`external_auth.rs:18`](https://github.com/openai/codex/blob/83086188ae0614bd882818ff1aa23f3194962012/codex-rs/app-server/src/external_auth.rs#L18) | Approximately ten-second upstream callback timeout; host must already own a qualified renewal route |

Official OpenAI documentation was read on 2026-11-06:
[app-server authentication](https://learn.chatgpt.com/docs/app-server#authentication-endpoints)
and [Codex authentication](https://learn.chatgpt.com/docs/auth).
They describe managed sign-in, optional managed refresh and experimental
host-managed token input. They do not establish this broker's account admission,
exact-release qualification, independent confidence or deployed issuance route.
The pinned source controls release-specific claims; current docs can evolve.

## One-shot consumer source

Repository: `relux-works/curator-agent-launcher`, inspected main
`2045339f703ee8190705c116a05197b12b684b71`.
[README target mode](https://github.com/relux-works/curator-agent-launcher/blob/2045339f703ee8190705c116a05197b12b684b71/README.md#target-one-shot-exec-mode)
and [SPEC §10](https://github.com/relux-works/curator-agent-launcher/blob/2045339f703ee8190705c116a05197b12b684b71/SPEC.md#10-agent-account-one-shot-exec-contract-target-amendment)
identify one-shot exec as a target with unresolved publication questions. Hosted
home/environment leases in that repository are a different resource from
credential-broker leases. They are not evidence that a broker one-shot intake
or a token-bearing lease file already exists.

## Decisions and proposals

The UID/GID range, three precreated account names, roster path/ownership,
generation/dispatcher binding, FD3 plan size, execution witness and stop/output
bounds in the design are frozen demo integration requirements. They are not
claims that broker main implements them. The operational acceptance record is
kept outside product source.

`AdmitCodexAccount`, `ResolveDemoPrincipal`, `DemoWorkerAuthority`, the
metadata-only lease-file lifecycle and CI timeline events are proposals in this
note. They are not published APIs, existing commands, new trust roots or code
changes. The four questions and acceptance table delimit what must be resolved
before implementation. No production run or independent review is claimed.
