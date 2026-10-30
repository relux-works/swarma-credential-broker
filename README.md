# swarma-credential-broker

The credential broker is **Merovingian** in the platform's codenames.

A credential broker for agent systems. It runs under its own OS user, holds subscription and API credentials in its own store, and leases them to authorised agent launches over a Unix socket whose peer it identifies through the kernel (`getpeereid` / `SO_PEERCRED`).

**Status: experimental Linux daemon core and runner.** The daemon covers protected static policy, metadata storage, kernel peer admission, the refresher transport subset and lease bookkeeping. The Linux [external-token runner](docs/runner.md) uses a [protected static authority and broker wire client](docs/broker-client.md). The shipped owner adapter refuses issuance and the production qualified release set is empty; the real contained auth owner and release qualification remain pending. A tested offline migration script is available for review; real deployment requires the site integrations and qualification described in [the migration guide](docs/service-user-migration.md). The broader broker remains a design. The specification is [`spec/broker.md`](spec/broker.md); diagrams are in [`diagrams/`](diagrams/). The proposed [Codex refresher v0 profile](spec/v0-codex-refresher.md) extracts the auth owner and external-token runner ahead of slice 0, with accepted interim rulings and pending release qualification. The remaining activation gates still apply.

## What it is for

Linux integrations can import the [v0 worker client and separate static-policy
observer](docs/brokerclient.md) at
`github.com/relux-works/swarma-credential-broker/brokerclient`. The observer
receives no lease material and its observation is not launch authority.

These bullets describe the readable-token broker baseline. The separately
versioned [secret-free mode proposal](spec/secret-free-mode.md) is **inactive**:
only the broker and admitted credential-spending services hold vendor-valid
material; a harness receives a launch-bound placeholder through a qualified
configured endpoint. The minimal broker owns credential lifecycle; a separate
gateway owns request adapters, and the action service owns all external
shared-state writes. Service compromise remains in the trusted base. Legacy v0
still delivers real external tokens; failed new-mode qualification grants no
fallback. [Local-only scope and closed gates](spec/secret-free-mode.md#1-modes-and-admission)
retain interception and donor B/C as closed, separate scopes.
The separate proposed [gateway contract](spec/secret-free-gateway.md) and
[equal provider adapter profiles](spec/secret-free-adapters.md) specify semantic
write refusal, two current authorities per use and account-wide containment;
all new-mode runtime witnesses remain UNRUN.

- One person, one subscription: a subscription is enrolled once and handed to the launches that person authorised, instead of a separate login per managed home.
- Trusted local agents run as separate OS users; a launch asks the broker for a lease for its profile and harness, and receives the credential only in the launched process.
- Authority is a signed grant (`credential.lease` on an account, for a profile, until a time), verifiable down to a root key; delegation can only narrow.
- An account may require a network profile, so its traffic leaves only through a named egress.
- Codex personal plans: a single auth owner refreshes the account with a required writer-lifecycle gate across daemon replacement; launches receive external access tokens and never hold a refresh token.
- Muse subscription qualification is prioritized (owner, 2026-10-13). [Proposed channel (b)](spec/broker.md#102-muse) uses one minting owner to lease the provider API key minted by device-code OAuth, never OAuth tokens, with fallback (c) if key billing or re-mint revocation prevents it. Qualification stays open; the API-key lane remains separate.

The configured operator and every subscription/API account's owner are `swarma-operator`, a separate account that never hosts agent sessions and holds the v0 Ed25519 software root. The main path uses a phone-held, hardware-backed **operator device key**: biometric confirmation signs each exact operator act, SSH over the tailnet reaches a forced **operator command** with no shell, and the machine verifies the pinned phone key. Terminal fallback uses password-authenticated sudo into `swarma-operator`, no `NOPASSWD` and `timestamp_timeout=0`. Widening acts need content confirmation and are refused inside agent sessions; revocation needs authentication only. Mandatory `swarma-observer` reads status, accounts, grants and bindings without confirmation. [Operator custody and acts](spec/broker.md#43-trust-root-and-key-classes) are design requirements; [operator format and phone-key lifecycle publication](spec/broker.md#18-open-questions) remain open.

The broker's v0 trusted-process exception is explicit: the harness can read and copy its leased token. Revocation and the journaled R-ALLSTOP node-wide freeze stop new leases and renewals; a copied token remains usable until expiry or vendor revocation. See [the exposure limits](spec/broker.md#121-what-a-compromised-agent-can-do) and [the required injection qualification](spec/broker.md#122-protected-binding-and-conflicting-sources).

R-UNTRUSTED accounts never receive a broker binding or lease; admission-class evidence from the dispatcher is mandatory, and slice 0/user-manager v0 refuse the class. A workplace has zero egress and its loop stays at the donor. [Circle membership, placement and enforcement class](spec/broker.md#42-principals) are separate predicates: membership alone grants neither a local host loop nor a review role. Review requires positive role admission; optional local-only reviewer and requester-exclusion policies remain open and off. Local trusted agents reach only model-provider endpoints through the bound profile proxy. No web tool is the default: tasks carry read-only resources, and trusted-circle web access is an explicit opt-in. The platform web-tool search key is a service credential, never an agent lease; [custody remains open](spec/broker.md#18-open-questions).

[R-ALLSTOP](spec/broker.md#155-node-wide-emergency-stop-r-allstop) freezes all broker leases and renewals durably, including delivery after asynchronous refresh. Recovery is explicit; a partial or unknown node-wide result keeps admission closed. Already delivered tokens keep their vendor lifetime. The phone or terminal operator path admits the node-wide act; agent sessions cannot invoke it.

[R-TRANSFER](spec/broker.md#121-what-a-compromised-agent-can-do) makes code leave an isolated account only as platform-exported data after account-wide process absence. Export precedes retirement unless an operator explicitly waives the cleanup obligation. The orchestrator imports a repository-signed candidate through the board, obtains review of that exact commit and integrates through its existing path. Builds, tests and any execution of worker code belong only to R-VERIFY ephemeral runners on another machine; R-EXEC allows qualified light checks in agent accounts.

The shared time provider is available at
`github.com/relux-works/swarma-credential-broker/timeconf`. Services use the same
policy and collector implementation; see [the embedding example](docs/time-policy.md#embedding-the-public-provider).
Pin a commit until a tagged version exists. The production collector and protected
policy loaders require Linux, and `CollectorEntry()` must run first in `main`.
The [qualified-time consumer contract](docs/time-contract.md) specifies the
required durable continuity and fresh pre-pin path; production consumption remains
inactive. The approved [local handoff contract](docs/time-handoff.md), generic
[window-profile template](docs/time-window-profile.md) and mandatory
[macOS parity requirements](docs/time-handoff-macos.md) publish the next
interfaces and gates without a codec or accepting adapter.

## How it fits

For the inactive [new-mode topology](spec/secret-free-mode.md#2-processes-and-custody),
credential-holding services authenticate as themselves and need their own lease
**and** the originating caller's current narrowing authority for every use.
The agent-side runner receives only a placeholder; board/session hosts retain
the dispatcher boundary. Local release, service-use closure, account hold,
session stop and vendor invalidation have distinct lifetimes and outcomes.
The figures retain their legacy flow and add a separately labeled proposed
flow; neither is qualification evidence. New-mode delivery has its own
[publication gates](spec/secret-free-mode.md#13-publication-and-activation-gates)
and [unrun qualification witnesses](spec/secret-free-mode.md#12-qualification-witnesses);
existing synthetic, native, fake-503 and version evidence keeps its scope.

- Curator composes the plan on the caller's side. The first broker consumer is [curator-run under the agent account](spec/broker.md#31-first-consumer-and-execution-boundary): its narrow one-shot mode verifies and executes that plan, obtains the lease and starts the harness (owner decision D-EXECUTOR, 2026-10-11). The board runner and session host ask swarma-dispatcher to launch through curator-run; they do not embed broker clients.
- swarma-user-manager creates the per-agent OS users the broker identifies.
- curator-network-profiles names the egress an account may require.
- curator-trust and swarma-envelope define the long-term grant and signature forms. Broker v0 verifies its closed local envelope; a versioned adapter reconciles the forms before 1.0.

Accepted cycle-2 contracts add [binding replacement](spec/broker.md#72-creating-and-removing) for the same UID/generation with no widening or lease carry-over, [durable time watermark and monotonic destruction gates](spec/broker.md#151-service-user-and-time), and receiver-owned [bind/unbind outcome tables](spec/broker.md#132-methods). The root helper has no broker principal; unconfirmed cleanup after direct retirement remains a dispatcher/operator obligation. [Broker proxy-only egress](spec/broker.md#152-paths) is a v1 service-profile capability requiring qualification; login/refresh and resolver routes remain publication gates. The machine owns the child network binding, and the user manager owns the shared process fate table. [R-LOCK](spec/broker.md#131-transport) forbids holding the state lock across synchronous platform-service calls.

The dispatcher is a Unix-socket service from the first slice, with no caller sudo entry. Configured dispatchers use `revocation.check` for current admission evidence; bind/unbind reconciliation uses receiver-owned `effect.observe`. [Fenced local restoration](spec/broker.md#154-fenced-local-restore-and-reopen) keeps authorization and auto-start closed until acknowledged revocations are recovered against evidence outside the restored failure domain, or old authorization roots are replaced and rights explicitly reissued. [Publication and qualification gates](spec/broker.md#18-open-questions) remain open; these are design requirements.

The first protected provider launch is Claude with an explicitly enrolled `setup-token`; Codex personal-plan external tokens follow in slice 1. The [provider × source × channel × phase table](spec/broker.md#52-kinds) distinguishes those targets from retained per-home authentication and later or unresolved lanes. Source-policy v1 keeps `per-home` when no entry is configured; v2 requires an explicit entry and migrates existing logins to explicit `per-home`. The first node and broker stores use protected 0600 files on macOS and Linux; Keychain and Secret Service backends are later work.

The repository, standalone binary and service account are named `swarma-credential-broker`; `curator broker` is the Curator front end. The earlier `curator-broker` CLI spelling is historical design text, with no shipped alias or migration. Signed domain tags are `swarma-credential-broker grant/1` and `swarma-credential-broker revocation/1`; `broker/1` remains the peer-authenticated transport. The [grant dialect boundary](spec/broker.md#66-relation-to-the-trust-design) and [key classes](spec/broker.md#43-trust-root-and-key-classes) distinguish this v0 design from the future keeper model. Managed identity checks read the root-owned ledger at `/opt/swarma/lib/user-manager/ledger.json` ([§4.2](spec/broker.md#42-principals)). These are design contracts, not runtime qualification claims.

The [registration](diagrams/agent-registration.puml), [launch](diagrams/lease-at-launch.puml), [enrolment](diagrams/enrol.puml), [Codex renewal](diagrams/codex-renewal.puml) [binding replacement](diagrams/binding-replacement.puml) and [revocation](diagrams/revoke-and-unbind.puml) sequences describe the intended flows. The module figures below show their component, recovery, state and storage boundaries. All are design contracts; visible “unspecified in spec” notes preserve gaps rather than supply implementation decisions.

[Launch-time lease lifetimes](spec/broker.md#85-renewal-release-and-reports) distinguish an env launcher replaced by exec from a live external-token client that can renew and release. The [cleanup policy remains open](spec/broker.md#18-open-questions) where the design does not publish a release point or record-reclamation rule.

| Figure | PlantUML source | Defining specification |
|---|---|---|
| M-CB1 — v0 components and process identities | [components.puml](diagrams/components.puml) | [§3 Components](spec/broker.md#3-components), [§3.1 First consumer](spec/broker.md#31-first-consumer-and-execution-boundary), [§4 Identities](spec/broker.md#4-identities-and-trust) |
| M-CB2 — lease refusal and recovery | [lease-recovery.puml](diagrams/lease-recovery.puml) | [§6.4 Revocation](spec/broker.md#64-revocation), [§8 Leases](spec/broker.md#8-leases), [§9 Codex auth owner](spec/broker.md#9-codex-auth-owner), [§15.4 Fenced restore](spec/broker.md#154-fenced-local-restore-and-reopen), [§15.5 Node-wide freeze](spec/broker.md#155-node-wide-emergency-stop-r-allstop) |
| M-CB3 — account, binding, lease and grant states | [record-states.puml](diagrams/record-states.puml) | [§5.1 Account record](spec/broker.md#51-record), [§6.4 Revocation](spec/broker.md#64-revocation), [§7 Bindings](spec/broker.md#7-bindings), [§13.2 Observations and verdicts](spec/broker.md#132-methods), [§8.3 Lease record](spec/broker.md#83-response-and-lease-record) |
| M-CB4 — owned storage, socket and removal | [storage-layout.puml](diagrams/storage-layout.puml) | [§5.3 Secret store](spec/broker.md#53-secret-store), [§12.4 Files](spec/broker.md#124-files), [§15 Installation and lifecycle](spec/broker.md#15-installation-and-lifecycle) |

See [qualification](docs/qualification.md) for the protected release-evidence
record and the pending `qualify-codex` administrative command. Its isolated
candidate observers measure version, schema and catalog. Private synthetic
admission controls now cover account, release qualification and ended leases;
seven fake owner-core pairs exercise durable store loss, absence recovery,
ambiguous refresh, rotation crashes, interrupted cleanup, daemon death and
competing replacements. The lifecycle pairs use independently supervised
singleton synthetic writers; they supply no real
vendor-subtree absence evidence.
The remaining pending rows still prevent production qualification.

An [inactive immutable storage fixture](docs/immutable-storage.md) provides bounded
content retention and exact reads; it has no production consumer or current-root authority.

An [inactive generation selection fixture](docs/generation-cas.md) adds shared
RAM-local comparison, attempt reconciliation and outcome fencing over retained
immutable units. It grants no production currentness or durable recovery authority.

## Tools

For diagram-source validation, an installed PlantUML can render both labeled
views in each source with `plantuml -o <absolute-scratch-directory> diagrams/*.puml`.
Keep generated images and validation logs in private scratch, outside versioned
source. This command is documentation validation, not runtime qualification;
an unavailable renderer leaves rendering UNRUN. Python 3 temporary checks may
validate local links, anchors and exact changed paths; finite text checks do not
prove semantic correctness or absence of secrets.

This repository contains specifications, PlantUML sources, declarative JSON
vectors, a Linux Go daemon and runner with fixture tests, and a
[service-user migration script](docs/service-user-migration.md). The standalone
runner command refuses execution until protected policy and broker transport
are integrated. Only isolated fixture tests are supplied for the migration tool;
real installation and writer-lifecycle qualification remain pending.
The daemon uses Go 1.25 or later. The contained owner adds the pinned
`github.com/godbus/dbus/v5 v5.1.0` dependency for user-manager D-Bus and private
Unix descriptor passing; production never invokes `systemd-run`. Development
checks use Go 1.26.10 through `CURATOR_GO`, with `GOTOOLCHAIN=local`; preserve the
configured `GOCACHE` and `GOPATH`. Tests use synthetic tokens and local
fixtures. Default tests run a synthetic Go vendor; tagged manager tests run only
isolated helpers and that fake vendor, with fresh homes. No logged-in home is used.

| Tool | Purpose and command | Outputs |
|---|---|---|
| Go immutable storage fixture | `GOTOOLCHAIN=local GOMAXPROCS=2 GO="$CURATOR_GO" SWARMA_TEST_UNPRIVILEGED=1 "$CURATOR_GO" test -p=2 ./internal/freshstore ./internal/store -run '^(TestFresh\|TestImmutable)' -count=1`; [bounded contract and build command](docs/immutable-storage.md#focused-validation) | Synthetic files under isolated `TMPDIR`; full logs and overlay controls in private scratch outside Git |
| Go generation selection fixture | `GOTOOLCHAIN=local GOMAXPROCS=2 go test -p=2 -count=1 -timeout=90s ./internal/generationcas`; [contract and focused validation](docs/generation-cas.md#focused-validation) | Synthetic files under isolated `TMPDIR`; full logs and overlay controls in private scratch outside Git |
| Bash migration tool (5.3 or later) | `bash scripts/migrate-service-user close-admission <absolute-config>`, then operator reconciliation, then `bash scripts/migrate-service-user migrate <absolute-config>`; see the [operator guide](docs/service-user-migration.md) for prerequisites and required site driver | Protected run directory: preflight metadata, append-only intent/recovery journal and phase records; fixed sanitized stderr |
| Bash / Python 3 fixture tests | `bash -n scripts/migrate-service-user`; `bash -n tests/migration/run`; `bash tests/migration/run <absolute-fresh-scratch-directory>`; Python standard-library doubles simulate privileged commands | Isolated account/filesystem/manager models, call records, canaries and narrowing-control logs in the supplied scratch directory |
| GNU coreutils / Linux process table | `sleep 0.05` bounds child-completion probes; `/proc/<pid>/stat` checks direct parent and start time before signaling. See the [operator guide](docs/service-user-migration.md) for tri-state observations and the remaining numeric PID race | Unconfirmed owned PIDs are reported on sanitized stderr; no process-table contents are copied |
| strace (Linux fixture tests) | `MIGRATION_TEST_FILTER='ProcessLookup*' bash tests/migration/run <absolute-fresh-scratch-directory>` injects EACCES/EIO into actual process metadata syscalls; Python's standard-library `ctypes` enables a test-only subreaper for abandoned fixture children | Exact injected-call traces, child/reclose evidence and narrowing-control logs under the supplied scratch directory |
| Git | Review whitespace with `git diff --check`; verify signed changes with `git log --format='%G? %an %s' origin/main..HEAD` | Terminal; capture private evidence in a scratch `.tmp` directory outside the versioned tree |
| Go importable v0 client | `GO="$CURATOR_GO" "$CURATOR_GO" test ./brokerclient -count=1`; [API and observer protocol](docs/brokerclient.md) | Synthetic socket/external-module fixtures in test-owned `TMPDIR`; use a short isolated root for Unix socket limits and private logs outside Git. No provider or cross-UID deployment qualification |
| Go 1.25+ | Build with `go build -o ../.tmp/swarma-credential-broker ./cmd/swarma-credential-broker`; build the fake with `go build -o ../.tmp/fake-app-server ./internal/runner/testdata/appserver`; check with `go vet ./internal/runner ./cmd/swarma-credential-broker`, `gofmt -l internal/runner cmd/swarma-credential-broker`, and `GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race ./internal/runner -count=1` | Set `CURATOR_GO` to the selected Go executable. Helper builds use explicit `GO` or the running toolchain GOROOT, and verify the same Go version. Binary in private scratch; tests build the fake app-server and command under `TMPDIR` (set it to a scratch directory outside the versioned tree) |
| strace (Linux tests) | Reproduce real proc metadata disappearance with `GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race ./internal/runner -run 'Test(CommandProcDisappearance\|StopProcDisappearance)$' -count=1 -v`; development runs skip with `UNVERIFIED` when strace or ptrace permission is unavailable (a native typed-errno probe runs first). Require every observation row with `RUNNER_QUALIFICATION=1 GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race ./internal/runner -count=1`; unavailable strace/ptrace or a skipped required row fails with a named `UNVERIFIED` diagnostic | Test-owned syscall traces under `TMPDIR`; no errno substitution or live account access |
| Python 3 / Linux seccomp (fixture control) | `GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race ./internal/runner -run '^TestTraceAvailability$' -count=1 -v`; the x86_64 `testdata/ptrace_denied.py` wrapper returns EPERM only for ptrace in its own subprocess tree | Named unavailable and applied-assertion controls in test output; no host policy changes |
| Qualified-time provider (inactive) | `go test ./timeconf -count=1 -v`; `go test ./cmd/swarma-credential-broker -run '^TestQualification(AuthorityContainment\|Containment\|TimeFixture)' -count=1 -v`; see [API and settlement format](docs/qualified-time-api.md). `NewConsumer` always returns typed activation refusals on consumption until the independent witness and native path are qualified | Isolated test-owned records, original evidence and receipt files under `TMPDIR`; logs belong in private scratch. No real clock service or account access |
| Handoff arithmetic consistency (Python 3) | `python3 tests/time-handoff-vectors.py`; checks the [documented vectors](docs/time-handoff.md#executable-arithmetic-controls), source/reserve/cap assumptions, exact negative predicates and strict deadline neighbour | Unit-check output only; no codec, native timing, consumer-use implementation or qualification evidence. Logs belong in private scratch |
| Retained-original interface (inactive, Linux) | `go build ./timeconf`; `go vet ./timeconf`; `go test ./timeconf -run '^TestClosedOriginalReader$' -count=1`; see [reader semantics](docs/time-handoff.md#original-reader-and-witness-interfaces) | Compile and typed closed-refusal evidence only; no accepting reader, handoff or native qualification. Capture logs in private scratch with the same toolchain/TMPDIR rules below |
| Consumer time fixtures (Linux, tests only) | `go test -tags=swarma_timeconf_fixture ./timeconftest -count=1`; default imports refuse activation. Import only from tagged `_test.go` files; see [consumer fixture guidance](docs/qualified-time-api.md#consumer-test-fixtures) | Synthetic records and receipts in test-owned empty mode-0700 directories under `TMPDIR`; fixture authority is excluded from default production builds |
| Inactive handoff controls (Linux) | `go test ./timeconf -run '^(TestHandoff|TestVerifyWindowCompiledPurity)'`; `go test -tags=swarma_timeconf_fixture ./timeconf -run '^TestHandoff'`; [API and limits](docs/time-handoff-api.md) | Test-owned `TMPDIR` holds synthetic originals and the symbol-bearing purity inspection binary; no production admission |
| Go public time provider | Build the separate consumer with `go test ./timeconf -run '^TestExternalModuleConsumer$' -count=1 -v`; its test module lives in `testdata/timeconf-consumer` and also checks that test-only exports are unavailable | Consumer executables in test-owned temporary directories; no system policy or collector is accessed |
| chrony / chronyc (optional, Linux) | Independent time reports through fixed bounded commands and protected recursive `sourcedir`/`confdir` inventory; collector execution requires Linux 5.11+, proc access and the explicit `timeconf.CollectorEntry()` hook for descriptor isolation. Run the read-only diagnostic with `go test -tags=timeconf_smoke ./timeconf -run '^TestHostTimeConfidenceSmoke$' -count=1 -v`; see [time confidence](docs/time-confidence.md) | Parsed numeric verdicts in private scratch logs; no source or system changes |
| x/sys/unix | Pin process identities with Linux pidfds before signalling owned descendants; pinned by `go.mod`, downloaded by Go commands | Go module cache |
| go-toml/v2 | Parse credential-source configuration, including nested and quoted keys; pinned by `go.mod`, downloaded automatically by Go commands | Go module cache; no generated repository artifacts |
| Python 3 | Parse vector JSON with the command in [vectors/v0](vectors/v0/README.md); strict canonical-byte/link checks use temporary validation scripts | Terminal and private scratch logs; scripts are not shipped tooling |
| Codex CLI | Measure a protected selected release through `swarma-credential-broker qualify-codex --executable "$CANDIDATE" --evidence-dir "$EVIDENCE" --fixtures`; the isolated version/help/schema/catalog commands and tagged checks are in [qualification](docs/qualification.md) | Bounded measurements in private `run.json`; every candidate process runs under the egress boundary in a fresh empty HOME/CODEX_HOME, removed afterwards |
| systemd user tools (Linux) | Inspect containment with `systemctl --user show <probe-unit>`; a bounded probe can use `systemd-run --user --unit=<probe-unit> --property=KillMode=control-group --property=RuntimeMaxSec=5s /usr/bin/true` | User-manager state and private scratch evidence; stop only the probe's own unit |
| godbus/dbus v5.1.0 | Direct D-Bus transport in `internal/authowner`; fetch with `"$CURATOR_GO" mod download github.com/godbus/dbus/v5`; checks below exercise it | Module cache and `go.sum`; no token material in unit properties |
| Synthetic owner lifecycle controls | `GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test ./internal/qualify -run '^TestOwner(TransientAmbiguousPair\|TransientBackoffResolution\|RotationCrashPair\|CleanupInterruptedPair\|DaemonDeathPair\|ReplacementContentionPair\|Parallel.*\|LifecycleRows)$' -count=1 -v`; see [scope and budgets](docs/qualification.md#synthetic-writer-lifecycle-pairs) and [closed close-timeout diagnostics](docs/owner-close-diagnostics.md) | Generated roots, synthetic native bytes and parent-bound artifacts under test-owned `TMPDIR`; no real account or network endpoint |
| Qualification command | `swarma-credential-broker qualify-codex --executable "$CANDIDATE" --evidence-dir "$EVIDENCE" --fixtures`; live syntax, tagged real-candidate checks and exit codes in [qualification](docs/qualification.md) | Owner-only `run.json` with isolated measurements, egress summaries and typed launcher diagnostics; protected admission fence beside static configuration. With protected `--fixture-config`, thirteen transport/admission/lease rows and seven fake owner-core rows execute paired controls with attested origin and protected artifacts; two runner rows also pass under the [measured-code testimony contract](docs/runner-testimony.md); peer remains UNRUN pending its origin authority (see [Execution evidence origin](docs/qualification.md#execution-evidence-origin)), so no qualified entry is published |
| Synthetic owner checks (Linux/amd64) | `go test ./internal/qualify -run '^TestOwner' -count=1 -v`; generated private state, fake manager/native peer/time and real owner/store/lease libraries | Test temporary roots are removed after both attested owner epochs join; row artifacts use the selected private evidence directory. No actual account, vendor execution or production activation |
| Go egress launcher | `GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" build -o "$TMPDIR/egress-launcher" ./internal/egress/cmd/launcher`; narrow checks and tagged version/HTTP probes are in [egress boundary](docs/egress-boundary.md) | Explicit private scratch: executable, bounded boundary JSON and connect trace; no account access |
| Go | Build with `"$CURATOR_GO" build -o "$TMPDIR/swarma-credential-broker" ./cmd/swarma-credential-broker`; vet with `"$CURATOR_GO" vet ./...`; format-check with `"$("$CURATOR_GO" env GOROOT)/bin/gofmt" -l .` | Binary and captured logs in the selected private scratch directory; format-check output must be empty |
| Runner trace origin (Linux/amd64, no row credit) | `GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race ./internal/egress -run '^TestRunnerOrigin' -count=1 -v`; see [testimony scope](docs/runner-testimony.md) | Synthetic runtime/runner fixtures and nested boundary reports under `TMPDIR`; capture logs in private scratch, using the host resource wrapper when required |
| Runner completion exchange (Linux/amd64, no row credit) | `GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race ./internal/qualify -run '^TestRunnerTestimony' -count=1 -v`; closed post-Command exchange and typed outcome checks | Private short `TMPDIR` for the measured case, seqpacket listener and synthetic app-server; capture logs in private scratch with the required host wrapper |
| Runner parent effect integration (Linux/amd64) | `GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race ./internal/qualify -run '^TestRunner(Parent.*\|WatcherCompleteness\|AdmissionExecOnly)$' -count=1 -v`; traced/testimony pairs with parent broker, store and filesystem checks | Synthetic cases and bounded observer data under a short private `TMPDIR`; logs in private scratch with the required host wrapper; observations alone cannot grant artifact credit |
| Runner artifact gate (Linux/amd64) | `GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race ./internal/qualify -run '^Test(RunnerArtifact.*\|RunnerParentImageMeasurement\|RowsHarness)$' -count=1 -v`; accepted-image, outcome, private proof and paired artifact checks | Protected synthetic row artifacts and explicit `measured-code-testimony` report entries under test-owned `TMPDIR`; use the host resource wrapper; no production tuple publication |
| Hosted Linux CI | `.github/workflows/linux-ci.yml`; exact local module/build/vet/format/test commands and the host-fixture inventory are in [Linux CI](docs/linux-ci.md). The test step uses `SWARMA_TEST_UNPRIVILEGED=1` and adds a bounded egress/wire/store race check | Verbose hosted job logs; local logs and fixture scratch belong outside the versioned tree; no account credentials or qualified entries |

Create a short, real scratch path outside the versioned tree (no symlink),
then run these package-scoped checks. Socket tests provision their own mode-0755
subdirectories; the scratch directory can remain private. The default eight-second deadline is exercised separately; `-short`
excludes only that longer test. The optional peer qualification is a separate
binary whose PENDING exit cannot be mistaken for a green package test.

```sh
export TMPDIR="$(mktemp -d /tmp/broker.XXXXXX)"
export GOTOOLCHAIN=local
"$CURATOR_GO" build -o "$TMPDIR/swarma-credential-broker" ./cmd/swarma-credential-broker
"$CURATOR_GO" vet ./...
"$("$CURATOR_GO" env GOROOT)/bin/gofmt" -l .
"$CURATOR_GO" test -short -count=1 -timeout=180s ./internal/wire ./internal/policy ./internal/store ./internal/owner ./internal/lease ./internal/server ./cmd/swarma-credential-broker
"$CURATOR_GO" test -short -race -count=1 -timeout=180s ./internal/lease ./internal/server
"$CURATOR_GO" test -short=false -count=1 -timeout=15s -run '^TestDefaultRenewDeadline$' ./internal/lease
"$CURATOR_GO" test -c -tags=peeraccounts -o "$TMPDIR/peer-qualification" ./internal/server
"$TMPDIR/peer-qualification" -test.run '^TestConfiguredPeers$' -test.v
"$TMPDIR/peer-qualification" -test.run '^TestConfiguredPeerConnect$' -test.v
```

The standalone qualification commands require `BROKER_TEST_PEER_CONFIG`,
pointing to a broker-owned 0600 JSON fixture configuration with exactly `allowed_peer`, `foreign_peer`,
`socket_directory`, and `helper_executable`. The first two values are configured
OS account names, resolved privately at runtime. The foreign UID must differ
from broker and allowed UIDs. The socket directory must already be daemon-owned
mode 0755, with intended ancestor permissions, and the helper must be an
operator-installed copy of the
same peer-qualification binary accessible to those accounts. The gate uses
`sudo -n -u` only for these configured accounts and verifies the helper's effective
UID. It never creates accounts or changes socket permissions. The helper keeps
tokens in memory and emits only a lease ID. Missing configuration, unusable
accounts, an inaccessible helper or socket returns **69, PENDING**, with no
qualification credit. A protocol assertion failure returns 1. Normal tests always
exercise the actual same-UID kernel path; injected peer failures are model
coverage and do not qualify foreign-account behavior. The separate connection
test treats a started helper's inability to connect as an assertion failure; its
positive control uses the same configuration and binary.

## Daemon configuration and current boundary

This is the existing static extraction policy, not service-principal or
use-through-service authorization. The proposed mode requires a separately
published compatible [dialect and policy](spec/secret-free-mode.md#13-publication-and-activation-gates);
no new configuration field, method or credential-holding service is enabled by
these daemon commands.

Run `swarma-credential-broker daemon --config <protected-config>` and
`swarma-credential-broker status --config <protected-config>`. Use
`--init-store` with `daemon` only to create new, empty metadata directories; it
never adopts a nonempty store whose installation marker is missing. Existing
socket paths are refused. The socket is created with mode 0666 in an
existing daemon-owned directory of exactly mode 0755 outside the store. Startup
refuses unsafe directories, ancestors and existing socket-path entries; it does
not change directory permissions. Kernel peer credentials and the static UID
allowlist authorize clients. The [socket permission notes](docs/socket-permissions.md)
describe the checked R2 ancestor guarantees and the stricter dedicated-service
requirements. Cross-UID reachability is an installation qualification gate.
Store directories are 0700; records and stable lock files are 0600. Configuration is a regular, broker-owned 0600 file, with no
symlink, duplicate or unknown member. JSON lists must use arrays, including `[]`
for an empty allowlist.

| Configuration member | Required value |
|---|---|
| `socket_path`, `store_root` | Operator-selected absolute paths; distinct socket and protected metadata locations |
| `policy.installation_id` | Random, never-reused installation identity |
| `policy.policy_generation` | Positive, monotonically increasing safe integer |
| `policy.broker_uid` | Configured broker UID; must match the daemon's effective UID |
| `policy.executable`, `policy.executable_sha256` | Approved absolute executable path and lowercase SHA-256 |
| `policy.max_lease_seconds` | Positive finite duration, normally 3600 |
| `policy.time_confidence` | Optional protected [time-confidence policy](docs/time-confidence.md); absent means off, broker backward tolerance must be zero, production owner remains stopped |
| `policy.accounts` | Array of the account entries below |

Each account has `label`, `vendor_account_id`, `allowed_uids`, `profiles`,
`endpoint`, `release_version`, `qualification_id`, `enabled`, and
`network_required`. Account labels and vendor IDs are unique. Endpoints use
HTTPS. Static admission requires the kernel UID, profile and account allowlist;
clients cannot supply authority through a binding. The refresher subset uses
release `0.163.0`, the external-token channel and no enforced network profile.
A qualification reference in configuration does not activate an owner.

`SIGHUP` rereads protected configuration, requires a higher generation in the
same installation and unchanged socket/store locations, then closes old
connections. Newly added accounts require their protected stores to be prepared
and the daemon restarted. `SIGTERM` and `SIGINT` stop this daemon's listener and
connections. Diagnostics contain fixed codes only.

The auth-owner interface is in `internal/owner`. Its adapter must establish
writer absence, durable outcome, account identity, independent freshness,
trusted time and the exact release qualification before returning a usable
snapshot. Qualification carries the matching policy generation, immutable evidence
reference and executable digest; a stale qualification cannot survive policy
replacement. Its refresh method receives the expected generation and must serialize
writers across replacement. The lease engine holds no state mutex during owner
I/O. After that I/O, it checks lease state and authority and registers the
publication under policy/account fences, then writes outside those state locks.
Release closes new publication admission for the lease, revokes its registered
writes and waits for them to stop before durable release acknowledgement. Policy
replacement closes admission and does the same for the old generation before
publishing its durable successor. Revocation interrupts the affected write with
an expired socket deadline. The writer waits for that interrupt to finish before
retirement or reuse of the connection, so a fully written frame preserves the
connection for its following release receipt. A partial frame fails its write and
closes the connection; it is never a successful delivery.
The write deadline also ends at the lease/token/account authorization limit.

Arrival deadlines start before lookup. A lease-label index avoids locking
unrelated accounts, state admission is cancellable, and expired-waiter cleanup
never holds up the caller's timeout response. When the last waiter leaves a
queued operation, cleanup removes both its admission entry and physical FIFO
entry while preserving the order of remaining operations. Per-connection writer
contention keeps the original request deadline; a non-draining socket cannot serialize
other leases' state transitions. Filesystem publication also uses revision CAS
outside the request state lock. The owner scheduler
uses the shared proactive gate; admitted demand suppresses proactive work.
The normative [connection request lifecycle](docs/request-lifecycle.md) defines
ID reservation and retirement, response completion, and the separate queue,
waiter, writer and publication resources.
Before admitting a refresh after a snapshot, the engine checks for live demand.
An already admitted attempt may reconcile under the manager lifetime, even when
its response waiters disappear; an abandoned snapshot starts no new refresh.
Durable time watermarking, attempt intent, containment, vendor-store reload,
recovery and backoff belong to that adapter. Integrations must supply the
conservative authorization clock through lease options. No command enables the
test fake or bypasses the stopped production adapter.

The store root reserves `policy-watermark.json` (`policy-watermark/1`) for the
installation's monotonic policy floor. It is flushed before initial authority or
a replacement generation becomes visible, including when no lease has yet been
written. Startup refuses a policy below that floor or any retained lease record;
uncertain watermark publication closes admission until restart. Missing watermark
evidence is initialized only in a fresh store, never reconstructed from an
existing account directory. Older experimental stores need explicit offline
migration; `--init-store` cannot erase this fence.

Within account directories, `lease-<id>.json` belongs to the lease engine and
`owner-*.json` is reserved for the contained owner (intent, evidence, checkpoints
and qualification). The store still checks canonical bytes and protection for
all records. The owner must validate and reconcile its namespace before returning
a usable snapshot; the lease engine ignores that namespace and rejects unknown
non-owner records. Checkpoints use expected-revision atomic `Account.Put`;
attempt history uses immutable `Account.Append` with attempt-wide increasing revisions.

All record writers share the readers' inclusive 1 MiB canonical-byte ceiling.
Oversized writes return `store.ErrTooLarge` before filesystem mutation and retain
the previous record; see [record size and caller handling](docs/store-records.md).

Lease metadata contains only protected digests, generations and authority. Tokens
remain in memory and framed socket responses. The canary lifecycle test scans
all metadata writes at durability checkpoints and all status output, including
full token and digest prefixes. This in-process test does not capture daemon
stdout/stderr and supplies no process-log qualification. Tests also cover canonical framing, schema
closure, queue/capacity bounds, lost responses, cancellation, FIFO, policy
replacement, expiry, uncertain publication, symlinks and restart.

The vector tests instantiate role UIDs, binding digests and access tokens from
fixtures. All transport and renewal vectors exercise their core contracts;
`renew-late` uses a shortened deadline and the real eight-second default has its
own test. Runner callback/turn effects and admission source/home-conflict vectors are
covered by the runner fixture tests; live release qualification remains pending. The contained owner
now exercises refresh recovery with a fake manager and vendor; the core's older
snapshot tests remain separate evidence. Enrolment, cutover, independent restore
reconciliation and actual vendor qualification remain deferred. See the
[owner coverage and limits](docs/auth-owner.md).

## Contained owner checks

Owner tests build the focused, race-enabled `internal/authowner/testdata/vendor`
fixture once with `GO` (or the current Go toolchain), under `TMPDIR`, and remove
it at exit. Every owner construction still hashes that executable; large test
sequence tables are excluded from the fixture image.

`internal/authowner` implements the refresh adapter as a library. The daemon
command still uses its stopped adapter: enrolment, exact release qualification
and independent time/restore confidence must precede activation. The library
constructor performs recovery before admitting snapshots. A real manager also
requires a successful empty-home `Probe` using an approved token-free echo helper,
and the owner process must belong to the configured daemon service. The helper
is supplied explicitly by installation; no ambient executable is selected.

Run only the affected packages. Put `TMPDIR` in an absolute private scratch
directory outside the checkout and preserve the configured caches:

```bash
export GOTOOLCHAIN=local
"$CURATOR_GO" test -race -short -count=1 -timeout=90s ./internal/authowner ./internal/store ./internal/owner ./internal/lease
"$CURATOR_GO" test -race -tags=realmanager -count=1 -timeout=60s ./internal/authowner -run '^TestReal'
"$CURATOR_GO" vet ./internal/authowner ./internal/store ./internal/owner ./internal/lease ./cmd/swarma-credential-broker
```

The second command needs a reachable systemd user bus, cgroup v2 and required
service sandbox features. Failure is a failed gate, never a skipped success.
Each test creates a random `scb-test-<random>-` prefix for its own daemon,
readiness probes and writers. Daemon unit and writer prefix are configurable.
Cleanup stops and unloads only allocated names on every test path, then requires
an exact not-found response for each name. Never substitute a deployed daemon
name or perform manager-wide cleanup. Verbose test logs contain each allocated
name and its cleanup result; capture those logs in private scratch.

Real-manager tests verify the 120-second configured ceiling and exercise runtime
expiry using a shorter control. They measure the two-second stop timeout with a
SIGTERM-ignoring grandchild and confirm recursive cgroup absence. They do not
measure a full 120-second elapsed run or qualify the native vendor. Native-vendor
refresh rows remain PENDING: a refresh URL override does not isolate background
vendor egress, so no native-vendor test entry point is shipped.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).

With protected fixtures on Linux/amd64, the qualification row harness credits
twenty attested transport/admission/lease/owner pairs and two runner pairs with
protected artifacts. Runner entries use the explicit
[measured-code testimony class](docs/runner-testimony.md). Peer remains UNRUN
pending its supervisor-origin decision; see
[Execution evidence origin](docs/qualification.md#execution-evidence-origin).
