# Public interfaces and integration seams

Resolve imports against the consumer's frozen pin. [go.mod](../../../../go.mod)
declares the module and Go version. Packages under `internal/` are repository
implementation components, not an external SDK.

## Linux broker clients: OWNER-SITTING for live interaction

Import `github.com/relux-works/swarma-credential-broker/brokerclient`.
The [public facade](../../../../brokerclient/client_linux.go) aliases the
[runner types](../../../../internal/runner/types.go) and
[allowlist types](../../../../internal/wire/types.go); the transport is
[the socket client](../../../../internal/runner/broker_client_linux.go).
This is the version-1 `codex-refresher-v0` contract, not signed-grant evaluation,
revocation observation or the proposed secret-free dialect.

| Interface | Existing contract; source inventory only |
|---|---|
| `DialWorker(ctx, path) (Worker, error)` | Two-second dial ceiling; sends no protocol bytes. Required order is `VerifyServer`, `Hello`, then worker operations. |
| `Worker` | `VerifyServer(context.Context, uint32) error`; `Hello(context.Context, HelloRequest) (HelloResult, error)`; `Request(context.Context, LeaseRequest) (Lease, error)`; `Renew(context.Context, RenewRequest) (Lease, error)`; `Release(context.Context, string) error`; `Close() error`. |
| `DialObserver(ctx, path, expectedBrokerUID) (*Observer, error)` | Kernel server-UID verification precedes hello; dial, verification and hello share a two-second deadline. |
| `Observer` | Only `Check(context.Context, AllowlistRequest) (AllowlistResult, error)` and `Close() error`. No acquisition, renewal, release or generic RPC method. |
| `Refusal` | Fixed `Code` and process `Status`; do not expose raw diagnostics. |

Worker hello uses `HelloRequest{Versions: []int{1}, Profile: ProtocolProfile}`.
The facade also exports `Binding`, `HelloResult`, `LeaseRequest`, `Executor`,
`RenewRequest`, `Lease`, `AllowlistRequest` and `AllowlistResult`.
`Lease.Token` is caller-owned material; `Lease.Erase()` clears that byte slice
and drops material-bearing plan/account metadata, without proving erasure of
copies or Go runtime strings. This is a custody limitation, not an agent workflow.

Observer checks have a two-second overall ceiling including queue wait and
validation; caller cancellation can shorten it. A nil/zero observer returns a
zero result and `Refusal{Code: "allowlist_unavailable", Status: 69}` without I/O.
A successful check matches request ID, complete tuple, binding and served/hello
generation. It neither checks mutable grants/revocations nor establishes owner
health, network enforcement, future admission or credential availability.
The [client guide](../../../../docs/brokerclient.md) explains the observation-to-use
race. Never route worker credentials through an observer or dispatcher.

The existing [public tests](../../../../brokerclient/client_linux_test.go) contain
synthetic protocol controls, server-identity refusals and an external-module
compile fixture. They are source evidence, not instructions to contact a broker.

## Time confidence: separate data checks from activation

Import `github.com/relux-works/swarma-credential-broker/timeconf` for pure parsing
or consumer integration analysis. `ParseTracking` and `ParseAuthData` parse bounded
in-memory reports in [parse.go](../../../../timeconf/parse.go). `ParseSources` is
only a test export in [export_test.go](../../../../timeconf/export_test.go), not
an external production API. See [inert validation](inert-validation.md).

[Provider](../../../../timeconf/provider.go) supplies `New`, `Sample` and
`StartSample`. `Policy.Validate`, `DecodePolicy` and `ServicePolicy` live in
[policy.go](../../../../timeconf/policy.go). Pure policy decoding does not read,
install or authenticate a protected deployment policy.

The actual caller-supplied seam is constructor injection: write a synthetic
`Collector` implementing `Collect(context.Context, Policy) (Evidence, error)`
and a synthetic `Clock` implementing `Read(context.Context) (ClockPoint, error)`,
then pass those instances to `New(p, collector, clock, incident)`. There is no
registration stage or plugin loader. For an in-memory validation design, use
fixed public evidence and clock points; make the incident callback retain only
fixed codes, not output. The existing `providerFixture`,
`TestCollectorErrorsNeverTrust` and `TestEvidenceBounds` in
[provider_test.go](../../../../timeconf/provider_test.go) pair acceptance with
collector-error, source and numeric-bound refusals. A sample is not durable
consumption or permission to issue credentials.

Native collection is outside inert agent examples. Linux
`LoadPolicy`, `LoadServicePolicy`, `Production`, `SystemCollector` and
`SystemClock` are [deployment APIs](../../../../timeconf/collect_linux.go);
[CollectorEntry](../../../../timeconf/exec_linux.go) must be first in `main`
for that re-execution path. They do not create authority from an unprotected
caller input. Do not run collectors or inspect installed policy for this skill.

[NewConsumer](../../../../timeconf/consume_linux.go) installs `ClosedWitness` and
has no qualified production path. `ConsumeBeforePin` returns an
`ActivationRefusal` with `Reason: "path_unqualified"` before collection on that
path. `EncodeReceipt`/`DecodeReceipt` in
[receipt.go](../../../../timeconf/receipt.go) check structure and interval rules;
codec success does not authenticate evidence. The same distinction applies to
`EncodeHandoff`/`DecodeHandoff` in [handoff_linux.go](../../../../timeconf/handoff_linux.go).
`ValidateHandoffWitness` always refuses with `witness_unavailable`.
`VerifyWindow` in [window_linux.go](../../../../timeconf/window_linux.go) is a pure
checker, but its opaque preparation has no production constructor.
[ClosedOriginalReader](../../../../timeconf/original_linux.go) is the only shipped
original reader and refuses; implementing `OriginalReader` does not install it
into a production consumer. These are not activation or plugin seams.

The Linux `github.com/relux-works/swarma-credential-broker/timeconftest` package
is test support, not a production backend. Its
[default stub](../../../../timeconftest/disabled_linux.go) refuses `New` with
`fixture_tag_required`; the [tagged facade](../../../../timeconftest/enabled_linux.go)
uses `swarma_timeconf_fixture`. Any future consumer-test work must keep imports
in tagged test files and approved applications on default tags; see the existing
[fixture containment contract](../../../../docs/qualified-time-api.md).
No tagged builds, fixture storage, installation or qualification are performed
by this skill's inert example.
