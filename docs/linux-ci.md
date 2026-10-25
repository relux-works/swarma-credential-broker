# Linux continuous integration

The workflow in `.github/workflows/linux-ci.yml` runs on pull requests and pushes
to `main`. It uses `ubuntu-26.04`, Go 1.26.10, `GOTOOLCHAIN=local`, read-only
repository permissions, commit-pinned checkout/setup actions, no persisted
checkout credentials and no action cache. The job has a 30-minute deadline.
It verifies modules, builds, vets, rejects every file listed by `gofmt -l .`,
and runs verbose tests. It does not provision accounts or qualify a release.

## Runner capabilities

[GitHub's runner reference](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
describes this label as an x64 VM, rather than the single-CPU container image.
The [image inventory](https://github.com/actions/runner-images/blob/main/images/ubuntu/Ubuntu2604-Readme.md)
lists a kernel newer than the Linux 5.11 minimum used by the collector, Python
and wget. The exact version label avoids the changing `ubuntu-latest` alias;
it does not pin an immutable weekly image build.

The design needs child-process tracing, pidfds, procfs, Unix credentials and
seccomp user notification. It does not create user namespaces or require them
to be enabled. [Yama's documented descendant relationship](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html)
allows ordinary parent/child tracing at scope 1. The
[seccomp API](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
permits unprivileged filters after `no_new_privs`; it does not require an
administrator capability for this path. These support keeping the ordinary
egress, origin, collector fixture and socket tests in CI. Their real assertions
remain authoritative: the image documentation is not a successful runtime
probe. Seccomp or origin startup failures fail those tests; CI does not weaken
the boundary or substitute successful measurements.

The image inventory does not guarantee strace or an active systemd user manager.
Tracing tests probe the actual tool and native tracing permission. They execute
when available and report an explicit shared-helper skip when unavailable.
`RUNNER_QUALIFICATION=1` retains its stricter missing-evidence failure, even when
the CI variable is set. There is no tool installation or host-policy change.
Read-only OS, kernel, libc, loader-cache and tracing diagnostics help explain
failures of the real wget/loader and tracing fixtures. Diagnostic failure never
turns a failed test into a pass.

## Shared fixture gate and inventory

`internal/testutil/hosttest.Require` is the only helper that performs CI fixture
skips. Only `SWARMA_TEST_UNPRIVILEGED=1` activates it; unset, `0` and `true` do not.
Every call supplies a reason. The workflow sets this variable only in its test
step. Review leaves it unset and provisions the relevant fixtures independently.
No test-name exclusion or global skip flag selects the hosted subset.

| Fixture or capability | Entry points | Hosted behavior and reason |
| --- | --- | --- |
| Protected peer configuration, distinct identities and helper permissions | `configuredPeerRow` (all callers listed below) | Shared skip before reading configuration or invoking a helper. These identities and permissions are deliberately not provisioned in CI. Missing configuration beyond the gate fails in CI. |
| Tagged cross-identity server fixture | `peeraccounts`: `TestConfiguredPeers`, `TestConfiguredPeerConnect` | Shared skip before using fixture globals. `TestMain` defers fixture initialization in CI so the tests can report their skips; a bypass reaches an explicit missing-fixture failure. |
| Tagged cross-identity runner fixture | `peeraccounts`: `TestConfiguredClientPins` | Same shared skip and missing-fixture failure; no sudo helper starts in CI. |
| Optional peer portion of a mixed harness | `configurePeers` in `TestRowsHarness` | Does not enroll optional peer configuration in CI. The test still executes its ten transport/admission pairs, origin supervision, runner fixtures and pending-publication assertions. It is not skipped. |
| Prepared user manager and sandbox configuration | `realmanager`: `realManager`, used by the containment/readiness tests and all connection/reference probes | Shared skip before opening the manager connection. A system manager or installed systemctl is not the prepared user manager required by these assertions. Without the gate, manager setup fails. |
| Selected real executable and private evidence directory | `realcandidate`: `TestRealCandidateVersion`, `TestLocalCandidateHTTPProbe`, `TestRealCandidateObservers` | Shared skip before inspecting paths or launching the real binary. CI has no selected candidate; bypassing the gate fails the explicit path prerequisites. Synthetic candidate tests continue to run. |
| Configured time services and source policy | `timeconf_smoke`: `TestHostTimeConfidenceSmoke` | Shared skip before collector/host reads. A bypass fails an explicit CI diagnostic guard. Synthetic collectors and the public time package remain runnable. |
| Optional strace, native attach permission and tracing-control prerequisites | `traceProcRead`, `requirePtrace`, `tracePublicationTiming` and their callers listed below | A failed tool/native probe reaches `unverifiedTrace`, then the shared gate with its actual cause. The CI fallback fails if that gate is bypassed. When probes succeed, the tests run; qualification mode still fails unavailable evidence. |
| Ptrace from birth, seccomp user notification, pidfds, procfs and Linux socket semantics | Ordinary egress/origin, qualification/row, runner, server and synthetic collector tests | Run on the VM; no blanket privileged skip. Existing real assertions reject unsupported or refused operations. |
| Non-root directory ownership assertion | `TestSocketDirectoryForeignOwnerRefused` | The existing root-only exclusion is irrelevant to the normal non-root runner. This is not an excluded host fixture. |

The complete `configuredPeerRow` caller inventory is:

- `TestPeerStartupReportDiagnostics`, `TestPeerStartupDiagnostics`,
  `TestPeerRowFixture` and `TestPeerRowSocketMode`;
- `TestCaseCompletionStatus/peer-denied/{0,17}` and
  `TestExecutionOrigin/peer/{metadataonly,receiptonly}`; their other paths run;
- `TestReviewPeerHelperOnlyCompletion`, `TestReviewPeerHelperOnlyReport`,
  `TestReviewDiagnosticBoundary`, `TestReviewPeerStartupEvidence` and
  `TestReviewPeerStartupCommand`.

The complete `realManager` inventory is `TestRealFDContainment`,
`TestRealGrandchildTimeoutAndDependencyStop`,
`TestRealReadinessRefusesRequiredPropertyAndDigest`,
`TestProbeManagerConnectionRetention`, `TestRealManagerConnectionRetention`,
`TestProbeReferenceReplyTiming`, `TestRealReferenceReplyTiming`,
`TestProbeReplacementConnectionLoss` and `TestRealReplacementConnectionLoss`.
Each shared setup is reached before manager access in every subcase.

The tracing-helper callers are `TestCommandProcDisappearance`,
`TestStopProcDisappearance`, `TestProbePublicationTiming`, the publication
subcases of `TestCommandStatusTable`, `TestTraceAvailability`, its child-only
`TestTraceAvailabilityWitness`, and the missing-tracer child cases of
`TestQualificationMode`. Only failed availability probes skip through the
shared helper. Intentionally failing child controls remain checked by their
parents and do not fail the surrounding passing test.

The optional build tags remain opt-in; the default workflow does not enable them.
The shared gates also apply if those tags are enabled during an unprivileged run.
The synthetic availability controls intentionally test both missing and working
tracers and both development and qualification verdicts. Their child verdicts
remain assertions, not extra qualification credit.

The runnable kernel-backed inventory also includes the following source groups.
They retain real syscall assertions and have no unconditional CI skip. Parser-
only cases in these groups do not acquire a new kernel prerequisite.

- `internal/egress/egress_linux_amd64_test.go`: `TestExternalRefusal`, `TestLoopbackPortAndThread`, `TestDatagramPolicy`, `TestUnixPolicy`, `TestEvidenceBudget`, `TestExplicitInputs`, `TestFailureAndCancellation`, `TestProxyEnvironment`, `TestBypassDenials`, `TestSocketOptions`, `TestAmbientDescriptorClosed`, `TestNamespaceCloneRefusal`, `TestAncillarySendRefused`, `TestLaunchPID`.
- `internal/egress/compatibility_linux_amd64_test.go`: `TestDescriptorModeIOCTL`, `TestLocalProxyClientProbe`, `TestLocalDNSProbe`, `TestBroadcastSendRefused`.
- `internal/egress/wait_linux_amd64_test.go`: `TestWaitedStatus`.
- `internal/egress/origin_gate_linux_amd64_test.go`: `TestOriginGate`, `TestOriginExecIdentity`, `TestOriginPostExecChallenge`, `TestOriginSocketContract`, `TestOriginWaitOwnership`, `TestOriginTraceLifecycle`, `TestOriginDefaultPath`, `TestOriginCloneCancellation`.
- `internal/qualification/candidate_test.go`: `TestCandidateVersion`, `TestCandidateIsolation`, `TestCandidateSchema`, `TestCandidateCatalog`, `TestCandidateExecutableBinding`, `TestCandidateCleanup`, `TestCandidateSchemaTreeBounds`.
- `timeconf/entry_linux_test.go`: `TestCollectorClosedOperations`, `TestCollectorEntryEnvironmentAndDescriptor`, `TestCollectorExecutableProtection`.

## Bounded race coverage

The test step also runs race checks for `internal/egress`, `internal/wire` and
`internal/store`. The last green review at `09d1f3b` measured these packages at
3.248, 1.010 and 1.017 seconds respectively under race. The entire review took
699.568 seconds; authowner, qualification and runner accounted for 332.771,
183.048 and 102.743 seconds. These are past review measurements, not predictions
for the hosted VM. The bounded race command has a three-minute deadline. The
reviewer's full race suite remains the comprehensive race gate.

## Local commands

Use Go 1.26.10 and export an absolute `GO` path for nested fixture builds:

```sh
export GOTOOLCHAIN=local
export GOMAXPROCS=2
export GO="$(command -v go)"
go mod verify
go build ./...
go vet ./...
out="$(gofmt -l .)"
if test -n "$out"; then
  printf '%s\n' "$out"
fi
test -z "$out"
SWARMA_TEST_UNPRIVILEGED=1 go test -v -p 1 -count=1 -timeout=20m ./...
SWARMA_TEST_UNPRIVILEGED=1 go test -race -v -p 1 -count=1 -timeout=3m ./internal/egress ./internal/wire ./internal/store
```

Keep scratch and captured logs outside the versioned tree; choose an explicit
fresh `TMPDIR` when isolating a local run. Shared-host scheduling and memory
limits still apply. A successful local run is not a claim of a hosted execution
or a qualified release.
