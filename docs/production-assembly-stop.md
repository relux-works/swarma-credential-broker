# Production assembly: contract stop

Status: **STOP:operator-act-contract**. Production assembly is not implemented.
The specification clarification in [broker §3.2](../spec/broker.md#32-production-assembly-activation-proposed-inactive)
is **PROPOSED**, not an accepted deployment or permission to activate.

## Evidence and failed assumption

Book cross-check: `swarma-docs` at
`b57a9be633c245373b448c3786bcbd49d636fe8a`, chapter **Operator and interfaces**,
`book/ru/16-interfeysy.md`, section **Operator phone**, requires an exact
confirmed act and a confined operator entry, distinct from ordinary SSH or
chat access. Disposition: **same**; reuse that boundary and broker §14,
without a local replacement protocol. The root-owned activation requirement
is recorded as **PROPOSED** only; no new mechanism or book rule is accepted.

The inspected source base is `103208a1ad384496cd55cdb0a0d865f5a60471ce`.
The custody/service implementation and managed-identity provider are present,
but their constructor seams are not a complete production authority backend:

- `cmd/swarma-credential-broker/main_linux.go` constructs `lease.New` with
  `owner.Stopped{}` and uses `server.New`, without a service controller.
- `internal/policy/policy.go` defines only `socket_path`, `store_root` and
  `policy` at the configuration root. `policy.Load` reads protected bytes
  owned by the supplied broker UID. It publishes no root-owned activation
  schema, operator directory pin or operator-act evidence source.
- `internal/service/managed_linux.go` implements managed **service** identities.
  Its `Principal` returns only the service role. `Owner` and `OperatorAct`
  delegate to separately supplied facts. Missing facts make `WithCurrent`
  refuse with `revocation_state_unavailable`, and cannot authorize owner acts.
  Wrapping facts in this provider does not turn its service-only `Principal`
  into an operator-principal reader.
- `internal/claude/account_linux.go` exposes custody `Enroll`; it is not an
  authenticated stdin receiver or an owner-checking operator transport.
- `internal/service/broker.go` already provides `NewWithLifetime`, rejecting
  nonpositive, fractional-second and above-900-second lifetimes. This does
  not publish daemon configuration bytes for selecting the value.

The failed assumption is that the projection plus existing constructors are
sufficient to authorize production use. They deliberately are not. The
[projection decision and provider contract](managed-identity-provider.md)
resolve service identity only, not activation or operator authority.

## Missing contracts and exact resume decisions

| Point | Existing contract and constraint | Publication or decision needed |
| --- | --- | --- |
| `operator-act-contract` | Broker §14 explicitly leaves the operator command binary, wire format, domain and canonical bytes unpublished. Service dialect §4 adds acts but no CLI grammar. Authentication plus exact-content confirmation is required for `service.bind` and enrollment; SSH login or a matching UID alone is insufficient. | Publish the narrow terminal/phone entry grammar, act representation, exact content binding, replay behavior and trustworthy evidence of authentication and agent-session exclusion. Name how the daemon verifies them. |
| `protected-authority-assembly` | Service `View` requires operator identity, account ownership, service policy, caller grants/bindings, revocations, events and sequence. Managed `Principal` admits services only; absent nonidentity facts refuse. | Publish the independently protected facts readers, directory/generation pins and the operator/service identity composition with its refusals. Do not insert an always-accepting adapter, static UID fallback or synthetic production facts. |
| `activation-schema` | Broker §15.1 and the current loader use broker-owned operational configuration; the requested activation gate is root-owned. No accepted activation pathname, exact mode or closed members are published. | Publish the versioned bytes, pathname, owner/group/mode, regular/single-link and ancestor checks, absent versus invalid behavior, reload semantics and relation to operational configuration. Unknown or unavailable authority must never mean enabled. |
| `owner-enrollment-transport` | Broker §§4.2, 5.4 and 14 make the configured operator the account owner; the ceremony person's interactive UID gains no ownership. Front-end syntax exists, but no receiving wire method or act format does. | Publish the owner-authenticated receiving transport, exact token framing/limits, confirmation ordering and interruption/retry behavior. Keep the existing custody implementation; do not invent an enrollment RPC or substitute the interactive UID for the owner. |
| `bootstrap-and-deployment` | Service dialect §5.1 requires an existing managed service and an enrolled Claude account before binding. The supplied runbook also records a prerequisite bind before enrollment and a live-broker dependency, without an executable reconciliation. Broker unit/configuration basenames and the managed broker/operator bootstrap remain unspecified. | Resolve the account/start/bind ordering without bypassing §5.1. Supply installer-owned bootstrap and unit/configuration/socket paths, numeric identity provenance and exact owners/modes. A generated unit must not pick them on the installer's behalf. |
| `service-lifetime-selector` | Service dialect §§5.3–5.4 cap issue and renewal at the earliest of evaluation time plus the configured ceiling, all caller-authority expiries and known token expiry. Default 900 seconds; above 900 refuses startup, never clamps. | Publish where the existing `service_lease_max_lifetime_seconds` parameter lives in the closed activation/configuration schema and how it is revalidated. Do not reuse the unrelated baseline `max_lease_seconds` by inference. |

The reference to service-principal §2.2 is to
[the service dialect](../spec/secret-free-service-v0.md#22-service-principal),
not a published activation section in `spec/broker.md`. Its bind method,
members and check ordering are already defined and must not be redesigned.
The external qualification audit identifies these integration gaps as
G05–G08 and G17; the source contracts above independently establish the stop.

## Bounded alternatives

The clean path is to publish and accept the missing operator/authority and
activation/enrollment contracts, reconcile bootstrap ordering with §5.1, then
implement against those exact revisions. The unit and configuration schema
follow the accepted installer paths, not locally guessed defaults. The
PROPOSED subsection records requirements only and is not that acceptance.

Retaining the stopped daemon is the safe interim alternative. It provides no
real-token service qualification, but preserves the current behavior. A
UID-only operator command, direct custody-file edits, a mock facts adapter,
an assumed enrollment RPC or a unit that silently enables service issuance
would be a forced fit and is not implemented.

Trusted time and restart continuity, external restore-fence custody, durable
consumer high-water, hold headroom and bounded native material publication
remain the existing [custody](claude-custody.md),
[provider](managed-identity-provider.md) and
[activation](../spec/secret-free-mode.md#13-publication-and-activation-gates)
gates. No fixture result or specification approval substitutes for them.

## Validation scope and required evidence on resume

This is a documentation-only stop, with no executable implementation delta.
Baseline formatting, vet and race results are recorded in the task handoff;
they are not production activation or token-handling evidence. No real token,
live enrollment, service account creation, daemon or system unit is used.

No surface table was supplied in the brief. The following is an acceptance
map, not a claim that the missing surfaces have tests or killed plants:

| Required surface | Positive and negative controls required after publication | Current result |
| --- | --- | --- |
| Activation | Accepted protected enabled file versus absent/disabled gate, wrong owner/mode/type/link count, symlink/ancestor replacement and unknown/duplicate members; preserve the inactive behavior and refuse invalid activation. | NOT RUN: activation schema/implementation absent; no plant applied. |
| Operator-only bind | Authenticated, exact-content-confirmed operator and existing managed service versus unauthorized kernel peer, forged confirmation, agent session, absent/retired/wrong-kind service; assert no binding on refusal and retain §5.1 ordering. | NOT RUN: operator transport/facts absent; no plant applied. |
| Owner-only enrollment | Admitted account-owner act versus other kernel peer and ceremony person's interactive UID; assert refusal before token consumption or custody changes. | NOT RUN: enrollment transport absent; no plant applied. |
| No echo | Synthetic token through the actual accepted input path with terminal echo suppressed and restored on success, refusal and interruption; pair with an echo-enabling plant that the named test detects. | NOT RUN: accepted receiving/input path absent; no plant applied. |
| No secret recording | Canary through the real accepted enrollment path; inspect captured logs/errors, argv, environment and fixture files outside custody, with a deliberate bounded recording plant. Never use a live token. | NOT RUN: accepted receiving/input path absent; no canary or plant applied. |
| Service lifetime | Issue and renewal at 900 and a smaller admitted value; earlier authority/token expiry; startup rejection above 900 without clamping; pair with a bound-removing plant. | Existing constructor tests only; daemon-selector tests and plant NOT RUN. |

There are no killed mutants to report. An unapplied plant is not a killed
mutant, and no omitted implementation row is treated as out of contract.
The entire requested production assembly remains blocked, including its
negative/positive controls and canary proof. No review acceptance, hosted
checks, landing, installation or native qualification is claimed.

## Proposed contract section for owner review

The six gaps above are now addressed by one candidate:
[Operator and activation v0](../spec/operator-and-activation-v0.md), revision 1,
**PROPOSED**, test profile v0, single Linux host, Claude service only.
The evidence and gap table above describe the inspected baseline; the new
section proposes bytes and integration, not an accepted revision of section 14.
**STOP:operator-act-contract remains pending owner decisions**, followed by
specification-acceptor review and the independent implementation/qualification
gates. No code, command, activation file or unit is installed by this packet.

| Original stop point | Proposed resolution |
| --- | --- |
| `operator-act-contract` | Section 2: terminal-only per-act password sudo, canonical exact-content act, confirmation and protected authentication receipt; DN-01 through DN-03. |
| `owner-enrollment-transport` | Section 3: configured operator owns the account; TTY-only no-echo capture, transient digest-prefix commitment and existing custody; DN-04. |
| `protected-authority-assembly` | Section 4: protected source inventory, closed schemas, freshness and independent containment; DN-02, DN-05 through DN-07. |
| `activation-schema` | Section 5: separate root-owned closed file, inactive when absent, explicit enabled semantics; DN-05. |
| `bootstrap-and-deployment` | Section 6: create managed service, enroll account, bind, then start gateway; broker control plane starts before enrollment; unit fields proposed under DN-08. |
| `service-lifetime-selector` | Section 5: activation member, default 900 s, startup refusal above 900 without clamping; DN-05. |

The full [DECISION-NEEDED register](../spec/operator-and-activation-v0.md#8-decision-needed-register)
gives two options and a recommendation for every unfixed bundle. DN-09 preserves
the separately owned continuity/recovery gates instead of inventing a witness.
Accepting this candidate does not itself authorize enrollment or production use.
