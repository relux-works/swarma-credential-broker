# Unresolved questions

The [Codex refresher v0 profile](spec/v0-codex-refresher.md#11-accepted-curator-rulings)
has resolved curator rulings R1 and R2:

- **R1 accepted:** a static, operator-owned UID allowlist per account, checked
  by `SO_PEERCRED`, replaces grants in v0.
- **R2 accepted as an interim mode:** the daemon runs under the launches' OS
  user with §2.1's reduced guarantees. Leaving this mode requires the dedicated
  service-user step in Appendix A after the migration tool is reviewed.

R3 fresh-home owner enrolment remains accepted; the standalone headless runner
and extraction ahead of slice 0 are confirmed in scope. The cutover ruling
requires a maintenance window scheduled in advance through the platform curator,
every Codex launch on the machine quiesced for that window, and owner-performed
fresh-home device-code enrolment inside it.

The profile remains inactive until the mandatory
[0.163.0 qualification procedure](spec/v0-codex-refresher.md#82-mandatory-01630-qualification-procedure)
is satisfied. Complete containment/durable recovery, approved live-account
cases, safe old-login retirement during [cutover](spec/v0-codex-refresher.md#31-cutover-from-a-shared-native-login),
and optional thread resume remain evidence gates. The full broker's
[publication gates](spec/broker.md#18-open-questions) remain open for other deployments.

The daemon core intentionally ships with an unavailable owner adapter. Activation
still requires exact-release qualification, durable attempt recovery and time
watermarking, writer containment, approved live-account cases, safe old-login
retirement and any optional thread-resume evidence. The core's fake-owner tests
provide no real vendor or lifecycle qualification credit.

Implementation integration questions:

- `authowner.New` now validates and reconciles `owner-*.json` before snapshots.
  Activation still needs protected fresh-enrolment checkpoints, an independently
  implemented time/restore confidence provider, configured service identities,
  and installation of the approved empty-home echo helper for manager readiness.
  No existing login is adopted and no qualification is manufactured locally.
- Which configured accounts and intended socket access will supply genuine
  foreign-UID qualification? The optional gate returns PENDING until that fixture
  can run; same-UID kernel coverage does not close this row.
- Which release evidence will establish safe transient backoff and unknown-expiry
  handling? The core rejects unknown expiry and delegates retries to the owner.

- Protected `qualification/1` records, evidence-first publication, current-input
  observer contracts and the command frame are implemented. Production version,
  experimental schema and model catalog remain unavailable until the next
  qualification slice supplies a network-isolated candidate launcher and row
  bodies. Applied unit properties remain unavailable until the contained owner
  supplies its template and current-property observer. Every required row is
  pending, live execution remains refused, and no production tuple qualifies.
  See [qualification](docs/qualification.md). An interrupted-run fence, missing activation or recovered pending activation
  requires operator reconciliation while closed; an automatic recovery tool is
  not shipped.
- The runner currently reads the same broker-owned 0600 configuration as the
  daemon in interim R2 mode. A dedicated-service deployment needs a protected
  client-readable policy contract; unreadable policy remains refused, with no
  copied policy or permission weakening in this slice.

- Native 0.163.0 fixture qualification remains PENDING. The refresh URL override
  alone does not confine unsolicited model-service requests; a clean, complete
  vendor egress boundary is needed before retrying. Sandbox startup capability
  also needs qualification under the required service properties. No live
  account or issuer evidence is supplied by fake-vendor success.
- Refresh RPC error codes are ambiguous without exact-release classification.
  The default owner treats them as unknown; qualified nonrotation/rejection
  classification is an integration input, not an operator retry override.
- Protected executable installation and approved routing configuration remain
  installation/enrolment gates. The refresh library rechecks the pinned digest
  and uses an explicit minimal environment; it adds no endpoint override path.
