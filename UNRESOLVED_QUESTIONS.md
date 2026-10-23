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

- Account `owner-*.json` is reserved for owner records beside lease metadata.
  Which startup reconciliation entry point will the contained owner expose? Its
  adapter must validate those records and provide independent freshness and the
  conservative authorization clock before issuance.
- Which configured accounts and intended socket access will supply genuine
  foreign-UID qualification? The optional gate returns PENDING until that fixture
  can run; same-UID kernel coverage does not close this row.
- Which release evidence will establish safe transient backoff and unknown-expiry
  handling? The core rejects unknown expiry and delegates retries to the owner.
