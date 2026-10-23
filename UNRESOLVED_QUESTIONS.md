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
