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
- Deployments must provision the protected peer mapping, helper and intended
  shared group for genuine foreign-UID qualification. The group-only fixture now
  checks a real configured pair; unavailable mappings still remain PENDING, and
  same-UID coverage does not substitute for that deployment evidence.
- Which release evidence will establish safe transient backoff and unknown-expiry
  handling? The core rejects unknown expiry and delegates retries to the owner.

- Protected `qualification/1` records, evidence-first publication, current-input
  observer contracts and the command frame are implemented. Production version,
  experimental schema and model catalog remain unavailable until the next
  qualification slice supplies a network-isolated candidate launcher and row
  bodies. Applied unit properties remain unavailable until the contained owner
  supplies its template and current-property observer. Ten transport/admission
  fixture rows have attested paired execution; the peer row needs an independently
  trusted inner-case waiter and image identity. Both runner rows need an approved
  witness of real Command preflight; kernel process identity alone is insufficient.
  These ownership/trust decisions remain open. Other rows stay pending, live
  execution remains refused, and no production tuple qualifies.
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

- The [platform time policy](docs/time-policy.md) selects configuration-based NTS
  evidence for v0, with matching selected source and the published bounds.
  Authdata is required before the dedicated service identity. Production source
  selection and owner wiring stay off until activation. Activation must establish
  protected shared upper bounds, the complete running source inventory and
  monitoring permission. A backward step spanning process replacement within the
  same boot remains an activation integration gate. The
  [qualified-time contract](docs/time-contract.md) requires durable consumed-time
  and hold continuity across restart and reboot; the owner's watermark alone
  is insufficient. The [provider fixture API](docs/qualified-time-api.md) ships
  with production consumption inactive. Before production activation, select the
  independent local rollback witness backend and enforce storage/restore exclusions for both checkpoint and
  witness. No missing or restored history may be reset. A proposed off-node
  witness protocol is only a conditional candidate, not the selected backend.
  It would require a separate time-continuity stream (not the consumer journal
  stream), fresh authenticated reads, and durable begin and end records. Its
  off-node acknowledgment round trips conflict with the current local-CAS
  assumption and a registry consumer's five-second decision budget until a
  bounded, lock-compatible protocol is qualified. Further prerequisites are an
  approved consumer profile; versioned record and domain schemas for begin,
  settle and recovery; exact generation/challenge mapping; provisioning, ACLs,
  rotation and administration. Each confirmed head needs independent protected
  custody that cannot roll back when either the provider or witness, or both,
  are restored. Keeping only the signing key separately is insufficient. Require
  exclusion of the old instance and fresh authenticated reads. Mutual-TLS and
  custodian acknowledgment round trips count against the original consumer
  budgets, including the 250, 1000 and 2000 ms paths; clock bootstrap dependencies
  must also be resolved. The time-provider and platform owners must resolve that
  latency/authority decision before activation; no
  remote-to-local adapter is assumed. Native pre-pin qualification and consumer
  review are also pending. Broker backward tolerance is zero.

- The `time-untrusted` qualification row needs a bounded durable synthetic-owner
  enrollment/restart fixture using the real time provider, adapter and retained
  watermark admission. The snapshot-only admission fixture has no owner
  watermark and cannot prove the no-advance invariant. Its account, release and
  ended-lease evidence supplies no time-row credit; see
  [qualification](docs/qualification.md#fixture-row-dispatch-and-limits).
