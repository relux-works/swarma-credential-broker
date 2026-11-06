---
name: swarma-credential-broker
description: Explain Swarma Credential Broker public Go interfaces and implemented command boundaries, or design synthetic validation fixtures. Credential custody and signing require OWNER-SITTING; this skill does not authorize live broker access.
---

# Swarma Credential Broker

Use this skill for module usage and source-backed integration questions in
`github.com/relux-works/swarma-credential-broker`. The module declares Go 1.25.
The baseline here is commit `e43b4b2b0c643eb0255ab1ae349af9eb7aa5cd23`;
check source at the consumer's exact pin before applying these interfaces.

Agent work stays with public source, synthetic inert data and static validation.
Owner presence, key handling, credential acquisition, storage, enrollment,
refresh, signing and live broker interaction are **OWNER-SITTING only**.
Do not turn the interface inventory into agent steps, read protected material,
log payloads or use a fixture result as permission for a live call.

- For public imports, worker versus observer roles and existing constructor
  seams, read [public interfaces](references/public-interfaces.md).
- For a complete in-memory valid input and its adjacent implemented refusal,
  read [inert validation](references/inert-validation.md). It has no fixture
  file, socket, collector process or credential input.
- For implemented command names, accepted selectors and closed activation
  gates, read [OWNER-SITTING boundary](references/owner-boundary.md).

Start with the [module README](../../../README.md), then the source linked by
these references. Treat [the broader broker specification](../../../spec/broker.md)
and [secret-free mode](../../../spec/secret-free-mode.md) as design contracts,
not added methods. The Linux daemon uses a stopped owner; release qualification
and secret-free mode remain closed. Legacy worker leases carry real tokens.
Static allowlist observation is metadata, not a lease or launch permit.

There is no plugin API or plugin registration/loader contract in this baseline.
Use only the existing Go constructor seams described in the interface reference;
do not invent plugin files, commands, registration hooks or activation switches.

The entrypoint is explicitly `agents/skills/swarma-credential-broker/SKILL.md`.
No native discovery links or automatic discovery claim accompany this skill.
Report the interface used, the actual validation/refusal, and the authority or
qualification that the result does not establish.
