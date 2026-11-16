# Secret-free service dialect v0

**Document revision 1 -- PROPOSED, inactive.** This file publishes the
broker-side service dialect for the v0 scope of
[secret-free mode](secret-free-mode.md): the service principal, its binding,
the service lease, the service revocation poll and the whole-account hold.
Publication is not implementation, qualification or activation. The
activation gates in [secret-free mode](secret-free-mode.md) section 13 stay,
except that the dialect publication they required for the scope in section 1
below is supplied here. Everything outside that scope stays PROPOSED and
unpublished in the same sense as before. Normative language follows
[the broker baseline](broker.md): MUST, MUST NOT, SHOULD and MAY are used as
in RFC 2119.

## 1. Scope and precedence

The v0 scope is closed:

- one host, local stations only;
- one service name, `credential-gateway`;
- one credential kind, `claude-oauth-token` (broker section 5.2).

No action service, no tool service classes, no remote enrollment and no donor
variants are in this dialect. A service name, kind, harness or scope outside
the list above is not a v0 variant of it and needs its own publication.

In v0, for `claude-oauth-token`, secret-free selection is per account (and
kind) in the protected machine policy, not per launch or per profile. For
an account of that kind whose policy so selects secret-free mode, the
secret-free contract wins for every launch using that account. The broker
issues material only to the service principal, by the service lease in
section 5.3. The agent account receives a placeholder and protected
nonsecret metadata through the gateway path (section 7); the broker
delivers no material to it. The selection closes every exposed-lane lease
on that account whatever the request's profile or launch. The
readable-token delivery channels in broker sections 5.2 and 8.4 are the
exposed lane: separately selected, separately qualified, and never a
fallback from a failed secret-free admission.

That precedence has one broker-side interlock, applied to the baseline
agent lease for an account of kind `claude-oauth-token`. Under the state
lock, after broker section 8.2 step 1 and again immediately before any
material release, `lease.request` and `lease.renew` from an agent
principal refuse as follows, each with effect: none:

- with the new code `secret_free_lease_required`, defined here and listed
  in section 8, when (a) the policy current under the lock selects
  secret-free mode for the account and kind, or (b) that policy cannot be
  read or does not determine the mode for the account and kind (fail
  closed). No exposed lease is issued or renewed instead, however valid
  the agent binding and grant chains are. An exposed lease issued before
  the account was switched to secret-free is not renewable after the
  switch;
- with `account_hold_active` (section 5.8), at the same two points, when
  an active account hold covers the account.

Machine policy is the protected installation policy held in the broker
configuration and pinned by digest in records that carry an installation
policy digest. A request field, a service binding by itself, a placeholder
or a caller-selected role never selects or overrides it. This dialect does
not assign the policy an encoding, a new `account/1` member or a mode enum;
selection stays where the existing contracts put it (broker section 5.2,
[secret-free mode](secret-free-mode.md) section 1).

The minimal broker keeps lifecycle only. It gains no network listener, no
plugins and no provider HTTP forwarding, and it classifies no gateway
request. Semantic classification, destination binding and the per-use
checks at the gateway remain the gateway contract
([secret-free gateway](secret-free-gateway.md) sections 3 to 5). Broker
issue and renewal checks in this file do not discharge them.

## 2. Channel, connections and the service principal

### 2.1 Channel

The channel is the broker's existing Unix socket and the `broker/1` protocol
(broker section 13). This dialect adds methods to that protocol (section 4).
There is no new socket, no network listener and no static UID allowance:
the static allowlist profile of [the Codex refresher v0](v0-codex-refresher.md)
admits no service principal, service lease or hold under this dialect.

The gateway connects as a client under its own service account. The broker
identifies it by kernel peer credentials as in broker section 4.1, and the
connection has the fixed role `service` for its whole life; a connection
never changes role (broker section 4.1 rule 5). The connection rules of
broker section 4.1 apply unchanged: close-on-exec descriptors that are
neither inherited nor passed, a fresh connection after any credential
transition, closure of a UID's connections when its binding is removed or its
generation retired, and the client check that the server peer UID is the
configured broker service UID before anything is sent
(`server_identity_mismatch`). Socket reachability is not authorization.

Deadlines follow broker section 13.1 by method class: `service.lease.request`
uses the lease-request bound, `service.lease.renew` the `lease.renew` bound,
and every other method in section 4 the administrative bound. Deadline
expiry refuses with `request_deadline_exceeded`, or `renew_timeout` for
renewal queueing as in the baseline. Effect: none; no late material is
delivered for an expired request.

### 2.2 Service principal

A service principal is the closed triple:

```
{ service_name, uid, service_generation }
```

- `service_name` is from the closed v0 set with the one member
  `credential-gateway`.
- `uid` is the OS user id of that service account, always taken from kernel
  peer credentials at connect time, never from a request.
- `service_generation` is the generation of that managed service account.
  The uid and the generation come from the user manager managed account
  record for that service account, under `spec/stations-v0.md` and
  `spec/generation-journal.md` of swarma-user-manager, cited here by name
  and not restated. The broker treats that record as the managed-principal
  evidence of broker section 4.2 for service accounts. That record MUST
  be a user-manager service account record, not an agent or workplace
  account record, with admitted local placement and a class other than
  untrusted; a missing, retired, ambiguous or unreadable record, a record
  of any other kind, a placement that is not admitted local placement, or
  the untrusted class refuses with `principal_ledger_mismatch`.
  Effect: none.

A service principal exists for broker purposes only while an active service
binding (section 6.1, made by `service.bind`)
names its exact triple. A configured name, a caller-selected role or a uid
alone admits nothing ([secret-free mode](secret-free-mode.md) section 3).
A connection has role `service` exactly when an active service binding
names the peer's (uid, active generation); the role is fixed for the
connection's whole life (section 2.1), and closure on binding removal or
generation retirement follows broker section 4.1 rule 3. Since broker
section 7.2 requires an agent account record for agent binds, the record
kind makes the `service` and agent roles disjoint: a (uid, generation)
with an active agent binding cannot be service-bound, and a (uid,
generation) with an active service binding cannot be agent-bound. The
refusal code for such a bind is `principal_ledger_mismatch`, effect:
none. One uid and generation held as a service principal is not at the
same time an agent principal on any connection.

A replaced service generation ends the old generation's service leases:
renewal, release and reports under the old triple refuse as in
sections 5.4 to 5.6, the old generation's connections close (broker
section 4.1 rule 3), and nothing is inherited by the new generation, a
recycled uid or a repeated service name. The new generation needs a fresh
operator `service.bind` and fresh leases. No seamless handoff is specified.

## 3. Requests, operation ids and refusals in general

Requests and responses ride the `broker/1` framing and request correlation
of broker section 13.1. The member lists in section 5 are the `params` and
`result` member lists of each method; every list is closed. All members are
required unless a member is stated as a time that may be null, exactly as
written. Times are the RFC 3339 UTC times of the baseline. Identifiers that
this dialect mints are fresh random identifiers that are never reused.
Unknown members, missing required members and values outside a stated
closed set refuse with the new code `request_malformed` (section 8), before
any state change. Effect: none. Frame-level and canonical-form failures
keep the transport behavior of broker section 13.1 and are not method
refusals. Errors never contain material or any derivation of it (hash,
prefix, length, fingerprint), a placeholder or raw request content,
matching broker section 12.3 and
[secret-free gateway](secret-free-gateway.md) section 5.

Mutating methods state an `operation_id` member where section 5 lists one.
It is scoped to the calling principal, is distinct from the transport
request correlation, and binds one method and one canonical argument set:

- The broker records the outcome under `(calling principal, method,
  operation_id)` before it replies, as part of the record or journal entry
  the method writes (section 6).
- A retry with the same principal, method, `operation_id` and equal
  canonical arguments returns the recorded outcome and the target current
  state. It never creates a second binding, lease or hold, and never
  extends authority a second time.
- The same `operation_id` with different canonical arguments refuses with
  the new code `service_operation_conflict` (section 8). Effect: none.
- A crash or a lost reply after the outcome is durable leaves the caller
  with an unknown outcome, never a success claim. The caller resolves it
  only by the same-`operation_id` retry above, on a fresh connection.

Material is the exception to plain replay, and it is stated where it
applies: on a same-`operation_id` replay of `service.lease.request` or
`service.lease.renew` the broker returns the recorded lease identity and
`authorized_until`, but releases the payload only after repeating the
final authority, revocation and hold checks at replay time, and only if
the lease is `active` and `max(now, watermark)` is before its recorded
`authorized_until`. If the final checks now refuse, that refusal governs
and no material is released. If the lease is not `active`, or that time
has reached the recorded `authorized_until`, the broker returns the
recorded outcome with `lease_not_active` and releases no material.
Effect: none; the already recorded lease is not a second effect.

Every other refusal in section 5 names its code at the check that raises it
and has effect: none -- no record is created or changed, no material is
released, no queued or later work is authorized -- unless the text at that
check says otherwise. The one stated exception is the unconfirmed hold in
section 5.8, whose outcome is unknown. Existing fences keep their baseline
mappings and are not reassigned here: trusted time and the watermark
(broker section 15.1), the restore fence (broker sections 6.4 and 15.4)
and R-ALLSTOP (broker section 15.5) refuse service binding, lease issue
and renewal exactly as they refuse their baseline counterparts. The
R-UNTRUSTED admission-class gate refuses service binding, and lease issue
and renewal, on the service account's own class and placement (section
2.2: admitted local placement and a class other than untrusted, refusing
with `principal_ledger_mismatch` there); at lease issue and renewal it
also refuses on the originating caller's admission class exactly as in
broker sections 4.2 and 8.2. Service binding has no originating caller,
so only the service account's own class and placement gate it. Each such
fence applies under the state lock immediately before any record that
creates authority or any material release, including
after any wait outside the lock (R-LOCK, broker section 13.1).
Effect: none, under the code each fence assigns at its check. No state
lock is held across a synchronous call to another service.

## 4. Method table

In the style of broker section 13.2. The `hello` exchange, the read methods
of broker section 13.2 and every baseline method are unchanged; a `service`
connection may use a baseline method only where broker section 13.2 already
admits its principal, which for agent leases it does not.

| Method | Accepted from | Purpose |
|---|---|---|
| `service.bind` | operators through the operator command | Create one active service binding (section 5.1) |
| `service.unbind` | operators through the operator command | Remove one service binding and end its leases (section 5.2) |
| `service.lease.request` | the service principal of an active service binding | Issue account material to that principal for one originating caller (section 5.3) |
| `service.lease.renew` | the service lease's own service principal and binding | Re-check both authorities and extend that lease (section 5.4) |
| `service.lease.release` | the service lease's own service principal and binding | End renewal of that lease (section 5.5) |
| `event.report` | the service lease's own service principal and binding | Report one typed event on that service lease only (section 5.6) |
| `service.revocation.check` | the service lease's own service principal and binding | Point-in-time revocation verdict for that lease (section 5.7) |
| `account.hold` | a service principal holding a current service lease on the account, or whose own lease on that account ended within the window in section 5.8 | Place the durable whole-account hold for a leak match (section 5.8) |
| `account.hold.lift` | the account owner, through the operator command | Lift an active account hold (section 5.9) |

Operator admission is the R-OPERATOR boundary of broker sections 13.2 and
14: `service.bind`, `service.unbind` and `account.hold.lift` reach the
broker only through the operator command after that admission, never from
a bare interactive uid, a harness session, the service principal itself, a
dispatcher or the read-only observer. Creating a service binding and
lifting a hold widen what may happen next -- the first creates service
authority, the second re-opens lease admission -- and each takes the
widening-act authentication and exact content confirmation of broker
section 14. `service.unbind` narrows and takes operator authentication as
a narrowing act there. None of the three is available inside an agent
session.

## 5. Methods

Each subsection gives, in order: the request members, the response members,
the checks in their stated order, and the refusal each check raises. Check
orders are normative. A check is evaluated only after every earlier check
in its list has passed, and the first failing check determines the refusal.
Unless a check states replay handling, the replay rule of section 3 is
resolved first: an equal retry returns the recorded outcome, a conflicting
one refuses with `service_operation_conflict` and effect: none.

### 5.1 `service.bind`

Request members:

```
{ operation_id,
  service_name,
  uid,
  service_generation,
  account,
  kind,
  installation_policy_digest }
```

Response members:

```
{ service_binding_id,
  service_name,
  uid,
  service_generation,
  account,
  kind,
  installation_policy_digest,
  state: "active" }
```

No material and no placeholder appears in either direction. Checks, in
order, under the broker state lock:

1. The peer is admitted as an operator through the operator command
   (section 4). Any other peer, including the service account itself,
   refuses with `role_not_permitted`. Effect: none.
2. `service_name` is `credential-gateway` and `kind` is
   `claude-oauth-token`. Any other value refuses with
   `bind_target_invalid`. Effect: none.
3. The managed account record for `uid` (section 2.2) shows
   `service_generation` as the active generation of that service account,
   and that record is a user-manager service account record (not an agent
   or workplace account record), with admitted local placement and a
   class other than untrusted. A missing, retired, replaced or
   unreadable record, a record of any other kind, a placement that is
   not admitted local placement, the untrusted class, or a (uid,
   generation) with an active agent binding refuses with
   `principal_ledger_mismatch`. Effect: none.
4. The account named by `account` exists. Otherwise `account_unknown`.
   Effect: none. The account record kind equals `kind`; otherwise the new
   code `service_binding_mismatch` (section 8). Effect: none.
5. `installation_policy_digest` equals the digest of the broker protected
   installation policy that is current under the lock, and that policy
   selects secret-free mode for this account and kind. The digest in the
   request is a pin to compare, never the source of the policy. A mismatch,
   a policy that does not so select, or an unreadable policy refuses with
   `service_binding_mismatch`. Effect: none.
6. No other active service binding exists for the same `(service_name, uid,
   service_generation, account, kind)`. Otherwise
   `service_binding_mismatch`. Effect: none. This dialect has no binding
   replacement operation: the operator unbinds first, then binds afresh.
   It does not limit v0 to one active service binding per `(account,
   kind)`: several gateway principals, under different triples, may each
   hold an active service binding and a service lease on one account.

On success the broker writes the service binding record of section 6.1,
durable before the reply. The binding by itself issues no material and
grants no caller authority.

### 5.2 `service.unbind`

Request members:

```
{ operation_id,
  service_binding_id }
```

Response members:

```
{ service_binding_id,
  state: "removed" }
```

Checks, in order, under the broker state lock:

1. The peer is admitted as an operator through the operator command
   (section 4). Any other peer refuses with `role_not_permitted`.
   Effect: none.
2. The binding named by `service_binding_id` is recorded. An unknown
   binding refuses with the new code `service_binding_unknown`
   (section 8). Effect: none. A retry of an already recorded unbind with
   the same `operation_id` returns the recorded `removed` outcome instead
   of refusing, under section 3.

On success the broker marks the binding removed, durable before the reply,
retaining the removal tombstone of section 6.1. Removal ends every service
lease issued under that binding for issue and renewal purposes and closes
the connections of that uid and generation (broker section 4.1 rule 3).
Renewal of an ended lease refuses as in section 5.4. Removal does not erase
lease or hold records, lift a hold, or recall material already delivered
to the service principal; material so delivered keeps only the bounds of
broker section 12.1 as they apply to a delivered credential.

### 5.3 `service.lease.request`

Request members. The request names the originating caller; the caller
identity members identify the existing agent binding to check and are
never trusted as authority by themselves:

```
{ operation_id,
  account,             // the requested account id
  agent_uid,           // originating caller: agent account uid
  agent_generation,    // originating caller: agent account generation
  launch_id }          // correlation only, as in broker section 8.1
```

Response members, to the service principal only:

```
{ service_lease_id,
  account,
  harness,             // from the account record
  kind,                // from the account record
  payload: { kind, value },
  token_expires_at,    // the account known expiry, or null when unknown
  authorized_until,
  renewable: true }
```

The `payload` is the account vendor material for its kind. It appears only
in this response and in renewal responses to the same service principal,
never in a persisted record, a log, an error or any response to an agent
principal. There is no agent delivery channel, variable name or file in
this dialect.

Checks, in this order, under the broker state lock. Material is released
only after every check passes under that lock, immediately before release:

1. **The service binding.** The peer connection has the fixed role
   `service`; any other role, including an agent (worker) principal,
   refuses with `role_not_permitted`. The managed account record shows
   the peer generation active for its service account, and that record is
   a user-manager service account record (not an agent or workplace
   account record), with admitted local placement and a class other than
   untrusted, as in section 2.2; otherwise
   `principal_ledger_mismatch`. An active service binding exists
   for the peer exact triple and the requested `account`; otherwise
   `service_binding_unknown`. That binding kind is `claude-oauth-token`,
   its pinned installation policy digest still equals the broker current
   digest, and that policy selects secret-free mode for this account and
   kind; otherwise `service_binding_mismatch`. Each refusal in this step
   has effect: none.
2. **The originating agent binding.** An active binding under broker
   section 7 exists for `(agent_uid, agent_generation)`, its ledger entry
   is an active agent account of that generation, and its `expires_at` has
   not been reached at `max(now, watermark)`. Otherwise `lease_unbound` or
   `principal_ledger_mismatch`, as in broker section 8.2 step 1. The
   R-UNTRUSTED admission-class evidence for that uid and generation is
   current and verifiable and is not the untrusted class, as in broker
   section 8.2. The broker resolves and records that binding
   `binding_id`; the request supplies no binding identity. Effect: none on
   refusal.
3. **The grant chain and revocations of the caller.** The binding chain
   and its caller chain verify now under broker section 6.2 against the
   current revocation state of broker section 6.4, and the leaf, within the
   caller intersection, covers `credential.lease` on the requested account
   for the account harness. The profile dimension of that authority is
   not a broker issue or renewal check in v0; it is bound per use at the
   gateway under [secret-free gateway](secret-free-gateway.md) section 4.
   A revoked envelope or key in the binding chain
   refuses with `lease_grant_revoked`, in the caller chain with
   `lease_caller_revoked`; a chain that fails verification refuses with the
   `grant_*` code broker section 6.2 assigns to that failure; a chain that
   does not cover this account refuses with `lease_not_authorised`. If the
   revocation state cannot be read or parsed, or restoration is fenced,
   the refusal is `revocation_state_unavailable`; unavailable revocation
   state is always a refusal, never an empty set. Effect: none. The
   service binding of step 1 never substitutes for any part of this step:
   both authorities are required at every issue.
4. **Account state and holds.** The account exists
   (`lease_account_unknown`); its kind is `claude-oauth-token` and its
   harness is the harness that kind serves (`lease_harness_mismatch`); it
   is `active`, with `revoked`, `reauth_required` and `owner_unavailable`
   states refusing as `lease_account_revoked`, `lease_reauth_required` and
   `lease_owner_unavailable`, and a known account expiry already reached
   at `max(now, watermark)` refusing as `lease_reauth_required`.
   `refresh_failed_transient` is not a state this kind reaches (broker
   section 10.1); if it is nevertheless recorded the account is not active
   and refuses as `lease_owner_unavailable`. No active
   account hold (section 6.3) covers the account; otherwise the new code
   `account_hold_active` (section 8). Each refusal in this step has
   effect: none.

On success the broker persists the service lease record of section 6.2,
without the payload, durable before the reply, then releases the payload
to the service principal on its `service` connection only.

`authorized_until` is the earliest of:

- the evaluation time plus the v0 parameter
  `service_lease_max_lifetime_seconds`;
- every expiry in the caller authority of steps 2 and 3: the originating
  binding expiry and the windows of the binding chain and caller chain;
- the account known expiry, when one is known.

`service_lease_max_lifetime_seconds` is a v0 parameter with the value 900
(seconds). A deployment MAY configure a smaller value and MUST NOT
configure a larger one. `authorized_until` at issue and at renewal MUST
NOT be later than the evaluation time plus this parameter. A configured
value above 900 is a broker start failure: the broker MUST refuse to
start, and MUST NOT clamp the value to 900 and start. Evaluation uses
trusted time as in broker
sections 8.3 and 15.1: expiry at `max(now, watermark)` and `not_before` at
`min(now, watermark)`. The lifetime of the vendor material itself, when
known, is reported separately as `token_expires_at` and is neither created
nor extended by this lease.

### 5.4 `service.lease.renew`

Request members:

```
{ operation_id,
  service_lease_id }
```

The request names no account, caller, account selector or new target: a
renewal can never retarget its lease. Response members are exactly those
of section 5.3, with the same `service_lease_id`, account, harness and kind
and a newly computed `authorized_until`.

Checks, in order, under the broker state lock:

1. The peer is the lease's own service principal: the fixed role `service`
   and the exact triple and `service_binding_id` recorded on the lease. An
   unknown lease, another service principal, a peer with no active
   service binding, a replaced generation or any agent principal refuses
   with `lease_not_owner`, as in broker section 8.5; an unknown lease is
   not distinguished, so no other
   principal's lease can be discovered this way. For renewal in this
   section, the recorded `service_binding_id` MUST be the currently active
   binding; a binding that was removed, including one removed and then
   replaced by a fresh bind for the same triple and account, refuses with
   `service_binding_unknown`. Sections 5.5 to 5.8 cite this step only for
   the own-principal identity in its first sentences (fixed role, exact
   triple and the recorded binding identity) and do not inherit the
   preceding renewal sentence. Each refusal in this step has
   effect: none.
2. The lease is `active` and `max(now, watermark)` has not reached its
   recorded `authorized_until`. A released, expired or revoked lease, or
   renewal at or after that limit, refuses with `lease_not_active`.
   Effect: none.
3. Every check of section 5.3 steps 1 to 4 repeats, in that order, for the
   lease's recorded account and recorded originating caller, including the
   originating binding identity: a replaced originating binding (a
   different recorded `binding_id` now current for that uid and
   generation) refuses at step 2 there with `lease_unbound`, and a removed
   service binding has already refused at step 1 above with
   `service_binding_unknown`. Renewal after a hold refuses at step 4
   with `account_hold_active`. Effect: none on every refusal. Both
   authorities are required at every renewal; a live service lease never
   substitutes for the caller chain.

On success the broker writes the new `authorized_until`, computed exactly
as in section 5.3 from the renewal evaluation time, durable before the
reply. A same-`operation_id` retry returns that recorded `authorized_until`
and creates no second extension; payload release on replay follows
section 3, so a replay when the lease is no longer `active` or its
recorded `authorized_until` has been reached returns the recorded
outcome with `lease_not_active` and releases no material, effect: none.
Renewal extends no grant, binding, account or vendor lifetime.

### 5.5 `service.lease.release`

Request members:

```
{ service_lease_id }
```

Response members:

```
{ service_lease_id,
  state: "released" }
```

Checks, in order, under the broker state lock:

1. The peer is the lease's own service principal, exactly as in
   section 5.4 step 1. Otherwise `lease_not_owner`. Effect: none.
2. The lease is `active` or already `released`. An expired or revoked
   lease refuses with `lease_not_active`. Effect: none.

On success an active lease becomes `released`, durable before the reply,
and release of an already released lease by its own principal returns the
same response with no further effect. Release ends renewal of that lease
only. It is not disconnect, it changes no account state, it places and
lifts no hold, and it does not by itself prevent a fresh
`service.lease.request` that passes every check of section 5.3, including
the hold check there. Leases are not tied to connections: the same service
principal may release from a fresh `service` connection.

### 5.6 `event.report` on a service lease

On a fixed-role `service` connection, `event.report` has the service-lease
form below. On an agent connection its baseline form on an agent lease
(broker section 8.5) is unchanged. A connection never changes role, so the
two forms never mix on one connection.

Request members:

```
{ service_lease_id,
  event }
```

`event` is exactly one typed event of broker section 11 in the form
accepted for an agent lease report under broker section 8.5, carrying
typed metadata only: no material, no placeholder, no body and no
agent-controlled strings. This dialect assigns no new event type, member
or class; an event outside that closed typed set refuses with
`request_malformed`. Effect: none.

Response members:

```
{ service_lease_id,
  state }              // the lease state after the report is recorded
```

Checks, in order, under the broker state lock:

1. The peer is the lease's own service principal, exactly as in
   section 5.4 step 1. Otherwise `lease_not_owner`. Effect: none.
2. The lease is `active`. Otherwise `lease_not_active`. Effect: none.

A report affects only the reporting lease record. It never changes an
account state, never places or lifts a hold, and never renews, releases or
extends the lease (broker section 8.5). In particular a `credential_error`
report is not the leak trigger of section 5.8.

### 5.7 `service.revocation.check`

Request members:

```
{ service_lease_id }
```

Response members, the same shape as `revocation.check` in broker
section 13.2:

```
{ verdict,             // exactly one of "not_revoked", "revoked", "unavailable"
  revocation_sequence }
```

`revocation_sequence` is the broker revocation sequence at this check
publication point, in exactly the representation `revocation.check`
returns; this dialect assigns no second representation, including for the
`unavailable` verdict. The encoding of `revocation_sequence` under
`unavailable` is an open item, owner: broker (section 10; broker
section 18 item 8).

Checks and verdict, under the broker state lock:

1. The peer is the lease's own service principal, exactly as in
   section 5.4 step 1. Otherwise the method refuses with
   `lease_not_owner` and returns no verdict. Effect: none.
2. The verdict is `revoked` when any of the following is current for this
   lease: an envelope or key of its originating binding chain or caller
   chain is revoked (broker section 6.4); its account is revoked; its
   originating agent binding is removed or replaced; its service
   binding is removed or its service generation is retired or replaced;
   or an active account hold (section 6.3) covers its account. The
   response shape is unchanged by the hold case.
3. The verdict is `unavailable` when the revocation state cannot be read
   or parsed, restoration is fenced, R-ALLSTOP is frozen or unresolved, or
   any record needed for step 2 cannot be read currently. Unreadable or
   stale evidence never yields `not_revoked` and never starts from an
   empty revocation set.
4. The verdict is `not_revoked` only on a complete current read in which
   none of step 2 holds.

Revocation of the caller chain, the account or the service binding closes
service lease issue and renewal at once: the revocation is recorded
durable before the broker replies to the act that records it, under broker
section 6.4 for grant and key revocations and under sections 5.2 and 6.1
for a service binding removal, and sections 5.3 and 5.4 refuse from that
publication point. This poll is how the broker reports that closure to the
service between renewals. The gateway is a revocation consumer: on a
`revoked` or `unavailable` verdict for a lease it MUST stop use of that
lease's material at once. A later `not_revoked` verdict is not material
and waives no check; further material from the broker needs a fresh
`service.lease.request` or a renewal that passes section 5.4 in full. A
verdict is point-in-time evidence for this lease only, never a grant, a
transferable permit or a waiver of the final issue and renewal checks.
An active hold on the lease's account is reported by this poll as
`revoked` under step 2 above, so every gateway principal holding a lease
on that account stops use on that verdict, including under
[secret-free gateway](secret-free-gateway.md) section 7; hold placement,
its issue and renewal refusals and its lift remain sections 5.8 and 5.9.
The poll by itself claims no propagation bound; consumer closure
composition stays in [secret-free mode](secret-free-mode.md) section 9.

### 5.8 `account.hold`

This is the whole-account leak trigger. It is callable only by the service
principal that holds a current service lease on that account, or by the
service principal whose own service lease on that account ended within
the window in step 3 below, and by no other principal: not an agent, not
a dispatcher, not the observer, and not a service principal whose lease
is on another account. It conveys no general operator power. A hold only
narrows; the ended-lease window exists so leak containment does not fail
because a lease lapsed between an unconfirmed attempt and its retry.

Request members, closed, with no other member admitted:

```
{ operation_id,
  service_lease_id,
  account,
  reason_code }        // closed v0 set: "leak_match" only
```

There is no body and no value: the suspected content, the matched material
in any form, a placeholder and free text have no member to travel in, and
supplying one refuses as an unknown member with `request_malformed`
(section 3). Effect: none.

Response members:

```
{ hold_id,
  account,
  reason_code,
  state: "active",
  placed_at }
```

Checks, in order, under the broker state lock:

1. The peer connection has the fixed role `service`. Otherwise
   `role_not_permitted`. Effect: none.
2. The lease named by `service_lease_id` is the peer's own lease, exactly as
   in section 5.4 step 1. Otherwise `lease_not_owner`. Effect: none.
3. That lease qualifies for this trigger, under either of these: (a) it
   is current -- its state is `active` and `max(now, watermark)` has not
   reached its `authorized_until`; or (b) it is the peer's own lease on
   that account and it ended, in state `released`, `expired` or
   `revoked`, no more than `service_lease_max_lifetime_seconds` (section
   5.3, at its configured value) before the evaluation time
   `max(now, watermark)`. For (b) the end time is the recorded
   `authorized_until` for an expired lease, and for a released or revoked
   lease the time the broker durably recorded that transition in its
   lease and journal evidence; if that end time cannot be read currently,
   the lease does not qualify under (b). The same checks otherwise apply
   in both cases (steps 1, 2, 4 and 5: role, own lease, account match and
   closed reason). A lease that qualifies under neither (a) nor (b), in
   particular a lease that ended earlier than the window in (b), refuses
   with `lease_not_active`. Effect: none.
4. `account` equals the account recorded on that lease and on its service
   binding. Otherwise `service_binding_mismatch`. Effect: none. The broker
   takes the hold target from the lease record, never from this member
   alone, and never invents a cross-account target.
5. `reason_code` is in the closed v0 set, whose one member is
   `leak_match`. Any other value refuses with the new code
   `hold_reason_unknown` (section 8). Effect: none.
6. When an active hold already covers the account, the broker returns that
   recorded hold in the response above and writes no second hold. Steps 1
   to 5 still apply first, so an unqualified caller learns no hold state
   this way.

On success the broker persists the hold record of section 6.3 durable
before the reply, under the same state lock that serializes lease issue
and renewal. From that publication point:

- every `service.lease.request` and `service.lease.renew` for the account
  refuses at section 5.3 step 4 with `account_hold_active`, and every
  exposed-lane lease issue and renewal for the account refuses with the
  same code before material release, including a final delivery after any
  wait outside the lock. Effect of each such refusal: none;
- the hold covers the whole account, all agent generations, all service
  generations and all launches. Reconnect, restart, a fresh generation, a
  fresh lease attempt or a new service binding does not bypass it;
- the hold changes no `account/1` state, releases and revokes no lease by
  rewriting its record, and invalidates no vendor material. Local block,
  durable hold, service-use closure, session stop and vendor invalidation
  remain the separate outcomes of
  [secret-free gateway](secret-free-gateway.md) section 7. A possible leak
  authorizes this hold only, never automatic vendor action.

When the broker cannot confirm that the hold is durable, it does not claim
the hold: it returns the new code `account_hold_unknown` (section 8) and
the outcome is unknown, not recorded and not effect: none. A lost reply
after durable persistence is likewise unknown to the caller. In both cases
the gateway stays closed -- it keeps the local block in place, stops use
of the account material and forwards nothing further for that account --
and resolves the outcome only by a same-`operation_id` retry under
section 3, which returns the recorded hold if one was persisted and never
writes a second hold.

### 5.9 `account.hold.lift`

Only the account owner lifts a hold, through the operator command under
the existing owner role and R-OPERATOR admission (broker sections 4.2,
13.2 and 14). No service principal, agent, dispatcher or observer effect,
and no lease release, report, expiry or service unbind, lifts it. The
owner lifts the hold it has seen: `status` and `account.describe`, for
each principal already admitted to that read (for `status`, the owner for
their accounts, operators and the observer; for `account.describe`, the
account owner, operators acting in the owner role through the operator
command included), list active holds as typed metadata `{hold_id,
account, reason_code, placed_at, state}` and nothing else, so the owner
can name the `hold_id` below. That listing is the only gain to those
reads in this dialect; it admits no new principal to either method.

Request members:

```
{ operation_id,
  hold_id,
  account }
```

Response members:

```
{ hold_id,
  account,
  state: "lifted",
  lifted_at }
```

Checks, in order, under the broker state lock:

1. The peer is the owner of the named account, admitted through the
   operator command (section 4), with a content-confirmed widening act
   under broker section 14, since lifting re-opens lease admission.
   Otherwise `role_not_permitted`. Effect: none; the hold persists.
2. An active hold with `hold_id` covers `account`. An unknown hold, a hold
   for another account, or no active hold refuses with the new code
   `account_hold_not_found` (section 8). Effect: none. A same-
   `operation_id` retry of a recorded lift returns that lifted outcome
   under section 3 instead of refusing.

On success the broker records the lift on the hold record, durable before
the reply. A lift clears no revocation, restore, R-ALLSTOP, time,
admission-class or account-state fence, revives no released, expired or
revoked lease, re-opens no gateway listener or session, and grants no
restart authority. Material after a lift needs a fresh lease or a renewal
that passes every current check.

## 6. Records

The broker is the only writer of every record in this section. Records are
broker-owned state under the storage boundary of broker section 12.4,
written atomically in their own directory, and contain no material and no
placeholder. Member lists are closed. A record write that a method in
section 5 requires "durable before the reply" is complete -- file
replacement and its directory durability step done, and the new state the
one later reads under the state lock observe -- before the success reply
is sent. Each subsection states what a crash between that durable point
and the reply leaves; section 3 gives the shared replay rule those crash
cases use. Service bindings, service leases and holds are inside the
closed recovery of broker section 15.4, so a restore never drops a hold
without an owner lift under section 5.9.

### 6.1 Service binding record

```
service-binding/1
{ service_binding_id,          // fresh random, never reused
  service_name,                // "credential-gateway"
  service_uid,
  service_generation,
  account,                     // one account id
  kind,                        // "claude-oauth-token"
  installation_policy_digest,
  created_by,                  // principal reference of the operator act
  operation_id,                // the service.bind operation that created it
  created_at,
  state: "active" | "removed",
  removed_operation_id,        // the service.unbind operation, or null while active
  removed_at }                 // a time, or null while active
```

Written only by `service.bind` (creation, as `active`) and `service.unbind`
(the `removed` transition), both operator acts through the operator
command. No service, agent, dispatcher or gateway write reaches it. The
removed form is the retained tombstone: removing the active index entry
deletes neither this record nor its bind and unbind operation outcomes,
which the broker retains for as long as a retry of either operation is
admissible, as in broker section 7.2. At most one `active` record exists
for one `(service_name, service_uid, service_generation, account, kind)`
(section 5.1 step 6). A record whose service generation the managed
account record no longer shows active is unusable for issue and renewal
whether or not its state has been marked `removed`.

Crash between durable and reply: the operator sees an unknown outcome. A
`service.bind` retry with the same operator principal, `operation_id` and
arguments returns the recorded binding and its current state and creates
no second binding; different arguments refuse with
`service_operation_conflict` and effect: none. The same rule with the
unbind operation returns the recorded `removed` outcome. A crash before
the durable point leaves no record; a retry is fresh admission and repeats
every check of section 5.1 or 5.2.

### 6.2 Service lease record

```
service-lease/1
{ service_lease_id,            // fresh random, never reused
  service_binding_id,
  service_name,
  service_uid,
  service_generation,
  account,
  harness,                     // from the account record at issue
  kind,                        // from the account record at issue
  agent_uid,                   // originating caller
  agent_generation,            // originating caller
  binding_id,                  // originating agent binding resolved at issue
  launch_id,                   // correlation only
  operation_id,                // the service.lease.request operation
  authorized_until,
  last_renewal_operation_id,   // most recent renew operation recorded here, or null
  state: "active" | "released" | "expired" | "revoked" }
```

Written only by `service.lease.request` (creation), `service.lease.renew`
(the recorded `authorized_until` and `last_renewal_operation_id`; the
broker retains each renewal operation outcome with the lease evidence for
the replay rule of section 3) and `service.lease.release`
(the `released` transition), each after its checks pass. No other
method, hold placement or lift, or component writes it; in particular a
hold refuses new issue and renewal without rewriting lease records, and
the precise automatic transition to
`expired` or `revoked` follows the same unspecified scheduling boundary as
broker section 8.5, while the refusals those states cause are specified in
section 5. The payload is never part of this record. A replacement of the
originating binding or of the service binding never rewrites a lease
record binding identity, account or `authorized_until`: the old lease
simply fails the renewal checks of section 5.4.

Crash between durable and reply: the gateway sees an unknown outcome. A
`service.lease.request` retry with the same service principal,
`operation_id` and arguments returns the recorded lease and creates no
second lease; different arguments refuse with `service_operation_conflict`
and effect: none. A renewal retry likewise returns the one recorded
`authorized_until` and extends nothing twice. Payload release on either
replay repeats the final authority, revocation and hold checks first and
requires the lease `active` with `max(now, watermark)` before its
recorded `authorized_until`; otherwise the recorded outcome returns with
`lease_not_active` and no material (section 3), effect: none. A crash
before the durable point leaves no lease and delivers no material; a
retry is fresh admission.

### 6.3 Account hold record

```
account-hold/1
{ hold_id,                     // fresh random, never reused
  account,
  reason_code,                 // "leak_match"
  service_name,                // principal that placed the hold
  service_uid,
  service_generation,
  service_binding_id,          // binding of the qualifying lease
  service_lease_id,            // qualifying lease at placement (section 5.8 step 3)
  operation_id,                // the account.hold operation
  placed_at,
  state: "active" | "lifted",
  lifted_by,                   // owner principal reference, or null while active
  lift_operation_id,           // the account.hold.lift operation, or null while active
  lifted_at }                  // a time, or null while active
```

Written only by `account.hold` (placement, as `active`) and
`account.hold.lift` (the `lifted` transition). At most one `active` hold
covers one account; a further conforming `account.hold` returns the
recorded active hold (section 5.8 step 6). The record carries typed
metadata only: no body, no suspected content, no material in any form, no
placeholder and no agent-controlled string. It is not an `account/1`
state and adds no member to that record.

Crash between durable and reply: the gateway sees an unknown outcome and
stays closed (section 5.8). A retry with the same service principal,
`operation_id` and arguments returns the recorded hold and writes no
second hold; different arguments refuse with `service_operation_conflict`
and effect: none. The same rule with the lift operation returns the
recorded `lifted` outcome to the owner. A crash before the durable point
leaves no hold record; the gateway still stays closed until a retry either
records the hold or a fresh admission decision by the owner path resolves
the local block, and the broker never reports that unrecorded attempt as a
hold.

## 7. Placeholder boundary

The broker never sees, stores or issues a placeholder. No request,
response, record, log entry or error in this dialect carries one; a member
carrying one is an unknown member and refuses under section 3. The broker
cannot create, validate, map, revoke or dispose of a placeholder, and no
placeholder, placeholder digest or listener fact is broker input to any
check in section 5.

The gateway creates the placeholder, random per service lease, after that
lease issues to its service principal. The gateway owns the mapping:

```
{ launch, agent_generation, account, service_generation, listener }
```

That mapping is gateway state, written and read only on the gateway side
of the boundary. The broker lease correlates with it only through facts
the gateway already holds from its own lease response and its own launch
handling; the broker is never told the mapping or the placeholder.

The placeholder format and its delivery to the launch are the gateway
dialect and are explicitly out of this revision; they are listed under
open items in section 10, owner: gateway. Nothing here qualifies a harness
to accept a placeholder, a listener to authenticate a caller, or a launch
to receive one. Those remain the qualification duties of
[secret-free mode](secret-free-mode.md) section 8 and
[secret-free gateway](secret-free-gateway.md) section 2.

## 8. Refusal codes assigned and reused here

New codes, each defined at the check that introduces it and listed here
once. Refusals with these codes have effect: none, except
`account_hold_unknown`, whose outcome is unknown as stated in section 5.8:

| New code | Introduced at | Meaning |
|---|---|---|
| `secret_free_lease_required` | Section 1 | Agent `lease.request` or `lease.renew` for an account and kind whose machine policy selects secret-free mode, or whose mode that policy does not determine or cannot be read (fail closed) |
| `request_malformed` | Section 3 | Unknown or missing member, or a value outside a stated closed set, in a method of this dialect |
| `service_operation_conflict` | Section 3 | An `operation_id` reused by the same principal and method with different canonical arguments |
| `service_binding_unknown` | Sections 5.2, 5.3 and 5.4 | No recorded binding for an unbind, no active service binding for the peer triple and requested account at lease issue, or, at renewal, the recorded `service_binding_id` is not the currently active binding |
| `service_binding_mismatch` | Sections 5.1, 5.3 and 5.8 | The service binding pinned account, kind or installation policy digest does not match the account, request or broker current policy |
| `account_hold_active` | Sections 1, 5.3 and 5.8 | Service or exposed-lane issue or renewal refused because an active whole-account hold covers the account |
| `hold_reason_unknown` | Section 5.8 | `account.hold` reason outside the closed v0 set |
| `account_hold_unknown` | Section 5.8 | The broker cannot confirm the hold is durable; outcome unknown, gateway stays closed |
| `account_hold_not_found` | Section 5.9 | No active hold with the named identity covers the named account at lift |

Reused baseline codes (broker Appendix A), with their baseline meanings
unchanged: `peer_identity_unavailable`, `server_identity_mismatch`,
`principal_ledger_mismatch`, `role_not_permitted`,
`request_deadline_exceeded`, `account_unknown`, the `grant_*` codes of
broker section 6.2, `revocation_state_unavailable`,
`bind_target_invalid`, `lease_unbound`, `lease_grant_revoked`,
`lease_caller_revoked`, `lease_not_authorised`, `lease_account_unknown`,
`lease_harness_mismatch`, `lease_account_revoked`,
`lease_reauth_required`, `lease_owner_unavailable`, `lease_not_owner`,
`lease_not_active` and `renew_timeout`. Codes for fences that broker
section 18 leaves unpublished -- the admission-class and node-wide freeze
mappings -- are not reassigned here (section 3).

## 9. Negative table

Every row is a prospective contract witness for this dialect, runtime
UNRUN, and sits beside its valid control. The valid control in every row
is the same shape unless the row says otherwise: an operator-made active
service binding for `credential-gateway` and a `claude-oauth-token`
account whose protected machine policy is readable, determines the mode
for that account and kind, and selects secret-free mode per account; the
managed record a user-manager service account record with admitted local
placement, a class other than untrusted and a current managed service
generation; no active agent binding for that (uid, generation); an active
originating agent binding whose chains cover that
account and verify against a readable current revocation state, an active
account with no hold, and a `service.lease.request` by that service
principal naming that caller -- which issues one service lease, material
to the service principal only, `authorized_until` within section 5.3. Each
negative changes one fact from that control. Every refusal below has
effect: none except where a row states an unknown outcome: no lease,
binding or hold record is created or changed by the refused call, and no
material is delivered to any principal, in particular none to the agent
account. Existing records named as preconditions keep the state the row
gives them.

| # | Negative case (one fact changed) | Required refusal and code | Valid control beside it |
|---|---|---|---|
| 1 | A worker (agent) principal, on its fixed-role agent connection, calls `service.lease.request` naming itself as the originating caller | `role_not_permitted` at section 5.3 step 1; effect: none | The same account and caller named by the service principal of the active service binding on its `service` connection: the lease issues to the service principal only |
| 2 | A service principal whose service generation has been retired or replaced calls `service.lease.request` under the old generation's binding | `principal_ledger_mismatch` at section 5.3 step 1; effect: none. The old generation's leases gain no renewal (section 5.4 step 1, `lease_not_owner`, for a caller under the new triple) and nothing is inherited | The new service generation, after a fresh operator `service.bind` for its triple, issues a fresh lease as in the control |
| 3 | A service binding made for one account is presented for another account: the same service principal requests a different account than its binding pins | `service_binding_unknown` where no active binding covers the peer triple and the requested account, or `service_binding_mismatch` where a covering binding pinned kind or policy does not match that account, at section 5.3 step 1; effect: none. No material for either account moves under the other account's binding | The same principal requests the account its binding pins: the lease issues for that account only |
| 4 | The originating caller binding chain or caller chain is revoked while the service binding stays live and otherwise matches | `lease_grant_revoked` or `lease_caller_revoked`, as the revoked chain falls, at section 5.3 step 3; effect: none. The live service binding substitutes for nothing, and a `service.revocation.check` on an earlier lease of that caller now returns `revoked`, on which the gateway stops use (section 5.7) | Both chains current and unrevoked under the same live service binding: the lease issues, and the poll for it returns `not_revoked` with the current revocation sequence |
| 5 | The revocation state is unreadable at issue (cannot be read or parsed, or restoration is fenced) | `revocation_state_unavailable` at section 5.3 step 3; effect: none. No empty revocation set is substituted. A poll for an existing lease in the same condition returns `unavailable`, on which the gateway stops use | A complete current revocation read with no revocation for this caller: the lease issues |
| 6 | `account.hold` is called by a principal with no qualifying lease on that account: a service principal naming another principal's lease, its own lease that ended earlier than the window in section 5.8 step 3(b), or a lease on a different account, with reason `leak_match` | `lease_not_owner`, `lease_not_active` or `service_binding_mismatch` respectively, at section 5.8 steps 2 to 4 (and `role_not_permitted` for any non-service caller at step 1); effect: none. No hold is recorded, and the caller learns no hold state | The service principal that holds the current active lease on that account calls `account.hold` with that lease and reason `leak_match`: one hold is durable before the reply, and later issue and renewal for the account refuse with `account_hold_active` |
| 7 | A service lease renewal is attempted after an active hold is placed on its account, with both authorities otherwise current | `account_hold_active` at section 5.4 step 3 by way of section 5.3 step 4; effect: none. The recorded `authorized_until` is unchanged, reconnect or a fresh generation does not bypass the hold, and no fresh lease issues either | The same renewal with no active hold -- or after the owner lift of section 5.9, with every other fence still passing -- renews once, with a newly computed `authorized_until` durable before the reply |
| 8 | A readable-token `lease.request` is made by the agent principal for a `claude-oauth-token` account whose machine policy selects secret-free mode per account (any profile or launch in the request), with an otherwise valid agent binding and chains | `secret_free_lease_required` under the section 1 interlock (broker sections 8.2 and 8.5), after broker section 8.2 step 1 and again before material release; effect: none. No exposed lease issues and the failure selects no fallback lane, account or billing | Two controls: the same account reached by `service.lease.request` from its service principal issues to that principal only; and an account whose readable machine policy determines and selects the exposed lane for that account and kind, separately qualified, still leases under broker section 8 unchanged |
| 9 | `service.bind` is called from the service account itself, on its own connection, for its own triple, with otherwise conforming members | `role_not_permitted` at section 5.1 step 1; effect: none. No binding is recorded and no service role is created by the call | The same bind, with the same members, admitted as an operator through the operator command with the widening-act confirmation of section 4: one active binding is durable before the reply |
| 10 | An operator `service.bind` names the uid and active generation of an agent account (or a workplace account, a service account without admitted local placement, or the untrusted class), with every other member conforming | `principal_ledger_mismatch` at section 5.1 step 3 (section 2.2); effect: none. That (uid, generation) gains no `service` role on any connection, its agent binding is unchanged, and no material can issue to it as a service principal | The same bind naming a user-manager service account record with admitted local placement and a class other than untrusted, and no active agent binding for that (uid, generation): the binding is recorded as in row 9 |
| 11 | `account.hold`, otherwise exactly as in the control of row 6, carries one extra member: a body, a free-text member or a placeholder member | `request_malformed` under section 3 at section 5.8 (unknown member, before any state change); effect: none. No hold is recorded, and no body, value or placeholder travels to or rests in the broker | The same call with exactly the closed members `{operation_id, service_lease_id, account, reason_code}` and reason `leak_match`: the hold is placed as in row 6 |
| 12 | `account.hold` is called exactly as in the control of row 6, but the broker cannot confirm that the hold is durable (or the reply is lost after durable persistence) | `account_hold_unknown` at section 5.8; outcome unknown, not effect: none and not a recorded hold. The gateway stays closed (local block kept, use stopped, nothing further forwarded for the account) and resolves the outcome only by a same-`operation_id` retry under section 3, which writes no second hold | The same call with durability confirmed before the reply: the recorded hold returns `{hold_id, account, reason_code, state: "active", placed_at}`, and issue and renewal then refuse with `account_hold_active` |
| 13 | At issue, and again at a renewal of the issued lease, every caller-authority expiry and any known account expiry lie more than 900 s after the evaluation time, so only the v0 ceiling can bound the result | No refusal: a conforming broker issues and renews with `authorized_until` never later than the evaluation time plus `service_lease_max_lifetime_seconds` (at most 900 s) under sections 5.3 and 5.4; a later `authorized_until` at either point is the failure this row witnesses. A configured value above 900 never reaches this row: the broker refuses to start (section 5.3) | Beside it, with a caller-authority expiry sooner than that bound: issue and renewal cap `authorized_until` at that earlier expiry instead |
| 14 | An operator `service.bind`, otherwise as in the control of row 9, carries an `installation_policy_digest` that does not equal the broker current digest, or the current policy does not select secret-free mode for this account and kind, or that policy is unreadable | `service_binding_mismatch` at section 5.1 step 5 in each case; effect: none. The request digest never becomes the policy source | The same bind with the digest equal to the readable current policy, which selects secret-free mode per account for this account and kind: the binding is recorded |
| 15 | An operator `service.bind` with a fresh `operation_id` repeats a `(service_name, uid, service_generation, account, kind)` tuple that already has an active service binding | `service_binding_mismatch` at section 5.1 step 6; effect: none. The existing active binding is unchanged and no replacement happens by this call | The same bind after an operator `service.unbind` of the earlier binding: the new binding is recorded with a fresh `service_binding_id`, and the removed tombstone is retained |
| 16 | `account.hold`, otherwise exactly as in the control of row 6, carries a `reason_code` other than `leak_match` | `hold_reason_unknown` at section 5.8 step 5; effect: none. No hold is recorded | The same call with reason `leak_match`, the one member of the closed v0 set: the hold is placed |
| 17 | `account.hold.lift` for an active hold is called by a non-owner: an operator who is not the account owner, the service principal, an agent, a dispatcher or the observer | `role_not_permitted` at section 5.9 step 1; effect: none. The hold persists and issue and renewal keep refusing | The account owner, through the operator command with the content-confirmed widening act, lifts that same hold by its `hold_id` and account as listed by `status` or `account.describe` (section 5.9): the lift is durable before the reply, and later material still needs a fresh lease or renewal passing every check |
| 18 | The account owner calls `account.hold.lift` exactly as in the control of row 17, but no active hold with that `hold_id` covers that account (unknown hold, a hold for another account, or no active hold) | `account_hold_not_found` at section 5.9 step 2; effect: none. Any active hold on either account persists | The same owner call naming the active hold listed for that account by `status` or `account.describe`, with its `hold_id` and account: the lift is recorded as in row 17 |
| 19 | After an operator `service.unbind` of the lease's binding with no fresh bind, a renewal of a lease issued under that binding is attempted | The binding's connections are closed and renewal refuses at section 5.4 step 1: `lease_not_owner` for a peer that is no longer the lease's service principal under an active binding, and in every evaluation no material is released; effect: none. The removed tombstone and the lease and hold records are retained | The same renewal attempted while that binding was still active, with every other check current: the lease renews once as in row 7 |
| 20 | `service.lease.release`, the service-lease form of `event.report`, or `service.revocation.check` is called for a lease by a principal that is not that lease's own service principal (another service principal, a replaced generation, or any agent principal) | `lease_not_owner` at section 5.5 step 1, section 5.6 step 1 or section 5.7 step 1 respectively; effect: none. The poll returns no verdict, the lease is neither released nor reported on, and no other principal's lease can be discovered this way | The lease's own service principal calls each method on its active lease: the poll returns its section 5.7 verdict with the current revocation sequence and the report is recorded on that lease only, each on the active lease, and release then returns `released` |
| 21 | A mutating call (for example `service.lease.request`) reuses an `operation_id` already recorded for the same principal and method, but with different canonical arguments | `service_operation_conflict` under section 3; effect: none. The recorded first outcome is unchanged and no second binding, lease or hold is created | The same call retried with the same `operation_id` and equal canonical arguments: the recorded outcome returns, with no second effect (and, for material, only under the replay rule of section 3) |
| 22 | An exposed-lane lease was issued to the agent principal for a `claude-oauth-token` account before its machine policy was switched to secret-free per account; after the switch the agent principal calls `lease.renew` on it within its recorded limit, with binding and chains otherwise valid | `secret_free_lease_required` under the section 1 interlock at broker section 8.5 (after the repeated broker section 8.2 step 1 and again before material release); effect: none. The pre-switch lease is not renewable after the switch and no new exposed lease issues | Two controls: before the switch, while the readable policy determined and selected the exposed lane for that account and kind, the same renewal proceeded under broker section 8.5; after the switch, material for the account is reached only by `service.lease.request` to its service principal |
| 23 | An agent principal calls `lease.request` (and, in the same condition, `lease.renew` on a live exposed lease) for a `claude-oauth-token` account while the protected machine policy cannot be read, or does not determine the mode for that account and kind, with binding and chains otherwise valid | `secret_free_lease_required` under the section 1 interlock (fail closed) at broker sections 8.2 and 8.5, after broker section 8.2 step 1 and again before material release; effect: none. Indeterminacy never defaults to the exposed lane | The same calls with the policy readable and determining the exposed lane for that account and kind, separately qualified: they proceed under broker sections 8.2 and 8.5; and with that readable policy selecting secret-free mode instead, row 8 and row 22 refuse them |
| 24 | The reply to a successful `service.lease.request` (or `service.lease.renew`) is lost, and the same service principal retries with the same `operation_id` and equal arguments only after `max(now, watermark)` has reached the recorded `authorized_until`, with both authorities otherwise current | The recorded outcome returns with `lease_not_active` under section 3; effect: none. No payload is released on the late replay, so the recorded limit and the section 5.3 ceiling are not passed, and no second lease or extension is created | The same retry while the lease is still `active` and before its recorded `authorized_until`, with the final authority, revocation and hold checks still passing: the recorded outcome returns and the payload is released to that service principal only |
| 25 | The reply to a successful `service.lease.renew` is lost; the gateway then releases that lease, and the same principal afterwards retries the renewal with the same `operation_id` and equal arguments | The recorded outcome returns with `lease_not_active` under section 3; effect: none. No payload is released on the replay after release, and the released lease is not extended or revived | The same renewal retry made before any release, while the lease is `active` and before its recorded `authorized_until`: the one recorded extension returns as in row 24 |
| 26 | A lease's binding is removed by `service.unbind` and a fresh `service.bind` then creates a new active binding for the same triple and account; the service principal under the new binding calls `service.lease.renew` on the old lease | `service_binding_unknown` at section 5.4 step 1, because the lease's recorded `service_binding_id` is not the currently active binding; effect: none. The new binding inherits no old lease and no material is released | A fresh `service.lease.request` by that principal under the new active binding, passing every check of section 5.3: a fresh lease issues to that principal only |
| 27 | `account.hold` with reason `leak_match` names the calling service principal's own lease on that account, but that lease ended (released, expired or revoked) earlier than `service_lease_max_lifetime_seconds` before the evaluation time | `lease_not_active` at section 5.8 step 3; effect: none. No hold is recorded under the stale lease | The same call when that own lease ended no more than `service_lease_max_lifetime_seconds` ago, with role, own-lease, account-match and closed-reason checks all passing: the hold is durable before the reply under section 5.8 step 3(b) |

## 10. Open items

| Open item | Owner |
|---|---|
| Placeholder format and its delivery to the launch | gateway |
| Listener binding: the qualified routing that binds listener ownership, generation, launch and served policy to the gateway mapping of section 7 | gateway, with the user manager |
| `revocation_sequence` encoding under the `unavailable` verdict (section 5.7) | broker |
| Action service | later |

Listing an item here assigns it no format, method, record or refusal code
in this dialect, and closes no activation gate in
[secret-free mode](secret-free-mode.md) section 13.
