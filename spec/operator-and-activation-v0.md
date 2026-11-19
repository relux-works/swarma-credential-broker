# Operator and activation v0

**Status: PROPOSED. Revision: 1. Test profile: v0. Inactive.**
Scope: one Linux host, local placement, `credential-gateway`, `claude_code`,
`claude-oauth-token` only. This is one proposed production-assembly section,
not an implementation, accepted owner decision, deployment instruction or
qualification result. The repository owner decides the items below;
specification-acceptor review remains separate. Until then the existing stopped
owner and absence of a service controller remain unchanged.
Basis: `spec/broker.md:156`, `spec/secret-free-service-v0.md:3`,
`spec/secret-free-service-v0.md:17`, `spec/secret-free-mode.md:433`.

## 1. Sources, disposition and notation

Source locations below refer to unchanged cited line spans at source base
`c5dfa9e27abb24369faa1179078bf9cf7fbec7d8`. Book references use `swarma-docs`
revision `b57a9be633c245373b448c3786bcbd49d636fe8a`:

- **Same:** book chapter **Operator and interfaces**,
  `book/ru/16-interfeysy.md:49` and `book/ru/16-interfeysy.md:68`, cited by
  `docs/production-assembly-stop.md:9`: confined entry, exact act, terminal
  password fallback, no agent sessions, separate observer. Reuse these rules.
- **Same:** book chapter **OS user per agent and network**,
  `book/ru/04-polzovatel-i-set.md:27`: installer/user-manager separation and
  narrow privileged entries; `docs/managed-identity-provider.md:13` names the
  managed-identity chapter under its earlier chapter name. No local user
  creation or substitute identity ledger is introduced.
- **Refines, requiring a specification decision:** the new spellings, schemas,
  paths and integration below fill the explicit gaps in `spec/broker.md:182`,
  `spec/broker.md:860`, `spec/broker.md:885` and
  `docs/managed-identity-provider.md:93`. Every unsettled bundle is labelled
  **DECISION-NEEDED** in section 8; its recommendation is the concrete proposed
  contract, not an already accepted default.
- **Refines, requiring an owner decision:** TTY-only token capture narrows the
  pipe example in `spec/broker.md:335` (DN-04). The existing software root signs
  the terminal act, while a protected receipt proves terminal authentication
  (DN-02); neither is a phone signature. No phone key or second-device ceremony
  is required by this test profile. A decision that instead changes the signed
  act requirement of `spec/broker.md:245` would be a conflict, not a refinement.
- **New operational integration:** the sudo authentication witness, installed
  source layout and unit template require the corresponding book/install
  update if accepted (DN-02, DN-05, DN-08). They are not attributed to the book.

`D` denotes `/opt/swarma/services/swarma-credential-broker`; `S` denotes
`D/store`; `A(id)` denotes `S/account-` followed by lowercase hex
`SHA-256(UTF-8(id))`. `P` denotes `/opt/swarma`. UID/GID values are installer
outputs, never literal examples or request-selected authority. `broker:broker`
below means the installed broker UID and its dedicated primary GID, not root.
These concrete layout choices are DN-05/DN-08. The existing home, unprivileged
service identity and outside-store socket boundary come from
`spec/broker.md:883`, `spec/broker.md:899`, `docs/production-assembly-stop.md:52`.

All proposed JSON objects are closed, required members are explicit, and arrays
are required even when empty. CCJ-1 means its existing canonical UTF-8 JSON
bytes, sorted object keys, no insignificant whitespace and no trailing LF;
reject duplicate keys, invalid Unicode, unknown members, floats, negative zero
and integers outside the safe range. Times are RFC 3339 UTC with `Z`.
`digest` means `sha256:` plus 64 lowercase hex digits; `nonce` and
`operation_id` are independent random 128-bit values encoded as 32 lowercase
hex digits. No new grant or revocation domain is assigned.
Basis: `spec/broker.md:386`, `spec/broker.md:388`,
`spec/secret-free-service-v0.md:148`; proposed identifier spelling: DN-01/DN-03.

## 2. operator-act-contract

### 2.1 Terminal entry and authentication

V0 uses **TERMINAL FALLBACK ONLY** from broker section 14. The proposed installed
entry is `/usr/libexec/swarma-credential-broker-operator-v0`, with **no argv**.
The person invokes `sudo -k -u swarma-operator --` followed by that absolute
entry. Its sole stdin document is a nonsecret CCJ-1 candidate
`{method, arguments}`; limit 16 KiB, one document, read within five seconds.
The command adds the authoritative fields below; no caller-supplied operator,
authentication, confirmation or receipt field is accepted. An enrollment
candidate contains only account metadata, never token bytes or a token digest.
Concrete entry and input limits: **DECISION-NEEDED DN-01**.
Basis: `spec/broker.md:850`, `spec/broker.md:856`, `spec/broker.md:860`;
book narrow-input precedent: `book/ru/04-polzovatel-i-set.md:31`.

The installer confines sudo to this exact executable and empty argument list,
run-as `swarma-operator`, password authentication for **each act**,
`timestamp_timeout=0`, no `NOPASSWD`, no `SETENV`, no shell/editor/harness
escape and no alternative execution entry into that identity. Sudo input/output
recording and terminal session recording are disabled for this entry; fixed
metadata auditing remains. Neither a successful ordinary login nor
`SUDO_UID`, environment hints or matching peer UID establishes an act.
There is no phone path, SSH operator entry, phone-key prerequisite or
noninteractive token-input alternative in this v0 profile. This scope does
not change the later second-device requirement.
Basis: `spec/broker.md:210`, `spec/broker.md:214`, `spec/broker.md:854`,
`spec/broker.md:856`, `spec/broker.md:858`, `spec/broker.md:885`;
confinement/recording integration: **DECISION-NEEDED DN-02/DN-04**.

**Proposed authentication witness (DN-02):** a root-installed sudo/PAM session
integration creates one root-owned receipt only after real password
authentication, trusted local login/controlling-TTY provenance, agent-session
exclusion and execution of the pinned entry as the configured operator. It
remains privileged while the command runs unprivileged. A dedicated private
control channel binds that invocation to the final act digest after display
and any required confirmation; it carries no token. The witness validates the live process
identity, executable digest and its own authentication session, not assertions
from an arbitrary operator process. It cannot issue receipts to general UID
peers. Unknown provenance, an agent ancestor/session, command substitution,
unavailable witness or recording-enabled terminal refuses before token input.
This privileged integration must be supplied and qualified; peer credentials
alone are explicitly insufficient. Basis: `spec/broker.md:166`,
`spec/broker.md:858`, `docs/claude-custody.md:59`.

The private channel is an unnamed local socketpair, installed by the privileged
sudo integration as FD3 of the one pinned command, with all other inherited
capabilities closed; the command marks FD3 close-on-exec immediately. It uses
the existing four-byte big-endian length plus CCJ-1 framing, bounded to 64 KiB,
but is not a broker connection. Before token input, the witness sends exactly
`{format, installation_id, authority_revision, authority_digest, nonce, operator, broker_uid, socket_path, authenticated_at, expires_at, tty_device}`,
with `format=swarma-broker-terminal-session/1`. The command uses these trusted
session values when composing the act and checking the server peer; `operator`
is the full configured pin and `socket_path` is the installed broker socket.
The command needs no access to the broker private directory or root authority
file. The witness verifies enabled activation/current pins before token input,
then releases configuration locks during human interaction; it rechecks them
before accepting the final act. After display, required confirmation
and signing it sends
exactly `{act, confirmation}`, containing no token; the witness verifies the
envelope and matching session and returns exactly `{receipt_nonce}` after
durably creating the receipt. EOF, an extra frame, a changed process/TTY or
session expiry closes the operation. This fills the proposed witness byte
boundary, not an assertion that sudo already supplies FD3. Basis:
`spec/broker.md:856`, `spec/broker.md:860`, `spec/broker.md:765`; DN-02/DN-03.

The broker verifies the receipt file in section 4, its authenticated process
binding against kernel peer PID/UID and boot/process-start identity, the
configured directory pin, installation/policy/revision pins, act digest,
freshness and required confirmation. It rechecks the live peer immediately
before a mutation, under the state lock. Receipt consumption and the final
operation outcome are published together in the broker journal, after the
intent/target reconciliation below. A receipt permits one
exact invocation, not another connection, act, process or future grant.
No broker connection or privileged witness channel may be inherited by a
harness. Basis: `spec/broker.md:196`, `spec/broker.md:198`,
`spec/broker.md:203`, `docs/claude-custody.md:59`; receipt details: DN-02/DN-06.

### 2.2 Exact canonical act

The proposed closed act body has these required members (DN-03):

| Member | Exact value/type |
| --- | --- |
| `format` | `swarma-broker-operator-act/1` |
| `installation_id` | The configured never-reused installation identifier |
| `authority_revision` | Positive safe integer from the protected authority file |
| `operator` | Closed `{uid, name, home}` pin; name is `swarma-operator` |
| `operation_id` | The method operation identity, unchanged on an equal retry |
| `nonce` | Fresh authentication-invocation identity |
| `not_before`, `expires_at` | Trusted UTC bounds, a nonempty interval of at most 300 seconds |
| `method` | `service.bind`, `account.enrol`, `service.unbind` or `account.hold.lift` only |
| `arguments` | Exactly the applicable closed object below |

The domain is the ASCII string `swarma-credential-broker operator-act/1`.
The preimage is `domain || LF || CCJ-1(body)`, with exactly one separating LF
and no terminal LF. `act_id = sha256:` plus lowercase SHA-256 of that preimage.
The signed act envelope is exactly `{body, id, sig}`, with `id=act_id` and
`sig` the unpadded base64url 64-byte Ed25519 signature of the configured
operator software-root key over that same preimage. Neither `id` nor `sig`
enters the preimage. The broker verifies it using the protected `operator_key`.
The domain separates this record from grants, revocations and phone acts;
it is not a broker request-signature domain or a claim of phone presence.
It reuses the existing signature algorithm/software root, not new hardware.
The separate root receipt proves fresh password authentication: a valid
software-root signature or matching operator UID alone is still insufficient.
The replay argument commitment uses a separate exact preimage:
`ASCII("swarma-credential-broker operator-arguments/1") || LF || UTF-8(method) || LF || CCJ-1(arguments)`.
Its digest binds the complete arguments, including the enrollment prefix,
without persisting that prefix as a separate record member.
Basis: `spec/broker.md:245`, `spec/broker.md:386`, `spec/broker.md:852`,
`spec/broker.md:856`, `spec/broker.md:860`; **DECISION-NEEDED DN-02/DN-03**.

For `service.bind`, `arguments` is exactly
`{operation_id, service_name, uid, service_generation, account, kind, installation_policy_digest}`
from service dialect section 5.1; its `operation_id` equals the body member.
The receipt is side evidence for those bytes, not extra method members.
For the already named `account.enrol` subscription operation, it is exactly
`{operation_id, account, harness, kind, issued_at, token_sha256_prefix}`:
`harness=claude_code`, `kind=claude-oauth-token`, `issued_at` is null or the
person-stated UTC time; ownership is derived, never supplied here.
`token_sha256_prefix` is the first 16 bytes of
`SHA-256(ASCII("swarma-credential-broker enrollment-token/1") || LF || token_bytes)`,
encoded as 32 lowercase hex digits. Neither the token nor a reversible
encoding is an act member. No full token digest is displayed or persisted.
Basis: `spec/secret-free-service-v0.md:259`, `spec/broker.md:264`,
`spec/broker.md:333`, `spec/broker.md:339`; enrollment/prefix choices:
**DECISION-NEEDED DN-03/DN-04**.

Preserve the two already-published lifecycle acts as well: `service.unbind`
arguments are exactly `{operation_id, service_binding_id}` and narrow authority;
`account.hold.lift` arguments are exactly `{operation_id, hold_id, account}`
and widen authority. Each inner operation ID equals the body operation ID.
Their existing role/owner checks, order and outcomes remain unchanged. No
other administrative act or phone format is published by this profile.
Basis: `spec/secret-free-service-v0.md:235`,
`spec/secret-free-service-v0.md:323`, `spec/secret-free-service-v0.md:760`;
entry mapping: DN-01/DN-03.

The command writes to its controlling TTY: method; operator pin; account;
service name/UID/generation and kind for bind; harness/kind/issue time and the
labelled digest prefix for enrollment; installation, policy digest where
applicable, revision, operation ID, nonce and both validity times. It then
displays the target binding/hold IDs when applicable, the domain, byte length,
**complete canonical body** and `act_id`.
Strings are JSON-escaped, never interpreted as terminal controls; no pager,
ellipsis, omitted member or friendly-name substitution is allowed. The person
types exactly `CONFIRM <act_id>` and Enter, case-sensitive, with no surrounding
spaces; only the final LF is excluded from comparison. EOF, mismatch, timeout,
TTY change or interruption refuses with no mutation. Any content change
requires a new display, any required confirmation and authenticated invocation. Enrollment,
bind and hold lift are widening acts; authentication alone cannot authorize
them. Unbind is authentication-only: display the same exact nonsecret content
but request no typed confirmation; its witness confirmation field is null.
Basis: `spec/broker.md:333`, `spec/broker.md:858`,
`spec/secret-free-service-v0.md:235`; exact display/confirmation: DN-03.

After the applicable confirmation the entry opens a fresh close-on-exec `broker/1` connection,
verifies the broker peer UID, and sends the act plus receipt nonce using the
proposed closed administrative method `operator.act.v0` (DN-01/DN-04):
`{act, receipt_nonce, token}`. `act` is the complete signed envelope from
section 2.2; `receipt_nonce` equals its body nonce and selects only that
hexadecimal filename.
`token` is null for every non-enrollment act and an in-memory string
for enrollment. This wrapper is not `service.bind` and does not add members to
that method. Its receiver validates admission, then dispatches the unchanged
inner service bind/unbind/lift arguments in their normative order, or the
enrollment receiver in section 3. It grants no other method. Framing remains the existing
64 KiB CCJ-1 frames and versions-only hello. Human interaction finishes before
opening this connection; broker administrative deadlines remain two seconds.
Basis: `spec/broker.md:765`, `spec/secret-free-service-v0.md:74`,
`spec/secret-free-service-v0.md:235`, `spec/secret-free-service-v0.md:284`.

## 3. owner-enrollment-transport

The account owner is the configured `swarma-operator` principal, never the
person login UID. The user manager operator UID is this same protected pin,
not a second role assigned to a terminal login. The protected policy may
reserve an account ID for that
owner before enrollment; this is **not** an existing enrolled account and
does not satisfy bind step 4. Enrollment requires the authenticated configured
operator, an explicit matching planned ownership row and exact confirmation;
an existing account with another owner refuses, never transfers ownership.
`View.Owner` for existing accounts also requires the durable account owner
record to match the same pin. Basis: `spec/broker.md:210`,
`spec/broker.md:214`, `spec/broker.md:267`, `spec/broker.md:333`,
`spec/secret-free-service-v0.md:302`; proposed planned rows: DN-05.

The proposed receiver refuses missing operator/owner admission as
`role_not_permitted`, malformed metadata as `request_malformed`, invalid token
framing or a digest-prefix mismatch as `enrol_material_invalid`, a different
operation attempting to replace existing custody as `account_exists`, and a
reused operation ID with unequal argument commitment as
`service_operation_conflict` (explicit enrollment extension under DN-04).
Each has effect none; uncertain publication instead remains unavailable/unknown,
not a fabricated definite refusal or success. Basis: `spec/broker.md:333`,
`spec/secret-free-service-v0.md:176`, `docs/claude-custody.md:16`,
`docs/claude-custody.md:97`; exact enrollment mapping: DN-04.

Inside that authenticated invocation, the person deliberately supplies the
fresh vendor `setup-token` using the **controlling TTY only**. The command
opens `/dev/tty`, verifies it is the authenticated foreground terminal, saves
its terminal state, disables `ECHO` and `ECHONL` before the first token byte,
and reads one LF-terminated token of 1 through 16,384 printable ASCII bytes
excluding whitespace. The LF is framing, not token content; CR, NUL, embedded
LF, excess bytes, timeout and missing TTY refuse without normalization.
The maximum human-input interval is the act authentication lifetime, 300 s.
Echo is restored before the nonsecret act display and on every success,
refusal and handled interruption. A signal-safe supervisor restores it after
child death; an unprovable terminal state requires a fresh terminal, not a
silent continuation. Synthetic canary qualification must exercise this path.
Basis: `spec/broker.md:175`, `spec/broker.md:333`, `spec/broker.md:858`;
TTY framing, bound and restoration integration: **DECISION-NEEDED DN-04**.

The token never enters argv, environment, stdin candidates, act files,
authentication receipts, logs, errors, history, temporary files or audit
payloads. Protected non-dumpable locked memory and disabled core/I/O capture
are prerequisites; inability to enforce them refuses before input. Capture
and transmission buffers are cleared on all exits. The only transmitted copy
is the confidential enrollment field on the verified local broker connection,
after exact-content confirmation. The broker recomputes the prefix before
writing anything and rejects mismatch. Secret frames must never be dumped.
Here "no file" means **no transport or staging file**: the pre-existing
broker-only 0600 secret store in a 0700 directory is the sole permitted durable
custody destination, as required by `spec/broker.md:329` and
`spec/broker.md:339`; this proposal adds no alternate token file/backend.
Basis also: `spec/broker.md:175`, `docs/claude-custody.md:16`,
`docs/claude-custody.md:83`; memory/receiver choices: DN-04.

The receiver derives ownership, validates the policy and prefix, then invokes
existing Claude custody enrollment, not refresh/import/native-login adoption.
Only enrollment makes the account exist; no bootstrap bind or metadata-only
precreation precedes it. Receipt consumption, intent and nonsecret outcome
use the journal below; a token prefix is displayed transiently but not copied
into status, audit or the service journal. Persist only the act ID and
canonical nonsecret metadata needed to reconcile enrollment. Service-bind
arguments contain no token-derived value. A crash with uncertain custody
publication keeps the account unavailable: reconcile existing protected
metadata/material durability under its sole writer, never overwrite or adopt
an orphan as a successful enrollment. Basis: `spec/broker.md:339`,
`docs/claude-custody.md:16`, `docs/claude-custody.md:83`,
`docs/store-records.md:25`; enrollment transaction detail: DN-04/DN-06.

Every retry needs fresh password authentication and a fresh receipt. Same
operator/method/operation ID and equal committed arguments resolve the existing
durable outcome, never a second bind, custody write or authority extension;
changed arguments refuse. Enrollment equality uses the transient prefix
commitment while the durable outcome records the act commitment; the journal
must retain a nonsecret argument-commitment digest, not the raw token prefix.
Unknown is not success. A fresh receipt may authenticate an equal retry but
does not revive an expired act; construct a fresh bounded act for the same
operation/arguments. Token-free status may report the existing metadata, not
reconstruct a token or fabricate success. Basis:
`spec/secret-free-service-v0.md:165`, `docs/claude-custody.md:93`;
enrollment replay extension: **DECISION-NEEDED DN-04/DN-06**.

## 4. protected-authority-assembly

### 4.1 Paths, protection and freshness

This is the complete proposed source inventory for the service `View`; request
claims, static UID allowlists, environment values and last-known-good caches
are not sources. **Every absent, unreadable, malformed, stale or unjoined
required fact refuses** its affected operation. An explicitly initialized
empty array is a known empty set, not permission to treat a missing file as
empty. Initialization is installer-owned, only for a new empty installation.
Basis: `spec/broker.md:212`, `spec/broker.md:429`,
`spec/secret-free-service-v0.md:395`, `docs/managed-identity-provider.md:104`,
`docs/store-records.md:8`; new inventory details: **DN-02/DN-05/DN-06/DN-07**.

| Source / View fact | Path and schema | Owner / exact mode | Freshness and missing-fact rule |
| --- | --- | --- | --- |
| Operator/observer/broker pins | `/etc/swarma/credential-broker/authority-v0.json`, schema below; local `/etc/passwd` directory name/UID/home join | Authority root:broker 0640; passwd root:root 0644 | Authority digest equals activation pin, same installation/revision; directory pin checked every identity window. Drift refuses `principal_identity_changed`; unknown peer refuses `role_not_permitted`. |
| Authenticated exact act | `/run/swarma/credential-broker/operator-acts/<nonce>.json`, receipt below | root:broker 0640 | Current boot, live peer process and invocation, trusted act interval, exact digest/confirmation, unused nonce or equal recorded retry. Missing/forged evidence refuses `role_not_permitted`; it never creates an operator. |
| Managed service and caller generation/class/placement | `P/lib/user-manager/identities.json` (`swarma-managed-identities/1`) joined to `P/lib/user-manager/generations/journal` (`gen-journal/1`) | root:root 0644, including existing locks | Exact same protected read pass and journal head; existing provider and original verifier rules unchanged. Service lookup remains service-only; caller lookup must prove active agent kind independently using the same verified evidence. Any gap refuses `principal_ledger_mismatch`. |
| Planned account owner and service policy | Account rows in `authority-v0.json` | root:broker 0640 | Exact account/kind selection and current digest; no default mode. Existing account ownership additionally matches broker account metadata. Missing policy refuses `service_binding_mismatch`; missing existing account refuses the method account-unknown code. |
| Existing account owner/state and material | Account registry in `D/authority-journal-v0.json` plus existing `A(id)/owner-claude-account.json` (`claude-account-record/1`) and `owner-claude-material.json` (`claude-material-record/1`) custody records | broker:broker 0600; directories 0700 | Registry identity/owner joins current operator pin; custody metadata is current and compatible, and publication rechecks it. Missing metadata is not an enrolled account; no material lookup for ownership or status. |
| Caller grants, originating binding and class evidence | `D/authority-journal-v0.json`, schema below | broker:broker 0600 | Sole writer, current revision under the state lock, independently verified signed chains and current managed-generation/class join; no request-supplied binding authority. Missing binding refuses `lease_unbound`; class gaps refuse `principal_ledger_mismatch`; invalid grants retain their `grant_*` refusals. |
| Service bindings, leases, holds and operation outcomes | Existing account `A(id)/owner-claude-service.json`, `claude-service-journal/1` | broker:broker 0600; directories 0700 | Current durable CAS revision, not a cached snapshot. Unbind tombstones, holds and outcome retention survive restart; unavailable journal closes authority and never clears a hold. |
| Revocations and `Sequence()` | `revocations` in `D/authority-journal-v0.json`, the sole baseline `{seq, records}` state | broker:broker 0600 | Same state lock and publication point as caller verification, monotone sequence and external recovery evidence. Missing state refuses `revocation_state_unavailable`, never `records=[]`; unavailable sequence follows DN-07. |
| Typed `Event()` validation and recorded events | Protected authority `event_schema` selector, fixed typed schema below; `events` in `D/authority-journal-v0.json`, lease reports in existing service journal | Authority root:broker 0640; journals broker:broker 0600 | Current format/closed event validator and lease ownership; no free-text policy or request-defined validator. Missing/incompatible event evidence refuses `request_malformed`; events grant no mutation power. |

Paths not fixed by the cited contracts, including the proposed daemon journal,
are DN-05/DN-06 recommendations, not claims that they are installed. The three
`owner-claude-*.json` basenames and account-directory derivation identify the
existing custody slots; preserve them and their formats, rather than rename,
migrate or silently adopt legacy files. Source basis for the table:
`spec/broker.md:210`, `spec/broker.md:262`, `spec/broker.md:386`,
`spec/broker.md:429`, `spec/broker.md:463`, `spec/broker.md:479`,
`spec/broker.md:698`, `spec/broker.md:756`,
`spec/secret-free-service-v0.md:395`, `spec/secret-free-service-v0.md:813`,
`docs/managed-identity-provider.md:44`, `docs/managed-identity-provider.md:66`,
`docs/claude-custody.md:83`, `docs/claude-custody.md:110`.

Every proposed protected JSON file is regular, single-linked, no symlink,
exact owner/group/mode including special bits, bounded by the existing 1 MiB
record ceiling unless its format owner already specifies another bound.
Resolve ancestors descriptor-relatively from `/`, without symlink following,
and reject group/world-writable ancestors. Root configuration/receipt
directories are root:broker 0750; broker data directories remain broker:broker
0700 with protected root-owned ancestors. The existing runtime socket directory
remains the explicit broker-owned 0755 exception, not an authority-file source.
Root facts are written by privileged installation/witness writers only, never
by a service/agent; broker journals only by the broker. Writes use temporary
file, file sync, atomic same-directory rename and directory sync before
acknowledgment. Basis: `spec/broker.md:329`, `spec/broker.md:429`,
`spec/broker.md:756`, `spec/broker.md:900`,
`docs/managed-identity-provider.md:44`, `docs/store-records.md:3`; DN-05/DN-06.

### 4.2 Closed authority, receipt and journal schemas

The existing custody records are not replaced by the authority journal:
metadata is closed `{kind, installation_id, revision, status}`, with
`kind=claude-account-record/1`; status is closed
`{account, harness, credential_kind, mode, state, token_expires_at, refreshable}`,
with Claude harness/kind, mode `secret-free`, state `enrolled|held`, nullable
known expiry and `refreshable=false`. Material is the existing closed
`{kind, installation_id, revision, token}` with
`kind=claude-material-record/1`; its token encoding belongs to existing custody
and is never an authority/status source. The service transaction is the
existing closed `{kind, installation_id, revision, watermark, bindings, leases, holds, operations}`,
with `kind=claude-service-journal/1`; its nested bindings/leases/holds are the
exact service-dialect section 6 records. Its nonsecret operation entries are
closed `{principal, method, operation_id, arguments, result, at}`. Existing
installation/revision/identity checks and the 1 MiB stored-byte limit remain.
Basis: `docs/claude-custody.md:16`, `docs/claude-custody.md:83`,
`spec/secret-free-service-v0.md:811`, `docs/store-records.md:3`;
inventory/mapping confirmation: DN-05/DN-06, not a custody-format migration.

`authority-v0.json` has exactly the required members below (DN-05).
`root_keys` and `dispatchers` are explicit arrays, not trust-on-first-use.

| Member | Schema |
| --- | --- |
| `format`, `installation_id`, `revision` | `swarma-broker-authority/1`, installation identifier, positive safe integer |
| `broker` | Closed `{uid, gid, name, home}`; installed broker identity and `D` |
| `operator`, `observer` | Each closed `{uid, name, home}`; dedicated distinct local unmanaged directory pins named `swarma-operator` and `swarma-observer`, no harness entry |
| `operator_entry` | Closed `{path, digest}`; exact libexec entry and approved executable digest |
| `operator_key` | Existing operator software-root public `ed25519:` key, present in the configured roots; no private key in this document |
| `terminal_callers` | Explicit distinct closed `{uid, name, home}` local login pins eligible for terminal authentication; no agent/workplace identities, and no owner authority from this list alone |
| `event_schema` | Exactly `broker-events/1`, the typed schema below |
| `root_keys` | Distinct baseline `ed25519:` public keys; no private material |
| `dispatchers` | Distinct closed `{uid, generation, key}` records, active managed generation and configured public delegating key |
| `accounts` | Distinct closed `{account, owner_uid, harness, kind, mode}` rows; owner equals operator UID, harness `claude_code`, kind `claude-oauth-token`, mode `secret-free` |

`installation_policy_digest` is the digest of the complete authority document
CCJ-1 bytes. It covers pins and account selection, not request-selected data.
A change requires a new revision/digest, connection closure and explicit
restart/rebinding as applicable; old bindings never inherit a new policy.
Pin names/homes are nonempty exact local directory strings, UIDs/GIDs are
uint32, generations are the existing 32-lowercase-hex identifiers, and paths
are normalized absolute paths. Account rows are unique by account/kind;
principal-role UID sets must be disjoint, including the broker itself.
`broker.name` is `swarma-credential-broker`; its UID/GID must match the running
daemon. A terminal caller is not the operator, observer, service or dispatcher.
Unmanaged operator/observer pins are checked against the protected local
directory; managed client lookup is composed alongside them, never by teaching
the existing service-only provider to call an operator a gateway. Other
directory backends or helper-managed operator pins require a later contract.
Basis: `spec/broker.md:210`, `spec/broker.md:213`,
`spec/secret-free-service-v0.md:57`, `spec/secret-free-service-v0.md:305`,
`docs/managed-identity-provider.md:93`; **DECISION-NEEDED DN-05**.

A receipt has exactly
`{format, installation_id, authority_revision, act_id, nonce, operator_uid, boot_id, peer_pid, peer_start_ticks, executable_digest, tty_device, authenticated_at, expires_at, authentication, confirmation}`.
`format=swarma-broker-terminal-receipt/1`, `authentication=password-sudo`,
`confirmation=exact-content` for widening or `not-required` for unbind only;
IDs/digests/times follow section 1; PID is
positive, UID is uint32, process-start ticks and TTY device numbers are safe
nonnegative integers, and boot ID is the kernel boot UUID. `tty_device` is
closed `{major, minor}`. Expiry is no later than authentication plus 300 s
and the act expiry. The receipt contains neither token nor act arguments.
The root witness creates it only after the applicable authentication/confirmation,
and removes expired
receipts after durable consumption evidence; the broker never writes it.
Root-receipt authenticity is protected ownership plus the qualified witness,
not a phone signature. Basis: `spec/broker.md:166`, `spec/broker.md:856`,
`docs/claude-custody.md:59`; **DECISION-NEEDED DN-02/DN-03**.

`authority-journal-v0.json` is one closed, atomically replaced document
`{format, installation_id, revision, accounts, grants, bindings, admissions, revocations, events, operator_outcomes}`,
with `format=swarma-broker-authority-journal/1` and positive safe revision.
`accounts` contains closed `{account, owner, custody_revision}` rows; `owner`
is the configured operator pin, never a ceremony UID. `grants` contains exact
baseline grant envelopes; `bindings` exact baseline `binding/1` records;
`admissions` contains closed `{uid, generation, class, placement, journal_head}`
records retaining the verified user-manager head at admission. Current reads
revalidate that same UID/generation and its class/placement against the live
projection (`trusted`, `local` required); a historical row never overrides a
changed current record. The protected producer evidence, not dispatcher
assertions, justifies class/placement. `revocations` is exactly `{seq, records}` with signed
baseline revocation envelopes. `seq` is a nonnegative safe integer; no overflow
or reset is admitted. `events` contains closed `{at, account, lease_id, event}`
rows; `operator_outcomes` contains closed
`{operation_id, method, operator, argument_commitment, act_ids, consumed_nonces, state, result}`
rows, state `intent`, `committed` or `refused`; result is null for intent,
the existing bind/unbind/lift result or enrollment account metadata for committed, and
closed `{code}` with the actual method refusal for refused. `act_ids` and
`consumed_nonces` are explicit arrays. `argument_commitment` is a
the exact domain-separated digest defined in section 2, never the arguments
containing a token prefix themselves. Unknown state or partial intent grants
no authority. Enrollment intent prevents duplicate writes; service operations
still use their existing per-account durable outcomes. The join must be
reconciled before acknowledgment, not mistaken for a cross-file atomic write.
Basis: `spec/broker.md:262`, `spec/broker.md:365`, `spec/broker.md:419`,
`spec/broker.md:429`, `spec/broker.md:463`, `spec/broker.md:479`,
`docs/claude-custody.md:83`; **DECISION-NEEDED DN-05/DN-06/DN-07**.

The existing broker admission paths populate authority, not direct file edits:
`grant.put`/`revocation.put` retain their signed key-holder rules and configured
dispatchers create/remove originating bindings through `bind`/`unbind`.
Admitted changes are validated and journaled by the broker; reading a request
does not itself make it a protected fact. Existing valid signed submissions
and dispatcher calls do not gain an operator role or use this wrapper.
Initial root delegation is an explicit pre-existing authority prerequisite,
not produced from an empty journal, a static allowlist or a service binding.
This profile does not publish additional operator grant-issuance grammar.
Basis: `spec/broker.md:483`, `spec/broker.md:787`, `spec/broker.md:789`,
`spec/broker.md:800`; installed journal integration: DN-05/DN-06.

Publish an operator operation in this order: (1) durable authority-journal
intent with method/argument commitment and reserved nonce, (2) the existing
target custody or service transaction, (3) durable committed/refused outcome
and consumed nonce, then reply. The same operation may not run concurrently.
After a crash, first reconcile the target transaction under the sole writer;
never infer success from an intent, and never rerun an irreversible custody
write merely because step 3 is absent. A fresh authenticated equal retry can
finish reconciliation. Ambiguous custody or journal durability keeps that
account unavailable and the outcome unknown. The per-account hold path does
not wait on this operator-outcome journal. Basis: `spec/broker.md:767`,
`spec/secret-free-service-v0.md:165`, `spec/secret-free-service-v0.md:857`,
`docs/claude-custody.md:88`; cross-file protocol: DN-04/DN-06.

The proposed nonsecret event encoding is a closed tagged object: exactly
`{kind: lease_expiring}`, `{kind: lease_expired}`, `{kind: reauth_required}`,
or `{kind: credential_error, class: auth|permission|quota|unknown}`. This fixes
the still-needed encoding, not a new event semantic. Reports remain limited
to the reporting lease, never account hold/lift or automatic notification.
Basis: `spec/broker.md:698`, `spec/broker.md:705`,
`spec/secret-free-service-v0.md:574`; encoding: **DECISION-NEEDED DN-06**.

### 4.3 Coherent views and independent containment

The proposed root configuration lock is
`/etc/swarma/credential-broker/authority.lock`, root:broker 0640, regular,
single-link, exactly zero bytes, with the protected ancestors above. Its inode
is created once by the installer and never replaced. Root configuration
writers take it exclusively before replacing activation/authority documents;
enabled readers take a shared nonblocking lock before their protected read,
then the existing user-manager gate/data locks, then the broker state lock,
and retain the shared configuration/data locks through the bounded callback.
A writer, missing lock, replaced inode or lock failure refuses that window.
Human TTY interaction holds none of these locks; changed pins are rechecked
after it. This is a proposed local synchronization contract, not a claim that
root ownership alone makes a stale snapshot current. Basis:
`docs/claude-custody.md:21`, `docs/managed-identity-provider.md:44`,
`spec/broker.md:767`; lock path/protocol: **DECISION-NEEDED DN-05/DN-06**.

`WithIdentity` settles only operator/service identity and exact operator-act
evidence. `WithCurrent` additionally settles current policy, account owner,
caller bindings/chains, revocations, sequence and trusted time. Capture facts
before the broker state lock, use the user-manager gate/data read protocol,
and keep the complete joined evidence stable through the bounded final
publication callback. No network/PAM/user-manager RPC runs under that lock.
Use the existing 250 ms identity window, cancellation and final live-principal
check, not a new cache TTL. Mutation after a wait repeats final checks.
Basis: `spec/broker.md:767`, `spec/secret-free-service-v0.md:194`,
`docs/claude-custody.md:21`, `docs/managed-identity-provider.md:75`.

Unavailable caller/use facts block issue and renewal, but **do not become a
new prerequisite for `account.hold`**: its identity-only path and its own lease,
account, reason and bounded recent-end evidence remain exactly the accepted
order. Operator unbind and stop retain independent narrowing paths. Missing
identity or hold durability still refuses; nothing silently clears a hold.
Basis: `docs/claude-custody.md:134`, `spec/secret-free-service-v0.md:194`.

The sole baseline revocation sequence is also the service poll sequence;
service-journal revision, policy revision and user-manager head are not that
sequence. Proposed unavailable encoding is JSON `null`, never zero or a cached
last-success value; both baseline and service poll must agree (DN-07).
External restore/start evidence, durable consumer high-water and trusted-time
restart continuity must remain outside the restored service-home failure
domain. This proposal selects **no substitute witness backend or fabricated
initial floor**. Until those independently owned contracts and installation
gates are satisfied, `enabled=true` cannot open issuance. Known old bytes are
not current facts. Basis: `spec/broker.md:429`, `spec/broker.md:431`,
`spec/broker.md:903`, `spec/secret-free-service-v0.md:615`,
`docs/managed-identity-provider.md:110`; **DECISION-NEEDED DN-07/DN-09**.

## 5. activation-schema and service-lifetime-selector

The proposed activation path is
`/etc/swarma/credential-broker/activation-v0.json`, **root:root 0644**,
regular, single-link, no symlink or extra permission bits. Its ancestors are
root-owned and not group/world writable; the immediate directory may be
root:broker 0750 as above. It is one CCJ-1 document, at most 16 KiB, with this
closed schema; only the last member is optional (DN-05):

| Member | Required value/type |
| --- | --- |
| `format` | `swarma-broker-activation/1` |
| `enabled` | Boolean only |
| `test_profile` | `v0` |
| `installation_id` | Exact operational configuration/store installation ID |
| `platform_root` | Exact normalized absolute `P`, never an environment override |
| `service_name` | `credential-gateway` |
| `kind` | `claude-oauth-token` |
| `authority_digest` | Digest of current protected authority document |
| `service_lease_max_lifetime_seconds` | Optional integral 1..900; absent means 900 |

**Absent activation file means inactive**, exactly today: stopped owner, no
production service controller/provider and no new production enrollment,
service bind or service-lease capability. Existing baseline reads remain as
before. Valid `enabled=false` means the same stopped assembly. A present
invalid/unreadable file, unsafe ancestor, malformed pin, schema/version or ceiling
is a startup refusal, not absence and not a fallback to an enabled or exposed
lane. Validate a present document even when `enabled=false`. A valid false
document does not open or require the authority/custody sources; an enabled
document additionally requires every source and equality join it selects.
An enabled authority-digest mismatch is a startup refusal, never fallback.
Basis: `spec/broker.md:156`, `spec/broker.md:178`,
`spec/secret-free-service-v0.md:462`, `docs/managed-identity-provider.md:110`;
**DECISION-NEEDED DN-05**.

`enabled=true` authorizes construction of the existing Claude custody owner,
managed-identity leg, independently protected facts and service controller
after structural/protection checks on their installed sources. It allows the
administrative bootstrap below; **every operation still requires its own
admission/qualification gates, and production material use remains closed
until the existing production gates pass**. It is not a
service binding, enrollment, caller grant, hold lift, trusted-time assertion,
restore reopen or vendor validity claim. An initialized but unenrolled planned
account remains unusable; only the enrollment administrative path may create
it. That enrollment also initializes its explicit empty per-account service
journal before acknowledgment; a later missing journal is never an empty set.
No account needs a service binding for enrollment or daemon bootstrap. Missing
caller grants do not prevent enrollment or an independently admitted hold,
but still prevent issue/renewal. Control-plane startup does not require a
successful real-token run that itself depends on enrollment; it grants no
qualification bypass for the ensuing gateway run.
Secret-free account selection is the protected authority policy above, never
the flag alone. Missing facts always close affected authority.
Basis: `spec/broker.md:166`, `spec/secret-free-service-v0.md:27`,
`spec/secret-free-service-v0.md:302`, `spec/secret-free-mode.md:433`;
bootstrap handling: DN-04/DN-05/DN-08.

Activation and authority are **startup-only**, not enabled by SIGHUP. Every
active authority window verifies their pinned identities/digests remain
unchanged; drift closes production admission and affected connections. A new
accepted revision requires explicit restart and fresh bindings where policy
pins changed. Disabling/removing activation cannot erase custody, holds or
outcomes; stop new use, close connections and preserve evidence. Existing
operational config remains broker-owned 0600 at `D/config.json`; it supplies
the daemon/store/socket and existing policy fields, not root activation.
Its static `allowed_uids` never supplies service/caller/owner authority.
Basis: `spec/broker.md:164`, `spec/broker.md:756`,
`spec/secret-free-service-v0.md:57`, `docs/production-assembly-stop.md:24`;
**DECISION-NEEDED DN-05/DN-08**.

The **only service lifetime selector** is
`activation.service_lease_max_lifetime_seconds`. Default 900 s; a smaller
positive integer is permitted; **above 900 refuses startup and never clamps**.
Zero, negative, float, string, null or conflicting selector also refuses.
The legacy `policy.max_lease_seconds` is unrelated. Issue and renewal compute
the earliest of trusted evaluation time plus this ceiling, **every** binding
and caller-chain authority expiry, and known token expiry; vendor expiry is
reported separately and never extended. Replay preserves the recorded limit,
then rechecks current authority before any material release. A change requires
restart and cannot revive a dead lease.
Basis: `spec/secret-free-service-v0.md:454`,
`spec/secret-free-service-v0.md:462`, `spec/secret-free-service-v0.md:509`,
`spec/secret-free-service-v0.md:520`, `docs/claude-custody.md:99`;
selector location: DN-05.

## 6. bootstrap-and-deployment

This is the **one proposed order**, not an instruction to execute it now:

1. Installer provisions broker/operator/observer identities, protected binaries,
   config, source directories, sudo witness and disabled unit; pins numeric
   identities from authoritative creation/directory records. The user manager
   creates the broker service user under the existing installer role, then the
   `credential-gateway` managed service account and active generation. Verify
   the accepted projection/journal bytes, including closed service-name rules;
   do not relax the provider or assume a created UID is an admitted client.
2. Installer initializes only the new empty store/journals, installs explicit
   policy/owner plans and qualified independent time/restore/high-water inputs.
   Only after the applicable prerequisite gates pass may it install the
   accepted activation and start the broker control plane. **Gateway stays
   stopped**. The broker may enroll a planned account without a service binding;
   absent custody still refuses every bind/issue for that account.
3. The person authenticates as the configured operator and enrolls the Claude
   token through section 3. Wait for durable account/custody metadata, not just
   browser success or the existence of a directory.
4. The person performs a separately authenticated, confirmed `service.bind`
   for the existing managed gateway triple, enrolled account and current policy
   digest. Preserve all six section 5.1 checks and their order. Persist before
   reply; a lost reply is reconciled by the same operation ID.
5. Start the gateway under that managed service identity **last**. Before use
   it needs its own service lease and the independent originating caller
   binding/grants. Starting the gateway supplies neither. Containment and
   service-route qualification still precede a real production use claim.

This resolves the qualification plan ordering conflict in favor of the
existing bind prerequisite: **user-manager service creation -> operator
enrollment -> operator bind -> gateway start**. Starting the broker before
enrollment is not starting the gateway or bypassing bind. Do not add a
metadata-only account seed or a bind-before-enrollment special case.
Basis: `spec/broker.md:103`, `spec/broker.md:333`, `spec/broker.md:883`,
`spec/broker.md:885`, `spec/secret-free-service-v0.md:287`,
`spec/secret-free-service-v0.md:302`, `docs/production-assembly-stop.md:52`;
deployment plumbing: **DECISION-NEEDED DN-08**.

### Systemd template fields (proposal only)

The proposed unit path is
`/etc/systemd/system/swarma-credential-broker.service`, root:root 0644,
regular single-link, root-protected ancestors. These are fields to render and
qualify, **not a unit file added by this change** (DN-08):

| Section / field | Proposed value or rendering rule |
| --- | --- |
| `[Unit] Description` | Swarma credential broker |
| `[Unit] After`, `Requires` | Exact installed user-manager readiness/time/continuity dependencies; installer substitutes their actual unit names, no invented target or claim that ordering alone proves readiness |
| `[Service] Type` | `simple` |
| `User`, `Group` | Numeric broker UID/GID from protected provisioning; fail if directory/home pin differs |
| `WorkingDirectory` | `D` |
| `ExecStart` | `/usr/libexec/swarma-credential-broker daemon --config /opt/swarma/services/swarma-credential-broker/config.json` |
| `UMask`, `LimitCORE` | `0077`, `0` |
| `KillMode`, `SendSIGKILL`, `TimeoutStopSec` | `control-group`, `yes`, `30s`; positive process-absence evidence still required before replacement |
| `NoNewPrivileges` | `yes`; the separate operator sudo entry is not a daemon child |
| `Restart` | `no` for first qualification; later restart policy requires the same restore/freeze/start checks |
| `StandardOutput`, `StandardError` | `journal`, fixed nonsecret diagnostics only; no request/frame logging |
| `[Install] WantedBy` | `multi-user.target`; installation leaves unit disabled until explicit admission |

Broker binary and operator entry are root:root 0755 at their absolute paths,
regular single-link with root-protected ancestors. Config is broker:broker
0600; `D` and `S` broker:broker 0700; socket basename is proposed as
`/opt/swarma/run/credential-broker/broker.sock`, mode 0666, in the existing
broker-owned 0755 directory with root-protected ancestors. No socket
activation or auto-initialize flag is implied. Unit content contains no token,
credential environment variable, literal UID example or broad sudo rule.
The installer resolves all template fields before installing; an unresolved
dependency or inadequate sandbox/read path is a failed readiness gate.
Basis: `spec/broker.md:883`, `spec/broker.md:899`, `spec/broker.md:903`,
`spec/broker.md:907`, `docs/production-assembly-stop.md:52`; all new basenames,
flags/template choices and stop bound: **DECISION-NEEDED DN-08**.

## 7. Contract qualification required after owner decisions

No executable test is added or claimed here. The brief has no implementation
surface table; the following is the proposed contract witness inventory, not
a filled coverage map or killed-mutant report. Each refusal requires an
adjacent valid control and unchanged post-refusal custody/authority state.
Basis: `docs/production-assembly-stop.md:90`,
`spec/secret-free-service-v0.md:1015`, `spec/secret-free-mode.md:381`.

| Contract | Required paired witness before implementation handoff |
| --- | --- |
| Activation | Absent/false stays stopped versus protected true assembly; malformed/unknown, owner/mode/link/ancestor/pin mutation and >900 refuse startup, never fallback/clamp. |
| Operator and owner | Real per-act password/confirmation versus bare same UID, observer, gateway, agent session, forged/expired/replayed receipt, changed content and wrong owner; no mutation. |
| Enrollment | Synthetic canary through the actual TTY path, echo-off and restoration on success/refusal/signals; no argv/env/log/staging file copies; token/prefix mismatch and interrupted publication versus durable enrollment. Never use a live token for these tests. |
| View sources | Remove or stale each table fact beside a coherent valid snapshot; wrong managed kind/class/placement/head and replacement binding refuse; unavailable caller facts still permit an independently admitted hold. |
| Journal/sequence | Equal retry versus conflict and crash-before/after-durability; no duplicate custody/binding/hold, no sequence reset or cached-success substitution, no missing file treated as empty. |
| Bootstrap/lifetime | Bind before enrolled account refuses; complete ordered control succeeds; issue/renewal at 900 and smaller ceiling, earlier caller/token expiry, no revival or second replay extension. |

Use narrowing control plants for the actual activation, operator/owner,
no-echo/no-record and lifetime gates once implemented; report named failing
tests and survivors, not unapplied-plant credit. Existing time, restore,
consumer high-water, native publication window, hold headroom, listener/route
and teardown gates stay independent. Documentation approval alone activates
nothing. Basis: `docs/production-assembly-stop.md:94`,
`docs/managed-identity-provider.md:75`, `docs/claude-custody.md:123`,
`spec/secret-free-mode.md:433`.

## 8. DECISION-NEEDED register

Every entry is **DECISION-NEEDED**, with two options. Recommendations are the
single concrete proposal used above. Acceptance must identify this revision,
any amended bytes and the affected specification/book owners; implementation
must not choose an option on the owners behalf.

| ID | Unfixed choice and source gap | Option A | Option B | Recommendation |
| --- | --- | --- | --- | --- |
| DN-01 | Operator binary/verb, input framing and receiving wrapper (`spec/broker.md:860`) | Fixed no-argv libexec entry and closed `operator.act.v0` wrapper on existing socket, as section 2 | Add an operator verb to the existing broker binary with a separately confined argv grammar | A: narrow sudo matching, no token in argv, no second service socket. |
| DN-02 | Trustworthy terminal authentication/agent-exclusion evidence and signed terminal-act admission (`spec/broker.md:245`, `spec/broker.md:856`, `docs/claude-custody.md:59`) | Existing software-root signed act plus root sudo/PAM invocation witness and protected one-use receipt, as section 2 | Same signed act and sole-entry confinement plus independently verified live sudo/executable/process provenance, with no receipt format | A: explicit verifiable authentication rather than UID/key possession; root integration and its qualification are prerequisites, not supplied by this change. |
| DN-03 | Act type/domain, 300 s freshness, identifiers, full display, typed confirmation and 128-bit token digest prefix (`spec/broker.md:860`) | Exact section 2 CCJ-1/domain and `CONFIRM <act_id>` grammar | A distinct versioned canonical envelope with a full typed canonical-content confirmation and a longer 192-bit digest prefix | A: bounded exact-content review; no phone signature or grant-domain reuse. |
| DN-04 | TTY-only transport versus pipe example, token framing/memory/recording safeguards and enrollment receiver/replay (`spec/broker.md:335`, `spec/broker.md:339`) | Sections 2-3 authenticated TTY-only capture, bounded secret field on existing socket, existing custody plus durable reconciliation | Preserve pipe/stdin capture with an independently authenticated receiving protocol and explicitly revise the v0 request | A: meets the requested TTY-only profile; the token never becomes an act or staging file. |
| DN-05 | Activation/authority paths, closed schemas, modes, local directory pins, planned ownership/policy and startup-only reload (`spec/broker.md:156`, `spec/broker.md:213`, `docs/production-assembly-stop.md:49`) | Separate root-owned activation and authority documents from sections 4-5, unmanaged operator/observer pins and selector in activation | One new root-owned versioned deployment manifest containing activation, managed operator pins and authority policy, with a separately published reader | A: preserves existing broker-owned operational config and the service-only managed provider; no silent root-file takeover. |
| DN-06 | Broker authority journal/schema, typed event encoding, source basename mapping and cross-file recovery (`spec/broker.md:479`, `spec/broker.md:756`, `docs/claude-custody.md:83`) | One protected authority snapshot/journal plus unchanged per-account service/custody records and reconciled intents, as section 4 | Separate protected grant/binding/revocation/event/outcome journals joined by an explicitly published transaction head | A: smallest coherent local authority source; no independent commit is mistaken for multi-file atomicity. |
| DN-07 | Unavailable sequence encoding and its relation to the sole baseline state (`spec/secret-free-service-v0.md:615`, `spec/secret-free-service-v0.md:1074`) | Same nonnegative baseline `seq` for known state; JSON null when unavailable in both dialects | Versioned tagged known/unavailable representation published jointly for both dialects | A: no invented zero/last-success authority; do not activate before baseline compatibility is accepted. |
| DN-08 | Installer bootstrapping, broker/config/socket/unit basenames, resolved dependencies and service-manager fields (`spec/broker.md:883`, `spec/broker.md:907`, `docs/production-assembly-stop.md:52`) | Section 6 ordering and system unit template; broker control plane before enrollment, gateway last | Same mandatory create/enroll/bind/start order, but a separately qualified temporary enrollment-only broker unit before the steady daemon | A: one owner/custody implementation and no bind-before-account exception; concrete installed dependency names remain installer inputs. |
| DN-09 | Independent time/restore/high-water custody not supplied by identity projection (`spec/broker.md:431`, `spec/broker.md:903`, `docs/managed-identity-provider.md:110`) | Keep activation closed until the existing owners publish and qualify independent continuity/recovery inputs | Restrict this revision to non-authorizing diagnostics while the same missing gates are resolved separately | A for eventual production assembly; B is todays safe operational state, not a relaxation or a selected witness backend. |

An accepted decision resolves only its listed publication gap. Source delivery,
owner acceptance, acceptor review, implementation, signed-head review/checks,
installation and real-token qualification remain separate gates.
Basis: `spec/secret-free-service-v0.md:3`, `spec/secret-free-mode.md:433`,
`docs/production-assembly-stop.md:102`.
