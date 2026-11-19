# Operator and activation v0

**Status: PROPOSED. Revision: 2. Test profile: v0. Inactive.**
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
- **Conflicts, requiring an explicit owner decision and amendments (DN-05):**
  moving principal/root-key pins and machine policy from broker-owned
  configuration into root-owned authority contradicts broker §§4.2, 12.4,
  15.1/15.2 and service dialect §1/§5.1 step 5. Section 4.4 publishes the
  proposed replacement language and the remaining operational-config locus.
  This is not a refinement or an accepted ownership change.
- **Refines, requiring an owner decision:** TTY-only token capture narrows the
  pipe example in `spec/broker.md:335` (DN-04). The existing software root signs
  the terminal act, while a protected receipt proves terminal authentication
  (DN-02); neither is a phone signature. No phone key or second-device ceremony
  is required by this test profile. A decision that instead changes the signed
  act requirement of `spec/broker.md:245` would be a conflict, not a refinement.
- **New operational integration:** the sudo authentication witness, installed
  source layout and unit template require the corresponding book/install
  update if accepted (DN-02, DN-05, DN-08). They are not attributed to the book.
- **Conflicts, TEST-PROFILE v0 only (DN-09 C):** allowing a time witness and
  its history to share the whole-VM rollback domain contradicts
  `docs/time-contract.md:272-279` and `docs/time-contract.md:297-306`.
  Section 4.3 gives the exact proposed exception and a clause-by-clause
  disposition audit. Acceptance requires the time-contract owner's approval
  of that amendment, not of a refinement. It is machine-bound, dedicated-test
  only, time-boxed and never changes production answer A or qualifies production.
- **Refines, DN-06:** the service dialect's effect-none rule applies to method
  records; burning a transport authentication nonce creates no refused method
  outcome or operation-ID reservation. Section 4.2 preserves fresh admission.

`D` denotes `/opt/swarma/services/swarma-credential-broker`; `S` denotes
`D/store`; `A(id)` denotes `S/account-` followed by lowercase hex
`SHA-256(UTF-8(id))`. `P` denotes `/opt/swarma`. UID/GID values are installer
outputs, never literal examples or request-selected authority. `broker:broker`
below means the installed broker UID and its dedicated primary GID, not root.
That GID has no other human, service or agent members; group-readable receipt
or authority data is not shared with observers or terminal callers.
These concrete layout choices are DN-05/DN-08. The existing home, unprivileged
service identity and outside-store socket boundary come from
`spec/broker.md:883`, `spec/broker.md:899`, `docs/production-assembly-stop.md:52`.

All proposed JSON objects are closed, required members are explicit, and arrays
are required even when empty. CCJ-1 means its existing canonical UTF-8 JSON
bytes, sorted object keys, no insignificant whitespace and no trailing LF;
reject duplicate keys, invalid Unicode, unknown members, floats, negative zero
and integers outside the safe range. UTC times are RFC 3339 with `Z`;
explicit BOOTTIME millisecond values are safe nonnegative integers.
`digest` means `sha256:` plus 64 lowercase hex digits; `nonce` and
`operation_id` are independent random 128-bit values encoded as 32 lowercase
hex digits. No new grant or revocation domain is assigned.
Basis: `spec/broker.md:386`, `spec/broker.md:388`,
`spec/secret-free-service-v0.md:148`; proposed identifier spelling: DN-01/DN-03.

## 2. operator-act-contract

### 2.1 Terminal entry and authentication

V0 uses **TERMINAL FALLBACK ONLY** from broker section 14. The proposed installed
entry is `/usr/libexec/swarma-credential-broker-operator-v0`, with **no argv**.
The fresh-login ceremony launcher invokes `/usr/bin/sudo -k -u swarma-operator --`
followed by that absolute entry; no interactive shell resolves `sudo`.
Its sole stdin document is a nonsecret CCJ-1 candidate
`{method, arguments}`; limit 16 KiB, one document, read within five seconds.
Stdin MUST NOT be a TTY; candidate input and secret/confirmation input cannot
interleave. It is a completely prepared regular file, not a pipe whose writer
could be frozen during authentication. The executable rejects every argv member.
The command adds the authoritative fields below; no caller-supplied operator,
authentication, confirmation or receipt field is accepted. An enrollment
candidate contains only account metadata, never token bytes or a token digest.
Concrete entry and input limits: **DECISION-NEEDED DN-01**.
Basis: `spec/broker.md:850`, `spec/broker.md:856`, `spec/broker.md:860`;
book narrow-input precedent: `book/ru/04-polzovatel-i-set.md:31`.

The following DN-02 sub-decisions are normative prerequisites of this proposed
profile; a missing proof refuses as `role_not_permitted` before password or
token input. A process-name/ancestry scan, environment flag, UID match or
operator-key possession alone is never a substitute.

1. **DN-02a, dedicated human caller.** Every `terminal_callers` UID is a
   dedicated human login, never a harness/agent/workplace identity and never
   the operator itself. It has never run an agent, harness or vendor CLI.
   Installation checks the protected managed projection,
   service launch configuration and all processes with any credential for
   that UID. A harness service, agent-controlled process, second login or
   process outside the one authenticated login session refuses. Session
   membership is rooted in the privileged login-service record and its
   non-delegated session containment, not the current parent PID: reparenting,
   double fork, `setsid` and a user-manager launch do not erase membership or
   authorize an extra process. Disable lingering and the per-UID systemd user
   manager, including `user@<uid>.service`; do not exempt it from this check.
   Each act uses a fresh authenticated login/session and outer TTY, ending
   that login after the invocation. Its login shell is a pinned root-owned
   ceremony launcher, not a general shell; it executes only the absolute sudo
   entry and never interprets caller files, functions, aliases or commands.
   The launcher, every startup file it can read, every PATH component and all
   their ancestors are root-owned and not caller-writable. Caller-writable
   filesystems are `noexec`; this is additional confinement, not a claim that
   `noexec` prevents an interpreter from reading attacker code. The launcher
   permits no such interpreter or alternate execution. The root login gate
   checks these paths before any prompt; the witness checks them again at
   every ceremony and binds the login -> launcher -> sudo -> entry ancestry
   by pidfds, start ticks and executable/configuration digests. A current
   process scan alone cannot establish this trusted path or account history.
   Unknown history, any earlier agent execution or a caller-writable path
   voids the login: refuse, retire the caller account, vendor-revoke exposed
   tokens and provision a fresh dedicated caller before another ceremony.
2. **DN-02b, password and sudo policy.** The sudoers user list equals
   `terminal_callers`; the command rule ends with the empty argument string
   `""`. Select `runaspw`, with `runas_default=swarma-operator`: authentication
   uses that dedicated operator password, not the login credential. Use a
   dedicated, pinned PAM service with `auth required pam_unix.so`, no
   `sufficient`, optional, key/device-only, passwordless or included alternative
   auth path, and pinned account/session modules. Require a new successful
   password conversation for every act, including unbind. Set
   `timestamp_timeout=0` for every rule of each terminal caller; callers have
   no other sudo rule, including root or a shell/editor escape. No
   `NOPASSWD`, `SETENV`, cached ticket or alternative entry supplies a receipt.
   Other pinned no-shell operator entries, including the user-manager entry,
   remain possible under broker §15.1, with their own per-act password and the
   same trusted-login, requiretty, no `-S`/`-A`/askpass password-source rules;
   the shared operator password must not be phishable through another entry.
   Only the broker entry digest receives this receipt.
3. **DN-02c, explicit terminal/authentication path.** Pin `requiretty`,
   `!use_pty`, `!log_input`, `!log_output`, no remote I/O logging, `env_reset`,
   `!setenv` and `closefrom=3` without caller override. Refuse `sudo -S`,
   `-A`/askpass, noninteractive/cached authentication and any password source
   except the authenticated outer terminal. Disabling `use_pty` is deliberate:
   there is no sudo inner pty to confuse with the outer login TTY. A deployment
   with a different setting is not this profile. Pin the sudo/plugin/PAM
   configuration and executable digests; defaults are not evidence.
4. **DN-02d, outer-login provenance.** Support only a directly authenticated
   Linux VT/console through a pinned getty/login path, or direct SSH through
   the actual installed, explicitly selected server/session path (including
   OpenSSH or Tailscale SSH only if that implementation satisfies every
   predicate). An OpenSSH assumption cannot qualify a different host login
   service. SSH into the human caller
   is not an SSH operator entry and does not grant operator authority. The
   privileged session record binds audit loginuid, session identifier, caller
   pin, boot ID, login-process PID/start ticks/executable digest and original
   controlling TTY device. The command TTY, foreground process group and
   session TTY must join that record. For a pty, root enumerates all master
   holders using `/proc/*/fdinfo` `tty-index` plus the devpts instance. The
   allowed set is implementation-specific and pinned: for qualified OpenSSH
   it includes its root monitor and per-session master-holding child, each
   joined to this same authenticated connection; for another server every
   master-holding role must be separately published and qualified. Every
   holder must have the pinned executable, protected process identity,
   nondumpability and live start binding. A singular assumed sshd PID is not
   sufficient. Any extra holder, passed master, nested pty,
   multiplexer, `script`, expect, IDE or harness refuses. A VT has no pty
   master; its console/login access must satisfy the same exclusive-input
   condition. Unknown process/FD visibility or login path refuses, including
   an SSH-only deployment whose actual server path is not qualified.
5. **DN-02e, exclusive input and execution integrity.** From authentication
   through display/capture/submission, the root login/witness gate serializes
   logins and process launch for the caller UID. It places all nontrusted
   caller tasks, including the waiting shell, in a root-owned nondelegated
   cgroup and verifies `cgroup.freeze=1`/`frozen=1`; pinned root witness/login
   relays and the operator entry run outside that frozen group. Enumerating
   credentials must prove no other caller task outside that set. While that
   gate is held, the witness limits the slave to operator-only 0600 access,
   verifies all existing terminal FDs (only pinned relays/entry and frozen
   tasks), and forbids FD transfer, extra master holders and input injection.
   Unprivileged accounts have no terminal group/device or proc-memory access;
   the kernel input-injection path is disabled. Thus a same-UID slave reader
   is rejected or remains frozen, not merely missed by a one-time scan. A
   task/FD visibility gap or inability to hold this gate refuses before input.
   The supervisor holds the input/launch gate through the queue discard and
   full terminal restoration in section 3, before thawing on any exit. It
   never returns token residue to a caller shell. These are witness-owned
   resources, not permission to freeze arbitrary user sessions.
   The root-owned operator ELF is unreadable to all but root (0711), with
   no file capabilities/set-ID bits; pin `fs.suid_dumpable=0`. Qualify that
   the deployed kernel enforces nondumpability on exec of this unreadable
   image before its first instruction (Linux v6.12 `fs/exec.c`, `would_dump`
   and `begin_new_exec`), and verify it remains non-dumpable. It performs no
   further exec; setting `PR_SET_DUMPABLE` only after startup is insufficient.
   Core dumps, ptrace/process-memory access and terminal/password auditing
   are excluded. No qualified gate/exec-boundary proof means no receipt, not
   best-effort admission. The witness rechecks session, holders and live peer
   immediately before issuance. Trusted root/kernel/login service and the
   owner-controlled SSH endpoint remain the boundary; compromise of those is
   not defeated by a TTY predicate. Endpoint recording/capture is a ceremony
   exclusion, never something the server claims to detect remotely.

Sudo, terminal, kernel TTY audit and client session recording are disabled for
this ceremony; fixed metadata auditing remains, without token-derived values.
There is no phone path, phone-key prerequisite or noninteractive token-input
alternative in v0. This does not change the later second-device requirement.
Basis: `spec/broker.md:210`, `spec/broker.md:214`, `spec/broker.md:854`,
`spec/broker.md:856`, `spec/broker.md:858`, `spec/broker.md:885`;
confinement/recording integration: **DECISION-NEEDED DN-02/DN-04**.

**Proposed authentication witness (DN-02):** a qualified root-installed sudo
plugin, with the pinned password-only PAM stack, enforces DN-02a through e
and creates one root-owned receipt for the pinned operator invocation. It
remains privileged while the command runs unprivileged. A dedicated private
control channel binds that invocation to the final act digest after display
and any required confirmation; it carries no token. The witness validates the live process
identity, executable digest and its own authentication session, not assertions
from an arbitrary operator process. It cannot issue receipts to general UID
peers. Unknown provenance, failed confinement, command substitution or an
unavailable witness refuses before token input.
This privileged integration must be supplied and qualified; peer credentials
alone are explicitly insufficient. Basis: `spec/broker.md:166`,
`spec/broker.md:858`, `docs/claude-custody.md:59`.

The private channel uses a **post-exec rendezvous**, not an inherited FD3.
Sudoers remains the policy plugin and enforces `closefrom=3`; neither caller
override nor an approval/I/O plugin is claimed to inject a descriptor. The
qualified privileged integration records its password-authentication session
with the root witness. The entry connects close-on-exec to the installed
`/run/swarma/credential-broker-operator/witness.sock`: root:root 0666 socket,
root:root 0711 directory, root-protected ancestors. Connect permission alone
grants nothing. Before reading the candidate or any TTY input, the entry
checks its effective UID against the protected local operator directory pin
and the socket peer's `SO_PEERCRED` UID is 0. The witness checks the client's
`SO_PEERCRED`, opens a pidfd, verifies start ticks/executable digest and the
parent sudo PID against its own fresh authentication-session record, and
checks the complete DN-02 ancestry. It accepts exactly one connection from
that live invocation, never a general operator-UID peer or a caller-supplied
auth record. Both sides reject peer substitution before any input. It uses
the existing four-byte big-endian length plus CCJ-1 framing, bounded to 64 KiB,
but is not a broker connection. After reading the non-TTY candidate, the entry
first sends exactly `{method, account}`, with one of the four allowed methods
and the candidate account, or null for unbind. The witness binds these to the
session; no alternate final method/account is accepted.
Before token input, the witness sends exactly
`{format, installation_id, authority_revision, authority_digest, nonce, operator, terminal_caller, broker_uid, socket_path, freshness, tty_device, account_policy, continuity}`,
with `format=swarma-broker-terminal-session/1`. The command uses these trusted
session values when composing the act and checking the server peer; `operator`
is the full configured pin and `socket_path` is the installed broker socket.
The command needs no access to the broker private directory or root authority
file. `account_policy` is closed `{account, test_subscription}` from the
protected matching row, and `continuity` is the protected selector in section
5; both are null for unbind. The witness verifies current identity pins, and
enabled activation, C machine/account scope and expiry for widening only,
before token input;
then releases configuration locks during human interaction; it rechecks them
before accepting the final act. After display, required confirmation
and signing it sends
exactly `{act, confirmation}`, containing no token; the witness verifies the
envelope and matching session and returns exactly `{receipt_nonce}` after
durably creating the receipt. EOF, an extra frame, a changed process/TTY or
session expiry closes the operation. This fills the proposed witness byte
boundary, not an assertion that stock sudo/PAM supplies the rendezvous or
authentication record. Qualifying this session-to-peer join, root supervisor
and the no-dump exec boundary is an implementation prerequisite before
freezing/accepting DN-02, not a `closefrom_override` workaround. Basis:
`spec/broker.md:856`, `spec/broker.md:860`, `spec/broker.md:765`; DN-02/DN-03.

The entry submits exactly one wrapper request on exactly one broker
connection, with no reconnect/retry inside the invocation. After its result
it sends exactly `{retire_nonce}` on the witness channel, equal to the issued
nonce. The root
witness durably unlinks the receipt and syncs its directory before returning
exactly `{retired_nonce}`; only then may the entry report a definite result
to the human and exit. The witness performs the same retirement on entry
death/interruption and never reissues a receipt on that session. Uncertain
retirement is unknown/unavailable, not reusable authentication. This
post-result phase is outside all broker state locks and carries no result,
arguments or operation ID. Together with live-peer binding and the successful
per-account nonce outcome, it burns refused unbind receipts without any
authority-journal write. The private channel permits exactly the three ordered
request/reply exchanges above, with the single broker request between receipt
and retirement. Extra/duplicate frames refuse and retire the invocation.

The broker verifies the receipt file in section 4, its authenticated process
binding against kernel peer PID/UID and boot/process-start identity, the
configured directory pin, installation/policy/revision pins, act digest,
freshness and required confirmation. It rechecks the live peer immediately
before a mutation, under the state lock. Receipt consumption is act-layer
replay evidence, separate from method outcomes; the widening/narrowing storage
paths are specified in section 4.2. A refusal never becomes a replayable
method outcome. A receipt permits one
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
| `authority_digest` | Digest of those exact protected authority bytes, not a revision alone |
| `operator` | Closed `{uid, name, home}` pin; name is `swarma-operator` |
| `operation_id` | The method operation identity, unchanged on an equal retry |
| `nonce` | Fresh authentication-invocation identity |
| `freshness` | The method-specific closed object below; no wall-time requirement for unbind |
| `method` | `service.bind`, `account.enrol`, `service.unbind` or `account.hold.lift` only |
| `arguments` | Exactly the applicable closed object below |

For widening, `freshness` is exactly `{kind, not_before, expires_at}`, with
`kind=utc`, trusted UTC bounds and a nonempty interval of at most 300 seconds.
Evaluate expiry at `max(now, watermark)` and `not_before` at
`min(now, watermark)` (broker §15.1). For `service.unbind` it is exactly
`{kind, boot_id, not_before_ms, expires_at_ms}`, with `kind=boottime`, current
kernel boot UUID and a nonempty `CLOCK_BOOTTIME` millisecond interval of at
most 300,000 ms, checked against that same clock. Boot mismatch, expiry or
peer death refuses. Both forms bind the live PID/start ticks and invocation
in the receipt. Untrusted UTC, restore/time confidence and use-policy gates
cannot prevent forming or accepting the narrowing form.

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
`{operation_id, account, harness, kind, token_expires_at, token_sha256_prefix}`:
`harness=claude_code`, `kind=claude-oauth-token`, `token_expires_at` is null
or the person-stated exact UTC vendor expiry, never an inferred TTL or
enrollment time. Non-null expiry must be a nonzero whole-second UTC `Z` value
in years 0001..9999, matching custody `validExpiry`; fractional seconds,
offsets, zero/out-of-range dates and malformed values refuse as
`request_malformed` before act composition, never round or silently drop.
It maps unchanged to custody `Enroll(token, expiresAt)` and
`Status.TokenExpiresAt`; null maps to nil. There is no `issued_at` member to
confirm and silently discard; ownership is derived, never supplied here.
`token_sha256_prefix` is the first 16 bytes of
`SHA-256(ASCII("swarma-credential-broker enrollment-token/1") || LF || CCJ-1({installation_id, operation_id}) || LF || token_bytes)`,
encoded as 32 lowercase hex digits. Neither the token nor a reversible
encoding is an act member. No full token digest is displayed or persisted.
The prefix, enrollment act ID and argument commitment are **token verifiers**,
not nonsecret metadata. Installation/operation scoping reduces cross-act
linkage, not verifier status.
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
service name/UID/generation and kind for bind; harness/kind/vendor expiry and the
labelled digest prefix for enrollment; the protected `test_subscription` marker
and, under C, the qualified VM identity/revision/expiry; installation, policy digest where
applicable, authority revision/digest, operation ID, nonce and freshness. The
test marker and C scope are committed by the exact `authority_digest`, checked
against the protected rows, never accepted as candidate assertions. It then
displays the target binding/hold IDs when applicable, the domain, byte length,
**complete canonical body** and `act_id`.
Strings JSON-escape every non-ASCII code point as `\u` sequences as well as
controls, never interpreted as terminal controls; no pager,
ellipsis, omitted member or friendly-name substitution is allowed. Render the
complete body reversibly; signing/hashing still uses the original
CCJ-1 UTF-8 bytes, not a recanonicalization of the display. The person
types exactly `CONFIRM <act_id>` and Enter, case-sensitive, with no surrounding
spaces; only the final LF is excluded from comparison. This binds confirmation
to the displayed act; it does not prove the person read or understood it.
EOF, mismatch, timeout,
TTY change or interruption refuses with no mutation. Any content change
requires a new display, any required confirmation and authenticated invocation. Enrollment,
bind and hold lift are widening acts; authentication alone cannot authorize
them. Unbind is authentication-only: display the same exact nonsecret content
but request no typed confirmation; its witness confirmation field is null.
The enrollment display is transient token-verifier output under the exclusive
ceremony, not permitted audit/status output or a persistent transcript.
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
DN-01 acceptance requires adding a broker §13.2 method-table row for
`operator.act.v0`: accepted only from the configured operator with this
password/receipt evidence, dispatching exactly the four named inner methods.
It grants no generic administrative, key-holder or service-role entry.

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
`role_not_permitted`, an absent planned account row as `account_unknown`,
malformed metadata as `request_malformed`, invalid token
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
opens `/dev/tty`, verifies it is the authenticated outer foreground terminal
under DN-02a through e (echo-off alone proves no secrecy), saves
the complete original termios state, also retained by the root supervisor.
Before the first token byte set `ICANON`, `ECHO`, `ECHONL`, `ECHOE`, `ECHOK`,
`IEXTEN`, `IXON` and `ISTRIP` off, `ICRNL` on, `INLCR`/`IGNCR` off, and
`VMIN=1`, `VTIME=0`. Read byte by byte: **1 through 4,096 bytes, each
0x21-0x7e**, then one LF. The terminal's Enter CR-to-LF translation is the
only permitted translation; CR is not token content. No canonical-line
truncation or token normalization is permitted. A 4,097th pre-terminator byte,
NUL, other whitespace/control/non-ASCII byte, timeout or missing TTY refuses
before act composition, confirmation, receipt or custody write. LF terminates
capture; following pasted lines never become confirmation or shell input.
The maximum human-input interval is the act authentication lifetime, 300 s.

**Queue and exit invariant (DN-04).** Under the exclusive input/launch gate,
quiesce input delivery and call `tcflush(tty_fd, TCIFLUSH)` after capture
(including invalid/overlong input), again immediately before confirmation,
and on **every exit path**: success, refusal, timeout, EOF, signal and child
death. Discard type-ahead; never drain it to an output, log or history. Flush
before restoring echo or any saved terminal mode, verify full `tcsetattr`
restoration with `tcgetattr`, then restore ownership/access and only then
release the gate. A root supervisor, not a child signal handler alone, owns
cleanup after uncatchable child death and receipt retirement. Input stays
quiesced/discarded through cleanup: `tcflush` alone followed by a race with a
continuing paste is insufficient. If input quiescence, discard or restoration
cannot be proved, retire the TTY and end the login; do not thaw/resume into
a caller shell. A fresh ceremony login is required after any such failure.
The pinned launcher ends its login after each act, never executes pending
input. Restore the saved mode before the token-verifier display only after
the capture queue is discarded, and flush again before opening confirmation
input. Synthetic canary qualification must exercise all these boundaries.
Supervisor/gate loss also ends the login without resuming a shell; no
child-only guarantee covers a dead supervisor or an unprovable terminal.
Basis: `spec/broker.md:175`, `spec/broker.md:333`, `spec/broker.md:858`;
TTY framing, bound and restoration integration: **DECISION-NEEDED DN-04**.

The token never enters argv, environment, stdin candidates, act files,
authentication receipts, logs, errors, history, temporary files or audit
payloads. Protected non-dumpable locked memory and disabled core/I/O capture
are prerequisites; inability to enforce them refuses before input. Clear the
owned capture/transmission buffers on every exit, without claiming erasure of
Go runtime/compiler/library copies (docs/claude-custody.md, memory limitations).
The vendor `setup-token` command runs only on the owner's nonrecording endpoint
or under a separately trusted non-caller account, **never as a terminal
caller**. Its output is deliberately transferred into the fresh ceremony's
TTY; no vendor CLI/harness executes in the dedicated caller login. A token
printed in an agent session, or obtained after caller-account contamination,
is ineligible and must be vendor-revoked, not reused in this ceremony.
The only transmitted copy
is the confidential enrollment field on the verified local broker connection,
after exact-content confirmation. The broker recomputes the prefix before
any method/custody write and rejects mismatch; burning the act nonce is not
method admission. Secret frames must never be dumped.
Here "no file" means **no transport or staging file**: the pre-existing
broker-only 0600 secret store in a 0700 directory is the sole permitted durable
custody destination, as required by `spec/broker.md:329` and
`spec/broker.md:339`; this proposal adds no alternate token file/backend.
Basis also: `spec/broker.md:175`, `docs/claude-custody.md:16`,
`docs/claude-custody.md:83`; memory/receiver choices: DN-04.

The receiver derives ownership, validates the policy and prefix, then invokes
existing Claude custody enrollment, not refresh/import/native-login adoption.
Only enrollment makes the account exist; no bootstrap bind or metadata-only
precreation precedes it. Receipt consumption, admitted intent and custody outcome
use the journal below; a token prefix is displayed transiently but not copied
into status, audit or the service journal. Enrollment act IDs, signed bodies,
argument commitments and receipt act IDs are token-derived verifiers. Their
only permitted durable locations are broker-only custody/reconciliation state
and the protected root receipt; never status, errors, alerts, general audit,
`effect.observe` replies or service journals. The transient display/channel
exceptions above do not make them nonsecret. Service-bind
arguments contain no token-derived value. A crash with uncertain custody
publication keeps the account unavailable: reconcile existing protected
metadata/material durability under its sole writer, never overwrite or adopt
an orphan as a successful enrollment. Material appended before metadata can
burn that account ID: never adopt, overwrite or complete that orphan on retry.
Recover with a new planned account ID and fresh enrollment; keep the orphan
inert, and vendor-revoke its token before recovery. Basis: `spec/broker.md:339`,
`docs/claude-custody.md:16`, `docs/claude-custody.md:83`,
`docs/store-records.md:25`; enrollment transaction detail: DN-04/DN-06.

Every retry needs fresh password authentication and a fresh receipt. Same
operator/method/operation ID and equal committed arguments resolve an existing
**admitted, committed** durable outcome, never a second bind, custody write
or authority extension;
changed arguments refuse. Enrollment equality uses the transient prefix
commitment while the broker-only durable outcome records the token-verifier
argument commitment, not the raw token prefix. A pre-admission refusal leaves
no method outcome or operation-ID reservation; after correcting its cause,
equal arguments with the same operation ID and a fresh receipt are fresh
admission. Only the old act nonce is burned. An admitted uncertain intent is
not a refusal and remains unavailable pending reconciliation.
Thus dialect effect-none creates/changes no method record; transport nonce
consumption is not admitted work or an exception permitting a refused outcome.
Unknown is not success. A fresh receipt may authenticate an equal retry but
does not revive an expired act; construct a fresh bounded act for the same
operation/arguments. Token-free status may report the existing metadata, not
reconstruct a token or fabricate success. Basis:
`spec/secret-free-service-v0.md:165`, `docs/claude-custody.md:93`;
enrollment replay extension: **DECISION-NEEDED DN-04/DN-06**.

**Disable and rotation in v0 (DN-04).** Disable by authenticated unbind of
**every** binding of the account, plus vendor-side token revocation; record
vendor disposition separately, never claim unbind recalls delivered material.
Do not rebind the disabled account; retire its planned policy row in the next
installer-owned authority revision, retaining old custody only as evidence.
If bindings cannot be enumerated or their
durability is unknown, disable is not established: retain containment/stop and
require vendor revocation. Rotation uses a new account ID admitted by a new
authority revision, fresh token enrollment and separately confirmed new binds;
the old/orphan custody stays inert and is neither overwritten nor adopted.
No in-place replacement, silent hold lift or token reuse is authorized.
This procedure adds no fifth wrapper method and no custody-format migration.
DN-04 also requires explicit broker §5.4/§14 amendments for TTY-only capture
and this receiver, and a Claude-v0 §5.1/§5.2 exception: known expiry is exact
vendor evidence or null, not an `issued_at` plus guessed-kind-lifetime effect.

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
| Authenticated exact act | `/run/swarma/credential-broker/operator-acts/<nonce>.json`, receipt below | root:broker 0640 | Current boot, live peer/invocation and outer-login TTY; widening UTC or unbind BOOTTIME interval, exact digest/confirmation, unused nonce. A method retry still needs a new nonce. Missing/forged evidence refuses `role_not_permitted`; it never creates an operator. |
| Managed service and caller generation/class/placement | `P/lib/user-manager/identities.json` (`swarma-managed-identities/1`) joined to `P/lib/user-manager/generations/journal` (`gen-journal/1`) | root:root 0644, including existing locks | Exact same protected read pass and journal head; existing provider and original verifier rules unchanged. Service lookup remains service-only; caller lookup must prove active agent kind independently using the same verified evidence. Any gap refuses `principal_ledger_mismatch`. |
| Planned account owner and service policy | Account rows in `authority-v0.json` | root:broker 0640 | Exact account/kind selection and current digest; no default mode. Existing account ownership additionally matches broker account metadata. Missing policy refuses `service_binding_mismatch`; missing existing account refuses the method account-unknown code. |
| Existing account owner/state and material | Account registry in `D/authority-journal-v0.json` plus existing `A(id)/owner-claude-account.json` (`claude-account-record/1`) and `owner-claude-material.json` (`claude-material-record/1`) custody records | broker:broker 0600; directories 0700 | Registry identity/owner joins current operator pin; custody metadata is current and compatible, and publication rechecks it. Missing metadata is not an enrolled account; no material lookup for ownership or status. |
| Caller grants and class evidence | `D/authority-journal-v0.json`, schema below | broker:broker 0600 | Sole writer, current revision under the state lock, independently verified signed chains and current managed-generation/class join; no request-supplied authority. Class gaps refuse `principal_ledger_mismatch`; invalid grants retain their `grant_*` refusals. |
| Originating caller bindings, tombstones and receiver effects | Separate `D/caller-bindings-v0.json`, schema below | broker:broker 0600 | Current protected binding/creator and retained effects under the state lock. Dispatcher unbind reads/writes only this state and its own current identity pins, not grants/class history or the authority snapshot. Missing own state is unavailable, never an empty binding set. |
| Service bindings, leases, holds and operation outcomes | Account `A(id)/owner-claude-service.json`; existing `/1`, proposed integration `/2` below | broker:broker 0600; directories 0700 | Current durable CAS revision, not a cached snapshot. Unbind and nonce evidence publish in this account transaction alone; narrowing headroom is reserved before widening. Unavailable own journal refuses, never clears a hold. |
| Act-layer nonce consumption for widening | `D/operator-nonces-v0.json`, schema below | broker:broker 0600 | No method/operation identity or token verifier. A refusal burns only its nonce; unbind does not depend on this file. |
| Revocations and `Sequence()` | Separate `D/revocations-v0.json`, sole baseline `{seq, records}` state in the protected envelope below | broker:broker 0600 | Same state lock/publication point as caller verification, monotone sequence and external recovery evidence. Root/operator-key revocation is independent of grant history; issuer-signed grant revocation needs its verified grant envelope (§6.4). Missing revocation state refuses `revocation_state_unavailable`, never `records=[]`; unavailable sequence follows DN-07. |
| Typed `Event()` validation and recorded events | Protected authority `event_schema` selector, fixed typed schema below; `events` in `D/authority-journal-v0.json`, lease reports in existing service journal | Authority root:broker 0640; journals broker:broker 0600 | Current format/closed event validator and lease ownership; no free-text policy or request-defined validator. Missing/incompatible event evidence refuses `request_malformed`; events grant no mutation power. |

Paths not fixed by the cited contracts, including the proposed daemon journal,
are DN-05/DN-06 recommendations, not claims that they are installed. The three
`owner-claude-*.json` basenames and account-directory derivation identify the
existing custody slots; preserve them and their formats, rather than rename,
migrate or silently adopt legacy files. Source basis for the table:
`spec/broker.md:210`, `spec/broker.md:262`, `spec/broker.md:386`,
`spec/broker.md:429`, broker §6.4 revocation storage, `spec/broker.md:479`,
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

**Proposed integration amendment, DN-06:** use
`kind=claude-service-journal/2` for new v0 installations, retaining the same
top-level members and exact dialect binding/lease/hold/result records. Each
operation entry adds required `receipt`, null for nonoperator operations or
closed `{nonce, terminal_caller, boot_id, peer_pid, peer_start_ticks, freshness}`
for an operator act; `terminal_caller` is its configured directory pin.
For narrowing only, `at` may be null when UTC is untrusted: the BOOTTIME
receipt supplies freshness and no wall-time watermark advances. This is an
explicit versioned service-journal change, not a claim that the current `/1`
reader supports extra members. Token custody records stay unchanged; no
in-place `/1` adoption/migration is published by this fresh-install profile.
No enrollment act ID, token prefix or argument commitment enters either
service-journal format.

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
| `terminal_auth` | Closed `{sudo_digest, sudoers_digest, pam_service, pam_digest, witness_digest, confinement_digest, launcher_digest, trusted_path_digest, login_paths}`; all digests pin installed root-protected enforcement, including launcher/startup/PATH/mount checks; PAM service is the dedicated local name, login paths are distinct closed `{kind, implementation, executable_digest, config_digest}` with kind `vt` or `ssh` and an exact installed login/server implementation identifier; DN-02a through e must all hold |
| `continuity` | The exact protected production/C selector defined in section 5, equal to activation; a C fence cannot select itself |
| `event_schema` | Exactly `broker-events/1`, the typed schema below |
| `root_keys` | Distinct baseline `ed25519:` public keys; no private material |
| `dispatchers` | Distinct closed `{uid, generation, key}` records, active managed generation and configured public delegating key |
| `accounts` | Distinct closed `{account, owner_uid, harness, kind, mode, test_subscription}` rows; owner equals operator UID, harness `claude_code`, kind `claude-oauth-token`, mode `secret-free`; `test_subscription` is a required installer-verified Boolean, true only for a dedicated test subscription |

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
These unmanaged operator/observer accounts are not created through
`user.create`; helper-created pins instead require broker §4.2 managed checks
and are outside this proposed profile. The full-authority policy digest is
deliberately conservative: even a caller/entry-pin change requires rebinding,
not just an account-policy change. DN-05 must accept that operational cost.
Basis: `spec/broker.md:210`, `spec/broker.md:213`,
`spec/secret-free-service-v0.md:57`, `spec/secret-free-service-v0.md:305`,
`docs/managed-identity-provider.md:93`; **DECISION-NEEDED DN-05**.

A receipt has exactly
`{format, installation_id, authority_revision, authority_digest, act_id, nonce, operator_uid, terminal_caller, login_session, boot_id, peer_pid, peer_start_ticks, executable_digest, tty_device, freshness, authentication, confirmation}`.
`format=swarma-broker-terminal-receipt/1`, `authentication=password-sudo`,
`confirmation=exact-content` for widening or `not-required` for unbind only;
`terminal_caller` is the authenticating directory pin; `login_session` is closed
`{kind, id, loginuid, login_pid, login_start_ticks, login_executable_digest}`,
using the verified root login record, not caller-provided strings.
`kind` is `vt|ssh`, `id` the nonnegative safe audit session identifier,
`loginuid` the terminal-caller UID, and login PID/start ticks/digest bind the
same pinned implementation/process as the outer-terminal predicate.
IDs/digests/times follow section 1; PID is
positive, UID is uint32, process-start ticks and TTY device numbers are safe
nonnegative integers, and boot ID is the kernel boot UUID. `tty_device` is
closed `{major, minor}` and always names the outer login terminal.
`freshness` has the same method-specific shape as section 2.2; its interval is
contained in the authenticated session interval and no longer than 300 s.
Unbind uses only current boot/BOOTTIME and live-process binding, never trusted
UTC. The receipt contains neither token nor act arguments; an enrollment
`act_id` is still a token verifier and stays within protected receipt custody.
The root witness creates it only after the applicable authentication/confirmation,
and removes expired
receipts after durable consumption evidence; the broker never writes it.
Root-receipt authenticity is protected ownership plus the qualified witness,
not a phone signature. Basis: `spec/broker.md:166`, `spec/broker.md:856`,
`docs/claude-custody.md:59`; **DECISION-NEEDED DN-02/DN-03**.

`authority-journal-v0.json` is one closed, atomically replaced document
`{format, installation_id, revision, accounts, grants, admissions, events, operator_outcomes}`,
with `format=swarma-broker-authority-journal/1` and positive safe revision.
`accounts` contains closed `{account, owner, custody_revision}` rows; `owner`
is the configured operator pin, never a ceremony UID. `grants` contains exact
baseline grant envelopes; originating bindings are in their independent state;
`admissions` contains closed `{uid, generation, class, placement, journal_head}`
records retaining the verified user-manager head at admission. Current reads
revalidate that same UID/generation and its class/placement against the live
projection (`trusted`, `local` required); a historical row never overrides a
changed current record. The protected producer evidence, not dispatcher
assertions, justifies class/placement. `events` contains closed `{at, account, lease_id, event}`
rows; `operator_outcomes` contains closed
`{operation_id, method, operator, terminal_caller, argument_commitment, act_ids, state, result}`
rows for `account.enrol` only, state **`intent` or `committed`, never `refused`**;
result is null for intent or enrollment account metadata for committed.
`terminal_caller` attributes the admitted act to its authenticating directory
pin. `act_ids` is an explicit array; it and `argument_commitment` are
token verifiers restricted to this broker-only reconciliation state, never
observable outcome/status fields. `argument_commitment` is the exact
domain-separated digest in section 2. Unknown state or an unresolved admitted
intent grants no authority. Enrollment intent prevents duplicate writes;
service methods use only their per-account durable outcomes. The join must be
reconciled before acknowledgment, not mistaken for a cross-file atomic write.
Basis: `spec/broker.md:262`, `spec/broker.md:365`, broker §6.2 grants,
broker §6.4 revocations, `spec/broker.md:479`,
`docs/claude-custody.md:83`; **DECISION-NEEDED DN-05/DN-06/DN-07**.

`operator-nonces-v0.json` is closed
`{format, installation_id, revision, consumed}`, with
`format=swarma-broker-operator-nonces/1`, positive safe revision and distinct
closed `{nonce, boot_id, peer_pid, peer_start_ticks}` rows. It contains no
method, operation ID, arguments, refusal code, act ID or token verifier. It
burns widening receipts, including refused attempts, without reserving method
identity. Entries may be reclaimed only after the bound process is proved
gone or its boot differs: its receipt can then never pass live-peer admission.
Unknown liveness retains evidence. Lack of nonce capacity closes widening,
not unbind or hold. Expired root receipts are removed only after their nonce
is irreversibly unusable; no missing consumed record revives a receipt.

**DN-06 revocation-only Option B:** `D/revocations-v0.json` is closed
`{format, installation_id, revision, state}`, with
`format=swarma-broker-revocations/1`, positive safe revision, and `state`
exactly the baseline `{seq, records}` with signed revocation envelopes.
`seq` is a nonnegative safe integer, never reset or overflowed. This is the
only revocation state/sequence, not a mirror in the authority journal.
For root-key or operator-key signatures, `revocation.put` verifies authority
against current protected pins and publishes here independently of the
authority snapshot, event history, outcomes and widening nonce file. This
covers root/operator revocation of either a grant or a key, including an
issuer's key. **Issuer-signed grant revocations retain broker §6.4:** load the
exact target grant envelope, recompute its ID, verify its signature and require
`by` to equal its issuer. Being a pinned dispatcher/key holder alone never
permits revoking someone else's grant or any key. Unavailable grant history
makes this issuer route unavailable; it is not an independent narrowing
guarantee. Root/operator-key revocation remains the supported route then.

The revocation file itself is bounded to **1 MiB**; retained revocations are
never evicted, compacted away or reset. Valid issuer submissions can exhaust
it. A full, missing or unwritable revocation file refuses the new publication
honestly and fences use; root signatures do not bypass physical capacity.
Containment then uses stop/vendor revocation and an installer authority
revision removing compromised pins, pending trustworthy recovery/fresh install.
No empty-state reconstruction, fabricated acknowledgement/sequence or unlimited
revocation availability is claimed by this test profile.

**Independent originating-binding state, DN-06.** `D/caller-bindings-v0.json`
is closed `{format, installation_id, revision, bindings, effects}`, with
`format=swarma-broker-caller-bindings/1`, positive safe revision and exact
baseline `binding/1` records, including `created_by` and retained removed
tombstones. `effects` rows are closed
`{principal, request_id, operation, argument_digest, binding_id, uid, generation, state}`;
operation is `bind|unbind`, and state is `pending|recorded|rolled_back` with
the broker §13.2 R-OUTCOME meanings. The binding record supplies the recorded
target/result and current removal state; missing/contradictory joins are
unavailable/contradictory, never `not_recorded`. These are proposed local
storage bytes, not a new request or `effect.observe` wire grammar. Preserve
the original effect/canonical-argument identity, bind/unbind serialization,
intent-before-mutation and durable outcome/tombstone-before-acknowledgement.
No authority-snapshot write is part of unbind or its reconciliation.
Before every widening write, reserve in this separate 1 MiB file the maximum
closed-format removal intent, tombstone and terminal effect for **every
resulting active originating binding**, including replacement's old-binding
removal. Bound effect/argument identities before admission; if evidence plus
reserve cannot fit, refuse widening before mutation. Removal spends its
already reserved bytes, never deletes replay evidence or targets a replacement.
Own-state loss or storage failure remains an honest unavailable result.

**Retention and narrowing capacity, DN-06.** Retain committed method outcomes,
unresolved intents, revocations, holds and required removal/expiry evidence;
never evict them to turn an equal retry into new work. Keep at most the newest
64 nonauthorizing event summaries in the authority snapshot; summary eviction
is not deletion of required effect/audit evidence. Before a widening
transaction, compute its serialized size plus the maximum closed-format
unbind/receipt outcome for every resulting active service binding and the
existing account-hold reserve. Reserve those bytes in the per-account journal
within its 1 MiB ceiling. If required evidence plus reserve cannot fit, refuse
widening before any intent or target mutation. Capacity reclaimed by narrowing
cannot erase its tombstone/replay evidence. Originating bindings have the
separate reserve above; neither reserve depends on free authority-journal
space. Independent revocation storage cannot be occupied by widening records.
Qualification must prove both reserves
with bounded full-record plants; account hold headroom remains an independent
gate, not an assertion that a fresh empty journal proves capacity forever.

The existing broker admission paths populate authority, not direct file edits:
`grant.put`/`revocation.put` retain their signed key-holder rules and configured
dispatchers create/remove originating bindings through `bind`/`unbind`.
Admitted changes are validated and journaled by the broker; reading a request
does not itself make it a protected fact. Existing valid signed submissions
and dispatcher calls do not gain an operator role or use this wrapper.
Initial root delegation is an explicit pre-existing authority prerequisite,
not produced from an empty journal, a static allowlist or a service binding.
This profile does not publish additional operator grant-issuance grammar.
Therefore a separately published, password-authenticated exact-content initial
root-to-dispatcher grant ceremony remains a qualification prerequisite; this
proposal does not claim an empty authority journal can issue end-to-end.
The corresponding authentication-only root/operator revocation ceremony is
also a qualification prerequisite, not one of this wrapper's four methods.
Until published and qualified, compromised dispatcher/root-to-dispatcher
delegation containment uses a privileged installer authority revision removing
that dispatcher pin (or rotating affected roots), immediately closing use by
drift, plus stop/vendor revocation as needed. Never claim that editing pins
created a signed revocation envelope or advanced `seq`.
Basis: `spec/broker.md:483`, `spec/broker.md:787`, `spec/broker.md:789`,
`spec/broker.md:800`; installed journal integration: DN-05/DN-06.

Publish a widening operator operation in this order: (1) verify and durably
burn the act nonce independently of method state; (2) run every inner
admission check in its published order, including all six bind checks, with
no method write, outcome or operation-ID reservation on refusal; (3) only at
the admitted mutation point write an enrollment intent, if applicable, and
the target custody/service transaction; (4) reconcile the admitted committed
outcome before reply. Service bind/lift outcomes are in the per-account
transaction, not a prerequisite authority-journal intent. An enrollment
intent is admitted work, never a sticky `refused` record. Serialize concurrent
attempts; a refused operation has no replay value, so a corrected equal retry
is fresh admission with a new password/nonce. A committed equal retry resolves
the recorded result; unequal committed arguments conflict.

**Independent narrowing:** `service.unbind` uses `WithIdentity`, its live
BOOTTIME receipt and the target account service journal only. It never
requires `WithCurrent`, trusted UTC, enabled use-policy, restore reopening,
caller grants, the authority snapshot, its intent/outcome/event capacity or
the widening nonce file. Its existing removal transaction durably stores the
consumed nonce in its `/2` operation receipt beside the unchanged removed
result; it preserves holds, tombstones and all lease-ending effects. A
refused unbind retires only its one-use root-witness receipt, with no
method-outcome/operation-ID record. Receipt retirement itself is independent
of the authority journal and UTC; the witness must qualify one-shot handoff
and refusal retirement, including interruption, before admission is enabled.
Target lookup is independent too: rebuild the binding-ID lookup from protected
per-account metadata/service journals under `S`, not the authority registry,
planned policy selection or token material. Verify each account label/hash,
installation and journal identity before using it. Missing, ambiguous,
unreadable or incomplete lookup is unavailable, never an empty binding set;
the bounded scan cannot silently skip the named target. It creates no account
or journal and does not adopt orphan material. A corrupt unrelated authority
snapshot cannot prevent locating an intact recorded binding.
An unknown binding still refuses `service_binding_unknown`; missing identity
or the target journal/durability still refuses. There is no narrowing path
that fabricates successful storage. `account.hold` retains its independently
admitted identity-only, per-account path; stop needs neither journal.

**Dispatcher `unbind` is independent too.** Its identity-only route checks
the live kernel peer, current protected dispatcher pin/generation and the
target binding's exact `created_by` in `caller-bindings-v0.json`. It preserves
the creating-dispatcher restriction, original request/argument identity and
all broker §7.2/§13.2 removal/replay effects. It uses neither `WithCurrent`,
trusted UTC, restore/use-policy readiness, caller chains/classes, revocation
admission, nor the authority snapshot/nonce/event/outcome files. Inactive use
does not disable it. Only current dispatcher identity and its target/removal
journal are required; an unknown/replaced target, wrong creator, unresolved
identity or missing/unwritable own state cannot fabricate success. Full or
unreadable authority history cannot block locating/removing an intact target.
The reserved removal transaction and its reconciliation are wholly within
the independent caller-binding journal. Lease release checks under the same
state lock observe the removed binding before any further material release;
already delivered vendor material is not recalled.

After a crash, reconcile the target under its sole writer; never infer success
from an intent or rerun immutable custody merely because the final outcome is
absent. Only already durable compatible metadata/material can finish an equal
retry. An orphan material append without metadata burns the account ID as in
section 3. Specifically, an unresolved enrollment intent with matching durable
metadata/material may initialize its missing empty service journal exactly
once under the sole writer, before committing enrollment. Keep the account
closed to every service operation until that commit, so this recovery cannot
erase any admitted service history. A committed enrollment, uncertain identity
or any prior service operation forbids missing-as-empty initialization.
The current `/1` reader's NotFound-as-empty behavior (`loadServiceState`,
`internal/claude/service_linux.go:80-81`) must change for the proposed `/2`
integration; this document does not claim it is already implemented.
Ambiguous durability stays unavailable/unknown, not `refused`.
Basis: `spec/broker.md:767`, broker §13.2 R-OUTCOME,
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
enabled readers take a shared nonblocking lock before rereading both exact
activation and authority bytes and comparing their startup pins,
then the existing user-manager gate/data locks, then the broker state lock,
and retain the shared configuration/data locks through the bounded callback.
A writer, missing lock, replaced inode or lock failure refuses that window.
Human TTY interaction holds none of these locks; changed pins are rechecked
after it. This is a proposed local synchronization contract, not a claim that
root ownership alone makes a stale snapshot current. Basis:
`docs/claude-custody.md:21`, `docs/managed-identity-provider.md:44`,
`spec/broker.md:767`; lock path/protocol: **DECISION-NEEDED DN-05/DN-06**.

`WithIdentity` settles only operator/service/dispatcher identity and exact operator-act
evidence. `WithCurrent` additionally settles current policy, account owner,
caller bindings/chains, revocations, sequence and trusted time. Capture facts
before the broker state lock, use the user-manager gate/data read protocol,
and keep the complete joined evidence stable through the bounded final
publication callback. No network/PAM/user-manager RPC runs under that lock.
Use the existing 250 ms identity window, cancellation and final live-principal
check, not a new cache TTL. Mutation after a wait repeats final checks.
The unmanaged operator unbind route reads only its current root/directory
identity, receipt and target account journal; it does not acquire a missing
managed-projection/caller/use gate. Service-principal identity-only hold still
uses the managed source needed to prove that service identity. The lock order
above applies to sources an operation actually requires, not a new requirement
to open every source for an operator narrowing act.
Basis: `spec/broker.md:767`, service dialect §§5.1-5.4,
`docs/claude-custody.md:21`, `docs/managed-identity-provider.md:75`.

Unavailable caller/use facts block issue and renewal, but **do not become a
new prerequisite for `account.hold`**: its identity-only path and its own lease,
account, reason and bounded recent-end evidence remain exactly the accepted
order. Operator service unbind, dispatcher caller unbind and stop retain
independent narrowing paths. Missing
identity or hold durability still refuses; nothing silently clears a hold.
Basis: `docs/claude-custody.md:134`, service dialect §§5.2 and 5.8.

The sole baseline revocation sequence is also the service poll sequence;
service-journal revision, policy revision and user-manager head are not that
sequence. Proposed unavailable encoding is JSON `null`, never zero or a cached
last-success value; both baseline and service poll must agree (DN-07).
**Production remains DN-09 A:** independent restore/start evidence, durable
consumer high-water and trusted-time restart continuity must survive every
supported restored failure domain under the contracts of their existing owners.
No local snapshot can witness its own rollback. `enabled=true` is not a
continuity override. Known old bytes are not current facts.
Basis: `spec/broker.md:429`, `spec/broker.md:431`,
`spec/broker.md:903`, `spec/secret-free-service-v0.md:615`,
`docs/managed-identity-provider.md:110`; **DECISION-NEEDED DN-07/DN-09**.

The future protected-facts implementation MUST make `WithCurrent` refuse
before its callback, with `revocation_state_unavailable`, while any required
continuity/readiness input below is absent, unknown, inconsistent or
unqualified. A verified generation regression instead retains
`principal_ledger_mismatch`. This applies again at publication; no cached
startup success or free-standing readiness boolean opens use. Missing inputs
do not close the independently authenticated identity-only unbind/hold paths.

| Gate input | Protected source and opening condition | Refusal/control boundary |
| --- | --- | --- |
| Trusted time and watermark | Existing `policy.time_confidence`, authenticated NTS collector configuration/evidence, qualified consumer checkpoint/witness and broker durable watermark | Existing time-confidence policy, source/start/restart and effective-time checks all pass; off/unknown source, closed collector, checkpoint mismatch or untrusted step closes use, never advances a watermark. |
| Restore/start continuity | Production independent witness/reconciliation evidence under broker §§6.4/15.2/15.4, or the explicitly selected, machine-bound C fence below | Every start verifies the installation and complete approved heads; missing/mismatched/frozen/unknown state closes use, never initializes from its own restored snapshot. A C fence cannot satisfy production selection. |
| Generation consumer high-water | Protected broker-store consumer record joined to current root-owned user-manager projection/journal under their locks | Persist the verified consumer head before authority release; a shorter chain or nonextending head refuses. Genesis-only verification or an in-memory floor is insufficient. |
| Hold/narrowing headroom and isolation | Protected per-account journal revision, serialized-size reserve and qualified account-scoped failure/retention evidence, docs/claude-custody.md:123-130 | Missing reserve or isolation proof closes new use; independently admitted hold/unbind still use their own durable paths. Empty-state examples are not qualification. |
| R-ALLSTOP | Protected journaled node-wide freeze and start-check evidence, broker §§15.2/15.5 | Frozen, unresolved or unreadable state closes bind/replacement and final issue/renewal; a known unfrozen record passes only this gate. Identity-only narrowing remains available. |
| C selection, machine and account | Equal root authority/activation continuity selectors, fresh qualified VM identity evidence, time-box and protected test-subscription row | Before enrollment/bind and every use window/publication, wrong/unknown VM, unselected C, non-test account or expired revision closes widening/use. None becomes an unbind prerequisite. |
| Bounded publication and routes | Exact protected qualification identity for native publication, gateway listener/route and teardown under the accepted contracts | No current qualified implementation/evidence means no material release, even if the four continuity inputs are present. |

**DN-09 C: CONFLICT, TEST-PROFILE v0 only, not production.** The repository
owner, time-contract owner and user-manager owner must explicitly accept the
exact exception below and its dedicated, machine-bound, time-boxed qualification
revision. Co-restorable history/witness contradicts the published time contract,
which has no existing test-profile exception. Calling this a refinement, or
accepting a residual without approving the amendment, cannot open C.

1. **Restore is unsupported. Recovery is a fresh installation.** VM snapshots,
   disk clones and restores of the VM, service home, user-manager store or
   `/etc/swarma`, and any unexplained state regression burn the installation.
   Vendor-revoke the old token, choose a new never-reused `installation_id`,
   replace root keys, create a fresh store/grants, reenroll a fresh token and
   bind afresh. Never reopen the old store, replay old grants or clear a hold
   by importing old state. Preserve evidence separately where required.
2. **Root-owned start/restore fence outside the service home, every start.**
   Proposed path `/etc/swarma/credential-broker/start-fence-v0.json`, root:broker
   0640 (broker-readable, root-writable only), with root-protected ancestors
   and the section 4.1 file checks. Its
   closed body is `{format, installation_id, machine_id, qualification_revision,
   qualification_expires_at, start_generation, state, revocation_seq, heads}`, with
   `format=swarma-broker-test-start-fence/1`, positive safe start generation,
   `state=admitted|fenced`, nonnegative safe revocation sequence and explicit
   `heads` array. The qualification revision is the exact accepted specification
   commit pin; its UTC expiry is the time-box in the owner/continuity-owner
   decision, checked through trusted time, never extended by restart. Each
   head is closed `{source, account, revision, digest}`;
   source is `config`, `authority`, `authority-journal`, `caller-bindings`, `service-journal`,
   `consumer-high-water` or `time-checkpoint`, and account is null except for
   service-journal rows. Include `D/config.json` (including time policy), the
   independent caller-binding journal and every existing account service
   journal. The fence machine/revision/expiry equals the protected C selector.
   Before each manual start the operator compares revisions/digests and
   revocation sequence against an out-of-band record kept off the VM, then
   the installer publishes the approved fence under the root config lock.
   The first start records fresh-install heads; each later start needs final
   heads recorded off-VM after an orderly quiesce. A crash without complete
   surviving acknowledgement evidence requires fresh-install recovery, not
   an assertion that the last pre-start heads are still current.
   Use admission requires exact approved start heads; absence, mismatch, unknown completeness,
   expired qualification decision or interrupted approval closes widening/use
   and invokes fresh-install recovery, not a new fence copied from suspect
   state. The unit stays disabled with `Restart=no`; the fence is not an
   auto-reopen flag. Fenced diagnostics and identity-only narrowing may still
   start; this is not a time/readiness dependency of process startup. Before
   every use window and final publication, recheck C selection, live machine
   evidence, `state=admitted` and expiry at `max(now, watermark)`; a long-running
   daemon cannot outlive the accepted time-box. Legitimate post-start journal
   advancement is not compared as equality to old pre-start heads; current
   continuity/monotonicity checks still apply. The privileged installer writes
   `state=fenced` under the configuration lock after orderly use quiescence,
   before restore/configuration change or when a failure is known. It records
   final stop heads off-VM; only a separately approved next manual start can
   publish a fresh admitted generation. Unknown crash evidence cannot be
   repaired by the broker writing a fence. This separates the witness from
   home-level rollback, not from a whole-VM rollback.
3. **Persist consumer high-water in the broker store.** Proposed
   `D/consumer-high-water-v0.json`, broker:broker 0600, closed
   `{format, installation_id, revision, entry_count, journal_head}`, with
   `format=swarma-broker-consumer-high-water/1`, positive safe revision,
   nonnegative verified entry count and the exact format-owner journal-head
   digest. Under the existing user-manager locks, require the current verified
   journal to contain that exact head at that count and only extend it.
   Persist advancement before authority release. A shorter journal or a
   different/nonextending head refuses; missing/corrupt high-water is not
   initialized from the observed producer. Initial genesis is installer-only
   for the new empty installation. Restart compares it with the approved
   outside-home fence/off-VM record. This record is not the revocation seq.
4. **Authenticated NTS time, existing policy and watermark.** Select the
   protected NTS source through the existing time-confidence policy; retain
   qualified checkpoint/settlement ordering and the broker watermark. Never
   use unauthenticated wall time, a process-local clock or a fixture witness
   as trusted consumption. A profile-local monotonic witness sharing the VM
   rollback domain may qualify **only under the exact accepted exception**
   below, not under the unamended time contract. The default build still
   has `ClosedWitness` and no qualified collector path; this document does
   not open it or add a flag to bypass it.
5. **Dedicated TEST subscription only**, under
   `spec/secret-free-mode.md:415`; never the production account of the owner.
   The protected per-account `test_subscription=true` marker and section 5's
   qualified-VM selector are mandatory, not a request flag or qualification
   convention. Verify vendor/test-subscription evidence during provisioning;
   the enrollment display shows that exact protected marker and scope before
   confirmation. Refuse enrollment, bind, issuance and renewal under C for an
   unmarked/production account, even with a valid fence.
   **Live whole-VM snapshot revert is an owner-accepted residual risk**: it can
   roll back the running daemon, outside-home fence, store/high-water and time
   state together and revive revoked grants/holds until vendor revocation.
   Paired off-VM orderly-stop/start heads detect rollback at the next manual
   start; the undetected live revert before that boundary is the residual.
   Only the hypervisor owner can exclude it; matching local bytes cannot.
   Record that acceptance and the exact qualification revision/time-box off
   the VM. A changed/expired revision closes admission pending a new decision.
   **No result, witness or qualification under C is promoted to production.**

**Exact proposed time-contract amendment, DN-09 C.** Append this exception to
`docs/time-contract.md`'s **Storage and crash ordering plan**, following its
co-rollback refusal (`:272-279`, `:297-306` at the source pin):

> For TEST-PROFILE v0 under explicitly accepted DN-09 C only, a witness sharing
> the whole-VM rollback domain with its history may qualify consumption solely
> for the dedicated test subscription on the independently verified qualified
> VM, within the protected qualification revision and expiry. Home-level restore
> remains fenced; any restore requires fresh-install recovery. Undetected live
> whole-VM snapshot revert is an explicitly owner-accepted residual, not detected
> rollback protection. This exception never qualifies production consumption,
> another VM/account, or an unaccepted/expired revision. All other settlement,
> authenticated-time, watermark and hold rules remain mandatory. The ordinary
> production consumer remains closed; fixtures alone qualify no backend.

The same accepted decision must add the following clarification to
`docs/qualified-time-api.md`'s fixture limitation (`:12-17`):

> DN-09 C qualification requires its separately accepted machine-bound test
> implementation and deployment evidence. Existing fixture constructors or test
> tags do not select that profile or qualify it, and no C result activates or
> qualifies the ordinary production consumer.

Neither amendment is applied to those published contracts by this proposal.
The time-contract owner must accept **these exception bytes**; repository and
user-manager owners must accept the joined start/high-water rules. No approval,
machine-identity verifier or qualified collector is supplied by this document.

**DN-09 C disposition audit (all five clauses and their machine scope):**

| C clause | Disposition and exact published rule | Required amendment/bound |
| --- | --- | --- |
| C1 unsupported restore/fresh install | **Refines** broker §6.4 history recovery: missing complete surviving evidence leaves authority unavailable or requires invalidating old roots and reissuing rights. | C chooses the fresh-install branch; it never reopens old rights or claims restored bytes current. |
| C2 outside-home start fence | **Same** as broker §6.4/§15.2's restore mark outside the restored home; **refines** its unpublished local fence bytes. **Conflicts** with time-contract `:272-279` for the whole-VM domain. | Apply the exact C-only exception above; every-start off-VM head comparison is not an independent live-VM time witness. |
| C3 consumer high-water | **Refines** managed-identity provider restart/high-water gates (`docs/managed-identity-provider.md:110`); **same** no-reset/no-regression rule. | Publish local record/lock ordering only; it supplies no off-VM rollback detection. |
| C4 NTS/local witness | **Same** existing authenticated time, settlement and watermark policy. **Conflicts** with time-contract `:297-306`: a witness restored with its checkpoint cannot qualify and co-rollback must refuse. | Only the exact accepted C exception changes that refusal for this VM/test subscription; ordinary `ClosedWitness` and fixture limits remain. |
| C5 test-only/residual/expiry | **Same** test-subscription restriction (`spec/secret-free-mode.md:415`); **refines** its protected marker and time-box. **Conflicts** with time-contract `:303-306`'s unconditional co-rollback qualification refusal. | Owner acceptance of the exact exception, not a refinement label; live-revert residual recorded off-VM, no production promotion. |
| C machine binding | **Refines** enrolled time `scope.machine` (`docs/time-contract.md:42`) by requiring the same independently verified VM identity in all root selectors/fence records. | Section 5 rejects transferable guest-image identifiers and unknown/unqualified evidence; another VM cannot enable C by copying files. |

### 4.4 Required ownership amendments: DN-05 CONFLICT

Acceptance of DN-05 requires an explicit owner decision and these amendments
to the published texts; none is applied to the accepted specifications here:

| Published clause | Proposed replacement/addition for accepted v0 integration |
| --- | --- |
| Broker §4.2, broker-owned config names principals | The protected root-owned authority document names operator/observer/broker directory pins, root keys, dispatchers and account machine-policy rows. Broker-owned operational config grants no additional principal authority. Existing managed/unmanaged identity checks still apply. |
| Broker §12.4, all broker files broker-owned | Broker mutable state, custody, operational config and journals remain broker-owned 0600/0700. Installed authority, activation, start fence, executable/confinement configuration and root witness receipts are explicit root-owned exceptions with the exact modes of this profile and independent writers; atomicity alone is not freshness. |
| Broker §15.1, operator/observer provisioning and configuration | Installer publishes root authority pins and dedicated terminal-caller/login/PAM/sudo enforcement; unmanaged operator/observer pins in this profile are not helper-created accounts. Other no-shell helper operator entries retain per-act password rules and cannot mint broker receipts. |
| Broker §15.2, data/config and start checks | `D/config.json` remains broker-owned operational input. Root authority/activation/fence paths are outside `D`; each start and authority window enforces the joins and scoped continuity rules in this proposal. No automatic adoption of old deployment files is authorized. |
| Service dialect §1, machine policy in broker configuration | In enabled v0, machine policy is the root authority account selection. Under the broker state lock, both baseline agent-lease interlocks read those rows and fail closed on missing/undetermined policy. No config-only observer or legacy lease path bypasses that source. |
| Service dialect §5.1 step 5, source of policy digest | Compare the request pin to the complete current protected authority document digest under the state/configuration locks, and require its account/kind row to select secret-free. A request or service binding is never the source. |

**Equality or startup refusal, never precedence.** Enabled startup and every
enabled use/read authority window require `config.policy.installation_id` to equal
`authority.installation_id`, `config.policy.broker_uid` to equal
`authority.broker.uid`, and the distinct `observer_uids` set to equal exactly
the authority observer UID set. The operational account-label set equals the
authority account set; selected accounts are enabled and their legacy
`allowed_uids` is empty, never an exposed-lane grant. Contradictory account
selection, an extra config observer or any duplicated fact mismatch refuses
startup/current admission. Socket/store paths must equal the installed paths.
`D/config.json` remains authoritative only for its operational socket/store,
executable, time-confidence policy and vendor/profile metadata; its static
allowlist is not enabled-mode authority. Facts with no operational counterpart
are read only from authority, not invented in config. There is no dual source
or config-wins/root-wins fallback. Absent/disabled activation preserves the
existing baseline reader without claiming adoption of the proposed locus.

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
| `continuity` | Required closed production/C selector below, exactly equal to authority's selector |
| `service_lease_max_lifetime_seconds` | Optional integral 1..900; absent means 900 |

`continuity` is exactly `{kind: production}`, or the closed
`{kind, machine_id, qualification_revision, qualification_expires_at}` with
`kind=test-c`. C's revision is the accepted specification commit pin and its
expiry is exact UTC; both equal the owner/time-contract/user-manager decision
record and fence. Its nonempty opaque `machine_id` identifies the **one
qualified VM**, equal to the enrolled time `scope.machine`, not a hostname,
guest `/etc/machine-id`, boot UUID or a value copied from the activation file.
At each C widening/use admission and final publication a qualified root
verifier obtains fresh local hypervisor-/hardware-bound VM identity evidence
outside the guest disk-clone domain and compares it to that exact pin. Copying
the guest disk, selector, fence or old evidence to another VM cannot satisfy
this check. The verifier/backend, nontransferability and freshness proof are
qualification prerequisites, not implemented or selected here; unknown evidence
refuses. Verification must fit the existing bounded local authority window;
no network/PAM RPC is added under broker locks. No guest-only identifier,
environment override or operator assertion
substitutes for it. The activation digest and authority digest bind C selection
and scope; a C fence under production selection refuses, never auto-selects C.
An enabled C file on a wrong/unknown machine cannot construct the use assembly;
the independent identity-only narrowing/diagnostic route remains available.

**Absent activation file means inactive** for material use: stopped owner, no
use-authorizing service controller/provider and no new production enrollment,
service bind or service-lease capability. Existing baseline reads remain as
before. Valid `enabled=false` means the same stopped assembly. A present
invalid/unreadable file, unsafe ancestor, malformed pin, schema/version or ceiling
is a startup refusal, not absence and not a fallback to an enabled or exposed
lane. Validate a present document even when `enabled=false`. A valid false
document does not open or require the authority/custody sources for inactive
startup; an enabled
document additionally requires every source and equality join it selects.
An enabled authority-digest mismatch is a startup refusal, never fallback.
For already recorded bindings/holds, inactive use assembly MUST retain a
separately confined identity-only narrowing route from current protected pins
and the target journal; neither absent/false activation nor unavailable
continuity inputs may demand enabling use first. Those own identity/storage
facts are required on the narrowing attempt, not fabricated on inactive start.
Basis: broker §3.2 inactive assembly,
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

Activation and authority changes are **startup-only**, not enabled by SIGHUP.
Every active authority window rereads both protected documents under the
configuration lock and compares their exact startup bytes/digests and equality
joins. Missing activation, `enabled=false`, any byte change or drift closes
use admission and affected connections, never falls back to the exposed lane.
Independently authenticated narrowing remains available under current identity
pins even while use is closed. A new
accepted revision requires explicit restart and fresh bindings where policy
pins changed. Disabling/removing activation cannot erase custody, holds or
outcomes; stop new use, close connections and preserve evidence. Existing
operational config remains broker-owned 0600 at `D/config.json`; it supplies
the daemon/store/socket and the operational fields/equality constraints in
section 4.4, not a second enabled-mode authority or root activation.
Its static `allowed_uids` never supplies service/caller/owner authority.
Basis: broker §§4.2/12.4/15.2, with DN-05 CONFLICT amendments above,
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
   policy/owner plans and qualified time/restore/high-water inputs: DN-09 A
   for production, or explicitly accepted TEST-PROFILE v0 C only.
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
Basis: broker §4.2 roles, `spec/broker.md:333`, `spec/broker.md:883`,
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
| `[Unit] After`, `Requires` | Installer resolves actual source/identity/storage unit names; ordering is not readiness. Time/continuity readiness gates use in `WithCurrent`, not control-plane process startup: a failed clock dependency must not prevent fenced diagnostics or authenticated narrowing. |
| `[Service] Type` | `simple` |
| `User`, `Group` | Numeric broker UID/GID from protected provisioning; fail if directory/home pin differs |
| `WorkingDirectory` | `D` |
| `ExecStart` | `/usr/libexec/swarma-credential-broker daemon --config /opt/swarma/services/swarma-credential-broker/config.json` |
| `UMask`, `LimitCORE` | `0077`, `0` |
| `KillMode`, `SendSIGKILL`, `TimeoutStopSec` | `control-group`, `yes`, `30s`; positive process-absence evidence still required before replacement |
| `NoNewPrivileges` | `yes`; the separate operator sudo entry is not a daemon child |
| `RestrictAddressFamilies`, `IPAddressDeny` | `AF_UNIX`, `any`; this Claude-only broker needs no network access |
| `ProtectSystem`, `ReadWritePaths` | `strict`; writable only `D` and the installed broker socket directory, never root authority/login configuration |
| `PrivateTmp`, `CapabilityBoundingSet` | `yes`, empty capability set |
| `LockPersonality`, `MemoryDenyWriteExecute` | `yes`, `yes`; qualify against the installed executable and service manager |
| `Restart` | `no` for first qualification; later restart policy requires the same restore/freeze/start checks |
| `StandardOutput`, `StandardError` | `journal`, fixed nonsecret diagnostics only; no request/frame logging |
| `[Install] WantedBy` | `multi-user.target`; installation leaves unit disabled until explicit admission |

Broker binary is root:root 0755; the operator entry is root:root 0711,
unreadable to all but root for DN-02e launch nondumpability. Both are at their absolute paths,
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

The stable names below are required **future implementation witnesses**, not
executed tests. Every row specifies its own valid control and negative or
forbidden result; all synthetic inputs are inert and no real token is used.

| Witness / contract | Negative or forbidden result to detect | Adjacent valid control |
| --- | --- | --- |
| ACTIVATE protection/selector | Malformed/unknown members, wrong owner/mode/link/ancestor/pin, or >900 refuses startup; any fallback/clamp fails the witness. | Absent/false stays stopped; valid protected true constructs only the gated assembly at 900 or a smaller ceiling. |
| ACTIVATE-DRIFT current bytes | Missing/changed activation or same-revision changed authority bytes closes use and affected connections; no exposed fallback. | Identical protected bytes/joins permit a current window; independent unbind still works while use is closed. |
| AUTH-ROLE exact operator/owner | Bare same UID/key, observer/gateway, forged/expired/replayed receipt, changed arguments or wrong owner refuses without method mutation. | Dedicated human per-act password and exact widening confirmation admits only the configured operator/owner. |
| AUTH-SCRIPT outer master | `script --log-in` master is unpinned; refuse before password/token input and no canary in its recording. | Direct pinned console/actual SSH login with exclusive input receives a receipt. |
| AUTH-TMUX outer master | tmux/screen or passed master refuses even after reparenting; sudo inner pty never substitutes for the outer device. | Direct pinned login, no multiplexer, `!use_pty` and matching outer device succeeds. |
| AUTH-EXPECT outer master | expect/harness-created pty refuses despite matching UID/loginuid or a detached parent. | Direct pinned login-service master, process start and devpts join succeeds. |
| AUTH-READER terminal exclusion | Existing same-UID slave reader, late open/fork/FD transfer or unqualified freeze/launch gate refuses before secret input; no canary release. | Pinned relays/entry, proven frozen caller tasks, exclusive slave and restored state permit the direct-login ceremony. |
| AUTH-PASSWORD source | `sudo -S`, `-A`/askpass or noninteractive input refuses, even with the correct password. | Fresh operator-password conversation on the admitted outer TTY succeeds. |
| AUTH-PAM password-only | Alternative sufficient/key/device/PAM auth path cannot issue a receipt; wrong password also refuses. | Exact dedicated required `pam_unix` stack and a correct fresh operator password succeeds. |
| AUTH-CACHE caller sudo policy | Another root/shell rule, cached ticket, permissive caller timeout or sudoers/caller-list difference refuses. | Exact caller-only narrow rules with zero timeout and a new password succeeds. |
| AUTH-SESSION dedicated login | Same-UID harness service/process, user manager/linger, second login, managed caller, `setsid`/double-fork/user-service escape refuses regardless of current ancestry. | One fresh installer-verified dedicated human login, pinned launcher ancestry and no external caller tasks succeeds. |
| AUTH-SPOOF trusted path regression | Plant a caller-writable PATH `sudo`, startup function or launcher/config path; creation must be impossible or the root login gate refuses before password/token input. Earlier agent/vendor-CLI execution or unknown account history requires retirement/revocation, even after the process exits. No canary may reach the substitute. | Fresh never-agent caller, root-owned launcher/startup/PATH, qualified noexec confinement, absolute sudo and witness-checked live ancestry admit the direct-login ceremony. |
| AUTH-SSH actual host path | Unknown/unqualified SSH-only login path, changed server digest or remote recording fails the ceremony prerequisite; generic SSH login is not proof. | Direct human login through the pinned actual SSH implementation plus fresh terminal sudo succeeds; no direct SSH operator authority. |
| AUTH-DUMP exec boundary | Readable operator image, changed dump policy, initial dumpability or ptrace access before first instruction refuses qualification; late buffer-only protection is insufficient. | Qualified 0711 image/kernel boundary remains nondumpable from launch through display/capture. |
| AUTH-CHANNEL rendezvous | Inherited-FD3 assumption, wrong effective UID/nonroot socket peer, unmatched sudo auth session/parent/start ticks, extra frame, substituted entry or second connection refuses before input. | With unchanged closefrom=3, the qualified root witness admits one post-exec SO_PEERCRED/pidfd/session-bound connection and attributes the human caller. |
| DISPLAY exact content | Non-ASCII/control/bidi display injection, omitted protected test marker/C scope, wrong confirmation, candidate TTY/pipe or caller-selected policy assertion refuses; no content reinterpretation. | Complete reversible escaped display of the exact signed body and digest-bound protected metadata, matching confirmation and prepared regular-file candidate succeeds. |
| ENROL-BOUND custody framing | Empty, 4,097-byte, NUL/whitespace/non-ASCII or unterminated token refuses before act/receipt/custody write; canonical truncation is a failure. | 1-byte and 4,096-byte 0x21-0x7e synthetic tokens pass in noncanonical mode; Enter CR-to-LF and direct LF terminate capture exactly as specified. |
| ENROL-RESIDUE queue cleanup | Multi-line/overlong paste and continuing type-ahead after refusal must leave no canary in a resumed fixture shell, screen/history or confirmation. Exercise EOF, timeout, signal and uncatchable child death; a failed flush/restoration may never resume that shell. | 1-byte and 4,096-byte controls flush after capture, before confirmation and at exit, restore the complete saved mode before thaw, and end the login with no queued input. |
| ENROL-EXPIRY effect | Legacy `issued_at`, invalid expiry or guessed TTL refuses; dropping/changing confirmed expiry or extending a known cap fails. | Null maps to nil, or exact vendor expiry is stored unchanged and caps authorized use. |
| ENROL-VERIFY verifier classification | Prefix mismatch refuses; enrollment act/commitment/prefix appearing in audit/status/errors/alerts/effect.observe/service state fails the witness. | Matching scoped prefix and equal-retry commitment remain only in protected receipt/custody reconciliation and transient display. |
| ENROL-CAPTURE secret boundary | Echo/recording plant, canary in argv/env/log/staging, earlier agent-session token or unproven terminal restoration refuses. | Synthetic canary on the admitted exclusive TTY, echo-off, owned-buffer clearing and restoration on success/refusal/signals succeeds without an erasure claim. |
| ENROL-ORPHAN crash recovery | Append material, interrupt before metadata, then equal retry must not adopt/overwrite or claim completion; missing planned row refuses `account_unknown`. | Durable compatible material+metadata reconciles; burned ID instead requires fresh planned ID/token and inert old custody. |
| ENROL-JOURNAL initialization | Deleting a service journal after enrollment commit or a service operation must refuse, never recreate empty state. Concurrent service access during unresolved enrollment is forbidden. | Interrupt after matching metadata/material but before initial journal publication; the sole writer reconciles the original intent to one empty journal and commits before service admission. |
| RETRY-REFUSAL fresh admission | Bind-before-enrollment yields `account_unknown`, with no method outcome/ID reservation; returning that stale refusal after correction fails. | Enroll then freshly authenticate equal bind arguments with the same operation ID: admission succeeds; old nonce still refuses. Repeat for corrected policy/role. |
| RETRY-COMMITTED recorded result | Changed committed arguments, duplicate mutation, replay extension or an admitted unresolved intent reported as refused/success fails. | Fresh receipt with equal committed arguments returns the recorded outcome without a second custody/binding write. |
| JOURNAL-VERSION explicit integration | Silently adopting `/1` with `/2` receipt fields, accepting unknown members or claiming an implicit migration fails. | New-install `/2` validates the closed receipt metadata (null for nonoperator entries); unbind nonce/removal publish in the same durable account transaction. |
| NARROW-TIME independent unbind | Requiring UTC/restore/use-policy/typed confirmation for authenticated unbind fails; wrong boot, expired BOOTTIME or dead peer still refuses. | Untrusted UTC with a live current-boot BOOTTIME receipt removes the recorded binding and preserves holds. |
| NARROW-JOURNAL authority exhaustion | Fill or make the authority snapshot/widening nonce file unreadable; blocking service unbind or root/operator-key revocation because of it fails. This row grants no issuer-without-history exemption. | Service unbind commits in its target journal; root/operator-key grant or key revocation commits in its separate healthy state, with full and unreadable widening-history variants. |
| REVOCATION-ISSUER section 6.4 | A pinned non-issuer revoking another issuer's grant, an issuer attempting key revocation, or unavailable/mismatched grant evidence refuses with no revocation/seq change. | Exact verified grant issuer may revoke that grant when its envelope is available; root/operator-key revocation still works without that history. |
| REVOCATION-PATH v0 containment | Accepting a fifth wrapper method, treating pin removal as a signed revocation/seq acknowledgement, or qualifying without the separate revocation ceremony fails. | Installer removal of a compromised dispatcher pin closes use by drift without a seq claim; qualification additionally requires the published authentication-only root/operator revocation ceremony. |
| NARROW-CALLER-UNBIND regression | With a live originating binding, full/unreadable authority history and untrusted UTC must not prevent its creating dispatcher from unbinding. Wrong creator, substituted/replacement target or missing own journal cannot fabricate removal. | Same dispatcher/target commits and replays retained removal in the independent reserved journal, without WithCurrent/restore/use gates; subsequent material release observes removal. |
| CALLER-JOURNAL reserve | A widening write that consumes reserved originating-binding tombstone/effect capacity, drops replay evidence or silently reads bindings from authority history refuses. | At authority-history exhaustion, the intact independent caller journal can still durably remove every active binding using its pre-reserved bytes. |
| NARROW-OWN-STATE honest failure | Missing/unwritable target account/caller journal or full/missing/unwritable revocation state must not fabricate success, empty state, seq advancement or hold removal; exhausted revocation storage fences use. | Healthy own-state storage admits the same authorized narrowing independently of widening history, retaining its original effect/revocation evidence. |
| NARROW-RESERVE bounded capacity | A widening write consuming reserved unbind/hold capacity must refuse before mutation; evicting tombstones/outcomes/audit evidence to fit or retaining more than 64 event summaries fails. | At the widening ceiling, reserved unbind receipt/removal and eligible hold still fit; 65 nonauthorizing summaries retain the newest 64 without deleting replay/effect/audit evidence. |
| AUTHORITY-LOCUS equality | Extra config observer, installation/broker/account selection difference, static allowlist or config-only dialect interlock refuses. | All duplicate facts equal; enabled baseline interlock and bind policy read the authority account rows under lock. |
| VIEW/SINGLE-SEQ current facts | Remove/stale each required fact, wrong kind/class/placement/head or sequence reset/cache/missing-as-empty refuses affected use. | Coherent protected facts and the sole revocation state admit use; unavailable caller facts still allow independently admitted hold. |
| DISABLE/ROTATE lifecycle | One remaining binding, vendor revocation unknown, in-place overwrite, old token/ID reuse or orphan adoption cannot count as disable/rotation. | Unbind every binding plus vendor revocation; new authority account ID, fresh token and fresh confirmed binds establish rotation. |
| CONTINUITY-C-RESTORE fresh install | VM/home/user-manager/etc restore, cloned disk or unexplained regression must not reopen the old installation. | Fresh ID, replacement roots/grants/store and fresh token/enrollment/binds after old-token revocation establish recovery. |
| CONTINUITY-C-FENCE every start/window | Absent/mismatched/fenced start record, omitted config/caller-journal head, missing off-VM evidence or expiry while running closes use; copying suspect heads into a new fence fails. | Exact approved heads admit a manual test start; each use window/publication rechecks live scope, admitted fence and expiry. Privileged orderly stop fences before recording off-VM final heads; diagnostics/narrowing remain independent. |
| CONTINUITY-C-HIGH-WATER regression | Shorter journal, same-count different head, missing/corrupt consumer floor or reset to producer/genesis refuses. | Persisted verified prefix/head, durable extension before release and matching start evidence permits consumption. |
| CONTINUITY-C-TIME authenticated time | Plain NTP/off/unknown source, untrusted step, checkpoint mismatch, ClosedWitness or fixture path cannot open use. | Qualified NTS evidence under existing policy, settled checkpoint and preserved watermark passes the time gate. |
| CONTINUITY-C-CONFLICT disposition | Missing C1-C5 disposition, time-owner approval of a mere refinement, unaccepted exception bytes or fixture-only qualification refuses C. | Exact time-contract/API exception and all owner approvals admit only the explicitly scoped C evaluation; production A retains independent-witness requirements. |
| CONTINUITY-C-SCOPE machine/account | Copy a valid guest image, selector/fence or old evidence to another VM; a wrong/unknown machine, production selector/account, absent test marker, expired revision or production promotion refuses. | Fresh nontransferable VM identity equals both root selectors, fence and enrolled time scope; protected test marker displayed/confirmed and accepted time-box permit only that VM's test subscription. |
| BOOTSTRAP/LIFETIME ordered gates | Bind before enrolled account, missing grant/revocation ceremony or VM-verifier qualification, unavailable gate input, widened ceiling or expired/revoked authority refuses use; no revival. | Complete create/enroll/bind/start control with published ceremonies and all independent gates caps issue/renewal at 900 or smaller, caller and token expiry. |

The repeated finding classes require these named narrowing plants in the
future implementation suite; none is applied or reported killed here:

| Required plant | What it narrows the gate to | Witness required to fail |
| --- | --- | --- |
| AUTH-SPOOF-PATH | Remove the launcher/startup/PATH ownership check while retaining current-process enumeration. | AUTH-SPOOF must expose the planted substitute or reject the missing prerequisite; direct-login control must still pass without the plant. |
| NARROW-CALLER-AUTHORITY | Reintroduce an authority-journal read/intent or WithCurrent as an unbind prerequisite. | NARROW-CALLER-UNBIND must fail its full/unreadable-history or untrusted-UTC control. |
| CONTINUITY-C-REFINEMENT | Treat C as an accepted refinement without the exact time-contract exception. | CONTINUITY-C-CONFLICT must reject the decision record, while the fully accepted C control passes. |
| ENROL-RESIDUE-NOFLUSH | Omit capture/refusal/death queue discard before restoration/thaw. | ENROL-RESIDUE must detect the synthetic queued canary; clean 1-byte/4,096-byte controls remain required. |

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
must not choose an option on the owner's behalf.

| ID | Unfixed choice and source gap | Option A | Option B | Recommendation |
| --- | --- | --- | --- | --- |
| DN-01 | Operator binary/verb, input framing and receiving wrapper (`spec/broker.md:860`) | Fixed no-argv libexec entry and closed `operator.act.v0` wrapper on existing socket, as section 2 | Add an operator verb to the existing broker binary with a separately confined argv grammar | A: narrow sudo matching, no token in argv, no second service socket. |
| DN-02 | Trustworthy terminal authentication/agent-exclusion evidence and signed terminal-act admission (`spec/broker.md:245`, `spec/broker.md:856`, `docs/claude-custody.md:59`) | Signed act plus qualified root-witness rendezvous/receipt, fresh never-agent caller, root-owned launcher/trusted path and every DN-02a-e predicate | Same signed act plus a separately published live-provenance integration without this receipt format; ancestry/UID alone is never an option | A conditional on each sub-decision and paired witness. closefrom=3 stays; no FD3 injection. Root/kernel/login and owner-controlled endpoint recording/capture remain explicit owner-accepted trust/ceremony boundaries. |
| DN-03 | Act type/domain, 300 s freshness, identifiers, full display, typed confirmation and 128-bit token digest prefix (`spec/broker.md:860`) | Exact section 2 CCJ-1/domain and `CONFIRM <act_id>` grammar | A distinct versioned canonical envelope with a full typed canonical-content confirmation and a longer 192-bit digest prefix | A: bounded exact-content review; no phone signature or grant-domain reuse. |
| DN-04 | TTY-only transport versus pipe example, token framing/memory/recording safeguards and enrollment receiver/replay (`spec/broker.md:335`, `spec/broker.md:339`) | Sections 2-3 noncanonical bounded TTY capture, queue discard/full restoration on every exit, vendor CLI outside the caller, existing custody plus durable reconciliation | Preserve pipe/stdin capture with an independently authenticated receiving protocol and explicitly revise the v0 request | A: no act/staging token file or return to a caller shell with pending token bytes; ENROL-RESIDUE and supervisor cleanup require native qualification. |
| DN-05 | **CONFLICT:** authority/policy ownership moves out of broker configuration; paths, schemas, pins and startup reload | Root authority/activation with the explicit broker §§4.2/12.4/15.1/15.2 and dialect §1/§5.1 amendments in section 4.4, plus equality-or-refuse | Decline this ownership move and publish a revised design retaining broker-owned principal/policy authority; do not call the current move a refinement | A on the merits only after the explicit owner conflict decision and amendments; operational config remains broker-owned, never a parallel authority. |
| DN-06 | Authority/nonce/revocation/caller-binding journals, service receipt metadata, retention and admitted-intent recovery | Authority snapshot plus separate nonce, revocation and originating-binding state, versioned service-journal integration and unchanged token custody | Separate every protected grant/binding/revocation/event/outcome journal with a published transaction head | A with independent revocation/caller-binding storage and reserved removals. Root/operator revocations do not need grants; issuer revocations do. Neither unbind path needs authority history. Own-state capacity/failures remain honest; no current-reader support is claimed. |
| DN-07 | Unavailable sequence encoding and its relation to the sole baseline state (`spec/secret-free-service-v0.md:615`, `spec/secret-free-service-v0.md:1074`) | Same nonnegative baseline `seq` for known state; JSON null when unavailable in both dialects | Versioned tagged known/unavailable representation published jointly for both dialects | A: no invented zero/last-success authority; do not activate before baseline compatibility is accepted. |
| DN-08 | Installer bootstrapping, broker/config/socket/unit basenames, resolved dependencies and service-manager fields (`spec/broker.md:883`, `spec/broker.md:907`, `docs/production-assembly-stop.md:52`) | Section 6 ordering and system unit template; broker control plane before enrollment, gateway last | Same mandatory create/enroll/bind/start order, but a separately qualified temporary enrollment-only broker unit before the steady daemon | A: one owner/custody implementation and no bind-before-account exception; concrete installed dependency names remain installer inputs. |
| DN-09 | Time/restore/high-water custody not supplied by identity projection (broker §§6.4/15.2; managed-identity provider activation gates) | Production stays closed until the existing owners publish/qualify independent continuity/recovery inputs | Non-authorizing diagnostics only while the missing gates are resolved | **A for production; C for explicitly accepted TEST-PROFILE v0 only**, as below; B remains the current nonauthorizing state. |

**DN-09 Option C** is the five-part TEST-PROFILE v0 **CONFLICT** in section 4.3:
unsupported restore/fresh installation; every-start root fence outside the
service home; broker-store persisted consumer high-water with regression
refusal; authenticated NTS through existing time confidence/watermark; dedicated
test subscription with a protected marker, independently verified qualified-VM
scope, named owner-accepted live-VM rollback risk and **no production promotion**.
The exact time-contract/API exceptions and C1-C5 disposition audit above are
mandatory acceptance inputs, not a third production answer or an implemented
collector. Machine-verifier qualification, exact revision/time-box and all
owner approvals remain open; a valid-looking fence alone cannot open C.

An accepted decision resolves only its listed publication gap. Source delivery,
owner acceptance, acceptor review, implementation, signed-head review/checks,
installation and real-token qualification remain separate gates.
Basis: `spec/secret-free-service-v0.md:3`, `spec/secret-free-mode.md:433`,
`docs/production-assembly-stop.md:102`.
