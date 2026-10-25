# Peer supervisor contract (proposed, inactive)

The selected design for genuine `peer-denied` is an owner-installed supervisor
running as test identity B. It is the case's direct parent and sole waiter.
Test identity A runs the qualification parent and the allowed control in the
same-user fixture profile. Their actual account mapping stays in protected
configuration. B must differ from both broker and allowed identities and remain
absent from every enabled policy entry. This proposal changes no qualification
status: `peer-denied` remains **UNRUN** until installation, independent supervisor
attestation and the implementation below are reviewed and qualified. The runner
rows `home-auth-present` and `source-conflict` remain **UNRUN** and undecided.

The existing [execution-origin rules](qualification.md#execution-evidence-origin)
and [genuine-peer requirements](../spec/v0-codex-refresher.md#81-configured-identities-and-genuine-peer-qualification)
continue to apply. Helper reports, inherited receipt bytes and a launcher's exit
status never establish case execution.

## Installation and closed launch

The proposed installation uses sudoers, with these owner-substituted templates.
All paths here are installation templates, not deployment records.

| Installed object | Path | Ownership and mode |
| --- | --- | --- |
| Static native supervisor, no interpreter | `/usr/local/libexec/credential-broker/peer-supervisor-v1` | system administrator, administrator group; 0555; no set-ID bits or file capabilities |
| Static canonical peer case worker | `/usr/local/libexec/credential-broker/peer-case-v1` | same ownership; 0555; no set-ID bits or file capabilities |
| Release manifest with both SHA-256 digests and protocol/environment profile | `/etc/credential-broker/peer-supervisor-v1.manifest` | same ownership; 0444; contains no account mapping or secrets |
| Private role mapping for A/B and the fixed group | `/etc/credential-broker/peer-supervisor-v1.roles` | system administrator, configured shared fixture group; 0440; readable by A/B only through that group |
| Narrow launch rule | `/etc/sudoers.d/credential-broker-peer-supervisor` | same ownership; 0440 |

Every ancestor directory must be administrator-owned, searchable by A/B and
unwritable by either identity, including through ACLs. The owner must quiesce
active cases before replacement, replace files by rename, and retain the old
release until all pinned descriptors are closed. Never mutate a measured inode
in place. Missing paths, symlinks, writable objects or unapproved manifests
prevent launch. The manifest is an owner trust anchor; hashing an arbitrary file
and accepting its own digest supplies no authority.

```sudoers
Cmnd_Alias PEER_SUPERVISOR = sha256:<SUPERVISOR_SHA256> /usr/local/libexec/credential-broker/peer-supervisor-v1 peer-denied-v1
Defaults!PEER_SUPERVISOR fdexec=always, env_reset, !setenv, !use_pty
<TEST_IDENTITY_A> <LOCAL_HOST> = (<TEST_IDENTITY_B>:<TEST_GROUP_B>) NOPASSWD: NOSETENV: PEER_SUPERVISOR
```

This is a proposed rule to validate with the installed sudo version. It grants
only the exact command and literal argument, with one target user/group. No
wildcards, shell, interpreter, free-form command, environment assignment or
arbitrary executable path is allowed. Existing broader test-role permissions
must be inventoried privately; adding this rule does not revoke them. Option A
is unavailable if another matching grant can authorize the same image without
its digest/argument/environment constraints. The owner must approve and narrow
that overlap before activation; this proposal changes no existing permissions. Digest-bound descriptor execution addresses the policy's
check/execute race; its availability must be verified, with no path-execution
fallback. See the [sudoers manual](https://man7.org/linux/man-pages/man5/sudoers.5.html).

The administrator-owned private role file pins the expected identities/group
for S and the optional witness; it must agree with P's protected fixture mapping.
It is not a caller-selected mapping. S checks its credentials against it before
accepting bootstrap input, so a broader legacy launch cannot select another role.

The supervisor accepts exactly `[<installed-path>, "peer-denied-v1"]` and one
bounded, versioned stdin bootstrap. The bootstrap is limited to 4096 bytes and carries only the private
rendezvous, launch nonce, input identity and deadline; no command, executable
selector, environment override or account selector. Configuration never opens a
shell. The supervisor validates the owner-pinned worker manifest and executes
that retained worker descriptor with exactly
`[<worker-path>, "qualification-case", "peer-denied", "negative"]`. It refuses extra
arguments, fields, descriptors, messages and trailing input. No vendor login,
credential file, real account or external network endpoint is involved.

Both images must be static so an ambient loader is not an unmeasured dependency.
Option A has a reviewed, closed sudo-initial environment profile: the parent's
minimal PATH/LANG plus only explicitly enumerated sudo-generated identity fields
with privately expected values. Unspecified PAM/environment additions refuse
launch. Option B constructs exactly PATH/LANG before S exec, with no sudo or
manager environment fields. Before reading bootstrap input, S clears its environment
and uses exactly `PATH=/usr/bin:/bin` and `LANG=C` for the worker, with no inherited
home/config variables. The initial and worker environment profiles are separate
checks; clearing later cannot prove what was supplied at exec.

## Independent supervisor attestation: required gate

P denotes the qualification parent, S the supervisor, and K the kernel. An
owner-approved authority independent of S must bind the following to the same
live S before P sends any execution challenge. Option A below establishes launch
facts through trusted enforcement; option B observes the initial exec stop:

1. P opens the manifest and installed images through retained trusted directory
   descriptors, refusing symlink traversal. It checks type, ownership, mode,
   size bounds and SHA-256 on each retained file descriptor. The executing
   supervisor must be matched to that same measured image. Option B compares
   device/inode and digest at its initial exec stop, before userspace can alter
   argv/environment; option A relies on approved sudo digest/FD enforcement.
   The execution path must use the measured descriptor, never reopen by name.
   A pathname or hash supplied by S does not satisfy this comparison.
2. Bind the exact bounded NUL-delimited initial argv and the closed initial
   environment profile through the chosen authority. In B, record them at the
   exec stop; in A, the owner must approve the launch policy as their enforcer.
   Check real/effective/saved credentials and groups against the private mapping, and prohibit subsequent identity changes
   or execs. Any namespace translation must be explicit; unknown mappings refuse.
3. Pin S's process lifetime with a pidfd and bind its kernel start identity to
   the observed launch chain. Check the parent link at creation, not just a
   later PPid snapshot. With sudo there may be a monitor between P and S; the
   selected sudo topology must be enumerated and bound to this launch. Never
   assume S's immediate parent is P or accept an arbitrary process owned by B.
4. S opens a fresh Unix stream connection to P after its identity transition and
   exec. P reads `SO_PEERCRED` and matches PID/UID/GID to the independently
   attested, still-live S. P enables credential delivery for subsequent framed
   messages and rejects a sender change, replay or transferred channel. S
   verifies P against the protected mapping. Bind one fresh launch nonce and
   protocol version to this connection; close all bootstrap copies afterwards.

### What the unprivileged parent can establish

| Observation | Meaning and limit |
| --- | --- |
| Root-owned installed path, retained FD and digest | P can measure readable installed bytes. This alone does not identify a foreign live process's executed image. |
| `/proc/<pid>/stat` or `status`, where permitted | Current process/parent/credential observations, subject to procfs policy and races. A later PPid is not a creation or ancestry witness. |
| `pidfd_open`, where available | Pins process lifetime and permits exit polling; it grants neither executable inspection nor a consuming wait on a non-child. |
| `SO_PEERCRED` on S's fresh connection | Kernel PID/UID/GID at connection establishment, not image, initial argv, environment or case entry. A socketpair created before the transition has earlier credentials. |
| Credential-bearing messages | Bind the sender of that message, not the code it ran. They do not replace initial image attestation. |
| Live `/proc/<pid>/exe` and `environ` | P cannot assume cross-identity access. Both are ptrace-permission gated. |
| `/proc/<pid>/cmdline` | May be readable, but userspace can rewrite it; it cannot prove initial argv after the process has run. |

These limits follow the Linux manuals for
[executable inspection](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html),
[initial environment](https://man7.org/linux/man-pages/man5/proc_pid_environ.5.html),
[mutable cmdline](https://man7.org/linux/man-pages/man5/proc_pid_cmdline.5.html),
[pidfds](https://man7.org/linux/man-pages/man2/pidfd_open.2.html) and
[Unix credentials](https://man7.org/linux/man-pages/man7/unix.7.html).
The [ptrace access algorithm](https://man7.org/linux/man-pages/man2/ptrace.2.html)
also applies independently of any Yama exception. Making S dumpable or allowing
P with `PR_SET_PTRACER` does not itself remove the base credential check.

## Alternative attestation gates: owner choice pending

Neither option is selected by this proposal. **Recommend A** if the owner accepts
its explicit trust in sudo and current installation policy; it adds no new
privileged program. If independent kernel observation of S's initial execution
is required even when launch policy is misconfigured, choose B. A does not offer
that stronger property. Both leave the row UNRUN until the owner approves the
chosen trust model, implementation and controls.

### A: sudo policy is the trusted launch witness

The installation above is the complete additional launch footprint. P retains
the approved manifest/images, starts exactly the noninteractive sudo command
with its private bootstrap pipe, and binds the fresh S connection to that launch
using its launch nonce, credentials and pidfd. A closed bootstrap channel limits
substitution by unrelated B processes; secrecy of that channel is an assumption,
not evidence of an executed image. P waits on its own sudo child and separately
requires the S-authenticated actual case wait report. A zero sudo exit alone
proves none of the case facts.

P may query its own effective permissions with `sudo -n -l` (not another user's
listing) if permitted without authentication. Reject inconsistent visible rules,
but do not treat human-readable listing output as a full policy attestation.
In particular, the currently broad test-role launch permission cannot silently
remain an alternative route around the pinned command. Owner verification of
the complete effective policy, and any required narrowing, is a prerequisite.
The owner also installs a nonsecret approved-policy export at
`/etc/credential-broker/peer-supervisor-v1.policy`, administrator-owned 0444,
and pins its digest in the release manifest. P can confirm that readable export
is the approved one. It cannot, without additional access, confirm that an
unreadable active sudoers file still equals the export. An owner-signed policy
digest would likewise need approved key origin and currentness; it would not by
itself prove which policy sudo loaded. This proposal installs no signing key.

The owner must freeze and verify the active rule, all matching Defaults,
plugins, PAM environment and monitor topology for the run, including closure of
the initial environment. `env_reset` alone is not an exact environment proof.
P's privilege-free evidence remains its own exact launch request, accepted
bootstrap/channel binding and sudo-child result; image, initial argv/environment
and ancestry enforcement are delegated to trusted sudo and owner installation.
The root-owned policy export is an installation assertion, not a kernel witness.

This closes substitution of an unapproved image or arguments under an intact
approved policy, including pathname replacement between hash and exec through
FD execution. It leaves open active-policy/export divergence, a compromised sudo
or plugin, and a launch-chain defect fabricating the expected connection. A
cannot independently detect those by reading B's procfs. This residual trust
must be accepted explicitly; otherwise it is not an admissible gate.

Controls: change the binary while keeping the approved digest (sudo must refuse);
request an extra argument, different target/group or environment override (the
selected launch gate or S must refuse, with no case execution); change the visible export/manifest (P must refuse); substitute a B
connection without the launch nonce (P must refuse). A privileged active-policy
change with an unchanged export is a declared blind spot, not a claimed killed
control. Privileged policy controls belong only in an owner-authorized isolated
installation, never on a shared host.

### B: restricted privileged exec observer

This alternative adds a separate static binary
`/usr/local/libexec/credential-broker/peer-witness-v1` (administrator-owned 0555),
a root-owned manifest pin, the common private role mapping, and two administrator-owned 0644 units under
`/etc/systemd/system/`: `credential-broker-peer-witness.socket` and `.service`.
It needs a separate protected non-login witness identity, not A or B. That
identity may run only this component. The system manager, installed unit/image
and owner lifecycle are explicit trust anchors; peer credentials alone do not
attest the witness binary. P verifies the readable approved unit/image/manifest
and authenticates the root-managed endpoint under the approved installation.
On the manager-created listening socket, `SO_PEERCRED` can identify the manager
at listen time, not the later accepting witness. P therefore binds each witness
reply through credential-bearing messages, the approved witness identity and
the root manager's current MainPID, then retains that pidfd. The readable unit
and manager installation remain trusted; MainPID alone proves no image. No
automatic unprivileged fallback from B to A is permitted.

```systemd
# credential-broker-peer-witness.socket
[Socket]
ListenStream=/run/credential-broker-peer-witness.sock
SocketUser=<TEST_IDENTITY_A>
SocketMode=0600
[Install]
WantedBy=sockets.target
```

```systemd
# credential-broker-peer-witness.service
[Service]
User=<WITNESS_IDENTITY>
Group=<WITNESS_GROUP>
ExecStart=/usr/local/libexec/credential-broker/peer-witness-v1
CapabilityBoundingSet=CAP_SYS_PTRACE CAP_SETUID CAP_SETGID
AmbientCapabilities=CAP_SYS_PTRACE CAP_SETUID CAP_SETGID
NoNewPrivileges=yes
RestrictAddressFamilies=AF_UNIX
ProtectSystem=strict
```

These are proposed templates, not qualified service properties. Unit semantics
must be checked against the target [service](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html),
[socket](https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html)
and [execution](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html)
contracts before installation. The listener is system-manager-created; the
witness accepts only A's kernel credentials and one closed `peer-denied-v1`
operation. There is no arbitrary PID reader, path/command/environment selector,
shell, file writer or general process-control API.

The witness itself forks S, installs the fixed B groups/credentials in the child,
drops all child capabilities, constructs the exact initial environment, closes
all witness/listener/control descriptors in the child, and execs the retained
approved S image descriptor.
It traces S's initial exec stop, reads image/argv/environment/credentials and
parent relation, retains S's pidfd and sends those bounded observations to P on
the authenticated witness channel with the launch challenge. It keeps ownership
of S's exec/exit events, so a later exec or identity change invalidates origin.
It does not trace S's child or consume that child's status: S remains the case's
direct parent, tracer and sole waiter. P separately binds S's fresh connection
to the witness-observed S. Witness loss invalidates origin and triggers exact
child cleanup; S loss must terminate and reap the case.

`CAP_SYS_PTRACE` is needed for cross-identity observation in the same user
namespace. `CAP_SETUID` and `CAP_SETGID` are needed only to launch that fixed B
child before its first exec; they must never reach S. A ptrace-only reader that
attaches after sudo has already run userspace cannot recover the original argv
or environment, so it would not satisfy this stronger gate. These capabilities
are broad kernel authority despite the narrow API; do not grant them to P or S.
The fixed mapping is owner-controlled, not caller-supplied. Dropping capabilities,
namespace visibility, tracing restrictions and manager hardening need isolated
qualification before claiming the proposed privilege set is sufficient.

B closes the policy/export blind spot for S by observing its actual initial
image, argv/environment and creation parent, even if a launch request is forged.
It adds a privileged service and compromise risk: the witness could lie, inspect
other processes or change identities if compromised. Controls must replace S's
image, initial argv/environment and parent separately (each must be refused),
replay witness frames, substitute endpoint credentials, request arbitrary PID or
identity selection, and kill the witness mid-case (all UNRUN, no artifacts).
The common controls below still apply; an attested witness does not make a
compromised S's child wait report independently true.

## Case lifecycle after the gate is satisfied

S is the trusted observer for the inner case only after P has attested S. Its
protocol has the states `bound -> exec-verified -> entered -> reaped -> closed`;
any missing or out-of-order transition invalidates execution credit. P starts
one 30-second monotonic budget before launch, covering the whole pair and
joined cleanup. S/the witness may shorten, never extend, that deadline.
Completion frames are bounded to 4096 bytes; late or oversized frames refuse.

1. S creates the canonical negative case as its direct child with an atomic
   pidfd association, retained measured worker FD, fixed argv and exact worker
   environment. S owns tracing and the sole wait path. At the child's exec stop
   S checks the live image against that FD, initial argv/environment, B's
   credentials and the direct-parent link. Unavailable same-identity tracing
   also leaves the row UNRUN; no receipt fallback is permitted.
2. Only after that exec verification, P generates a fresh case challenge bound
   to the launch nonce, input/candidate digests, row and negative side. S relays
   it over the typed case-entry channel. The measured case dispatcher answers
   only after canonical input, candidate and empty-home checks. S checks the
   kernel sender against its pinned child before relaying the entry observation.
   The parent never treats S's earlier bootstrap acknowledgment as case entry.
3. The case connects fresh to the real shared fixture listener and sends no
   request bytes. The broker checks kernel peer credentials. P correlates that
   socket PID/UID/GID with the attested child, checks the null-ID terminal denial
   and EOF, zero input reads/processed requests, unchanged store and zero
   Snapshot/Refresh/material/writer effects. The existing 0750 directory and
   0660 socket with configured group remain exact; do not relax them.
4. S uses `waitid(P_PIDFD, ..., WEXITED)` as the consuming wait on its direct
   child (or the single trace-owner wait path preserving the same association).
   It sends exactly one bounded completion frame over the S-bound channel:
   protocol/launch/challenge identities, child binding, actual exit-or-signal
   status, entry/completion observations and monotonic elapsed times. P checks
   ordering and its own elapsed deadline. Exit polling, `kill(pid, 0)`, EOF,
   `WNOWAIT` alone and S's own exit status do not replace this consuming wait.
5. Before S exits, P receives the authenticated completion and joins the launcher
   separately. A disconnect, S death or unexplained lineage change before the
   protocol is closed invalidates the pair. S must kill and reap its exact child
   on cancellation; parent-loss supervision must close the case too. P never
   signals an unverified foreign PID or claims cleanup from silence.
6. Only a fully verified negative permits the allowed control as A, using its
   existing independently attested origin, on the same listener. It must perform
   hello and a bounded real fixture lease. P joins both cases and verifies all
   expected effects before producing paired artifacts. Missing positive origin
   or cleanup evidence prevents PASS even when the negative denial was correct.

Execution credit needs both canonical entry and actual completion of that exact
case through the attested waiter, plus the independent broker observations. A
real nonzero case exit must be retained as nonzero, never converted to success.
A valid origin with a failed protocol assertion is a row failure. In contrast,
an incomplete or contradictory origin is UNRUN: `executed=false`,
`exit_code=-1`, no artifact and no neighbouring control. Private diagnostics may
retain known launcher/case status without upgrading that classification.

## Failure controls required before activation

Each proposed control needs a nearby valid installed-image/real-case positive
control. The expectations below specify assertions for later implementation;
none is claimed to have run in this documentation change.

| Negative control | Required result and forbidden effect |
| --- | --- |
| Missing supervisor or unavailable independent observer | UNRUN before case launch; no artifacts or allowed control. |
| Changed installed image, writable inode/ancestor, symlink or digest mismatch | UNRUN before challenge; no case credit. A replacement after open must either remain bound to the retained approved inode or be refused, never execute unmeasured bytes. |
| Forged argv/environment, extra argument, arbitrary command or extra descriptor | Reject the launch/bootstrap; UNRUN and no requested command executes. |
| Unexpected S parent/monitor, adopted process or stale/reused PID | UNRUN; credentials matching B alone cannot rescue it. |
| Wrong channel PID/UID/GID, inherited pre-transition credentials or sender change | UNRUN before entry credit; no artifact or positive neighbour. |
| Challenge sent/replied before verified exec, replay, helper-only receipt/report | UNRUN; no case-entered claim from an earlier stage. |
| S or case exits before entry, or S exits before authenticated consuming-wait completion | UNRUN; a successful launcher exit cannot rescue missing case execution. |
| Timeout at bootstrap, entry, wait or teardown | UNRUN; bounded cleanup must account for the exact child, never synthesize completion. |
| Forged status, duplicate completion or unrelated child status | UNRUN on contradiction. A genuine entered case exiting nonzero retains the real status and cannot PASS. |
| Foreign client sends bytes, wrong terminal, broker effects or allowed lease failure | Verified execution can be recorded as failed, but the row cannot PASS or publish a successful pair. |

## Trust and remaining owner choices

An attested S is deliberately trusted to measure/trace its child, issue the
post-exec challenge correctly, consume the real wait status and report monotonic
timing. If compromised, it can lie about those child observations or relay the
challenge itself. P's independent image/launch check establishes which trusted
artifact receives that authority; a digest is not proof of correct runtime
behavior. P still independently checks S's kernel channel identity and lifetime,
the actual broker peer, envelopes, effects and its own timeout. These facts do
not independently recover a withheld or fabricated child wait status.

The owner-installed manifest, immutable release custody, chosen launch witness,
selected sudo implementation/policy or witness/service manager, and absence of
unauthorized same-identity inspection
or descriptor theft are part of the trust base. No supervisor self-report,
self-supplied executable FD, self-computed hash, signed receipt without an
independently approved key origin, or earlier-stage metadata can bootstrap it.

Before implementation, the owner must select the independent initial-exec
attestation backend and its permitted authority, approve the concrete sudo
version/topology and closed initial environment, and confirm protected image
replacement and test-identity/group provisioning. The supervisor choice settles
who waits for the foreign case; it does not settle those installation facts.
No decision here covers runner preflight, `owner-mismatch`, live accounts or
production qualification.
