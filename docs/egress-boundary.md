# Candidate egress boundary

> **Proposed secret-free mode (inactive):** This cooperative fixture boundary does not establish the enforced secret-free gateway boundary. The pointer-race limit remains; local fake-503 compatibility/version probes prove neither hostile isolation nor successful login. Exact endpoint, IPC and bypass witnesses remain UNRUN.
> See [the separate contract](../spec/secret-free-mode.md#7-request-adapters-and-upstream-routing).

`internal/egress` confines accidental traffic from a cooperative or careless
candidate to explicitly configured local fakes. It is not a sandbox against a
hostile binary. It requires Linux amd64, seccomp user notification, TSYNC,
`process_vm_readv`, and `close_range(CLOSE_RANGE_CLOEXEC)`. Unsupported platforms
and unavailable kernel features fail closed. It requires no root or system
configuration change. Proxy variables alone are not its enforcement mechanism.

## Launcher and interface

Build the trusted launcher from `internal/egress/cmd/launcher`. The harness calls
`egress.Run` with its absolute launcher and candidate executable, fixed argument
slice, an explicit environment, a deadline, policy and selected files. No PATH
lookup or ambient environment is used to find the candidate. There is no
unfiltered fallback. The caller owns executable integrity and the environment
allowlist, including exclusion of injected loaders and language startup hooks.

Standard input/output/error default to null. Explicit selected descriptors must
be regular files or pipes, never existing network sockets or devices. Extra
files map to descriptors 4 upward; descriptor 3 is private bootstrap transport
and is closed before candidate exec. A final close-on-exec sweep closes every
unselected descriptor, including non-CLOEXEC ambient descriptors. The trusted
launcher and supervisor must not be replaced by candidate code.

The Go launcher locks its installer OS thread and prestarts one locked trusted
transport thread. It sets `PR_SET_NO_NEW_PRIVS`, installs the notification filter
on the installer, and transfers the listener via SCM_RIGHTS on the private socket.
The transport thread is not yet filtered, preventing a bootstrap sendmsg deadlock.
After the supervisor acknowledges readiness, the installer attaches a sealing
filter with `TSYNC | TSYNC_ESRCH`. This synchronizes its **entire existing filter
tree**, including the listener filter, onto all bootstrap threads. Only then does
that same locked thread exec the candidate. Failure aborts before candidate exec.
Candidate exec and subsequent threads/forks inherit the synchronized filters.
No candidate code executes during the unfiltered transport phase. This uses Go
throughout; no foreign-language pre-exec shim or unsafe raw fork is required.

`Run` owns the child process group and reaps the direct child. Cancellation,
evidence overflow and supervision errors fail the run and stop its group. The
filter refuses later process-group/session changes. This is fixture containment,
not a separate filesystem, user or resource sandbox. The harness must use local filesystems and must not expose network devices.

## Syscall policy

| Calls | Decision and reason |
|---|---|
| `socket`, `socketpair` | Notify. Permit Unix stream/datagram/seqpacket; permit IPv4/IPv6 TCP/UDP stream/datagram sockets (protocol zero or matching TCP/UDP). Other protocols, including SCTP and MPTCP with alternate connection mechanisms, are denied. Reject all other families and raw/packet types with EAFNOSUPPORT. Netlink, including route dump, is denied; this slice has no need for it. Raw sockets could put a second destination in packet headers. |
| `connect` | Notify and copy the sockaddr. Only 127.0.0.0/8 or ::1 with a configured port, or an exact configured absolute filesystem Unix path, may continue. IPv4-mapped IPv6 is classified by its embedded IPv4 address. Abstract Unix sockets are denied. Everything else returns ECONNREFUSED. |
| `sendto` | Apply the same check when a destination is supplied. A null destination may continue on an already connected descriptor. |
| `sendmsg`, `sendmmsg` | Copy each header and addressed sockaddr, applying the same check; deny the whole batch if any destination is refused. A batch is limited to 64 messages. Null destinations may continue. Ancillary control data is always denied with EPERM because routing controls can carry a destination outside msg_name; it is never logged. Payloads are never inspected or logged. |
| `ioctl` | Notify; permit exactly FIONBIO (0x5421), which changes descriptor nonblocking mode and is required by the native runtime. All other requests, including FIONREAD and device/interface controls, return EPERM. |
| `setsockopt` | Notify; permit only reuse/buffer/keepalive, SO_BROADCAST, TCP timing/NODELAY, and IPV6_V6ONLY options. Go's ordinary UDP setup enables SO_BROADCAST even for unicast DNS. This option does not select a destination: broadcast and external addresses remain refused at connect/sendto/sendmsg, and ancillary routing stays refused. All other options return EPERM, including multicast membership, transparent routing and protocol-specific connection controls. |
| `clone`, `clone3` | Notify. Permit ordinary thread/process creation; deny namespace flags and CLONE_UNTRACED with EPERM. clone3 flags are copied from child memory; malformed/unreadable structures fail closed. Filters inherit across ordinary forks and exec. |
| `io_uring_setup`, `io_uring_enter`, `io_uring_register` | EPERM: asynchronous socket operations could bypass direct socket syscall checks. |
| `bpf` | EPERM: prevents attaching alternative kernel packet programs. |
| `ptrace`, `process_vm_writev` | EPERM: prevents the candidate driving another process to send traffic. |
| `unshare`, `setns` | EPERM: prevents switching network namespaces. |
| `pidfd_getfd`, `recvmsg`, `recvmmsg` | EPERM: prevents importing connected descriptors through pidfds or SCM_RIGHTS. Ordinary `read`/`recvfrom` cannot import descriptors. |
| `bind`, `listen`, `accept`, `accept4` | EPERM: candidates cannot obtain unchecked inbound connected sockets. The harness creates local fake listeners outside the candidate. |
| `setsid`, `setpgid` | EPERM: descendants remain in the run's owned process group for cleanup. |
| `seccomp`, `prctl(PR_SET_SECCOMP)` after bootstrap | EPERM in the final sealing filter: a later listener/filter must not override a notification decision. Other prctl operations remain available. |
| Non-amd64 syscall ABI, including x32 | Kill the process: alternate syscall numbering cannot skip the table. |

All table denials except the final seal and ABI checks use the notifier and are
recorded. Other ordinary syscalls continue. `write`, `writev`, `sendfile`, and
`splice` cannot create a new destination: inherited socket descriptors and
incoming descriptor transfer are forbidden, and newly connected sockets have
passed the checks. A permitted local fake must itself be trusted not to relay
traffic externally. Exact Unix paths assume caller-controlled directories;
symlink/path replacement by a hostile peer is outside this boundary's contract.

## Pointer race and independent evidence

The supervisor checks `SECCOMP_IOCTL_NOTIF_ID_VALID` before and after copying
child memory and immediately before its reply. It copies headers and sockaddrs
using `process_vm_readv` and bounds their lengths; invalid notifications or
unreadable pointers never receive a continuation. These ID checks establish that
the request is still live. They do **not** freeze memory. Another candidate thread
can change an address/header after it is copied, including between the final ID
check and the kernel's use after `SECCOMP_USER_NOTIF_FLAG_CONTINUE`. A hostile
binary could exploit this gap. The boundary therefore makes no hostile sandbox
claim. A careless caller must not concurrently mutate in-flight arguments.

The harness also records `strace -f -e trace=connect` as an independent check of
observed connect arguments and results. This can reveal accidental connections
or disagreement; it does not remove the pointer race, audit every datagram, or
prove absence of traffic from an actively evasive binary. The tagged smoke
records all connect attempts, including refused ones, and rejects external or
undecodable connect records. A version-only smoke does not qualify other commands.

See the [kernel seccomp documentation](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
and [seccomp user notification manual](https://man7.org/linux/man-pages/man2/seccomp_unotify.2.html)
for the inheritance, synchronization, listener and continuation contracts.

## Bounded records and proxy environment

`Report.Events` records syscall name, numeric family, address class, port, verdict
and nanoseconds from a monotonic run origin. It records no payload, IP literal,
Unix path, command line or environment. Classes include loopback, unix, external,
connected (no new address), mixed (an admitted batch), socket, descriptor, process and other.
`Summary` holds allowed/refused counts per class. Allowed records the supervisor's continuation decision, not a completed kernel
operation or peer response. A notification already canceled at the final ID
check is counted as refused. Cancellation can also win between that check and
the reply; such a logged grant may never be applied by the kernel.

The default budget is 1024 events, with a maximum configurable budget of 65536.
Exhaustion refuses the next request, marks evidence incomplete, terminates the
run and returns `ErrEvidenceLimit`. Such a report cannot be used as successful
qualification evidence. Kernel struct sizes are checked before launch.

`ProxyEnvironment` replaces upper/lowercase HTTP_PROXY, HTTPS_PROXY and ALL_PROXY
with a closed loopback proxy URL, and sets NO_PROXY to the client-compatible host
exclusions `127.0.0.1,localhost,::1`. Port-qualified exclusions are ignored by some
clients. Seccomp independently enforces the exact configured destination ports,
including when the proxy exclusion matches a reachable disallowed port.
It preserves other explicitly supplied entries. The caller must reserve
the proxy port for the run; the tagged smoke binds a TCP socket without listening
and does not pass it to the candidate. Proxies are defense in depth: direct,
UDP, noncooperative and descendant traffic is checked by seccomp regardless.

## Checks and limits

```sh
GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" build -o "$TMPDIR/egress-launcher" ./internal/egress/cmd/launcher
GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race ./internal/egress -count=1 -v
EGRESS_SMOKE_CANDIDATE=<absolute-native-binary> EGRESS_SMOKE_EVIDENCE=<private-scratch> GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race -tags=realcandidate ./internal/egress -run '^TestRealCandidateVersion$' -count=1 -v
EGRESS_SMOKE_CANDIDATE=<absolute-native-binary> EGRESS_SMOKE_EVIDENCE=<separate-private-scratch> GO="$CURATOR_GO" GOTOOLCHAIN=local "$CURATOR_GO" test -race -tags=realcandidate ./internal/egress -run '^TestLocalCandidateHTTPProbe$' -count=1 -v
```

Use a fresh short real TMPDIR directly under /tmp and the host's heavy slot.
The version smoke runs only `--version`, with empty fresh HOME/CODEX_HOME, closed proxy
settings and an empty network allowlist. It writes boundary.json, connect.trace
and version.txt to the explicit private evidence directory. No login/account,
issuer, protected home or native refresh is used. Native qualification remains
PENDING; this package only supplies its egress prerequisite.

The tagged HTTP probe uses a separate empty fresh HOME/CODEX_HOME and an
explicitly configured account-free local provider. Its fake never forwards and
returns a fixed HTTP 503. It asserts request arrival, zero external grants, and
only loopback connects in independent strace output. The candidate then exits
with a service error and the boundary report is marked incomplete; this expected
result proves HTTP compatibility, not successful qualification. Artifacts in the
explicit private directory are boundary.json, connect.trace, connect-summary.json,
summary.json and candidate-output.txt. No real account or native refresh is used.

Synthetic probes cover TEST-NET external refusal, addressed UDP/sendmsg/sendmmsg,
IPv6 and mapped IPv6, raw/packet sockets, io_uring, later threads, fork/exec
grandchildren, exact Unix destinations, permitted and refused local ports,
environment/descriptor selection, cancellation, evidence overflow and bypass
syscalls. Compatibility regressions cover real wget requests with allowed and
disallowed ports, a local DNS answer with broadcast/TEST-NET resolver refusals,
FIONBIO with a refused valid FIONREAD, and addressed broadcast query refusals.
Mutant probes use listening local endpoints outside the allowlist, a harmless
pipe ioctl, or a broadcast socket whose SO_BROADCAST remains disabled. The last
control yields kernel EACCES if a mutant continues it, preventing emission while
distinguishing continuation from the expected supervisor ECONNREFUSED.
They do not need external packets. These are finite regression witnesses, not
an exhaustive syscall/hostile-kernel security proof.
