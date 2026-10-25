# Mandatory macOS handoff parity

Status: **required platform profile; unimplemented and unqualified**. This is a
shared requirements profile, not a consumer adapter or native test result.
Every [consumer window](time-window-profile.md) must publish equivalent Linux
and macOS bindings; neither can be activated using the other's evidence.
The [approved single-read rule](time-contract.md#final-issuance-enrollment-and-registration-windows)
and [handoff/use contract](time-handoff.md) apply without relaxation.

## Clock, boot and deadline

The selected candidate is a fixed `mach_continuous_time()` read after final-lock
admission, outside pure `VerifyWindow`. Apple's pinned
[Mach header](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.1.10/osfmk/mach/mach_time.h)
specifies sleep advancement and availability from macOS 10.12. Load the native
timebase before final locks; qualify its pinned ratio and conservative checked
tick-to-nanosecond conversion. Reject overflow; round elapsed upper bounds up
and exclusive deadlines down. Availability does not qualify suspend/hibernate,
restore, rate error, residual scheduling or storage bounds on a deployed target.

Apple's [libc implementation](https://github.com/apple-oss-distributions/Libc/blob/71bbe350ab79eef58113991d817ccc6165061a64/gen/clock_gettime.c)
maps Darwin `clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)` to
`mach_continuous_time`, and `clock_gettime(CLOCK_MONOTONIC_RAW)` uses that path.
This is a suspend-aware candidate on Darwin. `CLOCK_UPTIME_RAW` instead uses
`mach_absolute_time`; those awake-only choices are forbidden here. Linux's
similarly named `CLOCK_MONOTONIC_RAW` excludes suspend, so clock identifiers
must always include their OS/domain. The linked source revision is a research pin,
not a deployed release qualification; qualify the exact installed release/SDK. This profile
selects the explicit Mach continuous API, not runtime fallback among clocks.

For boot identity, Apple's pinned
[XNU sysctl declarations](https://github.com/apple-oss-distributions/xnu/blob/xnu-11215.1.10/bsd/kern/kern_sysctl.c#L2869-L2871)
expose `kern.bootsessionuuid` as a read-only string; `kern.boottime` is a timeval,
not a boot-session UUID. Select a protected native UUID read before final locks,
validate its canonical nonzero representation and retain its mapping to receipt,
original operation and live run. A wall timestamp, PID or process nonce is no
substitute. The declarations alone do not prove uniqueness across clones/VM
restore, continuity custody or exclusion of an older executor. Those need
independent authority and native restart/suspend/reboot/restore qualification.

Retain original boot/start/UTC deadline identity and same-domain absolute D,
every applicable original budget, and the qualified conservative mapping.
A proposed distinct platform identifier is `MACH_CONTINUOUS_TIME/ns`; it is
**not an accepted value in today's Linux receipt**. The current closed receipt
requires `CLOCK_BOOTTIME`. A jointly reviewed platform profile/version and
validator are needed before any Darwin receipt; relabeling Linux facts is
forbidden. Serialized wall time or Go's ordinary monotonic timestamp cannot
stand in for a qualified continuous-domain deadline. Preserve all original
intersections and `m-s+f+epsilon<=T`, `m+f+epsilon<D`; never renew on wake/retry.

## Storage, namespace and act

Apple's archived [fsync manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fsync.2.html)
explains that drive caches may retain and reorder data after fsync, and points
to F_FULLFSYNC for stronger ordering. Its
[fcntl manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/fcntl.2.html)
describes F_FULLFSYNC as fsync plus a device-cache flush request, warns of
latency and devices ignoring the request, and lists historical filesystem
support. Require checked full flushes of written durable files on the exact
qualified target; unsupported operations or ignored errors refuse. Silent
fallback to ordinary fsync or a different barrier is not equivalent evidence.
The archived support list does not establish APFS/device behavior today.

Namespace durability is **separately unverified**: qualify directory descriptor
operations, supported directory sync/full-sync semantics, create/rename/unlink
ordering, both parents where relevant, crash/power-loss recovery and all cleanup
barriers on the actual OS/filesystem/device. Do not infer from the file flush
manual that F_FULLFSYNC on a directory is supported or sufficient. If the chosen
directory operation fails or its recovery guarantee is unknown, admission stays
closed pending a reviewed native storage protocol; no ignored error or assumed
Linux translation is permitted.

The archived [rename manual](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/rename.2.html)
requires a same-filesystem rename and describes continuity of the destination
name. This does not establish the complete durable file/use/namespace endpoint,
a multi-file transaction, or bounded completion. Exact native act semantics,
protected descriptor/owner/symlink checks, ordered burn-intent and completion,
readback, versioned recovery and independent rollback custody remain consumer
requirements. A policy+use journal or participants+root+cleanup protocol needs
its full recoverable endpoint, not a claim that one rename atomically commits
all files. Unknown durability remains fenced and burned, never unused.

The full read-to-act/use durability span needs a qualified enforced bound or
an act primitive honoring the original exclusive deadline through that endpoint.
F_FULLFSYNC is not a deadline primitive. Sleeping/descheduling after the read,
blocking storage, post-write clock checks and withheld acknowledgments cannot
supply the required prevention of late authoritative effects.

## Implementation and qualification gaps

| Component | Required parity and present gap |
| --- | --- |
| `timeconf` | Native protected policy/executable/collector and source confidence; continuous clock/timebase/boot mapping; separately reviewed receipt platform identity; original reader, current witness, settlement and no-reset recovery; bounded original retention and invalidation. These production paths and interfaces currently require Linux; Darwin does not gain a provider from these docs. |
| Consumer window | Native lock/exclusion order, current intent/revision/epoch and one-use home, same original deadlines/reserve, full durable act/use endpoint and independently reachable stop. Qualify scheduling/suspend/fault/storage behavior and old/delegated-writer exclusion. No accepting native implementation is supplied. |
| Rest of broker | Existing Linux peer credentials, filesystem safety, lifecycle/process fences, service control, transport and deployment qualification need reviewed macOS equivalents. Native launch/service/descendant ownership, protected storage and act authority cannot be supplied by a Darwin clock wrapper. No broker-wide port is claimed. |
| Independent custody | Select backend, confirmed-head retention, provider/consumer/witness restore separation and fresh authenticated currentness. A read-only boot UUID and full disk flush do not supply independent rollback authority. |

Run named pause-after-read, suspend/wake-through-D, boot-change, conversion-boundary,
failed flush/namespace, partial multi-file commit, lost reply, coherent restore
and stale/delegated executor controls on isolated authorized native targets,
with the same on-time positives and exact post-state assertions. No native macOS
run occurred for this publication; all these qualifications remain pending.
See [unresolved inputs](../UNRESOLVED_QUESTIONS.md) before activation.
