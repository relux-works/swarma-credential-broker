# Platform time policy

This is the shared time-confidence policy for local services. The provider is
`internal/timeconf`; its [implementation and collection contract](time-confidence.md)
applies independently of account or lease state. The selected v0 evidence source
is option A below. Production admission remains closed until activation, and an
absent protected policy selects no source and returns unavailable.

## Shared rules

Every server or pool in the complete chrony configuration must carry `nts`.
The selected source in tracking must match an NTS configuration entry by original
name or numeric address. An unlisted selected source, including a bootstrap or
dynamically added source, is unavailable. Names come from the daemon's original
configured name, never from reverse DNS. No host-specific source list is part of
this document.

Directory membership follows chrony's
[`search_dirs` implementation](https://github.com/mlichvar/chrony/blob/4.8/conf.c#L1619-L1664):
`confdir` selects `*.conf`, and `sourcedir` selects `*.sources`, without matching
leading-dot filenames. Effective files must be protected regular files; links,
unsafe permissions and unreadable or oversized effective inputs refuse the
sample. Names sort lexicographically, with the first configured directory winning
for duplicate names. Ignored names still count toward the bounded directory-entry
scan; accepted configuration bytes also have an aggregate bound. Every sample
rebuilds this inventory, including a previously absent DHCP directory.

Tracking must report Normal leap status, a sync no older than 1024 seconds,
absolute offset no greater than 0.5 seconds, and root distance no greater than
one second. Root distance is root delay / 2 + root dispersion. The provider also
bounds last/RMS offsets and rejects malformed, nonfinite or structurally invalid
evidence. The authority interval is exclusive:

```
AuthorityUntil = min(sample time + 5 minutes, last sync + 1024 seconds)
```

The five-minute window never extends past evidence freshness. At exactly
`last sync + 1024 seconds` the interval is empty and confidence is unavailable;
at one nanosecond before it a valid sample retains a one-nanosecond interval.
An offset of exactly 0.5 seconds and root distance of exactly one second are
within the numeric bounds.

Within one boot, compare the change in wall time with the change in continuous
monotonic time. Relative backward movement exceeding one second raises an
incident and a hold. Forward movement beyond the explicitly configured forward
tolerance also holds. Evidence loss, repeated reports and passage of wall time
cannot clear a hold. Recovery requires a new authenticated sync beyond the
incident's maximum observed wall time and prior sync, with stable monotonic
progress, or explicit operator confirmation. No operator reset command is
provided in this slice. Boot changes reset the comparison; they do not establish
fresh evidence. Explicit stops remain available when time confidence fails.

Option A confirms NTS **from protected configuration, not from per-association
authdata**. This is its residual weakness: the evidence assumes the controlled
running daemon uses the complete configured inventory and has no unaccounted
runtime source changes. Matching the selected source reduces that gap but does
not independently prove negotiated NTS. Option B adds per-source NTS authdata
and correlation to the selected reference. Option B is required before moving
to a dedicated service identity. Missing authentication-report permission closes
confidence; permissions are not weakened to obtain evidence.

## Uncertainty and process start

Every successful sample carries δ, bounding the difference between true time
and the sample under the authenticated source's reported error model. The
minimum bound is absolute measured offset plus root distance. The implementation
uses the maximum of absolute system offset, absolute last offset and RMS offset,
adds root delay / 2 and root dispersion, and grows that bound by reported skew
since the reference sample. It rounds upward to nanoseconds. This conservative
bound does not turn an incorrect authenticated server into a correct time source.

A new process calls `StartSample` before any time decision. The call collects
fresh evidence and returns time, δ, boot identity, and the exclusive authority
endpoint. To order its start after a previous process's last decision, retain
that decision's time P and bound δP outside the rollback domain, then require the
new lower bound `sample - δ` to be strictly later than `P + δP`. Otherwise wait
using continuous monotonic elapsed time and resample. When δ bounds both samples,
waiting more than 2δ provides the corresponding separation under continued
confidence; different bounds require their sum. A hold or boot change requires
re-establishing evidence and continuity. Waiting cannot reconstruct missing
history, and confidence must still be checked at later decisions.

A hold belongs to its provider instance and boot in this slice; durable hold
storage is not placed in the rollback domain. A backward step spanning process
replacement within the same boot remains an **activation integration gate**.
The contained owner's durable watermark keeps effective time from decreasing
and preserves expiry refusals, while the new process requires fresh independent
evidence. Consumers without their own durable watermark must decide separately
how they preserve the previous decision bound and hold continuity.

## Protected configuration and evidence interface

The protected shared policy supplies upper bounds. A service may retain or
narrow them, never loosen them. `LoadServicePolicy` rejects a looser value at
load. It cannot substitute the executable or complete configuration inventory;
NTS authdata may strengthen configuration-only evidence, never weaken it. A
service may turn itself off. The broker requires zero backward tolerance to
close on any relative backward movement, including measurement jitter or clock
slewing; this stricter choice trades availability for refusal. Other broker
bounds have no stricter implicit defaults.

The evidence-source interface consists of `Policy`, its strict protected loader,
`Collector.Collect(context, policy)`, `Clock.Read(context)`, and `Sample` /
`StartSample`. `Sample` supplies `Now`, `AuthorityUntil`, `Uncertainty`, `Boot`,
`Trusted` and `Fresh`. Collectors supply parsed tracking, the complete NTS source
inventory and optional authentication data. Every execution, timeout, output
limit, protected-read or parse failure is unavailable. Only the protected policy
can select a source; no environment or command-line override exists. Other
services use this same provider contract and stricter-only policy loader.
