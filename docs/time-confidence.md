# Independent time confidence

`internal/timeconf` supplies independent clock evidence. It depends only on the
standard library and `golang.org/x/sys`; it has no account, lease or server
imports. `internal/ownerconfidence` adapts its samples to `authowner.Confidence`.
The owner still applies the [effective-time and durable-watermark model](auth-owner.md#normative-trusted-time-model).
The command continues to use `owner.Stopped`.

## Source selection and policy

The [platform ruling](time-policy.md) selects configuration-based NTS evidence
for v0 and requires authdata before the dedicated service. Absent policy selects `off`, and every sample
returns `time_confidence_unavailable`. Environment variables and command arguments
cannot select a source. The two implemented choices are:

- `chrony-nts-config`: a protected, complete list of chrony configuration files
  contains only NTS server/pool associations; tracking passes all bounds.
- `chrony-nts-authdata`: the same checks plus authentication status for every
  reported association, including the selected tracking address. Missing monitor
  permission, including a 501 response, refuses confidence.

Neither selection is activated by this change. An operator must control the installed daemon, its
executable, configuration inventory and all ways it can add/change associations.
Configuration inspection alone cannot establish that an independently reconfigured
running daemon loaded those files. Dynamic includes/source directories, peers,
local reference clocks and unknown directives are refused. A closed subset of
ordinary non-source directives is parsed; unsupported configuration refuses
rather than being silently skipped. Referenced key/certificate files are never
opened by the collector.

`LoadPolicy(path, uid)` reads a regular, singly linked mode-0600 file owned by
that UID, rejects symlinks and unsafe ancestors, and strictly decodes JSON.
Duplicate/unknown members, nulls, trailing input and missing enabled bounds are
errors. Enabled policies use integer nanoseconds:

| Field | Accepted bound |
|---|---|
| `source` | `off`, `chrony-nts-config`, `chrony-nts-authdata` |
| `chronyc` | Clean absolute executable path; no PATH lookup |
| `source_files` | 1–32 unique clean absolute paths, constituting the complete configuration inventory |
| `max_sync_age_ns` | Positive, at most 1024 seconds |
| `max_offset_ns` | Positive, at most 0.5 seconds; covers absolute system/last offset and RMS offset |
| `max_root_distance_ns` | Positive, at most one second; root delay / 2 + root dispersion |
| `authority_window_ns` | Positive, at most five minutes and no greater than sync age |
| `step_tolerance_ns` | Positive, at most one minute; forward wall-minus-elapsed tolerance |
| `backward_tolerance_ns` | Explicit, zero through one second; backward wall-minus-elapsed tolerance |
| `timeout_ns` | Positive, at most ten seconds per command |
| `max_output_bytes` | 256–65536 bytes for each configuration file/command |
| `resync` | `new-authenticated-sync` or `operator` |

`off` accepts no nonzero settings. Zero backward tolerance is valid and closes
on any observed negative wall-minus-elapsed delta. Broker static policy requires
zero. This deliberately includes measurement jitter and ordinary clock slewing;
a deployment must account for the resulting availability cost.

Another service loads the protected shared upper bounds with `LoadPolicy`, then
its protected restriction with `LoadServicePolicy(path, uid, shared)`. Every
numeric upper bound may stay equal or become smaller; zero backward tolerance is
the strictest value. The executable and complete file inventory must stay identical. A service
may strengthen configuration-only evidence to require NTS authdata, but cannot
weaken that requirement. Operator-only recovery may replace automatic recovery. An `off`
restriction is always allowed; a service cannot enable shared `off` policy.
Looser overrides are rejected during load. `ServicePolicy` provides the same
comparison for an embedding service's already protected static configuration.
The optional broker member `policy.time_confidence` is validated and cloned with
the rest of the static policy; activation must still apply the shared restriction
contract before construction. It does not change command wiring.

## Collection and samples

The collector invokes exactly `chronyc -c tracking`. When the numeric selected
address does not directly match a configured entry, it also invokes
`chronyc -c -N tracking` to obtain the original configured name. Both reports
must agree on reference ID, reference timestamp and stratum; changed selection
refuses. The final report supplies the measured fields and the first address
remains the authentication correlation. Names are canonicalized without DNS
lookups. For the second option, it invokes
`chronyc -c authdata -a`. Commands use only `LC_ALL=C`, `LANG=C`, `TZ=UTC`, no
stdin, a deadline and a shared bounded stdout/stderr writer. Nonzero exits,
timeouts, overflow and parsing errors discard all output. Diagnostic text is
never interpreted as authority or returned to callers.

Tracking uses the fixed 14-column CSV report. Authentication uses ten columns.
Parsers reject truncated/extra rows or fields, blank lines, quoting, nonfinite
numbers and unknown enums. Tracking requires Normal leap, stratum 1–15, a
nonfuture reference strictly younger than the age bound, bounded offsets and
root distance, and sensible numeric fields. Authentication requires NTS,
recognized negotiated algorithm/key size, cookies, no NAK, and no repeated
failed establishment. A successful collection is required on every sample.

`Sample` contains `Now`, exclusive `AuthorityUntil`, `Trusted`, `Fresh`,
`Uncertainty` (δ), and `Boot`. Failure returns a zero sample and the fixed error.
Authority ends at the earlier of `Now + authority_window` and
`reference_time + max_sync_age`; a consumer must recheck at that exclusive end.

Under the authenticated time source's NTP error model, δ in seconds is:

```
max(abs(system_offset), abs(last_offset), rms_offset)
+ root_delay / 2 + root_dispersion
+ age_since_reference * skew_ppm / 1000000
```

The conversion rounds upward to nanoseconds. This includes measured correction
plus root distance and conservatively includes last/RMS correction and dispersion
growth. It is conditional on the selected source's correctness and the reported
error estimates; authentication cannot make a false server's time true. The
[chrony tracking documentation](https://chrony-project.org/doc/4.6/chronyc.html#tracking)
describes the offset and root-distance error model; CSV layouts follow the
[chrony client implementation](https://gitlab.com/chrony/chrony/-/blob/4.6/client.c).

## Boot comparison, hold and process start

Samples serialize clock/evidence reads. Linux collection reads boot ID and
`CLOCK_REALTIME` / `CLOCK_BOOTTIME` before and after evidence collection, even
when that collection fails. Comparisons occur only within the same boot. A
negative elapsed delta, relative backward movement beyond its bound,
or excessive relative forward movement sets a hold and emits `clock_step_hold`.
Collector failures and subsequent ordinary good reports cannot clear it.
Automatic recovery requires stable elapsed progression and a newer authenticated
reference later than both the prior reference and the maximum wall time observed
at the incident. Operator recovery has no reset command in this slice and stays
closed. A changed boot discards comparison state, refuses the transition sample,
and still requires valid fresh evidence on a later sample.

Hold/baseline state belongs to a provider instance for its boot; it is not stored
in the restored account store. Replacing an instance is not an operator
acknowledgement. Deployments needing one hold across process replacement must
retain that independent authority or require authenticated resynchronization
before reopening. A backward step spanning process replacement within one boot
is an activation integration gate; consumers without a durable watermark must
decide continuity separately. See the [platform policy](time-policy.md).
Diagnostics contain fixed incident codes, never command output, boot IDs or
source addresses.

A new process calls `StartSample(ctx)` before any time decision. This performs
new collection and returns δ and the boot identity, with the same refusal rules.
A consumer uses monotonic elapsed time for waiting; it must not sleep against
a wall-clock deadline to establish ordering. Given the previous process's last
decision sample P and uncertainty δP, the new lower bound `Now - δ` must be
strictly greater than `P + δP`. Otherwise wait and sample again. If one bound δ
covers both observations, waiting more than 2δ on a continuous monotonic clock
provides the corresponding separation, subject to fresh confidence and the
absence of intervening steps. Unequal bounds need at least their sum. A boot
change or hold requires re-establishing evidence and the previous decision bound;
2δ alone cannot reconstruct lost history. Consumers must keep the previous
bound outside their rollback domain and continue checking confidence at each
decision. `StartSample` does not manufacture that history or persist an account
watermark.

## Checks

Fixture tests exercise collectors without system time changes or vendor access:

```sh
go test ./internal/timeconf ./internal/ownerconfidence ./internal/policy -count=1
go test ./internal/authowner -run '^TestConfidence' -count=1
```

For a read-only installation diagnostic, explicitly opt into:

```sh
go test -tags=timeconf_smoke ./internal/timeconf -run '^TestHostTimeConfidenceSmoke$' -count=1 -v
```

The diagnostic prints only fixed verdicts and parsed numeric/enum aggregates.
Unavailable configuration or monitoring permission is reported as unavailable;
its test-process success is evidence collection only and grants no qualification
or activation. It does not write system configuration, change the clock, log in,
or contact a credential issuer. Keep captured output in private scratch.
