Historical synthetic evidence; not current lab forwarding authority.
# Claude Code 2.1.328: Unix-socket wire contract

Local-only synthetic research; no credentials, upstream calls or product qualification.
UTC evidence date: 2026-11-19T10:28:01.932785+00:00. Started at 2026-11-19T09:58:27Z; completed within the requested 60-minute window.

## 1. Executive findings

- **The special placeholder mode does not remove model-call authentication headers.** OAuth sends `Authorization: Bearer ssh-placeholder`; API-key mode sends `x-api-key: ssh-placeholder`. The policy fetch is unauthenticated in both special-mode rows.
- **The same Unix socket carries two protocols with the default base URL:** policy uses plaintext HTTP/1.1, while model requests use TLS, then HTTP/1.1 inside TLS. A plaintext-only HTTP recorder therefore misses model requests; no logged GET/POST does not mean no socket traffic.
- **All four requested rows completed a one-turn synthetic model response over the Unix socket**, both with the default HTTPS model URL and with an explicit HTTP base URL. The two nonmagic rows skip the policy request in this fresh-HOME probe but still use the socket for model requests.
- An explicit `ANTHROPIC_BASE_URL=http://api.anthropic.com` makes both tested paths plaintext HTTP on the Unix socket. This is the simplest tested intake shape for a local credential-injecting gateway; treat it as **PROPOSED**, not as a shipped design.
- The valid minimal policy body tested is `{"restrictions":{}}`. A `request-id` response header is **not required in these tunnel runs**. `{}` is schema-invalid: it causes six policy fetches, although this configuration subsequently proceeds to the synthetic model call. Do not mistake eventual model success for policy acceptance.
- Every successful matrix run returned only the fixed synthetic text `ok` from the stub; no real model or credential validation was performed. Telemetry-disable flags alone did **not** prevent attempted network activity. Seccomp denied those attempts.

## 2. Binary identity and exact execution envelope

Binary: `<EXACT_CLIENT_EXECUTABLE>`.

Observed `--version`: `2.1.328 (Claude Code)`; version probe exited 0.

```text
a982d38030b97e750848add2cbb2df6d9a70d5544a22ca9b216a349ba25865e8
```

This SHA-256 was measured before probing and is independently included in every final run metadata file. All ten historical matrix/control runs share their original harness identity; their digests are recorded in `run.json` and the audit JSON.

Each CLI invocation had:

- a newly created, initially empty absolute HOME; task-owned cwd, config, cache, state, managed-settings, and temp directories;
- `/usr/bin/env -i` plus only the explicitly enumerated environment in `run.json`; stdin `/dev/null`; a 40-second timeout with TERM and a five-second kill grace;
- `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`, `DISABLE_TELEMETRY=1`, `DISABLE_ERROR_REPORTING=1`, `DISABLE_AUTOUPDATER=1`, `DISABLE_UPDATES=1`, `CLAUDE_CODE_DISABLE_CLAUDE_MDS=1`, and `ENABLE_CLAUDEAI_MCP_SERVERS=false`;
- `ANTHROPIC_UNIX_SOCKET` pointing at that run's owned `api.sock`; exactly the specified fake auth variable; no real auth material;
- a fail-closed seccomp launcher before exec; `strace -f` limited to `socket`, `connect`, and, in final runs, the three io_uring syscalls. No I/O-buffer tracing and no request-body persistence.

The model command was:

```sh
claude.exe -p "say ok" --max-turns 1 --no-session-persistence \
  --setting-sources "" --strict-mcp-config --tools "" \
  --disable-slash-commands --output-format json
```

The extra flags isolate settings/tools and prevent transcript persistence; this report is bounded to this invocation. The recorder consumes request bytes in memory and retains only a boolean indicating whether `stream` was true, never the body. The CLI's own stdout contains its synthetic result, not recorded request bodies.

For default-base TLS tests, the stub used a locally generated one-day certificate with SAN `api.anthropic.com`, trusted via `NODE_EXTRA_CA_CERTS`. TLS verification was **not disabled**. The private test key remains mode 0600 in task scratch and is not reproduced in this report. Adding this fixture trust changes trust only, not the requested model URL or Unix-socket routing.

## 3. Authentication matrix and complete observed sequences

Notation: **P** = plaintext `GET /api/claude_code/policy_limits`; **M** = `POST /v1/messages?beta=true` with JSON request and `stream:true`, answered by SSE. `absent` means no header, not an empty-valued header.

| Only auth variable set | Default model URL: sequence on the Unix socket | P auth | M auth | Explicit HTTP base: sequence | Exits / result |
| --- | --- | --- | --- | --- | --- |
| `CLAUDE_CODE_OAUTH_TOKEN=ssh-placeholder` | P (HTTP), then M (TLS → HTTP) | Both auth headers absent | `Authorization: Bearer ssh-placeholder`; no `x-api-key` | P (HTTP), then M (HTTP) | 0 / `ok` in both |
| `ANTHROPIC_API_KEY=ssh-placeholder` | P (HTTP), then M (TLS → HTTP) | Both auth headers absent | `x-api-key: ssh-placeholder`; no Authorization | P (HTTP), then M (HTTP) | 0 / `ok` in both |
| `CLAUDE_CODE_OAUTH_TOKEN=another-placeholder` | M only (TLS → HTTP) | No P observed | `Authorization: Bearer another-placeholder`; no `x-api-key` | M only (HTTP) | 0 / `ok` in both |
| `ANTHROPIC_AUTH_TOKEN=placeholder` | M only (TLS → HTTP) | No P observed | `Authorization: Bearer placeholder`; no `x-api-key` | M only (HTTP) | 0 / `ok` in both |

All eight final matrix runs had `is_error:false`, `stop_reason:end_turn`, and `num_turns:1`. No settings, profile, bootstrap, or token-count request was observed in these sequences. These absences are scoped to this version and isolated one-turn run, not a universal endpoint inventory.

### Exact recorded five-header profiles

P is identical for both exact-placeholder rows:

```json
{
  "authorization": null,
  "x-api-key": null,
  "anthropic-beta": null,
  "anthropic-version": null,
  "user-agent": "claude-code/2.1.328"
}
```

For M, `anthropic-version` is `2023-06-01` and `user-agent` is `claude-cli/2.1.328 (external, sdk-cli)` in every row. Full header records follow; these are copied from the default-base TLS observations, and the explicit-HTTP runs matched their corresponding profile.

#### OAuth / exact placeholder

```json
{
  "authorization": "Bearer ssh-placeholder",
  "x-api-key": null,
  "anthropic-beta": "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,tool-provenance-2026-10-26,thinking-token-count-2026-05-13,mid-conversation-system-clear-at-2026-08-21,effort-2025-11-24,thinking-binding-controls-2026-08-01,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07",
  "anthropic-version": "2023-06-01",
  "user-agent": "claude-cli/2.1.328 (external, sdk-cli)"
}
```

#### API key / exact placeholder

```json
{
  "authorization": null,
  "x-api-key": "ssh-placeholder",
  "anthropic-beta": "claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,thinking-token-count-2026-05-13,mid-conversation-system-clear-at-2026-08-21,effort-2025-11-24,thinking-binding-controls-2026-08-01,cache-diagnosis-2026-04-07",
  "anthropic-version": "2023-06-01",
  "user-agent": "claude-cli/2.1.328 (external, sdk-cli)"
}
```

#### OAuth / other placeholder

```json
{
  "authorization": "Bearer another-placeholder",
  "x-api-key": null,
  "anthropic-beta": "claude-code-20250219,oauth-2025-04-20,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,tool-provenance-2026-10-26,thinking-token-count-2026-05-13,mid-conversation-system-clear-at-2026-08-21,effort-2025-11-24,thinking-binding-controls-2026-08-01,extended-cache-ttl-2025-04-11,cache-diagnosis-2026-04-07",
  "anthropic-version": "2023-06-01",
  "user-agent": "claude-cli/2.1.328 (external, sdk-cli)"
}
```

#### ANTHROPIC_AUTH_TOKEN

```json
{
  "authorization": "Bearer placeholder",
  "x-api-key": null,
  "anthropic-beta": "claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,tool-provenance-2026-10-26,thinking-token-count-2026-05-13,mid-conversation-system-clear-at-2026-08-21,effort-2025-11-24,thinking-binding-controls-2026-08-01,cache-diagnosis-2026-04-07",
  "anthropic-version": "2023-06-01",
  "user-agent": "claude-cli/2.1.328 (external, sdk-cli)"
}
```

### Timing and reproducible evidence refs

Every run directory below is `<PRIVATE_EVIDENCE_ROOT>/<name>/` and contains `run.json`, `requests.jsonl`, `transport.jsonl`, `network.strace`, `stdout.log`, and `stderr.log`.

| Run | CLI exit | Seconds | Sequence | Successful socket connects |
| --- | ---: | ---: | --- | ---: |
| `final-oauth-ssh-tls` | 0 | 18.63 | GET /api/claude_code/policy_limits → POST /v1/messages?beta=true | 2 |
| `final-apikey-ssh-tls` | 0 | 20.305 | GET /api/claude_code/policy_limits → POST /v1/messages?beta=true | 2 |
| `final-oauth-other-tls` | 0 | 19.714 | POST /v1/messages?beta=true | 1 |
| `final-auth-token-tls` | 0 | 1.453 | POST /v1/messages?beta=true | 1 |
| `final-oauth-ssh-http` | 0 | 19.303 | GET /api/claude_code/policy_limits → POST /v1/messages?beta=true | 2 |
| `final-apikey-ssh-http` | 0 | 18.54 | GET /api/claude_code/policy_limits → POST /v1/messages?beta=true | 2 |
| `final-oauth-other-http` | 0 | 19.422 | POST /v1/messages?beta=true | 1 |
| `final-auth-token-http` | 0 | 1.091 | POST /v1/messages?beta=true | 1 |
| `final-policy-missing-restrictions` | 0 | 19.883 | GET /api/claude_code/policy_limits → GET /api/claude_code/policy_limits → GET /api/claude_code/policy_limits → GET /api/claude_code/policy_limits → GET /api/claude_code/policy_limits → GET /api/claude_code/policy_limits → POST /v1/messages?beta=true | 7 |
| `final-model-rejection` | 1 | 19.614 | GET /api/claude_code/policy_limits → POST /v1/messages?beta=true → POST /v1/messages?beta=true → POST /v1/messages?beta=true | 4 |

### Reconciliation with the earlier exploratory probe

`oauth-other-default-01/transport.jsonl` recorded six TLS ClientHellos during its 45-second plaintext-only run but no parsed HTTP requests; `auth-token-default-01` recorded seven. Both timed out (CLI exit 124) because that recorder did not serve TLS. After adding locally trusted TLS, the same auth rows completed over the Unix socket.

The exact previously mentioned fake value `CLAUDE_CODE_OAUTH_TOKEN=swarma-ph-test1` was also retested in `swarma-placeholder-tls-01`: exit 0, one TLS model POST, `Authorization: Bearer swarma-ph-test1`, no policy GET. Thus the earlier absence of HTTP log entries is not evidence that this fake value disables the socket.

The first stub's `{}` policy response also explains its six visible policy GETs: the controlled `{}` run reproduced six GETs. The transport explanation for the first stub is an inference supported by these direct reproductions; the original exploratory run itself was not modified or rerun.

## 4. Minimal successful response shapes

### Policy limits: accepted small body

```http
HTTP/1.1 200 OK
Content-Type: application/json
Content-Length: 19
Connection: close

{"restrictions":{}}
```

`Content-Length` must match the bytes actually serialized. The canonical compact example above is **19 bytes**. The harness uses Python's default JSON serializer, which inserts one space and therefore advertises **20 bytes**. Both are the same JSON shape.

`compliance_taints`, monitoring/default fields, and a `request-id` response header were omitted in the final successful runs. The body passed the small-shape path with one policy GET. The embedded schema requires `restrictions` as a record whose entries, when present, contain boolean `allowed`; `compliance_taints` defaults to an empty list. No broader claim about signed policy, principal attribution, managed settings, or production organization restrictions is made.

Negative neighbor: `final-policy-missing-restrictions` returned `{}` and caused **six** policy GETs before M. Its ultimate CLI exit 0 proves that this smoke configuration can proceed despite the unusable policy response; it does **not** make `{}` a valid policy response. A real gateway must forward actual policy, not fabricate permissive policy based on this stub.

### Settings/profile/bootstrap

No such request was needed to reach or finish M in any final matrix row. Therefore no valid response shape for those paths was established. `probe.py` has unused exploratory fixtures for settings/profile; they are **not evidence** and are not part of the proven minimal contract. Future gateway support for those endpoints requires forwarding and separate coverage, not copying those unused fixture bodies.

### Messages: streaming SSE

Observed request path is `/v1/messages?beta=true`, not merely `/v1/messages`. The request has `stream:true`. The small canonical SSE fixture below completed both OAuth and API-key rows. It intentionally includes normal message identity, role, model, content and token usage; it is a tested small protocol-valid fixture, not a claim of byte-optimal minimality or every field's necessity.

```http
HTTP/1.1 200 OK
Content-Type: text/event-stream
Content-Length: <actual SSE byte count>
Connection: close
```

Each SSE event is followed by a blank line; the final `message_stop` also has a terminating blank line. No `data: [DONE]` sentinel, ping, response `request-id`, tool event, stop_sequence field, or additional turn was required:

```text
event: message_start
data: {"type":"message_start","message":{"id":"msg_synthetic","type":"message","role":"assistant","model":"claude-sonnet-4-6","content":[],"usage":{"input_tokens":1,"output_tokens":0}}}

event: content_block_start
data: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}

event: content_block_delta
data: {"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"ok"}}

event: content_block_stop
data: {"type":"content_block_stop","index":0}

event: message_delta
data: {"type":"message_delta","delta":{"stop_reason":"end_turn"},"usage":{"output_tokens":1}}

event: message_stop
data: {"type":"message_stop"}
```

The fixture's model name is a synthetic response field; no real model was contacted. The client's request model was not persisted. A production gateway forwards the genuine upstream message/SSE response rather than synthesizing these frames.

### Required negative model control

`final-model-rejection` returned HTTP 400 with `{"type":"error","error":{"type":"invalid_request_error","message":"synthetic negative control"}}`. The CLI made three model POSTs and returned **exit 1**, `is_error:true`, `API Error: 400 synthetic negative control`. This remains a failing CLI run, intentionally. Its `stop_reason` field was `stop_sequence`; that field does not override the error verdict. The final harness returns the child's actual exit code.

## 5. No-egress evidence and its bounds

`unshare -rn` failed before execution: `unshare: write failed /proc/self/uid_map: Operation not permitted`. Evidence: `<PRIVATE_EVIDENCE_ROOT>/readiness-01.log`. A network namespace was therefore **not** available and is not claimed.

Instead, `socket_only.py` loaded libseccomp before exec, closed inherited descriptors above stderr, and installed:

- allow AF_UNIX socket creation; refuse **every other socket family** with EPERM, including IPv4, IPv6, packet, and netlink;
- refuse io_uring setup/enter/register and native socketcall if available, preventing an alternate socket-creation path;
- preserve the filter across exec and children (`NoNewPrivs:1`, `Seccomp:2` verified in a child). Failure to load a rule/filter aborts before launching Claude.

Positive/negative controls in `validation-final/tests.log`:

| Named test | Claim and bound | Result |
| --- | --- | --- |
| `test_seccomp_allows_unix_and_rejects_other_socket_families` | Actual AF_UNIX creation succeeds; IPv4/IPv6/packet creation and x86_64 io_uring setup return EPERM; security status is active. | Passed |
| `test_unfiltered_socket_creation_control` | Without this filter an AF_INET socket can be created and closed; no connect/send occurs. Thus the denial control is meaningful, not merely inherited host refusal. | Passed |
| `test_unix_http_records_only_allowlisted_headers_and_stream_flag` | A filtered child performs a real Unix HTTP POST and receives SSE; sentinel request body does not appear in recorder output. | Passed |
| `test_trace_auditor_accepts_owned_unix_and_rejects_planted_egress` | Synthetic log plants of successful AF_INET creation and foreign Unix connect are detected, with valid owned-Unix positive control. These plants generate no network traffic. | Passed |
| `test_sse_fixture_has_complete_text_turn` | Canonical full SSE fixture orders text events and an end_turn stop without a tool call. Runtime final probes independently exercise the reduced fixture. | Passed |

All five tests passed, command exit **0**. Isolated `py_compile` of all four Python files exited **0**. The evidence auditor exited **0** on all ten final runs, with no violations. Each final CLI process tree had **zero successful non-Unix socket creations**, and **every successful connect was to that run's own stub socket**. The recorder neither forwards nor passes file descriptors. These facts establish no network egress for the probed process trees; they do not claim a host-wide isolation policy for unrelated processes.

Attempted non-Unix activity was nevertheless observed and refused:

| Final run | Refused socket-family calls |
| --- | --- |
| `final-oauth-ssh-tls` | AF_NETLINK: 7, AF_INET: 14 |
| `final-apikey-ssh-tls` | AF_NETLINK: 7, AF_INET: 14 |
| `final-oauth-other-tls` | AF_NETLINK: 12, AF_INET: 24 |
| `final-auth-token-tls` | None observed |
| `final-oauth-ssh-http` | AF_NETLINK: 7, AF_INET: 14 |
| `final-apikey-ssh-http` | AF_NETLINK: 7, AF_INET: 14 |
| `final-oauth-other-http` | AF_NETLINK: 12, AF_INET: 24 |
| `final-auth-token-http` | None observed |
| `final-policy-missing-restrictions` | AF_NETLINK: 7, AF_INET: 14 |
| `final-model-rejection` | AF_NETLINK: 7, AF_INET: 14 |

Typical traces include failed `/var/run/nscd/socket` lookups (ENOENT) and denied DNS/netlink-related socket creation. No successful connect to an outside Unix proxy occurred. Thus “no egress” is an enforced/observed property here, **not** a claim that Claude made no attempted off-socket calls. The 18–20 second timings in several rows include isolated startup and denied activity; they are not production latency measurements.

## 6. What the embedded strings/code establish

Offsets below are zero-based byte offsets in the SHA-pinned binary. Only short fragments are quoted:

| Offset | Fragment / function | Interpretation |
| ---: | --- | --- |
| 306322961 | `var Iye="ssh-placeholder"` | The placeholder is a literal, not an arbitrary token prefix. |
| 306322987 | `function Kul(e)` | Special-mode predicate: socket nonempty, auth-token falsey, and either OAuth exactly the literal with API-key falsey, or API-key exactly the literal with OAuth falsey. Empty values are falsey; PROPOSED configuration below uses unset for clarity. |
| 309346284 | `function odo()` | Caches/returns the socket only when that special predicate holds. `OJa()` resets its cached selection. |
| 307720189 | `if(e.forAnthropicAPI)` | Separate fetch-option helper `el(e)` reads the raw socket environment and supplies `unix:u` for Anthropic API requests (with a runner/third-party exception outside this probe). It is not gated by Kul. This matches model routing for nonmagic tokens. |
| 310979450 | `KIn` / `restrictions` | Policy schema has required restrictions; compliance_taints has an empty-list default. |

Additional observed functions: `Ucr(e)` performs the policy HTTP request using `socketPath`; `z$e(e)` checks request-id presence in some response-validation paths. The no-request-id positive controls show that its existence in the binary does not imply a mandatory response header in the tested tunnel mode. Minified identifiers are version-specific, not a stable public API. Static evidence: `<PRIVATE_EVIDENCE_ROOT>/static-findings.json`; bounded inspection logs also remain under `.temp/synthetic/`.

## 7. PROPOSED worker-side contract

For a gateway that holds a real **OAuth bearer token**, use exactly:

```sh
ANTHROPIC_UNIX_SOCKET=/absolute/task-owned/gateway.sock
ANTHROPIC_BASE_URL=http://api.anthropic.com
CLAUDE_CODE_OAUTH_TOKEN=ssh-placeholder
# ANTHROPIC_API_KEY is unset
# ANTHROPIC_AUTH_TOKEN is unset
```

These are variable assignments, not an invitation to inherit the rest of a host environment: construct an allowlisted worker environment and export the three named values when launching the CLI. Keep the traffic/update disable flags and independent no-egress confinement. The absolute Unix path is the physical destination; the HTTP base removes model TLS on that local transport. Do not ship `NODE_TLS_REJECT_UNAUTHORIZED=0` or an impersonating Anthropic certificate as a workaround. The TLS certificate in this research is only a controlled test fixture.

If the gateway instead holds a real **API key**, the tested alternative is `ANTHROPIC_API_KEY=ssh-placeholder`, with both OAuth and auth-token variables unset and the same socket/HTTP-base variables. The model request then contains `x-api-key: ssh-placeholder`, and the beta profile differs. Do not automatically convert between OAuth/API-key modes: upstream credential type, headers and entitlements must agree.

Do not use `ANTHROPIC_AUTH_TOKEN=placeholder` or an arbitrary OAuth placeholder as the supported worker contract merely because model traffic reaches the socket: those rows do not activate the special policy-tunnel predicate. The literal is also **not** a secret or an identity boundary.

## 8. PROPOSED gateway intake contract

1. **Local transport and identity:** accept plaintext HTTP/1.1 on the protected AF_UNIX socket for the proposed explicit-HTTP-base worker. Authenticate/authorize the worker by socket permissions and Unix peer identity/custody, not by possession of a public placeholder. If the default HTTPS model base is retained instead, the intake must additionally multiplex plaintext policy HTTP and model TLS, with a legitimate trust arrangement; plaintext-only intake cannot serve that default flow.
2. **Policy request:** accept `GET /api/claude_code/policy_limits` with **no Authorization and no x-api-key** from the authorized local peer. The client's User-Agent is the smaller `claude-code/2.1.328` profile. Supply the configured real upstream credential before forwarding. Return the genuine policy response and applicable headers; do not require a placeholder header on this path and do not fabricate `{}` or permissive restrictions.
3. **Model request:** accept `POST /v1/messages?beta=true`; preserve the query string and the JSON request bytes. In OAuth mode the expected incoming marker is `Authorization: Bearer ssh-placeholder`; in API-key mode it is `x-api-key: ssh-placeholder`. Strip worker-supplied credential headers and inject only the gateway-owned credential of the configured type. Reject unexpected credential forms rather than accidentally forwarding them. Preserve the observed anthropic-version/beta and other legitimate end-to-end protocol headers; do not mistake the policy UA for the model UA.
4. **Streaming response:** proxy upstream SSE incrementally without buffering the entire completion; preserve event names/data, JSON structure, usage, terminal events, status and meaningful upstream error metadata. A 400/error response must remain an error, not be replaced with the synthetic `ok` fixture.
5. **Forwarding boundary:** pin the upstream origin and admitted paths/methods; do not turn the Unix endpoint into a general arbitrary-origin proxy. No worker-selected placeholder is sufficient authorization for cross-task credential use. Do not return the real credential to the worker or include request bodies/credentials in logs.
6. **Future endpoints:** settings/profile/bootstrap were absent here. Forwarding support and shapes for those paths are not established by this research. If admitted later, add protocol-preserving coverage against the actual contract rather than inventing success bodies from the exploratory stub.

This proposal is an intake design recommendation grounded in the measured client wire behavior, **not** an implementation or an upstream-token-injection qualification. Real OAuth/API-key authorization, production managed-policy signatures, account/profile behavior, upstream errors/retry semantics beyond the bounded 400 control, and long-running/multiturn sessions remain untested because this probe intentionally used no network or real credential.

## 9. Artifacts, validation commands, and remaining boundaries

- Harness source: `repo/probe.py`, `repo/socket_only.py`, `repo/audit_evidence.py`, `repo/test_harness.py`; tools/reproduction: `repo/README.md`.
- Exact final evidence projection: `<PRIVATE_EVIDENCE_ROOT>/final-evidence-audit.json` (auditor exit 0); detailed per-run paths listed above.
- Test evidence: `<PRIVATE_EVIDENCE_ROOT>/validation-final/tests.log` (5 passed, exit 0); syntax evidence: `validation-final/compile.log` (exit 0).
- Historical readiness, binary-fragment and version evidence was retained privately; no private paths are reproduction requirements.
- Historical tooling/process notes are omitted from this public protocol report.
- No product implementation, real credential, live vendor call or native qualification was involved.
- This sanitized historical report preserves original line numbering; private evidence paths are not reproduction instructions.
