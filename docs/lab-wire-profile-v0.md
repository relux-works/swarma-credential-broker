# Lab API-key wire profile v0

Status: measured synthetic evidence; not upstream authorization or qualification.

## 1. Identity and boundary

The no-network probe on 2026-11-20 used Claude Code **2.1.328**, Linux x86_64,
executable SHA-256 `a982d38030b97e750848add2cbb2df6d9a70d5544a22ca9b216a349ba25865e8`.
The vendor platform package's published SHA-512 integrity was checked before
extracting that executable; its SHA-256 exactly matches the earlier wire probe.
No package install script ran and no host CLI installation changed.

The original 2026-11-19 report, `REPORT.md:94–97` and `:279–287`, has SHA-256
`b0012b9dcf893eab063ced90311cf297bfda5cfc1caf0d0506bbdb71914437d8`.
It measured the API-key header and eleven flags but explicitly did not retain
body fields (`REPORT.md:44`). The new probe retains structural field paths and
nonsecret protocol enum values only, never prompt text or metadata values.

Both probes use `ANTHROPIC_API_KEY=ssh-placeholder`, unset OAuth/auth-token
variables, `ANTHROPIC_UNIX_SOCKET` and `ANTHROPIC_BASE_URL=http://api.anthropic.com`.
The new invocation was one synthetic turn with isolated empty HOME/cwd/caches,
no session persistence, empty settings/tools and a fixed local SSE reply.
Seccomp runs before exec, closes inherited descriptors and forbids non-Unix
sockets and io_uring. Its valid Unix socket control and AF_INET/EPERM negative
both passed (exit 0). The exact-client probe exited 0 with synthetic `ok`;
strace records syscall metadata, not request buffers. No real key, login,
external request, broker action or action on the dedicated lab VM occurred.

## 2. Measured requests

`GET /api/claude_code/policy_limits` had neither Authorization nor x-api-key,
no beta/version headers and `User-Agent: claude-code/2.1.328`.

`POST /v1/messages?beta=true` had exactly `x-api-key: ssh-placeholder`, no
Authorization, `anthropic-version: 2023-06-01` and
`User-Agent: claude-cli/2.1.328 (external, sdk-cli)`. Its comma-list was:

```text
claude-code-20250219,interleaved-thinking-2025-05-14,context-management-2025-06-27,prompt-caching-scope-2026-01-05,per-turn-control-2026-07-01,mid-conversation-tool-changes-2026-07-01,thinking-token-count-2026-05-13,mid-conversation-system-clear-at-2026-08-21,effort-2025-11-24,thinking-binding-controls-2026-08-01,cache-diagnosis-2026-04-07
```

The header profile matches the original API-key observation. Relative to the
OAuth observation, the API-key client itself omits `oauth-2025-04-20`,
`tool-provenance-2026-10-26` and `extended-cache-ttl-2025-04-11`. The latter two
are **not declared OAuth-only**: the gateway must not silently strip them from
an OAuth-mode request and pretend the remaining body is this API-key profile.

## 3. Body-field evidence and beta coupling

| Measured field/control | Value or bounded observation | Required retained profile token |
| --- | --- | --- |
| `stream` | `true`; fixed valid SSE completed | Protocol behavior, not a beta removal license |
| `system[].cache_control` | ephemeral; one control has `scope:global`; no `ttl:1h` | `prompt-caching-scope-2026-01-05` for scope |
| `messages[].content[].cache_control` | ephemeral; no one-hour TTL observed | Keep the measured API-key profile; no extended-TTL conversion |
| `context_management.edits[]` | `type:clear_thinking_20251015`, `keep:all` | `context-management-2025-06-27` |
| `diagnostics.previous_message_id` | Field present; value not retained | `cache-diagnosis-2026-04-07` |
| `output_config.effort` | `medium` | `effort-2025-11-24` |
| `messages[].output_config.effort` | Field present; value not retained | `per-turn-control-2026-07-01` and `effort-2025-11-24` |
| `thinking` | `type:adaptive`, `display:omitted` | Retain interleaved-thinking and thinking profile flags |
| `tools` | Empty in this one-turn probe | Absence does not qualify tools/multiturn behavior |
| `model`, `max_tokens` | `claude-opus-5-5`, `128000` observed default | Measurement only, **not an approved live cost/output bound** |

No system `clear_at`, tool provenance or one-hour TTL appeared in the observed
structural inventory. Keep the other measured flags too: absence in one turn
is not evidence that a client flag is safe to remove. The landed OAuth fixture
is a counterexample to strip-all: its `cache_control.scope:global,ttl:1h`
requires preserving its own beta/body coupling, not treating it as this row.

## 4. Reproduction and limits

| Probe component | SHA-256 |
| --- | --- |
| `probe.py` | `f6577f89d25cf82a2d152f9925379a396d2a60ad4717499a52a508c8bebcecb6` |
| `socket_only.py` | `1b9d051798e12b8562aa14db5f46aca66d53ea23a44d07d9b9fd11d092632776` |

The harness is derived from the original Unix-only recorder. Its only protocol
observation extension walks decoded JSON in memory and emits sorted field paths,
cache-control enum values, thinking/context-management structure and output
configuration; string contents and metadata values are excluded. All executable
bytes and harness digests are retained with the local evidence. A structural
positive/negative control checks that scope/TTL paths are distinguished without
emitting content. The observed GET and POST headers are asserted against the
closed eleven-token profile, not accepted because two implementations agree.

This is a local wire observation, not evidence that an inert key authenticates,
that every beta/body combination is vendor-valid, or that a changed model,
executor, tool configuration or later client preserves this profile. Freeze and
measure the final approved bounded invocation before release; real vendor API
compatibility remains an owner-run Q1 gate. Preserve genuine vendor errors.

## 5. Repository reproduction boundary

**This wire profile cannot be reproduced from this repository.** The original
`REPORT.md` and the digest-pinned `probe.py`/`socket_only.py` are externally held
artifacts, not files published here; their line references name that external
report. Digests bind identities, not availability or an executable reproduction.
The structural observations above are retained evidence, not a repository-owned
probe suite. C0 must publish reviewed exact-client harness/fixtures and a
reproducible bounded invocation before freezing the release profile; absent
those artifacts, the release gate stays closed. No new probe or upstream API
qualification is claimed by this clarification.
