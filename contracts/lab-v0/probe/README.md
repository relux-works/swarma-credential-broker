# Exact-client synthetic probe

Linux x86_64/glibc only. No real key, login, installed credential, vendor call or
product acceptance. `socket_only.py` uses libseccomp.so.2 **before exec**, closes
inherited descriptors above stderr and denies every non-Unix socket and io_uring.
`probe.py` starts a local stub, never a forwarder, in a new empty absolute
HOME/cwd/cache/config/tmp. Its child environment is enumerated from scratch;
OAuth and auth-token variables are absent in the API-key row. Input is /dev/null;
settings/tools/session persistence are disabled. The only API credential value
is the public `ssh-placeholder`. No setting here is a credential-use permit.

## Provenance

Recovered historical sources were hashed before editing; they match the design:

| Artifact | Prior SHA-256 | Published disposition |
| --- | --- | --- |
| probe.py | f6577f89d25cf82a2d152f9925379a396d2a60ad4717499a52a508c8bebcecb6 | Re-pinned portable successor: fixed local paths replaced by explicit --binary/--scratch; exact executable digest checked before run creation; API-key row default; internal request label replaced; structural enum and synthetic credential guards added. |
| socket_only.py | 1b9d051798e12b8562aa14db5f46aca66d53ea23a44d07d9b9fd11d092632776 | Exact unchanged bytes. |
| REPORT.md | b0012b9dcf893eab063ced90311cf297bfda5cfc1caf0d0506bbdb71914437d8 | Sanitized historical report: local paths, identity/request labels and process notes removed/replaced; original line numbering and protocol observations retained. Not a byte-identical copy. |

Current file hashes are in `../index.json`. The old report's references to
private audit sources/logs are historical evidence, **not** available artifacts or
reproduction prerequisites. Its sections 7–8 are superseded by the lab design:
API-key policy GET forwards credential-free, never injects a key or fabricates
successful restrictions. `observed.json` is the retained header/shape-only
2026-11-20 observation, with nondeterministic timings removed. It is not a retained
body. `../wire-fixtures.json` reconstructs that shape with public sentinels; it
never claims to reproduce private client prompt/metadata bytes.

`client.json` records public package identity, SHA-512 tarball integrity and
SHA-256 executable pin. No executable or package archive is vendored. Acquire
that exact public package independently, verify SHA-512 **before** extraction,
and verify the extracted `package/claude` SHA-256 before running it. Do not use
npm install or any package install hook. No latest-version lookup is a pin.
Example acquisition in an absolute task-owned scratch directory:

```sh
curl --fail --location --proto '=https' --tlsv1.2 \
  'https://registry.npmjs.org/@anthropic-ai/claude-code-linux-x64/-/claude-code-linux-x64-2.1.328.tgz' \
  --output "$SCRATCH/client.tgz"
python3 - "$SCRATCH/client.tgz" "$REPO/contracts/lab-v0/probe/client.json" <<'PY'
import base64, hashlib, json, pathlib, sys
archive = pathlib.Path(sys.argv[1]).read_bytes()
expected = json.loads(pathlib.Path(sys.argv[2]).read_text())["tarball_sha512_integrity"]
assert "sha512-" + base64.b64encode(hashlib.sha512(archive).digest()).decode() == expected
PY
tar -xzf "$SCRATCH/client.tgz" -C "$SCRATCH" -- package/claude
printf '%s  %s\n' \
  a982d38030b97e750848add2cbb2df6d9a70d5544a22ca9b216a349ba25865e8 \
  "$SCRATCH/package/claude" | sha256sum --check --strict
```

## Reproduce in an isolated checkout

Prerequisites: Python 3 (standard library only), libseccomp.so.2, strace, GNU
timeout, exact pinned executable, Linux x86_64. No root or namespaces required.
Use an absolute short scratch path for Unix sockets; preserve no login state.
Set REPO to an isolated checkout and SCRATCH to a newly created task-owned
absolute physical directory. HOME, USERPROFILE, XDG_CONFIG_HOME, XDG_CACHE_HOME,
XDG_STATE_HOME, TMPDIR/TMP/TEMP must all name separate directories inside it.
The root test-isolation contract applies before any test starts. All outputs
stay under SCRATCH; never use an installed broker/service directory.

```sh
cd "$REPO"
python3 contracts/lab-v0/probe/test_probe.py -v
python3 contracts/lab-v0/probe/probe.py \
  --binary "$SCRATCH/package/claude" --scratch "$SCRATCH" --name api-valid \
  --row apikey-ssh --timeout 40 \
  --extra-env ANTHROPIC_BASE_URL=http://api.anthropic.com \
  --extra-env API_TIMEOUT_MS=6000
python3 contracts/lab-v0/probe/verify_run.py "$SCRATCH/api-valid"
```

The valid child exits 0 with synthetic ok. Adjacent negative: the **same command**
with `--name api-error --messages error` must return **1**; record that nonzero
exit as expected refusal, then run `verify_run.py "$SCRATCH/api-error"
--expected-exit 1` (exit 0 means the auditor confirmed the expected failing run).
The negative is not a successful vendor call. The local stub uses a minimal
restrictions object solely to complete the synthetic protocol; the live gateway
must preserve genuine upstream errors. The trace auditor rejects successful
foreign-Unix/non-Unix connects/creation, incomplete trace records and missing
own-socket/model observations; test plants establish that it detects violations.

Each run keeps run.json, requests.jsonl, transport.jsonl, network.strace and
synthetic stdout/stderr in its owned directory. Only headers/shape/enum values
are projected from request bodies, not prompt/metadata values. The child's raw
output is private synthetic scratch, not public evidence; do not copy runtime
identifiers into a handoff. Reproduction need not reproduce durations, ephemeral
identifiers or exact prompt contents. It must reproduce exact measured protocol
headers/field paths and bounded result. Binary, model or invocation drift refuses;
review a new C0/profile revision instead of accepting a new golden silently.

No live output/spend bound is approved: observed max_tokens=128000 is a fixture
fact, not budget permission. The owner-approved live bounded invocation, capped
workspace, C-OPEN owner decisions, native isolation/NTS and release gates remain
mandatory. Reproduction runs zero vendor inference and supplies no authority to
proceed with any of them.

### Error fallback observation (not an admitted profile)

The exact-client HTTP-400 control exits 1 after three local model attempts.
`probe/error-observed.json` (relative to the contract root) retains only projected
headers/shape. The second/third attempts omit thinking-token-count-2026-05-13;
the third exceeds the recorder's reviewed enum projection and therefore has no
complete body shape. The published auditor validates the initial full profile,
fixed auth/path and genuine 400 replies, reports two **unqualified retries**, and
never treats those retries as admitted API-key requests. The corresponding
missing-thinking-beta fixture is a refusal. The lab gateway must reject such
profile drift, not silently broaden the eleven-token/body contract to make an
error fallback succeed. This observation qualifies neither a fallback body nor
vendor retry behavior; live Q1 must tolerate genuine errors under the closed
profile. The successful synthetic control remains exactly GET then POST.
