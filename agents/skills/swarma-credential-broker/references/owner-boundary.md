# OWNER-SITTING boundary and implemented commands

This is a static interface inventory, not an execution procedure. All owner
presence, keys, enrollment, credential custody, storage, refresh, signing and
live broker interaction are **OWNER-SITTING only**. An agent may explain public
source and validate synthetic inert data; it must not obtain credentials, open
live broker sockets, read protected stores, collect host evidence or log secret
payloads. A flag named fixtures can still execute processes and write state.
No command below is run by this skill's inert workflow.

## Existing executable surface

[main.go](../../../../cmd/swarma-credential-broker/main.go) dispatches the binary
`swarma-credential-broker`. The following rows identify existing parsers, not
permission or an assertion that a binary is installed.

| Command | Accepted selectors at this pin | Defining source |
|---|---|---|
| `daemon` | Required `--config`; optional `--init-store` for new empty metadata directories. | [main_linux.go](../../../../cmd/swarma-credential-broker/main_linux.go) |
| `status` | Required `--config`; `--init-store` is rejected. Reads live broker metadata and is still outside agent scope here. | [main_linux.go](../../../../cmd/swarma-credential-broker/main_linux.go) |
| `run-codex` | Required `--account`, `--profile`, `--launch-home`, `--model`, `--reasoning-effort`, `--output-last-message`; exactly one of `--prompt-file` or `--prompt-stdin`. Optional `--cwd`, `--timeout` (positive seconds, default 300). `--resume` is parsed but always refused. | [options.go](../../../../internal/runner/options.go) |
| `qualify-codex` | `--executable`, `--evidence-dir`; exactly one of `--fixtures` or `--live`. `--fixture-config` is optional only with fixtures. `--approval-ref`, `--account` are parsed, forbidden with fixtures; live still refuses. | [command_linux.go](../../../../internal/qualify/command_linux.go) |

The Linux daemon/status parser returns 64 for invalid arguments, including
missing configuration or status initialization. Protected configuration failure
returns 69. Non-Linux daemon/status dispatch returns 69 in
[main_other.go](../../../../cmd/swarma-credential-broker/main_other.go).
Runner invalid syntax returns `invalid_command` (64); after required syntax
checks, a supplied resume selector returns `lease_harness_unqualified` (69). The runner has no CLI selector for
policy, socket, broker UID or qualification authority; its
[protected authority](../../../../internal/runner/authority_linux.go) uses the
fixed protected configuration through existing wiring.

Qualification requires clean absolute executable/evidence paths; duplicate
selectors, extra positional arguments or conflicting modes return 64.
Syntactically valid live mode returns 69 before any qualification work. Fixtures
can run candidate observers, create evidence and exercise protected synthetic
rows; they are not the inert in-memory validation in this skill. Pending/missing
qualification is 69, not qualification success. See the
[qualification guide](../../../../docs/qualification.md) for the remaining gates;
do not run its ceremonies as agent steps.

## Custody and activation limits

The daemon constructs `lease.New` with `owner.Stopped{}` in
[main_linux.go](../../../../cmd/swarma-credential-broker/main_linux.go).
[Stopped](../../../../internal/owner/owner.go) returns `owner_unavailable` state
from both `Snapshot` and `Refresh`; the existence of internal owner machinery
does not wire a production owner. Neither source availability nor a qualification
reference activates issuance. Legacy worker leases expose real external tokens;
they are not the proposed placeholder mode.

The [broker specification](../../../../spec/broker.md) and
[README](../../../../README.md) describe operator/device keys, grants, enrollment
and signing as broader design/custody requirements. This command dispatch does
not implement an enrollment or signing subcommand. Do not invent one or translate
phone-key, root-key or terminal fallback designs into agent instructions.
[Secret-free mode](../../../../spec/secret-free-mode.md),
[gateway](../../../../spec/secret-free-gateway.md) and
[adapter profiles](../../../../spec/secret-free-adapters.md) are inactive designs,
not a plugin API, newly admitted configuration or live service capability.

For a requested live operation, keep the decision and every custody/signing act
OWNER-SITTING. Agent preparation can supply a source explanation with synthetic
inputs, fixed refusal codes and unresolved gates; it supplies no secret payload,
key handling recipe, installation, qualification or authority to proceed.
