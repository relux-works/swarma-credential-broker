# Claude secret-free custody preparation

This is an **inactive, partial source delivery**. The owner selects secret-free
Claude subscription use: material may reach only the gateway service principal;
a worker receives `ANTHROPIC_BASE_URL` and a nonsecret placeholder. No production
entry, service identity, lease, delivery channel or harness is activated here.

The book's `book/ru/09-uchetnye-dannye.md`, sections "Режим без секретов у агента"
and "Растяжка утечки", is the architecture reference. Custody and account hold
remain the same as [mode §§2,10](../spec/secret-free-mode.md),
[gateway §7](../spec/secret-free-gateway.md#7-leak-tripwire-and-account-containment)
and [adapters §3](../spec/secret-free-adapters.md#3-broker-side-lifecycle).
No replacement book rule or service protocol is proposed.

## Stopped contract points

[Broker §5.2](../spec/broker.md#52-kinds) and
[§8.4](../spec/broker.md#84-delivery-channels) prescribe real Claude token
delivery to a worker environment. That path is stopped under the owner override.
This change does not add Claude to the legacy Codex-only static lease policy.

[Mode §13](../spec/secret-free-mode.md#13-publication-and-activation-gates),
[gateway §10](../spec/secret-free-gateway.md#10-qualification-and-publication)
and [adapters §7](../spec/secret-free-adapters.md#7-publication-and-qualification)
leave the service-principal/binding/lease dialect, protected material channel
and narrowly authenticated account-hold trigger unpublished. A protected IPC
requirement is not a concrete socket method, descriptor format or enrollment
command. A static UID, caller-selected service role or test double cannot fill
that gap. No such channel is implemented here. An approved successor contract
must specify these before gateway lease work can resume.

## Broker-only primitives

`internal/claude.NewAccount` wraps a dedicated, already protected
`store.Account`. A future authenticated operator entry must provide its correct
installation and account scope; construction grants no authority. `Enroll`
accepts fresh owner-supplied opaque token bytes, optional vendor-expiry evidence,
and writes no home, environment or launch file. It never runs `setup-token`,
reads a native login or refreshes material. This library has no material getter,
socket export or CLI integration. Existing operator custody requirements remain.

The private `owner-claude-material.json` record stores material under the
existing broker UID, 0700 directory, 0600 regular-file, no-link, lifetime-lock and
durable atomic-publication rules. The separate `owner-claude-account.json`
record contains only installation/revision, account/kind/mode, recorded state,
optional vendor expiry and `refreshable:false`. These are local persistence
records, not additions to the broker wire dialect. They use a dedicated account
directory, separate from legacy Codex owner/lease records.

`Status` selects only metadata using `store.Account.Read`, without opening the
material record or computing a token digest. `enrolled` means custody was
recorded, not live authority, material health, gateway readiness or vendor
acceptance. Unknown vendor expiry stays null. Status returns no token, secret
reference, token hash or raw filesystem error.

Enrollment commits immutable material before metadata. A duplicate cannot
replace material or clear a hold. An interrupted enrollment may retain a
protected orphan; missing metadata stays unavailable, and retries cannot adopt
or overwrite retained material. Offline operator reconciliation/re-enrollment
is not supplied. Go encoding may retain temporary copies; secure memory erasure
is not claimed.

`Hold` is only the internal persistence primitive for a whole-account hold. It
serializes metadata updates, flushes before every acknowledgment, is idempotent
in account state and survives reopening. Even an already observed hold is
republished, so a prior uncertain rename cannot become a false acknowledgment
through a fresh wrapper. It has no lease, launch or generation selector. A failed
write returns unavailable/UNKNOWN and closes that object; it never reports a
durable hold. Consumers must retain their local block and reconcile unknown
outcomes before recovery. This is not an authenticated detector RPC, final
lease-delivery gate, matcher, service-use closure, session stop, vendor
invalidation or owner alert. No hold-lift API is supplied: owner authentication
and independent recovery fences remain necessary. Possible leak alone never
authorizes vendor action.

## Worker environment primitive

`internal/claudeworker.NewProfile` constructs only an in-memory candidate from
nonsecret home/endpoint metadata. It accepts a numeric loopback endpoint with
an explicit port, creates fresh random nonsecret bytes and constructs exactly
`HOME`, fixed `PATH`/`LANG`, `ANTHROPIC_BASE_URL` and
`CLAUDE_CODE_OAUTH_TOKEN=<candidate placeholder>`. It never accepts vendor
material or inherits ambient environment. The subscription variable preserves
the selected auth-kind intent; no API billing substitution is claimed.

`ValidateEnvironment` is the final-composition tripwire: every key/value must
match that profile, including the exact placeholder. A replaced token, alternate
auth source, duplicate, extra or malformed entry refuses with fixed metadata.
A future executor must validate after all composition and before starting a
child. The Linux fixture inspects a real child's argv/environment and output;
the material-bearing negative candidate is never started.

The candidate prefix is internal nonsecret test metadata, **not a published
placeholder wire format or authenticated mapping**. There is no listener,
UID/generation/launch/account mapping or active launch command. A numeric local
URL is not routing enforcement or listener ownership. Exact Claude release,
placeholder acceptance, subscription billing, startup/background/child routes,
protected source/home/plan checks, kernel isolation and the final executor are
unqualified. This constructor cannot grant production launch admission.

## Validation

Use the task's private Go environment and absolute private `TMPDIR`/`GOTMPDIR`.
Run commands directly, capturing each exit code and log in task scratch:

```sh
gofmt -w internal/claude internal/claudeworker internal/store/read_linux_test.go internal/store/store_linux.go
go build ./...
go vet ./...
go test -p=1 -count=1 -timeout=20m ./...
go test -race -p=1 -count=1 -timeout=3m ./internal/claude ./internal/claudeworker ./internal/store
```

Fixture tokens have an explicit fake prefix. Tests use fixed diagnostics and
check metadata/errors/process output against the canary. Material is permitted
only inside the broker test's private store and memory. These are synthetic
custody/environment witnesses, not real service-principal, lease, leak-matcher,
kernel-account or vendor qualification. No real account or token is used.
