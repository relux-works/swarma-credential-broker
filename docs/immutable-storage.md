# Inactive immutable storage fixture

`internal/freshstore` is an internal Linux fixture algorithm. No daemon,
runner, configuration or production owner imports it. Caller-supplied limits,
installation identifiers and hashes grant no authority. Production activation,
current-root selection, compare-and-swap, reclamation and restore reconciliation
remain separate work.

`NewFixture(account, limits)` validates an already initialized dedicated account;
it never creates missing history. `Retain(binding, inputs)` stores a nonempty,
strictly ordered immutable unit. `ReadExact(expected)` requires the complete
independent ordered inventory and binding, and returns raw byte copies only
when every selected record matches. Failures return `ErrInvalid`, `ErrLimit`,
`ErrConflict` or `ErrUnavailable`, without partial read output. A successful
retention is content storage, not current-generation publication.

The closed `freshstore/1` grammar fixes JSON field order and spelling, decimal
positive integers, padded canonical base64 and exact EOF. Identifiers use
lowercase ASCII letters, digits, dots and hyphens, starting with a letter or
digit, at most 64 bytes. Digests are lowercase SHA-256 of exact encoded or raw
bytes as specified by each field. No normalization occurs. A binding carries
installation, scope, pin and an explicit predecessor: `g:` plus 64 hex digits
for a caller-supplied genesis commitment, or `m:` plus the retained predecessor
manifest digest. A retained predecessor must match installation, scope and pin;
this check does not prove a recursive history or current authority.

All nine `Limits` fields are required and positive. `RecordBytes` is inclusive
and at most 1 MiB of the entire encoded record, including metadata and base64.
`RetainedBytes` and `RetainedRecords` include account controls, retained partials,
recognized pending files and zero-byte files. `UnitBytes`, `Dependencies` and
`RawObjectBytes` bound the proposed unit. `ReadBytes` bounds selected actual
encoded bytes plus a fixed 512-byte allowance for two identity documents, each
checked to be at most 256 bytes before reading. Missing or unsafe controls
refuse; no generic unbounded metadata parser is called by this path.

`MemoryBytes` and `WorkBytes` admit logical buffer/work estimates before
payload encoding, reading or decoding. With U proposed encoded bytes, Q selected
read bytes including controls, V raw bytes, K dependencies, and conservative
ceilings C=`RetainedRecords`, T=`RetainedBytes`, the checked formulas are:

```
Mem  = 4*(U+Q) + 4*V + 512*(C+K+4) + 4096
Work = 8*(T+U+Q+V) + 1024*(C+K+4)
```

Read measurement uses a bounded metadata census. It admits these costs before
reading payloads and caps the subsequent locked read to the admitted byte
count, so changed file sizes cannot expand the allocation. These formulas are
logical bounds, not qualified heap, RSS or latency guarantees. Fixture tests
use at most 64 MiB and 128 MiB respectively. Counts are capped at 4096,
dependencies at 256 and other scalar ceilings at 2^40; all size arithmetic and
integer conversions are checked. There are no zero-as-unlimited defaults.

The new `store.Account` primitives validate protected descriptor roots and
single-link regular records. `AppendImmutableBounded` holds the account
exclusion through a fresh bounded census, complete-unit quota/name/digest
admission and exclusive creates. It never overwrites existing immutable names.
The manifest is the last new file. Each file and containing directory is
synced; this fixture does not qualify physical crash or rollback behavior.
Input and capacity refusal creates no files. I/O failure can leave charged
partials; a lost acknowledgement after complete writes is uncertain and cannot
be interpreted as confirmed absence. No cleanup or space refund occurs.

## Focused validation

Select Go 1.26.10 with `CURATOR_GO`, preserve the configured caches, and set an
isolated absolute `TMPDIR` outside the checkout. Run through the host's admitted
resource scheduler when required. These commands use only synthetic fixtures:

```bash
GOTOOLCHAIN=local GOMAXPROCS=2 GO="$CURATOR_GO" SWARMA_TEST_UNPRIVILEGED=1 "$CURATOR_GO" test -p=2 ./internal/freshstore ./internal/store -run '^(TestFresh|TestImmutable|TestOversizedWriteRegression|TestRecordSizeBoundary|TestRecordEncodingOnce|TestInitialRecordSizeRefusal)' -count=1 -v
GOTOOLCHAIN=local GOMAXPROCS=2 "$CURATOR_GO" build -p=2 ./internal/freshstore ./internal/store
"${CURATOR_GO%/go}/gofmt" -l internal/freshstore internal/store/immutable_linux.go internal/store/immutable_linux_test.go
```

Keep full validation logs and any isolated Go-overlay mutation controls outside
versioned source. Tests cover literal identities, parser-reaching malformed
content, finite boundaries, exact inventory, link refusal, deterministic account
replacement, concurrent cooperating admission and charged I/O failures. They do
not qualify mount changes, case-folding filesystems, hostile timed replacements,
physical durability, a real provider or production activation.
