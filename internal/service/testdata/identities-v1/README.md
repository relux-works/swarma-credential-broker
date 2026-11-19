# Managed identity v1 compatibility fixtures

Copy the compatibility files in this directory unchanged into broker
`internal/service/testdata/identities-v1/`. `SHA256SUMS` seals every fixture,
`journal.jsonl` and the canonical `cases.json` verdict manifest; this explanatory
README is not part of the byte contract.

`journal.jsonl` is the published two-record active journal vector. The manifest's
head is the SHA-256 of its final record including LF, not of the entire file.
`valid.json` and `valid-mixed.json` are bare canonical CCJ-1 with no final newline
and are compared to the producer's actual atomic write. Mixed projection rows
are synthetic inputs at the shared head, not a claim that the two-record journal
contains their full lifecycle history.

Manifest checks:

- `decode`: apply the named accept/refusal verdict to the document, including
  empty accounts, duplicate generations and scalar-boundary controls.
- `service`: require successful decoding, then resolve the row's `uid` and
  `generation` as an active, trusted, local service. Absent row coordinates use
  the manifest header; coordinates on other check kinds do not trigger lookup.
  `valid-mixed` accepts the active service beside an agent and a retired
  same-name service with distinct UIDs/generations; lookups of those neighbors
  refuse. `duplicate-name` instead has two active services and refuses decoding.
- `transition`: require both documents to decode, then compare with `previous`.
  Same-kind retirement accepts; a retained UID's kind change refuses. This is
  a pairwise check, not durable history across an intervening empty document.
- `custody`: use the valid bytes, but apply `condition` before opening
  `identities.json`. Missing-file means leave the file absent; unreadable-file
  means mode 0000 (unprivileged fixture read), wrong-mode means 0600. Wrong-owner
  and wrong-group use a mismatching expected fixture UID/GID, while production
  always requires 0:0. Symlink, hardlink and not-regular apply those filesystem
  shapes. Refusal returns `principal_ledger_mismatch` without changing bytes.

The manager runs all rows via `TestSharedFixtures`, `TestSharedCustodyFixtures`
and `TestProjectionSharedProducerBytes`; `TestSharedFixtureChecksums` verifies
both digest equality and complete fixture coverage. These are source/contract
tests, not proof of an installed broker provider or host qualification.

```sh
sha256sum -c SHA256SUMS
GOMAXPROCS=2 go test ../../internal/identities -count=1
```
