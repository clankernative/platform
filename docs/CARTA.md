# Carta reads and the synthetic provider

[`pf.Carta`](../sdk/contracts/Carta.roc) exposes two typed read operations:

```roc
Carta.begin : {} -> Observe(Carta.Snapshot)
Carta.next : Str, U64 -> Observe(Carta.ReadResult)
```

`begin({})` returns `{id, issuer_id}` for the runtime's selected capture.
`next(snapshot.id, 0)` reads its first record. Increment the ordinal only after
successfully applying that record; `Done` occurs exactly at the record count.
Larger cursors, unknown snapshots and snapshots belonging to another runtime
scope fail. Selecting a newer capture preserves previously issued identities.

The current native adapter is **an explicitly seeded local synthetic provider**.
It makes no Carta HTTP calls, resolves no credentials and does not import live
company data. An ordinary unconfigured runtime fails with `carta_unconfigured`;
it never fabricates an empty or demonstration portfolio.

## Records and responsibilities

`ReadResult` is `Stakeholder`, `Grant`, `VestingEvent`, `Exercise`, or `Done`.
Each data tag contains its corresponding typed record. Grant headers omit their
nested arrays; vesting events and exercises retain the grant's external ID and
travel individually. Large nested arrays therefore do not require a single
large observation. Dates, quantities and amounts remain exact provider strings.
Optional strings preserve missing versus present-but-empty values.

The transport preserves every field in the inspected source DTOs, including
stakeholder relationship, optional address country and vesting schedule modification
date. It preserves duplicates and input order. It does not decide whether a record
is new, valid for a business import, owned by an employee, or ready for publication.
Those decisions, local IDs, progress checkpoints and calculations belong to the app.

Each encoded record is limited to 12,288 bytes. A capture contains at most 10,000
records and 32 MiB of encoded feed data. These limits fail explicitly before
publication; there is no truncation. They keep each nested observation envelope
within the command runtime's 64 KiB bound. Runtime scope participates in the
content-addressed capture identity, and every provider lookup includes that scope.
Snapshots and record rows reject update, delete and replacement insert.

The capability names are `carta.snapshot.v1` and `carta.record.v1`, both in the
operation's observation grants. There is no Carta application write capability.
Host authorization supplies the runtime scope; callers cannot substitute it in
the payload. Existing actor, operation, phase and current-authority checks apply.
These flat grants permit an admitted operation to read that runtime's captures;
the broader typed resource and connection design remains proposed.

Native backups include the reviewed local provider databases with individual
digests and SQLite integrity checks; restore retains the Carta captures and the
local notification mailbox. Older backups lacking this manifest field contain no
provider backup. The managed rebuild pauses HTTP, awaits its command scheduler,
and synchronously drains work before taking a checkpoint. A successful paused
checkpoint therefore includes its managed provider state. Generic online backup
provides an individual SQLite snapshot per file, not an atomic snapshot across
independently active stores or other processes. The separate business-only
`--backup` import mode intentionally excludes provider state and authority.

## Native setup and verification

[`carta::seed_synthetic`](../crates/day2/src/carta.rs) installs an explicit
`SyntheticSnapshot` into the separate `carta.synthetic.sqlite` provider store.
An identical capture is idempotent. A different capture gets a different identity
and becomes current without rewriting old snapshots. This is a native operator
and test setup API, never an application operation or an ordinary runtime default.

Disposable `development::Campaign` verification explicitly provides shared
synthetic provider models. Its Carta setup runs only when that runtime scope has
no selected capture, preserving custom worlds seeded by independent tests.
`carta::synthetic_example()` contains eight records: two synthetic stakeholders,
two grants and one vesting event and exercise per grant. Its issuer is
`synthetic-issuer-1`; holders are `holder-alice` and `holder-bob`, with the reserved
example addresses `alice@example.test` and `bob@example.test`. The shared provider
does not map a verification actor to either employee; the application must do so.

`carta::fail_reads` installs a finite host-only failure schedule for one snapshot
ordinal. Failures have the typed `SyntheticFailure::Unavailable` category and
stable `carta_unavailable` code. Current preparation semantics journal an adapter
error as a terminal failed observation. Retrying that invocation identity replays
its failure; a fresh business attempt can resume the saved import cursor. No
automatic provider retry, backoff or `Retry-After` support is claimed here.

## A live adapter still requires implementation

A real Carta adapter must add operator-owned credentials, narrowly scoped issuer
bindings, OAuth refresh, bounded HTTP pagination and a stable capture implementation.
It must define repeated page-token handling, provider changes while collecting a
capture, error classification and retry scheduling, retention and conformance.
The inspected Carta API usage does not establish a cross-endpoint point-in-time
snapshot guarantee. A local immutable capture must not be described as that
upstream guarantee. None of this requires an extra application operation kind.
