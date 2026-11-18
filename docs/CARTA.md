# Carta captures: synthetic and live, held by the application

[`pf.Carta`](../sdk/contracts/Carta.roc) hands a complete issuer capture to the
application, which holds it in its own database until it releases it:

```roc
Carta.deliver : Context -> Observe(Carta.Delivery)
Carta.read : Context, Str, U64, U64 -> Observe(Carta.Records)
Carta.release : Context, Str -> Observe({ released : Bool })
```

`deliver(context)` (`carta.snapshot.v2`) collects or selects one complete
capture and returns its `id`, `issuer_id`, record and per-kind counts, and
explicit `source_profile`: `"synthetic"` for a seeded capture, or
`"carta_production"`, `"carta_playground"` or `"carta_simulated"` for a live
capture. Counts include every source record, including duplicates.
`read(context, delivery.id, from, limit)` (`carta.records.v2`) returns up to
`limit` (1–256) records starting at record `from`, with `next` and `done`;
reading at the record count answers no records and `done`. Keep a single record
cursor and advance it by the records actually applied. `release`
(`carta.release.v2`) deletes a held copy no later read needs. Like delivery, it
runs while preparing, so a reader releases finished captures before it holds a
new one; it is idempotent. Larger cursors, unknown captures and
captures held under another grant fail.

The `carta` provider has two sources, chosen by the bound resource's
connection. A connection without `live` reads **an explicitly seeded local
synthetic provider**: no HTTP calls, no credentials, no live company data. An
ordinary unconfigured runtime fails with `carta_unconfigured`; it never
fabricates an empty or demonstration portfolio. A connection with a live
`carta` profile makes `deliver` perform one complete, bounded collection of the
issuer before returning; see [Live captures](#live-captures). The application
contract is identical for both sources.

## Records and responsibilities

`Carta.Record` is `Stakeholder`, `Grant`, `VestingEvent` or `Exercise`. Each tag
contains its corresponding typed record. Grant headers omit their nested
arrays; vesting events and exercises retain the grant's external ID and travel
individually. Dates, quantities and amounts remain exact provider strings.
Optional strings preserve missing versus present-but-empty values.

The transport preserves every field in the inspected source DTOs, including
stakeholder relationship, optional address country and vesting schedule modification
date. It preserves duplicates and input order. It does not decide whether a record
is new, valid for a business import, owned by an employee, or ready for publication.
Those decisions, local IDs, progress checkpoints and calculations belong to the app.

Each encoded record is limited to 12,288 bytes. A capture contains at most 10,000
records and 32 MiB of encoded feed data. These limits fail explicitly before the
capture is held; there is no truncation. A read never crosses a held page of at
most 256 records and 56 KiB once journaled, so every answer fits one
observation. Runtime scope participates in the content-addressed capture
identity, and every provider lookup includes that scope.

## Holding, reading and releasing

A delivered capture is held in the application's own database
(`day2_capture_deliveries`, see [provider capture delivery](PROVIDER-CAPTURE-DELIVERY.md)).
Nothing expires it: it stays until the application releases it. At most two
unreleased captures are held per grant authority; a third delivery fails with
`capture_delivery_release_required` and never discards one the application
still holds. All held captures in one application database are capped at
128 MiB (`capture_delivery_capacity`). An unchanged recapture has the same
identity and returns the capture already held.

A held capture is bound to everything its grant names: the runtime scope, the
connection authority (a digest of the reviewed connection ID and revision, its
environment, OAuth `client_id` and client secret reference), issuer,
child-record mode and source profile; a synthetic capture is bound to the
scope and issuer. A read or release under any other grant, including another
connection revision, OAuth client, credential or environment, or a simulated
production connection reading a simulated playground capture, gets
`capture_delivery_authority_changed`.

`carta.snapshot.v2`, `carta.records.v2` and `carta.release.v2` are observations
in the operation's grants. The SDK binds
the context's typed Carta resource; the `_with` variants accept that admitted
resource directly. Host authorization supplies the runtime scope and selected
issuer; callers cannot substitute them in the payload. Existing actor,
operation, phase, resource-policy and current-authority checks apply.

Held captures live in the application database, so native backups copy them
with the application's own rows and a restore resumes an in-flight import from
the cursor it saved. Native backups also include the reviewed local provider
databases with individual digests and SQLite integrity checks: the synthetic
Carta captures and the local notification mailbox. Older backups lacking that
manifest field contain no provider backup. The managed rebuild pauses HTTP,
awaits its command scheduler, and synchronously drains work before taking a
checkpoint. Generic online backup provides an individual SQLite snapshot per
file, not an atomic snapshot across independently active stores or other
processes. The separate business-only `--backup` import mode intentionally
excludes provider state and authority.

## Live captures

A live connection names a reviewed OAuth client and a closed environment:

```json
{"provider":"carta","credential_ref":{"id":"carta-playground-secret","revision":1},
 "client_id":"PLAYGROUND_CLIENT_ID","environment":"playground","max_pages_per_collection":50}
```

`client_id` is an identifier (1–128 of `A-Z a-z 0-9 _ -`); only the client
secret is mounted, through the ordinary credential mount. `environment` is
`production` or `playground`, each selecting a fixed login/API origin pair in
the adapter; no URL is configurable. `max_pages_per_collection` is 1–100.
The resource target is `{"kind":"carta_issuer","issuer_id":"1234567"}` with an
optional `"children":"omit"`. A live issuer is 1–20 ASCII digits. `include`,
the default, is not serialized, so existing targets keep their exact bytes.
`omit` captures grants without their vesting events and exercises; those
arrays still count toward response bounds but are neither typed nor stored, and
their counts are zero. Omitting children is live-only: a synthetic capture is
seeded verbatim, so catalog validation rejects `omit` without a live connection.
Attenuation preserves both target fields.

`carta.snapshot.v2` on a live resource reserves the whole collection before
dispatch: `1 + 2 × max_pages_per_collection` calls against the grant's
`max_calls_per_invocation`, 64 KiB of aggregate request bytes, and an
aggregate response envelope of 16 KiB for the token plus 64 MiB of pages (each
with a one-byte oversize probe). The grant must allow at least 64 KiB per
request and 16 KiB per response; each page is bounded by the grant's
`max_response_bytes`, at most 4 MiB. The budget's physical connection is
`carta/<environment>/<client_id>`. Settlement is known and records the calls
and bytes actually sent and read, including for a failed collection. The
delivery itself is a small observation. `carta.records.v2` and
`carta.release.v2` are local to the held capture: they plan and settle zero
provider calls and no traffic, so they need no budget.

Collection exchanges the client credentials for one access token held in
memory for that capture only, then reads every stakeholders page and every
option grants page in order. A continuation token is URL-encoded; an absent,
null or empty `nextPageToken` ends a collection. A token the provider already
issued fails with `carta_pagination_invalid` instead of silently stopping, and
a token remaining after the page ceiling fails with `carta_page_budget` instead
of truncating. There are no automatic retries; a `Retry-After` is recorded in
correlation and never slept on.

Provider objects map to the SDK records field for field. Unknown provider
fields are ignored. Every mapped field is required with its exact type; a
missing or null required field fails the capture with `carta_response_invalid`.
Optional SDK text (`employee_id`, `group`, `address_country`,
`stakeholder_acceptance_date`, `vested_quantity`,
`fair_market_value_as_of_date`) is `None` when the field or its `{value}`
wrapper is absent or null, and `Some("")` when present but empty. Absent or
null page arrays and child arrays are empty. Records keep provider order: all
stakeholders, then each grant followed by its vesting events and exercises.
Duplicates are preserved; deduplication belongs to the application. A
stakeholder or grant whose `issuerId` differs from the target fails with
`carta_issuer_scope_mismatch`.

Failures are stable redacted codes: `carta_credential_unavailable`,
`carta_authentication_failed` (token 400/401, malformed or short-lived token,
API 401), `carta_scope_denied` (403, a granted scope missing a required one, or
an API 404 for the issuer), `carta_rate_limited` (429), `carta_unavailable`
(connection or read failure, 5xx, deadline), `carta_response_invalid`,
`carta_response_too_large`, `carta_request_budget`,
`carta_pagination_invalid`, `carta_page_budget`, the record, byte and capture
budgets above. A failure's final exchange is kept as
correlation: its phase, zero-based page, HTTP status and any `Retry-After`,
never a body, URL, header or token. As with synthetic reads, current preparation
journals the failed observation; retrying the same invocation replays the
failure and a new business attempt recaptures.

A live capture's identity is a digest of the runtime scope, connection
authority, environment, issuer, child-record mode, records, counts and source
profile, with no collection time, so an unchanged daily recapture through the
same connection is the same capture. The same records collected through
another connection, client or credential are a different capture.

Stakeholders and option grants are separate endpoints read in sequence. The
local capture is immutable; it is not an upstream point-in-time snapshot, and
Carta may change between the two collections.

Under a simulated provider host the live path reads the provider's wire world:
`SimulatedFixture.carta` holds a token body and verbatim stakeholder and option
grant pages in the Carta world store, beside any synthetic captures. The
simulated port runs the same DTO parser, pagination, token validation and status
classification as the native adapter, records each request, and consumes
scheduled faults per endpoint (`carta.oauth.access_token`,
`carta.issuers.stakeholders`, `carta.issuers.option_grants`). Its captures are
labelled `carta_simulated`. A simulated host never falls through to HTTP: the
source is frozen when the capability is authorized.

On a native host the adapter resolves the connection's mounted client secret
(`carta_credential_unavailable` when it is missing, retargeted or rotated),
exchanges it at the environment's fixed token endpoint with HTTP Basic and reads
the fixed issuer routes. Transport details, origins and the explicit
`xtask carta-qualify` command are in [live integrations](LIVE-INTEGRATIONS.md#carta-issuer-captures).
Loopback HTTP tests pin every request's method, path, query encoding, headers
and body, refuse redirects, bound reads and check that refusals never echo the
secret or token. The parity fixtures are reconstructions documented in
[CARTA-PROVENANCE](../crates/day2/fixtures/provider-responses/CARTA-PROVENANCE.md)
until a redacted playground recording replaces them.

## Native setup and verification

[`carta::seed_synthetic`](../crates/day2/src/carta.rs) installs an explicit
`SyntheticSnapshot` into the separate `carta.synthetic.sqlite` provider store.
An identical capture is idempotent. A different capture gets a different identity
and becomes the one `carta.snapshot.v2` delivers, without rewriting old snapshots. This is a native operator
and test setup API, never an application operation or an ordinary runtime default.

Disposable `development::Campaign` verification explicitly provides shared
synthetic provider models. Its Carta setup runs only when that runtime scope has
no selected capture, preserving custom worlds seeded by independent tests.
`carta::synthetic_example()` contains eight records: two synthetic stakeholders,
two grants and one vesting event and exercise per grant. Its issuer is
`9000` (`carta::SYNTHETIC_ISSUER`); holders are `9001` (alice) and `9002` (bob), with
the reserved example addresses `alice@example.test` and `bob@example.test`. The IDs
are numeric like live Carta IDs, so an app that validates issuer and stakeholder IDs
can configure and assign them. The shared provider
does not map a verification actor to either employee; the application must do so.

## Remaining qualification

Live provider qualification is an open evidence gap. The parity fixtures are
reconstructed from the earlier Equity client's DTOs, not recorded from Carta,
and every `carta-qualify` receipt reports `provider_qualified: false`; neither
establishes that the adapter works against Carta. Only a credentialed
playground run, reviewed afterwards, can settle the required scopes, the
playground API origin, end-of-pagination behaviour, whether a page size can be
requested, and which fields Carta omits or nulls. None of this requires an
extra application operation kind.
