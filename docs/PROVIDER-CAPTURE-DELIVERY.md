# Provider capture delivery

Everything about an application lives in its own database. A provider capture
is handed to the reading application, which persists what it keeps in its own
models and owns that retention. The host does not keep provider data for an
application in a sibling store with a platform-chosen expiry.

Status: both paths are implemented beside the unchanged v1 capabilities.
Workspace Directory (`workspace_directory.hierarchy.v2`, `page.v2`) uses an
invocation-held delivery. Carta (`carta.snapshot.v2`, `records.v2`,
`release.v2`) uses an application-held delivery, the option chosen in
[Carta](#carta-application-held-delivery).

## What this replaces

| Store | Contents | Retention today | Problem |
| --- | --- | --- | --- |
| `workspace_directory.sqlite` | Org-unit hierarchy and membership captures | `SOURCE_TTL_SECONDS = 900`; expired rows are deleted on the next publish | Not in backups. An app keeps only a capture id, so a pointer older than 15 minutes, or any pointer after a restore, dangles. |
| `carta.sqlite` | Full live issuer captures | The two newest selections per connection and issuer | Excluded from backups. Equity holds `capture_id + cursor` across about one invocation per record, so two newer captures published mid-import delete its snapshot. |
| `notifications.sqlite` | Local mailbox world | Never pruned; one JSON blob capped at 4 MiB, after which every send fails | Unused by apps today. See [Notifications](#notifications). |

## Budgets that shape the design

One invocation allows 32 preparation observations, 64 interpreter steps, and
64 KiB per journaled observation, including JSON escaping and the instruction.
Every observation is a step. `Tx.create_many` writes up to 256 rows as one step
(and at most 64 KiB of encoded rows).

So one invocation can carry about 31 observations of up to about 60 KiB each,
and write each of them with one `create_many`: about 31 × 256 = 7,936 rows,
62 steps. A capture larger than that cannot reach application tables in one
invocation without either something that outlives the invocation or a host
write that bypasses the step budget. That is the fork described below.

| Capture | Provider bound | Fits one invocation? |
| --- | --- | --- |
| Directory hierarchy | 10,000 units, 4 MiB, one provider response | Up to 31 pages: about 7,900 typical units. Home's own bound is 256. |
| Carta issuer | 10,000 records, 32 MiB encoded (128 MiB store) | Only small issuers: 32 MiB needs at least 546 pages of 60 KiB. |

## Workspace Directory: invocation-held delivery

```
prepare (one invocation)
  hierarchy.v2 ──► provider port (native or simulated), complete validation
                   │  split into pages: ≤256 units, ≤56 KiB journaled, ≤31 pages
                   ▼
                 app.sqlite: day2_capture_deliveries  (one row per page, keyed by holder)
                   │  returns {id, customer_id, org_unit_count, page_count, captured_at}
  page.v2 ×N ───► read this invocation's page (no provider call)  ─► journaled observation
  Decide boundary ─► release this invocation's staged pages
decide (Tx)
  app writes units into its own models (one Tx.create_many per page), sets its own expiry
```

- **Collection**: `workspace_directory.hierarchy.v2` always reads the provider.
  It has no host cache and no TTL. It uses the same ports, OAuth scopes, call
  plan (4 direct / 5 delegated), byte reservation and validation as the v1
  hierarchy cold path, and settles the same known usage even when it fails.
- **Identity**: `id` is a digest of the customer, the connection
  (`id@revision`) and the validated units. It has no actor and no time, so an
  unchanged hierarchy delivers the same `id`. An app that stored the last
  synced `id` can stop after one observation.
- **Staging**: pages are written to one `day2_capture_deliveries` host table in
  the app's own database, one row per page, keyed by holder. See
  [Schema and restore](#schema-and-restore) for why it is one object. Staging first sweeps
  deliveries whose invocation is finished, unknown, or permanently blocked by
  an authority change. All staged pages in one database are capped at 64 MiB
  (`capture_delivery_capacity`).
- **Reading**: `workspace_directory.page.v2 {capture_id, page}` is a local read.
  It reserves no calls or bytes. It answers only for the invocation that staged
  the capture, and only while the current grant's (customer, connection
  revision, actor) equals the staged authority. Every read is reauthorized as an
  ordinary observation.
- **Release**: when preparation reaches its decision boundary or fails, the host
  deletes that invocation's staged pages. This write happens only if the
  invocation staged something. A crash between those points leaves rows that
  the next staging sweeps. Nothing staged outlives the invocation.
- **Persistence and retention**: the app persists what it keeps in its own
  models in the decision transaction. Expiry, refresh cadence and history are
  app decisions. Because the platform has no hard delete, an app that replaces
  a snapshot soft-deletes rows; physical removal stays operator retention.

### Failure semantics

| Situation | Result |
| --- | --- |
| Provider error, invalid or incomplete hierarchy | The v1 error codes (`workspace_directory_hierarchy_lookup_failed`, …). Nothing is staged; usage settles. |
| More than 31 pages | `workspace_directory_delivery_exceeds_invocation` at delivery time. Nothing is staged. |
| Page from another invocation, after release, or never staged | `capture_delivery_unavailable` |
| Grant's connection revision, customer or actor changed | `capture_delivery_authority_changed` (the resource check usually refuses first) |
| Page index ≥ `page_count` | `capture_delivery_page_invalid` |
| Buffer cap reached | `capture_delivery_capacity` |
| Crash after delivery, before all pages are journaled | The buffer is durable in the app DB, so resumed preparation keeps reading pages. |
| Crash after the decision boundary | Replay uses the journaled pages and never reads the buffer. |

A recorded preparation error is terminal for that invocation identity, as
today. A fresh business attempt delivers again.

### Verification and simulation

- The simulated provider host uses the same `SimulatedDirectoryPort`, the same
  fault schedule and the same request log. A delivery never falls through to
  HTTP.
- Pages are ordinary journaled observations, so replay is deterministic and
  never reads the buffer. The content identity has no clock or actor, so
  identical worlds produce identical journals.
- Declare `.observes("workspace_directory.hierarchy.v2").observes("workspace_directory.page.v2")`.
  Disposable verification derives the synthetic Directory bindings for both,
  as it does for v1.
- The simulated Directory world is itself decoded under the 1 MiB / 20,000-node
  transport bound (pre-existing), so a campaign can model roughly 2,500 units,
  not the 31-page ceiling. The page bound is tested through the same collection
  pipeline with a fixture port.
- A delivery spends 4 (direct) or 5 (delegated) of the grant's
  `max_calls_per_invocation`, as v1 does, so a second delivery in the same
  invocation is refused with `resource_limit_exceeded`. Pages cost no calls.
- Backups copy `app.sqlite`, so a restore carries both the app's persisted
  hierarchy and any in-flight invocation's staged pages. No separate provider
  database is involved.

### SDK

```roc
WorkspaceDirectory.deliver_hierarchy : Context -> Observe(HierarchyDelivery)
WorkspaceDirectory.deliver_hierarchy_with : Resource -> Observe(HierarchyDelivery)
WorkspaceDirectory.delivery_page_with : Resource, Str, U64 -> Observe(DeliveryPage)
# HierarchyDelivery : { id, customer_id, org_unit_count, page_count, captured_at }
# DeliveryPage      : { items : List(OrgUnit), page : U64, done : Bool }
```

`WorkspaceDirectory.roc` is sealed. Its admission pin was refreshed after
reviewing the added surface: two capability names, two decoders, and no new
host authority.

## Schema and restore

`day2_capture_deliveries` is one ordinary rowid table: no primary key, no
autoindex, no foreign key and no trigger. Two restore constraints require this:

- Security admission charges every `sqlite_master` object on each full-schema
  scan, under the fixed `ADMISSION_ROWS` budget (16,384) in `oauth/schema.rs`.
- Restore snapshots read every table `ORDER BY rowid`, so `WITHOUT ROWID` is
  not an option.

Measured against the `restore_staging` suite: the restore fixture has 3 objects
of headroom over `bd96d438`. A 4th extra object fails 19 tests. This table uses
1, and the trace-policy table on `journal-trace-policy-dedupe` uses 1. The first
version of this change (two tables with composite keys plus two no-update
triggers, about 6 objects) would have exceeded it.

What the schema no longer enforces, code does, inside the same write
transaction or on every read:

| Was | Now |
| --- | --- |
| Primary keys `(holder,id)` and `(holder,id,page)` | Staging deletes or refuses an existing `(holder,id)` before inserting. Every read groups the capture's rows and requires one header, `count = page_count`, distinct pages, and pages `0..page_count`; otherwise `capture_delivery_inconsistent`. |
| Foreign key from pages to header | Every row repeats the header; the same read check refuses rows that disagree. |
| `BEFORE UPDATE` triggers | No statement updates a row. An out-of-band edit that breaks consistency is refused on read. A consistent rewrite of every row (for example, changing the authority) is caught as an authority mismatch, as before. |

The triggers never stopped a writer with database access, who could drop them,
so they did not add tamper resistance against such a writer. What remains is
consistency checking, now in code. The restore fixture installs this table as
ordinary initialization does, so `restore_staging` charges it from now on.

## Home migration

Home's `HierarchyRead.read` already captures and pages within one invocation.
The daily sync that another thread is adding should switch from
`capture_hierarchy_with` + `page_with` to the following:

1. In `prepare`, call `deliver_hierarchy_with(resource)`. If `delivery.id`
   equals the id Home last persisted, return `Unchanged`. Otherwise read pages
   `0 .. page_count` with `delivery_page_with` and keep Home's 256-unit bound.
2. In `decide`, upsert units into Home's own org-unit table and soft-delete
   removed units. Record `delivery.id` and `captured_at`. Home decides how old
   a hierarchy may be.
3. Remove `read_saved`, which pages a host capture by a saved pointer. Read
   Home's own table instead. Restores then stay consistent because there are no
   host pointers.
4. Declare the two v2 observations. Operators add the two v2 actions to Home's
   Directory policy slot; v2 needs the same response limit and call allowance as
   the v1 hierarchy.

## Carta: application-held delivery

Equity imports one record per invocation and keeps `capture_id + cursor` across
up to 10,000 invocations. A Carta capture (up to 32 MiB encoded) cannot cross
into Equity's tables within one invocation's budget. So "a transient buffer
that never outlives the invocation" and "the app receives the whole capture"
cannot both hold for Carta under the current budgets. The options were:

- **A. App-held delivery (chosen).** The same tables, held for the app instead
  of one invocation, until the app releases the capture.
- **B. Re-collect per invocation.** Infeasible for Carta: one collection is up
  to 101 calls and 64 MiB, repeated for every slice.
- **C. Host bulk ingest into app-declared models.** One invocation and no host
  table, but a new sealed `Tx` primitive, Rust-side encoding of app rows, and
  10,000-row writes and verification snapshots. Still the long-term option if
  captures should become app models with no host table at all.
- **D. Larger budgets for capture reads.** Rejected: it weakens a global
  invariant for one feature.

### How A works

- **Holder**: `day2_capture_deliveries.holder` is the invocation id for
  Directory and empty for an application-held capture. The sweep only ever
  touches invocation-held rows.
- **`carta.snapshot.v2`** (observation): collects exactly as v1 does. A live
  connection uses the same plan, token, pagination, bounds, failure codes and
  metered settlement; a connection without `live` uses the seeded synthetic
  capture. It stages the typed records in pages of at most 256 records and
  56 KiB journaled, and returns `Delivery` (v1's snapshot facts plus
  `page_count`). Nothing is published to `carta.sqlite`.
- **Identity**: `id` is the v1 capture identity (`carta_<sha256>`): scope,
  connection authority, environment, issuer, child mode, records, counts and
  source, with no time. An unchanged recapture of a held capture returns the
  same `id` and stores nothing new.
- **Authority**: a held capture is bound to the runtime scope, connection
  authority (connection id and revision, environment, OAuth client and
  credential reference), issuer, child-record mode and source profile. A
  synthetic capture is bound to the scope and issuer. Any other grant, including
  another connection revision or a live binding reading a synthetic capture, gets
  `capture_delivery_authority_changed`.
- **`carta.records.v2 {capture_id, from, limit}`** (observation): a local read
  with no calls or bytes of up to `limit` (1–256) records starting at record
  `from`, never crossing a staged page. Any invocation of the app can read while
  the authority matches. An importer keeps one record cursor, so no app model
  needs page bookkeeping (an installed app can only add optional text fields).
  Records use SDK tags:
  `{"records":[{"Stakeholder":{...}},{"Grant":{...}},…],"next":3,"done":true}`.
- **`carta.release.v2 {capture_id}`** (observation): deletes the app's held copy
  and returns `{"released": bool}`. Like delivery, it changes only host-held
  capture rows, never an app row or provider data, so it is a preparation step:
  a reader releases what no later read needs before it holds a new capture. It
  is idempotent, so re-preparation is safe.
- **Bounds**: at most two unreleased captures per authority. A third snapshot
  fails with `capture_delivery_release_required` and discards nothing. All held
  captures in one app database are capped at 128 MiB
  (`capture_delivery_capacity`), the old `carta.sqlite` bound.
- **Backup and restore**: held pages live in `app.sqlite`, so they are copied
  and restored together with Equity's cursor. A restore cannot strand an import.

### Equity migration

As implemented on Equity's `carta-delivery-v2` branch:

- While preparing, `capture_import` releases the held captures of the
  catalog's finished runs, newest first and at most sixteen, then calls
  `Carta.deliver_with`; its run fields keep their meaning. A capture an earlier
  preparation kept belonged to a run then in flight, which is newer than every
  run released before it. Capture identity is content, so a capture that a
  pending or importing run of the catalog records is kept.
- `advance_import` reads up to eight records from its cursor with `Carta.read`
  and stages them in one transaction, carrying the run's counters in memory and
  saving them once. Eight records at no more than five steps each, plus the
  reads and the continuation, stay inside the 64-step budget. A rejected record
  saves the progress made before it and then fails the run, so pruning stays
  accounted.
- Operators grant `carta_snapshot_delivery` and `carta_release` to
  `capture_import`, and `carta_records` to `advance_import`, all as
  observations.
- Verification campaigns use the synthetic seed through `snapshot.v2`, and
  disposable verification grants the v2 actions from the declarations.

## Notifications

`notifications.sqlite` is the local mailbox provider itself, not a capture held
for an app. Delivery does not apply to it. The app-relevant facts (message id,
accepted status) already return as effect results journaled in the app database,
and an app persists the receipts it needs. Using `notifications.latest.v1` to
recover them should become unnecessary. The store's defects are provider-side:
one unbounded JSON row and a hard 4 MiB failure. The fix is per-message rows
with operator-owned, per-scope bounded retention, the same model as any external
provider's history. This is not implemented.

## Deprecation path (proposed, not executed)

1. Ship v2 beside v1. This change does that.
2. Migrate Home (Directory v2) and Equity (Carta v2) as described above.
3. Remove `workspace_directory.capture.v1` / `hierarchy.v1` / `page.v1` and
   `carta.snapshot.v1` / `record.v1`, with `workspace_directory.sqlite`,
   `carta.sqlite` and their sweep/prune code. `user_path.v1` stores nothing and
   stays. Keep the synthetic seed store; it is the synthetic provider, not an app
   capture. No data migration: under AGENTS.md the stores are disposable caches,
   and app tables now hold what matters.
4. Drop `SOURCE_TTL_SECONDS` and the Directory cache plan.

## Implementation map

- [`capture_delivery.rs`](../crates/day2/src/capture_delivery.rs): holders,
  staging, page reads, release, sweep and bounds.
- [`workspace_directory.rs`](../crates/day2/src/workspace_directory.rs):
  `deliver_hierarchy` and `delivery_pages`.
- [`carta.rs`](../crates/day2/src/carta.rs): `Delivery`, tagged page encoding,
  `delivery_pages`, and the synthetic capture reader.
  [`carta_live.rs`](../crates/day2/src/carta_live.rs): typed records on a
  complete capture, and the delivery authority.
- [`capabilities.rs`](../crates/day2/src/capabilities.rs): authorization, quotes,
  observe, execute and usage for all five v2 capabilities.
- [`preparation.rs`](../crates/day2/src/preparation.rs): release of
  invocation-held deliveries at the decision boundary or on failure.
- SDK: `WorkspaceDirectory.roc` and `Carta.roc` (both sealed; pins refreshed).
- Registry actions, disposable-verification bindings and coverage
  demonstrations (`HeldCaptureRelease` for the release).
- Tests:
  - `capture_delivery::tests`: bounds, isolation, sweep, app holder, cap and
    release.
  - `store::capture_delivery_host_tests`: admitted Directory path.
  - `integrations::coverage_tests::carta`: admitted Carta v2 path: live
    simulated wire, synthetic seed, authority refusals, cap, release.
  - `tests/app_contract.rs`: native Roc decode tests for both SDKs.
