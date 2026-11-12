# Provider capture delivery

Everything about an application lives in its own database. A provider capture
is handed to the reading application, which persists what it keeps in its own
models and owns that retention. The host does not keep provider data for an
application in a sibling store with a platform-chosen expiry.

Status: the Workspace Directory path (`workspace_directory.hierarchy.v2` and
`workspace_directory.page.v2`) is implemented. Carta needs a decision first;
see [Carta: decision needed](#carta-decision-needed). The v1 capabilities are
unchanged.

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

## Delivery: the implemented design

```
prepare (one invocation)
  hierarchy.v2 ──► provider port (native or simulated), complete validation
                   │  split into pages: ≤256 units, ≤56 KiB journaled, ≤31 pages
                   ▼
                 app.sqlite: day2_capture_deliveries / _pages  (keyed by invocation)
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
- **Staging**: pages are written to two `day2_` host tables in the app's own
  database, keyed by invocation. Rows are immutable. Staging first sweeps
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

## Carta: decision needed

Equity imports one record per invocation and keeps `capture_id + cursor` across
up to 10,000 invocations. A Carta capture (up to 32 MiB encoded) cannot cross
into Equity's tables within one invocation's budget. So "a transient buffer
that never outlives the invocation" and "the app receives the whole capture"
cannot both hold for Carta under the current budgets. Something has to give:

**A. App-held delivery (recommended).** Use the same `day2_capture_deliveries`
tables, but the staged capture is held for the app rather than for one
invocation. `carta.snapshot.v2` stages the capture in the app's own database.
`carta.page.v2 {capture_id, page}` reads ≤256-record pages from any invocation
of the same app under the same connection authority and issuer.
`carta.release.v2` deletes it. A per-resource cap (for example, two unreleased
captures) makes a further snapshot fail with `carta_delivery_capacity`. It never
prunes silently. There is no platform expiry. The capture is backed up and
restored with Equity's cursor, so a restore cannot strand an import. Equity
goes from about one invocation per record to about one invocation per 31 pages
(around 7,900 records). Cost: the app database temporarily holds up to 32 MiB per
unreleased capture. The staged rows are host tables, not app models. Their
retention is app-controlled but not app-defined.

**B. Re-collect per invocation.** Hold nothing. Each invocation recollects the
issuer and reads a slice, and the app checks that `id` is unchanged. This is
infeasible for Carta: one collection is up to 101 calls and 64 MiB, repeated
for every slice. It is plausible only for Directory beyond 7,900 units.

**C. Host bulk ingest into app-declared models.** A new sealed `Tx` primitive
writes a whole validated capture into an app model shaped like the SDK record,
in the decision transaction, as one bounded step. This is the purest option:
one invocation, no staging, app tables only. It is also the largest change. Rust
would encode rows in the app's generated codec, audit up to 10,000 rows per
step, enlarge verification snapshots, and keep N snapshots of 10,000 rows that
can only be soft-deleted.

**D. Larger budgets for capture reads.** This weakens a global invariant for
one feature. Rejected.

Recommendation: **A** for Carta, and for any future capture that exceeds one
invocation, including Directory beyond about 7,900 units. It reuses this
module's tables, authority binding and bounds. Only the holder (invocation or
app) and an explicit release are added. **C** remains the long-term option if
captures should become app models with no host table at all.

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
2. Migrate Home as described above, then Equity once the Carta decision is made.
3. Remove `workspace_directory.capture.v1` / `hierarchy.v1` / `page.v1` and the
   `carta.snapshot.v1` / `record.v1` live path, with `workspace_directory.sqlite`
   and `carta.sqlite`. `user_path.v1` stores nothing and stays. No data
   migration: under AGENTS.md the stores are disposable caches, and app tables
   now hold what matters.
4. Drop `SOURCE_TTL_SECONDS` and the cache plan.

## Implementation map

- [`capture_delivery.rs`](../crates/day2/src/capture_delivery.rs): staging,
  page reads, release and sweep, bounds.
- [`workspace_directory.rs`](../crates/day2/src/workspace_directory.rs):
  `deliver_hierarchy` and `delivery_pages`.
- [`capabilities.rs`](../crates/day2/src/capabilities.rs): authorization, quotes,
  observe and usage.
- [`preparation.rs`](../crates/day2/src/preparation.rs): release at the
  decision boundary or on failure.
- Registry actions, disposable-verification bindings and coverage
  demonstrations for both capabilities.
- Tests: `capture_delivery::tests` (SQLite bounds, isolation, sweep),
  `store::capture_delivery_host_tests` (admitted capability path, budgets,
  settlement, faults, v1 coexistence), and the native Roc decode test in
  `tests/app_contract.rs`.
