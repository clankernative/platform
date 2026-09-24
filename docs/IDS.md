# Model identities

App rows use TypeID-style public identifiers: a model prefix, `_`, and a
26-character lowercase base32 encoding of a UUIDv7. For example,
`rep_01h455vb4pex5vsknk084sn02q`. The database primary key and foreign keys store
only the UUID's 16 bytes. Prefixes are metadata, not part of those bytes.
Prefixes can differ in length: an `ord_` ID has 30 characters, an `orde_` ID 31.
Within one model the length is fixed. API clients should treat IDs as strings.

## Automatic, permanent prefixes

Declare ordinary nominal models and `Ref(Models.Customer)` relationships.
The platform assigns IDs on create; app authors need no UUID factory or counters.
Register each model explicitly with `xtask register-model APP TABLE Models.Type`.
This creates or extends `model-identities.json`; commit it. Every build derives
its tables from this ledger and `Models.roc` without creating identities.
It records a stable random model key, its prefix, the table and
Roc type, and retirement status. It is included in the build source digest and
retained as checked artifact evidence. Isolated builds cannot invent assignments.

The allocator starts with three lowercase letters from the table name, then
extends the prefix until it is unused. If `ordinals` already owns `ord`, adding
`orders` assigns `orde`. Existing assignments always win; simultaneous additions
are considered in sorted table order. Very short names and exhausted stems get a
letter suffix. Platform prefixes contain 3–63 lowercase ASCII letters.
The per-app registry rejects duplicates, including retired assignments.
Different apps have independent registries.

Never remove old entries or change published prefixes. Migration planning and
activation compare against the installed registry and reject rewritten history.
Use `xtask retire-model APP TABLE` when removing a model. A later new model does not inherit its assignment.
For an intentional source rename, preserve the identity before building:

```console
cargo run --locked -p xtask -- rename-model ../my-app orders purchases Models.Purchase
```

This updates registry metadata; update the Roc model/catalog names consistently.
It does not rename an installed database table. The migration planner rejects
table additions and renames. Explicitly retiring a model is supported: remove its
Roc model/table and retire the unchanged identity registration before building.
The checked migration plan lists `retire_models`. Applying it removes those
models from the active schema while preserving their physical tables, rows,
indexes and outgoing foreign keys. Host triggers make the retired tables read-only;
historical Platform audit records remain intact. Active models cannot retain
references to retired models. Retirement cannot be combined with integer-ID
conversion, and neither retired identities nor their prefixes can be reused.

## Validation and replay

`Ref.from_str` accepts canonical UUIDv7 references; generated codecs additionally
check the expected model prefix. Host validation repeats those checks for inputs,
outputs, stored foreign keys, and query cursors. Passing a customer ID where an
order ID is expected fails even though both are strings. Keep response IDs typed
as `Ref(Model)` so OpenAPI can generate the prefix, pattern, exact length, and
shared schema automatically. An ID does not confer authorization or prove that a
row exists.

The host persists a fresh random seed with each admitted invocation. It derives
UUIDv7 values from that seed, the stable model key, and the create's observation
position, using the invocation's captured time. Retries reproduce the same IDs;
independent invocations get independent random bits. Pagination sorts the binary
UUID keys and uses the last public ID as the next cursor. Start with `""` and
return continuation values unchanged. This is keyset traversal, not a snapshot;
UUID order does not guarantee commit order across concurrent invocations.

## Existing integer-ID databases

New databases use UUID keys. Existing databases require the explicit operator
transition; loading a new artifact never reinterprets integer bytes as a UUID.
Stop traffic and drain pending invocations with the old
artifact/host before upgrading. Back up the database and instance configuration.
Build the new app, then use the artifact directory printed by that build:

```console
cargo run --locked -p day2 -- migration-plan INSTANCE APP TARGET_ARTIFACT PLAN_FILE
cargo run --locked -p day2 -- migration-apply INSTANCE APP TARGET_ARTIFACT PLAN_FILE
cargo run --locked -p day2 -- activate INSTANCE APP TARGET_ARTIFACT LOCAL_OPERATOR EXPECTED_STAMP_JSON REQUEST_ID
```

Review the plan's `convert_ids: true` before applying. One SQLite transaction
assigns UUIDs to every existing row, rewrites every declared foreign key, preserves
data/revisions/creation times, checks referential integrity, and journals the
transition. Failure rolls back the rewrite. Repeating a committed plan retains
the same mapping. `day2_id_mappings` preserves the stable model key, old integer,
and new UUID for operator correlation with historical audit records and receipts.
Historical evidence keeps its original representation; new API calls use UUID IDs.
Old numeric bookmarks and stored client IDs must be updated from that mapping.

The conversion supports otherwise unchanged tables and fields, plus the planner's
existing nullable text additions. It does not also convert count columns from
integer to U64 blobs, rename tables, or backfill other required fields.
