# Notifications: owner-authorized configuration

This versioned Roc app implements a complete configuration flow from the
Notifications business source, rather than its old starter CRUD port:

1. Check the current human's app ownership through generated
   `ImportedContracts.app_ownership_check({ app_id })`.
2. Read an event's current configuration, save against its expected revision, or
   validate and preview a message.
3. Create a new contract version with `version=0`, or edit a positive version's
   template while preserving its field schema.

Every app-scoped operation checks ownership before reading or changing business
state. A negative or mismatched decision refuses the operation. A missing grant,
unavailable receiver, invalid response or stale serving selection fails in the
host before the business transaction. Preparation crosses the app boundary
without holding a SQLite transaction. As with the source application's remote
authorization, ownership can change after that check; this is not a distributed
transaction spanning both applications.

Save atomically updates the definition and version and inserts an immutable
actor-attributed change record. A stale revision, missing version or schema change
rolls back all writes. The ordinary command runtime supplies durable acceptance,
idempotency and status; there is no remote mutation to reconcile in this flow.
The editor retains the original save input and idempotency key until the outcome
is resolved, including across page reloads.

Text, integer, boolean and enum fields are supported. The domain preserves the
source's identifier rules and UTF-16 length limits, including astral Unicode.
Payload substitution is one pass: inserted text cannot create a placeholder.
Preview is a POST command with no declared business writes, so complete schemas
and payloads use the bounded JSON body instead of exceeding GET's URL limit.
Valid schemas have at most 20 fields and enum choices at most 50. The API returns
complete collection envelopes for schemas, choices and findings. Oversized field
and payload sets are rejected; repeated unknown-placeholder findings are
deduplicated. No result is silently truncated. Field schemas are canonical,
app-owned JSON content within a nominal contract-version row, with a typed codec
and invariant checked on every read/build. Relationships use nominal references.
Stored schemas also obey the host's 16 KiB text bound. Larger admitted schemas
return `invalid_configuration` before writing; preview can still validate their
supplied schema and payload within the host's POST body budget.

The UI covers the common `summary` text field; the same typed API supports the
other field kinds. It renders preview text with `textContent`. Delivery remains
disabled. Publication acceptance, delivery workers, Slack routes, group ownership
and content retention are separate capabilities, not simulated by this slice.

Source oracle: Notifications revision
`38bd9ab974e6757e1f6e9689d56e051ecde1534e`, specifically
`Notifications.Application/Notifications/NotificationHandler.fs`,
`Notifications.Domain/Notifications.fs` and
`Notifications.Infrastructure/Notifications/RemoteAdapters.fs`.

`xtask build-delegation-business` builds the ownership exporter first, pins the
candidate catalog through the normal import-lock path, then builds this app.
The full gate and native Linux qualification run the signed two-host HTTP
campaign in `day2-control/tests/release_execution/notifications.rs`. Instance
authority must grant Notifications its exact query import, all configuration rows
for its app-owned authorization decisions, and only the declared local writes.
Use the existing qualified GKE release workflow for the resulting native artifacts;
macOS artifacts are development evidence only.
