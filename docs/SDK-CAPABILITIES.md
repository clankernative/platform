# Two Capability Surfaces

There is one company installation file, two authority boundaries, and no
provider-specific APIs in application Roc.

## Application commands and queries

The app-facing runtime now exposes commands and queries, with optional read-only
preparation and typed external effects. Read [COMMAND-RUNTIME.md](COMMAND-RUNTIME.md)
first for the executable Reports example, invocation semantics, instance grants,
shared adapters/simulators and current limits. Apps have no job registry or
background binding. The platform's release control plane has its own private
durable execution adapter.

## Bounded Queries And Context

App handlers receive opaque `Context`, with `actor()`, `invocation_id()` and `now()`
accessors. `Wire` belongs to the private worker protocol, not the app SDK. Its
instructions are still independently checked by the host, even for generated code.

Every collection in a newly built API output, including command results and nested
collections, must use `CollectionPage(a)`. Bare `List(a)` output contracts fail
admission. Lists can still be used for internal pure computations.

```roc
ListReports := { after : Cursor, limit : PageSize }
ReportsPage : CollectionPage(ReportView)

list_reports : Context, Contracts.ListReports -> Query(Contracts.ReportsPage)
list_reports = |_context, input|
    Query.page(Data.all_reports(input.after, input.limit))
        .map(|page| page.map(row_view))
```

`PageSize.from_i64` accepts only 1..100. `Cursor.from_str` accepts the empty
starting cursor or a canonical prefixed UUIDv7. Both return `Try`; callers can also use `Cursor.start`,
`PageSize.default` (20), or `PageSize.maximum` (100). The public JSON shape is:

```json
{"items":[],"has_more":false,"next_after":""}
```

An initial API request uses `{"after":"","limit":20}`. For another page, pass
`next_after` back unchanged; the host validates that it belongs to the selected model.
Generated codecs reject invalid inputs before worker execution. The host enforces
100 returned rows per DB selection and 100 items per output page independently,
plus a 1,000-item aggregate budget across nested/composed output pages. Internally,
one extra DB row can be fetched to determine `has_more`.

This bounds returned data, not rows examined by SQLite. There is no new cost
planner or generated owner-index guarantee in this increment; the existing SQLite
VM execution budget remains. Cursors are typed keyset positions, not signed,
query-bound or snapshot-bound continuation tokens. New installations and activation
require the current artifact contract. Format 14 removes the legacy job fields;
rebuild older applications and remove their `background` instance bindings.
Use the previous runtime to drain any legacy work before upgrading. This runtime
does not interpret the removed job contracts. Preserve older artifacts and their
runtime separately when historical inspection or replay is needed.

## Mandatory Audit

Commands, queries and private completions retain host-owned completion receipts;
successful app changes, row-change audit and receipts commit atomically. A common
redacted event stream now also covers admission/reuse/rejection, interrupted
execution, HTTP events and command execution attempts. Its fields include sequence,
scope, kind, identity, actor, initiator, operation, outcome, time, artifact and a
bounded reason code. It excludes request bodies, results, tokens and raw errors.

```text
cargo run --locked -p day2 -- audit-events ../my-private-instance/instance.json reports developer 0
```

This owner-only view returns at most 50 events with `has_more` and `next_before`.
Use `0` for the first page. The existing HTML audit page remains the completed
invocation/change view; it does not yet display every lifecycle event.

The generated `/docs` Platform section also includes `platform.audit` at
`GET /api/audit` and `platform.audit_events` at `GET /api/audit/events`. The first
returns completed invocations and redacted changes, with optional
`actor`/`operation`/`status`/`model`/`record_id` filters. The second returns the full
lifecycle stream, with optional `actor`/`operation`/`kind`/`identity`/`outcome`
filters. A `record_id` requires `model`; a matched completion retains all changes
from the same invocation. Native callers use `Runtime::audit_page` and
`Runtime::audit_event_page` with `audit::PageRequest`.

Both JSON APIs return `{items,next_cursor}`, newest sequence first, with a default
50-row limit and an allowed range of 1–50. Empty `next_cursor` means no older
matches. Cursors are opaque 256-bit handles bound to the database/app, artifact,
actor, view, filter set and limit, and expire after 24 hours. Each page rechecks
current app owner permission; a revoked owner cannot continue. The host keeps at
most 10,000 live handles per app database, reuses a handle for the same boundary,
and never evicts a live handle to make room. Exact descending sequence boundaries
prevent new events from shifting later pages. The legacy HTML/CLI integer
`before` interfaces remain supported independently.

Applications do not need an audit model or logging command. The host captures
completion, identity, artifact, changed field names and revisions automatically.
This mandatory record is redacted: it excludes business field values, application
input/results, and free-form deletion reasons. Record-filtered history is a
revision timeline, not historical value reconstruction. Business data such as
the current deletion reason belongs on the business record under its ordinary
authorization policy. See [WEB.md](WEB.md) for request examples and HTTP behavior.

UPDATE, DELETE and replacement-insert guards protect audit records. Missing
transactional guards fail closed; transactional audit failures prevent the
associated state commit. HTTP-response logging occurs later: its failure returns
503 but cannot undo an already committed operation. Retry with the same identity.
Migrations do not invent historical events or actors. Admission events use the
attempted request time; receipts preserve accepted invocation time. Interruption events use observed host time. A missing actor
means no authenticated actor or host-originated work, not an inferred user.

## Application History

`pf.Audit.history` reads only the current app's completed commands and queries,
with redacted row changes. It excludes platform admission/rejection, interruption,
HTTP and retention events. It exposes no invocation input, output, raw error,
token, request body or business field value. The platform audit remains accessible
only to the enabled policy's `admins`; granting an app history query grants no
platform audit access.

Use `Handler.prepared(prepare, handle)` and return
`Audit.history({ operations: ["links.edit"], after: input.after, limit: input.limit })`
from `prepare`. The handle phase receives `CollectionPage(Audit.Entry)` and can
project it into the app's own output or join current rows through ordinary model
grants. The operation needs `"observations": ["audit.history.v1"]` in its policy.
The host rechecks this grant before reading and before using a cached observation.
No provider, resource binding or platform owner role is needed.

`Entry` contains `sequence`, `operation`, `actor`, `initiator`, `trigger`, `outcome`,
`at` (Unix seconds), `changes` and `change_count`. A change contains `model`,
`record_id`, `before_version` (zero for creation), `after_version`, and changed
`fields`. No row values are copied into append-only history. Read current rows
under the operation's model grants when values are needed.

Results are newest first. `operations` is an exact-name filter of at most 64 names;
empty includes all completed operations, including reads. Retired names remain
readable. `limit` must be 1–50, even though `PageSize` itself permits up to 100.
Each entry includes at most 20 row changes, while `change_count` states the total.
A page stops early when its escaped JSON approaches 40 KB. An unusually large
change list may be omitted with its total still reported. Follow `has_more` and
pass `next_after` unchanged. Cursors bind app, actor, calling operation and filter,
expire after 24 hours, and retain exact sequence boundaries across new writes.
The read is journaled for deterministic replay. See the
`fixtures/delegation-conformance/queries/history` example.
`initiator` is the original requesting actor, not a work identifier.

These are platform invariants, not WORM storage. A SQLite file owner can alter the
database or remove guards. Production DB-role separation, external immutable
export, retention and encryption remain unfinished. Failures before a runtime or
its database can initialize cannot be recorded in that database's event stream.

## Control Plane

The same installation file contains `control`, using shared types from
`crates/day2-capabilities`. `control.apps` only references installed applications.
The service authorizes an operator and returns an opaque `AppHandle`; source,
build and provider-secret operations require that handle. App code receives none
of these privileges automatically.

Company operators configure the repository binding, builder and runtime explicitly
in their installation's `control` section; see the [control-plane configuration](CONTROL-PLANE.md).
Managed local development provisions app execution without granting those operator
capabilities. The commands below assume an existing `../my-private-instance/instance.json`
with Reports installed and its source/build bindings configured. Export the authored app source:

```text
cargo run --locked -p day2-control --bin control -- --local ../my-private-instance/instance.json developer reports export first-export examples/reports
```

The command returns a durable execution identity. Run it, or resume after a process
restart, with `run ID`; inspect it with `status ID`. Use `propose REQUEST BASE_COMMIT
SOURCE_DIRECTORY` to create a proposal branch against an exact exported revision.
The service selects the repository. A request cannot substitute another app's repo.
An app whose source is a `remote_git` repository skips export and propose: push to
the repository, then build the exact commit.
The local provider verifies the base revision and creates the proposal ref atomically;
it does not automatically merge changes.

`build-pin local_builder local_temporal --write` computes actual platform, recipe,
toolchain, cache, source and runtime pins and records the approved profile.
`build-submit REQUEST COMMIT` accepts the exact commit even while Temporal is down.
`build-run ID` runs the real isolated compiler recipe through Temporal; `build-status
ID` reads its journaled state. An existing request never silently follows changed pins.
The configured Temporal namespace must exist; the spike does not provision production
Temporal or use production namespaces. The verification harness provisions its own
isolated persisted server and tests restart and offline acceptance.

For an installation configured with endpoint `127.0.0.1:17233` and namespace
`day2-exampleco`, start the local Temporal server in a separate terminal before
`build-run` (after the source operation has created `.control`). This uses the
same CLI flags as the tested server harness, a local
database, and a dedicated namespace:

```text
temporal --disable-config-env --disable-config-file --env-file ../example-instance/.control/unused-temporal-environment.yaml server start-dev --headless --ip 127.0.0.1 --port 17233 --namespace day2-exampleco --db-filename ../example-instance/.control/temporal.sqlite
```

The configured port must be free. If it is occupied, select a different local
port in `control.runtimes.local_temporal`, use that port in the command, and run
`build-pin` again before accepting a new build. Existing executions retain their
original runtime pin.

Company `control.secrets` maps logical bindings to explicit GCP numeric versions.
`control.apps.<app>.provider_secrets` grants app-local provider references to those
bindings. `Service::secret_resolver` requires the authorized app handle and an
explicit trusted access-token provider. It returns a scoped host resolver, not a
serializable secret. There is deliberately no Roc or CLI command to print secrets.

## Architectural Boundaries

Pure application code, host-owned effects, exact typed declarations, bounded
collection responses and mandatory audit are intentional constraints. Company
provider choice belongs to the instance. Supporting additional effect capabilities
does not require allowing app code to open arbitrary files or start processes.

Roc permits forward references between associated methods and module definitions.
Local sequential bindings already reject use-before-definition. The pinned
compiler has no switch to impose that local rule on associated methods. Its LSP
does not expose complete associated-definition metadata, so a partial text/LSP
checker would not establish the requested guarantee. Examples place helper
callbacks before their use where practical. A strict rule needs compiler-resolved
declaration/use metadata, an explicit recursion policy, and tests for associated
methods and shadowing; it remains unimplemented.

[The custom-rule proposal](ROC-STYLE-RULES.md) describes a pinned compiler patch
for source-reference order and associated-definition spacing, including recursion
policy, dispatch limits, admission enforcement, and acceptance tests.

The [pinned native formatter patch](../tools/roc-formatter/README.md) extends Roc's
existing AST-based declaration grouping to associated definitions. `xtask fmt`
inserts missing blank lines; `xtask fmt-check` rejects their absence. It preserves
signature/body groups and comments, including comment-only associated blocks.
This is a separate formatter build, not a change to the application compiler.
The unmodified upstream `roc fmt` still accepts compact groups. Formatting is
enforced by the platform verification workflow, not yet by each isolated app CI
build or by an automatically configured editor.

The [SDK source map](../sdk/README.md) separates contracts, data, web,
testing and runtime internals. A checked explicit package catalog preserves the
existing `pf.*` imports; directory names are not inferred capability declarations.
The [fixture guide](../fixtures/README.md) distinguishes reusable platform
conformance examples from company-owned applications and their acceptance tests.

## Current Spike Limits

This completes a local end-to-end surface, not fleet or production parity:

- The current command runtime and capability limits are documented in
  [COMMAND-RUNTIME.md](COMMAND-RUNTIME.md). Real messaging and warehouse adapters
  still need provider-specific contracts and conformance evidence.
- SQLite is durable but not highly available. The Temporal adapter is currently
  restricted to local loopback. Terminal workflow failure/timeouts require explicit
  operational recovery; they are never reported as a successful execution.
- Source writes use real local Git, not GitHub/GitLab PR APIs. Remote Git
  sources are read-only exact-commit fetches. The existing GitHub
  fetch/check and GCP adapters have HTTP conformance coverage, not live-cloud qualification.
- Replay traces and source snapshots can contain sensitive app data. Local state
  is protected, but production encryption, retention and access control remain gates.
- `--local` is an operator identity assertion, not production SSO. IAP/Entra/Okta,
  Linux hosted/BYOC execution, PostgreSQL/HA, IaC and deployment remain separate work.
