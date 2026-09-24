# Architecture

## Trust And Ownership

The local operator and Rust platform are trusted. Roc app behavior is constrained
by the supplied platform, the compiler sandbox, a separate native worker, and
host-side effect validation. Native worker isolation is defense in depth, not a
claim of hostile-code certification. Each company has an independent instance
repository and each installed app has its own database.

The separate [enterprise control plane](CONTROL-PLANE.md) owns source/build/secret
adapters and Temporal-backed operations. Its journal/outbox does not change the
[command/query runtime](COMMAND-RUNTIME.md). Apps describe read-only preparation,
transactional decisions, external effects and private completion. The host journals
command progress and enforces those boundaries. Both surfaces use the company
instance file; Temporal is private to the release control plane.

Dispatch identity is installation/environment/app/operation. The operation name
only needs to be unique within its artifact; duplicate names there are rejected.
Identical operation names across apps or companies are normal. The host selects
the artifact and database from the installation binding, not from command JSON.
Unknown input fields, including a caller-supplied scope, are rejected.

The instance independently approves an `authority` policy for each app. Missing
policy denies invocations, including for legacy artifacts. Reader/writer
membership remains an outer gate; explicit operation actors and model grants
must also permit the invocation. Policy is checked against the compiled contract,
not supplied or expanded by the app. See [AUTHORITY.md](AUTHORITY.md).

`App.definition` registers typed command and query definitions once. Each
requires structured descriptions and verification alongside the callback. Commands
also require execution bounds. Record keys define operation names, and checked
wrapper witnesses infer their actual types. See [the complete root](APP-CONTRACT.md).
The platform generates typed handles and an internal `AppContract.Product`
callback record, then rechecks the complete app with those exact handles.
There is no authored `Catalog.roc` or repeated operation type list. The platform does not
infer intent from a function name, result type, or URL. Commands return Tx(a);
queries return Query(a). There is no public Query conversion from an arbitrary
Tx. Independently, the interpreter rejects mutations from query operations.
Execution context and pagination values are opaque public types; `Wire` stays
internal. New API output catalogs reject bare lists, including nested lists.
`CollectionPage(a)` bounds each collection to 100 items and host output validation
also bounds their aggregate size. These limits do not prove an index is used or
bound how many rows SQLite examines. See [SDK-CAPABILITIES.md](SDK-CAPABILITIES.md).

The local HTTP adapter serves full HTML pages and normal forms, progressively
enhanced by platform-generated Datastar attributes. Read(a,b) retains a query's
types for Page.define; private page dispatch runs that same query under the query
write guard. Compiler-generated Outputs handles supply result codecs and checked
output shapes. The host renders app-owned ordinary HTML templates using those
values; it does not choose the app's layout. Template admission checks all
branches, includes, field paths and command bindings, while runtime rendering
escapes values and binds concrete forms to signed command tickets. Native app
JavaScript is trusted presentation code, not part of the pure Roc core or a
capability sandbox. See [UI-POC.md](UI-POC.md) for the exact limits.
Page bindings retain metadata only. Private dispatch resolves the registered
query by name and requires its query kind; there is no separately stored page
handler that can shadow a same-name registered operation.
Live page bindings subscribe to that same query through platform-owned SSE.
Business writes advance a durable revision atomically; the host reruns bounded
queries and morphs only admitted display regions. External/time-dependent reads
require an explicit server refresh interval. Forms retain their draft and original
edit version until submission or deliberate reload. See [WEB.md](WEB.md#live-queries-over-sse).
Format-7 page metadata pins both input and output handle names. Route admission
and private dispatch require exact agreement with the registered query, not
merely compatible wire shapes. Legacy page metadata remains loadable unchanged.
Page declarations choose explicit paths and generated opaque template handles.
`Page(input)` retains the query input until `.register()` erases it into a
`PageBinding` for the product catalog. Output metadata and encoding derive from
the typed read, not a second page output argument. Partial defaults are checked
against input codecs at build and artifact load; path fields must be supplied
by the request, never by placeholder defaults.
`.with_defaults(input)` uses the read's existing typed input encoder, so complete
DTOs retain nominal types and numeric inference. Mixed routes instead use
`.with_query_defaults(partial)` with explicit partial numeric types such as
`20.I64`. Partial records do not inherit the query's field types through Roc's
type checker, and the host does not coerce decimal JSON into integers.
Admission checks wire shapes and built-in scalar codecs, not arbitrary custom
text-domain predicates. Their `from_str` constructors run in the generated
query input decoder, so structurally valid partial defaults or URL parameters
may still be rejected at query execution.

One host route catalog handles request decoding and URL construction. Checked
template `routes.<page>(...)` helpers and `platform.audit()` use that catalog;
there is no second Roc-side URL codec or native browser router. Admission
rejects overlapping routes and requires an explicitly registered `/` with
complete query defaults when an app has pages. Template filenames, page names
and route paths are independent declarations, not naming conventions.
JSON CLI, REST and MCP invoke the same admitted command/query catalog.
The local command scheduler resumes durably accepted invocations independently
of their HTTP callers. Scheduled commands can use the same acceptance contract.

## From Roc Record To Relational Row

1. Snapshot bounded Roc sources and declared resources together; reject symlinks, special files, unexpected
   inputs, and app-owned generated headers, Data.roc, Inputs.roc, Outputs.roc,
   Assets.roc or Templates.roc.
   App assets, templates, browser resources and the identity ledger are admitted
   from the captured tree, never through Roc filesystem access.
2. A generated schema platform follows App.definition's explicit storage dependency
   and exposes its persistence and domain witnesses. Registered handler wrappers
   determine all reachable request/result codecs; no authored codec lists exist.
3. The pinned compiler's glue API supplies checked type metadata to
   SchemaGlue.roc. It projects only structural metadata into JSON.
4. Rust validates supported shapes and generates Data.roc, Inputs.roc and Outputs.roc.
   It checks App.definition with temporary operation handles, discovers record keys
   through compiler reflection, then specializes witnesses against each callback
   to infer the catalog. Exact Commands/Reads handles replace the temporary
   modules before final reflection, admission and linking. The final metadata is
   retained as artifact evidence. See [SDK-CAPABILITIES.md](SDK-CAPABILITIES.md).
   The generated handles carry the Roc value type, model/input name, and codecs.
   Assets.roc is generated from the app's validated asset directory. Format-4
   artifacts include the normalized asset catalog and content-addressed blobs.
   Format-6 artifacts add checked output contracts and HTML template blobs.
   Format-7 artifacts add explicit route declarations and independent template
   references. HTML is packaged before compilation to generate opaque template
   constants in the trusted SDK and the app's Templates.roc aliases. There is
   no public arbitrary-filename template factory.
   Output-only changes do not change database schema hashes or generate DDL.
5. Check identical authored sources against both the execution SDK and a restricted
   factory-admission SDK. Generated modules adapt internally; app references to
   either profile's generated-only factory names fail the other profile. Compile
   the execution profile and extract its operation and nonempty property catalog
   through the isolated worker. Host effect validation remains independent of
   this authoring boundary.
6. Derive relationships from checked reference types, generate STRICT DDL and indexes, and hash
   the executable, schema, checked inputs, source fingerprints, and toolchain.

There is no regex parser for Roc source and no separately handwritten SQL model.
Persistent models must be nominal records (:=), not structural aliases (:).
The supported fields are I64, Str, Bool, [None, Some(Str)], Ref(Model), and nominal
text wrappers with a single value : Str field. Unknown shapes fail instead of
falling back to JSON storage. A plain integer is not inferred to be a relationship.

Ref(a) is opaque and retains its target identity through an empty List(a) witness
in checked compiler metadata. The witness is always empty at runtime. The
generator matches the target's nominal name, not a compiler-local type index:
the same nominal type can appear in multiple metadata nodes.

The final app uses one copy of Models and the domain modules. Generated Data
and Inputs sit beside them; only generic SDK modules live in the platform
package. Copying the same nominal model into both packages would create distinct
types and is deliberately avoided.

Reference input codecs require a canonical positive decimal string, reject
numeric JSON, leading zeros, signs, and overflow, then construct Ref(Model).
Storage codecs use positive I64 values. Text domain codecs call the app type's
from_str and to_str functions; final compilation checks those signatures.
Title validates nonblank text of at most 200 UTF-8 bytes. It is validated both
at command decoding and when stored rows are decoded, including property snapshots.
SQLite enforces its text representation, not the app's arbitrary predicate.
Company policy additionally requires declarative host constraints for nominal
text model fields. Nonempty/max-byte checks run on every create/update, even if
an app constructor is permissive. They do not execute or prove arbitrary Roc
domain predicates; the baseline Title policies separately approve its 200-byte
nonblank rule.

Generated all_MODEL and MODEL_by_REFERENCE_FIELD functions construct typed
Selection(Model) values. Tx.page and Query.page accept these selections. The
target reference type is checked by Roc; the host separately checks the model,
indexed field, cursor, and page budget. This is bounded indexed lookup, not a
general relational algebra. No joins or expression-tree query optimizer exist.

Table keys, versions, and creation times are platform-managed. Foreign-key
columns reference actual tables. Reads and writes use parameters for values and
only registered, validated identifiers for generated SQL.

## Transaction Interpreter

    validated input + captured context
        -> Roc Tx(a)
        -> next typed storage request
        -> Rust validation and SQLite
        -> observation
        -> resume the same pure decision

Tx(a) contains a pure continuation, not a .NET Task or a Roc effectful function.
To cross the process boundary, the host supplies the original input plus the
ordered observation transcript. Roc reconstructs the transaction from the
beginning, verifies each prior request against its observation, and returns the
next request or terminal result. No closures are serialized.

The SQLite BEGIN IMMEDIATE transaction stays open during this interpretation.
Reads may depend on previous reads, branch on results, and observe earlier writes
from the same invocation. These are not preloaded snapshots with a disconnected
write batch.

The CRM move reads the deal, source stage, and target stage; checks the expected
version and counters; updates the deal; decrements one counter; increments
another; appends history; and reads the updated deal back. All four writes commit
or roll back together. Foreign keys and version predicates are enforced again
by the host/database.

Single-target Edit commands also declare their reference/version inputs in
company policy. Before worker startup, the host loads that target in the same
transaction and checks ownership and the caller's version. Subsequent updates
cannot escape the target or approved fields. The SQL entity-version predicate
still runs independently. CurrentState commands deliberately lack this extra
caller precondition; the CRM multi-row move uses that explicit mode because
Edit does not yet support its other-model writes.

The transcript approach is intentionally bounded and O(n^2) in reconstruction
work. It is a simple correctness-first prototype, not a high-throughput runtime.

## Durable Acceptance And Recovery

Acceptance validates the current binding, actor permission, exact input shape,
and caller's invocation identity, then commits a pending receipt. The receipt
pins the artifact, actor, canonical input, and captured time. Reusing an identity
with different input, actor, operation, or artifact is a conflict.

Execution obtains the database writer lock and rechecks the active authority
stamp persisted at acceptance. Policy, outer memberships and active artifact
binding live in the same SQLite database as business data. Activation advances
the revision even when policy contents return to an earlier value, so an
invocation cannot mix grants or resume after an A-to-B-to-A change.
Model effects enforce declared row scope and update-field limits; owner predicates
enter paginated SQL before `LIMIT`. Mutations return full rows and therefore
require read permission too. These are not field-specific read projections.
Any owner-scoped grant establishes one model-wide owner field for the policy.
All operations, including broader `rows: all` grants, preserve that field and
assign the caller on creation. Conflicting owner fields fail policy admission.
Local authority and artifact activation hold that same database lock and require
an expected stamp plus an idempotency request ID. `instance.json` prepares desired
policy; editing it does not activate authority and startup never overwrites an
active record from stale desired configuration. Existing data needs explicit
operator initialization, and restored databases receive a new epoch with grants
disabled until current policy is explicitly activated. This is an atomic boundary
per app database, not an instantaneous company-wide activation across databases.

Successful domain writes, result, decision trace, and completion audit commit in
the same transaction. A business/storage rejection rolls back all domain writes
and records a failure in a separate transaction. Another executor that completes
during that rollback gap wins through the durable receipt check.

A crash before commit leaves a pending invocation and no partial domain writes.
Resume reexecutes with the pinned original context. A lost response after commit
returns the original receipt on redelivery. Generated IDs derive from scope,
invocation identity, model, and request position; collisions fail on primary-key
constraints. This is local idempotency, not exactly-once external side effects.
The CRM's legacy result projections encode references as decimal strings.
Typed page queries instead derive output contracts and encoders from checked
Roc types; their view projections remain app-authored.
Completed results require current authorization and the same captured policy.
Policy changes or legacy receipts without policy evidence deny reuse; the host
does not rerun the command or release a historical result under changed grants.

## Replay And Simulation

Replay runs the exact artifact in a fresh worker against recorded observations.
It verifies each requested effect, consumption position, and terminal result.
It does not contact SQLite or repeat business writes. Rejected effect
observations also replay. Infrastructure interruptions remain pending rather
than being falsely reported as business rejections.

New format-2 traces additionally capture the company policy and host Edit guard's
precondition row/error. Replay reevaluates that guard; a pre-worker rejection
replays without invoking the app. Guard success retains normal effect replay.
Legacy format-1 replay does not establish that authority guards were performed.
Captured policy and row evidence are unsigned local records, not independent
proof that an operator approved a historical policy.

The state-machine campaign generates moves, stale versions, duplicate delivery,
rejection after selected writes, interrupted attempts, and commit ambiguity.
An independent reference state checks deal location, versions, counter
conservation, and history cardinality. Every completed generated operation is
replayed. Separate tests use actual process exit at all four write positions
and real two-thread contention with an expected-version race.

Properties.roc registers three named invariant predicates over Data.Snapshot:
stage counters match actual deals, deal versions match history cardinality,
and relationship targets exist. The generator decodes platform rows into
Model.Entity(Model) values through the same domain/reference codecs as commands.
The campaign evaluates these Roc predicates at the initial state, after every
transition, and after pre-commit interruptions before recovery. They complement,
not replace, the independent Rust model and SQLite integrity checks.

Inspection holds one read transaction across all tables and rejects more than
256 rows per model instead of silently truncating. The property worker receives
only that snapshot, fixed verifier context, and no observations. There is no
effect interpreter for this call. Its returned names must exactly match the
artifact catalog, with no missing checks or successful decoding errors.
The reserved $properties operation is inaccessible through normal dispatch.
Properties are verification evidence, not arbitrary predicates evaluated before
every commit. Host policy, text constraints and Edit preconditions are separate,
non-optional runtime guards.

Failed predicates and row decoding errors persist the exact snapshot, artifact
identity, and checks in a content-addressed local evidence file. Replay reruns
the isolated artifact without a database and compares every check. Deliberately
corrupted counter, history, reference, and domain fixtures test the checks
themselves. Generators and shrinkers still live in Rust; this is an app-owned
invariant contract, not an app-authored scenario/generator language.

This is local deterministic fault scheduling plus real adapter conformance.
It is not a distributed-system simulator, OS scheduler replay, or provider
simulation. Replay establishes decision consistency with recorded observations;
unsigned local trace files are not tamper-proof audit evidence.

## Guard Layers

| Layer | Enforcement |
| --- | --- |
| Compiler | Pure required entrypoint, nominal rows/references, domain codecs, typed selections, Tx versus Query |
| Compiler process | Read allowlist for staged inputs/toolchain, isolated caches/temp, no network, build timeout |
| Worker | No app I/O host functions, OS file/network/process restrictions, cleared environment |
| Protocol | Bounded frames, exact response structures, transcript/request matching |
| Host | Instance-approved operation/model grants, owner row scope, update-field limits, text constraints, caller Edit preconditions, stable execution policy, query-write denial |
| Storage | STRICT columns, foreign keys, PK uniqueness, version predicates, atomic receipt/write completion |
| Verification | Positive/negative canaries, seeded shrinking properties, real SQLite and crash/replay tests |

Limits: 1 MiB protocol frames, 64 storage requests, 3 seconds per worker exchange,
15 seconds per transaction attempt, 64 MiB of Roc-managed allocations, bounded
SQLite VM work, and pages of at most 100 rows. The allocation limit is not a
whole-process RSS limit. Read-only queries currently take the writer lock too,
because query receipts share the same durability protocol.
Inputs, precondition rows and observation traces still retain raw business data;
the redacted public audit view is not an encryption or retention policy. Nothing
an application does removes a row or an object — deletion is a platform state
and removal is an operator's declared policy. See [DELETION.md](DELETION.md).

Runtime profiles permit system-library reads and filesystem metadata. Compiler
profiles additionally permit the staged source tree and pinned build tools.
Both use macOS sandbox-exec and fail closed on unsupported hosts; there is no
unsandboxed application fallback. Native canaries prove selected denials, not
the absence of every possible sandbox escape or side channel.

## Migrations

Schema identity covers persistent models and relationships, not merely input
DTO changes. Artifact identity covers both. Supported transitions include adding
optional text, adding declared indexes, and explicitly retiring registered models.
Existing rows receive SQL NULL for a new optional text field and decode to None;
a non-null column round-trips as Some(Str). A new unique index checks existing
rows before the migration commits. Retired models require unchanged identity
registrations marked retired; the plan names each model. Their physical tables,
data, indexes and historical audit remain, with host triggers preventing further
writes. Active models cannot refer to retired models. Required-field additions,
removed or renamed fields on active models, changed types or nominal model
identities, relationship changes on active models, and table additions or renames
fail. New builds use artifact format 12 and require the complete
[application contract](APP-CONTRACT.md), typed models,
a nonempty property catalog, dual-profile generated-factory admission, an exact
command/query catalog, and bounded collection outputs. Formats 1 through 11
remain readable for inspection, replay, and explicit recovery of accepted work;
format 1 lacks the property contract. Fresh API invocations, HTTP serving, new
databases and activation require the current format. Execution always requires
explicit company authority. Conversion to new domain/reference kinds is not
silently treated as an additive migration.

A migration plan includes scope and exact source/target artifact and schema
identities. Apply recomputes it and checks database scope, current schema, drain
state, and journal identity under the writer lock. DDL, schema metadata, and the
journal commit together. Reapplying the same plan is idempotent.

Activation is a separate checked database transaction after schema compatibility
and drain checks. It publishes the artifact binding and compatible authority
together using the expected authority revision; the instance file supplies desired
configuration. The intermediate state between schema migration and activation
fails closed. See [transactional authority](TRANSACTIONAL-AUTHORITY.md). General
backfills, expand/contract rollouts and automatic rollback orchestration remain
future platform work.
