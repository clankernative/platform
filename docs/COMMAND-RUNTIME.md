# Commands and queries with external dependencies

Applications register exactly two kinds of operations: `Api.command` and
`Api.query`. Reports is the executable reference. There is no application job,
queue, worker, retry or workflow definition. The current implementation is a
bounded local durable interpreter backed by SQLite; it does not start a Temporal
workflow for each command.

## Authoring contract

Each operation keeps its nominal request, handler, meaning, execution bounds and
verification together. `App.definition.operations` registers it once.

| Handler | Preparation | Decision | External effects | Completion |
| --- | --- | --- | --- | --- |
| `Handler.local(handle)` | None | `Context, Input -> Tx(Output)` or `Query(Output)` | None | None |
| `Handler.prepared(prepare, decide)` | `Context, Input -> Observe(Facts)` | `Context, Input, Facts -> Tx(Output)` or `Query(Output)` | None | None |
| `Handler.effects(prepare, decide, deliver, complete)` | `Observe(Facts)` | `Tx(Decision)` | `Decision -> Effects(Result)` | `Context, Input, Decision, Result -> Tx(Output)` |

These are typed specifications passed to the same `handler` field, not additional
operation kinds. Pure commands need no empty preparation or completion callbacks.
Effectful commands use explicit completion because their final result may depend
on provider results. A completion that has nothing to save uses `Tx.succeed`.

`Observe.local(Query.get(...))` and `Observe.and_then` support dependent read-only
preparation: read local IDs, query one capability, then use that result in another
read. `Observe` cannot contain a `Tx`. `Effects.and_then` supports dependent
external writes, including returning an earlier provider ID to a later call.
Neither preparation nor delivery exposes arbitrary HTTP, credentials, clocks,
files or processes. Typed capability packs are the integration boundary.

The transactional decision remains a **pure Tx program**, interpreted under one
local transaction. Current local reads and declared writes belong there; external
observations belong in preparation. This preserves read-your-writes and atomic
business invariants without pretending that independently observed external state
is part of a distributed snapshot. App edit declarations and prepared local reads
are checked again when that transaction starts. A stale preparation fails with a
conflict; a fresh business attempt needs a new invocation identity.

Reports demonstrates all three forms:

- [SubmitReport](../examples/reports/commands/submit/SubmitReport.roc) atomically
  creates a pending report and requests `Commands.analyze` with the observed row,
  captured revision and document. Retrying submission reuses both receipts.
- [AnalyzeReport](../examples/reports/commands/analyze/AnalyzeReport.roc) computes
  statistics outside the decision transaction, then updates only the captured
  revision and requests the notification command in that same transaction.
- [NotifyReady](../examples/reports/commands/notify/NotifyReady.roc) prepares the
  recipient, reads the ready report in its decision, sends an external notification
  and returns the receipt through private completion.
- [GetReport](../examples/reports/queries/detail/GetReport.roc) combines a local
  report with a prepared capability read of its notification status.

`Api.internal(Api.edit(...))` makes a command requestable through generated
`Commands` handles while excluding it from HTTP, forms, OpenAPI and MCP. There is
no public completion operation. Child requests require an authentic observation
from the current transaction and explicit instance-policy grants.

A command may create a supporting record in its decision and finish it in
completion. Declare `Api.create(Data.workflows)` together with
`Api.update_created(Data.workflows, [Api.field(Selectors.workflows_status)])`.
The handler continues to use `Tx.update` with the observed row revision. Native
append-only audit proves creation by this exact invocation in this installation;
worker observations cannot grant this permission. Rolled-back creates grant
nothing. A committed creation remains valid after restart, while stale revisions
still conflict if another command updates the row. Origin does not refresh CAS.

`Api.update_created` also works under `Api.current_state`, with the same origin
restriction. For `Api.edit`, it permits supporting models while the primary model
retains its exact input target. Captured child targets and current operator
authority remain enforced. An operator `Edit` policy intentionally allows only
its single target and forbids creates; this policy cannot authorize supporting
records. An operator `CurrentState` policy with explicit per-model grants can
authorize an application edit with these additional bounded effects.

## Invocation and completion

A parent command completes when **its own** contract completes. A successful
submit means the report and its analysis request committed. The analysis and
notification commands have their own outcomes. Reports' `ready` field expresses
the business state; provider attempts and delivery progress live in host tables.

HTTP callers can send `Prefer: respond-async` with the normal command request to
wait only for durable acceptance. The response is `202` with an invocation ID and
`Location: /api/invocations/{id}`. A normal command request executes immediately;
if external work remains it also returns `202`. `GET` on that status URL is
actor-scoped and checks current authority; it returns status, final result and
child-command receipts, never raw preparation or provider payloads. An HTTP
timeout is not cancellation. Retrying with the same idempotency key reuses the
invocation; changing the operation or payload under that key is rejected.

## Runtime implementation

The native worker stays pure. A sealed SDK lowers phase specifications into a
private pure callback when constructing the command or query definition. That
callback emits the transcript protocol. The supervisor enforces which instructions each phase may
request, independently of the Roc types. The platform stores:

1. Accepted input, actor, stable identity, ID seed and pinned artifact.
2. Command preparation observations, recorded after each bounded read.
3. Local business writes, child invocations and the effect continuation in one
   SQLite transaction.
4. Each external intent and result outside that transaction, using a stable
   capability invocation ID derived from scope, command ID and ordinal.
5. Private completion writes, audit and the final result in a fresh transaction.

Prepared facts and decisions are reconstructed by replaying the pinned pure code
against recorded observations. The runtime does not serialize closures or repeat
past database mutations. There is no checkpoint at every line. Query preparation
is ephemeral: a crash restarts its reads. Queries still retain the existing
completion/audit evidence, but get no durable preparation journal by default.

Local web serving owns the scheduler. It resumes accepted commands independently
of HTTP request capacity; multiple schedulers converge on transaction receipts and
provider idempotency. Admission captures the active authority epoch and revision.
Every later phase requires that stamp in its database transaction. External
calls require a separate transactional dispatch admission, followed by the
provider call outside the business transaction. A changed stamp or binding blocks
further execution and does not become current again if identical grants are
restored. Already admitted calls may finish; settlement records their outcome
even after revocation without invoking application completion writes. Retries
require fresh admission, a distinct attempt identity and the original effect ID.
Migration/activation requires pending invocations to drain, including commands
whose local decision committed while external delivery remains incomplete.

There is no atomic commit across SQLite and an external service. Failure after
the decision commit retains those committed changes. Applications must model any
business compensation explicitly; retry and cancellation cannot undo delivery.

## Shared integrations and deterministic simulation

[`pf.Notifications`](../sdk/contracts/Notifications.roc) is the first reusable
capability pack. Its typed operations are recipient resolution, latest acceptance
status and send. [`capabilities.rs`](../crates/day2/src/capabilities.rs) owns the
semantic model and a durable local mailbox adapter in a separate SQLite file.
Any admitted app can use the same pack and model with explicit instance grants.
No Reports-specific behavior lives in this adapter.

[`pf.Carta`](CARTA.md) is a typed read pack backed by explicitly seeded, immutable
synthetic captures. It reads individual stakeholder, grant, vesting and exercise
records so nested arrays do not exceed one observation. Disposable verification
campaigns explicitly supply its shared synthetic model; ordinary runtimes remain
unconfigured until a native operator seeds a capture. It makes no live Carta calls.

The mailbox provides idempotent acceptance for a stable effect identity. Tests
interrupt execution **after provider acceptance but before recording its result**,
restart the runtime and verify one notification. A conformance overlay exercises
two dependent sends: the second consumes the first receipt. Replay uses recorded
observations and never contacts the adapter. Literal domain results, SQLite
rollback tests, authority probes and concurrent schedulers cover the other edges.
The seeded command campaign varies crashes across preparation, decision commit,
provider acceptance and completion. It compares final business and provider state
across schedules against literal domain expectations. Identical scenarios also
compare the complete logical journal, provider state and worker exchanges.
Generated schedules use a fixed proptest seed, shrinking and failure persistence.

The host-only [`Simulation`](../crates/day2/src/simulation.rs) supplies identity
entropy and logical audit time without modifying accepted invocations in SQL.
Entropy is derived per invocation; duplicate acceptance reuses its persisted seed.
Worker timeout/crash outcomes can be scheduled explicitly. Real process watchdogs
remain active; an unexpected adapter failure fails the simulation.

The runtime and simulator share external-effect `claim`, `perform` and `settle`
operations. Tests can hold two claimed effects, interleave provider calls, lose a
response, reverse settlement order, or change authority while a response is in
flight. Settlement preserves knowledge of an already performed effect; subsequent
work reauthorizes. These controls are Rust host interfaces, not app capabilities.

Every campaign saves its scenario before execution and checkpoints partial
evidence under a unique `artifacts/command-simulation/run-*/evidence.json` path.
Expected injected interruptions are typed; unexpected execution failures fail the
campaign. Errors and panics retain the latest evidence, and abrupt process loss
leaves the last persisted checkpoint. A successful rerun cannot overwrite it.

A Twilio, Slack, Linear or Snowflake pack must supply typed operations, an explicit
read/write classification, authority and resource bounds, error semantics, a real
adapter, and a shared deterministic model. Test its adapter against that contract,
then reuse the model in every app's simulation campaign. A simulator models the
admitted operations, not the provider's entire product. External reads are
classified by semantics; an HTTP method alone cannot establish read-only behavior.

Retry guarantees belong to each operation. A provider idempotency key or verified
reconciliation can resolve an acknowledgement loss. A provider lacking both must
retain an **unknown outcome** for reconciliation; the platform cannot manufacture
exactly-once delivery by writing an outbox row. Current executable packs include
the local mailbox, synthetic Carta captures, and the typed GoogleDirectory,
Linear and OperatorAlerts [People Ops providers](PEOPLE-PROVIDERS.md). These make
no live provider calls; mailbox or alert "accepted" does not mean delivered.
People Ops uses separate resource-scoped SQLite stores with stable effect ledgers,
immutable directory captures and typed partial-failure outcomes. Synthetic
deduplication does not establish retry safety for a future live adapter. Adding a
real provider is a separate adapter implementation. A recorded preparation error is
currently terminal for that invocation identity; fresh attempts can resume an
application checkpoint, but automatic provider read retries are not implemented.
An invocation blocked after committing its application decision can also require
an operator recovery API that is not implemented; see the concrete
[operator recovery boundary](OPERATOR-RECOVERY.md).

## Rust enforcement boundaries

`LoadedArtifact` and `Runtime` have private fields and read-only accessors. Runtime
clones share admitted artifact metadata through `Arc`; editable manifests remain
separate records. File integrity, installation bindings and current authority are
still checked at use time. Transaction-only entry points require a SQLite
`Transaction` in their signatures.

Worker messages retain their existing wire representation and replay evidence.
The host decodes them into checked instruction, reply, outcome and phase enums
before interpretation. Pure phase transitions reject observation/mutation
crossings. Database-dependent authorization and revision checks remain inside the
transaction containing the mutation.

Expected host failures carry typed categories and stable codes. HTML, HTTP API
and MCP share one mapping; diagnostic context cannot change the status or public
code. Serialized application failures remain part of the admitted app contract.

## Recovery

A local operator can resolve a **blocked** invocation through native
`recovery-abandon`, `recovery-reissue`, and `recovery-readmit` commands. Recovery
is not an app capability. Each request supplies `expected_revision`, the count of
prior recoveries; stale requests fail with `recovery_revision_conflict`. Repeating
the same request ID and payload returns its original receipt. Recoveries are
append-only revisions without a cap. `abandoned` and `reissued` are terminal;
after either, further recovery fails with `recovery_already_resolved`.

Abandon fences the old invocation from new dispatch and completion, and stores
native effect evidence as **never admitted**, **known result**, or **unknown
outcome**. It may abandon blocked work whose artifact is no longer active, but
`expected_artifact` must still match that invocation. Status receipts expose the
latest resolution and revision, successor identity, and redacted evidence counts.
Unknown outcomes keep their existing budget reservations. A permit checked before
the fence commits may already be in flight; recovery cannot cancel that provider
call, but its late result is still settled and does not run app completion.
Committed child command requests and deferrals remain committed business and are
reported in the recovery receipt; recovery does not recursively abandon them.

Readmit re-admits the **same** blocked invocation against the active artifact
and current authority, after verifying that the recorded actor may still invoke
its operation. It preserves the original journal and effect identities, so known
results are reused and never re-sent; a never-admitted effect can be dispatched
under current authority. An unknown outcome is allowed only when that effect's
capability deduplicates retries. Otherwise readmit fails with
`recovery_readmit_requires_known_outcomes` and identifies the effects. The
original trace guard remains unchanged as evidence of its first decision; the
readmission records its current authority stamp and policy, updates the live
invocation pin, and moves the active block into append-only block history. A
subsequent authority change creates a new active block as usual. For command
request children, readmit refreshes the captured policy only after rechecking the
captured target-row version. Recovery is one invocation at a time; it does not
fence descendants or cascade.

Reissue is narrower: it requires a blocked invocation with no committed decision,
children, or external effects/attempts. It admits the same operation, actor, and
input afresh against current authority, with a deterministic successor identity
and `recovery` authentication. If fresh admission fails, the recovery transaction
rolls back. In-flight calls cannot be cancelled; there is no operator-attested
outcome path or automatic retry/backoff. Local operator assertions are not
production authentication. The recovery schema changed directly in this
undeployed branch; no migration for a deployed database is included.

## Deferrals

A deferral records that a command should be invoked with an input at a due time. It commits atomically with the command that creates it, but it is not a command request: while waiting it has no invocation row, authority pin, or target-version fence. This lets it survive policy changes, deploys, and target edits.

The identity is derived from the instance scope, parent invocation, and shared child ordinal. `Write.defer_until` accepts a due Unix time in seconds; `Write.defer_for` accepts a delay in seconds, with the host computing due time as the origin invocation's recorded clock plus the delay. Both take `I64` publicly, matching `Context.now`, and are converted to unsigned values inside the sealed SDK because the pinned Roc compiler's `roc build` segfaults when an app passes a `U64` through this boundary; negative values are rejected. The delay is encoded distinctly from a due time, and the host validates both against the same 30-day bound (zero delay is due now). When due, the deferral is offered once and freshly admitted against the active artifact and current policy. An admitted invocation is pinned to the current authority stamp; an incompatible command/input is blocked as `deferral_incompatible`, and a currently unauthorized actor is blocked as `deferral_forbidden`. Blocked invocations are retained and excluded from draining. Artifact activation checks every unoffered deferral for command contract and input compatibility. The instance holds at most 1,000 unoffered deferrals. Restore never resurrects pending work held by a backup: each unoffered deferral is marked offered and recorded as a blocked invocation with reason `deferral_restored` in the restore transaction.

## Current scope

This is a local spike with bounded execution: 32 preparation observations, 32
external effects, 64 total interpreter steps, 64 KiB observation results and eight
combined child command requests and deferrals per invocation. Native computation retains the worker timeout.
There is no HA scheduler, automatic worker classification, arbitrary hour-long
backfill, public cancellation API for the new engine, timers, external signals,
human approval waits or generic compensation engine yet. The SDK leaves room to
add those deliberately without introducing a second application job primitive.

The app job SDK, registry, dispatcher, storage runner and `background` instance
binding have been removed. Artifact format 14 contains only command/query bindings;
rebuild older app artifacts before using this runtime. Temporal remains an internal
adapter for the platform's source/build/release workflows. Full-workspace `xtask verify`
builds platform-owned relational, migration and HTTP fixtures and runs their ported
suites. Roc's application-contract glue crash currently prevents full acceptance;
see [verification coverage](VERIFICATION-COVERAGE.md). `xtask verify-reports` runs
the narrower Reports campaign, including the migrated command runtime suites.
