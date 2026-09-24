# Spike Findings

## Decision

Roc is a credible candidate for the application language. The spike demonstrates
that an app can own real multi-row business decisions while the platform owns
I/O, dispatch, storage generation, and durable execution. Continue evaluation;
do not replace the F# implementation solely on this result.

Rust was chosen for the host because it provides a native ABI, explicit ownership
at the small unsafe boundary, mature SQLite bindings, and a property-testing
ecosystem. Authored operational automation is Rust too. Roc is used for app/SDK
logic and the compiler's own typed glue interface.

## Established Evidence

The repeatable entry point is cargo run --locked -p xtask -- verify. It rebuilds
both schemas and runs the actual compiled Roc app; the CRM is not reimplemented
in Rust. Verification fails rather than skipping when the required compiler,
artifact, sandbox, or migration fixture is missing.

- Checked Roc metadata produces real tables, typed handles, input decoders,
  foreign keys, and indexes.
- Nominal model-specific references produce foreign keys and typed indexed
  selections without string relationship declarations. Reference DTOs reject
  lossy numeric JSON and noncanonical strings.
- The app's opaque Title constructor validates both command inputs and decoded
  rows. The generated API rejects wrong-model IDs and forged opaque records.
- Four-write moves preserve counters/history and demonstrate read-your-writes.
- Injected rejection and real process exit at every write leave no partial
  domain state; pending work resumes and completed work deduplicates.
- Version races have one winner. App/installation scope changes fail closed.
- Recorded decisions replay, including effect rejection.
- Company-owned policies require explicit operation/model grants, owner/admin
  row scope and update-field ceilings. Missing policies deny execution rather
  than inheriting broad app membership permissions.
- Single-target Edit guards check caller versions before worker startup; text
  constraints apply independently of app constructors. The owned Links fixture
  deliberately omits app ownership/version checks, and hostile effect fixtures
  exercise forbidden fields/targets and transactional rollback.
- New traces retain host precondition evidence and replay pre-worker failures;
  the accepted authority epoch and revision are checked transactionally before
  effects and completion. Identical restored policy does not revive stale work.
- A seeded proptest campaign compares SQLite state with an independent model;
  failures are shrinkable and regression seeds are persisted.
- The same campaign evaluates the CRM's three Roc-owned invariants over complete
  typed snapshots. Corrupt-state fixtures prove the predicates can fail, and
  their saved artifact-bound snapshots reproduce the exact failed checks.
- Additive migration preserves existing and non-null optional data, drains
  pending work, rejects forged/destructive plans, and re-applies idempotently.
- Native positive controls establish file/network/process access outside the
  worker sandbox and denial inside it. Nontermination and oversized frames fail.
- A valid relative compile-time file import works outside the compiler sandbox
  and fails inside. Absolute-import rejection alone was not accepted as evidence.
- Incorrect field types, same-shape nominal substitutions, wrong query references,
  misspelled generated query fields, and Tx-as-Query assignments fail compilation.
  Duplicate dispatch/property keys and changed executables fail admission checks.

The machine-readable evidence is artifacts/verification.json and
artifacts/simulation-report.json. They identify the exact tested artifacts and
actual schedule coverage. Company demo traces live only in ignored .state
directories. These are unsigned local evidence, not production certificates.

## What Roc Removes

The supplied app platform exposes no arbitrary file, socket, process, clock,
randomness, database, or secret API. Its entrypoint is pure. This removes a large
category of F# ambient-effect bans from the application authoring surface.
Time is captured by the host; identifiers are derived by the host.

Roc's compile-time file ingestion still requires build isolation. Purity does
not imply termination, reasonable resource use, business correctness, current
authorization, tenancy, transactional durability, or safe migrations. Those
remain platform responsibilities.

## What Still Needs Guards

There is no claim of complete FSharp-Safety-Guard plan coverage. Equivalent
semantic rules would still be needed for:

- Domain constructors beyond the supported text-wrapper codec convention,
  including contracts that prove every relevant invariant rather than just shape.
- Scope-specific identifiers; Ref(Model) is model-specific, not installation-bound.
- Exhaustive domain errors and explicit overflow/partial-operation policies.
- Query shape/index budgets and forbidden implicit scans. Newly built API output
  catalogs now require bounded `CollectionPage` values (100 items each), but that
  does not guarantee an index is used or bound rows examined by SQLite.
- Migration compatibility, immutable dependencies, and artifact provenance.
- Property adequacy, app-authored generators, and negative fixtures for every guard.
- Output contracts, transport codecs, and safe renderer boundaries.

Some belong in types, some in compiler-metadata admission, and some in host
checks/tests. This spike uses structural compiler metadata, not a complete
semantic call-graph/AST linter. Adding regex source bans would not close that gap.

## Limits And Follow-On Work

This is a pinned nightly on macOS ARM64. The compiler and its generated ABI are
trusted dependencies. The selected nightly sometimes emits an additional
compile-time crash diagnostic after a legitimate type error. Its tools and ABI
must be evaluated over time, not treated as a stable product contract.

The SQL model subset is intentionally restricted. There are no arbitrary joins,
aggregates, nested persistent unions, decimals, deletions, or user SQL. Query
selections cover unfiltered pages and equality on derived reference indexes,
not arbitrary typed relational expressions. There is no LINQ/EF Core equivalent.
Input handles and stored-row codecs are generated; output projections are explicit.

References use lossless decimal-string input/output in the CRM and integer
storage internally. Keyset cursors, versions, and timestamps still use numeric
I64 in the CLI. The HTTP form adapter preserves integer text without passing
through JavaScript numbers, binds row versions in opaque signed tickets, and
generates page URLs with lossless cursors. A future public JSON API still needs
explicit browser-safe numeric contracts. The authoring
surface is not a complete opaque DDD model: stage names, counters, domain errors,
and other business values still use primitive types.

Generated-only factories now have an explicit compiler-admission boundary. The
same authored source bytes must check against both SDK profiles: the execution
profile has the original factory names, and an admission-only profile renames
them while adapting generated modules. Direct, aliased, first-class and dead-branch
source references must resolve in both checks. Factory-bearing SDK
source fingerprints are pinned for review. This is not a regex source ban or
a claim of arbitrary behavioral equivalence between profiles; compile-time
source imports can observe their differences. It does not make native worker
effects authoritative. Host schema, policy and transaction guards remain required.
Ref.from_str/from_i64 likewise prove representation, not row existence or access.

Company policy now supplies independently enforced nonempty/byte constraints
for nominal text, full-row owner/admin scope, explicit operation/model grants,
update-field limits and single-target Edit preconditions. These are not arbitrary
Roc predicate proofs, field-read projections or relationship-target policies.
Admins still need operation permissions and cannot bypass an owner-scoped grant's
model-wide owner immutability, even through another `rows: all` operation.
Owned-model creates assign the caller under every grant. Completed receipts
also require unchanged captured policy, not just newly sufficient permissions.
CurrentState is an explicit broader concurrency choice; the
CRM multi-model move retains that mode and its app-written version/counter checks.
See [AUTHORITY.md](AUTHORITY.md) for the exact contract and fixture boundaries.

The local HTTP/HTML adapter now exercises MPA forms, Datastar patches, server-side
development sessions, atomic redacted audit changes and an audit viewer. App
images/icons and company branding are independently admitted content-addressed
inputs, not a universal platform asset set. See WEB.md for boundaries and tests.

The private Rust control plane now has a durable journal/outbox, real local
Temporal execution, GitHub source/check adapters, a version-pinned GCP credential
resolver and an isolated local build recipe. See [CONTROL-PLANE.md](CONTROL-PLANE.md)
for its separate evidence and limits. These capabilities are not exposed to Roc
app commands. Apps use command/query phases and durable invocation journals;
see [COMMAND-RUNTIME.md](COMMAND-RUNTIME.md). The shared Notifications capability
has a local mailbox adapter and deterministic model. Production provider adapters,
unbounded commands, production identity, distributed/HA deployment, multi-region
operations and production infrastructure remain absent.
Exhausted durable executions still need operator recovery; there is no production
dead-letter workflow or cross-app transaction.

The simulator covers local invocation schedules, not every operation in
RADICAL.md. Roc owns invariant predicates; Rust still owns the generated schedules,
reference model, and shrinking. A nonempty catalog cannot prove that predicates
are adequate or that an app is correct. Snapshots are capped at 256 rows per model
and the worker's frame budget; there is no sampled/truncated success fallback.
Failure snapshots are complete within that budget, but they are not independently
minimized. Cross-provider traces need a future evidence protocol.
Properties are not commit constraints. Host guards prevent their declared
violations without handler cooperation, but cannot prove all allowed business
decisions correct. Browser JavaScript still carries the authenticated session's
authority; this backend slice does not prove user intent or isolate native app JS.
Private inputs, observations and precondition evidence also retain raw business
data. The new control plane excludes secret values from its journal and Temporal
history, but business-trace classification and production retention remain absent.

Native sandboxing here is macOS-specific and not a multi-tenant security
certification. There is no whole-process RSS quota or build-memory quota.
Same-user local administrators remain trusted. Package signing, hermetic
toolchain distribution, bit-for-bit rebuild proof, semantic admission evidence,
and an immutable deployment controller are missing. Content addressing is not
signature verification.

The durable capability foundation remains isolated from app execution. Its next
gate is a disposable company-owned repository plus Linux execution/containment
and deployment, alongside SQLite/PostgreSQL semantic conformance. Keep fleet
migration gated on those operational guarantees and app-level coverage.
