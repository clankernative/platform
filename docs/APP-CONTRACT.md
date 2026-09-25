# Required application contracts

Start with [Reports App.roc](../examples/reports/App.roc). `App.definition` is the
single application definition; OpenAPI, reference docs and MCP are projections.
No production metadata is imported from a test fixture. A module filename does
not activate documentation, verification, stylesheets or scripts.

| Read this file | What it owns |
| --- | --- |
| [Reports App](../examples/reports/App.roc) | Namespace; one operations record with public and internal commands; named pages, model checks, error cases, examples and presentation |
| [SubmitReport](../examples/reports/commands/submit/SubmitReport.roc), [GetReport](../examples/reports/queries/detail/GetReport.roc) | Complete operation: request, handler, structured contract, typed example and verification |
| [AnalyzeReport](../examples/reports/commands/analyze/AnalyzeReport.roc), [NotifyReady](../examples/reports/commands/notify/NotifyReady.roc) | Internal commands with preparation and external effects |
| [Models](../examples/reports/storage/Models.roc), [Title](../examples/reports/domain/Title.roc), [Document](../examples/reports/domain/Document.roc) | Tables and their keys, and executable text rules; the committed identity ledger names each table |
| [Api SDK](../sdk/contracts/Api.roc) | Required command/query constructors, verification, errors and execution requirements |
| [Registry inference](../crates/day2/src/registry.rs), [application contract](../crates/day2/src/app_contract.rs) | Derive codecs and exact application/description types from checked wrapper witnesses; generate final handles and dispatcher |
| [Build workflow](../ops/Build.roc), [Check workflow](../ops/Check.roc) | Required compiler, admission, native build and behavioral verification order |
| [Operation catalog](../crates/day2/src/operation_catalog.rs) | One admitted representation consumed by HTTP, OpenAPI, docs and MCP |
| [Artifact loader](../crates/day2/src/artifact.rs) | Strict format 13 contract validation against compiler evidence and compiled worker |

Follow the [application layout](APP-LAYOUT.md), including when scaffolding new
apps. Each operation module exports its complete `definition`; App binds that
value to its public name. Each public record field contains `Api.command({ handler, contract, execution,
verification })` or `Api.query({ handler, contract, verification })`. These are
abbreviated signatures; the actual compiling example is Reports. Keys provide
names, so a command and query cannot have the same public key: Roc rejects the
duplicate record field. Internal commands use the same record and bind
`Api.internal(...)` execution. Helpers become operations only through this root.

The compiler checks required root fields, callback signatures, exact nested
description records, typed examples and selectors. Both mandatory final profiles
consume generated `AppContract.Product`; the type is not an unused annotation.
`Commands`, `Reads`, `Selectors`, `Data`, `Inputs`, `Outputs` and `Domains`
are generated. Applications retain their nominal data types but do not maintain
separate input/output codec inventories. The persistence registry remains
explicit so removing the last endpoint for a table cannot delete its history.

Bootstrap reflection follows the explicit storage import and uses provisional
handles to break the data/handler import cycle. The final checked wrapper's type
witnesses determine membership and codec reachability. Provisional handles are
replaced, and the whole app is rechecked under normal and restricted interfaces.
The pinned compiler needs a temporary selector representation during bootstrap;
the captured sealed representation is restored before final admission.
Operation definitions use function type witnesses to avoid the compiler's native layout
crash for distinct nominal payloads/results with identical fields. After discovering
operation names, the platform generates exported identity functions checked against
those exact registered definitions; these expose their types to native reflection.
Both final profiles still consume the complete application type. Historical
artifacts with list witnesses remain readable.

Compiler layout boxes are explicit in `SchemaGlue` metadata. Registry inference
resolves finite box chains to the original payload type IDs before deriving
storage and API contracts; nominal identity and all codec bounds remain intact.
Malformed references and box cycles fail admission. This structural projection
does not determine native memory layouts: Rust glue uses the compiler's committed
ABI directly, and artifacts retain the original reflection evidence.

Build admission rejects empty required prose, missing or extra descriptions,
unsupported codec shapes, invalid typed examples, stale routes/resources and
inconsistent identity history. Complete standard text descriptors drive sealed
Roc construction, codecs, host checks, JSON schemas and UTF-8-aware form helpers.
`Text(Title)` and `Text(Document)` retain distinct nominal identities even though
their JSON values are strings. Arbitrary custom predicates are not supported as
new-format text domains; they cannot silently escape this shared rule system.

Optional text fields have the same checked wire representation in storage,
operation inputs and outputs: `[None, Some(Str)]` encodes as `"None"` or
`{"Some":"text"}`. The Some string is bounded to 16,384 UTF-8 bytes; an empty
Some string remains distinct from None. Other union payloads are not admitted by
this codec. Generated encoders, verification decoders and API schemas preserve
these tags instead of replacing absence with an empty string or JSON null.

Command `execution` contains enforced effect bounds and any mandatory revision
guard. Reports revise binds its model, reference and expected version through
typed selectors. The host enforces that guard even under a `CurrentState`
operator policy. Policy can restrict access further. Queries stay read-only;
internal commands retain captured targets, revisions and allowed effects.
See [the phase contract](COMMAND-RUNTIME.md) for preparation and delivery.
An effect bound describes what may happen, not a promise that every effect occurs.

Use `Api.update_created(Data.workflows, [Api.field(Selectors.workflows_status)])`
when a command creates a supporting row and later updates it through `Tx.update`.
This applies in the same transaction and in private completion after a restart.
The host requires the exact row's native creation audit to belong to this
invocation. A row created by an earlier invocation, including the parent of an
internal command, does not qualify. An `Api.edit` primary model remains bound to
its exact input reference; creating another row of that model cannot bypass it.
Ordinary `Api.update` and `Api.update_created` cannot both declare one model.
Current authority, declared fields and observed row versions still apply.

`Context.authentication` reports what established the invocation's authority:
`Request` (an actor asked and the host authenticated them), `Schedule` (nobody
asked; the instance bound one), `CommandRequest` (another command in this app,
inside its transaction), `Ingress` (a signature established the sender),
`Delegated` (another application asked for the same effective actor), or
`Other(Str)` for a cause this SDK predates. It is read from the invocation
record, never from input, and it is the same fact the audit log records — so
what an application branches on and what an operator reads afterwards cannot
disagree. It is stable across preparation, execution and replay, which is what
makes it safe to decide on.

`context.actor()` is the effective actor authorized by the host. It need not be
the authenticated requester: `context.acting()` is `Directly`, or
`ForAnother({by, rule})`, with `by` equal to `Person(name)` or
`Application(name)`. The rule names the operator's outermost impersonation rule;
an app-to-app hop uses the admitted resource grant and leaves that field empty.
`context.caller()` is `External` or `Internal({application, chain})`, where
`application` is the immediate caller and `chain` lists applications oldest
first. Apps cannot construct these facts or override them through input.

For a prepared cross-app query, resolve an operator-owned binding with
`Resource.bind(context, "delegation")`, then call `Delegate.query(resource, "{}")`.
The resource pins the callee and its query schema; the effective actor is inherited,
not a method argument. The answer is recorded JSON for deterministic replay.
The callee independently authorizes the actor. See the complete
[request identity fixture](../fixtures/delegation-conformance/README.md) and
[HTTP request contract](WEB.md#acting-on-behalf-of-another-actor).

`Api.soft_delete(Data.tickets)` declares deletion. The same declaration also
permits `Tx.restore` on that model: an operation allowed to delete a row must
be able to undo it. See [DELETION.md](DELETION.md).

Declare complete read visibility separately from write effects:

```roc
definition = Api.query({
    handler: Handler.local(handle),
    contract,
    verification: { input: verify_input, check: verify_result },
}).require_all_rows(Data.catalogs)
  .require_all_rows(Data.policies)
  .require_all_rows(Data.policy_rules)
```

Both command and query definitions support this typed model builder. Existing
definitions default to no requirements; `.required_all_rows()` exposes the model
names to generated metadata. Admission rejects unknown or duplicate models and
more than 64 requirements per operation. It does not silently remove duplicates.

Use this when hidden rows would alter a business decision: missing parent policy
rules would change inheritance, a hidden latest revision would expose stale
policy, or a hidden pending workflow would permit conflicting work. It applies
even when the handler uses a filtered lookup or asks for only one matching row.
Explicit-ID reads and pages whose meaning is simply the currently visible rows
can retain ordinary row filters.

This requirement grants no additional access. Under the current effective
operator policy, every declared model must have unfiltered read scope; otherwise
the host refuses the affected operation with `required_all_rows_unavailable`
before application execution. Narrowing or revoking policy remains valid and
does not disable unrelated operations. Current authority is still enforced when
durable work resumes; the declaration does not freeze old permissions. Generated
docs expose required visibility and OpenAPI carries `x-day2-required-all-rows`.
Read completeness does not remove collection bounds: `Query.collect` and
`Tx.collect` still fail when a complete visible result exceeds their budget.

`Tx.reject` and `Tx.from_try` accept generated `Failure` handles. Each root error
case requires a description, recovery guidance and typed failing scenario; the
operation contract explicitly lists its failures. Trusted host errors use a
separate sealed path. HTTP and MCP share failure rendering. The authority
conformance fixture demonstrates a declared business failure; Reports currently
declares an explicit empty error record.

`Api.error` keeps the single-operation form. Use `Api.error_cases` when commands
or queries share the same failure identity:

```roc
invalid_input = Api.error_cases({
    description: "The requested business values are invalid.",
    recovery: "Correct the values and submit a new request.",
    verification: |_| [
        Api.failed_command(Commands.policy_upsert, UpsertPolicy.invalid_input),
        Api.failed_query(Reads.effective_policy, EffectivePolicy.invalid_input),
    ],
})
```

Each generator retains its operation's actual input type. Admission requires a
nonempty list, exactly one case per declaring operation, and no duplicate,
undeclared or mismatched targets. The campaign executes every operation/error
pair with deterministic inputs and checks the exact error, unchanged application
state, trace replay and duplicate delivery. Shared wording never substitutes for
an executable case. Platform capacity and authority failures stay on the sealed
host path; they do not need fabricated business-error examples.

Every persistent model has a typed invariant registration. Every public operation
has required typed verification; declared failures have required cases.
The campaign checks actual results, model snapshots, rollback, replay, duplicate
receipts and background completion, retaining the platform's independent oracles.
It compares executed counts with the exact obligation inventory. Demo examples
are an explicit list and may be empty; zero generated cases never count as a
verified build. The normal build runs at least two cases per obligation before
selecting its artifact. Longer campaigns use the same Roc workflow.

Storage must bind `model-identities.json`. Ordinary builds are read-only.
`xtask register-model APP TABLE Models.Type`, `rename-model APP OLD NEW Models.Type`
and `retire-model APP TABLE` are explicit authoring actions. Commit the ledger;
history cannot be reconstructed from today's model names. Presentation explicitly
names its stylesheet/script (empty strings mean absent); named pages bind their
templates. An optional `redirects` record registers `Redirect.route(...)` declarations,
each binding one public command and one text field of its result; admission
checks them against that command's contract (see [redirect routes](WEB.md#redirect-routes)). Resources and source overlays are captured before packaging, and
platform inputs are checked for changes before publication and selection.

Format 12 requires a complete contract. The loader rederives types/registrations,
checks resources and compares the serialized contract and manifest with the
compiled worker. Rehashing an edited manifest cannot bypass these checks. Older
formats retain their explicit historical decoding path and do not acquire these
new guarantees. This is still the local spike's admission model, not signed
production provenance or hostile-native-code containment.

Use `xtask contract-diff PREVIOUS_ARTIFACT NEXT_ARTIFACT` for a conservative JSON
report of public removals, input/result/constraint changes, errors, execution,
storage and internal commands. Descriptions/examples are reported separately from wire changes.
The report does not migrate clients or databases; installed schema transitions
still use the explicit migration/activation protocol. Activation checks existing
stored text against the target domain rules and validates the existing policy
against the target operations before changing the installation binding.

Required structure cannot prove that arbitrary English remains true, that an
assertion expresses the intended business rule, or that a new helper was meant
to be public. Behavior changes still need meaningful tests and review. Scaffolding
is an editing convenience, not an enforcement boundary; unfinished fields cannot
pass the same required checks.

Run `cargo run --locked -p xtask -- verify-reports` for this workspace's Reports
campaign, compiler negatives, shared transport tests and control checks. The full
`verify` command additionally builds platform-owned relational, migration and HTTP
conformance fixtures. See [coverage and acceptance](VERIFICATION-COVERAGE.md) for
the suites still awaiting successful native builds.
