# Application layout

[Reports](../examples/reports/App.roc) is the canonical authoring example. Every
app and complete conformance app uses this organization; source overlays mirror
the paths they replace. Create directories when they contain app code.

```text
App.roc                              # explicit App.definition registry
commands/submit/SubmitReport.roc      # definition, handler, meaning and checks
commands/submit/SubmitReportTypes.roc # nominal request types
commands/revise/                      # another complete command and its types
queries/list/                        # complete query and its types
queries/detail/
commands/analyze/AnalyzeReport.roc     # internal analysis command
commands/analyze/AnalyzeReportTypes.roc # captured nominal request
commands/notify/NotifyReady.roc        # preparation, decision, external effects, completion
domain/Title.roc                     # nominal value and executable constraints
domain/Document.roc
storage/Models.roc                   # nominal persistent records; each is a table
shared/ReportView.roc                # shared result shapes and field meaning
verification/ReportInvariants.roc    # checks spanning application state
verification/ReportScenarios.roc     # shared scenario setup, when needed
examples/Demo.roc                    # optional sample command inputs
pages/Routes.roc                     # typed routes and template bindings
pages/Redirects.roc                  # optional redirect routes bound to commands
ui/pages/                           # HTML templates
ui/app.css                          # presentation resources
assets/                             # admitted images
model-identities.json                # committed identity history
```

Each operation has its own folder. The main module keeps its handler, contract,
typed example and verification together; an adjacent `SubmitReportTypes.roc`
declares its nominal `Input := ...` (or `Input : {}` when it takes no fields). Its `definition` passes all
of them to `Api.command` or `Api.query`; a command also binds its execution
requirements there. App imports and registers these complete definitions:

```roc
operations: {
    submit: SubmitReport.definition,
    revise: ReviseReport.definition,
    analyze: AnalyzeReport.definition,
    notify: NotifyReady.definition,
    list: ListReports.definition,
    detail: GetReport.definition,
},
```

To understand a command, start in its module. Visit App for its public name or
the overall composition. Shared output descriptions belong with the shared
shape; there is no application-wide descriptions or checks inventory. Substantial
verification can live under `verification/` and be explicitly passed by the
operation. Model invariants span parent commands, child commands and completion.

Internal commands use the same layout, required contract and verification as
public commands. `Api.internal(...)` excludes them from public routes; generated
`Commands` handles allow atomic requests from other commands. Preparation and
effects are phases of a command or query, not separately registered operations.
See [the runtime contract](COMMAND-RUNTIME.md) for the authoring API.

`examples/Demo.roc` supplies optional sample data through typed command inputs for
local development and demonstrations, registered as `examples: [Demo.definition]`.
Apps without demo data use `examples: []` and need no Demo file. Removing examples
never removes mandatory operation verification.

## Module resolution and identity

Imports use declared module names, such as `import SubmitReport` and
`import Models`, regardless of their folders. The pinned Roc compiler currently
requires these modules in one package. The platform captures the source tree,
validates each top-level module declaration against its filename, rejects duplicate
names across folders (including case collisions), and assembles each module once
beside the generated handles. It does not rewrite app source.
Roc rejects import cycles: generated handles import request types, while operation
implementations import those handles. Adjacent type-only modules keep this graph
acyclic. They are explicitly imported, not optionally discovered metadata. Artifact hashes
retain original paths; `artifacts/build/app-modules.json` maps compiler names to
those captured paths. SDK exports retain their separate explicit sealed catalog.

Moving `storage/Models.roc` into another folder preserves `Models.Report` and its
identity history. Renaming the nominal model itself requires the explicit identity
authoring operation. Nonempty operation inputs use `:=`; the build
rejects registered nonempty codec inputs without nominal identity. An operation
with no request fields uses the structural `Input : {}` type. Its wire value must
be exactly the JSON object `{}`; unknown fields and non-object values are rejected.
Native reflection erases the name of an empty nominal record, so this explicit
empty-input case does not infer a nominal identity from source names. Persistent
models still require nominal records. Shared result aliases
may use `:`. Missing fields or incompatible callback/description types fail the
compiler checks; incomplete prose and unsupported codec shapes fail admission.

Operation inputs may contain bounded structural records and lists, for example
`attributes : List({ key : Str, value : Str })`. These are decoded as typed values
in the same request and transaction; callers need not serialize a second JSON
document inside a string. Nested fields support builtin scalars, optional text,
records and lists. Nested nominal wrappers and model references are rejected
until their codecs are explicitly supported. The top-level nonempty input still
has nominal identity. See [input_shape.rs](../crates/day2/src/input_shape.rs) for
the enforced depth, size and collection budgets. These input shapes do not add
collection or JSON columns to persistent models. Generated API documentation must
describe every nested field, including list elements. JSON API ingress supports
these inputs; generated HTML form bindings currently reject structured fields.

For a decision that needs every visible matching row, use
`Query.collect(selection, maximum_rows)` or `Tx.collect(selection, maximum_rows)`.
They retain the predicate and ordering, start at the beginning regardless of the
selection's cursor/page size, and collect inside the same transaction. The bound
must be 1–256 rows. Overflow returns the platform's `collection_limit_exceeded`
failure; callers never receive a truncated prefix. An invalid bound returns
`invalid_collection_bound`. Ordinary paginated endpoints continue to use `page`.

Folders never register operations. An unregistered helper remains a helper, and
deleting a registered dependency fails compilation. There is no second authored
module manifest or catalog.

## Cross-app contract discovery (in progress)

An operation may opt into a checked export with
`Api.query(...).cross_app({ version: 1 })` or
`Api.command(...).cross_app({ version: 1 })`. The normal build derives its export
manifest from the registered operation and checked types. Unsupported codecs and
internal operations fail admission. The app does not maintain a second schema.

For a selected instance checkout, platform tooling can inspect candidate exports
and create an exact import lock without copying contract digests by hand:

```text
cargo run --locked -p xtask -- catalog-candidate path/to/instance.json
cargo run --locked -p xtask -- catalog-pin path/to/instance.json directory.lookup
cargo run --locked -p xtask -- catalog-resolve path/to/instance.json path/to/import-lock.json
```

These commands verify the instance's selected artifacts. A lock names the
installation, environment, target apps, and consumed operation/version/digests;
resolution rejects missing or changed contracts and conflicting nominal type
shapes. Candidate discovery does not mean an operation is serving or permitted.
`catalog-check-consumers INSTANCE_JSON CONSUMER_LOCKS_JSON` also checks the
supplied caller locks against one candidate and refuses an app import cycle.
The supplied locks are not yet a complete release dependency inventory.

The normal caller build can resolve that lock against the selected instance:

```text
cargo run --locked -p xtask -- build path/to/caller-app --instance path/to/instance.json --imports path/to/import-lock.json
```

Both options are required together. The build rejects a stale pin, another
instance scope, a self-import, or an imported shape it cannot represent. It
stages `ImportedContracts.roc` beside the caller modules and includes the exact
consumed operation packages and transitive type closure in the caller artifact.
The instance scope, selected artifact IDs and unrelated exports stay out of that
artifact, so those changes alone do not alter its compiled contract input.
For a supported structural contract, caller modules can `import ImportedContracts`
and refer to types such as `ImportedContracts.DirectoryLookupInput` and
`ImportedContracts.DirectoryLookupOutput`. Nominal inputs are rejected until
the generator can preserve their identities. The generated module currently
provides types only; authenticated cross-app calls, active catalog publication,
and release dependency inventory are subsequent work.

## Future app creation

The platform's future app-creation workflow must initialize this layout and a complete
`App.definition`. Use the canonical Reports modules as the authoring reference,
not a fixture as a production dependency. Scaffold operation-specific request
types, definitions, contract fields, examples and verification in the operation's folder;
register each complete definition once. Register model identities through the
existing identity authoring capability. Add pages, internal commands and demos only when used.

Scaffolding belongs in the platform's Roc operational workflow and must invoke
the same ordinary build and required verification. A placeholder description or
unfinished check must not gain a bypass. There is no app-creation workflow yet; this
is its required output convention, not an additional runtime manifest.
