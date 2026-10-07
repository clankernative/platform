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
connections/CalendarConnection.roc   # app-owned semantic connection requirement
storage/Models.roc                   # nominal persistent records; each is a table
shared/ReportView.roc                # shared result shapes and field meaning
verification/ReportInvariants.roc    # checks spanning application state
verification/ReportScenarios.roc     # shared scenario setup, when needed
examples/Demo.roc                    # optional sample command inputs
pages/Routes.roc                     # typed routes and template bindings
pages/Redirects.roc                  # optional redirect routes bound to commands
ui/pages/                           # HTML templates
ui/app.css                          # presentation resources
.ui-dependencies/vanilla/            # optional explicitly locked build-only package
assets/                             # admitted images
model-identities.json                # committed identity history
.clanker/                            # optional design-tool data; never captured
```

Root-level `.clanker/` tool metadata and `.ui-dependencies/` are excluded from
ordinary source capture. Optional assembly captures only the package closure
explicitly locked by `ui/ui.lock.json`; raw dependency files are not served.

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
`ImportedContracts.DirectoryLookupOutput`. A pinned query also generates a
function such as `ImportedContracts.directory_lookup(input)`, returning an
`Observe(ImportedContracts.DirectoryLookupOutput)` for a prepared handler. The
host finds one matching operator-granted app-operation binding for the current
invocation; app code supplies neither a binding name nor an actor. It checks the
callee's exported contract digest before dispatch. A missing, ambiguous or stale
grant fails the observation. Nominal inputs are rejected until the generator can
preserve their identities. Commands currently have types only; command receipts,
separate-host transport and delegated command receipts are subsequent work.

During a normal build, mandatory verification supplies each imported query with
the selected callee's checked contract example and a disposable, operation-pinned
grant. The simulated reply is available only for that example input; a different
request fails verification unless it matches the callee's example. These
build-time grants do not become instance authority. An operator still grants the
exact app operation when installing the caller.

For a release-managed installation, `xtask catalog-active RELEASE_JOURNAL
ARTIFACT_STORE COMPANY ENVIRONMENT` derives discovery from activated release
receipts and verifies the selected artifact bytes. `xtask catalog-release-candidate
RELEASE_JOURNAL ARTIFACT_STORE RELEASE_ID` replaces only the approved app and
checks every selected caller's embedded imports against the candidate exports.
Its `base_selection` digest identifies the active composition the candidate
was checked against. Add `INSTANCE` as the last argument to qualify imported
queries against the instance's resource catalog and access policy, and against
validated deployment readbacks for their selected serving targets. A
`ReleaseExecutionHost` configured with `with_catalog_store` enrolls its
installation/environment in catalog-managed activation; configure
`with_catalog_instance` as well for releases with imports. At settlement, the
host qualifies the approved artifact and all selected callers again. The
journal compares the candidate's base selection and serving binding evidence
inside the activation transaction. A missing, changed, or unready imported
target leaves the active pointer unchanged. The instance document is checked
at qualification time; request authorization remains a runtime decision against
activated app authority.

At live dispatch, a compiled imported query reads the release journal's active
caller and callee receipts and checks them against the loaded artifacts. It also
pins the callee's activated authority stamp and document for the duration of the
read. A missing journal or selected release, a stale activated artifact, or an
authority change during the call fails the read closed, even when the old
artifact still exports the pinned contract. Simulated build verification uses
its recorded world and does not consult a live release journal.

## App creation

`day2 platform app-create NEW_DIRECTORY NAME --ui none|html|clanker` initializes
this layout and runs ordinary build/verification before atomic publication.
See [APP-CREATE.md](APP-CREATE.md) for installation and execution approval.
The starter model is educational, not an inferred business domain.

## Connection intent

Declare outbound connection intent in a module under `connections/`, and
register it once in `App.definition.connections`. `pf.ConnectionRequirement`
requires an explicit stable logical ID, revision, owner category, account policy,
usage and a closed semantic access value such as `pf.GoogleCalendar.read_events`.
The build derives `connection_declarations` from the checked native registration;
admission compares those bytes with the compiled app. Scope strings, deployment
URLs, registrations and credentials belong to the private host and instance.

Declaration support does not supply the generated nominal `Use`, Calendar event
execution, or live registration qualification. See the connection declaration
conformance fixture for the currently supported declaration API.
