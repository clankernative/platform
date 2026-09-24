# Roc SDK

Start with the responsibility you are working on, not the private transport.
Applications still import `pf.Query`, `pf.Tx`, `pf.Context`, and the other public
modules. The folders below organize platform source; they do not add another
namespace to application code.

## Source Map

| Directory | Responsibility | Start Here |
| --- | --- | --- |
| `contracts/` | Execution context, typed input/output and generated operation handles | [Context](contracts/Context.roc), [Read](contracts/Read.roc), [Write](contracts/Write.roc) |
| `data/` | Model identity, references, generated selections, read-only queries and atomic transactions | [Model](data/Model.roc), [Query](data/Query.roc), [Tx](data/Tx.roc) |
| `data/pagination/` | Bounded collection results and opaque pagination inputs | [CollectionPage](data/pagination/CollectionPage.roc), [Cursor](data/pagination/Cursor.roc), [PageSize](data/pagination/PageSize.roc) |
| `domain/` | Reusable validated values | [WebUrl](domain/WebUrl.roc) |
| `contracts/Handler.roc`, `data/Observe.roc`, `contracts/Effects.roc` | Command/query phases and admitted capabilities | [Runtime contract](../docs/COMMAND-RUNTIME.md) |
| `contracts/Notifications.roc`, `contracts/Carta.roc` | Typed provider packs with explicit host adapters | [Notifications](contracts/Notifications.roc), [Carta synthetic reads](../docs/CARTA.md) |
| `contracts/Schedule.roc` | Platform-owned recurring triggers for internal commands | [Schedule](contracts/Schedule.roc), [plan and current limits](../docs/SCHEDULES-PLAN.md) |
| `web/` | Typed page registration, template references, assets and form fields | [Page](web/Page.roc), [PageBinding](web/PageBinding.roc), [Control](web/Control.roc) |
| `web/markup/` | Existing pure HTML node helpers | [Html](web/markup/Html.roc); applications can use ordinary HTML templates instead |
| `testing/` | Pure invariant predicates, example command inputs and deterministic generators | [Property](testing/Property.roc), [Example](testing/Example.roc), [Generator](testing/Generator.roc) |
| `runtime/` | Generated dispatcher, erased bindings and private worker protocol | [Product](runtime/Product.roc); most app authors need none of this directory |

## Public Does Not Mean Constructible

`Read`, `Write`, model witnesses and codecs have nominal types that apps
can reference. Their constructors are reserved for generated code by the two
mandatory compiler admission profiles. A visible type is not permission to create
an arbitrary capability. `Wire` and `Operation` are not app exports.
Context construction and transaction evaluation are also sealed.

An app registers commands and queries once in `App.definition`. The compiler
infers their types from the callbacks and uses the record keys as operation names.
The platform generates `Commands`, `Reads`, and an internal `AppContract`
handler record. Apps need no `Catalog.roc` or `AppContract` annotation.
See the [Reports walkthrough](../docs/SDK-CAPABILITIES.md) for the
complete path from declarations to handlers, preparation, effects and private completion.

Use [`pf.Api`](contracts/Api.roc) to bind each handler to required structured
meaning, exact field descriptions, typed examples and verification. Commands
also bind executable preconditions and effect bounds. The single root generates
OpenAPI, docs and MCP; there is no optional metadata module. See the
[application contract guide](../docs/APP-CONTRACT.md) and [MCP guide](../docs/MCP.md).

`Api.update_created(model, fields)` permits `Tx.update` only for rows whose native
creation audit belongs to the same invocation, including private completion after
restart. It preserves edit targets, row revisions, declared fields and current
authority. See the [phase contract](../docs/COMMAND-RUNTIME.md) for supporting
records and the stricter operator edit policy.

Chain `.require_all_rows(Data.workflows)` onto a command or query definition when
its business decision depends on complete row visibility, such as proving that
no workflow is pending. Repeat it for each required model. This grants no access:
the host refuses the affected operation with `required_all_rows_unavailable`
unless current effective policy allows every row of each declared model. Policy
activation remains valid, and ordinary filtered operations remain available.
The requirements also appear in generated docs and OpenAPI. See the
[application contract guide](../docs/APP-CONTRACT.md) for inheritance and paging.

All SDK execution values describe pure computation. Rust interprets database and
command requests, enforces current company policy, and owns auditing and effects.
Company-specific source, CI, identity and secret providers are host capabilities,
not SDK modules to import into an app.

Use [typed predicates and ordered pages](../docs/DATA-QUERIES.md) for indexed
field lookups, compound AND/OR predicates, single-row `find`, and business-field
ordering. [Storage index declarations](../docs/STORAGE-INDEXES.md) support single
and compound uniqueness enforced on inserts and updates.

Every operation requires typed verification callbacks. Every model
requires a named invariant; every declared operation/failure pair requires a scenario.
`Api.error` supplies one typed failing example. `Api.error_cases` lets several
commands or queries share one error identity while supplying a typed failing
example for each operation that declares it.
The platform runs the checks through ordinary transactions, durable commands and replay
before selecting a build. Optional demo inputs are an explicit root list;
their filename has no significance. See Reports'
[complete command](../examples/reports/commands/submit/SubmitReport.roc) and
[optional demo](../examples/reports/examples/Demo.roc).
Follow the [application layout](../docs/APP-LAYOUT.md) for new apps and scaffolding.

## How The Package Is Built

[`crates/day2/src/sdk.rs`](../crates/day2/src/sdk.rs) is the explicit catalog of
source paths, published module names, and app exports. `xtask build` checks that
every Roc source has exactly one catalog entry, then stages a flat SDK package.
Missing files, unregistered files, duplicate identities, symlinks and stale stage
contents fail closed. Artifact source hashes retain the grouped repository paths.
This mapping also defines reserved names that application modules cannot shadow.

SDK imports such as `import Model` refer to this assembled package. Check and
build applications through `xtask`, not by invoking the compiler directly on an
unassembled source directory. `main.roc` at this directory's root is the minimal
native ABI header; the full app header is generated from the export catalog.
`types.roc` is the schema-reflection package header. `targets/` holds separately
digest-pinned native linker inputs, not application capabilities.

The HTML template witness is specialized after staging. Admission then creates a
separate restricted SDK stage and requires both compiler profiles to pass before
building the executable. Folder organization does not replace either check.

## Editing And Formatting

Use a blank line between associated methods, keeping a signature immediately
above its implementation. The separately pinned native Roc formatter inserts a
missing separator; its check rejects compact adjacent definition groups.

[Roc style rules](../docs/ROC-STYLE-RULES.md) distinguish the implemented spacing
patch from the still-proposed definition-order diagnostic. The application
compiler and its semantic rules remain unchanged.

```text
cargo run --locked -p xtask -- bootstrap-formatter
cargo run --locked -p xtask -- fmt
cargo run --locked -p xtask -- fmt-check
cargo run --locked -p xtask -- verify
```

`fmt` formats authored Rust and Roc. `fmt-check` is read-only; `verify` includes
the same checks before compilation and runtime tests. Generated outputs and
vendored compiler glue are not reformatted as authored source.
The full-workspace commands use Reports and platform-owned conformance fixtures;
`fmt-reports` / `verify-reports` provide the narrower Reports scope.
See [verification coverage](../docs/VERIFICATION-COVERAGE.md) for current native-build blockers.

When changing a sealed SDK module, review its complete capability surface and
update the explicit admission pin in `admission.rs`. Formatting and comments also
change its bytes. Never disable that check to make a source edit pass.
