# Day2 Roc spike

Roc owns application decisions and platform operational composition. Rust owns
the host, provider adapters, process supervision, admission and enforcement.
Keep platform operations private; apps expose pure examples and generators,
never arbitrary task callbacks or a second operational SDK.
Put operational recipes in ops/*.roc, including step order and verification
campaigns. The CLI, xtask and central CI execute those same recipes through
ops/Runner.roc. Keep Rust capabilities small enough that they do not hide another
recipe. Atomic native operations and mandatory admission/evidence guards remain
Rust. Update the explicit automation::SOURCES catalog when adding a workflow;
the workflow source and executable pins are part of the CI build identity.
Do not add shell, Python, Ruby, or JavaScript automation. This is a local spike,
not production admission. Never change the sibling day2 workspace.

Persistent models are nominal Roc records. Derive relationships and indexed
selections from checked Ref(Model) fields, never from naming guesses. Keep one
copy of app/domain modules; generated Data and Inputs belong beside them in the
staged app so nominal identity is preserved. Reject unsupported codec shapes.

Use docs/APP-LAYOUT.md for all applications, conformance apps and future app
creation workflows. Reports is the canonical example. Each command and query owns its complete definition, contract and verification in its module;
App.definition registers it once. Source overlays mirror the canonical paths.
Do not introduce a global descriptions/checks inventory or a second app catalog.

Require app-owned properties, evaluate complete consistent bounded snapshots,
and persist failed checks for artifact-bound replay. Never silently truncate
verification state or replace the independent reference model with app assertions.
Use `cargo run --locked -p xtask -- verify-fast` and scoped app builds while
iterating. Do not edit covered sources during a full gate. Run
`cargo run --locked -p xtask -- verify` before claiming verification.

SDK source folders are assembled through crates/day2/src/sdk.rs; keep that explicit
catalog, app exports and reserved module names consistent. Do not infer published
names by recursively copying basenames. Public imports stay pf.Query, pf.Tx, etc.
Use xtask fmt / fmt-check for authored Rust and Roc. Keep a blank line between
associated methods with each signature adjacent to its implementation. Wrap Roc
code at 120 columns, allowing unbreakable strings, URLs, comments and identifiers.
The pinned native formatter patch enforces width and group separation through xtask fmt / fmt-check;
bootstrap it with xtask bootstrap-formatter. Apple Silicon app compilation uses the
unmodified official September 12 compiler pinned in toolchain.json. The historical
reflection backport remains documented in tools/roc-compiler. Keep each native
compiler paired with its reviewed ABI generator; Linux retains its separate pin. Review sealed
module byte changes and refresh admission pins explicitly, never bypass the checks.

Keep arbitrary I/O out of the app platform. The native worker exposes only a pure
entrypoint. Its process protocol is private; validate all requested effects in
the supervisor. Generated ABI code is derived from the pinned Roc compiler.
Unsafe authored Rust is confined to the worker's allocator and ABI boundary.

Apps register only commands and queries. Handler.local, Handler.prepared and
Handler.effects describe phases of the same operation. Observe accepts read-only
local queries and admitted capability reads; Effects accepts admitted external
writes. Database decisions and completions are pure Tx programs. Never hold a
business transaction open across an external call. Current local reads, writes,
child-command requests and effect continuations commit atomically. Preparation
reads are revalidated; captured child targets and app edit bounds remain enforced.
The host journals observations and effect results under pinned artifacts and
rechecks current authority. Generated phase and commit boundaries are sealed.
Provider idempotency is capability-specific; never retry an ambiguous write on a
provider that lacks deduplication or reconciliation. See docs/COMMAND-RUNTIME.md.
There is no app job SDK, job binding, job dispatcher or background configuration.
The control plane uses its own private Temporal adapter for release workflows.
Neither Temporal nor arbitrary I/O is an app capability.

Use day2-capabilities for shared instance contracts, not a second company config.
Source/CI/secret provider authority is operator-owned, never automatically granted
to apps. Local operator CLI assertions are not production authentication. Expose
only redacted invocation metadata to users; raw replay evidence needs protected storage.

Use real SQLite for adapter conformance, seeded schedules and proptest for
state-machine tests, and persist replay traces. Unknown schema shapes, policy
states, and artifact identities fail closed. Do not claim full safety-standard
coverage, native hostile-code containment, or production readiness.

Keep platform security pages, app-owned presentation and company branding
separate. Apps own ordinary HTML templates, app styles and native browser JS
under ui/. Roc owns typed view data, not HTML markup. Validate template syntax,
field paths, form bindings and resource references during artifact admission.
Escape dynamic values and validate concrete rendered forms again at runtime.
Browser JS is presentation code, not authored automation or server
code. No npm, package installation or app build scripts. Admit executable
resources and their complete import graph; pin and verify all served bytes.
Dependency admission is supply-chain governance, not a sandbox for app JS.

Generate Assets.roc from admitted images; normalize/rasterize untrusted sources
and scope serving by installation/app/artifact. Escape dynamic HTML text and
attributes; bind HTML form names to generated Roc command/input contracts.
Company branding is an independent content-addressed instance input, not a
global platform constant or a reason to rebuild the app. Never infer domain
intent or presentation from form shape. The Roc business core remains pure.
