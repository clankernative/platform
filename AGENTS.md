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
Do not add shell, Python, Ruby, or JavaScript automation. The one exception is a
VM first-boot script (a stack's GCE startup-script, today
deploy/gke/stacks/qualification-runner/startup.sh and
deploy/gke/stacks/gitea-instance-ci/startup.sh.tftpl): it runs before any day2
tooling exists on the machine, so it may be shell. Keep it to installing and
starting what the VM needs; anything after boot is an ops recipe. This is a local
spike, not production admission. Never change the sibling day2 workspace.

Nothing built on this platform has production users or external API consumers
yet. Do not add legacy paths, compatibility shims, deprecation periods, dual
reads or writes, data migrations or staged cutovers for platform APIs, schemas,
artifact formats or app contracts. Change the code and every caller in place,
and delete what it replaces. Deployed canaries and test installations are
disposable: tear them down and redeploy instead of migrating their state.
GoLinks' persisted links are the one exception; preserve them. This rule
overrides any migration, compatibility or cutover section in a proposal.

Persistent models are nominal Roc records. Derive relationships and indexed
selections from checked Ref(Model) fields, never from naming guesses. Keep one
copy of app/domain modules; generated Data and Inputs belong beside them in the
staged app so nominal identity is preserved. Reject unsupported codec shapes.

Use docs/APP-LAYOUT.md for all applications, conformance apps and future app
creation workflows. Reports is the canonical example. Each command and query owns its complete definition, contract and verification in its module;
App.definition registers it once. Source overlays mirror the canonical paths.
Do not introduce a global descriptions/checks inventory or a second app catalog.
Optional first-party creation is `day2 platform app-create`, composed by
ops/AppCreate.roc. UI-free and ordinary HTML remain first-class; Clanker uses an
explicitly execution-approved installed vanilla bundle. Keep its locked package
outside ui/ under .ui-dependencies/, captured only by the generic assembly port.
No downloads, app-owned executable approval or unfinished checks belong in the
scaffold. Preserve atomic fresh-directory publication and source revalidation;
see docs/APP-CREATE.md.

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

Keep `xtask app-contracts` provider-neutral: project admitted typed operation,
route, form and schedule contracts, not component-library or presentation guesses.
Export every registered query, including API-only queries, deterministically under
explicit byte budgets. Preserve normal artifact admission checks; exporter access
never grants execution authority. CLI output must publish private temporary bytes
atomically at the canonical destination, never truncate an existing/hardlinked inode.
Use no-clobber publication for initially absent outputs; replace only the explicitly
checked regular output. Output parents are operator-owned with no concurrent
namespace mutation, not a hostile-directory sandbox. Local-dev exports are private atomic files;
status must bind success to the served artifact and file digest or report an error
without advertising stale output. Test failure paths in disposable private state,
never by mutating shared admitted artifacts or full-gate fixtures. Generic binding
ABI fixtures are versioned, identical producer/host inputs under `crates/day2/tests/protocol/`;
review and pin exact bytes and run them independently, without deriving expected
results from either implementation or weakening host semantics to match a producer.
Generic `ui_key` admits only known scalar identity fields, including checked nominal
`Ref(Model)` fields; never fabricate a string ID or infer a model from its spelling.
Normal registry-bound prefix/UUIDv7 output validation precedes rendering. Generic
key syntax is not nominal validity, row existence, authorization or DOM uniqueness.

Generate Assets.roc from admitted images; normalize/rasterize untrusted sources
and scope serving by installation/app/artifact. Escape dynamic HTML text and
attributes; bind HTML form names to generated Roc command/input contracts.
Company branding is an independent content-addressed instance input, not a
global platform constant or a reason to rebuild the app. Never infer domain
intent or presentation from form shape. The Roc business core remains pure.

UI producers are optional build adapters, never runtime SDKs. The app-owned
ui/ui.lock.json is the sole schema-1 provider/package manifest; legacy flat locks
are unsupported. A lock pins data, not executable authority. Explicit dependency
restore may acquire reviewed exact-version release bytes before a build; it must
not choose latest, fetch during compilation or require a sibling source checkout.
Keep the host binding ABI implementation independent of the producer and test the
identical versioned vectors in crates/day2/tests/protocol/. Producer package
verification, static preview, native admission and browser acceptance are distinct
gates. Architecture drawings under docs/architecture/ui-toolchain/ record intent,
not production qualification or a CI/deployment topology decision.
