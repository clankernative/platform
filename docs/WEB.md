# Web Authoring And Ownership

This slice is a real loopback HTTP server, not a production identity adapter.
App decisions still run in the pure native Roc worker. Rust owns HTTP, sessions,
CSRF, transaction dispatch, rendering, asset admission and mandatory auditing.

The current Links proof of concept uses ordinary app-owned HTML/Jinja templates,
CSS and native browser modules. Roc supplies typed query data and business
commands, not a page-building DSL. See [UI-POC.md](UI-POC.md) for the file map.

## Live queries over SSE

SSE is the platform transport for live frontend updates. A live page subscribes
to its existing registered query; there is no third operation kind, app-owned
subscription handler, WebSocket endpoint, or arbitrary I/O in Roc. Normal query
API calls still return one JSON result and commands retain their HTTP POST,
CSRF, authority and durable invocation contracts.

Call `.live()` on a `Page` to refresh after local business writes. Call
`.live_refresh_every(1000.U64)` for a query with external reads or time-dependent
output; this also enables live updates and adds a server refresh interval.
Nonzero intervals must be between 1000 and 60000 milliseconds. Zero means no
periodic refresh. Dependency freshness is an explicit author responsibility:
the current operation catalog does not identify external or clock dependencies.
Defaults and live options can be chained in either order.

Templates mark display regions with literal, unique IDs and the empty
`data-live` attribute, for example `<section id="report-result" data-live>`.
Admission checks every structural variant: region roots must exist with the
same IDs in every branch, stay outside loops, and cannot nest or contain forms,
editable controls, or contenteditable elements. Loops and conditionals are
allowed inside a stable region. Command forms on live pages also require stable,
unique literal IDs outside loops. Runtime checks validate the actual targets.

The host renders the initial full HTML and generates a Datastar initializer
outside the patched main region. It opens `GET /_live?path=<encoded page URL>`;
the shared route codec validates that URL and all query inputs. The endpoint
requires the current session, a Datastar request, and same-origin fetch metadata
when supplied. Datastar's optional signals parameter must be an empty object;
it cannot override the typed page inputs. The `/_live` namespace is reserved.

The stream sends an initial authorized snapshot as a `datastar-patch-elements`
event, then morphs only changed live regions. Command responses separately patch
the acknowledgement and replace the submitted form after success. Rejections
retain the draft and its original signed ticket/version; a stale edit requires
a deliberate reload. Live data never silently rebases an in-progress edit.
If a prepared page read conflicts with a concurrent completion, the host retries
that query with fresh invocation IDs, up to three attempts. It never reissues the
command for rendering. Transport failures retain the form and show a prompt to
retry it using the same durable invocation ticket.

The storage interpreter advances a durable per-app revision in the same
transaction as each model change. Rollbacks, duplicate invocation delivery,
query receipts and ordinary audit writes do not advance it. Both initial command
decisions and later completion writes participate, regardless of their caller.
The server checks the revision every 250 ms and coalesces changes before rerunning
the query; browsers do not poll. Each subscription samples the revision before
rendering, so a concurrent commit forces another pass instead of being missed.
This first version invalidates broadly across the app and does not infer a
precise dependency graph or share rendered data between actors.

Each refresh keeps the existing bounded query interpreter, output validation,
read guards and audit evidence. Idle streams hold no worker, database transaction
or ordinary HTTP request slot. A host permits at most 64 live streams and one
queued patch per stream. Heartbeat comments are sent every ten seconds. Slow
clients and transient failures reconnect through Datastar and obtain fresh
snapshots; intermediate states are not an event-delivery guarantee. Transient
SSE admission failures use an interrupted SSE body so Datastar's native network
retry applies, while authentication failures remain terminal.

Session, binding and current authority are checked even when data is unchanged,
and again after rendering before releasing data. Policy changes cause refresh;
revoked sessions or access clear live regions and terminate the stream. Shutdown
stops stream producers. The platform status region surfaces connection failures.
Query evaluations currently retain the writer-lock and receipt cost of ordinary
queries, so this is a bounded local implementation, not a high-fanout runtime.

[Reports](../examples/reports/README.md) demonstrates live list updates,
asynchronous analysis completion, periodic notification-status refresh and draft
preservation across two browser windows.

## Built-in JSON API And OpenAPI

Every admitted app has the same platform-owned endpoints when served with
`serve-local`, including apps that register no pages:

| Endpoint | Purpose |
| --- | --- |
| `GET /openapi.json` | OpenAPI 3.1.1 document generated from checked operation contracts |
| `GET /docs` | Searchable API reference with schemas and a request console |
| `GET /api/session` | Current actor and session-bound CSRF token |
| `GET /api/{operation}` | A registered query, with URL query parameters |
| `POST /api/{operation}` | A registered command, with an `application/json` body |
| `POST /mcp` | MCP discovery and tool calls from the shared operation catalog |

For example, Reports exposes `GET /api/reports.list?after=&limit=20` and
`POST /api/reports.submit`. Methods come from the declared command/query kind;
apps do not maintain HTTP bindings or a separate schema. The same platform
catalog supplies dispatch and documentation. Inputs and successful JSON results
use the admitted Roc wire contracts, including typed command results, typed
reference IDs, opaque cursors, bounded collection pages and nominal text domains.
Domain constructor validation still runs in Roc; the spec describes the wire
shape and identifies constraints that require application validation.

The first path segments `api`, `docs`, `openapi.json`, and `mcp` are reserved. Admission
rejects app pages that use those namespaces, including descendants, encoded
aliases and dynamic path segments that could overlap them. There is no app
configuration to rename, disable or replace these endpoints. Platform dispatch
also handles them before app routes. Datastar `/actions`, HTML pages, assets,
audit, verification and internal command handlers are excluded from the
business API specification. Unregistered operations are never dispatched.

Docs, spec and API calls require the app's existing session. The raw spec is
machine-readable but not anonymous. Any actor with access to a public operation
can read the app's full public contract; individual operations enforce current
authority on every call. No production API credential mechanism is introduced.
An app without pages redirects its root to `/docs` after sign-in. App templates
can link to these fixed URLs with `platform.docs()` and `platform.openapi()`.

Queries require every declared field, even fields that have defaults on an HTML
page. Use scalar URL parameters; `OptionalText` parameters carry JSON, such as
`"None"` or `{"Some":"value"}`, before URL encoding. Missing, extra, duplicate,
malformed or out-of-range fields fail with HTTP 400. GET calls cannot invoke
commands. Unsupported methods receive HTTP 405 with an `Allow` header.

Commands require the session cookie plus these headers:

| Header | Value |
| --- | --- |
| `Content-Type` | `application/json` |
| `Origin` | The exact app origin; supplied automatically by browsers |
| `X-CSRF-Token` | `csrf_token` from `GET /api/session` |
| `Idempotency-Key` | 1–128 ASCII letters, digits, underscores or hyphens |

Keys are scoped to the authenticated requester and app installation, not the input or operation.
Retry an uncertain command with the same key and identical input. Reusing a key
with different input or another command returns HTTP 409; a successful retry
returns the original typed result without repeating committed effects. Choose a
new key for each new command. Success returns the typed JSON result directly,
with `X-Day2-Invocation` identifying the durable business invocation. Queued
background work may still be running after the command succeeds.

Failures use `{"error":{"code":"…","message":"…"}}`. The spec documents
authentication/authorization errors, conflicts, application rejection and
transport failures. Requests retain the host's 64 KiB body, 8192-byte URI and
three-second body-read limits. Responses remain `Cache-Control: no-store`.
The docs console sends commands only when explicitly submitted, preserves the
key for retries, and forwards JSON text without rounding 64-bit integers.
It uses embedded platform CSS/JS with ETag revalidation, a strict CSP, and no
app scripts, CDN dependencies or package installation.

### Acting on behalf of another actor

The session-authenticated JSON operation API supports a request-scoped
`X-Day2-Act-As: customer` header. It selects the effective actor; it does not
authenticate the requester. The requester always comes from the server's session
record. Forwarded-user headers and business input fields cannot replace either
identity. Omitting the header preserves ordinary direct-request behavior.

Every request carrying this header, including a GET query or status read, must
send exactly one `Origin` matching the app origin and a valid `X-CSRF-Token`
from `GET /api/session`. The target header must occur exactly once and contain a
valid nonempty actor. Cross-site fetch metadata is rejected. The host requires an
active operator delegation rule with `paths: ["request"]`, then independently
checks the target's membership, operation, model and row permissions. A rule
for `ingress` is not usable by a session. See [AUTHORITY.md](AUTHORITY.md).

For example, a signed-in support client can send:

```http
GET /api/delegation.who HTTP/1.1
Origin: http://127.0.0.1:PORT
Cookie: SESSION_COOKIE
X-CSRF-Token: SESSION_CSRF_TOKEN
X-Day2-Act-As: customer
```

Command requests add the ordinary JSON and idempotency headers. Preserve the
target, operation, input and key on retry: changing the target under the same
requester's key returns 409. `Prefer: respond-async` works unchanged. Follow its
`Location` with the same authenticated requester, target header, origin and CSRF
token; status access checks both identities and the current delegation rule.
Revocation blocks subsequent admission and on-behalf-of status access, including
retries of completed commands. Authority revisions also invalidate pending work
under the normal runtime rules.

The header never changes the session; `/api/session` continues to identify the
requester. A principal with only a request delegation rule can sign in and read
the public contract, but has no direct business-operation permission. This does
not add an impersonation picker to the docs console. HTML, signed forms, SSE,
MCP, audit, login and documentation routes reject the header rather than silently
interpreting it as a direct request. Production SSO/gateway authentication remains
outside this loopback slice.

Roc reads the effective actor through `context.actor()` and the verified
requester/rule through `context.acting()`. `Delegate.query` inherits the effective
actor; the callee independently authorizes it and sees the immediate calling
application through `context.caller()` and `context.acting()`. Admission,
execution, replay and mandatory audit preserve these identities. The audit event
`actor` is the effective actor and `initiator` is the verified requester at that
hop. See the executable [conformance fixture](../fixtures/delegation-conformance/README.md).

## Descriptions And Examples

OpenAPI, MCP and this reference share one admitted operation catalog. Each
operation's required contract in `App.definition` supplies structured intent,
complete field meaning, typed examples and typed relationships. See the
[application contract](APP-CONTRACT.md) and [MCP guide](MCP.md).

Typed `Ref(Models.Report)` fields generate string schemas with the model's saved
prefix, exact length, UUIDv7 pattern, and valid examples. Shared `Id_<prefix>`
components appear in OpenAPI. Use typed references in output contracts as well
as inputs; converting an ID to `Str` discards that metadata. See [IDs](IDS.md)
for storage, prefix assignment, and the explicit integer-ID migration.

Numeric domains are retained from the checked Roc types. `U8`, `U16`, `U32`,
and `U64` inputs and outputs have a minimum of zero and their exact width's
maximum; generated codecs and host validation enforce those bounds. `I64`
remains signed. Standard app fields use 64-bit types: `U64` for nonnegative
counts and `I64` for signed quantities. Smaller widths remain supported for
explicitly narrower contracts. SQLite model fields support `U8`, `U16`, and
`U32` with matching integer checks. Persistent `U64` fields use eight-byte
big-endian blobs, preserving the full range and ordering without rounding or
signed overflow. Generated codecs and API responses still use JSON numbers.
Changing an existing integer column to `U64` requires a schema migration;
the current migration planner refuses automatic field-type changes.

Use `pf.RowVersion` for host row revisions. It wraps `U64` but accepts only
`1..=I64.max`, matching the host's SQLite revision counter. It encodes as a
JSON number and generates `format: uint64` and `minimum: 1`, with the same
maximum enforced at runtime. `Model.Entity.version` already has
this type; preserve it in response fields and expected-version inputs. Construct
examples with `RowVersion.one` or the checked `RowVersion.from_u64(number)`.
`from_i64` remains available as a checked bridge for signed host values.
There are no field-name guesses or documentation-only numeric overrides.

The reference derives methods, paths, types, required fields, built-in bounds,
collection structure and errors from the checked contracts. It renders field
descriptions, nested fields, status-specific response examples, raw JSON Schema,
and copyable HTTP requests in cURL, JavaScript (Node.js), Python, Go, Java and C#.
The samples use standard HTTP clients and are also published as `x-codeSamples`
in OpenAPI. They are generated examples, not separate language SDKs.

Descriptions are required values passed to each `Api.command` and `Api.query`.
See [Reports SubmitReport.roc](../examples/reports/commands/submit/SubmitReport.roc), which
keeps the contract beside its handler and checks. Field records must exactly match each checked
input/result, including nested collection fields. Typed examples use generated
codecs and must satisfy declared domains during build admission. They remain
illustrative and need not identify live database rows.

Generated selectors preserve field types for relationships and form bindings.
Descriptions cannot override requiredness, nominal identity or standard bounds.
Comments are ordinary comments and are never scraped. Empty required prose,
stale fields and missing operation contracts fail the normal build.
Native-client samples use `DAY2_SESSION_COOKIE` (full `name=value`), plus
`DAY2_CSRF_TOKEN` and a stable `DAY2_IDEMPOTENCY_KEY` for commands. They preserve
raw JSON number precision and never embed session credentials.

For an anonymous, read-only preview, run
`day2 docs-preview ARTIFACT_DIRECTORY PORT` (use `0` for an available port).
This loads the built artifact directly, requires no instance directory or
database, and serves only the documentation snapshot and its assets. Its cookie
scheme is marked as installation-specific; the live app's spec supplies the
concrete binding. Request execution is disabled in this preview.

## Page Authoring

The app registers typed `Read(input, output)` and `Write(input, output)` handles.
It explicitly chooses a page name, title, route and generated template handle:

```roc
directory = Page.define(
    { name: "links", title: "Links", path: "/", template: Templates.directory },
    Reads.list,
).with_defaults({ after: Cursor.start, limit: PageSize.default })
details = Page.define(
    { name: "link", title: "Link details", path: "/links/{link_id}", template: Templates.details },
    Reads.detail,
)
all = [directory.register(), details.register()]
```

`Page(input)` retains the query's input type. `register()` erases that input
parameter into an opaque `PageBinding` for the heterogeneous product catalog.
The binding contains metadata, not an alternate query handler. Private page
dispatch resolves the registered query and executes that exact operation, just
as RPC does; a separate same-name `Read` cannot replace its behavior.
Admission and dispatch require the page's input and output handle names to
match the registered query, even when two nominal DTOs have the same wire shape.
The read supplies its checked output contract and encoder; page registration
does not repeat an `Outputs` argument. Generated opaque `Templates` handles
refer to actual packaged page files, independently of the public page name.
There is no public template constructor accepting an arbitrary filename.

The host compiles one route catalog for matching requests, typed URL building
and template validation. Path placeholders must name fields from the query's
generated input contract. `.with_defaults(input)` accepts the complete typed
query DTO, infers its field types, and uses the read's generated input encoder.
For a route with path fields, `.with_query_defaults({ limit: 20.I64 })` accepts
only the non-path query fields; the host validates this partial record at build
and artifact load, not through Roc's type checker. No fabricated reference IDs
are needed for path inputs. Defaults methods replace, rather than merge, a
previous defaults record. Without either method the defaults record is empty.

Partial numeric literals need explicit types: unconstrained Roc numbers encode
as decimals and are rejected by integer input codecs. The platform does not
coerce decimal JSON to integers. Complete `.with_defaults(...)` values do not
need these annotations because the query's existing DTO supplies their types
and encoder, including nominal wrappers.

Partial-default and URL admission checks declared wire shapes and built-in
codecs, not arbitrary app-defined domain predicates. For a custom text wrapper,
the host checks the string representation and size; the generated Roc input
decoder invokes its `from_str` constructor when the query executes. A value
that passes structural admission can therefore still be rejected by domain
validation at request time. Template route checking has the same boundary.

Unknown, duplicated, malformed or conflicting routes and inputs fail closed.
A nonempty catalog must explicitly register `/`, with all its query fields
defaulted. The first page in a list is never an implicit landing page.

Apps choose routes but supply no HTTP server or router implementation. Queries
remain independently invocable as JSON through the CLI and receive only
transactional read capabilities.

The actual output types inferred from registered operation callbacks generate the Roc
`Outputs` module and JSON shape contract from compiler metadata. App developers
do not write a parallel JSON schema. The query result must match its typed
output handle, and the host independently validates the returned JSON shape.

MiniJinja renders the app's HTML templates with query data under the page name
(`links.items`, for example) and separate company metadata (`company.name`).
Internal links use checked helpers such as
`{{ routes.link(link_id=link.id) }}` or `{{ routes.links() }}` inside `href`.
`{{ platform.audit() }}` names the reserved audit route; `{{ platform.docs() }}`
and `{{ platform.openapi() }}` link to the API reference and raw specification.
These helpers take no arguments. The same route catalog
checks helper names, field names and value shapes and encodes their URLs;
templates do not maintain a second list of route strings. Context names
`company`, `asset`, `routes` and `platform` are reserved.
Template type checking is structural: a projected string ID does not retain
Roc's nominal `Ref(Model)` identity in HTML. Its concrete value must pass the
registered reference codec at runtime. There is no separate Roc `Page.link`
API in this slice; all template navigation uses the shared host codec.
Templates compose ordinary HTML, loops, conditionals and literal local includes
such as `{% include "components/link-row.html" %}`. The app chooses every
element, class, label, control and layout. Build admission checks template
references against the output, command and asset contracts, including included
components and conditional branches. Undefined data and invalid rendered
markup are rejected independently at runtime.

The supported template subset includes scalar field access, selected typed
operators, `length`, `asset`, `if`, list `for` and literal includes, not full
Jinja. Admission expands at most 256 structural variants and rejects larger
branch combinations. Loops must have balanced HTML bodies. Source/render
budgets, include depth, HTML depth and interpreter fuel are bounded; see
[UI-POC.md](UI-POC.md) for the limits. These checks examine symbolic branches,
not just whichever branch one fixture happens to render.

Forms declare `data-command="links.create"` and ordinary named inputs. Their
command name, complete field binding and control shapes are checked against
the generated command contract. Declared hidden row inputs, such as a row ID
and expected version, become validated bound values in the signed ticket.
The host supplies action/method, CSRF, ticket and Datastar submission behavior;
apps never construct those credentials or choose an alternate command route.
Sign-out uses a `data-platform="sign-out"` form.

Form signing is not authorization or stale-edit protection by itself. The
instance's explicit authority policy controls which commands the actor may
perform and which rows/fields they may change. For an Edit command, the host
maps the declared reference/version inputs and checks the caller's version in
the transaction before starting Roc. It does not infer this from a hidden field's
name. Unauthorized operation forms are omitted; row authority is independently
enforced on execution. A permitted operation with a visible form is not a grant
to every row. See [AUTHORITY.md](AUTHORITY.md).

Command forms currently support one scalar value per field: text-like,
numeric and date/time/color inputs, `textarea`, single `select`, or declared
hidden bindings. Checkbox/radio/file inputs, multiple-value controls, disabled
named fields/fieldsets and optional-text command fields are unsupported. A
boolean can use a single select with `true`/`false` values. Unsupported controls
must fail admission/binding, not silently submit a partial command.

Dynamic text and ordinary attribute values are escaped. Unescaped output
filters and interpolation into executable Datastar expressions are not
permitted. Static app-authored Datastar expressions are executable browser
code, not Roc-checked business logic. Script/style loading belongs to the
admitted resource pipeline. HTML templates provide no runtime filesystem or
network I/O capability to the pure Roc worker.

The host supplies the document envelope and outer `main#day2-main` patch region;
the app owns its content and header. App documents do not load the platform's
default UI stylesheet. Ordinary pages replace the whole main region after a
command. Live pages patch admitted display regions over SSE and keep command
acknowledgements and submitted-form replacements separate. Custom document-head
APIs remain follow-up work. Tickets and browser randomness are added outside core replay.
New builds use artifact format 12 with required complete application contracts. Fresh API invocations and HTTP serving require
that current contract; older HTML adapters are not a compatibility bypass.
Formats 1 through 11 remain loadable for inspection, replay, and explicit operator
recovery of accepted work. Upgrade requires draining accepted invocations and
pending invocations, then explicit migration and activation. Company authority is
still required for execution; loading a legacy artifact grants no permission.

## Native UI Resources

The required `App.definition.presentation` explicitly names stylesheet and script
entries under `ui/`; empty strings mean absent. Modules can import other
local admitted `.js` modules with relative paths. A Rust Oxc parser rejects bare,
remote, computed, escaping and missing module imports; no npm, Node server or
app build scripts run. The complete source graph and resource hashes are bound
to the app artifact and verified again on load/serve. HTML templates and their
include graph are separately admitted, hashed and rendered on the server;
they are not browser module entrypoints. A general company library
catalog is not implemented yet; Datastar is a fixed platform dependency.

CSS is parsed with cssparser. Layout, custom properties and responsive media
queries are allowed. This first asset pipeline does not admit CSS `@import`,
external fonts/images or non-fragment URL references. HTML images use checked
`{{ asset('name') }}` references to the admitted app image catalog.
Browser JS is ordinary native code, not a capability sandbox. CSP restricts script
sources to the admitted app resource prefix and pinned platform Datastar file;
`unsafe-eval` is necessary for Datastar expressions. Import admission is dependency
governance, not proof that app code cannot synthesize executable code.
The new backend authority checks do not change that browser trust model. App
scripts can submit commands allowed to the signed-in session; neither a ticket
nor a valid Edit precondition proves a human intended the action.

## Three Asset Owners

| Owner | Inputs | Runtime URLs |
| --- | --- | --- |
| Platform | Embedded Datastar and security-page/audit assets | `/assets/platform/...` |
| App | Its own `assets/` directory, bundled in its immutable artifact | `/assets/app/<scope>/<artifact>/<key>/<digest>.png` |
| App | Its `ui/` browser modules and styles | `/assets/ui/<scope>/<artifact>/<relative-path>` |
| Company instance | Independently built branding bundle | `/assets/instance/<scope>/<brand>/<key>/<digest>.png` |

Scopes and identities in URLs are computed hashes. URLs are never filesystem
paths. A request must match a catalog entry in the bound artifact/bundle. App
assets require an authorized session; company branding is public to its local
origin so the sign-in page can use it. CORP, no-sniff and same-origin CSP apply.
Wrong scopes, unregistered assets and changed bytes fail closed. The same app
artifact can run unchanged under entirely different companies and brands.

Asset GET and HEAD responses carry a strong content-derived `ETag`. Public
branding images and theme CSS use their bundle/content-addressed URLs with
`Cache-Control: public, max-age=31536000, immutable`. Existing platform CSS,
icons and Datastar URLs use `no-cache`, so browsers may store their bytes but
must revalidate before reuse. A version in a filename alone is not treated as
a content-addressing guarantee.

App images, CSS and browser modules use `private, no-cache` and `Vary: Cookie`.
Even though their URLs include artifact identities, each reuse requires current
session authorization. Matching `If-None-Match` requests return a bodyless 304
with the same ETag and cache policy only after scope, authorization and packaged
byte checks succeed. Weak validators, lists and wildcard conditions are
supported; malformed conditions are ignored and receive the full response.
HEAD returns GET's headers without a body. Validation still performs server
work and verifies disk bytes; it saves transfer, not those checks.

Rendered pages, Datastar event streams, commands, sign-in/sign-out, audit and
error responses retain `no-store`. The HTML templates are not static browser
documents: rendering inserts current query data and expiring session-bound
command tickets. Query caching requires a separate freshness contract. Public
immutable assets already cached by a browser may remain reusable after a
branding change; the new binding produces different URLs.

```text
links-app/
  App.roc
  pages/Routes.roc
  storage/Models.roc
  ui/
    pages/directory.html
    pages/details.html
    components/link-row.html
    app.css
    app.js
  assets/
    directory_logo.svg
    icons/
      plus.svg
      archive.svg
```

No app image manifest is handwritten. Templates use `asset('directory_logo')`,
`asset('icons_plus')` and `asset('icons_archive')` inside image `src` attributes.
Unknown keys fail template admission. The host resolves them to its scoped
catalog URLs and verifies the image bytes independently. Apps author their own
image sizes, classes and alternate text. The legacy Roc HTML path retains
generated opaque `Assets` handles.

Use lowercase snake_case filenames and directories. Nested names flatten with
underscores; collisions, unsupported files, symlinks and special files are
rejected. Assets.roc is platform-generated, never app-authored. Markdown notices
may accompany source assets; they are not executable or served as app resources.

PNG, JPEG and WebP are decoded and re-encoded as PNG, stripping metadata and
trailing payloads. SVG is parsed with roxmltree and rasterized with resvg/usvg,
with all image resource resolvers disabled. A closed subset allows basic paths,
shapes, groups, gradients and clipping. Scripts, event attributes, foreignObject,
style, embedded images, text/fonts, use, DTDs and processing instructions are
rejected. Convert unsupported artwork to a raster image or outlined paths.
Untrusted SVG source never reaches the browser. Trusted platform SVG icons are
separate vendored code assets.

Budgets: 64 images, 4 MiB per source/output, 16 MiB per source/output bundle,
2048 px per edge, and four nested directories. SVG also has source, XML-node,
nesting and attribute budgets. Decoder allocation limits are defense in depth;
this is not a certified hostile-image build sandbox or hard CPU/memory proof.

## Company Branding

Company owners supply a small branding source directory:

```text
company-instance/
  instance.json
  branding/
    source/
      brand.json
      assets/
        logo.png
```

`brand.json` accepts only the name and accent:

```json
{ "name": "Example Company", "accent": "#8b3150" }
```

The optional asset named `logo` is the conventional company logo. The accent
must be a six-digit hex color with adequate contrast against white text; it is
compiled into a tiny external stylesheet, never interpolated as arbitrary CSS.

```text
cargo run --locked -p xtask -- brand ../company-instance/branding/source ../company-instance/branding/bundles
```

The command prints the immutable bundle directory. Set the instance's optional
`branding` to that directory relative to the instance root, for example
`branding/bundles/<printed-digest>`. The loader rejects absolute paths, parent
traversal, symlinks and mismatched content identities. No app rebuild or app
schema migration is needed to change brands. Restart the local server after
changing a binding; an existing server fails closed on a changed binding.
Without branding, the installation name and platform defaults are used.

## Receipts And Audit

The one-time local sign-in link expires after ten minutes and requires a
same-origin confirmation POST. Sessions are server-side, have an eight-hour
expiry, and use hashed tokens in SQLite plus HttpOnly/SameSite cookies. The
plain HTTP development cookie is not Secure; do not expose this server publicly.
Host is checked exactly; forwarded actor headers are never identity inputs.

Form POSTs require exact same-origin checks, a session-bound CSRF token and an
HMAC-signed action ticket. Tickets bind actor, scope, artifact, page, command,
editable fields and hidden row inputs. The nonce becomes the durable invocation
ID. Retrying the same ticket/input does not repeat a write, including after a
restart or a lost post-commit response. Different input with the same nonce is
an idempotency conflict. The host secret and sessions persist privately.
Receipt reuse additionally requires the original authority epoch and revision
and current authorization; an activation denies access to historical results
instead of rerunning the action. Legacy receipts without that evidence also deny.
Edit guards also reject distinct new invocations carrying a stale caller version.
Such pre-worker rejections have durable failure receipts and replayable host
guard evidence, without starting the business handler or committing row changes.

All successful row mutations and their redacted field-change records commit
with the invocation receipt and completion audit entry. Failed transactions
leave no committed changes; audit failure prevents a successful business commit.
Actor, operation, artifact, row identity and versions are host-derived. Apps
cannot disable capture or write the audit tables. UPDATE/DELETE/replacement guards enforce
append-only audit behavior under the host contract, not against a local DB admin.

The reserved `/audit` viewer requires explicit instance `auditors` membership.
It has actor/operation/status filters and bounded cursor pagination. Values are
redacted by default. Read-only page queries also get completion entries. Separate
`day2_web_events` record request admission/status, including rejected requests,
without bodies, tokens or query strings. The common `audit-events` CLI stream also
includes invocation admission/rejection, interruptions and command execution attempts;
it is auditor-only, redacted and cursor-paged.

The generated `/docs` **Platform** section exposes two authenticated JSON reads:

- `GET /api/audit` (`platform.audit`) lists completion receipts and redacted row
  changes. Optional `actor`, `operation` and `status` filters select completions;
  `model` and `record_id` select a record's revision timeline. `record_id` requires
  `model`. Every matching entry retains all changes in that transaction.
- `GET /api/audit/events` (`platform.audit_events`) lists the full lifecycle stream,
  including admission, rejected attempts, retry reuse, interruptions and HTTP
  events. Optional `actor`, `operation`, `kind`, `identity` and `outcome` filters
  select events. `identity` follows a particular invocation across attempts.

Both return `{ "items": [...], "next_cursor": "..." }` in descending sequence.
Omit `cursor` or pass an empty string for the newest page; copy `next_cursor` for
older pages and stop when it is empty. `limit` defaults to 50 and accepts 1–50.
Filters are exact; omitted or empty filters match all. Continuations are opaque
256-bit random handles, expire after 24 hours, and are bound to the app, artifact,
actor, view, filters and limit. Every page rechecks current auditor authority.
Newer writes do not shift older page boundaries. Cursor storage is capped at
10,000 active handles per app database; it fails closed without evicting active
continuations when full. Expired handles are reclaimed as new pages are issued.
Neither endpoint runs app code. Their HTTP access is itself recorded without
query strings or bodies. Auditors can sign in and use these APIs/docs without
permission to execute an application operation. Ordinary app permissions still
apply to application APIs.

These platform timelines replace application audit tables; they do not reconstruct
old or new business field values. A deletion reason, when it is business data,
belongs on the business record and remains governed by that record's access
policy. The audit records that its field changed without copying its value.
The `/audit` HTML page remains the completion view; the lifecycle stream is
available through the Platform API/docs and CLI. See
[SDK-CAPABILITIES.md](SDK-CAPABILITIES.md) for schema and limits.
Internal invocation inputs/traces, including captured Edit precondition rows,
still contain business values in the protected database: redacted audit views
are not an at-rest encryption, secret-handling or retention policy.

Normal forms work without JavaScript. Vendored Datastar 1.0.1 enhances form
submissions with HTML updates. App modules provide local search, filtering and
copy actions without changing the Roc transaction path. Production identity,
per-app production origins, fine-grained row policy, uploads/media storage,
company-approved library catalogs, strict-CSP Datastar
migration and full audit retention/export remain follow-up work. Deterministic
simulation covers the Roc core and recorded host observations, not arbitrary
native browser execution.
