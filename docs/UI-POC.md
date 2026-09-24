# App-Owned UI POC

Apps own ordinary `.html` templates, CSS, assets and native browser JavaScript.
The link-directory examples below come from the platform's
[row-authority fixture](../fixtures/row-authority-web-conformance/README.md) and
[HTTP presentation overlay](../fixtures/http-conformance/README.md).
HTML is not written through a Roc UI DSL. The platform does not
choose the app's layout or require shared visual components. Its Roc business
core remains pure.

This is a local, loopback-only development system. Dependency admission is
supply-chain control, not a browser sandbox or production security approval.

## Where The App Lives

```text
app/                Staged conformance app with the HTTP overlay
  App.roc           Registers complete definitions once
  commands/         Commands with their contracts and verification
  queries/          Queries with their contracts and verification
  storage/          Persistent models and their registration
  domain/           Nominal values and executable constraints
  shared/           Shared result shapes and field meaning
  verification/     Invariants and shared scenarios
  examples/         Optional demo command inputs
  pages/Routes.roc  Typed queries, routes and template handles
  ui/
    app.css         App stylesheet entrypoint
    app.js          Native browser module entrypoint
    pages/
      directory.html Page layout, loops and conditionals
      details.html   A link's detail page
    components/
      header.html
      create-form.html
      link-row.html
  assets/           App images and icons, admitted into the artifact catalog
```

The instance chooses the installed app artifact, actors and company branding.
Page layouts belong to the app. HTTP tests provision isolated instances;
[managed local development](../ops/LOCAL-DEVELOPMENT.md) provisions a persistent
local instance for interactive work on Reports.

## A Page Request

`App.definition.pages` registers named bindings from `pages/Routes.roc`.
The page declaration connects a typed query to an explicit route and generated
opaque template handle:

```roc
directory = Page.route(
    { title: "Links", path: "/", template: Templates.directory },
    Reads.list,
).with_defaults({ after: Cursor.start, limit: PageSize.default })
details = Page.route(
    { title: "Link details", path: "/links/{link_id}", template: Templates.details },
    Reads.detail,
)
# In App.definition:
pages: { links: Routes.directory.register(), link: Routes.details.register() },
```

`shared/LinkView.roc` declares the reused result shapes and field meaning.
Each query's checked return type supplies its output codec; there is no authored
output inventory or duplicate JSON schema. A mismatched query/output handle is a Roc
type error; misspelled template fields are template-admission errors. Each generated
`Reads` handle owns its output codec, so `Page.define` cannot select a second, conflicting
output contract. `Page(input)` retains each query input type; `PageBinding`
is the erased registration type needed for a list of differently typed pages.
Its binding is metadata-only: the private page dispatcher runs the registered
query operation, not a second handler retained by the page declaration.
The page's declared input and output handles must exactly match that registered
query; structurally identical but differently named input contracts do not match.

HTML is packaged before Roc compilation. Its checked catalog generates
`Templates.roc` plus an opaque SDK `Template` module with file-specific constants,
not a string factory. App-owned generated modules are rejected. The name
`links` and template filename `pages/directory.html` are deliberately independent.

`.with_defaults(input)` accepts the complete query DTO and uses its existing
typed input encoder. The compiler checks field types, including nominal types;
integer literals inherit their field types without extra annotations. Definition
alone has empty defaults, so detail pages do not need a dummy DTO.

For mixed path/query routes, `.with_query_defaults({ limit: 20.I64 })` accepts
a partial structural record. This is a build/admission guarantee: every key and
value is checked against the generated input codec, and path fields cannot be
defaulted. Partial numeric values need their wire scalar type; unconstrained
numeric literals infer Roc decimals, which an integer codec rejects. Each
defaults method replaces, rather than merges, the previous defaults record.
Admission validates wire shapes and built-in codecs; it does not execute
arbitrary custom domain predicates. Text-wrapper `from_str` constructors run
in the generated Roc input decoder when the query executes. Structurally valid
partial defaults or route parameters can still fail that domain validation.
For detail pages the actual `Ref(Model)` comes from the request path, not a
dummy ID in a complete default DTO. The URL matcher and URL builder share one
host route catalog. A nonempty catalog requires an explicit `/` page whose
query inputs are all defaulted; no list-order landing-page convention applies.

For `/`, the pure Roc worker returns typed query data. The Rust host
validates that data against the generated output schema and renders
`ui/pages/directory.html` using MiniJinja. The template receives the data under
`links`; company metadata is separate. The app chooses every element, class,
label, loop and component include. There is no generated table layout.

```html
<div id="links-list">
  {% for link in links.items %}
    {% include "components/link-row.html" %}
  {% else %}
    <p>No links yet.</p>
  {% endfor %}
</div>
```

Templates use the supported Jinja expression, loop, conditional and include
syntax. Ordinary dynamic text and attribute values are escaped. Template
source is checked during artifact construction against the generated query,
command and asset contracts; the template is not just tested with one sample
query result. Runtime output and form validation remain independent checks.

An internal anchor uses `href="{{ routes.link(link_id=link.id) }}"`;
`routes.links()` returns the registered directory URL and `platform.audit()`
returns the reserved audit URL. Build checks validate route names, required
parameters and their types. Runtime checks validate concrete values and apply
the same URL codec used for requests. `routes`, `platform`, `asset` and `company`
cannot be repurposed as page-context names. This is not a separate app router.
This template check preserves JSON shapes, not the full nominal Roc type system:
a string-valued view ID is checked by the target reference codec at runtime.
A separate Roc-side navigation builder is not implemented in this slice.

This is a checked subset of Jinja, not the full language. It supports scalar
field access, selected typed operators, `length`, `asset`, `if`, list `for` and
literal includes. Macros, dynamic includes, arbitrary functions, unsafe filters,
recursive loops and arbitrary Python execution are not available. HTML must be
balanced, and a loop body must be balanced independently.

Admission checks at most 256 structural branch variants and fails closed above
that bound; it does not silently skip branches. Limits also include 128 template
files, 256 KiB per file, 2 MiB total source, 16 nested includes, 4,096 dynamic
expressions, 512 KiB rendered HTML, 48 element levels and 8,192 parsed nodes.
Rendering has a bounded interpreter fuel budget and recursion limit. These
bounds are POC constraints, not a claim that every existing Jinja app is
compatible without changes.

The host adds the HTTP document and protected transport boundary. The app's
stylesheet and JavaScript module are loaded from its bound artifact.
Platform security screens, such as sign-in and audit, retain platform styling;
the app page does not load the platform's `web.css`.

Templates reference images using `{{ asset('icons_plus') }}`. The build checks
the key and the host resolves it through the bound app/instance/artifact-scoped
catalog. Images are independently normalized. HTML templates do not enable
unescaped interpolation of business data or runtime filesystem access.

## Forms And Browser Behavior

Forms are ordinary HTML with a `data-command` binding. Command and input names
are checked against the generated contracts; they are not arbitrary HTTP
routes. The app chooses labels, grouping, controls and presentation:

```html
<form data-command="links.create" id="create-link-form" class="command">
  <label for="link-title">Name</label>
  <input id="link-title" name="title" type="text" required maxlength="200">
  <label for="link-destination">Destination</label>
  <input id="link-destination" name="destination" type="url" required>
  <button type="submit">Add link</button>
</form>
```

Row actions bind declared hidden inputs from typed query values, including the
row ID and expected version. The host validates these values, moves them into
the signed action ticket and does not trust a browser-supplied replacement.
`data-platform="sign-out"` similarly identifies a host-managed sign-out form.

Each editable field has one successful scalar control: a text-like or numeric
input, `textarea`, or single-value `select`. Scalar input modes also include
date/time/month/week/color and declared hidden bindings. Checkbox, radio, file,
multiple-value controls, disabled named controls and disabled fieldsets are
not supported by this form protocol. Use a single select with literal `true`
and `false` values for a boolean. Optional-text command fields are not yet
supported. Native browser validation remains advisory; the host checks all
submitted values against the actual command contract.

The platform injects the form action, CSRF token and signed action ticket.
Native form submissions use ordinary HTTP and redirect after completion.
Datastar submissions run the same command, query the updated state and return
the app's freshly rendered HTML as an SSE patch to `main#day2-main` for ordinary
pages. Pages opting into `.live()` instead keep one SSE subscription to the same
query, patch stable `data-live` regions, and replace only the submitted form after
a successful command. Reports demonstrates this mode; see [WEB.md](WEB.md#live-queries-over-sse).
The signed
ticket's invocation identity preserves retries across a lost response or host
restart. App markup cannot change transaction, authorization or audit rules.

A command that completes synchronously answers `200` and redirects; a durably
accepted command whose effects are still running answers `202` with its
invocation identity. Acceptance is not rejection: the accepted form is reset with
a fresh ticket rather than re-presented for resubmission, because resubmitting an
accepted command creates a second durable invocation. Only `403`, `409` and `422`
retain the draft and its original ticket. Live pages mark the status region
`success`, `pending` or `failure` accordingly.

`ui/app.js` owns browser-only interactions such as local filtering and copying
a link. It is ordinary browser JavaScript, not Roc and not deterministic by
construction. Event handling must continue to work after Datastar replaces the
main region. Browser-only search or display state is not a database command;
creating and archiving a link always goes through the platform command path.

The POC retains platform-generated Datastar command submission behavior. Apps
can also author Datastar `data-*` expressions and native module behavior. These
expressions are executable browser code with the same trust boundary as the
app module, not a restricted or pure expression language. Never interpolate
user-provided strings into an expression; use escaped data attributes and
checked command bindings instead. Template admission rejects interpolation in
executable-expression contexts. The host's command form bindings remain
protected.

## Module And Style Admission

The required `App.definition.presentation` explicitly selects stylesheet and script
paths under `ui/`; an empty string means no entry. There is no npm,
package installation, per-app build script or CDN module import. The build
parses JavaScript imports, admits the local dependency graph and records the
resource bytes, media types and hashes in the immutable app artifact. Template
files and their include graph are also admitted and pinned; templates are
server-rendering inputs, not executable browser modules. Styles
also pass admission; external style imports and resource URLs are not an
unrestricted network-loading escape hatch.

Browser resources use:

```text
/assets/ui/<installation-app-scope>/<artifact>/<relative-path>
```

Serving requires the current app's authorized session and a matching catalog
entry. The host verifies the bytes against the pinned artifact. An unknown
path, another app's scope or a changed resource cannot silently become an
executable dependency. The platform's own Datastar runtime is separately pinned.

This local module graph is not a general company dependency registry. A future
registry needs explicit ownership, approval, versioning and revocation rules;
this POC does not claim to implement those workflows.

## Trust And Simulation

The native module runs in the app page's browser origin. It can inspect the
rendered data, manipulate its UI and submit forms using the current user's
available authority. Type checking, import admission, CSP and HttpOnly cookies
do not make arbitrary native app JavaScript capability-safe. The platform must
never rely on a button being hidden, on client validation or on a particular
browser event sequence for business authorization.

The server still validates command contracts and tickets, checks current
permissions, executes real SQLite transactions and commits mandatory audit
records atomically. The Roc core remains replayable under deterministic
simulation. UI actions are inputs to that core, not new server-side I/O powers.

Native browser scheduling, clipboard availability, focus, layout and pixels
are outside the pure-core replay guarantee. The pure page output is query data,
not a document containing randomized, session-bound form tickets. HTTP tests can check returned HTML,
resource hashes, SSE payloads and transaction effects. Browser integration and
visual tests must separately check actual interaction and rendering. Client
traces are diagnostics, not authoritative audit evidence. No browser visual or
interaction verification is implied by passing the Rust/HTTP verifier.

## Run And Verify

From `platform/`:

```text
cargo run --locked -p xtask -- cli
./cli/day2 platform local-dev examples/reports
```

Local development prints the origin, sign-in URL and managed instance path. It
watches Reports, rebuilds changed source and preserves local data between sessions.
Run `cargo run --locked -p xtask -- verify` for the platform's HTTP and relational
conformance suites. Verification evidence applies to the built artifact; current
native-build blockers are recorded in [verification coverage](VERIFICATION-COVERAGE.md).

The POC is intentionally not a capability VM, full Datastar authoring system,
production identity adapter or proof of deterministic browser execution.
