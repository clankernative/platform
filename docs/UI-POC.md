# App-Owned UI POC

Apps own ordinary `.html` templates, CSS, assets and checked bindings; Roc owns
business and view meaning. They do not author JavaScript entrypoints, bootstraps,
callbacks or Datastar expressions. CUI is a build-time catalog with reviewed
local behaviors; Custom Elements are optional and are not a sandbox. The
link-directory examples below come from the platform's
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
`.on_failure(page)` names another registered page with the same input type to
render, under the original 5xx status, when this page fails on the server; see
[WEB.md](WEB.md#app-owned-failure-pages).

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
stylesheet is loaded from its bound artifact. Platform security screens, such
as sign-in and audit, retain platform styling; the app page does not load the
platform's `web.css`. Platform-owned Datastar/form transport remains trusted.
Host-generated transport directives are added after source admission and cannot
be forged by app templates or concrete content.

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

The default policy rejects app-authored JavaScript resources and nonempty
script entrypoints. Two existing app behaviors are retained as explicit
unchanged-module exceptions, not as a general JavaScript mode:

| App namespace | Exact path | Required SHA-256 |
| --- | --- | --- |
| `notifications` | `notifications.js` | `4ae41088b340a78bf3ba53e56d5163805448b5d330330401c8e267cc3820857e` |
| `chart-live` | `app.js` | `a200c72e74c8d38d888829979b8619b36cb145a6aaa315578d63a97da09d7aca` |
| `chart-live` | `chart-navigation.js` | `156b19235681b17e1bc4f36628435c2d2b12b58e38ad75e1889bba824f96115f` |

These Platform-owned records bind exact namespace, path and bytes. Changed bytes,
another path/namespace or any unlisted module fail admission; no new exception
app code may be authored. CUI-generated modules use the separate host receipt
path described below. App-authored Datastar execution/reactivity directives
(including event, init, effect, computed, signals, bind, text, show, class, attr
and style forms), inline handlers and script injection are rejected during
source admission and concrete content validation. Inert app `data-*` metadata,
including closed `data-query-*` declarations, remains available. The platform
retains host-generated Datastar command submission and live-query transport:
those directives are added after app source admission, and the reserved
transport fields cannot be forged by the app. Keep one DOM writer and preserve
unsaved drafts during updates. Apps need no local callback to submit a query or
command; Platform coordinates those interactions through checked bindings.

New browser behavior belongs in a reviewed CUI package or explicitly approved
host capability, not ordinary app JavaScript. A trusted component entrypoint
and its complete module closure require digest-checked assembly provenance from
the host-verified managed UI provider/package. A `ui/` prefix, self-declared
source marker or editable lockfile is not proof. This code still has ordinary
browser-origin authority; neither package review, CSP nor admission creates a
per-component sandbox or removes ambient authority. Browser screenshot evidence was not captured for this policy change because
browser access was user-ended; verification is limited to focused source and
admission tests plus formatting.

## Module And Style Admission

`App.definition.presentation.stylesheet` may select the app stylesheet;
`presentation.script` is empty by default; it accepts only the exact legacy
namespace/path/digest exceptions listed above. There is no npm, package
installation, per-app build script or CDN module import. Other app-authored
`.js` resources and executable template content are rejected. A managed
component module graph is permitted only through a digest-checked host assembly
receipt binding `ui-package.js` and its complete reachable import closure to the
verified provider executable, package and captured UI source authority; it is
not selected by an app presentation script path. A lockfile or self-asserted
source prefix is insufficient. Template files and their include graph are admitted and pinned;
they are server-rendering inputs, not executable browser modules. Styles also
pass admission; external style imports and resource URLs are not an unrestricted
network-loading escape hatch.

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

Reviewed host/package browser behavior runs in the app page's browser origin
and has ambient browser authority. Admission and provider/package review govern
what code is shipped; they do not make it capability-safe or sandbox it. CSP,
checked bindings and HttpOnly cookies do not remove that authority. The platform
must never rely on a button being hidden, on client validation or on a particular
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
