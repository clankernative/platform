# Chart Live

`chart_live` is an isolated Native app proving that the request-time chart reads
real, persisted, actor-owned Roc data. It does not import or modify `chart-lab`
and contains no generator, host renderer hook, or JavaScript automation.

## Data and operations

- `Models.ChartSample` is nominal persistent data with owner, UTC epoch-ms time,
  integer value and an explicit missing marker. `(owner, time)` is a database
  unique key. A real value of `0` remains distinct from `missing: true`.
- `append_sample` creates a sample for the current actor, rejects values outside
  0..100 and enforces a 100-row owner bound in the write transaction.
- `update_sample` finds a sample only within the current actor's owner/time
  selection, checks its row version, and can change value/missing without
  changing its timestamp or owner.
- `chart` reads the actor's bounded persisted selection, orders by timestamp,
  then retains only the checked `[start, end)` interval. It returns `title` and
  the renderer input `chart` with width 640, height 240, y-domain 0..100 and
  kind `line`. Its API collections use Native's bounded `CollectionPage`
  envelope; the package projects only checked `samples.items` into the
  separately approved renderer contract. No API collection budget is relaxed.
  Each sample includes the real nominal row reference as `key`.
  Invalid ranges fail closed; accepted ranges are nonnegative, end-exclusive,
  and no longer than 31 days.
- `ChartInvariants` independently checks owner, value, timestamp, uniqueness and
  cardinality invariants. Each operation owns its own contract, example and
  verification alongside its implementation.

The `/chart` page defaults to the bounded UTC week **2025-01-01 00:00 through
2025-01-08 00:00**, with the end exclusive: ranges are half-open `[start, end)`.
The output also supplies `full_start`/`full_end` for a reset link and
`sample_edits` with the checked `update_sample` form values. It is live and the
normal registered query refreshes after writes. Changing `start` and `end` uses
checked I64 query inputs; the app does not interpret presentation callbacks as
state.

`examples/Demo.roc` demonstrates normal registered `append_sample` command
inputs, including a measured zero and a marked gap. It is sample data, not an
immutable chart source; the query always reads current persisted rows. The model identity ledger was authored with the ordinary `xtask register-model`
workflow and is retained in `model-identities.json`; builds use it read-only.

## UI handoff

The app UI lives in `ui/pages/chart.html`, `ui/app.css`, and
`ui/app.js` (the latter two are named in `App.definition.presentation`). The app
explicitly imports the staged `./clanker-ui.js` module; resource staging by itself
does not install enhancement. The
page template binds the checked `/chart` route and render `Templates.chart`
scene data as ordinary escaped HTML/SVG. It provides native GET range forms with
`data-page="chart"` and checked `start`/`end` fields, plus no-JS preset links
within the full interval and a reset to `full_start`/`full_end`. Any JS range
enhancement should navigate the checked same-origin URL with a normal page
request first, so the live SSE initializer receives the new inputs; do not add a
custom signal transport. The optional app enhancement requests ordinary checked
HTML, replaces only server-confirmed live regions and reuses the host-produced
live initializer; command forms and drafts remain outside those regions.

For mutations, the form operation names are `chart_live.append_sample` with
`time`, `value`, `missing`, and `chart_live.update_sample` with `sample_time`,
`expected_version`, `value`, `missing`. Render update controls from
`sample_edits`; use the regular command forms and retain ordinary server-side
validation. The sample records remain current query data, not template fixtures.

For the generic declaration, independent operator pin and runtime bounds, see
[request-time presentation setup](../../docs/RUNTIME-PRESENTATIONS.md). Clanker UI's
`docs/runtime-chart-renderer.md` describes the separately provisioned worker and
experimental component; normal UI bundles do not install it.

## Provisioning and deterministic adapters

The canonical lock expects an independently reviewed package tree at
`.ui-dependencies/vanilla`; installed bytes are excluded from Git. Use explicit
UI install/restore before building, verify the captured package against the lock,
and configure separate compiler/renderer approval. This unreleased chart package
must be obtained from matching reviewed UI source; no cold/hosted release is
claimed and compilation never restores dependencies.

`ui/app.js` wires browser adapters only. `ui/chart-navigation.js` receives DOM,
network, parsing, cancellation and timer ports explicitly; its route/generation
decisions use supplied inputs. Seeded tests replace network/timers without global
mutation or real waits. These are not application-DST or browser qualification.

## Local qualification

Use the ordinary Native builder and its generated model identity ledger, then
run the scoped app build/verification. A successful Linux compile is not proof
of the ordinary Apple Silicon Native build. This app's source contribution does
not qualify the presentation worker, SVG templates, browser behavior, full gate,
or release path; those remain separate gates. [VERIFICATION.md](VERIFICATION.md)
records executed evidence, the first real browser failures and outstanding checks.
