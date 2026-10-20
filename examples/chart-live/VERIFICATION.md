# Chart Live verification

Experimental source support. Component/browser acceptance, full application
deterministic simulation testing (DST), full Platform verification and release
qualification are separate; none is implied by a local demo.

## Historical evidence and scope

The records below predate the current-main reconciliation. The PR's latest
validation report identifies the tested candidate and current checks.

| Boundary | Evidence | Scope |
| --- | --- | --- |
| Renderer core | Seeded engine-port schedules, typed coordinate failures, pure SVG/protocol checks | Deterministic core; not ECharts or OS isolation proof |
| Real renderer | Recorded JSONL replay, changed values/ranges, zero/gap/singleton, schema parity, host timezone/locale comparisons | Actual ECharts/QuickJS subprocess |
| Native port | Typed admission/projection, request-local memoization, virtual admission deadlines and seeded restart/contention schedules | Same ports/validation; explicit simulated failures |
| Confinement | Linux real-worker replay/recovery and concurrent renders through unchanged isolation/frame/exchange budgets | Requires independently reviewed executable bytes; rerun after source changes |
| Browser adapters | Seeded DOM lifecycle and injected network/timer schedules, delayed-body/cancellation/draft regressions | Simulations, not real browser acceptance |
| Native app | Current PR source passed ordinary Mac Native build; browser confirmed 0→35/version 1→2, Add 83/version 1, changed SVG, retained draft 84, keyboard range/cancel/apply, and a server-confirmed six-hour range | Actual persisted/query/HTTP/browser path; partial acceptance, not every interaction |

Unit schedules have no real sleeps/network. Failures identify seed/step; real
adapters run separately. Worker and host budgets are unchanged. App/server data
is not component-local state, and editable forms stay outside live regions.

## Historical cleanup checks

Full UI Rust tests and workspace/all-target Clippy pass. Scoped Platform
presentation/template/projection/route/resource tests, Day2 all-target Clippy,
architecture checks, canonical lock verification, formatting, deterministic
component/navigation schedules and real confined worker replay/concurrency pass.
These are focused source/adapter checks, not a substitute for the gates below.

## Remaining gates

The ordinary gate now includes the Chart Live native build, independent multi-actor
range and exact-update regressions, the paused-render HTTP revocation test, and
the Node navigation suite. Those sources are part of the verification identity.
The HTTP test uses a controlled presentation port through real HTTP, Roc, SQLite,
template and form paths; it does not qualify a particular renderer executable.

- Continuous/reversed/clipped/short pointer ranges, SVG-only text-selection
  suppression and table copying. The current browser bridge lacks drag operations.
- Dialog focus return, mobile, no-JS, reduced motion, stale cancellation,
  replacement/back/BFCache and concurrent GET/live acknowledgements. Current
  browser proof covers keyboard navigation/selection/apply/cancel and dialog
  open/close, but its tools lack viewport, console and JS-disabled contexts.
- Real-browser range/reset/empty and login-consumption journeys remain separate
  from native dispatcher and controlled-port HTTP regression coverage.
- Full application DST and the current candidate's frozen-source Platform gate.
  Use the repository's pinned toolchain and verification recipes; hosted portable
  Linux and focused Mac validation have separate receipts. Historical local
  environment failures are not evidence that the current candidate passed.
  No guard may be relaxed to bypass these gates.
- Deployment/release qualification remains separate. The example now uses the
  Platform's managed schema-2 package lock; the distribution includes the chart
  worker and ABI contract. Request-time execution still needs separate operator
  approval. App-local dependency copies are not supported.

Private receipts, historical task/artifact logs, login/session material and
screenshots remain outside repositories. Existing local demo servers are not
restarted by source cleanup.
