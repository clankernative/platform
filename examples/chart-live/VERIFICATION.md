# Chart Live verification

Experimental source support. Component/browser acceptance, full application
deterministic simulation testing (DST), full Platform verification and release
qualification are separate; none is implied by a local demo.

## Evidence and scope

| Boundary | Evidence | Scope |
| --- | --- | --- |
| Renderer core | Seeded engine-port schedules, typed coordinate failures, pure SVG/protocol checks | Deterministic core; not ECharts or OS isolation proof |
| Real renderer | Recorded JSONL replay, changed values/ranges, zero/gap/singleton, schema parity, host timezone/locale comparisons | Actual ECharts/QuickJS subprocess |
| Native port | Typed admission/projection, request-local memoization, virtual admission deadlines and seeded restart/contention schedules | Same ports/validation; explicit simulated failures |
| Confinement | Linux real-worker replay/recovery and concurrent renders through unchanged isolation/frame/exchange budgets | Requires independently reviewed executable bytes; rerun after source changes |
| Browser adapters | Seeded DOM lifecycle and injected network/timer schedules, delayed-body/cancellation/draft regressions | Simulations, not real browser acceptance |
| Native app | Prior ordinary Mac build and app verification; persisted value 0→35/version 1→2 changed SVG without rebuild; operator-confirmed smaller range fetched data | Prior implementation; current cleanup changes need fresh Mac review |

Unit schedules have no real sleeps/network. Failures identify seed/step; real
adapters run separately. Worker and host budgets are unchanged. App/server data
is not component-local state, and editable forms stay outside live regions.

## Current cleanup checks

Full UI Rust tests and workspace/all-target Clippy pass. Scoped Platform
presentation/template/projection/route/resource tests, Day2 all-target Clippy,
architecture checks, canonical lock verification, formatting, deterministic
component/navigation schedules and real confined worker replay/concurrency pass.
These are focused source/adapter checks, not a substitute for the gates below.

## Remaining gates

- Rebuild current sources normally on Mac; qualify Add with an unused timestamp,
  continuous/reversed/clipped/short pointer ranges and SVG-only text-selection
  suppression. Preserve persisted data and unrelated drafts.
- Real keyboard/focus/dialog, mobile, no-JS, reduced motion, stale cancellation,
  replacement/back/BFCache and concurrent GET/live acknowledgements.
- HTTP range/reset/empty, owner isolation/version conflicts and authority/session
  revocation during slow render; login-consumption regression with the separately
  built HTTP-conformance artifact.
- Full frozen-source Platform verification and full application DST.
  Linux formatter setup is Mac-only and its HTTP compiler requires a private
  cgroup-v2 namespace. Mac full verification still needs local OpenTofu
  configuration. No guard has been relaxed to bypass these gates.
- Cold package/worker provisioning and release acquisition. The example excludes
  installed `.ui-dependencies/` bytes from Git; the canonical lock requires
  matching independently captured inputs. Existing UI bundles omit the worker.

Private receipts, historical task/artifact logs, login/session material and
screenshots remain outside repositories. Existing local demo servers are not
restarted by source cleanup.
