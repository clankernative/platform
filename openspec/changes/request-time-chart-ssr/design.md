## Context and scope

Authorized Roc queries already produce current page/live data. Native needs an
optional bounded presentation port, not a request-time build provider, raw-markup
helper or chart-specific runtime dependency.

## Decisions

- Captured `ui/presentation.json` declares exact input/output contracts for
  literal `ui_scene` calls. Pin/schema/response validation is deterministic and
  uses the existing closed type vocabulary; checked record projections preserve
  ordinary collection rules.
- Operator-owned `DAY2_PRESENTATION_PIN_JSON` independently approves executable
  digest, ABI and contracts. Startup captures checked regular bytes privately,
  then uses the existing isolated framed worker. App/package metadata is not
  execution authority; absent declarations leave the existing path unchanged.
- `Port`, exchange and starter abstractions separate template rendering from
  process startup/recovery. `AdmissionWait` makes the admission scheduler explicit.
  Only `SystemWait` reads a monotonic clock/sleeps; virtual schedules exercise the
  same exclusive two-second deadline without wall-clock assertions.
- Scene results are memoized within one render (eight-result bound), then rendered
  by ordinary escaped/admitted templates. Authority/binding/session are checked
  again after slow work. Frame/exchange/isolation budgets do not change.
- The Roc example owns persisted samples, checked half-open ranges and normal
  commands. Browser navigation injects network/parsing/timer/DOM adapters and
  preserves accepted charts/drafts on stale, failed or cancelled responses.
  Clanker UI owns ECharts and component contracts, not Platform.

## Verification and migration

Seeded restart/contention and browser schedules use independent state models and
seed/step traces. Pure admission, actual capture, recorded protocol, real confined
worker, ordinary Native app build and browser acceptance are separate evidence.
Current browser/full-Platform/application-DST/cold-restore/release gates remain
open. Source adoption is opt-in; reviewed executable configuration stays private.
Unrelated login changes and installed package bytes are excluded from this diff;
existing historical worktrees and running instances remain untouched.
