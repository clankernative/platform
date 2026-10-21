# Schedule contract

Applications declare pure commands and schedule declarations. Instances explicitly
bind a schedule's actor. The host persists occurrences, bounds catch-up and admits
each invocation under current authority. A schedule does not grant credentials or
turn an app into a general background worker.

See the public [Reports schedule](../examples/reports/schedules/Schedules.roc),
[schedule SDK](../sdk/contracts/Schedule.roc), and
[command runtime](COMMAND-RUNTIME.md). Product-specific schedule inventories and
migration plans remain in private application repositories.

## Occurrences

Occurrences are derived from the clock, not stored. A schedule shorter than a day
(`every_minutes`, `every_hours`) occurs at every multiple of its interval since
the Unix epoch. A daily schedule (`daily_at_hour`) must declare a UTC anchor hour
and occurs at `k * interval + hour * 3_600_000` milliseconds since the epoch, so
`daily_at_hour(10, ...)` runs at 10:00 UTC. The occurrence names the invocation
(`schedule.<app>.<name>.<occurrence ms>`) and is the run's `Context.now`, so a
late tick produces the same invocation an on-time tick would have.

The source reads the most recent occurrence it offered back from the invocation
table. If that occurrence is not on the schedule's current grid -- a run recorded
before anchors were honoured, when every daily schedule ran at 00:00 UTC, or
before an app changed its declared hour -- it counts as the run of the anchored
occurrence that covers it. Each anchored occurrence still runs at most once and
none is skipped: an installation that last ran at 00:00 runs nothing more until
the next anchor hour, then continues on the anchored grid. `Coalesce` and
`RunEach` catch up only anchored occurrences after that point.
