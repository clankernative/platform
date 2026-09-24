# Schedule contract

Applications declare pure commands and schedule declarations. Instances explicitly
bind a schedule's actor. The host persists occurrences, bounds catch-up and admits
each invocation under current authority. A schedule does not grant credentials or
turn an app into a general background worker.

See the public [Reports schedule](../examples/reports/schedules/Schedules.roc),
[schedule SDK](../sdk/contracts/Schedule.roc), and
[command runtime](COMMAND-RUNTIME.md). Product-specific schedule inventories and
migration plans remain in private application repositories.
