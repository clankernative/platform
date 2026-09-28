# On-call escalation example

This small app models incidents as `Open`, `Acknowledged`, or `Resolved` with a
monotonically increasing escalation rung. Opening an incident atomically creates
it and defers an internal escalation attempt for 300 seconds. Each admitted
attempt re-reads current incident state: open incidents advance through rung 3
and defer another attempt; acknowledged or resolved incidents complete normally
without changing the rung. The app owns those result reasons.

Acknowledgement is a version-checked edit. Deferrals intentionally have no
version fence, so an escalation admitted before acknowledgement still runs and
observes the latest row when drained. `crates/day2/tests/oncall_escalation.rs`
exercises offer, execution, policy changes, and operator recovery with real
SQLite state.

Build from the platform repository root with:

```console
cargo run --locked -p xtask -- build examples/oncall
```
