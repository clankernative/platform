# Ordinary backup/restore histories

`crates/day2-ops/tests/reports/backup_lifecycle.rs` drives the production
`backup::take`, `verify` and `restore` adapters against real SQLite and a normally
built Reports artifact. Four fixed seeds each generate a bounded 35-event
history, executed twice in fresh directories. The mandatory prefix covers an
uncommitted WAL writer, rollback, later commits, two caller-lost successful
replies, duplicate output attempts, corrupt database/artifact bytes and a bundle
without its final completion marker. The suffix varies further writes,
transaction completion, verification and restore attempts.

The independent model derives complete Reports rows, revisions and immutable
snapshot expectations from events. It never reads an adapter receipt or a
database to choose expected rows. Every cut compares all committed and in-transaction Reports columns, transaction state,
source/snapshot authority continuity, stable restored epochs, browser session/secret counts, bundle
verification and every restored output. Restores must have distinct new epochs,
one revision advance, disabled authority, cleared desired readers/writers and
browser secrets, and refusal of ordinary authorization. Normalized observations
omit temporary paths and random epoch values; their equality and uniqueness
relationships are still checked. Unexpected partial output is a divergence.

Lost replies are discarded **after** a successful local call. They do not model
process death inside SQLite, prove an unapplied write, or authorize a retry. A
second attempt at an existing output must refuse. The event harness also refuses
nested source transactions; that is a harness precondition, not an authority
decision attributed to production. The tests do not resume pending commands or
add a restore path. The existing Roc backup recipe remains the only operational
composition.

On divergence, the original program, complete expected/actual record prefix and
failing position are retained privately under
`artifacts/simulations/backup-lifecycle/replay-*.json`. A deliberately wrong oracle
that includes an uncommitted row must fail at the snapshot cut and reproduce the
same retained failure. Separate controls reject false saved observations, stale
source/artifact identities, duplicate JSON fields, unknown fields and out-of-range
events. Replay has a two-MiB input bound, at most 64 events, and the shared strict
JSON decoder's depth/node bounds. The source identity binds the compiled backup
adapter, authority-state implementation and campaign; it is not a whole-platform
or native-runtime receipt. Counterexamples are not minimized by this slice.

Run locally with the pinned tooling and an actual artifact (the full operations
gate supplies this artifact normally):

```text
build-out/bin/xtask build examples/reports
DAY2_TEST_REPORTS_ARTIFACT=<published artifact directory> build-out/bin/xtask test-rust //crates/day2-ops:reports backup_lifecycle:: --test-threads=1
```

For a retained record, additionally set `DAY2_BACKUP_REPLAY` to that file. The
external replay test checks the saved content against two fresh executions.
Absent input is explicitly optional and is not a saved-corpus pass. These tests
run in the ordinary workspace operations target; CI retains failed histories
from the workspace-other shard.

This is bounded ordinary-adapter coverage. It does not qualify managed-secret
restore, current external security authority, native enrollment/P3/writer owners,
cross-store atomicity, physical crash/power-loss durability, remote object-store
upload, or deployment behavior. Credential's managed-store backup tests and
separate Linux/native qualification retain their own scopes.
