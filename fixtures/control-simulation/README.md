# Control simulation regressions

These are bounded synthetic operation schedules, not applications, company
instances, or recordings from live providers. They run through the production
control host and SQLite journal with a shared simulated provider world.

| Schedule | Boundary |
| --- | --- |
| `lost-publication.json` | An accepted check publication survives a lost acknowledgement and host restart without a second mutation. |
| `unknown-publication.json` | A publication claim with no observable receipt remains intervention-needed; other executions still drain. The simulator must not invent provider idempotency. |
| `release-readiness.json` | An incumbent remains active while a successor encounters missing readiness, wrong Git evidence, cross-company requests, and stale proofs. Fresh readiness permits the qualified successor to activate. |
| `workflow-competition.json` | The compiled release recipe converges competing approved revisions and an independent company through the durable host. |
| `workflow-lost-ack.json` | Applied dependency preparation is reconciled after a lost acknowledgement and process reconstruction, without a second mutation. |
| `workflow-secret-revision.json` | Watcher-delivered secret revisions invalidate old readiness and require new deployment preparation/readback before activation. |

`ops/Simulation.roc` runs every committed schedule and replays its resulting trace
before generated cases. The source catalog and campaign evidence pin this corpus.
`tests/simulation.rs`, `tests/simulation_acceptance.rs`, and
`tests/simulation_workflows.rs` add generative checks,
negative probes, and explicit successful outcomes so refusing every request cannot
pass acceptance.

```text
cargo run --locked -p xtask -- simulate-control 42 32
cargo run --locked -p xtask -- replay-control TRACE.json
```

The runner prints its evidence directory under `artifacts/control-simulation/`.
Property-test failures retain a replayable latest failing candidate under its
`proptest/` subdirectory. Review and minimize a failure before adding a regression
here; test execution never automatically changes the approved corpus. Do not put
credentials, secret values, customer records, or production instance configuration
in these fixtures.

See [the lab scope and next gates](../../docs/DETERMINISTIC-LAB.md) and the
[release workflow](../../docs/RELEASE-WORKFLOW.md). The workflow runs through the
production host; its synthetic providers are not qualified cloud adapters.
