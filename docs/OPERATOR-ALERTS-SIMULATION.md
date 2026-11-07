# Synthetic operator-alert coverage

The provider-world gate sends operator alerts through real operation policy,
resource binding, current authority, budget reservation, the SQLite adapter,
settlement and result validation. A host contract fixture runs no Roc worker
and contacts no live service.

Enabled and disabled destinations must produce distinguishable results. An
accepted send changes only its declared alert world; a disabled send changes
no business state. Positive baselines precede constant-result, missing-adapter,
missing-effect, wrong-world and mutating-disabled-world substitutes. Other
controls refuse foreign topics, actors and handles, destination substitution,
empty or oversized messages and current resource-policy revocation. Reusing an
old effect cannot bypass the revoked actor's resource authority.

Eight fixed seeds each run 29 logical steps twice against an independent
accepted-request list. Every step compares complete messages, effect ledger,
call history and fault schedule, plus all seeded foreign targets, scopes and
providers. A real foreign alert proves that the isolation guard notices changes.
Histories compose acceptance, disabled destinations, definite failures, duplicate
effects, discarded replies and topic refusals. A definite failure stays cached
for that effect; a new intent can recover. Conflicting payloads leave the store
unchanged and retain their unknown-usage reservation. An otherwise-valid next
call must fail at the unchanged one-slot concurrency budget. All eight declared
outcome/replay categories must be observed.

CI retains `day2-alerts-coverage-<run>-<attempt>` and, on failure,
`day2-alerts-replays-<shard>-<run>-<attempt>` for fourteen days. Missing success output
fails its artifact step. Failure bundles contain only the format, compiled
campaign-source digest and numeric seed, never alert bodies, handles,
credentials, raw snapshots or error text.

```console
DAY2_ALERTS_REPLAY=<failure.json> bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib integrations::coverage_tests::alerts::replay_saved_alert_history --exact
```

Use the CI revision for replay. The bundle binds the campaign file, not a
complete independently retained compiler/native closure. Unknown fields,
oversized bundles and changed campaign sources are refused before dispatch.
This establishes synthetic adapter/authorization coverage, not native-worker,
live delivery or production qualification. Runtime outcomes are never cached.
