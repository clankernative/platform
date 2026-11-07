# Synthetic Linear adapter coverage

Both Linear actions run through the real operation policy, resource binding,
current authority, budget reservation, SQLite provider, settlement and result
validation. A contract fixture supplies host metadata; it runs no Roc worker
and contacts no live Linear service.

The shared provider-world gate checks distinguishable account identities and
requires the effect to land only in the declared Linear world. Passing baselines
precede constant-result, missing-adapter, missing-effect and wrong-world
substitutes. Separate controls refuse foreign domains, actors and handles,
target substitution, malformed inputs and revoked resource actions, including
reuse of an earlier effect after revocation.

Eight fixed seeds each run 34 logical steps twice. An independent ordered
account and accepted-request history predicts complete users, invitations,
effect ledger, call history and fault schedule. It covers active and reactivated
users, pending and new invitations, suspended and already-suspended accounts,
missing accounts, disabled providers and definite provider failures. Accepted
or expired invitations cannot masquerade as pending invitations. Each step also
checks every seeded foreign target, scope and provider partition. A real foreign
write proves that this guard detects a mutation rather than comparing empty
snapshots.

Histories compose duplicate delivery, discarded accepted replies, definite
failures and domain refusals. The same effect replays its result, including a
definite failure; only a new intent can execute again. A conflicting payload
must fail without changing the provider. Its unknown-usage reservation remains
held under the existing one-slot concurrency budget; a subsequent otherwise-valid
call must fail at that budget. No fixture raises or releases the budget to
continue. All fourteen declared outcome/replay categories must be observed.

CI publishes `day2-linear-coverage-<run>-<attempt>` and retains
`day2-linear-replays-<shard>-<run>-<attempt>` on failure for fourteen days. A missing
success receipt fails the artifact step, so silently dropping the campaign
cannot leave a green run. Failure bundles contain only a format, campaign-source
digest and numeric seed, never provider data, handles, credentials or errors.

```console
DAY2_LINEAR_REPLAY=<failure.json> bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib integrations::coverage_tests::linear::replay_saved_linear_history --exact
```

Use the CI revision for replay. The bundle pins the campaign file, not a complete
independently retained compiler or native-action closure. Unknown fields,
oversized bundles and changed campaign sources are refused before dispatch.
These are synthetic adapter and authorization checks, not native-worker,
live-provider or production qualification. Runtime outcomes are never cached.
