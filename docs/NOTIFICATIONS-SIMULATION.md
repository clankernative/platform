# Local Notifications adapter coverage

The required provider-world gate drives all three Notifications actions through
production operation policy, resource binding, current authority, reservation,
the actual adapter and usage settlement. Its contract fixture needs no Roc
worker; this is adapter/authorization evidence, not native artifact or live
notification-service qualification.

Recipient resolution is a pure projection of the admitted invocation actor.
It must return that actor, refuse impersonation, and leave provider state alone.
It is deliberately not described as a world-dependent read. Latest-message reads
use distinguishable SQLite mailboxes and must reflect only the current
scope/actor/topic. Sends must change only the declared Notifications world and
return the stable effect receipt. The checker itself is exercised with constant,
missing, landless, wrong-world and mutating-read substitutes.

The harness also refuses foreign/substituted handles, malformed payloads and a
resource policy that denies sending while the operation policy still allows it.
Provider acceptance followed by a discarded reply, retry and conflicting-payload
retry run through real authorization and a reopened committed mailbox.

Eight fixed seeds each run 24 steps twice against an independent accepted-request
history. Every step compares the complete provider state and all other declared
worlds; the reference never calls the production send/latest transitions.
Observed sends, duplicates, conflicts, impersonation refusals, scoped reads and
discarded-reply retries must all be nonempty. Missing campaign output fails its
CI artifact step, including if the seeded test stops running.

CI retains `day2-notifications-coverage-<run>-<attempt>` and, on failure,
`day2-notifications-replays-<run>-<attempt>` for 14 days. Replay seeds contain only
the format, compiled campaign digest and numeric seed, never bodies, handles,
credentials, raw snapshots, environments or error strings:

```console
DAY2_NOTIFICATIONS_REPLAY=<failure.json> bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib integrations::coverage_tests::notifications::replay_saved_notification_history --exact
```

Use the CI revision when replaying: the compact bundle binds the campaign source,
not an independently retained native/compiler closure. Unknown fields, oversized
bundles and a changed campaign are refused before execution. No cloud credentials
or network services are involved, and runtime outcomes are never cached.
