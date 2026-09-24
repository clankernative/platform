# People Ops provider contracts

The People Ops canary uses typed, resource-scoped SDK capabilities backed by
explicit synthetic SQLite providers. It makes no Google, Linear or Slack calls,
uses no provider credentials and creates no real accounts. Business policy,
cross-provider ordering and partial-failure decisions remain in Roc.

| SDK pack / resource slot | Operations and observable outcomes | Operator-owned scope |
| --- | --- | --- |
| [GoogleDirectory](../sdk/contracts/GoogleDirectory.roc) / `google_directory` | `snapshot(context)` captures directory facts; `next_with(resource, snapshot_id, cursor)` yields `User`, `Group`, `OrgUnit` or `Done`. `create_user` returns `Created`, `Conflict` or `Failed`; `patch_attributes` returns `Patched` or `Failed`; `ensure_group_member` returns `Added`, `AlreadyMember` or `Failed`. | Exact customer and email domain, organization subtree, and an approved role/email-to-group mapping. A grant role such as `engineering` is resolved by this mapping, not treated as an arbitrary group address. |
| [Linear](../sdk/contracts/Linear.roc) / `linear` | `ensure_access` returns `Active`, `Reactivated`, `PendingInvitation`, `Invited`, `Disabled` or `Failed`. `suspend` returns `Suspended`, `AlreadySuspended`, `NotFound`, `Disabled` or `Failed`. | Exact organization and email domain. Lookup, pending-invitation reconciliation and mutation are one provider's semantics. |
| [OperatorAlerts](../sdk/contracts/OperatorAlerts.roc) / `operator_alerts` | `send(resource, topic, body)` returns `Accepted`, `Disabled` or `Failed`. Acceptance records one message; it does not claim human delivery. | Fixed configured destination and allowed topics. The canary grants only topic `people_ops`; app input cannot choose a recipient. |

`Problem` contains `code`, `message` and `retryable`. These typed failures let the
app finish and expose provider-specific outcomes. They are distinct from native
protocol, authorization or transport errors that abort an invocation.
Diagnostic messages and operator bodies preserve bounded multiline text.

The [native implementation](../crates/day2/src/people_providers.rs) persists Google,
Linear and alerts in separate SQLite files, outside the business transaction. Each
provider records a stable effect-identity ledger with its decoded payload and
result, rejecting payload substitution. Call histories distinguish physical
attempts, replayed effects and actual changes. This synthetic deduplication is not
a claim that a future Slack or other live adapter can safely retry unknown writes.

Directory captures are immutable and scoped to the installation/app, customer and
resource limits. Paging a capture with broader-than-authorized facts is rejected.
The app imports one fact per captured child command and persists its cursor;
`directory_status.complete` identifies a fully imported run. Local user queries
filter an exact organization path using ASCII case folding; an empty path selects
all users in the authorized capture. OU pages use SQLite UTF-8 ordering. The
source uses .NET `OrdinalIgnoreCase` filtering and UTF-16 string ordering, so full
non-ASCII directory comparison parity remains unqualified.

The synthetic limits are 10,000 directory records, 16 KiB requests/record responses,
32 MiB stored provider state, and 100,000 call/ledger entries. Attribute patches
allow at most 64 entries; alert bodies at most 8,000 bytes. Resource grants and the
runtime's per-invocation limits independently bound execution. Oversized state is
rejected, not silently truncated.

Tests explicitly seed `SyntheticFixture`, inspect provider state and schedule
`Definite` failures before mutation or `PatchVerificationMismatch` after the
attribute change. The latter retains the external mutation while returning a
failed verification result. Lost acknowledgement is modeled by performing an
effect and dropping its result before settlement; it is not modeled as a definite
provider rejection. The default fixture includes users, groups, organization units,
active/suspended Linear users and a pending invitation.

Only explicit development/verification campaigns initialize missing synthetic
targets for artifacts that admit these capabilities. Custom seeded state is
preserved. The generic campaign alone adds a one-shot retryable Linear suspension
failure for `demo_hire@exampleco.example`, so `retry_deprovision` has a concrete
positive example. `synthetic_example()` and independently seeded native histories
do not include that fault.

Live authentication, Google readback behavior and provider-specific unknown-write
reconciliation still require real adapters. The separate
[operator recovery API gap](OPERATOR-RECOVERY.md) remains even with complete
live adapters; it does not require changing the app's existing Handler phases.
