# Notifications: owner-authorized configuration and Slack delivery

This versioned Roc app implements configuration and publication flows from the
Notifications business source, rather than its old starter CRUD port:

1. Check the current human's app ownership through generated
   `ImportedContracts.app_ownership_check({ app_id })`.
2. Read an event's current configuration, save against its expected revision, or
   validate and preview a message.
3. Create a new contract version with `version=0`, or edit a positive version's
   template while preserving its field schema.
4. Enable publication, accept an event against an explicit contract version, and
   deliver its captured message to the operator-bound Slack channel.

Every app-scoped operation checks ownership before reading or changing business
state. A negative or mismatched decision refuses the operation. A missing grant,
unavailable receiver, invalid response or stale serving selection fails in the
host before the business transaction. Preparation crosses the app boundary
without holding a SQLite transaction. As with the source application's remote
authorization, ownership can change after that check; this is not a distributed
transaction spanning both applications.

Save atomically updates the definition and version and inserts an immutable
actor-attributed change record. A stale revision, missing version or schema change
rolls back all writes. The ordinary command runtime supplies durable acceptance,
idempotency and status; there is no remote mutation to reconcile in this flow.
The editor retains the original save input and idempotency key until the outcome
is resolved, including across page reloads.

Text, integer, boolean and enum fields are supported. The domain preserves the
source's identifier rules and UTF-16 length limits, including astral Unicode.
Payload substitution is one pass: inserted text cannot create a placeholder.
Preview is a POST command with no declared business writes, so complete schemas
and payloads use the bounded JSON body instead of exceeding GET's URL limit.
Valid schemas have at most 20 fields and enum choices at most 50. The API returns
complete collection envelopes for schemas, choices and findings. Oversized field
and payload sets are rejected; repeated unknown-placeholder findings are
deduplicated. No result is silently truncated. Field schemas are canonical,
app-owned JSON content within a nominal contract-version row, with a typed codec
and invariant checked on every read/build. Relationships use nominal references.
Stored schemas also obey the host's 16 KiB text bound. Larger admitted schemas
return `invalid_configuration` before writing; preview can still validate their
supplied schema and payload within the host's POST body budget.

The UI covers the common `summary` text field; the same typed API supports the
other field kinds. It renders preview text with `textContent`.

## Publication and Slack delivery

New events start disabled. `set_enabled` checks ownership and the expected
configuration revision, records an actor-attributed change, and requires an
activated `notification_channel` resource binding when enabling. The binding is
operator authority, not a live readiness probe. Saving a template preserves the
existing enablement. Disabling prevents new publications; it does not cancel an
accepted command.

`publish` accepts an explicit positive contract version, a stable publication ID
and typed named payload values under inherited human authority. It checks current
ownership and the channel grant before accessing business state. In one decision
transaction it deduplicates by app/publication ID, validates enablement and the
exact version, and snapshots the immutable field schema, normalized payload,
rendered message, accepted template revision, latest version, actor, time and
original invocation. It then uses `pf.Slack.post` outside the business transaction.
Completion may update only this invocation's created publication with a validated
Slack channel/timestamp acceptance receipt. Slack acceptance does not certify that
every channel member read the message.

A retained duplicate returns the original receipt before consulting current
enablement or the current template, without another provider call. Changed event,
version or business payload under that ID is refused. Payload order and unused
structural codec fields do not change its business identity. Rejected publications
do not reserve an identity; native transport idempotency still requires the same
input for the same transport key.

`publication` rechecks ownership and returns the retained receipt without message
or payload content. `slack_accepted=false` means no confirmed completion receipt;
it never proves non-delivery. The original invocation status URL exposes the
ordinary host's pending, failed, blocked or successful result, separately scoped
to its original actor and current authority. A receiver outage, policy change or
unknown provider outcome cannot silently become successful delivery.

The ordinary command scheduler owns continuation and recovery. No app delivery
worker, queue, lease, timer or retry loop is added. Slack has no admitted provider
deduplication or reconciliation contract: a dispatched timeout/lost response stays
uncertain in the host ledger and is not automatically retried. A new transport key
with the same publication ID cannot resend that retained publication. The editor
keeps exact pending input and transport identity across reloads; uncertain work
requires inspecting the original status, not inventing another publication ID.

The first profile retains at most 256 publications, each with a payload within the
host's 16 KiB text bound and a message within the domain's 3000 UTF-16-unit bound.
Capacity exhaustion refuses new acceptance; receipts are never silently forgotten.
Automatic content expiration/retention, EngOps route provisioning, group ownership,
machine-origin publication and callbacks remain outside this human-origin profile.
The source's two-attempt worker policy is deliberately not applied to an ambiguous
Slack post, whose provider does not establish retry safety.

The operator pins one workspace, channel and credential version in the normal
resource catalog and grants only `slack_post` to `notification_channel`. Apps cannot
choose recipients or credentials. The native HTTP campaign uses real Roc workers,
separate app databases and signed ownership HTTP calls, with explicitly offline
Slack transport through the real adapter. That profile is not live Slack evidence.
The [Day2 bot manifest](../../deploy/slack/day2-bot-manifest.json) requests only
`chat:write`; invite it to the reviewed channel and provision its token through
the normal numbered Secret Manager credential mount.

Source oracle: Notifications revision
`38bd9ab974e6757e1f6e9689d56e051ecde1534e`, specifically
`Notifications.Application/Notifications/NotificationHandler.fs`,
`Notifications.Domain/Notifications.fs` and
`Notifications.Infrastructure/Notifications/RemoteAdapters.fs`.

`xtask build-delegation-business` builds the ownership exporter first, pins the
candidate catalog through the normal import-lock path, then builds this app.
The full gate and native Linux qualification run the signed two-host HTTP
campaign in `day2-control/tests/release_execution/notifications.rs`. Instance
authority must grant Notifications its exact query import, all configuration rows
for its app-owned authorization decisions, and only the declared local writes.
Use the existing qualified GKE release workflow for the resulting native artifacts;
macOS artifacts are development evidence only.
