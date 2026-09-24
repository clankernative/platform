# Resource grants, policy activation and durable consumption

This guide describes the implemented enforcement. Executable providers include
the local notification mailbox, explicitly seeded synthetic provider fixtures,
and [reviewed Slack, Snowflake and OpenAI adapters](LIVE-INTEGRATIONS.md). Live
account qualification is separate from adapter tests. Other names in the
integration inventory remain a roadmap, not enabled capabilities.

## Enforcement

An operation must pass both its existing business policy and an activated resource
binding. The binding specifies provider connection, exact resource version,
actions, actors, request/response ceilings, invocation call ceiling, expiry and
durable budget accounts. Missing bindings deny access. Connecting a provider does
not grant app access.

HTTP pages and API calls resolve to the same registered operation for grant and
budget checks. A page's internal route alias does not create separate authority.

`day2-capabilities::resources` defines the shared desired catalog and attachments.
Activation resolves these into `AuthorityDocument.resources` in the app database.
The snapshot contains concrete targets and bounds plus policy, resource,
connection and budget versions. Execution never resolves mutable catalog names.
Editing desired configuration cannot remap an active handle.

Targets include an invoking actor's notification mailbox with explicitly selected
topics, prefix or all-topic scope; a particular synthetic Carta issuer; and the
reviewed Slack, Snowflake and OpenAI profiles described in [live integrations](LIVE-INTEGRATIONS.md). Notification
access still cannot select another recipient. Carta issuer selection happens in
the provider query before records are returned. Discovery, record reads and sending
are separate actions. Unknown kinds, versions and fields fail closed.

Host-issued handles are tied to installation, app, artifact, operation, invocation,
actor and authority stamp. Every provider use checks the binding and action again.
Handles can narrow actions, topics, limits and expiry; copies share accounting. Cached
observations retain provenance and are revalidated before returning to app code.
Expiry cannot be bypassed by replaying an earlier preparation into a later phase.

The SDK requires the opaque operation `Context` to issue a handle. Helpers given
only a handle can use or narrow it; they cannot obtain a broader grant. Passing
the context explicitly delegates issuance authority. This relies on the pure app
and admitted SDK boundary. It does not establish hostile native-code containment
or prove that information read under one grant cannot be sent under another.

For example, a preparation phase can restrict its notification binding to one
report topic before giving it to a helper:

```roc
prepare_recipient : Context, Str -> Observe(Notifications.Recipient)
prepare_recipient = |context, report_topic|
    Resource.bind(context, "notifications")
        .and_then(|grant| Resource.only_topics(grant, [report_topic]))
        .and_then(|grant| recipient_for(grant, context.actor()))

recipient_for : Resource, Str -> Observe(Notifications.Recipient)
recipient_for = |grant, actor| Notifications.resolve_with(grant, actor)
```

The resulting recipient carries the narrowed handle into `Notifications.send`.
Sending another topic is rejected by the host. The helper has no `Context` with
which to request the original binding. `Resource.restrict_actions`,
`Resource.restrict_limits` and `Resource.expires_at` provide additional narrowing;
expiry is an absolute Unix timestamp in milliseconds. Existing conveniences such
as `Notifications.resolve(context)` bind the operation's named slot directly.
Reports and Equity have been migrated to the Context-based SDK; ordinary pure
database operations require no resource-handle changes.

## Reusable policy shape

`Instance.resources` holds connections, resources, policies and budgets.
`apps[app].resource_policies` attaches a versioned policy to an operation and binds
its named slots to allowed resource versions. A policy names allowed apps, actors,
an owner/delegates, and an optional maximum access duration. Attachments can narrow
actors and set expiry; actions and request limits come from the policy ceiling.

For example, a catalog allowing a Reports operation to send its invoking actor a
notification only on topics beginning with `rep_` has this shape. Reports uses the
report ID as its notification topic:

```json
{
  "version": 1,
  "connections": {
    "mailbox": {"revision": 1, "provider": "local_notifications"}
  },
  "resources": {
    "report-notifications": {
      "revision": 1,
      "connection": {"id": "mailbox", "revision": 1},
      "target": {
        "kind": "notification_mailbox",
        "topics": {"kind": "prefix", "prefix": "rep_"}
      }
    }
  },
  "budgets": {
    "reports-calls": {
      "revision": 1, "scope": "app", "period_seconds": 86400,
      "limits": {"calls": 1000, "bytes": 2000000,
                 "cost_microunits": null, "concurrency": 4}
    }
  },
  "policies": {
    "report-delivery": {
      "revision": 1, "owner": "reports-owner@example.com", "delegates": [],
      "actors": ["alice@example.com"], "allowed_apps": ["reports"],
      "max_duration_seconds": null,
      "slots": {
        "notifications": {
          "kind": "notification_mailbox",
          "allowed_resources": [{"id": "report-notifications", "revision": 1}],
          "actions": ["notifications_resolve", "notifications_send"],
          "limits": {"max_request_bytes": 10000, "max_response_bytes": 1024,
                     "max_calls_per_invocation": 3},
          "budgets": [{"id": "reports-calls", "revision": 1}]
        }
      }
    }
  }
}
```

Attach it to an admitted operation (use the actual app's operation name):

```json
{
  "policy": {"id": "report-delivery", "revision": 1},
  "operation": "reports.notify",
  "bindings": {"notifications": {"id": "report-notifications", "revision": 1}},
  "actors": ["alice@example.com"], "expires_at_ms": null
}
```

This example grants sending access. The Reports detail page also needs a binding
with `notifications_latest` on `reports.detail` to display notification status.

The business policy must separately permit these actors and capability actions.
Resource resolution intersects with those ceilings and cannot restore a revoked
business permission. Changing a definition requires a new revision. The authoring
service keeps an append-only version registry, including retired definitions, so
deleting and recreating an identifier cannot reuse a version with new meaning.
Recording a version precedes replacing the desired file; a crash can reserve a
version, and retrying the same bytes remains safe.

## Real administration

Start the service with:

```text
./platform/cli/day2 platform authority admin INSTANCE_JSON LOCAL_OPERATOR
```

Open the printed session URL. The service binds loopback on a separate port and
issues an eight-hour, process-local bearer. The browser removes it from the URL
and keeps it in memory. App cookies do not authenticate this service. Host, Origin,
content type and bearer are checked on every API request. Responses cannot be
framed and do not permit cross-origin API access. Use the launch URL again after
refresh; relaunch after the server restarts or the session expires.

This is authenticated local operator administration. The launcher's identity is
still a trusted local assertion, as in the existing CLI. Production SSO, remote
identity verification and deployed organization administration remain separate
integration work.

Installation administrators are `Instance.control.operators`. They edit catalog
definitions, grant ownership and allocate company capacity. Policy owners and
delegates can stage attachments only within unchanged pinned templates for allowed
apps. They cannot increase the ceiling. Mixed-owner source/destination combinations
require an installation administrator. App membership, business-policy `admins`
and ordinary app sessions confer no administration authority.

The interface displays active/proposed grants, exact provenance, recorded reviews,
usage and outstanding reservations. Policy pickers offer approved resources; an
advanced editor exposes the shared contract for initial authoring. Staging changes
does not activate them.

The browser refuses integers outside its exact range (plus or minus
9,007,199,254,740,991), and rejects decimal or exponent notation in these integer
contracts. It never silently rounds a limit or converts an invalid expiry to null.
Use the native CLI for larger ledger values; native accounting retains its full
integer range.

A review stores the concrete document, artifact and expected authority stamp.
Approval records its decision and performs compare-and-swap activation in the same
app transaction. The approver explicitly reviews combined sources, destinations,
principal and usage. Denial preserves existing access. Unrelated catalog edits do
not invalidate an unchanged resolved document. Changed artifacts, stamps or grants
require a new review. Reviews and decisions are append-only.

Resource administration retains the active business policy, memberships and enabled
state. It cannot apply unrelated desired membership edits, switch an artifact or
enable a disabled app. Supported catalog writers serialize with approval, so a
completed delegation revocation precedes subsequent approval admission.

CLI equivalents run the same private Roc workflows and native guards:

```text
day2 platform resources catalog INSTANCE APP LOCAL_OPERATOR
day2 platform resources preview INSTANCE APP LOCAL_OPERATOR
day2 platform resources reviews INSTANCE APP LOCAL_OPERATOR
day2 platform resources save INSTANCE APP LOCAL_OPERATOR AUTHORING_JSON_FILE
day2 platform resources attach INSTANCE APP LOCAL_OPERATOR ATTACHMENT_REQUEST_FILE
day2 platform resources propose INSTANCE APP LOCAL_OPERATOR PROPOSAL_JSON_FILE
day2 platform resources decide INSTANCE APP LOCAL_OPERATOR DECISION_JSON_FILE
```

`catalog` returns the revision for compare-and-swap saves. `preview` supplies the
active stamp for a proposal. Input shapes are the public `Authoring`, `Attach`,
`Proposal` and `Decision` contracts in `resource_admin.rs`.

## Durable usage and company capacity

Admission reserves usage in the same transaction as authority and resource checks.
The provider is called after commit. Every applicable meter must satisfy:

```text
settled usage + outstanding reservations + maximum new usage <= limit
```

Meters support calls, request/response bytes, integer monetary microunits and
concurrent attempts. Actual bytes are accounted before a response is rejected for
exceeding a grant. The current local providers have zero external monetary charge.
OpenAI uses the activated reviewed tariff; those charges are platform accounting,
not a guarantee about a provider's invoice.

Known results settle idempotently and release unused capacity. Unknown outcomes
retain their maximum reservation. Each physical retry needs another admission and
reservation; provider effect deduplication is separate from billing deduplication.
Already admitted work can settle after revocation without authorizing new business
writes. An overrun records the full amount and freezes admission. Operator overrun
resolution must name the exact outstanding incident set and record a reason and
repair/reconciliation evidence; it preserves balances and quota checks.
The CLI equivalent is `day2 platform resources resolve-overruns INSTANCE APP
LOCAL_OPERATOR RESOLUTION_JSON_FILE`.

App, actor and connection budgets aggregate operations in one app database.
Invocation-root usage follows children and cannot be reset by spawning a command.
Actor/connection counters are **not company-wide counters**. Installation budgets
use centrally committed, disjoint fixed allocations:

```text
day2 platform resources company-setup INSTANCE APP LOCAL_OPERATOR
day2 platform resources allocate INSTANCE APP LOCAL_OPERATOR ALLOCATION_JSON_FILE
```

The central ledger's identity is pinned separately. New allocations and restore
recovery fail closed if that ledger is missing or replaced. Already imported fixed
capacity can be consumed independently; the allocator is not a live revocation
service. Capacity commits centrally before import into the app; a crash can strand
capacity but cannot duplicate it. Retries reuse the original allocation/window,
including after a window or policy change. Capacity is not automatically returned
or copied from a backup. This is fixed allocation, not cross-database ACID.

Quota changes preserve accounting identity and consumption. Windows use trusted
host admission time. Unknown concurrency survives rollover, and invocation-root
usage does not reset at a window boundary. OpenAI reserves a conservative quote
at the reviewed model tariff and settles reported usage; missing usage retains
the hold. Snowflake does not support monetary grants. Platform tariff accounting
is not a provider invoice guarantee; see [monetary limits](LIVE-INTEGRATIONS.md#monetary-limits-and-uncertain-outcomes).

Installation-pool ceilings can be raised through a new definition. Lower positive
ceilings require a coordinated reduction in the real administration page under
**Policies & resources → Company capacity**. The review names an exact current
definition, next definition, current period and explicit amounts each app returns.
It cannot remove a meter, rewrite a past period, or infer that an unavailable
app's allocation is unused. Company concurrency remains one persistent pool.

Recording the review pauses new central allocations for that budget. Existing
apps can still consume their allocations until each reviewed app return commits
under its admission lock. The app imports any outstanding committed allocation
receipts, checks that retained capacity covers all spent amounts and unresolved
holds, and records an immutable return. Every later admission subtracts those
returns; importing an old or cached allocation receipt cannot restore capacity.
SQLite admission triggers enforce the remaining imported capacity, including
first-use accounts and future periods. A host that was already running before
the reduction cannot restore the original limit through its older reservation
SQL. Central SQL guards also fence pending reviews, stale company definitions,
and allocations above the current ceiling. The exact trigger definitions are
pinned during schema initialization; missing or changed established guards stop
admission initialization. Settlement can still record full actual usage above a
cap and retain its overrun freeze.
The allocator reads that committed app receipt directly before crediting it. Only
after every reviewed return is acknowledged and outstanding allocations fit the
new ceiling can the central reduction commit. Current and future periods use the
lower ceiling; historical period caps and all liabilities remain intact.

Import the verified central completion proof into an app before activating its
lower budget definition. Importing proof does not activate grants or edit desired
configuration. Stage the approved definition in the catalog, update its version
references, and approve affected app reviews normally. Apps retaining an older
active definition still obey their reduced local allocation. Their next central
allocation requires the current company definition.

A crash between local return and central acknowledgment can temporarily strand
capacity; retrying the same review and app ledger recovers the exact return. A
cancelled review retains the original company ceiling and keeps completed returns
available centrally. It never resurrects app allocations; replenishment is an
explicit new allocation. Late acknowledgments of already committed returns remain
valid after cancellation. This protocol provides durable fences and replayable
receipts, not cross-database ACID or immediate remote revocation.

The same atomic operations are available through the Roc operational workflow:

```text
day2 platform resources company-budget INSTANCE APP LOCAL_OPERATOR
day2 platform resources pool-propose INSTANCE APP LOCAL_OPERATOR REDUCTION_JSON_FILE
day2 platform resources pool-return INSTANCE APP LOCAL_OPERATOR RETURN_JSON_FILE
day2 platform resources pool-decide INSTANCE APP LOCAL_OPERATOR DECISION_JSON_FILE
day2 platform resources pool-import INSTANCE APP LOCAL_OPERATOR PROOF_JSON_FILE
```

`pool-propose` accepts `PoolReductionRequest`: an id, budget_id, exact expected and
next definition, effective_window in admission-time seconds, explicit returns and
reason. Each return specifies ledger_id, window_start, unit and amount returned;
concurrency always uses window zero. `pool-return` accepts `reduction` and the
reviewed `ledger_id`; `pool-decide` accepts `reduction` and `complete` (false cancels);
`pool-import` accepts `reduction`. Reuse the original IDs after uncertain responses.
All operations require an installation administrator.

App-local quotas can decrease immediately without erasing reservations or
incorrectly classifying previously admitted usage as an adapter overrun.

An installation administrator can reconcile an attempt already recorded as an
unknown provider outcome using **Usage & spending capacity → Reconcile unknown
usage**, or:

```text
day2 platform resources reconcile-usage INSTANCE APP LOCAL_OPERATOR RECONCILIATION_JSON_FILE
```

The request names an id, current ledger_id, exact reservation, terminal actual
Consumption (concurrency zero), reason and provider receipt/evidence reference in
`proof`. The administrator explicitly asserts that the evidence establishes those
amounts; the platform does not independently verify an invoice. The immutable
receipt records that assertion and the settling operator. Exact retries return the
same receipt; altered requests or already known settlements cannot rewrite usage.
The original unknown record remains, and an actual amount above its quote still
freezes admission. This operation updates accounting only: it cannot create a
provider result, retry a call, resume an invocation or authorize business completion.
In-flight attempts without an unknown marker and restored copies of old ledgers
fail closed; this control cannot infer that a crash or timeout made a request free.

## Migration and restore

Rebuild existing artifacts against the sealed resource SDK. Existing installations
get no implicit resource grants: author and activate bindings before provider
operations can run. Disposable development fixtures explicitly opt into their
declared local resources at creation; that helper is not a runtime fallback.

Managed local-development rebuilds can recover the canonical disposable grants
while preserving accounting. Customized resource authority or company-backed
capacity blocks automatic cutover and keeps the incumbent instance selected;
those cases require explicit migration. Ordinary restore still disables the app
and freezes accounting, as described below.

Restore rotates authority lineage, disables the app, removes desired attachments
and freezes accounting. Recovery preserves historical usage and unknown holds.
Apps that previously held company allocations require fresh capacity from the
surviving allocator, bound to a new ledger ID. Local-only recovery can use an empty
allocation map. Neither resets spent funds or enables the application:

```text
day2 platform resources recover INSTANCE APP LOCAL_OPERATOR RECOVERY_JSON_FILE
```

Local-only recovery preserves the copied ledger's balances; it cannot prove that
the original instance stopped spending after the backup. Cross-instance or company
money guarantees therefore require central allocations and the surviving allocator.

The [integration inventory](RESOURCE-INTEGRATION-INVENTORY.md) remains the roadmap.
Each real provider needs typed resource/actions, host-only credentials and identity,
request binding, output bounds, retry semantics, usage qualification and adversarial
adapter tests.
