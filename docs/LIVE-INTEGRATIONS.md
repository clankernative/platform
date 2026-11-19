# Reviewed live integrations

The live adapters implement four closed capabilities. Apps supply an opaque
resource handle and operation data; the activated binding supplies the provider,
credential version, destination and profile. Nothing in the app request can
select an endpoint, token, workspace, account, role, warehouse, model or project.

Implementation: `crates/day2/src/integrations/`, shared authority profiles in
`crates/day2-capabilities/src/integrations.rs`, credential mounts in
`crates/day2/src/integration_host.rs`. These integrations remain subject to the
normal operation permission, resource grant, transaction admission and budget
checks described in [resource enforcement](RESOURCE-ENFORCEMENT.md).

## Supported contracts

| Capability | App input, in addition to `handle` | Activated resource | Returned data |
| --- | --- | --- | --- |
| `slack.read.v1` | `limit` from 1 through 100 | One workspace and channel ID | Plain message text and timestamps, channel ID, explicit `has_more` |
| `slack.post.v1` | Nonempty `text`, at most 4,000 characters | One workspace and channel ID | Channel ID, timestamp and accepted status |
| `snowflake.read.v1` | `parameters`: array of `{name, kind, value}` | Exact database/schema/view, selected columns and required typed equality filters | Complete bounded rows, with each cell `{is_null, value}` |
| `openai.generate.v1` | `text` and `max_output_tokens` | Fixed project, model and reviewed limits/rates | Plain output text and input/output token counts |

Slack posting and model generation are Effects capabilities. Model generation is
a billable external operation even when its result is only text. Slack history
and Snowflake reads are observations; they still require resource authority and
consume their admitted budgets.

Slack accepts channel-like C/G identifiers; user identifiers that implicitly
create a conversation and D identifiers are rejected. Each invocation first
checks `auth.test` against the pinned workspace, then makes exactly one channel
request. This fixed plan reserves two provider calls together at the same
transactional admission cutoff. Both requests are covered by that admission;
revocation after admission does not cancel the second request. A failed workspace
check prevents app text from being transmitted to the channel endpoint. Actual
call accounting includes the identity check and failed transport attempts.

Posting escapes Slack's special characters, disables markdown and name parsing,
and disables link/media unfurls. Apps cannot supply blocks, attachments, reply
broadcasts, impersonation fields, files or webhooks. History projects text and
timestamps only; it neither follows file links nor accepts an app-supplied
pagination cursor. `has_more` exposes the bounded page rather than pretending it
is a complete channel archive. See Slack's [message formatting rules](https://docs.slack.dev/messaging/formatting-message-text/),
[posting API](https://docs.slack.dev/reference/methods/chat.postMessage/) and
[history API](https://docs.slack.dev/reference/methods/conversations.history/).

Snowflake builds one quoted `SELECT` over the approved view. Every configured
filter is required and becomes a bound equality parameter; parameter types are
`text`, `integer` and `boolean`, with canonical string values. Unknown names,
duplicates, missing filters and type mismatches fail before dispatch. The SQL
includes the selected columns, fixed role/warehouse, a 20-second statement
timeout and a one-statement limit. It asks for one extra row so row overflow is
rejected, never silently truncated. Only a complete single-partition synchronous
result with the expected columns is accepted. A `202` response or additional
partitions fails; the adapter does not poll, fetch partitions or follow status
URLs. See [statement submission](https://docs.snowflake.com/en/developer-guide/sql-api/submitting-requests)
and the [SQL API response contract](https://docs.snowflake.com/en/developer-guide/sql-api/reference).

The OpenAI adapter sends a synchronous Responses request with fixed default
service tier, plain text output, `store:false`, disabled background/streaming,
empty tools and no conversation/previous-response references. It accepts only
assistant text; refusals fail with a redacted error. Unexpected tools or pricing
identity changes leave the reservation unresolved. These request controls do not
establish an account-wide zero-retention guarantee; provider account data controls
remain a separate deployment requirement. See the [Responses API](https://developers.openai.com/api/reference/typescript/resources/responses/methods/create)
and [data controls](https://platform.openai.com/docs/models/default-usage-policies-by-endpoint).

## Workspace Directory hierarchy reads

`WorkspaceDirectory.deliver_hierarchy_with(resource)` (`workspace_directory.hierarchy.v2`) reads and validates the complete organizational-unit hierarchy without looking up the current user or claiming a membership path. Every delivery is a provider read that requests only the organizational-unit OAuth scope; the host keeps no cache and no expiry. The validated hierarchy is staged as bounded pages in the application's own database for the reading invocation only, and `delivery_page_with` (`workspace_directory.page.v2`) reads them back locally. The application persists what it keeps in its own models and owns its age limit and retention. Its `id` is the content identity, so an unchanged hierarchy delivers the same `id`. See [provider capture delivery](PROVIDER-CAPTURE-DELIVERY.md).

`WorkspaceDirectory.user_path(context)` / `user_path_with(resource)` independently observe the current actor's checked Google user path through `workspace_directory.user_path.v1`. Only the host-issued resource handle crosses the capability boundary; actor, customer, connection revision and invocation time come from current native authority. It requests only the user-read OAuth scope, never fetches or publishes a hierarchy, and supplies no primary-email/profile claim or default path on failure. The full authentication/user-read envelope reserves 32 KiB of requests and at most 64 KiB + 1 byte of responses; direct and delegated flows reserve three and four calls respectively. The application owns any user-path cache and its expiry. A cache-first workflow can commit that user fact before a separate hierarchy command, preserving it if the latter fails.

Applications own membership-cache validity, ancestry decisions, persistence and reconciliation. The platform supplies bounded, customer/connection/actor-bound hierarchy facts; operators own real identity and provider grants. Declare read dependencies on the operation definition, for example `Api.query({...}).observes("workspace_directory.hierarchy.v2").observes("workspace_directory.page.v2")`. Admission rejects unknown capabilities, writes and duplicate declarations. The generated artifact carries those declarations into the disposable build-verification and local-development policy. That policy selects synthetic Directory bindings for any application namespace; an operation without a Directory declaration receives no default Directory authority. Explicit disposable policies may narrow or supply the observations used by a scenario. Production loading never infers authority from these declarations. Read-dependency declarations are not identity or membership claims.

Authorization freezes the provider source before reserving provider traffic: a simulated host never falls through to the network. Live and simulated adapters run the same parser and validation. The simulator records requests and consumes scheduled endpoint faults in its SQLite world. The Directory regression campaign checks provider faults, recovery, content-identity changes, a user-path read that never touches the hierarchy, and identical replay; real HTTP fixtures separately check the native authentication and request paths.

## Internal-tools app library reads

`InternalTools.app_library(context)` / `app_library_with(resource)`
(`internal_tools.app_library.v1`) reads which tools the internal-tools control
plane has registered and where each launches. It returns only
`{app_id, name, url}` per tool and `captured_at`; owners, repository, custom
fields and every other control-plane field are dropped by the parser and never
decoded. Tools are sorted by name (case-insensitive) then `app_id`, one per
`app_id`; a tool without a subdomain is skipped. `url` is
`https://<subdomain>.<app_domain>/`, where `app_domain` is the activated
`internal_tools_library` resource's and the subdomain is validated as one
lowercase DNS label. A malformed app ID, name or subdomain fails the read rather
than being dropped. Nothing is cached: every call is a provider read, so an app
should call it when a person asks, not on every page load.

The `internal_tools` connection names the control-plane `origin` (https, host
only), the `iap_audience` (a path under that origin, such as `/*`), the
`service_account` whose IAP credential is signed, and the control plane's own
`target_app_id`. Nothing in the app request selects any of them; the request
carries only the resource handle. A read is one fixed plan:

1. Sign a Google service-account JWT for `iap_audience` keylessly through IAM
   Credentials (`crate::iap_workload::Signer`, authorized by the workload's GKE
   metadata token). No key is mounted.
2. `POST {origin}/api/internal-tools/service-tokens` with
   `{"target_app_id":…,"scopes":["control-plane.app-library.read"]}` and the
   JWT as `Authorization: Bearer`. The returned `service_token` is held in
   memory for this read only, never cached, journaled or recorded.
3. `GET {origin}/api/app-library?Page=N&PageSize=100` with the JWT and the
   service token in `X-Internal-Tools-Service`, following `hasNextPage`. A
   page that is not the requested page or size, or a short page that claims
   more, fails as `internal_tools_pagination_invalid`.

At most 1,000 tools (10 pages) are read; a further page fails the read as
`internal_tools_app_budget` and is never requested. Each page is bounded at
1 MiB and all pages together at 3 MiB; the service-token response at 16 KiB.
The read reserves 13 calls, 8 KiB of requests and the whole response envelope,
and settles what it consumed, including failed and truncated exchanges.
Signing is charged at its reviewed bound (two calls, 4 KiB of requests and
28 KiB of responses), because the reused signer does not report byte counts.
The 64-KiB observation journal still applies, so a library whose projection
exceeds it fails with `provider_result_journal_budget` rather than being
truncated; that is roughly 700 tools with typical names.

Failures are stable codes: `internal_tools_credential_unavailable` (signing),
`internal_tools_service_token_refused` (400/401/403/404 at the token endpoint,
for example a missing `service_callers` grant), `internal_tools_authentication_failed`
(401 from the library), `internal_tools_scope_denied` (403 from the library),
`internal_tools_rate_limited`, `internal_tools_unavailable`,
`internal_tools_response_invalid`, `internal_tools_response_too_large`,
`internal_tools_pagination_invalid` and `internal_tools_app_budget`. A failure
keeps only its last exchange's phase, page and HTTP status as correlation.

The simulated control plane (`internal_tools.simulated.sqlite`) serves verbatim
`AppLibraryEntryDto` bodies in the control plane's own pages, checks the
presented IAP credential, target app, scope and service token, and compares the
connection's service account, origin, audience and target app on every exchange,
failing closed with `internal_tools_connection_mismatch`. Verification and local
development bind a synthetic connection to `https://it.wonderly.test` with app
domain `wonderly.test` for any operation that declares the read; an operation
without the declaration receives no internal-tools authority.

Live use requires the control plane to admit the host workload: register its
service account as a source app and grant it `control-plane.app-library.read`
in the control plane's `service_callers`. The adapter has not been qualified
against the live control plane.

## Carta issuer captures

A resource on a live `carta` connection makes `carta.snapshot.v2` collect one
issuer's stakeholders and option grants completely and hand the capture to the
application, which holds it in its own database, reads it with
`carta.records.v2` and releases it with `carta.release.v2`. [Carta](CARTA.md) describes
the profile, bounds, mapping, retention and failure codes. The native adapter
(`crates/day2/src/carta_http.rs`) builds its own blocking client because the
token exchange needs HTTP Basic and a form body, which the shared bearer
transport cannot express. The client is https-only, follows no redirect, retries
nothing, uses no proxy, cookie or content encoding, keeps no idle connection,
and has 5-second connect and 30-second request timeouts. A 180-second capture
deadline is checked before every request.

Origins are fixed by the closed environment: production uses
`https://login.app.carta.com` and `https://api.carta.com`; playground uses
`https://login.playground.carta.team` and `https://api.playground.carta.team`.
The playground API origin is pinned for qualification; the inspected Equity
client paired that login with a mock API origin, which is not admitted. The
token request is `POST /o/access_token/` with
`grant_type=CLIENT_CREDENTIALS&scope=read_issuer_stakeholders read_issuer_securities`
and Basic `client_id:secret`; page requests are bearer `GET`s of
`/v1alpha1/issuers/{issuer}/stakeholders` and `/optionGrants` with a
URL-encoded `pageToken`. No page size is requested until qualification shows
the provider honours one.

Only the client secret is mounted, through the ordinary credential mount and
registration path. It resolves as `CartaClientSecret`, a type sent only as
Basic authentication, under the same profile and fingerprint checks as every
mount; bearer resolution refuses a Carta connection. The access token lives in
memory for one capture and is never cached.

A truncated or failed response is still metered: a body read that stops on a
close or timeout keeps the bytes it already consumed, and a response refused
from its headers keeps its status and `Retry-After`. Known settlement and the
failure's correlation therefore record all provider traffic.

`bazel run //crates/xtask:xtask -- carta-qualify PROFILE SECRET_FILE NEW_EVIDENCE_DIRECTORY`
is the explicit operator qualification. It is not part of any verification
recipe. The private [`ops/CartaQualification.roc`](../ops/CartaQualification.roc)
recipe owns its step order and runs through `ops/Runner.roc`: open the inputs,
create a private scratch store, collect, discard the scratch store, then publish
the receipt. The native session supplies only those steps, refuses them out of
order, with arguments or replayed, and deletes the scratch store if any step
fails. The profile is JSON with `format: 1`, `environment: "playground"`
(production is refused before the secret is read), `client_id`, numeric
`issuer_id`, optional `children`, `max_pages_per_collection` and `expires_at`
(Unix seconds). The secret file must be an owner-private regular file, and the
evidence directory must be new. Collection drives the native adapter through
the production pipeline and holds the capture in the scratch store exactly as
an application database holds a `carta.snapshot.v2` delivery. The `receipt.json` it publishes
has an outcome code, counts, usage, the last exchange, each page's status, bytes,
item count, `nextPageToken` form and any transport failure code, and
per-field present/null/absent/empty counts. The token exchange is recorded only
as JSON shapes, whether `token_type` is `Bearer`, a lifetime of at most a year,
the granted scopes from a reviewed list and a count of other scopes. Unmapped
field names are kept only when identifier-shaped, at most 64 per kind; the rest
are counted. No provider value or JSON subtree is retained, including from a
malformed response. Before publishing, the session refuses a receipt that claims
`provider_qualified` or contains the client secret. Every receipt reports
`provider_qualified: false` until a reviewer accepts it.

## Credentials and transport

This illustrative `Instance.resources` catalog allows the `reports` app to post
to one Slack channel. The workspace/channel IDs, credential reference, actor and
limits are examples requiring operator review; this is not live-account approval.
The reusable policy can be attached to additional approved operations without
giving their code a token or letting it select another channel.

```json
{
  "version": 1,
  "connections": {
    "company-slack": {
      "revision": 1, "provider": "slack",
      "live": {
        "provider": "slack", "workspace_id": "T123",
        "credential_ref": {"id": "slack-bot", "revision": 1}
      }
    }
  },
  "resources": {
    "report-channel": {
      "revision": 1,
      "connection": {"id": "company-slack", "revision": 1},
      "target": {"kind": "slack_channel", "channel": {"channel_id": "C123"}}
    }
  },
  "budgets": {
    "slack-daily": {
      "revision": 1, "scope": "app", "period_seconds": 86400,
      "limits": {"calls": 200, "bytes": 2000000,
                 "cost_microunits": null, "concurrency": 2}
    }
  },
  "policies": {
    "report-posting": {
      "revision": 1, "owner": "it@example.com", "delegates": [],
      "actors": ["alice@example.com"], "allowed_apps": ["reports"],
      "max_duration_seconds": null,
      "slots": {
        "report_channel": {
          "kind": "slack_channel",
          "allowed_resources": [{"id": "report-channel", "revision": 1}],
          "actions": ["slack_post"],
          "limits": {"max_request_bytes": 16384, "max_response_bytes": 16384,
                     "max_calls_per_invocation": 2},
          "budgets": [{"id": "slack-daily", "revision": 1}]
        }
      }
    }
  }
}
```

Add this attachment to `apps.reports.resource_policies`, using an actual admitted
operation that separately permits `slack.post.v1` in its business authority:

```json
{
  "policy": {"id": "report-posting", "revision": 1},
  "operation": "reports.notify",
  "bindings": {"report_channel": {"id": "report-channel", "revision": 1}},
  "actors": ["alice@example.com"], "expires_at_ms": null
}
```

The two-call invocation ceiling covers workspace verification and one post. The
daily 200-call budget admits at most 100 complete plans; failed attempts also
consume their recorded calls. Resolve, review and activate this desired policy
through the [normal administration workflow](RESOURCE-ENFORCEMENT.md#real-administration).
Credential registration and live qualification remain separate prerequisites.

A connection contains a `credential_ref` with an immutable ID and revision, never
a token. A trusted installation administrator registers an existing private
credential file against the exact connection profile. The host records a token
fingerprint; changing the file's token requires a new credential revision and
matching activated configuration. Symlinks, non-regular files and group/world
readable credential files are rejected. Missing mounts deny execution before
provider HTTP. App artifacts, policy JSON and receipts contain no credential
bytes. This local administrator mechanism is not production SSO.

For a local source installation, register the file explicitly:

```text
day2 platform resources credential-mount INSTANCE APP LOCAL_OPERATOR MOUNT_JSON_FILE
```

The input is `{"connection": LIVE_CONNECTION_PROFILE, "credential_file": "/absolute/private/token-file"}`.
Use the complete connection's `live` profile, including its credential reference.

### Packaged Linux provisioning

Exporting an app with live grants requires explicit provisioning metadata. The
exporter never copies a source credential registry or token file. Supply a private
JSON file containing the pinned tooling image, an installation administrator and
exactly the credential references used by the selected app's resolved grants:

```json
{
  "tooling_image": "sha256:ACTUAL_TOOLING_IMAGE_DIGEST",
  "operator": "it@example.com",
  "credentials": [
    {"credential_ref": {"id": "slack-bot", "revision": 1},
     "source_file": "/absolute/private/slack-bot-v1"}
  ]
}
```

The placeholder must be replaced by the actual 64-hex image digest. Source files
must be existing private regular files, at most 16 KiB, readable by container
UID/GID `10001:10001` while retaining owner-only permissions. A host-managed secret
mount must provide that access; provisioning never changes file ownership or
permissions. Both containers run with that UID, so an unreadable mount fails
before registration. Keep each file available for the runtime's lifetime.

```text
build-out/bin/day2-package INSTANCE APP ACTOR RUNTIME_IMAGE_DIGEST PORT NEW_DIRECTORY --provisioning PRIVATE_PROVISIONING_JSON
docker compose -f NEW_DIRECTORY/compose.json run --rm provision-credentials
docker compose -f NEW_DIRECTORY/compose.json up -d app
```

The exporter reads only the explicitly supplied files to fingerprint them. The
package contains reviewed profiles, paths and fingerprints, never token bytes.
Each credential has the same deterministic read-only path in tooling and runtime.
The one-shot tooling service is opt-in, has no provider network access, and writes
the registry into the runtime's named state volume. Its separate operator instance
contains only the asserted administrator and no source, build, runtime-provider or
secret-provider authority. The app-facing instance still has no control-plane
administrators. The private `Provision.roc` recipe validates the pinned inputs and
passes those exact profiles and fingerprints to registration in memory. Registration
compares the fingerprint against the same token read it records, before touching
the registry; changing a token or input file after preflight cannot substitute
an unreviewed first registration.

Registration is idempotent per reference; if a later file fails, retry the same
review to finish the remaining registrations. Registration grants no app authority
and makes no provider calls. Normal startup never runs provisioning automatically.
Token rotation requires a new credential revision, matching connection/grant
revisions and an explicit new export/provisioning review. A changed file cannot
silently replace the token of a registered version. Exports with no live grants
retain the ordinary packaging workflow and need no provisioning configuration.

The HTTP client allows HTTPS only, uses fixed reviewed provider hosts, verifies
TLS, disables redirects, environment proxies, automatic retries and content
decompression, and installs no cookie store. Connection and total timeouts are
five and thirty seconds respectively. Requests and responses have independent
grant ceilings and a four-MiB hard payload maximum. Accounting measures submitted
body/query bytes and consumed response-body bytes, not TLS or HTTP-header bytes.
Responses are bounded while reading, with at most one extra byte used to detect
overflow. Provider error bodies and transport diagnostics are replaced with
stable redacted error codes.

The durable observation has a separate 64-KiB ceiling, including JSON escaping
and the original instruction. An instruction that cannot fit with a small error
is rejected before dispatch. If a provider result cannot fit, the app receives
`provider_result_journal_budget`; known usage and bounded correlation still settle
and persist. The larger transport ceiling is not an app result-size guarantee.

## Monetary limits and uncertain outcomes

OpenAI rates are integer nanodollars per token, supplied in the versioned
operator-reviewed profile. Each request reserves the entire reviewed billable
input-context ceiling plus its allowed output tokens. Prompt byte size is not
used as a tokenizer or a proof of the model's context bound. Settlement uses
reported input/output token counts and rounds the configured tariff upward to
microdollars. All input tokens receive the regular input tariff, including cached
tokens, so this is conservative platform budget accounting rather than invoice
reconciliation. Reasoning tokens are included in the provider's output count.

Complete trustworthy usage remains chargeable even if content validation fails.
Missing usage, an unexpected model/service tier or unexpected hosted tools keep
the reservation held. Usage above the reserved allowance is reported in full for
the host's overrun/freeze handling. Provider pricing changes, discounts, taxes
and billing adjustments are outside this ledger's guarantee.

Slack has no per-request monetary tariff in this adapter. Snowflake warehouse
costs cannot be derived from result rows or a statement timeout; monetary budgets
are therefore unsupported for Snowflake and must be rejected before dispatch.
Calls, payload bytes and concurrency remain enforceable. An independently
governed warehouse and its provider-side controls are still needed for warehouse
spend containment.

No ambiguous provider attempt is automatically retried. Timeouts, lost responses
and uncertain accepted outcomes preserve holds for explicit reconciliation. An
operator must resolve the existing attempt using evidence, rather than resend it
and risk duplicate messages or charges.

The journaled host attempt is sent to OpenAI as `X-Client-Request-Id`. Bounded
diagnostic metadata records the HTTP status, a validated OpenAI request ID and,
for Snowflake, an exact statement UUID when available. A body timeout preserves
IDs already received in headers. Slack's identity check and operation have
separate entries in the same bounded plan. These IDs support investigation;
they do not establish idempotency or authorize polling, resending or releasing a
hold. Tokens, arbitrary headers, provider messages and status URLs are excluded.
See OpenAI's [request ID guidance](https://developers.openai.com/api/reference/overview#debugging-requests).

## Qualification status and required account inputs

Local adversarial tests cover request confinement, workspace mismatch, SQL
injection and incomplete results, malformed/pricing-changed model responses,
unknown outcomes, payload ceilings and redacted errors. Injected transport tests
do not establish live-provider qualification.

A live qualification requires explicitly approved nonproduction targets:

- Slack workspace, dedicated channel, bot membership/scopes, and a private token
  mount. Approve the test message and verify it has no mentions or unfurls.
- Snowflake account, dedicated read-only role/warehouse and approved view with
  its columns, filters and test rows. The view/role must enforce tenant and row
  restrictions; caller-chosen filter values do not enforce those restrictions.
- OpenAI project, reviewed fixed model/context/rates, approved test prompt and
  spend allowance, private API-key mount, and required provider data controls.
- Carta playground OAuth client with read access to one test issuer, a private
  client-secret file and an expiring `carta-qualify` profile. Its receipt must
  settle the granted scopes, the playground API origin, end-of-pagination form,
  page sizes and which fields Carta omits or nulls before production cut-over.

Live credentials and account evidence must be provided before those checks can
be completed. Installing an adapter or mounting a credential does not assert
qualification. Neither provider qualification nor these handles establish
information-flow noninterference between separate read and write grants.
