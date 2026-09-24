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
cargo run --locked -p day2 --bin day2-package -- INSTANCE APP ACTOR RUNTIME_IMAGE_DIGEST PORT NEW_DIRECTORY --provisioning PRIVATE_PROVISIONING_JSON
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

Live credentials and account evidence must be provided before those checks can
be completed. Installing an adapter or mounting a credential does not assert
qualification. Neither provider qualification nor these handles establish
information-flow noninterference between separate read and write grants.
