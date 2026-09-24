# Host-Enforced Authority

The company instance approves authority independently of the Roc application.
The host checks that approval against the compiled contracts, then enforces it
before returning storage observations or committing writes. A handler omitting
an ownership or caller-version comparison does not remove these guards.

This is a bounded owner/admin edit contract, not a general policy language or a
proof of arbitrary business correctness. See `crates/day2/src/authority.rs` and
`crates/day2/src/store.rs` for the policy and transaction interpreter.

## Ownership And Admission

Each `instance.json` app binding prepares a desired `authority` object. The
active authorization document lives in the app SQLite database and changes only
through explicit operator activation. Editing the file does not change live grants.
Existing `readers`
and `writers` remain an outer membership gate: writers can be considered for
commands and queries; readers only for queries. Passing that gate is insufficient.
The named operation must also explicitly grant the actor in its authority policy.
`auditors` remains a separate permission for the platform audit viewer.

An absent policy denies invocations, including for legacy artifacts. The host
does not derive a broad policy from old membership lists or operation names.
Loading an older artifact is not permission to execute it. Existing installation
files and databases are not automatically changed.

Policy version 1 contains:

- `admins`: actor identities that may bypass an owner row predicate, not all
  other checks.
- `operations`: an exact entry for every compiled operation, with allowed
  `actors`, an explicit execution `mode`, and per-model grants. An empty actor
  list is an explicit denial; an omitted operation makes the policy incomplete.
- `constraints`: per-model text-field rules enforced by the host on writes.
- `delegations`: named rules permitting an authenticated requester to act for a
  target on explicitly named authentication paths; absent means no impersonation.

Unknown operations, models, fields, incompatible modes and invalid precondition
mappings fail validation. Every nominal text model field requires an explicit
host constraint. Plain text fields may also declare one. The policy is validated
when loading the runtime and on fresh authorization against its pinned artifact.
It is company-owned configuration, not an app-supplied request or an app-generated
grant. The same reusable artifact may have different company policies.

For example, this entry belongs under `authority.operations`:

```json
{
  "links.edit": {
    "actors": ["alice", "bob", "admin"],
    "mode": {
      "kind": "edit",
      "model": "links",
      "id_field": "link_id",
      "version_field": "expected_version"
    },
    "models": {
      "links": {
        "read": true,
        "update_fields": ["title"],
        "rows": {"kind": "owner_or_admin", "field": "owner"}
      }
    }
  }
}
```

For the same policy, `admins` can contain `admin`, and `constraints` contains:

```json
{
  "links": {
    "title": {"nonempty": true, "max_bytes": 200}
  }
}
```

These are policy excerpts, not a complete installation file. The remaining
compiled operations also need explicit entries. See the conformance policies in
[owned-links.json](../fixtures/authority-policies/owned-links.json) and
[relational-conformance.json](../fixtures/authority-policies/relational-conformance.json),
and their use in `crates/day2/tests/owned_web.rs`,
`crates/day2/tests/owned_runtime.rs`, and `crates/day2/tests/runtime.rs`.

## Request Identity And Delegation

Identity is settled by the host before operation authorization. The authenticated
requester is who the host verified; the effective actor is whom the invocation
acts for. Membership, operation/model grants and row predicates use the effective
actor, never the requester's potentially broader privileges. Being an admin or
an installation operator does not itself permit impersonation.

An operator can add this excerpt under `authority.delegations` and activate it
through the ordinary authority workflow:

```json
{
  "customer-support": {
    "authenticated": ["support"],
    "may_act_as": {"kind": "actors", "actors": ["customer"]},
    "paths": ["request"]
  }
}
```

`may_act_as: {"kind":"any_human"}` excludes application admins, installation
operators, and the `app:`/`svc:` namespaces. `actors` instead names an explicit
reviewed target set. Rules only authorize identity selection, not any operation.
The [session JSON API](WEB.md#acting-on-behalf-of-another-actor) accepts the target
in `X-Day2-Act-As`; the requester comes from the session. `paths: ["ingress"]`
cannot be exercised by that request path.

Admission checks the active delegation policy in the same writer transaction
that captures the invocation's authority revision. The pair, rule, cause and
caller chain are immutable retry identity. A request may choose its target only
at the outermost boundary. A subsequent `Delegate.query` carries that effective
actor across the app boundary, is constrained by its resource grant and pinned
callee schema, and requires the callee's own operation authority. The callee
records `app:CALLER` as initiator and the application chain as provenance; it
does not borrow the caller application's grants.

## Model And Row Limits

A model grant allows full-row `read`, `create`, and/or updates to an explicit
`update_fields` set. Missing capabilities deny access. The host compares old and
new values: assigning an unchanged field is harmless, but changing a field
outside that set rejects the effect. Creates supply a complete schema-valid row;
there is no create-field projection in this slice.

Mutations return complete rows through the existing storage protocol, so their
grants must also permit `read`. Write-only grants are rejected rather than
silently revealing fields. These are update-field ceilings, not field-specific
read permissions or redacted projections.

`rows` is either `all` or `owner_or_admin` with a declared text field. Any owner
grant establishes that model's owner field across the whole approved policy;
all owner grants for that model must name the same field. Under an owner grant,
non-admin reads and updates require it to equal the effective actor.
Paginated reads include the owner predicate in SQL before `LIMIT`; the
host does not filter an already selected page. Single-row reads are checked
before the row reaches the worker.
The current single-row adapter distinguishes a missing row from a forbidden
existing row; it withholds values but does not hide row existence completely.

A create on an owned model must assign the current actor, including for admins
and operations whose own grant is `rows: all`. No operation's update grant can
include that model's owner field. Runtime write checks independently enforce
this immutability, so another broader operation cannot transfer ownership and
invalidate the scope of previously returned data. Owner-scoped updates must
also satisfy the scope for both old and new rows. Admins may edit another owner's
row but may not change ownership or another forbidden field. They still need
outer membership and explicit operation/model permissions. A company can approve
`rows: all` for broader row access; it does not remove model-wide ownership rules.

`nonempty` rejects whitespace-only text. `max_bytes` is a UTF-8 byte limit,
bounded by the existing 16 KiB host text budget. These constraints run on the
whole proposed row for every accepted create/update, independently of SDK
factories and the app's `from_str` implementation. They do not execute arbitrary
Roc predicates or infer business rules from a nominal type's name.
Changing a constraint does not scan or migrate existing rows. Validation checks
policy/contract compatibility and proposed writes; automatic existing-data
validation when tightening a policy remains unimplemented.

## Edit And Current State

An operation's mode must match its compiled command/query kind:

| Mode | Meaning |
| --- | --- |
| `read` | A query with no create/update grants. |
| `edit` | A command with one required caller-seen model reference and version. Updates are confined to that exact row; creates are forbidden. |
| `current_state` | A command intentionally operating on current transactional state, within its approved effect/row/field limits. No caller-seen version is inferred. |

The Edit ID input must be a compiled `Ref` to the target model. The version
input must be `I64`. Canonical positive reference strings and positive bounded
versions are checked by the host; field names are explicitly mapped, not guessed.

After accepting the invocation, execution acquires the SQLite transaction and
loads the target before starting the Roc worker. It checks row authority before
comparing the caller's version. Unauthorized callers receive `forbidden`, not
a version-conflict disclosure. A stale authorized caller receives `conflict`.
The original input remains authoritative even if the handler ignores its version
field or reloads the newest row. Each later update must target that same row.

This is separate from the existing SQL compare-and-swap predicate in `Tx.update`.
SQL still checks the entity version supplied by the effect. The Edit guard
additionally checks the version the caller saw, inside the same transaction.
With unchanged policy and current authorization, the same invocation ID returns
its recorded result without repeating writes;
two distinct invocation IDs do not bypass a stale caller precondition.

The bounded Edit mode does not yet support a multi-row precondition set or
derived writes to other models. The CRM four-write move has an explicit
CurrentState approval and retains its app-written caller-version and counter
checks. This is not the same guarantee as the owned Edit fixture. The existing
Links archive uses Edit with `rows: all` for its approved writers.

## Authorization, Recovery And Replay

The host reads current company authority and the active artifact binding from
the same SQLite transaction as protected data. Active authority has an opaque
epoch and a monotonically increasing revision; policy format `version` is
independent. Acceptance persists this stamp on the invocation. Preparation,
decision, completion, child acceptance, external dispatch admission and result
retrieval require that same stamp. Every authority activation advances the
revision, including restoring identical policy contents, so A-to-B-to-A does not
revive old work. An authority change invalidates all unfinished work for that
installed app; it does not select only operations affected by the edited grant.

Policy activation takes the same SQLite writer lock as business mutations. If
the mutation wins the lock, its commit precedes activation. If activation wins,
the old invocation cannot commit further business writes. Readers and auditors
use an active authorization snapshot in the same read transaction as their
data. Live subscriptions remain bound to their original stamp and terminate
on any activation; they cannot silently capture replacement authority.

Before each external call, a short transaction admits a particular attempt and
commits its authority stamp. The provider call follows outside the database
transaction. Revocation prevents later dispatch admissions, but an attempt
already admitted may finish, including after revocation returns. Settlement
preserves knowledge of that outcome without authorizing additional business
writes. Every retry requires fresh admission with a new attempt identity and
the original effect identity for provider deduplication. An ambiguous provider
result is not permission to blindly send again.

Private `ops/Authority.roc` exposes local operator inspect, apply and artifact
activation workflows. Apply and activation require an expected stamp and an
idempotency request ID; a conflicting or stale request fails closed. The local
operator assertion is not production authentication. See
[TRANSACTIONAL-AUTHORITY.md](TRANSACTIONAL-AUTHORITY.md) for operator commands,
legacy initialization and restore behavior.

An Edit rejection before worker startup becomes a durable failed outcome with
no business writes. New trace format 2 captures the policy, precondition row
when present, and host precondition error. Replay reevaluates this guard using
the captured evidence; it does not start the application to invent a failure
the host originally produced. Successful guard checks retain the normal
worker-observation replay. Existing format-1 traces remain a legacy replay
format, not evidence that these new checks ran.
Normal effect replay checks recorded worker decisions, not a second execution
of every host row/field/constraint decision against a reconstructed database.

Denied later effects abort the transaction, including preceding writes and
their row-change audit records. Failure completion and its audit entry are
durable. Infrastructure interruptions remain recoverable pending invocations.
Current authorization is required even to retrieve a completed outcome. Its
captured authority stamp must equal the current active stamp; changed authority denies
receipt reuse instead of returning historical data under new permissions or
rerunning a completed command. Legacy receipts without captured policy are
also unavailable through `invoke`/`resume`. Their existence is not permission
to expose a historical result under newly approved policy.

The guard snapshot, inputs, rows and replay observations contain business values.
The redacted public audit viewer does not redact this private trace store.
Retention, secret-specific handling and at-rest encryption remain separate work.

## Evidence And Boundaries

[The row-authority web conformance fixture](../fixtures/row-authority-web-conformance/README.md)
is a platform-owned test of reusable authority and HTTP behavior, run against a
fresh database rather than an implicit migration of the existing Links app.
Its edit handler deliberately omits ownership and caller-version checks.
Host guards are exercised by HTTP
and native runtime tests, including other owners, stale versions, retries,
revocation, forbidden fields/targets and rollback after a later denied effect.
The authority unit suite also checks malformed policies, write-only grants,
text byte boundaries and a fixed-seed Unicode property campaign.

Properties remain a separate verification facility. A mandatory property
catalog does not prove adequate coverage, and arbitrary app predicates are not
evaluated as commit constraints. Keep independent reference models, mutation
fixtures, fault schedules and replay alongside these non-optional host guards.

Native browser JavaScript remains trusted to the authenticated session. It can
submit commands that session is authorized to perform; tickets and these guards
do not prove human intent. This slice does not replace app-owned presentation
with a browser sandbox or change dependency admission into behavioral confinement.

Still outside this contract: field read projections, relationship-target scope,
general role/group policy, ownership transfer, multi-row Edit preconditions,
arbitrary transition/uniqueness constraints, secret/resource capabilities and
production policy signing/distribution. Host constraints narrow app authority;
they do not prove the correctness of every permitted application decision.
