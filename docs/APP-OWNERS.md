# App owners and CLI management

An app's owners are exactly `policy.admins` in its active authority document.
There is no separate registry, global owner role or mutable desired-file grant.
The shared native `owners::authorize_in` guard covers `audit.read`,
`secrets.list`, `secrets.read` and `sqlite.download`. Audit reads already use
this guard. The secret and snapshot names establish the permission boundary for
future control operations; no value reveal or snapshot export endpoint is added.

Checks require an enabled app, current validated authority, the exact installation
and artifact binding, current hosted-domain selection and applicable native
security admission. They run inside the protected database read transaction.
A returned stamp or a CLI `check` result is diagnostic data, not a credential or
permission that a later read can reuse. A future endpoint must authenticate its
actor and call the guard inside the actual read/export admission transaction.
It must also resolve only that app's approved secret bindings or snapshot identity;
ownership grants no access to arbitrary shared/platform secrets or other apps.

Owners retain the existing admin row behavior. They gain no additional app
operation, membership, resource, provider or installation permissions. Readers,
writers, service principals and installation operators do not become owners.
An operator needs an explicit app owner entry to pass an owner permission check.

## Local operator commands

The platform distribution exposes this supported command/result contract:

```text
day2 platform owners list INSTANCE APP LOCAL_OPERATOR '{}'
day2 platform owners check INSTANCE APP LOCAL_OPERATOR '{"actor":"alice@example.com","permission":"secrets.read"}'
day2 platform owners add INSTANCE APP LOCAL_OPERATOR CHANGE_JSON
day2 platform owners remove INSTANCE APP LOCAL_OPERATOR CHANGE_JSON
```

`LOCAL_OPERATOR` must be listed in the selected instance's `control.operators`.
It is a trusted local assertion requiring access to the private instance and
database, not production network authentication or a human session. Every command
checks the operator; app ownership alone cannot administer the owner list.
No HTTP or MCP owner-management route is installed.

All commands emit one JSON object on success:

```json
{
  "protocol": 1,
  "kind": "app-owners",
  "scope": "company/environment/app",
  "app": "app",
  "action": "list",
  "mode": "local-operator-only",
  "result": {}
}
```

Native errors follow the platform CLI's existing stderr/nonzero-exit contract.
No secret material or private replay evidence belongs in these results.
`list` returns `stamp`, `enabled`, active `owners`, `desired_owners`,
`desired_matches_active` and the four permission names. It never includes the
rest of the app policy or provider bindings. `check` returns the requested
`actor`, `permission` and `allowed` boolean. False is a diagnostic denial, not a
failure to evaluate the command. The standalone Rust CLI maps it to exit code 3.

`CHANGE_JSON` has exactly `owner`, `expected` and `request_id`. `expected` is
the complete epoch/revision stamp from `list`. A successful add/remove returns
the same owner/request/expected identity, an authority `receipt` and
`desired_config_changed: false`. Reuse the exact request ID, operator, operation,
owner and expected stamp after a lost response. A retry returns the original
receipt even if later changes have committed; it does not reapply the change.
Changed inputs conflict. The receipt identifies that historical change, not a
claim that its owner list is still current; inspect again for current state.

## Mutation boundaries

The existing native writer transaction checks the current stamp and atomically
updates only policy admins, appends authority history and records its retry
receipt. It preserves enabled state, artifact identity, memberships, operations,
resource grants and credential-family selections. Pending desired-file edits
cannot be activated by an owner mutation. Normal authority revision fencing
applies to unfinished work, live subscriptions and historical outcomes.

New owners must be individual principals, not group, domain, app or service
selectors. Google service-account identities are refused. In an IAP installation,
new owners must be exact people at its verified hosted domain. Local development
can use its explicit development actor names. The list is bounded to 512 owners.
Adding an existing owner, removing an absent owner, mutating a disabled app and
removing the final owner are refused. Deliberate installation recovery can still
use the separately reviewed full authority activation path.

The commands apply immediately to active authority and deliberately do not edit
`instance.json` or a Git repository. `list` exposes any active/desired difference.
Reconcile the private instance source before a subsequent full `authority apply`,
which intentionally activates its complete reviewed desired policy. The owner
command never silently commits unrelated configuration. CI can call this same
entry point with an approved exact stamp/request; CI is not required for the
initial local operator workflow.

Restored authority remains disabled under a new epoch. Historical owner entries
and old receipts cannot authorize access or replay into that restored lineage.
