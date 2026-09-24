# Transactional authority activation

An installed app's SQLite database owns its active authority document and artifact
binding. `instance.json` is desired configuration. Editing it prepares a change;
it never modifies live grants, and runtime startup does not overwrite active
authority from that file. Apps retain their existing Roc handlers and SDK.

The active document includes enabled state, readers, writers, auditors and policy.
Its stamp has an opaque `epoch` and an increasing `revision`, separate from the
policy's format `version`. All invocation phases retain the stamp accepted with
their original input. Every activation advances the revision even for identical
policy bytes. Old unfinished work and cached outcomes do not acquire replacement
authority. Reissuing the same operator request ID with the same expected stamp
and document returns its original receipt; changed request contents conflict.

## Local operator commands

Build the CLI distribution with `cargo run --locked -p xtask -- cli` inside
`platform/`, then run from the workspace root:

```console
./platform/cli/day2 platform authority inspect INSTANCE APP
./platform/cli/day2 platform authority apply INSTANCE APP LOCAL_OPERATOR EXPECTED_STAMP_JSON REQUEST_ID
./platform/cli/day2 platform authority activate INSTANCE APP TARGET LOCAL_OPERATOR EXPECTED_STAMP_JSON REQUEST_ID
```

Use the exact `active.stamp` JSON returned by inspect as one shell-quoted argument,
for example `'{"epoch":"sha256:...","revision":7}'`, with the actual opaque
epoch. `apply` activates the desired memberships and policy for the existing
active artifact. `activate` publishes the target artifact and its compatible
desired memberships and policy in one transaction after migration requirements
have been satisfied. A stale expected stamp fails closed; inspect and review the
current state before issuing a new request ID. Retry an uncertain activation with
the same request ID and original arguments. Preserve the original desired
memberships and policy in `INSTANCE` for that retry: these commands reload the
file, so changed contents conflict even when the command line is unchanged.

`LOCAL_OPERATOR` explicitly asserts a trusted local operator identity for audit.
It is not a production authentication mechanism. These private operations are
not HTTP/MCP app routes, and Roc apps have no authority-management capability.
Roc workflows compose the operation; Rust enforces its atomic commit and guards.

## Initialization and recovery

A freshly initialized empty app database receives its explicitly supplied
installation policy during initialization. An existing database without active
authority requires deliberate operator initialization: inspect reports `active:
null`, and `apply` accepts literal `null` as the expected stamp only in that state.
It does not assign that new stamp to old invocations. Historical pending work
requires explicit recovery; new authority must not silently revive it.

Restore accepts only format-2 backups, which include an authority stamp. Older
backup bundles are unsupported; no automatic conversion is provided.

Backups bind their manifest to the active artifact, policy and authority stamp
read from the completed SQLite snapshot. Desired file edits cannot change what
the snapshot claims was active. Restore verifies the bundle, relocates its
artifact and rotates the authority epoch while disabling the restored grants.
Restored desired configuration has empty membership lists and no policy. Restore
also discards browser sessions and the ticket-signing secret. Before serving,
supply current company-approved policy and explicitly activate it using
the restored stamp. Backup policy is historical evidence, never fresh approval.
Old invocations remain fenced even after activation. The managed local-dev
workflow explicitly activates a newly generated disposable policy when migrating
a restored checkpoint; it never treats copying the old file as activation.

## Commit and dispatch boundaries

Business transactions and activation serialize on the same SQLite writer lock.
If a business transaction commits first, revocation follows it. If revocation
commits first, the old stamp cannot authorize another business mutation.
Read transactions authorize against the same snapshot as their returned rows.
Live subscriptions terminate when their admission stamp becomes stale.

Each external attempt has a separate short dispatch-admission transaction.
Its commit is the cutoff: an already admitted call may finish after revocation,
including if the process was paused between admission and network dispatch.
No business transaction spans a provider call. Settlement records outcomes
even if authority changed, but does not authorize application completion writes.
A retry needs new admission and a new attempt ID while retaining the original
effect ID for provider deduplication. Unknown provider outcomes need the adapter's
reconciliation rules; restoring a grant is not evidence that a timed-out send
never happened.

The atomic guarantee applies within one installed app database. Company-wide
updates across databases need individual activation receipts. Production identity,
policy distribution, provider cancellation and a general operator recovery API
are separate capabilities; no stronger guarantee is implied here.
