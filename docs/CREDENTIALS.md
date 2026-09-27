# Managed credential implementation boundary

This document records the implemented foundation for
`proposals/app-identity/03-CREDENTIALS.md`. The implementation is staged. No
managed credential can currently be issued through an app, verified at API
ingress or revealed through a browser route.

## Portable contracts

`day2-capabilities::credentials` defines the managed family declaration,
manifest, public metadata/result shapes, selected-instance binding and static
qualification receipt. A family has a stable ID distinct from its code-facing
registration name. The declaration fixes its principal/resource profile,
fixed or selectable grant mode, canonical root names and bounded lifetime.

`build_manifest` rejects duplicate family IDs and generated names with both
source locations. It requires each selected root to be a registered eligible
ordinary operation and requires a canonical single-resource target for resource
profiles. The family contract is derived from exact canonical
`OperationAuthorityContract` values, which are also used by OAuth. An unrelated
operation does not enter the family digest. The code does not define credential
query/command wrappers or a scope-string inventory.

`qualify` checks the exact binding, pinned management policy, approved authority,
profile, lifetime and reveal bounds for a selected namespace/composition. A
qualification receipt is evidence for one composition; it is not permission to
issue or use a credential. The key, vault, security shell, epoch store, current
identity, policy and consumer still require readiness and live checks. The
portable public `Issued`, `Summary`, `Inspection`, cursor, management snapshot
and outcome schemas have no secret field. Their Rust types are contract sketches
until the generated Roc API and codecs use them.

## Private per-app state

`day2::managed_credentials` owns a host-only token/envelope format and SQLite
tables. `Runtime::initialize` installs versioned reserved tables in the existing
app database. The tables contain lineages, immutable versions, encrypted
material, deliveries, receipts and reveal authorizations. They are outside Roc
`Data`. The private module is not an app SDK or a callable HTTP route.

The local token format is `d2c1.<selector>.<32-byte-secret>`, with independent
cryptographic randomness for selector, secret and AES-GCM nonce. The verifier
uses a domain-separated HMAC-SHA256 bound to the full material identity. The
private envelope uses AES-256-GCM with authenticated namespace, family, lineage,
version, recipient, security epoch, material revision, envelope revision and
encryption-key version. Exact key versions come from a caller-supplied private
lease. The current adapter does not resolve that lease from a qualified instance
key provider.

`stage_issue` accepts the existing app SQLite transaction. It stages the
lineage/version, verifier, encrypted material, delivery and deduplication receipt
with any product writes. A retry of the same accepted invocation and intent
returns the original public identity; changed intent fails. The pending result
has no token or delivery permit. The containing product coordinator owns commit
and unknown-commit recovery.

`stage_rotation` checks the expected head/revision in that transaction and a
unique predecessor constraint allows at most one successor. It preserves the
stored grant and lineage, closes the predecessor delivery and supersedes its
version. `stage_revoke` is terminal for the lineage and closes all versions and
deliveries. The initial private kernel implements atomic replacement; overlap,
selectable-grant narrowing, callback use budgets and impersonation handoff have
not been implemented.

`authorize_reveal` serializes an available delivery check and an authorization
record in SQLite. Only a known successful commit produces a process-local,
consuming permit. A closure committed first denies; an authorization committed
first may complete its exact response afterward. A historical receipt cannot
produce a permit. The selected lineage independently supplies the expected
namespace, owner, version, recipient, epoch and material revision. The security
origin, session/CSRF/intent verification and no-store HTTP sink are still absent;
the current `VerifiedHumanPost` is an internal staging input, not proof of those
checks.

## Verification and remaining gates

Focused tests cover duplicate declarations, selected-instance qualification,
public codec rejection of secret fields, authenticated material substitution,
real SQLite rollback with a product write, same-invocation retry, stale rotation,
terminal revocation, reveal closure ordering, reopen and an independent 32-case
SQLite transition model. The model checks state outcomes, not cryptographic
strength or browser isolation.

Before activation, complete the following gates from the proposal:

1. Generate and native-typecheck the complete family-specific Roc API and
   security actions; integrate declarations and exact authority summaries into
   the normal app build and admission path. Prove the interactive context and
   negative compiler fixtures with the pinned compiler.
2. Connect selected-instance bindings to the resource catalog and release
   qualification, including principal/context compatibility across child,
   delegated and provider paths. Resolve actual key/custody readiness and
   current management/metadata policy.
3. Add credential ingress verification and mandatory propagated identity and
   immutable ceiling checks to the dispatcher. Add bounded metadata readers,
   recipient-specific security shell and protected HTTP response sink.
4. Share the role-specific vault commit boundary with OAuth; add callback,
   provider and worker sinks without a generic token getter. Add external
   non-rollback security epoch readiness, clock high-water and exact-key restore
   fencing.
5. Run concurrency, process-kill/reopen, browser, consumer and secret-canary
   campaigns. Migrate Beastly Transcriber first, then the remaining cohorts;
   record unsupported adapters as blockers until their real consumers qualify.

The current private crypto and state code is an implementation foundation, not
evidence of production readiness. In particular, it must not be activated by
adding an HTTP route that constructs `IssueIntent` or `VerifiedHumanPost` from
caller input.
