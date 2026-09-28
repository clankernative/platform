# Managed credential implementation boundary

This document records the implemented foundation for
`proposals/app-identity/03-CREDENTIALS.md`. The implementation is staged. No
managed credential can currently be issued through an app, verified at API
ingress or revealed through a browser route.

## Portable contracts

Unified apps can now register `credentials` in `App.definition`. The sealed
`pf.Credential` module supports `client_family` and `personal_family` with fixed
or selectable grants over canonical `Api.write(Commands.<name>)` and
`Api.read(Reads.<name>)` targets. The family constructor fixes the profile in
the checked compiler type. The app supplies a stable ID and a bounded lifetime
in seconds; registration names remain separate from IDs. This is declaration
intent only. No family-specific lifecycle methods are generated yet.

The normal build reflects registered families into the artifact and recompares
them with the native worker at artifact load. It rejects duplicate IDs,
registration/profile drift, empty or duplicate roots, unsupported lifetimes,
internal command roots and target signatures that differ from the checked
operation catalog. Resource and impersonation families remain unsupported.

An operation can opt into a bounded credential authority contract with
`credential_ready`, then add typed local models with `credential_read`. The
normal build derives a credential manifest from checked operation definitions,
including local write effects and recursive child command requests. Artifact
load rederives it from the worker-checked app contract. Runtime execution of an
opted-in operation rejects undeclared local reads and all provider/resource
observations or external effects. Cycles, unmarked children and provider write
effects fail the build. These declarations are an enforced upper bound; a
handler need not exercise every declared action.

The instance resource catalog now holds named management policies and approved
authority ceilings, and each app binding selects its credential families with
an exact namespace and pinned references. A catalog-managed release candidate
qualifies every selected artifact's families against those definitions and
records composition-bound receipts. Activation refuses a credential-bearing
candidate without those receipts. Missing bindings, changed policies, enlarged
child authority and provider/resource authority fail qualification. This is
static release evidence; credential-specific host admission still must be
implemented before a declared family can issue or receive a key. Imported
operation credential paths remain unsupported until they have selected
permission contracts and step-level enforcement.

The trusted build runner classifies credential presence from the loaded
artifact and includes that claim in its verification evidence. An activation
without a catalog candidate now checks the exact completed verification
observation pinned by the release approval and requires verified absence.
Historical evidence without a classification is unknown and cannot use this
path. Credential-bearing artifacts therefore require a qualified catalog
candidate and selected instance at activation, including when the workflow
host has no catalog store.

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
and unknown-commit recovery. `prepare_issue` now requires a verified family
manifest and refuses a changed family contract, undeclared or enlarged root,
fixed-grant narrowing and a lifetime beyond the family bound. The host still
must establish the current selected instance binding and interactive authority.

`stage_rotation` checks the expected head/revision in that transaction and a
unique predecessor constraint allows at most one successor. It preserves the
stored grant and lineage, closes the predecessor delivery and supersedes its
version. `stage_revoke` is terminal for the lineage and closes all versions and
deliveries. The initial private kernel implements atomic replacement; overlap,
selectable-grant narrowing, callback use budgets and impersonation handoff have
not been implemented.

The private `verify_ingress` selector checks the current head, lineage and
version state, namespace, family contract, security epoch, expiry, authenticated
material identity, verifier and immutable operation ceiling. A malformed,
unknown, rotated or revoked token yields no identity. It is not wired to an API
route or dispatcher yet. The host must still establish current instance binding,
key readiness, audience, principal policy and resource authorization before
accepting an ingress invocation.

`authorize_reveal` serializes an available delivery check and an authorization
record in SQLite. Only a known successful commit produces a process-local,
consuming permit. A closure committed first denies; an authorization committed
first may complete its exact response afterward. A historical receipt cannot
produce a permit. The selected lineage independently supplies the expected
namespace, owner, version, recipient, epoch and material revision. The security
origin, session/CSRF/intent verification and no-store HTTP sink are still absent;
the current `VerifiedHumanPost` is an internal staging input, not proof of those
checks. Reveal authorization also checks issue, version expiry, grant expiry and
delivery expiry times.

## Verification and remaining gates

Focused tests cover duplicate declarations, selected-instance qualification,
public codec rejection of secret fields, authenticated material substitution,
real SQLite rollback with a product write, same-invocation retry, stale rotation,
terminal revocation, reveal closure ordering, reopen and an independent 32-case
SQLite transition model. The model checks state outcomes, not cryptographic
strength or browser isolation.

Before activation, complete the following gates from the proposal:

1. Generate and native-typecheck the complete family-specific Roc API and
   security actions; bind the derived authority manifest at admission, and add
   selected provider/resource/import contracts. Prove the interactive context and
   negative compiler fixtures with the pinned compiler. The declaration-only
   client/personal build path is present.
2. Complete selected-instance principal/context compatibility across child,
   delegated and provider paths. Resolve actual key/custody readiness and
   current management/metadata policy. The catalog-managed release path now
   checks exact local family bindings and approved authority; legacy activation
   requires a verified credential-free artifact.
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
