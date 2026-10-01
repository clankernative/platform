# Managed credential implementation boundary

This document records the implemented foundation for
`proposals/app-identity/03-CREDENTIALS.md`. The implementation is staged. No
managed credential can currently be verified at API ingress. Fixed-grant
client/personal issuance runs through a host-confirmed interactive command.
The isolated security shell supplies fresh confirmation, protected POST reveal
and acknowledgement. An ordinary app session starts navigation only.

## Portable contracts

Unified apps can now register `credentials` in `App.definition`. The sealed
`pf.Credential` module supports `client_family` and `personal_family` with fixed
or selectable grants over canonical `Api.write(Commands.<name>)` and
`Api.read(Reads.<name>)` targets. The family constructor fixes the profile in
the checked compiler type. The app supplies a stable ID and a bounded lifetime
in seconds; registration names remain separate from IDs. Generated metadata reads
and fixed client/personal `issue` are available. Rotation/revocation methods and
selectable lifecycle inputs remain absent.

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
opted-in operation rejects undeclared local reads and provider/resource
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
static release evidence; the interactive issuance adapter also requires current
confirmation and a ready host authority before a declared family can issue.
Credential-authenticated ingress remains absent. Imported
operation credential paths remain unsupported until they have selected
permission contracts and step-level enforcement.

Activation now resolves each family binding, management policy and approved
authority into the app's activated authority document. It verifies the family
receipt against the loaded artifact and rejects a missing or stale selection.
The selected snapshot is available to host admission without rereading mutable
desired instance configuration. Live policy, key and epoch readiness checks are
still required before issue or ingress.

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
until their generated Roc API and codecs use them. Metadata now has its own
native-checked family-specific API over these private readers.

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
lease. The selected readiness adapter resolves exact verifier/encryption versions
through the same purpose-bound key-provider port used by OAuth, including its
GCP Secret Manager adapter. Missing, expired or changed selected evidence denies.

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

The private store also has bounded creator-visible metadata `list` and `inspect`
readers for client and personal families. List visibility is applied in SQLite
before a page limit; cursors bind the namespace, family contract, requester and
management policy revision, and each call rechecks its supplied policy. These
readers return only safe summary and rotation data. The host must still verify
the activated family selection, current policy and authenticated requester
before calling them. A host-only runtime adapter now performs those checks for
a live browser session in one app database snapshot before list or inspect. It
refuses an inactive family, artifact mismatch or changed app scope.

### Interactive issuance through the ordinary command runtime

`Handler.interactive` specializes a local command's handler to the nominal
`pf.InteractiveContext`; an ordinary `Context` cannot be passed to generated
`Credentials.<registration>.issue`. Context construction and raw issue instructions
are sealed through both compiler admission profiles. The reflected operation is
interactive-only and requires exactly one fixed client/personal issue declaration:

```roc
.credentials(Credential.issue_access(KeyFamilies.clients))
.credential_label(Selectors.create_client_input_label)
```

The label selector is a generated `Path(Input, Str)` from the canonical input
codec. Admission requires a supported top-level text field; the host checks the
instruction's label against both that exact input value and the frozen confirmation.
Computed substitutions, another family, subject overrides and a second issuance
are refused. This first profile permits only local product writes, with no child
commands, external effects or preparation capability reads.

All acceptance channels require a host-only confirmation bound to the normalized
input, operation, actor, authenticated subject, recipient session, artifact,
activated authority revision, family binding, security epoch and fresh-authentication
time. Direct request provenance is rechecked at issuance. App sessions and actor
strings cannot create confirmation evidence. The protected browser shell creates
this evidence only after fresh reauthentication and exact form confirmation;
there is no raw family issue route.

The selected host authority obtains purpose-bound exact-version keys before the
product writer lock and rechecks its current local readiness and issuer permission
at issuance and final commit. No authority adapter is installed by default.
Generated issuance is a sealed local `Tx` instruction: private material, delivery,
receipt and ordinary product writes commit together, and failures roll them back.
Client subjects remain distinct from their human creators; personal subjects come
from confirmed identity evidence. App observations and results contain only nominal
public references, label and expiry. Lost-response retry returns the committed
public receipt without restoring a secret-delivery permission.

The disposable verification campaign explicitly installs random in-memory test keys
and simulated interaction evidence for app-owned properties. Ordinary runtime/web
loading does not install this adapter. These campaigns test composition and atomicity;
they do not qualify a real key provider, browser session or non-rollback epoch store.

Normal builds now generate `Credentials.<registration>.list` and `inspect`
for client and personal families. These return `Observe(Try(...))`, accept no
actor/context override, and require the containing operation to declare
`.credentials(Credential.metadata_access(family))`. The declaration witness
and raw observation constructors are sealed through both compiler admission
profiles. The host checks the exact registered family and access declaration,
the accepted invocation principal, and current activated authority under the
ordinary preparation lock. Recorded observations recheck authority before use.
Policy changes fence old invocations; metadata and rotation revisions remain
stale-able data, never mutation authority.

For example, a prepared query can call:

```roc
(Credentials.clients.list)({ after: Credentials.clients.start, limit: PageSize.default })
```

Each family has concrete nominal types such as `Credentials.Ref_clients`,
`Cursor_clients`, `VersionRef_clients`, `ManagementSnapshot_clients`, and
`Page_clients`; another family's cursor or reference fails native type checking.
The family record supplies `start`,
`cursor_from_str` and `ref_from_str`. Safe projections use `to_str`, page
`items`/`has_more`/`next_after`, and snapshot accessors. A page wraps the existing
bounded `CollectionPage`; `map` projects it into an ordinary serializable app
result. Public `cm1_` cursors and `cr1_` references are bounded shape codecs;
the host rechecks provenance, namespace, principal and current policy on use.
Apps currently decode these helpers from text inputs and project their safe
values into supported operation output shapes.

The credential metadata conformance app exercises the generated readers through
ordinary native dispatch, replay, and session-authenticated HTTP queries.
Group and resource visibility are still unsupported. There is no anonymous or
separate management endpoint; apps register their own ordinary queries.

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
origin now supplies session/CSRF/intent verification and a no-store HTTP sink.
The current `VerifiedHumanPost` remains an internal input constructed only after
those checks. Reveal authorization also checks issue, version expiry, grant expiry
and delivery expiry times.

### Protected browser actions

The build generates typed `SecurityActions.<command>` descriptors from the
registered command codecs and `ProductReturns.<page>` from admitted app pages.
Both constructors are sealed in normal/restricted admission. The descriptors are
navigation data; the protected navigation adapter accepts only the registered
interactive fixed-family issuance profile. A descriptor for another ordinary
command grants no authority and is refused by that adapter.

```roc
SecurityAction.bind(SecurityActions.create_client, client_input, ProductReturns.keys)
```

This produces `{ operation, payload, product_return }`, suitable for an ordinary
app view. A live app session submits it to `POST /api/security-actions` with the
normal Origin, CSRF and idempotency headers. The host validates the exact command
input codec and admitted static return page, then stores one bounded pending
intent in that app's existing database. Its response contains only an opaque
confirmation URL and invocation identity. Ordinary JSON commands and signed
native forms also start this flow for interactive commands. There is no issuance
acceptance or key-provider call at navigation time. Same-invocation retries retain
the intent; changed input or return page is refused.

The existing OAuth security shell mounts `/credentials/actions/<attempt>` on its
dedicated HTTPS edge and shares its IAP identity verifier and fresh Google OIDC
reauthentication adapter. App cookies and IAP identity alone cannot substitute
fresh authentication. The shell cookie, current canonical subject, challenge,
Origin and CSRF bind each POST to the exact pending command. Confirmation invokes
that ordinary command, including its product writes, through the normal runtime.
Selected issuer readiness, exact keys and epoch are checked before issuance and
again under the product writer lock. The bounded active-lineage quota is checked
under that same lock.

GET renders confirmation/delivery controls and never returns key material. A
reveal POST resolves the version from the successful invocation's private receipt,
rechecks current app/family authority and recipient/session/epoch, and commits a
fresh authorization under the SQLite writer lock. Only then does the selected
provider load keys and decrypt into the protected response. The consuming permit
cannot be replayed from a receipt. Acknowledgement closes delivery and clears the
shell session, returning only to an admitted app page. Every shell response uses
no-store, restrictive CSP, no-referrer and frame isolation headers.

The host explicitly attaches an installation-selected local credential registry with
`SecurityShell::with_credentials` before serving. It shares the isolated edge and
fresh-authentication state with the separately configured private OAuth transport.
Credential transport across separate shell/app hosts and live installation
qualification remain later steps. App runtime loading does not install
a credential authority or simulated browser proof. Readiness snapshots must be
supplied by admitted installation adapters, expire within five minutes, and bind
the exact family, management policy, security origin, key versions, issuer subjects,
quota and current security epoch. This slice does not qualify an external
non-rollback epoch/clock adapter or deploy a live installation.

The conformance app's management query binds client and personal creation to its
generated return page; its browser script only starts ordinary navigation. Native
tests cover fresh authentication, atomic product issuance, public receipt retry,
POST-only secret delivery, wrong origin/subject/cookie/CSRF/challenge/query rejection,
acknowledgement closure, readiness removal, epoch change and quota denial. Rejected
reveal requests assert zero additional provider loads.

## Verification and remaining gates

Focused tests cover duplicate declarations, selected-instance qualification,
public codec rejection of secret fields, authenticated material substitution,
real SQLite rollback with a product write, same-invocation retry, stale rotation,
terminal revocation, reveal closure ordering, reopen and an independent 32-case
SQLite transition model. The model checks state outcomes, not cryptographic
strength or browser isolation.

Before end-to-end credential use, complete the following gates from the proposal:

1. Generate and native-typecheck the complete family-specific Roc API and
   security actions; bind the derived authority manifest at admission, and add
   selected provider/resource/import contracts. Prove the interactive context and
   negative compiler fixtures with the pinned compiler. Client/personal
   declarations, generated metadata reads and fixed-grant interactive issuance
   and protected browser confirmation/reveal are present. Resource, selectable and
   impersonation issuance plus generated lifecycle management remain incomplete.
2. Complete selected-instance principal/context compatibility across child,
   delegated and provider paths. Resolve actual key/custody readiness and
   current management/metadata policy. The catalog-managed release path now
   checks exact local family bindings and approved authority; uncatalogued
   activation requires a verified credential-free artifact.
3. Add credential ingress verification and mandatory propagated identity and
   immutable ceiling checks to the dispatcher. Complete group/resource metadata
   visibility. The recipient-specific fixed client/personal security shell and
   protected HTTP response sink are present.
4. Share the role-specific vault commit boundary with OAuth; add callback,
   provider and worker sinks without a generic token getter. Add external
   non-rollback security epoch readiness, clock high-water and exact-key restore
   fencing.
5. Run concurrency, process-kill/reopen, browser, consumer and secret-canary
   campaigns. Integrate the first real app, then qualify later consumers;
   record unsupported adapters as blockers until their real consumers qualify.
   There are no live apps to migrate today.

The current private crypto and state code is an implementation foundation, not
evidence of production readiness. In particular, it must not be activated by
adding an HTTP route that constructs `IssueIntent` or `VerifiedHumanPost` from
caller input.
