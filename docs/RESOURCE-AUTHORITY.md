# Activated resource authority

The resource contract is implemented in
[`day2-capabilities::resources`](../crates/day2-capabilities/src/resources.rs).
It currently covers the actor's local notification mailbox and an exact issuer
in the explicitly seeded synthetic Carta reader. It does not connect any live
SaaS provider. The broader [integration plan](RESOURCE-CAPABILITIES-PLAN.md) and
[inventory](RESOURCE-INTEGRATION-INVENTORY.md) describe future provider work.

## Desired definitions and active grants

The existing `Instance` contract has one optional `resources` catalog. It contains
versioned connections, typed resources, reusable policies, and budget definitions.
Each `AppBinding.resource_policies` entry attaches one exact policy revision to
one operation and binds every named slot to an exact allowed resource revision.
There is no second company configuration and no runtime catalog lookup.

A reusable policy declares its owner and delegates, eligible apps and actors,
named slots, permitted resource revisions, actions, request/response/call ceilings,
budget references, and optional maximum duration. An attachment can narrow actors
and supply an absolute expiry. It cannot widen a slot or silently select all
resources mentioned by a policy. Two attachments cannot supply the same operation
slot. Unknown versions, incompatible resource/action kinds, missing slots and
expired attachments fail resolution.

Activation resolves this authoring data into
`AuthorityDocument.resources.operations[operation][slot]`. Every resulting grant
contains the concrete provider and resource target plus the exact policy,
resource, connection and budget revisions. Actor and action sets are intersected
with ordinary operation policy and outer app memberships. The existing coarse
policy remains an independent ceiling. A missing resource grant denies integration
use even when the operation's ordinary capability allowlist permits that action.

The authority document also contains the concrete definitions of every referenced
budget. Its artifact pointer, authority revision, resolved grants and budget cap
updates commit together under the app database's writer lock. Updating desired
catalog bytes does not change the active document. A shared policy rollout needs
an explicit reviewed activation for each affected app.

Supported authoring saves retain version evidence in
`.state/resource-authoring.sqlite`. That database records immutable definition
bytes, including definitions retired from the desired catalog. Deleting and
re-adding an alias cannot reuse its version for different content or reset a
budget's scope or period. The version reservation commits before the desired file
is atomically replaced. After an interrupted replacement, retry the same proposed
definition; a reserved version cannot be repurposed or rolled back. This is
provenance storage, not another live policy source.

## Resource boundaries

`notification_mailbox` always means the invoking actor's mailbox. Topic `any`
covers that actor's topics only; it never grants arbitrary recipients. `only`
enumerates topics, while `prefix` deliberately includes future topics under an
approved prefix. The action facets distinguish recipient resolution, latest
message reads and sends.

`carta_issuer` pins an exact issuer identifier within the synthetic Carta provider.
Snapshot and record reads are distinct facets. A seed file or guessed issuer ID
does not grant authority. There are no network credentials in either resource
definition. Each current local provider has one physical connection per catalog;
aliases cannot manufacture independent physical connection budgets.

The pure Roc SDK requires the opaque operation `Context` to ask the host for a
named operation binding. Host-issued handles
are bound to the installed app, artifact, actor, operation, invocation and active
authority stamp. Narrowing can restrict topics, actions, expiry and limits while
retaining budget ancestry. A helper can accept a narrower opaque handle as its
ordinary argument; the host validates its authority on use. A helper receiving
only that handle cannot obtain a broader binding. Passing the full `Context`
explicitly delegates issuance authority. This admitted-SDK boundary does not prove
information-flow noninterference between separately permitted reads and writes
or containment of hostile native code.

## Migration and recovery

Old desired instances deserialize with no catalog and no attachments. Old active
authority documents deserialize with an empty resource snapshot. Neither path
creates compatibility grants. Existing integrations therefore require an explicit
catalog, operation attachments and authority activation before resource use.
Ordinary local database operations continue to depend on their existing policy.

`development::local_resource_fixture` is an explicit authoring helper for disposable
development and verification instances. The caller chooses actor-mailbox topic
scope and/or an exact synthetic issuer. It only authors facets already present in
the supplied operation policy. Runtime loading and normal activation never call
it as a fallback. The local development creator and relevant test worlds use it
before initialization; their broader self-mailbox topics are fixture permissions,
not deployment defaults.

Backups retain the resolved active resource document in the app database and in
backup verification evidence. They omit the mutable desired catalog and
attachments. Restore disables the copied authority, rotates its authority epoch,
blocks copied pending work and freezes copied budget accounting. Re-enabling a
restored app requires deliberate authority activation; budget recovery is a
separate operator action. Neither activation nor a new policy revision resets
previous spending. Installation-wide capacity requires disjoint allocations from
the surviving company allocator before the app can spend it.

These boundaries extend [transactional authority](TRANSACTIONAL-AUTHORITY.md).
They do not establish production authentication, native hostile-code isolation,
provider-side revocation of already admitted calls, or automatic data movement
approval. Owners and delegates become operational roles only through the trusted
administration surface's explicit checks; their presence in a catalog is not an
app-facing capability.
