# Initial credential control slots

The initial bootstrap reserves one permanent control document for each authority
and stage in the selected physical Firestore authority database. The document
name depends on the authority and Create/Complete stage, never on a request ID or
controller attempt. Changing the request, seed, app process or key cannot select
a replacement slot.

## Immutable selection and acyclic IDs

Desired policy contains selections. OriginalSeedCore adds the once-generated
record, database and activation incarnations and binds the policy, authority,
physical database UID, key set, stable controller role, volume/mount/schema,
artifact and app workload. It excludes the actual marker hash, operation,
request, receipt, holder, after state and attempt/execution/time values.

InitialMarker binds the seed digest, marker format and schema contract. The
bootstrap request is derived from that seed and marker. Create operation ID
binds authority and seed digest. Complete operation ID binds authority and the
original holder core: seed, Create receipt, original root/sentinel versions and
app principal/Pod/process/key DATA. Its own operation/request ID and resulting
after state are excluded. Exact closed typed JSON bytes are retained for the
counter request; the slot cannot substitute a different canonical spelling.

## State and dispatch

Prepared reserves the original immutable logical core. MayHaveBeenSent records
a version-bound attempt with a nonzero, checked, nonwrapping string ordinal.
Retryable retains that attempt and an explicit version-bound rearm. Observed
retains its receipt and control lineage. Fenced retains the reservation. There
is no deletion, expiry, reset, replacement, reseed, takeover or release operation.

Every slot mutation needs separate opaque current execution authority and fresh
counter and slot observations. The authority's production factory is absent.
Claim requires a coherent NotApplied counter result and the exact accepted slot.
Only a known successful claim commit with still-valid original authority yields
a consuming counter-send handle. A lost/malformed/expired claim reply yields no
handle. Reading a matching stored MayHaveBeenSent cannot reconstruct one.
Rearming requires a fresh coherent NotApplied observation, preserves the frozen
request and grants no send handle. A later separately authorized claim is needed.
Settlement requires a coherent Applied receipt; its control lineage does not
identify the winning physical HTTP attempt and is not app readiness.

## Native preparation prerequisite

The production current execution factory must own and recheck the original
controller-created file capability, completed P3 durability/readback, native
process/role/code/clock and the original app key/channel where required. The app
opens an existing prepared file; it cannot create or replace it. Descriptor loss
or controller death refuses all mutations, including when the remote slot is
absent. DATA, receipts, a copied file, a new descriptor and a reconstructed key
cannot supply these capabilities. Native original-file preparation and app
runtime/channel qualification remain separate work. Controlled context-loss
fixtures do not establish actual FD-loss or durability qualification.

## Conformance evidence

The independent SQLite provider oracle implements only create-only and exact
version CAS semantics. Its shared journal records stable handle/attempt/event
identities, dispatch order, provider-observed versions, commit/refusal outcomes,
reply loss and final rows/versions. Dispatch records commit separately from the
mutation; a failed CAS or process exit cannot erase them. Each capture creates a
new artifact. An independent conditional-write replay reconstructs final state
without calling the production transition or request-reconciliation code.

Concurrent reservation and claim races, reply loss, immutable Complete candidate
checks and actual process exits around mutation/commit are covered by authored
controls. Test execution and source guards must be recorded separately; authored
cases alone are not verification evidence. No Linux/GKE, live bootstrap,
hostile-code containment, cold-cache or once-only HTTP claim follows from these
controlled tests.
