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
counter and slot observations. Only the actual original native owner can supply
the current execution context; observations and provider tokens cannot do so.
Claim requires a coherent NotApplied counter result and the exact accepted slot.
Only a known successful claim commit with still-valid original authority yields
a consuming counter-send handle. A lost/malformed/expired claim reply yields no
handle. Reading a matching stored MayHaveBeenSent cannot reconstruct one.
Rearming requires a fresh coherent NotApplied observation, preserves the frozen
request and grants no send handle. A later separately authorized claim is needed.
Settlement requires a coherent Applied receipt; its control lineage does not
identify the winning physical HTTP attempt and is not app readiness.

## One Controller-owned transaction per action

The Controller starts an explicit Firestore read-write transaction with one
`batchGet` of the exact counter documents and control slot. The opaque, one-use
token is bound to the selected database and logical core. The slot commit
consumes it, retaining create-only or exact-version preconditions. A known
successful MayHaveBeenSent commit still precedes the separate counter send;
neither a stored May nor an ambiguous commit reply can create a send handle.
There is no retry on contention, abort, expiry or lost acknowledgement.

After the commit, the Controller performs a token-free strong `batchGet` and
the unchanged complete after-state validation before announcement/transfer. The
App's paired read is also strong and read-only. Every returned document appears
exactly once, the entire stream has nondecreasing readTime, and the existing
closed counter and slot codecs run only after those global checks. No read-time
selector or old transaction is reused to observe a commit's result.

Normal reserve and settle use three counter/slot Firestore RPCs: transaction
read, slot commit, strong post-read. Dispatch uses four: transaction read,
known-May commit, counter commit, strong post-read. Other metadata and identity
exchanges are unchanged. Discovery is additional: discard both first values, close any
known transaction, then reread the entire expanded pair under the original
budget. Pre-send failure attempts token cleanup only while the same actual port
and budget remain valid. A refused owner cannot bypass its guards for rollback;
unresolved provider resources expire without granting permission. A token is
spent before a possible commit send, so an ambiguous reply cannot resend it.

All role, physical file, writer, identity, original-clock and per-RPC pre/post
checks remain. The independent Firestore 20-second lock deadline can abort a
transaction even within the native storage-bootstrap ceiling. This change does
not raise either deadline or qualify latency, live contention or timing margin.
Provider contracts: [batchGet strong reads and stream coherence](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/batchGet),
[transaction commit](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/commit),
and [transaction failure limits](https://firebase.google.com/docs/firestore/manage-data/transactions#transaction_failure).

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

### Unchanged initial-file continuity

The original creator can recheck the bound layout, same retained descriptor and
anchor, fixed leaf, complete bytes, and original acquisition budget. Every read
has checks before and after it. A handled failure permanently refuses the owner
and acquisition while retaining the original file, anchor and proposal; restoring
the path or bytes, or supplying another interval, cannot clear that refusal.

This check returns unit. It produces no stored permission, role or P3 witness.
It checks the unchanged initial image before later application writes: a valid
SQLite write deliberately makes this check refuse. It is not a general check of
serving database integrity. Sampled checks do not eliminate concurrent changes,
qualify provider durability or establish a hard OS I/O deadline. This continuity
check itself supplies neither a storage issuer nor a current execution context.

## Conformance evidence

The independent SQLite provider oracle implements only create-only and exact
version CAS semantics. The paired-reader model additionally snapshots both
SQLite stores and rejects an action commit if any requested document changed;
it is a controlled schedule, not a live Firestore transaction implementation.
Its shared journal records stable handle/attempt/event
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
