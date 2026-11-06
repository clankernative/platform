# Restored-writer transition and peer protocol

This is the DATA/protocol portion of secure restore. It does not supply a genuine
approval, complete incumbent fencing, an accepting archive reader, a native
creator/P3, a receiving App keeper or a serving writer. The native supplier must
retain those actual owners throughout its one attempt; none can be reconstructed
from the records described here.

A successful restore settlement leaves epoch two **fenced**. The distinct writer
transition requires the exact completed whole-application reset, its target
incarnation/image/schema/artifact, the consumed grant and an authenticated new App
holder. It never relabels the initial seed or adopts the old first holder. The
existing initial bootstrap reader explicitly refuses the new restored phase.
Ordinary serving is not enabled by this change.

The transaction captures all eight versioned records: root, sentinel, initial
creation, initial activation, epoch advance, restore reservation, terminal
settlement and consumed grant. It also requires the writer-operation name to be
absent. Equal-value rewrites are changes. Current approval, keys, epoch and
exclusive deadlines are rechecked when preparing the write body.

One Firestore read-write transaction reads those nine names. It updates root and
sentinel with explicit version preconditions and creates one writer record. The
other captured records remain in the transaction read set. The three ordered
write results and commit time are checked against a fresh strong read, including
the returned versions. This uses Firestore's [transaction read-set guarantees](https://docs.cloud.google.com/firestore/native/docs/transaction-data-contention)
and [atomic, ordered commit contract](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/commit).
The bounded codec uses [BatchGetDocuments](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/batchGet)
with `newTransaction.readWrite` for the initial read and default strong
consistency for the post-read. It adds no provider retry or alternate ledger.

The signed restored-holder transcript has nine fixed steps: Ready, Hello, Offer,
Confirm, Durable, Accepted, Activated, ActivatedAck and Released. It binds both
actual stage commitments, both nonces, the complete target/creator/reset
projection and activation versions. The restore transcript uses the existing
five-second Current purpose. The initial ten-second and temporary bootstrap
sixty-second purposes cannot be substituted. Completing this DATA transcript
alone creates no native owner or current request permission.

Local availability is spent before a possible action. Error, unwind, an unknown
commit, changed target or a second attempt permanently refuses that original.
Historical reconciliation can identify applied, unapplied or conflicting DATA;
it cannot resend, restore availability or adopt a writer after process reopen.

Portable checks use a separate oracle for generated multi-step histories, replay
each history twice, and compare real SQLite records. Child-process cuts require
the exact checkpoint, actual SIGKILL, reaping and pipe EOF before inspecting
reopened state. Failure bundles preserve complete expected/actual prefixes with
private directory/file modes, including provider setup failure. These are
ordinary SQLite and protocol checks, not native filesystem, Linux, Firestore,
power-loss or production qualification.

The production report producer is still owed. It must bind the actual successful
whole-application reset and its exact Cut, complete archive/inventory, final
serialized reset-image hash and held creator under the same original. Counts,
supplied reports or credential-only reset are insufficient. Before accepting
native publication, the remaining supplier must also retain genuine consumed
approval, complete drained exclusion, physical P3, authenticated receiving App,
current counter authority and known final settlement. The signed approval's
one-hour validity remains separate from the unchanged short execution original.

## Existing staged-owner foundation

This borrows the actual closed incumbent-drain session and restore-staging owner;
it does not construct a production writer. There is no production approval,
complete renewal-stop, current settled-root or P3/writer/peer supplier. The source
is sealed, has no production/default implementation, and its admission origin
has no production variants. The approved policy requires a current instance admin,
a reviewed-registry passkey, a signed archive/target/epoch/executor-bound approval
and a single-use, non-renewable one-hour grant. Its genuine producer and
consuming native owner remain separate implementations.

The staged owner freezes the reset image commitment before any target creation,
and records the identity from its first actual creator file before postchecks.
Candidate admission and every later consuming check reread and hash that held
creator file, bounded to the existing sixteen-mebibyte image limit with one
refusal byte. Same inode, length, path or an old positive projection cannot prove
current contents. Root/directory/named-file checks remain in place; the creator
cannot be replaced by a byte-identical inode or reopened path.

Every read is bracketed by fresh checks of the same borrowed approval/exclusion
session, actual staging owner and, once admitted, retained writer source. Scope,
selection, namespace generation, operation, source/target epochs, target
incarnation, original continuity, settled-root commitment, creator and reset
image must join. The opaque original identity is DATA continuity only; it cannot
mint admission or confer authority after refusal/expiry. A future native supplier
must retain genuine same-original rights and prove the currently settled/fenced
root plus actual P3/current-writer/peer owners on this file. It must not acquire
unrelated authority on a new clock and stamp a copied identity onto it.

Admission marks the actual staging owner spent before any possible writer send.
Unknown completion never retries. Mandatory postchecks run on primary errors and
preserve the primary cause. Any error, caught unwind or dropped candidate
terminally refuses the actual staging owner, drain session and writer source,
even when a caller retains them and repairs the input. A new staging owner cannot
adopt the path after process loss or drop; exclusive creation still refuses it.

No FD or raw connection getter, publication, serving conversion or native writer
constructor is added. No original database or business state is changed. The
staged image remains the previously documented credential-unit reset, not the
complete application/session-disable policy. Tests use real SQLite/files and
controlled unqualified suppliers. They do not qualify native exclusion, epoch
settlement, physical fencing, custody, operator execution or crash power-loss.

The joined stage entry captures original continuity from the actual borrowed
drain session before reset or creation, not at candidate admission. Raw mechanical
staging leaves that field absent and cannot produce a candidate. The wrapper
retains the actual session through staging and checks it before/after the whole
call. This establishes structural birth continuity only. It does not qualify
native approval freshness at each internal staging effect: the future genuine
Checks supplier must retain the same actual original and check it at every IO
boundary and local SQL/COMMIT using a qualified cheap local clock, without
fencing/provider RPC inside a transaction. No accepting supplier exists here.
