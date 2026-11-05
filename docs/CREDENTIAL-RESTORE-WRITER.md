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
