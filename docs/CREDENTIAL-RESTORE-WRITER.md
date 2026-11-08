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

The transaction captures all nine versioned records: root, sentinel, initial
creation, initial activation, epoch advance, restore reservation, terminal
settlement, consumed grant and the exact signed approval publication. It also requires the writer-operation name to be
absent. Equal-value rewrites are changes. Current approval, keys, epoch and
exclusive deadlines are rechecked when preparing the write body.

One Firestore read-write transaction reads those ten names. It updates root and
sentinel with explicit version preconditions and creates one writer record. The
other captured records remain in the transaction read set. The three ordered
write results and commit time are checked against a fresh strong read, including
the returned versions. This uses Firestore's [transaction read-set guarantees](https://docs.cloud.google.com/firestore/native/docs/transaction-data-contention)
and [atomic, ordered commit contract](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/commit).
The bounded codec uses [BatchGetDocuments](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/batchGet)
with `newTransaction.readWrite` for the initial read and default strong
consistency for the post-read. It adds no provider retry or alternate ledger.

The reservation send also retains its actual acknowledgement and complete
eight-record readback together. Its confirmation DATA binds the grant, the
acknowledged commit time, all five returned write versions, and every value and
version from the readback, including both immutable histories and the unchanged
approval publication. Acknowledged time is not inferred from a document version.
Moving this DATA cannot recover an uncertain send or construct a native owner.
The accepting supplier still owes a separate fresh confirmation by the same
drained App peer, under its retained original and real authority checks.

The retained counter request has a fixed read-only confirmation operation. Its
selectors come from the original initial completion, restore operation, captured
Active predecessor and known acknowledgement projection. It uses the same
eight-record decoder as the sender, checks the exact successor and unchanged
history, requires a read no earlier than the actual commit, and compares all
acknowledged versions and the complete record commitment. Its real postcheck
runs even when transport, decoding or comparison fails; failure permanently
refuses the request. This read operation does not yet supply the separate signed
peer acknowledgement or an accepting restore owner.

The incumbent stop protocol now has distinct frozen, drained, known-fence,
fence-confirmed and terminal-release messages. It branches only at the existing
Current result boundary and keeps the same clock, sequence, exchange, signed
peer and physical handles. The stopped channel cannot begin another Current.
The signed admin request distinguishes a policy observation from restore
execution. The latter captures both the approval intent used to select policy
and the distinct restore execution operation before freeze; neither is inferred
from the other or replaced by a later stop message. The Controller compares
both against its own retained selection. Plain observation cannot enter Stop.
The App seals its actual historical cohort, checks the exact Active predecessor
against its independently retained operation, and acknowledges drain before the
conditional fence can be sent. It keeps exclusion while waiting for the separate
known-fence message, performs the complete fresh confirmation read, checks the
same cohort again and only then sends the distinct fence acknowledgement.
Ordinary completion messages cannot stand in for these phases. This fixes the
peer-side ordering; the accepting Controller reservation producer and its
private post-CAS authority checks use the retained composition below.

The consuming Controller entry retains its authenticated executor and historical
keys, then commits the grant-keyed attempt marker and all native/file postchecks
before sending any stop or reservation packet. It freezes the genuine issuer,
awaits the actual drained App acknowledgement, prepares the exact conditional
plan and permits one native reservation send. Its transport uses the genuine
Controller write authentication, with no counter-read promotion, generic port
installer, retry or row-to-owner recovery.

A separate private registry-read loan covers the self-CAS interval. Before send
it requires the captured Active snapshot. During that one send/readback it may
observe only that predecessor or the exact planned Fenced values with unchanged
history; it authorizes no unrelated work. After the actual acknowledgement and
complete checked readback it requires the exact known versions, and cannot
regress to Active or accept equal-value rewrites. Current registry, executor,
attempt row, keys, authentication files, physical handles, frozen issuer and the
unchanged native original remain checked. The same fixed SQL projection serves
the distinct typed loans; the ordinary Active and Known-Fenced checks stay
strict. No provider call runs inside either SQL transaction.

The exact captured Current readiness interval moves into the Fenced continuation.
Fresh qualified clock checks enforce it at reservation, peer-envelope, handoff
and later current/SQL-local boundaries; expiry or rewind permanently refuses the
owner even if the clock is repaired. The signed native interval is unchanged.
These checks withhold success and owner publication after expiry, but cannot
undo an earlier provider commit or partially sent packet. They promise neither
rollback nor zero remote effect, and never authorize a retry.

Only after the same drained peer freshly confirms the complete known reservation
does the entry construct its retained Fenced continuation. The first profile
refuses any additional historical enrolled actor, another issuer/holder or an
escaping right that it cannot close; a signed count alone is insufficient. The
one-hour approval is never substituted for the short original. These source and
local-model checks do not establish native, live-provider, operator-command,
physical creator/P3, final restore settlement or receiving-writer qualification.

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


## Private native consuming entry

The private native composition consumes the actual authenticated executor into
one retained fenced continuation. A one-use borrow admits the actual root and
keeps that same loan with the staging State and immutable application selection.
Before source or staging effects, the fixed native check must bind the actual
plan, signed record, selection, intent and namespace generation. Pure input and
Cut comparisons are additional refusal gates, never substitutes for that check.
No second approval Session, original, stage, getter or caller-supplied approval
boolean is created.

The native branch runs the same complete reset and guarded file body as the
existing portable controls. Its report is constructed from that actual reset
result, admitted artifact/schema, immutable Cut/inventory, serialized reset-image
commitment and target. The kernel field `report.archive` still denotes the
source SQLite-image digest; the signed approval and Cut separately bind the full
archive graph digest. Counts and reports remain DATA. Target settlement and
writer activation still require genuine retained creator, physical P3 and the
authenticated receiving App at the fixed lower operations. Mandatory postchecks,
primary errors, Known-May and original deadlines are unchanged.

This is not an operational restore. No production constructor supplies staging
State from a fully admitted immutable native archive yet; source controls forbid
adding one from a record or ordinary path. All unfinished fixed suppliers still
permanently refuse. The receiving keeper and authenticated serving-generation
handoff are also absent. Returning receipt DATA cannot complete the borrowed
loan: losing it still refuses the retained owner, and no empty ledger, unseal,
cold reenrollment or initial-bootstrap adoption can replace the handoff.
Formatting, compilation, complete inventory/policy review and native qualification
are separate and remain required for the final joined source.
