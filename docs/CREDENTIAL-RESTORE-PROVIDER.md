# Exact restore provider messages

The private Firestore restore codec binds one original conditional reservation
to the admitted external epoch selection. It has no HTTP sender, approval
constructor, consumed-grant factory or retry path. The existing read-only
counter connection and purpose-bound bootstrap writer are unchanged.

One `batchGet` with a new **read-write** transaction reads seven exact documents:
root, bootstrap sentinel, initial create and activation receipts, the proposed
advance and restore receipts, and the grant-ID use row. The token is bounded,
canonical base64 and belongs only to that parsed transaction. Semantic document
failure retains it for pre-send rollback; malformed bytes do not invent a token.
No mask, historical read time or retry transaction is accepted.

The commit body uses that transaction and contains exactly five writes: CAS root
and sentinel under their captured update times, then create-only advance,
reservation and grant-use records. All four old records and the three absences
belong to the transaction read set, including immutable-history versions. Names
come from the validated original plan; paths cannot be supplied by a caller.
The grant-use key is independent of operation ID. New receipt documents contain
canonical typed JSON and a domain-separated digest; the initial record codec is
unchanged. Unknown fields, duplicates, sequence-shaped records, wrong tags or
digests, changed versions, occupied names and expired current DATA refuse.

These rules follow the provider's [batchGet contract](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/batchGet),
[read-write options](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/TransactionOptions)
and [atomic commit contract](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/commit).
The [transaction read set](https://firebase.google.com/docs/firestore/transaction-data-contention)
protects records not rewritten by this commit. Local SQLite interpretation of
these conditions is conformance evidence, not live Firestore qualification.

A five-result acknowledgement is only historical DATA. Fresh default-strong
readback must cover the complete same seven-document set, with provider read
times no earlier than the acknowledgement and full kernel reconciliation. It
cannot reuse the transaction's old snapshot. Neither readback nor a matching
receipt reconstructs a consumed approval owner after loss, ambiguity or expiry.

The accepting native consumer still must retain the genuine passkey approval,
actual current executor and native storage owners; compare every approved field;
mark May before the possible send; preserve its original short work budget; and
perform mandatory actual postchecks before publishing an opaque consumed owner.
The one-hour approval is not a new native acquisition clock. The codec alone
cannot authorize a stop, copy, key use, reset, P3/writer admission or serving.
