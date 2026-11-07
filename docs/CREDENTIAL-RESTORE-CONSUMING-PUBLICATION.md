# Signed approval consumption boundary

The restore reservation now reads the exact immutable approval publication from
`day2_restore_approval_publications_v1` in the same read-write transaction as the
incumbent root, sentinel, initial receipts, advance name, restore reservation and
single-use grant name. This joins the producer's publication to the existing
five-write reservation; it does not add a second consumption store or a no-op
publication write.

The publication's stable authority/grant name, complete signed record, canonical
payload, document commitment and provider timestamps must match. Missing,
foreign, malformed, duplicate or substituted records refuse. A transaction
retains its header on semantic refusal for bounded rollback only. Unknown commit
completion does not permit another attempt or reconstruct native authority.

The post-commit API belongs to the retained consuming transaction. It compares
the strong read with that transaction's captured publication, including its
original `updateTime`. A caller cannot pass the post-read as its own before
version. The distinct restored-writer codec retains this exact publication
version while reading all ten names and checks it again on its strong post-read.
Equal signed bytes rewritten at a new version still refuse. The consuming and
writer transactions keep their existing five and three writes respectively.

Firestore validates the read set of a read-write transaction and commits its
writes atomically. The implementation follows the
[transaction contract](https://docs.cloud.google.com/firestore/native/docs/transaction-data-contention),
[BatchGetDocuments request](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/batchGet)
and [ordered commit results](https://docs.cloud.google.com/firestore/docs/reference/rest/v1/projects.databases.documents/commit).
No unsupported REST `verify` write or provider retry is added.

These are bounded DATA codecs, not an accepting native restore. A genuine
consumer must verify current registry/admin/signing selection and executor
presence; retain its original, auth-store and physical/exclusion owners; mark
its attempt before a possible send; and carry the same actual transaction
through the mandatory native postchecks. The signed grant's one-hour validity
and the execution original's five-second bound remain separate and unchanged.

Local tests use synthetic signed records, strict wire envelopes and ordinary
SQLite with an independent transaction/read-set oracle. Existing write cuts,
unknown completion and twice-replay histories include the publication read.
They do not qualify live Firestore, native ownership, power-loss durability,
complete incumbent drain, staged reset, writer admission or operator execution.
