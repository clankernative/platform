# Private credential restore staging

The private staging code captures one SQLite image through a held source file,
validates its complete current credential unit, and revokes imported credentials
in a fresh memory-only database. It freezes the resulting bytes before creating
a new target, using directory-relative creation under the held root and private
directory descriptors. It writes only through the actual creator descriptor,
then syncs and checks the exact readback. Memory commit records prepared DATA;
physical writes and durability checks remain separate effects.

The first profile bounds the image to 16 MiB, lineages to 1,024 and versions to
4,096. It requires an existing complete canonical credential unit with foreign
keys enabled. Unknown or partial schemas, foreign namespaces or source epochs,
occupied peer history, WAL images and sidecar files refuse. Sidecar absence and
SQLite integrity do not establish committed-backup provenance: the future
maintenance supplier must bind the exact verified cold archive.

Reset uses the existing active-to-revoked transition. Original epochs, grants,
identities, custody envelopes, receipts, reveals and origin history are retained;
delivery closes through that same transition. It does not retag ciphertext or
reissue credentials. A replaced or revoked credential remains refused. Business
rows in the admitted profile survive. The ordinary restore refusal is unchanged.

The production accepting boundary remains closed. Every implementation of the
private checks trait is test-only; no default implementation, public command,
Runtime opener, native factory, target adoption or publication path is installed.
The test application validator is synthetic. A staging projection supplies
counts and image identity only. It does not establish a complete application
reset, current external epoch settlement, a new writer or serving readiness.
Whole-application disable/session invalidation is still required before any
future writer admission.

A usable restore additionally requires designated restore approvers and
executors, genuine approval evidence with one fixed original deadline, exact
custody-key authority, external reservation and settlement, old-owner fencing
and drain, actual artifact/profile admission and the same-created target's new
writer. Enrollment, bootstrap or OAuth trust does not implicitly grant restore.
The operational recipe belongs in Roc and must publish last. Neither a previous
staging projection nor a reconstructed descriptor can renew an uncertain attempt.

The conformance suite uses real SQLite and descriptor I/O, an independent
commit-cut oracle, twice replay, source/target and creation-parent pathname swaps and actual process
loss followed by reopen. Reopen is an oracle observation; it never adopts an
existing target. Local process-loss tests make no power-loss, Linux, hostile
filesystem containment or live-provider qualification claim.
