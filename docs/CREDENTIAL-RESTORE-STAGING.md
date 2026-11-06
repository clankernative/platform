# Private credential restore staging

The private staging code captures one SQLite image through a held source file,
validates its complete current credential unit, and performs the complete
application denial reset in a fresh memory-only database. The staging owner
opens the sole outer transaction; the prepared application selection supplies
the same fence, canonical schema references and inventory cut to the existing
SQL-only reset. The cut must match the staging namespace and source epoch.
There is no second autocommit reset path or transaction held over provider,
artifact, entropy or filesystem work. It freezes the resulting bytes before creating
a new target, using directory-relative creation under the held root and private
directory descriptors. It writes only through the actual creator descriptor,
then syncs and checks the exact readback. Memory commit records prepared DATA;
physical writes and durability checks remain separate effects.

The first profile bounds the image to 16 MiB, lineages to 1,024 and versions to
4,096. It requires an existing complete canonical credential unit with foreign
keys enabled. Unknown or partial schemas, foreign namespaces or source epochs,
unclosed or foreign peer history, WAL images and sidecar files refuse. Retained
canonical peer history is admitted only through the concrete full-reset cut
inside the same transaction. Sidecar absence and
SQLite integrity do not establish committed-backup provenance: the future
maintenance supplier must bind the exact verified cold archive.

Reset uses the existing active-to-revoked transition. Original epochs, grants,
identities, custody envelopes, receipts, reveals and origin history are retained;
delivery closes through that same transition. It does not retag ciphertext or
reissue credentials. A replaced or revoked credential remains refused. Business
rows in the admitted profile survive. The same reset disables the old application
authority, invalidates old sessions and ticket secrets, fences delegations,
freezes budget debt and marks imported OAuth connections for fresh
reauthorization. Existing uncertain refresh and external-effect history stays.
The ordinary restore refusal is unchanged.

The production accepting boundary remains closed. Every implementation of the
private checks trait is test-only; no default implementation, public command,
Runtime opener, native factory, target adoption or publication path is installed.
The test application validator is synthetic. A staging projection supplies
counts and image identity only. It now describes the concrete whole reset that
ran before memory commit, serialization and close, but cannot establish actual
archive/artifact/model admission, current external epoch settlement, a new
writer or serving readiness. No production checks implementation exists yet;
the complete admitted artifact/profile and same creator must remain held by
the future genuine native supplier rather than supplied as a summary.

A usable restore additionally requires designated restore approvers and
executors, genuine approval evidence with one fixed original deadline, exact
custody-key authority, external reservation and settlement, old-owner fencing
and drain, actual artifact/profile admission and the same-created target's new
writer. Enrollment, bootstrap or OAuth trust does not implicitly grant restore.
The operational recipe belongs in Roc and must publish last. Neither a previous
staging projection nor a reconstructed descriptor can renew an uncertain attempt.

The conformance suite uses real SQLite and descriptor I/O, an independent
commit-cut oracle with full application-state readback, twice replay,
source/target and creation-parent pathname swaps and actual process
loss followed by reopen. Reopen is an oracle observation; it never adopts an
existing target. Local process-loss tests make no power-loss, Linux, hostile
filesystem containment or live-provider qualification claim.
