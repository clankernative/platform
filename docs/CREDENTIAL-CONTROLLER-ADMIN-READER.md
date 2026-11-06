# Action-scoped Controller administrator reader

`ActiveControllerStorageContinuity::begin_accepting_admin_reader` acquires the
actual authenticated `ControllerAdminReadLoan` and consumes it into the reader. It binds the exact metadata object, operation,
approver and executor to one current policy revision. Both principals must be
current administrators; they may be the same administrator. Their supplied
names are still DATA, not authentication. A passkey-backed approval producer
must authenticate their identity and subject bindings separately.

An initial known nonmember returns `None` only after actual SQLite close,
native postchecks and complete counter/peer settlement. It creates no reader or
approval. Malformed input and native/SQL/unknown outcomes remain errors. Losing
membership after a reader has captured its selection remains terminal.

The App holds its real mutable owner and storage continuation before the
Controller opens SQLite. The reader opens one read-only, no-follow connection,
binds its stable boxed identity, and retains its actual MAIN/WAL/SHM descriptors
for the entire action. Every fixed policy read uses a fresh transaction. The
transaction commits or rolls back before provider/configuration reobservation
or any external work. There is no SQL, connection, descriptor, stage or native
owner getter and no arbitrary SQL callback.

Before configuration, both Controller reader entries compare SQLite's actual
opened MAIN with the original and authenticated App cohort. Every sidecar
already open must also match. WAL/SHM may be opened lazily, so this early check
does not claim a complete cohort. The later complete checks before and after
policy projection remain mandatory. Comparisons inspect held descriptors;
they never open and close a duplicate of the SQLite MAIN inode.

The first read captures the exact authority stamp. Later checks read current
policy again and refuse a different stamp, removed principal, disabled
application, changed artifact, substituted metadata/operation or changed
handles. A successful read never adopts a newer revision, even when the same
names remain administrators. All refusal is terminal for the actual loan;
repairing a clock, input, connection or policy cannot resurrect it.

Transaction completion and connection close have separate states. Finishing
a transaction allows external freshness checks while retaining the same actual
connection. It cannot release the App peer. The fixed close operation consumes
the same boxed connection, checks the authenticated cohort and actual
autocommit state, performs `Connection::close`, and runs the native postcheck.
Only a known close permits final counter/peer settlement. The reader's fields
also drop SQLite before the native loan on abandonment. Original errors take
precedence while mandatory postchecks still run; unknown completion cannot
publish success.

The reader is limited to the current accepting action under the existing
five-second original. It must settle before a human wait, old-host fencing or
the approval's one-hour validity period. Approval signing/consumption must use
the still-retained reader and perform their own exact-purpose checks. Successful
reader settlement returns no permission or grant. It does not establish complete
old-host fencing, archive readiness, restore completion or a new writer.

Portable tests cover real SQLite auxiliary-handle retention between closed
transactions, read-only refusal, a second connection to the same inode cohort,
fresh snapshots, principal/stamp selection, generated connection/transaction
histories and mutations of the actual production wiring. These tests do not
construct a simulated native owner. Linux hostile-process admission, actual
App/Controller concurrency and deployed qualification remain separate work.

The approval producer and accepting Controller dispatcher remain pending. This
reader provides their typed retained source; there is no new public restore
endpoint, operator authentication shortcut or receipt-to-authority conversion.
