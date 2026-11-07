# Reserved restore observation settlement

`security_epoch::kernel::restore::completion` is the next pure DATA transition
following prepare-for-restore. It records a completed target observation or an
explicit cancellation under one create-only key for the original operation.
Both outcomes leave the epoch-2 root and sentinel fenced. There is no provider
send port, copy permit, native maintenance supplier, restored writer, activation
or ordinary-restore exception.

The input retains the original reservation and its fixed maintenance grant.
Preparation requires fresh enabled authority, the same exact available key
references, unchanged issuer/revision/policy/domain/fence and the original
interval. Equality at the deadline, rewind, revocation, key loss or any later
epoch produces an error and **no write plan**, even for refusal. That error is
not itself an irreversible native-owner latch. A future genuine owner must
provide that behavior; reconciliation cannot manufacture permission to write a
denial after the original grant has expired.

The completed observation fixes the exact intent, archive image, new target
incarnation, epoch 2, schema, artifact, resulting image and reset-observation
commitment. Its only policy is reissue-and-reauthorize. These are bounded,
unauthenticated DATA commitments, not proof that a copy or sanitization occurred.
A future checked reset/admission producer must establish the actual image,
invalidated credentials/callbacks/delivery and OAuth quarantine before any
execution or readiness claim. No preservation profile exists.

A single provider transaction must compare the complete values and captured
update tokens of root, sentinel, initial create/activation history, advance
receipt and reservation, then create the terminal record if absent. Equal-value
rewrites invalidate an existing plan. Completed and Refused compete for that
same key; neither may overwrite the other. Revalidation checks current authority
again and cannot recapture a new state into old work. The terminal timestamp is
preparation time, not an asserted commit or target-admission time.

After an unknown send, historical reconciliation distinguishes the complete
unchanged-before state, the exact terminal record under the exact captured
state, and conflict. It does not dispatch, retry, refresh the original grant or
activate anything. A newer epoch, substituted receipt, restored old active root
or equal-value rewrite conflicts. Exact historical classification can be read
after expiry but never becomes present authority.

The ordinary SQLite conditional fixture models that one transaction. An
independent terminal-wire oracle owns complete expected records, tokens,
attempts, preparation and decisions. Generated histories run twice, including
lost replies, reopen, competing dispositions, rewrites, revocation, key loss and
epoch changes. Complete failure prefixes are bounded, source-bound, privately
retained gzip records under the existing CI replay path. Parser errors are
closed; optional absent replay inputs are not saved-corpus passes.

Separate child processes pause before comparison, after comparison, after
terminal insertion and after commit. Exact checkpoint, SIGKILL, reaping and pipe
EOF precede reopen. Precommit loss leaves no terminal; postcommit loss preserves
the whole terminal. Normal exit cannot impersonate a killed process. This is
ordinary SQLite process-loss evidence, not Firestore, power-loss or native
owner qualification.

Both dispositions are also checked against the actual initial-activation
reconciler (fenced authority stays refused) and actual ordinary-restore history
guard. Real bearer/target/native-consumer settlement is not joined here; existing
epoch-fencing bearer tests remain separately scoped. Native copy/reset and
fresh target/epoch admission are still required work.
