# First prepare-for-restore reservation

The private `security_epoch::kernel::restore` module is a pure DATA transition,
not an operational restore command. It reserves one exact backup and new target
incarnation while advancing active initial epoch 1 to fenced epoch 2. It composes
the existing first-advance kernel instead of defining another epoch store.
The ordinary restore refusal remains unchanged. There is no native maintenance
producer, provider send port, copy permit, restored writer or new activation.

## Binding and conditional write

The intent fixes the complete selected store, authority scope, immutable backup
image digest, source database incarnation, source epoch, schema, artifact and
bounded exact key-reference manifest, plus the unique restore operation and
new target incarnation. Only an epoch-1 copy from that initial database is
supported. The target must differ. Other scopes, key sets and epochs refuse;
there is no general re-epoch, import or preservation profile.

A domain-separated digest of that complete intent is also the **existing
advance operation identity**. The fenced root therefore commits to the same
archive and target as the restore ledger. Derived receipts and after-record
hashes are excluded from the intent digest, avoiding recursive hashing.

Preparation requires an independent, current maintenance statement bound to
the intent, exact incumbent root and holder, policy/revision and clock domain.
It also requires the complete exact key-reference list, unchanged and in
canonical order. References never contain key material; missing, substituted,
duplicate, unbounded or mutable `latest`/`current` key selectors refuse. The
statement has a fixed original interval. Re-observation cannot extend it;
expiry equality, rewind, a new source/revision or lost permission refuses.

These are **DATA commitments**. The kernel cannot authenticate the maintenance
issuer, physically fence a holder, wait out leases, validate a real archive or
obtain an exact key. A future trusted supplier and copy preflight must establish
those facts with genuine owners and current evidence. A record asserting a
fence or key availability is not itself that proof.

One provider transaction must compare the exact observed root and sentinel
versions and atomically write all four records:

1. The existing epoch-2 fenced root.
2. The existing fenced sentinel, retaining its immutable initial epoch.
3. The existing create-only advance receipt.
4. A create-only restore reservation for this exact operation and intent.

Revalidation repeats the current authority/key/time checks and compares the
complete before state immediately before conditional staging. Equal-value
rewrites and competing restores invalidate stale plans. The plan grants no
send permission and does not settle an unknown provider outcome.

The initial policy requires reissuing pre-restore managed credentials and
callbacks, closing pending delivery and quarantining OAuth for reauthorization.
This module records that policy but performs no copy or sanitization. It never
changes a credential row's epoch, relabels ciphertext, reopens delivery or
restores a historical permit. Both epoch records remain fenced, so existing
initial activation/readiness reconciliation rejects the former holder. A later
copy and new-writer transition needs its own authenticated maintenance and
current schema/key/authority admission.

## Unknown completion and verification

Reconciliation is historical DATA only. `NotApplied` requires the entire exact
before state, versions and initial history, with both new receipts absent.
`Applied` requires the exact restore reservation, advance receipt and both
complete fenced records. Missing or foreign receipts, partial writes, a
substituted archive or restored before records conflict. Classification after
revocation or expiry does not revive permission, authorize a retry or report a
completed restore.

The ordinary SQLite fixture interprets exact-value/version CAS and create-only
receipt keys; it does not implement the production transition. An independent
wire model builds the expected full root, sentinel, initial history and both
new receipts from immutable input. Generated multi-step histories compare
complete rows, attempts, preparation, clock and permission state after every
event, twice. Reopen, competing work, equal-value rewrites, missing receipts,
expiry and revocation remain explicit events. A false rollback oracle and a
second-run-only disagreement must retain both full observations. Replay binds
the actual kernel, adapter, model, JSON codec, fixture and dependency sources.

Separate child processes pause before mutation, after each of the four writes
and after commit. The parent requires the exact checkpoint, actual SIGKILL,
reaping and pipe EOF, then reopens SQLite. Precommit cuts retain the complete
old state; postcommit retains all four new records despite no delivered reply.
Normal completion and clean checkpoint exit cannot impersonate process loss.
This is process-loss/WAL evidence, not power-loss, Firestore or native-owner
qualification.

Failure histories use the existing CI replay-retention directory, private
directories/files and one gzip member of counted JSON records with complete
synthetic metadata. Each record uses the unchanged evidence decoder, with a
256-KiB local record cap, 24-event input cap and 16-MiB decoded archive cap.
Both run counts, every step index and the final marker are mandatory; no
sampling or truncation replaces either run. Admitted fixture, temporary
directory, provider and model/request setup failures retain their closed stage
and available prefixes, including a completed first run when the second fails.
Crash failures retain actual checkpoint/kill/reap/EOF observations and optional
readback; an unresolved child is not reported as reaped or launched again. They
contain no token, verifier, ciphertext, key bytes or foreign error text. Optional
external replay input being absent is not a saved-corpus pass.

```console
bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::kernel::restore::tests:: --test-threads=1
DAY2_SECURE_RESTORE_REPLAY=/absolute/path/replay.json.gz bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::kernel::restore::tests::history::replay_saved_secure_restore_history --exact
DAY2_SECURE_RESTORE_CRASH_REPLAY=/absolute/path/replay.json.gz bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::kernel::restore::tests::process::replay_saved_secure_restore_process_loss --exact
```
