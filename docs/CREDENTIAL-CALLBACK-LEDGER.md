# Single-acceptance callback reservation kernel

The private `managed_credentials::callback` module is the first callback-ledger
transition. It produces conditional-write DATA plans and historical reservation
records. It installs no store, ingress, token issuer, worker-claim supplier,
command-acceptance adapter or native authority. Claim-bound callbacks remain
unsupported as a usable feature.

A binding fixes the namespace and generation, callback and credential version,
artifact, authority, worker, dispatch, claim and claim epoch, security epoch,
resource, complete operation contract, ceiling and lifetime. Those records are
DATA; a future caller must authenticate the credential and actual current claim,
decode the canonical operation input and prove its target equality. Passing a
record to this kernel never supplies those proofs.

The closed transition is `Unspent` to `Reserved(invocation, input, time)`. A
fresh invocation ID cannot reset the one-use budget. An identical invocation and
input digest recover the original reservation time, subject to fresh claim,
epoch, enablement and expiry checks. Changed input, claim replacement, epoch
advance, another resource or scope, expiry equality and clock rewind refuse.
No reusable-during-claim profile is added.

A plan fixes the complete before/after records and exact provider versions.
Equal-value rewrites invalidate an old conditional plan. Revalidation checks the
fresh source DATA, unchanged read and original reservation time. It never renews
the callback lifetime or a native original. Reconciliation distinguishes exact
applied, exact unapplied and conflicting state after an uncertain write; it may
report historical DATA after revocation. It gives no retry, polling, result-read
or execution authority.

## Model and crash boundaries

An independently scripted reference tracks the spent identity/input, conditional
version, prepared time and outside-backup claim/epoch. It never calls production
transition helpers or reads actual results to predict expectations. Every event
compares the complete callback and intent rows, pending plan, clock and source,
plus the exact adapter phases reached. Both complete runs are retained on a
disagreement, including a disagreement occurring only on the second run.
Initial cuts vary across commit and rollback. Generated steps run before the
irreversible epoch advance as well as after restore; initially rolled-back
histories must witness an actual later transaction, not only refusals.

The ordinary SQLite fixture conditionally changes the callback row and inserts
an acceptance-INTENT row in one transaction. These are fixture records, not
`day2_invocations` or a second command runtime. The future host adapter must
combine the ledger with actual canonical command acceptance under the existing
owner and transaction; that integration remains a separate slice.

Actual child processes stop at before-write, after-record, after-intent and
after-commit checkpoints. The parent requires the exact checkpoint, sends
SIGKILL, observes its signal and pipe EOF, then reopens SQLite. Before-commit
cuts leave neither reservation nor intent. After-commit retains both even though
the original process never delivered a result. Normal completion and a clean
exit at a checkpoint are controls. Partial error prefixes retain closed phase,
exit, cleanup and available row observations, with no raw stderr. Source-bound
crash records replay the actual child case; unresolved cleanup refuses replay.
This is process-loss/WAL coverage, not
power-loss or native-owner qualification.

Restore tests keep the separately modelled epoch monotonic. Restoring old local
rows is permitted in the fixture only after that external epoch advanced, so
old bindings remain fenced. This models the required restore ordering; it does
not implement an operational restore or establish a genuine external witness.
Ordinary restore refusal and native fencing remain separate enforced boundaries.

The existing failed-credential CI artifact path retains source-bound, bounded
synthetic records under `artifacts/credential-simulation/failure-callback-*`.
History replay checks both runs with a 64-event/two-MiB limit. Unknown fields,
changed source and altered observations refuse. Records contain no token,
verifier, ciphertext, provider payload or downstream error messages.

```console
bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib managed_credentials::callback::tests:: --test-threads=1
DAY2_CALLBACK_LEDGER_REPLAY=/absolute/path/to/failure.json bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib managed_credentials::callback::tests::saved_callback_reservation_replay --exact
DAY2_CALLBACK_LEDGER_CRASH_REPLAY=/absolute/path/to/crash.json bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib managed_credentials::callback::tests::saved_callback_crash_replay --exact
```
