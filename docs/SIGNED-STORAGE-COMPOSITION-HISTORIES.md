# Signed first-holder and conditional activation histories

This portable campaign joins the actual signed issuer/role statements,
first-holder packet decoder/verifier, production body-to-transcript frame mapping
and two-sided transcript reducer to the
actual holder derivation, activation-request derivation, peer request-binding
selector, consuming journal and Firestore codec over the existing independently
conditional SQLite provider. Small cfg(test) forwarders expose only the two
existing pure DATA selectors. There is no enrolled-process, physical-file, P3,
native clock, authenticated live provider or native writer constructor.

The projection is explicitly synthetic file DATA. Generated public statements
and packets share one issuer/policy/selection; private signing keys are discarded
before execution and never saved. Each program runs twice. Its pending-authority fixture prelude records every
fallible protocol step and all available state on refusal, rather than dropping
an early error before a replay record can be made. Disposable adapter allocation
is an ordinary environmental precondition, not native enrollment. The independent
reference uses only the script and immutable input, independently deriving holder
identity, activation IDs, complete records/receipts, conditional versions,
journal states, exact provider RPCs and both transcript states. It shares DTO
serialization/hash primitives and the immutable seed projection, not production
transition, reconciliation or adapter results.

Histories cover six signed initial messages, issuer/role/process/signature and
nonce/projection and validly signed packet-kind substitution, original equality/rewind, changed holder keys,
processes, Pods and namespaces, conditional activation, actual mid-transaction rollback,
malformed acknowledgement after a real commit, duplicate dispatch, reopen and
historical readback. Refusal is permanent for the retained fixture continuation.
A historical Applied result does not complete that continuation, erase durable
May, authorize retry or issue a native writer. The deliberately wrong oracle
claims a malformed acknowledgement meant no write; the recorded actual four
rows and durable May must contradict it and replay twice.

Both complete runs and any first divergent prefix retain every event, full
provider/journal rows, RPCs, selected request/binding and transcript. Auxiliary
read-only observations retain their own complete call prefixes, including
semantic refusal followed by rollback; they never renew the refused writer. Replay
requires counted canonical source-bound JSON records, event and run order, both
complete recorded states and bounded gzip/decoded lengths before rerunning.
Each header, run-start and event record uses the unchanged central evidence
decoder byte/node/depth/key limits. Missing, duplicated, reordered or trailing
records refuse; the aggregate is never passed as one oversized JSON value. Limits are forty events,
128 KiB of closed fixture input and sixteen MiB decoded; evidence is losslessly compressed, never sampled or
truncated. The existing control-slot CI retention glob captures these synthetic
records at `artifacts/control-slot-replays/signed-first-holder-*/replay.json.gz`. Parser failures keep fixed errors instead of foreign values.

```console
bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::native_enrollment::storage_peer_wire::tests::activation_histories:: --test-threads=1
DAY2_SIGNED_STORAGE_REPLAY=/absolute/path/replay.json.gz bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::native_enrollment::storage_peer_wire::tests::activation_histories::external_signed_storage_history_replays_twice_when_supplied --exact
```

Absent optional replay input is not a saved-corpus pass. These histories check
portable decision/codec composition. They do not qualify actual enrollment,
first-holder receipt/P3, live Firestore, serving/writer authority, native Linux
identity, physical durability, power loss or the complete OAuth deployment.
