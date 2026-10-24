# OAuth consumers joined to native lifecycle decisions

The private library campaign
`oauth::management::app::tests::native_lifecycle` composes the existing
[storage lifecycle](STORAGE-LIFECYCLE-SIMULATION.md) and
[enrollment/handshake](NATIVE-HANDSHAKE-SIMULATION.md) DATA campaigns with the
real OAuth management, read and refresh decisions. It uses real SQLite and the
ordinary admitted synthetic Calendar declaration, controlled wall and monotonic
clocks, seeded entropy and allowlisted HTTP responses. It does not construct
native role, holder, writer or serving permissions.

Each history establishes the three enrollment transcripts, first holder,
creation and activation slots, current storage and Shell serving transcripts.
It then captures an App original, completes the Shell approval and connect
callback, resolves and reads Calendar, performs demand refresh, and disconnects.
Fresh resolution, the original callback and the old read reference are exercised
again after disconnect. A closed schedule can interleave App, Shell or Controller
death, an identical-value epoch rewrite, SQLite reopen, restored observations and
loss of the test executor registry.

## Independent expectations and fault boundaries

The OAuth oracle consumes only the schedule. It independently specifies pending,
authorized, active and disabled states, token versions and expiry, refresh
attempt rows, provider sends and read outcomes. It never consumes the actual
result or calls production transition helpers to choose an expectation. The
storage and handshake campaigns retain their own independent models and compare
their complete state before the composed consumer receives an observation.

Four successful seeds and fifty-six owner/prefix schedules replay twice.
Coverage requires the scheduled owner actually to become unavailable. Directed
histories additionally check:

- Original five-minute deadline equality, reobservation and database reopen.
- A failed same-instant freshness attempt permanently refusing the same Shell
  original, and an unexpired read reference fenced by a newer token version.
- Refresh response completion at 4,999 milliseconds versus the five-second
  deadline, and an accepted provider request whose reply is lost.
- Crashes after dispatch commit, material write and publication commit. Stored
  uncertainty and a committed replacement remain distinguishable; neither grants
  a new send or recovers the dead original.
- A final check expiring after durable publication, monotonic rewind, and an
  executor-registry restart while the database remains intact.
- Another company's runtime with the same app name, rejected before use of the
  selected company's owner.

Every step compares the independent slot, refresh and provider projections and
checks original-owner invariants. Exact replay additionally compares the complete
bounded OAuth SQL snapshot, provider journal, original owner clocks and bindings,
and retained storage/enrollment/serving observations. Original
origin, binding and ceiling must remain fixed; observed clock samples cannot
rewind and refusal cannot clear. Bounds reject excessive histories and evidence;
they do not truncate compared state.

## Running and replay

```console
bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib oauth::management::app::tests::native_lifecycle:: --test-threads=1
```

The normal fast/full library discovery includes the campaign. Model or replay
divergence saves an original schedule, a bounded deletion reduction, full
observations through divergence and the compiled source identity under
`artifacts/oauth-native-consumer-simulation/failure-*/failure.json`. Directories
are private temporary directories and files are created with mode 0600. The
workspace day2 CI shard retains these bundles when it fails.

```console
DAY2_NATIVE_OAUTH_REPLAY=/absolute/path/to/failure.json bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib oauth::management::app::tests::native_lifecycle::replay_saved_native_oauth_consumer_history --exact
```

Replay refuses another compiled source, unknown fields, duplicate JSON fields,
positional descriptors, changed seeds, histories outside the bounds and a reduced
schedule that is not a deletion of its original. Without a replay file the entry
point returns without running a saved corpus. The suite separately exercises
actual saved-file replay and negative descriptor controls. Preserve failing
evidence and add its semantic schedule as a regression when fixing a defect.

All provider values are fixed synthetic fixtures. Evidence records allowlisted
provider event classifications and redacted SQL, not request bodies, tokens,
credentials or raw native errors. Privacy controls inspect complete recorded
histories for the fixture's private code, tokens and client secret.

## Qualification boundary

The composition drives production OAuth decisions and shared storage/transcript
reducers using controlled DATA observations. The explicit opt-in simulated
runtime owner is test-only; native-metadata runtimes cannot select it. Approval
uses an isolated reauthentication fixture, rather than a signed live Google
proof. The admitted read contract is synthetic; no Roc worker or browser HTTP
sink is executed here.

This campaign does not execute production enrollment, native executor/process
ownership, SCM_PIDFD, kernel/file integrity, actual Firestore transport, KMS,
durability, browser delivery or signed `auth_time`. Those retain their native and
live qualification requirements. Passing these histories does not establish
timing margin, provider fidelity or completion of the complete native OAuth
system.
