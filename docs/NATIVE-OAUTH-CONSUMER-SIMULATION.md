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

Serving progress can also be interleaved with actual OAuth decisions. A closed
`BeginShell` queues one conversation; bounded `AdvanceShell` batches resume its
existing events without starting another stage or clock. Each batch contains
one to 64 events and the whole history retains its 64-step limit. Applying an
input is distinct from completing the protocol: the complete observation labels
pending, completed or refused progress. The existing selected-role hook still
checks storage/enrollment and the actual Shell transcript before approval.
No progress label becomes a permission or genuine-owner constructor.

## Independent expectations and fault boundaries

The OAuth oracle consumes only the schedule. It independently specifies pending,
authorized, active and disabled states, token versions and expiry, refresh
attempt rows, provider sends and read outcomes. It never consumes the actual
result or calls production transition helpers to choose an expectation. The
storage and handshake campaigns retain their own independent models and compare
their complete state before the composed consumer receives an observation.
Handshake simulator/oracle errors retain a typed failure channel across the
storage phase's pessimistic refusal handling. A negative control deliberately
disagrees only in the reference transcript: even when peer death produces the
expected denial and the complete outer storage state still matches, the model
error must fail the composition.

Storage interleavings use the same first-holder and bootstrap/Current steppers.
Each program explicitly starts either with active storage or before first holder;
reduction cannot change that immutable setup. Closed events expose checked Offer,
App observation, Controller retention, mutation, release and final completion.
Adjacent wire events may share a batch of at most 64 events, retaining each
event's wait, original clock, retry and postcheck; batches do not conceal a
consumer or provider/file obligation. The whole history keeps its 64-step bound.

A reference-only storage model is initialized from controlled immutable scope
and core inputs, without constructing an actual world or reading SQLite or
consumer outcomes. It independently predicts rows, versions, continuation,
current usability and the complete retained handshake. Every consumer cut
compares those predictions with the real conditional adapters and their existing
independent model. Expected-current observations remain DATA, not witnesses or
permission. Actual App reads/refresh still enter the selected runtime hook.

Generated first-holder and Current pauses exercise both outcomes: avoiding an
early request permits later use after complete storage, while a request during
the pause permanently refuses that App owner even after storage completes.
The histories require the actual selected-role refusal, not merely an unavailable
connection result. Controller reserve/dispatch/settle before retention or during
pending Current must refuse without writes and cannot recover by reopening or
restoring observations. Lost or malformed mutation replies retain applied rows
and durable May; an actual rollback retains the old rows. Neither uncertainty
nor an already active row establishes known mutation, wire completion, usable
Current or permission to settle again. Complete observations replay twice;
a deliberately false pending-storage expectation is saved and replayed through
the existing source-bound counterexample path. No enrolled execution owner is
constructed by these histories.

A separate reference-only serving world consumes the seed and explicit
begin/advance/death inputs. It never reads the consumer transcript, SQL, hook
results or provider journal to predict progress or approval. Every consumer step
compares its complete reference endpoint world, schedule, clocks, queues and
failure state; absent or unknown progress is a disagreement. Generated pauses
before the first event, during the conversation and after completion exercise
the real approval and App read/refresh calls. Approval while pending permanently
refuses that selected Shell owner. Later transcript completion, restored
observations or reopening SQLite cannot revive it; independently admitted App
reads remain distinct. Peer death and executor restart retain the same refusal
rules. A deliberately false completion expectation is saved and replayed as a
real consumer disagreement, and a corrupt transcript oracle cannot be hidden
behind an expected pending denial.

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
divergence saves an original schedule, a bounded deletion reduction, both runs
of each schedule, complete observations through divergence and the compiled
source identity under
`artifacts/oauth-native-consumer-simulation/failure-*/failure.json`. This file is
the manifest: preserve its entire directory, including every sibling
`record-*.json` file. Copying only the manifest cannot replay the counterexample.
Directories are private temporary directories and files are created with mode
0600. The workspace day2 CI shard retains the manifest and all record files when
it fails.

Each complete record uses the existing four-MiB evidence decoder limit; the
whole archive is bounded to 64 MiB. Histories retain the existing 64-step limit.
Whole identical records share one parsed value through bounded, borrowed record
references; replay does not expand those references into copied value trees.
Every complete original and reduced observation is still compared, without
truncation. The manifest binds every record's
length and digest and is written only after its referenced files are synced and
closed. This is not a directory-fsync or power-loss durability claim. Reduction
retains the actual last winning observation, including an intermittent failure
that no longer reproduces later. An unavailable failure cause keeps the original
history and remains unqualified by replay.

```console
DAY2_NATIVE_OAUTH_REPLAY=/absolute/path/to/failure.json bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib oauth::management::app::tests::native_lifecycle::replay_saved_native_oauth_consumer_history --exact
```

Replay refuses another compiled source, unknown fields, duplicate JSON fields,
positional descriptors, changed seeds, histories outside the bounds and a reduced
schedule that is not a deletion of its original. It checks the complete original
and reduced observations, including the failure category, twice. Missing,
changed, additional or unreferenced record files are refused; success cannot be
saved as a disagreement. Without a replay file the entry point returns without
running a saved corpus. The suite separately exercises actual saved-file replay,
the maximum-length history, intermittent retention and negative descriptor
controls. Preserve failing evidence and add its semantic schedule as a regression
when fixing a defect.

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
