# Storage lifecycle simulation

The private library campaign `security_epoch::control_slot_tests::lifecycle`
extends the conditional SQLite provider fixtures into multi-step histories.
It drives production control-slot reservation, consuming claim/counter dispatch,
settlement, initial activation reconciliation, active provider-version checks
and the pessimistic file-continuation decision. Those are real decisions under
controlled observations; the execution contexts remain explicitly DATA fixtures.

Thirty-two seeded successful histories traverse the initial first-holder
transcript, both three-operation bootstrap stages and three current exchanges.
Generated reopen points retain the complete provider databases. Fault cuts at
each bootstrap operation explore lost/malformed acknowledgements, expiry after
the slot or counter commits, counter loss before and after application,
abandoned claims, well-formed replacement candidates and stale conditional
versions. Further histories join peer death and identical-value provider rewrites
to the current continuation. Restoring observations and reopening SQLite never
restore a refused original continuation or turn stored May into send permission.

Paired post-commit clock histories also cover all six slot writes and both counter
sends. A reply at time 103 follows either an observation at 102 (forward control)
or 104 (rewind), with the same original interval 100..105. Both samples remain
before expiry; only the direction changes. The actual primary budget clock-order error must
be observed, not merely any refusal. The fixture keeps the same clock domain, so
these schedules isolate a rewind. The independent oracle predicts that closed
cause count separately from the adapter, alongside every committed row/version
and send count. A rewound claim acknowledgement leaves durable May without a
counter send; a rewound counter acknowledgement retains the applied counter write.
Clock restoration, independent DATA readback, provider reopen and repeated action
attempts cannot revive the refused continuation or resend. The forward controls
must still complete both bootstrap stages and all three Current exchanges. Four
seeds cover all sixteen operation/direction cuts through the existing serialized
history, twice-replay and bounded reduction path. These controlled clock inputs
do not construct a native original or qualify a real clock implementation.

Further generated histories drive the existing conditional backend's malformed
counter acknowledgement after its real SQLite commit, at both bootstrap stages.
The consumer must return the actual primary acknowledgement decode failure,
retain durable May and all applied counter rows/versions, and refuse further
settlement, dispatch or Current use on that continuation. Resetting only the
backend fault, independent historical DATA readback and provider reopen cannot
authorize a resend. Paired ordinary acknowledgements still complete both stages
and all three Current exchanges. Complete serialized histories use the same
independent oracle, twice replay and bounded reduction. These schedules know
where their fixture applied the write; a malformed real provider response alone
does not establish application or permit rollback, retry or a new grant.

Further generated histories fail the existing SQLite counter adapter after two
of its three real writes, before commit. The transaction rolls back every counter
row and version, while the earlier known May slot and attempted-send count remain.
The actual fixture's mid-commit failure must be observed; an unrelated refusal
does not satisfy the cut. An independent oracle predicts the complete unchanged
counter state and durable May. Backend reset, independent readback and reopen
cannot revive the same refused continuation, settle it, resend or grant Current.
Paired normal commits still complete both stages and three Current exchanges.
These controlled histories know exactly where their fixture failed; a real lost
or rejected provider response alone does not prove rollback or authorize retry.

The lifecycle oracle separately specifies the allowed state changes and every
expected provider row, including immutable requests, candidate/holder data,
receipts, attempt lineage and exact versions. It does not call production slot
transition, reconciliation, codec, clock or permission methods. Immutable fixture
DTO serialization and standard hashing are shared. After every event the
campaign compares the result and complete expected rows. It replays each history
twice and compares the complete provider journals, HTTP fixture calls, pending
handshake state and continuation observations as well. Bounds refuse oversized
inputs; the compared state is never silently truncated.

A further thirty-two seeded adversarial histories and thirty-two proptest cases
start at generated reachable prefixes, then interleave duplicate or out-of-order
operations, current exchanges, read-only observations and connection reopens.

## Composition with the handshake campaign

The existing native-handshake scheduler and its independent wire-prefix oracle
are retained across lifecycle operations. The initial storage conversation must
complete through Accepted; subsequent conversations retain the original endpoint
state and advance the exact sequence through Known, Consumed and Released.
Injected peer death occurs at generated wire-event cuts. A completed simulated
transcript remains DATA, and neither a successful exchange nor provider readback
constructs an enrolled role, first holder, original file/P3 or current writer.

On Linux the same histories additionally retain a real original file prepared
by the existing **unqualified filesystem fixture**. Original image checks call
the production full-file validator. Current physical checks use its actual
identity observer on the held descriptor and named leaf. Generated substitution
and byte-tampering cuts retain that descriptor; restoration cannot clear an
observed refusal. A legitimate same-inode SQLite write is a positive control for
the distinct current physical contract. A shorter same-inode file is accepted
only by the physical observer; initial image checks still refuse it. This physical
control does not assert SQLite schema or data integrity. OS identities are
compared as retained identity relationships, so replay does not depend on coincidentally reused file
descriptor or inode numbers.

A second physical matrix mutates the file after each of the six real bootstrap
operations completes its conditional write, before the enclosing fixture phase's
mandatory final file observation. Tampering, leaf replacement and shortening all
refuse that phase. The independent oracle first predicts the successful durable
write, then the physical refusal. Complete counter/slot rows and both send counts
must equal the successful prefix even though the operation reports failure.
Independent DATA readback, exact file restoration, provider reopen and clock
restoration cannot erase those committed rows, revive the refused continuation
or resend either write. Four seeds cover all eighteen operation/fault cuts, and
each serialized history is replayed twice. A file-fault history without an actual
initial-image input is rejected before fixture execution. These cuts model a
known committed write followed by local refusal; they do not assert that a lost
provider reply was unapplied or construct a native writer.

The physical campaign first projects immutable proposed selection, policy and
seed DATA to initialize its fixture models. That is neither a provider call nor
permission. After the scheduled actual preparation succeeds, the existing strict
blueprint checks the retained file and proposal before first-holder work can
begin. Both conditional requests and the independent model retain those same
immutable inputs. The input binding also includes the validated initial
image digest and length. The complete initial image is captured once as a bounded
history input: the real initializer contains authority entropy and a temporary
artifact path, so rerunning it would produce different bytes. Each replay validates
the captured image through the normal schema/core/marker decoder before preparing
its fresh unqualified file at the explicit preparation event. The saved
original and reduced programs retain those same bytes. Proposed DATA is fixed
before the history, and the checked post-preparation blueprint never restamps it;
current writes cannot replace it. Saved bundles also bind those fixture inputs,
so replay refuses changed runtime fixture definitions even with the same Rust
campaign source.

## Running and replaying

```console
bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::control_slot_tests::lifecycle:: --test-threads=1
```

Library discovery includes these cases in the normal fast/full verification
recipes and workspace CI. Linux file cases retain their platform restriction;
they are additional fixture controls, not a substitute for kernel conformance.

Model/replay divergence retains an original and reduced typed history, complete
observations through the failure and compiled source identity under
`artifacts/storage-lifecycle-simulation/`. Reduction is bounded and preserves the
failure category. A failed hosted day2 shard uploads these bundles as the
`day2-storage-lifecycle-failures` artifact. Bundles contain only fixed synthetic
fixture data, never live provider values, credentials, certificates or native
process identities.

The conditional provider additionally saves every before-dispatch and
post-outcome journal prefix under `artifacts/control-slot-replays/`. Each private
capture contains `replay.json.gz`: lossless gzip of the complete previous JSON
payload, including its label, event/attempt identities and final rows. Duplicate
payloads still receive distinct captures. Decompress these diagnostic records
before inspecting JSON; they are not the typed `failure.json` replay input.
Compression changes no campaign, evidence or scratch-space bound and does not
establish filesystem durability. Original uncompressed captures remain retained
as historical evidence; no compatibility reader or state migration is added.

```console
DAY2_STORAGE_LIFECYCLE_REPLAY=/absolute/path/to/failure.json bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::control_slot_tests::lifecycle::replay_saved_storage_lifecycle_history --exact
```

Replay refuses a different source identity, unsupported version or excessive
history/bundle size. Preserve original evidence when fixing a failure and add its
reduced semantic history as a regression on the corrected source.

The [OAuth consumer campaign](NATIVE-OAUTH-CONSUMER-SIMULATION.md) retains this
campaign's independent state and transcript models while driving actual
connect/read/refresh/disconnect decisions. Its closed DATA composition exposes
observations, never a native permission or current writer.

This storage campaign does not execute native Controller/App/Shell owners,
authenticated provider adapters or actual current-writer effects. It does not
prove physical durability, kernel admission, AppArmor, provider fidelity or timing
margin. The real kernel conformance tests remain unchanged. Executing the complete
native producer/consumer lifecycle remains separate qualification work.

The first-holder conversation can also advance one controlled wire event at a
time. Its App file observation is a separate obligation after the checked Offer
and before Confirm; Controller retention follows its checked Accepted, rather
than treating an empty queue or successful send as a receipt. Both use the same
original controlled observations before and after file work, including when file
work fails. A file error remains primary after the mandatory postcheck. Histories
retain checked-Accepted DATA separately from usable first-holder retention, so a
late file/clock refusal cannot erase history or grant bootstrap work. File work
can consume controlled time inside the original interval; equality and rewind
refuse. Each record also retains the separate reference world and its pending
queue, including failure paths.

The existing complete-exchange event drains this same path. The outer program
retains its 96 ordinary-event bound and allows up to 512 individual handshake
advances in addition, with the existing bundle byte bound unchanged. The oracle
owns its own independent wire model and never reads the actual transcript to
predict an outcome. Pending file obligations, restoration, late packets and
SQLite reopen cannot repair a refused continuation. Linux histories use the
existing unqualified held-file fixture at the actual observation cuts. They do
not qualify physical durability, enrolled peers, P3 or writer authority. The
explicit preparation event below calls real file/directory sync operations but
does not simulate their behavior across power loss.


## Stepped bootstrap and Current completion

Each complete bootstrap or ordinary Current event now drains the same explicit
completion path used by paused histories. Bootstrap selects the closed
StorageBootstrap purpose; ordinary Current keeps CurrentRole. A checked local
Controller Ready send precedes its conditional mutation; App receipt remains a
separate later observation. Only a successful mutation reaches the strong
counter/slot post-read and the production `validate_after` decision before
Known. A mutation error still receives its retained-original postcheck, keeps
its actual primary error, and starts no additional provider read.

Histories separately pause after checked Consumed before Released and after
peer completion before final file validation. Final activation keeps its last
initial-byte check before App release, then checks physical identity at final
finish. A late file or provider refusal retains committed rows, consumed and
peer-complete history while denying usable completion. Current's completion
count advances only after its post-read and final file check. A pending
completion also fences the actual shared consumer-readiness fixture before any
provider call; later readiness after a successful finish does not reuse or
unpoison a refused outer request original.

The outer reference now independently drives every bootstrap and Current wire
conversation. Complete worlds, queues, original observations and cumulative
schedule state are compared after every event. Fixed/generated cuts cover all
six bootstrap actions and ordinary Current, lost Known/Consumed/Released,
applied-but-unacknowledged and rolled-back counter writes, pending operation
exclusion, restoration/reopen, deadline equality and a positive small-work
control. Only one target conversation is expanded per history, retaining the
existing independent ordinary-event and wire-advance input caps.

The provider fixture's controller-process-clock execution interval stays fixed
at 100..105. Wire observations retain their distinct seed/endpoint/sequence
domains and original purpose-bound intervals. Controlled work explicitly advances
each domain; numeric samples are never translated into each other or used to
renew a context. These are synthetic observations, not a physical clock-rate or
native timing qualification. Linux uses the existing unqualified held-file
fixture; its observations and DATA contexts do not construct native authority,
P3, current-writer ownership or a real request original.


## Original-file preparation inside the history

Linux physical histories explicitly schedule `PrepareOriginal`; the fixture no
longer creates the selected file in its constructor. The event calls the same
production `prepare_original_file` synchronously, retains its exact owning
outcome before fallible observation, and records its closed checkpoint. No new
native factory, resumable owner or syscall pause is introduced. Only actual
Prepared can reach the existing checked blueprint and subsequent fresh
first-holder/file checks. Prepared is historical local success, not lasting
readiness, P3 or permission to skip later checks.

Sixteen seeds cover the six existing post-effect cuts (create, first write,
file sync, directory sync, readback and decode), wrong proposal, and existing
file/symlink/directory/hardlink leaves, with paired successes through bootstrap
and Current. The write cut also uses a multi-batch image: exactly its first MiB
is retained before refusal. The complete image is
one immutable replay input. Prefix observations reference every exact byte of
that input losslessly; non-prefix observations preserve all bytes instead of
hashing or truncating them.

The oracle derives disposition, attempted status, returned descriptor and
named/held/foreign observations from immutable inputs, never the coordinator's
outcome or diagnostic phase. Historical observations at return stay separate
from live observations while pending/refused; later successful app writes use
the existing current physical checks. A missing returned FD never proves no
creation or no committed effect. Refused owners retain their descriptor when
one returned, original anchor and proposal.

Restoration repairs the injected plan/fault and file inputs, then verifies that
the actual native refusal still rejects the original and a replacement interval
outside the expected-refusal path. Reopen and repaired inputs cannot revive the
same continuation; a later preparation attempt remains refused. Tests exercise pending
use and repeated preparation before and after first-holder retention. Fixture
SQLite initialization and read-only DATA observations remain distinct from
conditional provider protocol calls, whose sends stay zero until actual
preparation and first-holder completion.

The existing 96 ordinary events, separate 512 wire advances, complete reference
comparison, twice replay, reduction, source binding and bundle bounds remain.
New preparation inputs require a map and reject unknown/duplicate fields and
positional shapes. These cases cover real local syscalls and decisions under an
unqualified test issuer; injected post-effect errors do not prove partial-syscall
or crash durability, native enrollment, writer authority or timing margin.
