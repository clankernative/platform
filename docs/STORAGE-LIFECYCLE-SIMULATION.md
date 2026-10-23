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
failure category. Bundles contain only fixed synthetic fixture data, never live
provider values, credentials, certificates or native process identities.

```console
DAY2_STORAGE_LIFECYCLE_REPLAY=/absolute/path/to/failure.json bazel run //crates/xtask:xtask -- test-rust //crates/day2:unit_lib security_epoch::control_slot_tests::lifecycle::replay_saved_storage_lifecycle_history --exact
```

Replay refuses a different source identity, unsupported version or excessive
history/bundle size. Preserve original evidence when fixing a failure and add its
reduced semantic history as a regression on the corrected source.

This campaign does not execute native Controller/App/Shell owners, authenticated
provider adapters, actual current-writer effects or OAuth consumers. It does not
prove physical durability, kernel admission, AppArmor, provider fidelity or timing
margin. The real kernel conformance tests remain unchanged. Joining the complete
native producer/consumer lifecycle and OAuth operations is further work.
