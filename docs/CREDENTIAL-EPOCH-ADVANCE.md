# First external epoch advance

The private `security_epoch::kernel::advance` module describes one transition:
active initial authority at epoch 1 becomes fenced authority at epoch 2. It is a
pure DATA kernel, with conditional SQLite conformance tests. There is no native
maintenance-purpose producer, provider transport, restore command or new-writer
activation for this transition.

The existing initial request, receipt and snapshot shapes stay unchanged. The
advance request is a separate closed type containing a unique operation, the
exact initial activation receipt and both observed provider versions. Preparation
requires the selected authority's complete active initial state and exact root
and sentinel versions. Reusing either initial operation, changing the selection,
or presenting a different version refuses preparation.
The request also pins the complete selected store configuration. Changing an IAM
selector or lease bound cannot reinterpret an already prepared request, even
when its immutable database authority key remains the same.

The plan describes an atomic write of the new root, fenced sentinel and a
create-only advance receipt. Both root and sentinel require their exact previous
versions. The sentinel retains its immutable initial epoch 1; both records carry
the same fenced phase, binding the advance request, prior records and activation
receipt. The root epoch advances to 2. No phase in this transition grants a
replacement holder or writer.

The request excludes its derived after-state hashes. The fenced phase binds the
domain-separated request digest and prior record hashes; the receipt then binds
the complete request and both derived after records. This avoids a recursive
hash. All fields and phase maps are closed; unknown fields, duplicate phase
fields and malformed epochs refuse rather than becoming another spelling of an
accepted state.

Reconciliation is historical classification, never permission to send. An absent
advance receipt yields `NotApplied` only when the entire exact active before
state still matches, including both conditional versions. An absent receipt with
fenced or partial records refuses. `Applied` requires the exact receipt and both
complete fenced records with changed provider versions. Another request's
receipt, restored before records, partial writes and substituted history refuse.

Both existing initial requests refuse reconciliation against a fenced root. The
kernel cannot reactivate the old holder by replaying its activation receipt. The
conditional provider tests also reject stale plans after the write; losing an
acknowledgement does not erase committed records or authorize a second advance.

These are controlled protocol properties. The SQLite oracle interprets only
exact-version CAS and create-only receipt keys, independently of the transition
logic. Its reference transition constructs the expected fenced records and
receipt separately. Faults before mutation, after the first transactional write
and after commit distinguish rollback from unknown completion.

Twenty histories capture the complete selected store, initial records and
provider versions, operation and fault cut. Each round-trips its serialized input
and runs twice against the independent complete-row model. Replay binds the
kernel, model and dependency source, refuses a foreign source or oversized input,
and saves complete divergent input/actual/expected data under
`artifacts/epoch-advance-failures`. The `replay_saved_first_advance_history` test
accepts that bundle through `DAY2_REPLAY_EPOCH_ADVANCE`; saved outcomes never
replace the independent oracle. This is a controlled interrupted-transaction
campaign, not a native process-kill or real Firestore qualification.

This does not establish that incumbent native leases were physically fenced, that
a historical snapshot is fresh, or that an external epoch can be safely changed
by a running installation. A later producer must retain genuine maintenance
authority, original clocks and refusal through every real effect, fence or wait
out incumbent leases, and reobserve the actual outside-backup store. Restored
credential rows, delivery permits and ciphertext cannot be relabelled into the
new epoch. The initial restore policy and new-writer readiness remain separate.
