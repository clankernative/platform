# Restore approval time floor protocol

The pure `kernel::approval_time` transition describes two atomic writes in the
selected external EpochStore: advance the existing safe-time floor and create
an immutable receipt for this operation. Four current root/history versions,
the exact prior floor version and absence of that receipt are conditions of the
same provider transaction. It never creates missing floor state, initializes
a counter or uses a restored app database.

The floor key binds the immutable database identity and app authority scope. It
does not change with an IAM/config selector, key rotation, process, boot, grant
or the future restore target epoch. This first protocol requires the existing
coherent active first-holder root; it does not authorize work under a future
fenced target. General later-epoch issuance remains unsupported.

For an actual current interval `[L,U]` and saved upper floor `H`, require
`L >= H` and conditionally write `H = U`. Intervals are bounded to one second.
Overlap, rollback, uncertain or malformed observations refuse. Never clamp a
clock to another writer's floor or reset it after repair/reboot. A fresh native
clock/domain cannot erase an older durable floor.

The plan, observation, floor and receipt are DATA. Even exact positive readback
after a lost reply is historical classification. It cannot reconstruct the
lost native/time owner, qualify approval time, rearm a send or renew a grant.
Another writer, changed current root, partial write or foreign receipt cannot
be treated as this operation's positive result.

The real sampler, pre-fence storage owner, known May journal, conditional sender
and fresh postchecks must still be joined. Completion must choose its fixed
approval start conservatively from actual qualified time, with expiry exactly
one hour later; consumption requires a fresh qualified upper bound strictly
before expiry. Those signing/approval owners and the initial outside-archive
floor installation are not provided here. Absence refuses rather than silently
installing zero.

Tests use real SQLite conditional transactions, reopen and deterministic injected
cuts, plus an independent integer-time model with generated histories and
source-bound replay. They do not claim real child death, power-loss, native,
Firestore-provider or whole approval qualification. Failed model traces are
retained for replay. No cloud resources or provider permissions are created.
